#!/usr/bin/env python3
"""Full-screen terminal application for Peekaboo."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import sys
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from pygments.lexers import guess_lexer_for_filename
from pygments.util import ClassNotFound
from rich.syntax import Syntax
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Key, Resize
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Input,
    Markdown,
    OptionList,
    RichLog,
    Static,
)
from textual.widgets.option_list import Option

BASE = Path(__file__).resolve().parent
DASHBOARD = BASE / "dashboard"
if str(DASHBOARD) not in sys.path:
    sys.path.insert(0, str(DASHBOARD))

TACTIC_COLORS = {
    "reconnaissance": "#9CA3AF",
    "resource-development": "#A78BFA",
    "initial-access": "#F97316",
    "execution": "#30D158",
    "defense-evasion": "#FFD60A",
    "persistence": "#0A84FF",
    "command-and-control": "#FF453A",
    "privilege-escalation": "#FF9F0A",
    "credential-access": "#BF5AF2",
    "discovery": "#64D2FF",
    "lateral-movement": "#FF8FAD",
    "collection": "#FFD60A",
    "exfiltration": "#0A84FF",
    "impact": "#FF375F",
}

LANG_BY_EXT = {
    ".asm": "nasm",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".go": "go",
    ".h": "c",
    ".hpp": "cpp",
    ".nim": "nim",
    ".ps1": "powershell",
    ".py": "python",
    ".rs": "rust",
    ".s": "asm",
    ".S": "asm",
    ".sh": "bash",
    ".yar": "yara",
    ".yara": "yara",
}


def _clean(value: Any, limit: int = 1000) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "~"


def _md(value: Any, limit: int = 1000) -> str:
    return _clean(value, limit).replace("|", "\\|")


def _human_size(value: float | None) -> str:
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return "0 B"


def _status(value: Any) -> Text:
    label = str(value or "unknown")
    color = {
        "success": "#56D98A",
        "ready": "#56D98A",
        "ok": "#56D98A",
        "actor": "#78B4FF",
        "family": "#B57BFF",
        "running": "#72D9F5",
        "queued": "#FFD166",
        "failed": "#FF7875",
        "error": "#FF7875",
    }.get(label.lower(), "#8A85A8")
    return Text(label, style=f"bold {color}")


def _tactic(value: Any) -> Text:
    label = str(value or "unknown")
    primary = re.split(r"[,\s]+", label)[0]
    return Text(label, style=f"bold {TACTIC_COLORS.get(primary, '#8A85A8')}")


def _coverage(value: Any) -> Text:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return Text("-", style="#8A85A8")
    color = "#56D98A" if number >= 80 else "#FFD166" if number >= 50 else "#FF7875"
    return Text(f"{number}%", style=f"bold {color}")


def _resolve_source_path(value: Any) -> Path | None:
    raw = str(value or "").strip()
    if not raw:
        return None

    stored = Path(raw).expanduser()
    candidates = [stored] if stored.is_absolute() else [BASE / stored]
    if "/meow/" in raw:
        meow_root = Path(
            os.environ.get("MEOW_ROOT") or BASE.parent / "meow"
        ).expanduser()
        candidates.append(meow_root / raw.split("/meow/", 1)[1])

    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def _source_language(path: Path, source: str) -> str:
    if path.suffix in LANG_BY_EXT:
        return LANG_BY_EXT[path.suffix]
    try:
        lexer = guess_lexer_for_filename(path.name or "source.txt", source)
        if lexer.aliases:
            return lexer.aliases[0]
    except ClassNotFound:
        return "text"
    return "text"


@dataclass(frozen=True)
class Column:
    key: str
    title: str
    width: int


@dataclass
class ViewData:
    title: str
    subtitle: str
    columns: tuple[Column, ...]
    rows: list[dict[str, Any]]


def _row(
    key: str,
    cells: tuple[Any, ...],
    search: str,
    detail: str | Callable[[], str],
    **context: Any,
) -> dict[str, Any]:
    return {
        "key": key,
        "cells": cells,
        "search": search.lower(),
        "detail": detail,
        "context": context,
    }


class PeekabooRepository:
    """A small read model over the existing dashboard database."""

    def __init__(self, db_path: Path | None = None) -> None:
        import db

        if db_path is not None:
            resolved = db_path.expanduser().resolve()
            os.environ["PEEKABOO_DB_PATH"] = str(resolved)
            db.DB_PATH = resolved
        db.init()
        self.db = db

    @property
    def db_path(self) -> Path:
        return Path(self.db.DB_PATH)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _scalar(self, query: str, args: tuple[Any, ...] = ()) -> int:
        with self._connect() as connection:
            value = connection.execute(query, args).fetchone()[0]
        return int(value or 0)

    def header_status(self) -> str:
        campaigns = self._scalar("SELECT COUNT(*) FROM pipeline_sessions")
        modules = self.db.count_mitre_entries()
        detections = self.db.count_artifact_entries()
        size = _human_size(self.db_path.stat().st_size if self.db_path.exists() else 0)
        return f"DB {size}  |  {campaigns} campaigns  |  {modules} modules  |  {detections} detections"

    def load(self, view: str) -> ViewData:
        loaders: dict[str, Callable[[], ViewData]] = {
            "overview": self._overview,
            "campaigns": self._campaigns,
            "library": self._library,
            "attack": self._attack,
            "detection": self._detection,
            "intel": self._intel,
            "builds": self._builds,
            "samples": self._samples,
            "tools": self._tools,
        }
        return loaders.get(view, self._overview)()

    def source_record(self, slug: str) -> dict[str, Any]:
        return self.db.get_mitre_entry(slug) or {}

    def _overview(self) -> ViewData:
        campaigns = self.db.get_pipeline_sessions(500)
        builds = self.db.get_builds(500)
        samples = self.db.get_samples(500)
        artifacts = self.db.get_artifact_stats()
        metrics = [
            (
                "APT campaigns",
                len(campaigns),
                "ready" if campaigns else "empty",
                f"{sum(item.get('status') == 'success' for item in campaigns)} successful sessions",
            ),
            (
                "Research modules",
                self.db.count_mitre_entries(),
                "ready",
                "Local blog implementations indexed in SQLite",
            ),
            (
                "ATT&CK implementations",
                self.db.count_ttp_implementations(),
                "ready",
                f"{self.db.count_ttp_techniques()} distinct techniques",
            ),
            (
                "Detection coverage",
                artifacts.get("total_techniques", 0),
                "ready",
                (
                    f"{artifacts.get('total_rules', 0):,} Sigma rules across "
                    f"{artifacts.get('unique_tactics', 0)} tactics"
                ),
            ),
            (
                "Report TTPs",
                self.db.count_report_ttps(),
                "ready",
                "Precomputed report evidence available offline",
            ),
            (
                "Build history",
                len(builds),
                "ready" if builds else "empty",
                f"{sum(item.get('status') == 'success' for item in builds)} successful builds",
            ),
            (
                "Compiled samples",
                len(samples),
                "ready" if samples else "empty",
                _human_size(sum(item.get("total_size", 0) for item in samples)),
            ),
            (
                "SQLite tables",
                self._scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table'"),
                "ok",
                f"{self.db_path} ({_human_size(self.db_path.stat().st_size)})",
            ),
        ]
        rows = [
            _row(
                f"metric-{index}",
                (
                    Text(name, style="bold #EAE6FF"),
                    Text(f"{value:,}", style="bold #B57BFF"),
                    _status(state),
                    detail,
                ),
                f"{name} {value} {state} {detail}",
                f"# {name}\n\n**Value:** {value:,}\n\n**State:** {state}\n\n{detail}",
            )
            for index, (name, value, state, detail) in enumerate(metrics)
        ]
        return ViewData(
            "Overview",
            "Local readiness and demo inventory",
            (
                Column("metric", "METRIC", 26),
                Column("value", "VALUE", 12),
                Column("state", "STATE", 12),
                Column("detail", "DETAIL", 48),
            ),
            rows,
        )

    def _campaigns(self) -> ViewData:
        rows = []
        for session in self.db.get_pipeline_sessions(100):
            params = session.get("params") or {}
            detection = params.get("detection") or {}
            stages = params.get("stages") or []
            reports = params.get("report_sources") or []
            coverage = detection.get("coverage_pct")
            rows.append(
                _row(
                    session.get("session_id", ""),
                    (
                        Text(session.get("session_id", ""), style="bold #B57BFF"),
                        session.get("actor_id", ""),
                        len(stages),
                        _coverage(coverage),
                        len(detection.get("gaps") or []),
                        len(reports),
                        _status(session.get("status")),
                    ),
                    " ".join(
                        [
                            str(session.get("session_id") or ""),
                            str(session.get("actor_id") or ""),
                            str(session.get("status") or ""),
                            str(coverage or ""),
                            " ".join(stage.get("ttp_id", "") for stage in stages),
                            " ".join(stage.get("ttp_name", "") for stage in stages),
                        ]
                    ),
                    lambda item=session: self._campaign_detail(item),
                    record=session,
                    url=next(
                        (
                            report.get("url")
                            for report in reports
                            if str(report.get("url", "")).startswith(
                                ("http://", "https://")
                            )
                        ),
                        "",
                    ),
                )
            )
        return ViewData(
            "APT Campaigns",
            "Simulation sessions with hunt and detection context",
            (
                Column("session", "SESSION", 8),
                Column("actor", "ACTOR / FAMILY", 18),
                Column("stages", "STAGES", 6),
                Column("coverage", "COVERAGE", 8),
                Column("gaps", "GAPS", 5),
                Column("reports", "REPORTS", 7),
                Column("status", "STATUS", 8),
            ),
            rows,
        )

    def _campaign_detail(self, session: dict[str, Any]) -> str:
        params = session.get("params") or {}
        stages = params.get("stages") or []
        detection = params.get("detection") or {}
        reports = params.get("report_sources") or []
        lines = [
            f"# {_md(session.get('actor_id') or 'Campaign')}",
            "",
            (
                f"`{_md(session.get('session_id'))}`  "
                f"**{_md(session.get('status'))}**  "
                f"coverage **{detection.get('coverage_pct', '-')}%**"
            ),
            "",
            "## Kill chain",
            "",
        ]
        for index, stage in enumerate(stages, 1):
            overlay = stage.get("detection") or {}
            coverage = (
                f"{overlay.get('sigma_count', 0)} Sigma"
                if overlay.get("covered")
                else "gap"
            )
            technique = f"{_md(stage.get('ttp_id'))} {_md(stage.get('ttp_name'))}"
            module = stage.get("module_slug") or stage.get("module_id") or "-"
            lines.extend(
                [
                    f"**{index:02}. {technique}**",
                    "",
                    f"`{_md(stage.get('tactic'))}`  `{_md(coverage)}`  ",
                    f"`{_md(module)}`",
                    "",
                ]
            )
        if stages:
            lines.extend(["", "## Evidence", ""])
            for stage in stages:
                evidence = _clean(stage.get("evidence"), 500)
                if evidence:
                    lines.extend(
                        [
                            f"**{_md(stage.get('ttp_id'))} {_md(stage.get('ttp_name'))}**",
                            "",
                            evidence,
                            "",
                        ]
                    )
        if reports:
            lines.extend(["## Reports", ""])
            for report in reports[:12]:
                url = str(report.get("url") or "")
                label = _md(report.get("title") or url, 140)
                state = _md(report.get("status") or "cached")
                lines.append(
                    f"- [{label}]({url}) `{state}`" if url else f"- {label} `{state}`"
                )
        return "\n".join(lines)

    def _library(self) -> ViewData:
        rows = []
        for entry in self.db.get_mitre_entries():
            attack_ids = entry.get("attack_ids") or []
            rows.append(
                _row(
                    entry.get("slug", ""),
                    (
                        entry.get("date", ""),
                        Text(entry.get("slug", ""), style="bold #B57BFF"),
                        entry.get("category", ""),
                        Text(" ".join(attack_ids) or "-", style="#FFD166"),
                        _status("ready" if entry.get("implemented") else "source"),
                        entry.get("title", ""),
                    ),
                    " ".join(
                        [
                            entry.get("date", ""),
                            entry.get("slug", ""),
                            entry.get("category", ""),
                            entry.get("title", ""),
                            " ".join(attack_ids),
                        ]
                    ),
                    lambda item=entry: self._library_detail(item),
                    record=entry,
                    slug=entry.get("slug", ""),
                    url=entry.get("blog_url", ""),
                )
            )
        return ViewData(
            "Research Library",
            "Blog code, source paths and ATT&CK mappings",
            (
                Column("date", "DATE", 10),
                Column("slug", "SLUG", 24),
                Column("category", "CATEGORY", 12),
                Column("attack", "ATT&CK", 15),
                Column("state", "STATE", 8),
                Column("title", "TITLE", 30),
            ),
            rows,
        )

    def _library_detail(self, entry: dict[str, Any]) -> str:
        summary = self.db.get_kb_summary_for_slug(entry.get("slug", ""))
        source = str(entry.get("snippet") or "")
        source_lines = source.splitlines()[:45]
        suffix = "\n// ..." if len(source.splitlines()) > len(source_lines) else ""
        lines = [
            f"# {_md(entry.get('title') or entry.get('slug'))}",
            "",
            f"**Slug:** `{_md(entry.get('slug'))}`  ",
            f"**Category:** `{_md(entry.get('category'))}`  ",
            f"**ATT&CK:** `{_md(' '.join(entry.get('attack_ids') or []) or '-')}`  ",
            f"**Source:** `{_md(entry.get('src_path'))}`",
            "",
        ]
        if entry.get("blog_url"):
            lines.extend([f"[Open blog post]({entry['blog_url']})", ""])
        if summary:
            lines.extend(["## Brief", "", summary, ""])
        if source_lines:
            language = {
                ".c": "c",
                ".cc": "cpp",
                ".cpp": "cpp",
                ".py": "python",
                ".rs": "rust",
                ".asm": "nasm",
                ".s": "asm",
            }.get(Path(str(entry.get("src_path") or "")).suffix.lower(), "text")
            lines.extend(
                [
                    "## Source preview",
                    "",
                    f"```{language}",
                    "\n".join(source_lines) + suffix,
                    "```",
                ]
            )
        return "\n".join(lines)

    def _attack(self) -> ViewData:
        rows = []
        for item in self.db.get_ttp_implementations():
            rows.append(
                _row(
                    f"{item.get('attack_id')}:{item.get('blog_slug')}",
                    (
                        Text(item.get("attack_id", ""), style="bold #FF7875"),
                        _tactic(item.get("tactic")),
                        item.get("platform", ""),
                        Text(item.get("blog_slug", ""), style="#B57BFF"),
                        item.get("tech_name", ""),
                    ),
                    " ".join(
                        str(item.get(key) or "")
                        for key in (
                            "attack_id",
                            "tech_name",
                            "tactic",
                            "platform",
                            "blog_slug",
                            "notes",
                        )
                    ),
                    lambda record=item: self._attack_detail(record),
                    record=item,
                    slug=item.get("blog_slug", ""),
                    url=item.get("blog_url", ""),
                )
            )
        return ViewData(
            "MITRE ATT&CK",
            "Techniques with local code implementations",
            (
                Column("id", "TECHNIQUE", 13),
                Column("tactic", "TACTIC", 22),
                Column("platform", "PLATFORM", 11),
                Column("module", "IMPLEMENTATION", 30),
                Column("name", "NAME", 42),
            ),
            rows,
        )

    def _attack_detail(self, item: dict[str, Any]) -> str:
        attack_id = item.get("attack_id", "")
        implementations = self.db.get_ttp_by_attack_id(attack_id)
        detection = self.db.get_artifact_entry(attack_id)
        summary = self.db.get_artifact_summary(attack_id)
        lines = [
            f"# {attack_id} {_md(item.get('tech_name'))}",
            "",
            f"**Tactic:** `{_md(item.get('tactic'))}`  ",
            f"**Platform:** `{_md(item.get('platform'))}`",
            "",
        ]
        if summary:
            lines.extend(["## Detection brief", "", summary, ""])
        if item.get("notes"):
            lines.extend(["## Notes", "", str(item["notes"]), ""])
        lines.extend(
            [
                "## Local implementations",
                "",
            ]
        )
        for implementation in implementations:
            url = implementation.get("blog_url")
            slug = _md(implementation.get("blog_slug"))
            platform = _md(implementation.get("platform"))
            lines.append(
                f"- [`{slug}`]({url}) `{platform}`"
                if url
                else f"- `{slug}` `{platform}`"
            )
        if detection:
            lines.extend(
                [
                    "",
                    "## Detection coverage",
                    "",
                    f"**{detection.get('rule_count', 0)} Sigma rules**  ",
                    f"Event IDs: `{_md(', '.join(map(str, detection.get('event_ids') or [])))}`",
                ]
            )
        return "\n".join(lines)

    def _detection(self) -> ViewData:
        rows = []
        for entry in self.db.get_artifact_entries():
            rows.append(
                _row(
                    entry.get("tid", ""),
                    (
                        Text(entry.get("tid", ""), style="bold #FF7875"),
                        entry.get("name", ""),
                        _tactic(entry.get("tactic")),
                        Text(str(entry.get("rule_count", 0)), style="bold #56D98A"),
                        len(entry.get("event_ids") or []),
                        len(entry.get("processes") or []),
                    ),
                    " ".join(
                        [
                            entry.get("tid", ""),
                            entry.get("name", ""),
                            entry.get("tactic", ""),
                            " ".join(map(str, entry.get("event_ids") or [])),
                            " ".join(entry.get("processes") or []),
                        ]
                    ),
                    lambda record=entry: self._detection_detail(record),
                    record=entry,
                )
            )
        return ViewData(
            "Detection Engineering",
            "ATT&CK x Sigma coverage, Event IDs and telemetry",
            (
                Column("id", "TECHNIQUE", 13),
                Column("name", "NAME", 38),
                Column("tactic", "TACTIC", 28),
                Column("rules", "SIGMA", 9),
                Column("events", "EVENTS", 9),
                Column("processes", "PROCS", 8),
            ),
            rows,
        )

    def _detection_detail(self, entry: dict[str, Any]) -> str:
        summary = self.db.get_artifact_summary(entry.get("tid", ""))
        lines = [
            f"# {_md(entry.get('tid'))} {_md(entry.get('name'))}",
            "",
            f"**Tactic:** `{_md(entry.get('tactic'))}`  ",
            f"**Sigma rules:** **{entry.get('rule_count', 0)}**  ",
            f"**Event IDs:** `{_md(', '.join(map(str, entry.get('event_ids') or [])) or '-')}`",
            "",
        ]
        if summary:
            lines.extend(["## Detection brief", "", summary, ""])
        for title, values in (
            ("Processes", entry.get("processes") or []),
            ("Registry keys", entry.get("reg_keys") or []),
            ("Command lines", entry.get("cmdlines") or []),
        ):
            if values:
                lines.extend([f"## {title}", ""])
                lines.extend(f"- `{_md(value, 180)}`" for value in values[:18])
                lines.append("")
        rules = entry.get("rules") or []
        if rules:
            lines.extend(["## Sigma rules", ""])
            for rule in rules[:24]:
                if isinstance(rule, dict):
                    lines.append(
                        f"- **{_md(rule.get('title') or 'Untitled')}** "
                        f"`{_md(rule.get('level') or 'unknown')}`"
                    )
                else:
                    lines.append(f"- {_md(rule)}")
        return "\n".join(lines)

    def _intel(self) -> ViewData:
        query = """
            SELECT subject_type, subject_id,
                   COUNT(DISTINCT report_url) AS reports,
                   COUNT(DISTINCT tid) AS techniques,
                   COUNT(*) AS evidence,
                   MAX(extracted_at) AS updated,
                   MIN(CASE
                         WHEN report_url LIKE 'http://%'
                           OR report_url LIKE 'https://%'
                         THEN report_url
                       END) AS first_url
            FROM report_ttps
            GROUP BY subject_type, subject_id
            ORDER BY reports DESC, techniques DESC, subject_id
        """
        with self._connect() as connection:
            entities = [dict(row) for row in connection.execute(query).fetchall()]
        rows = []
        for entity in entities:
            rows.append(
                _row(
                    f"{entity.get('subject_type')}:{entity.get('subject_id')}",
                    (
                        _status(entity.get("subject_type")),
                        Text(entity.get("subject_id", ""), style="bold #B57BFF"),
                        entity.get("reports", 0),
                        entity.get("techniques", 0),
                        entity.get("evidence", 0),
                        _clean(entity.get("updated"), 19),
                    ),
                    " ".join(str(value or "") for value in entity.values()),
                    lambda record=entity: self._intel_detail(record),
                    record=entity,
                    url=entity.get("first_url") or "",
                )
            )
        return ViewData(
            "Threat Intelligence",
            "Precomputed actor and malware-family report evidence",
            (
                Column("type", "TYPE", 10),
                Column("entity", "ACTOR / FAMILY", 30),
                Column("reports", "REPORTS", 9),
                Column("techniques", "TTPS", 8),
                Column("evidence", "EVIDENCE", 10),
                Column("updated", "UPDATED", 20),
            ),
            rows,
        )

    def _intel_entries(self, entity: dict[str, Any]) -> list[dict[str, Any]]:
        return self.db.get_report_ttps(
            entity.get("subject_id", ""), entity.get("subject_type")
        )

    def _intel_detail(self, entity: dict[str, Any]) -> str:
        subject_type = entity.get("subject_type", "")
        subject_id = entity.get("subject_id", "")
        entries = self._intel_entries(entity)
        summary = (
            self.db.get_actor_summary(subject_id)
            if subject_type == "actor"
            else self.db.get_family_summary(subject_id)
        )
        lines = [
            f"# {_md(subject_id)}",
            "",
            f"**Type:** `{_md(subject_type)}`  ",
            f"**Reports:** **{entity.get('reports', 0)}**  ",
            f"**Techniques:** **{entity.get('techniques', 0)}**",
            "",
        ]
        if summary:
            lines.extend(["## Intelligence brief", "", summary, ""])
        lines.extend(
            [
                "## Report-derived techniques",
                "",
            ]
        )
        seen: set[tuple[str, str]] = set()
        for item in entries:
            marker = (item.get("tid", ""), item.get("evidence", ""))
            if marker in seen:
                continue
            seen.add(marker)
            lines.extend(
                [
                    (
                        f"**{_md(item.get('tid'))}** "
                        f"`{_md(item.get('tactic'))}` `{_md(item.get('confidence'))}`"
                    ),
                    "",
                    _clean(item.get("evidence"), 220),
                    "",
                ]
            )
            if len(seen) >= 28:
                break
        urls: list[str] = []
        for item in entries:
            url = str(item.get("report_url") or "")
            if url and url not in urls:
                urls.append(url)
        if urls:
            lines.extend(["", "## Reports", ""])
            lines.extend(f"- [{_md(url, 120)}]({url})" for url in urls[:14])
        return "\n".join(lines)

    def _builds(self) -> ViewData:
        rows = []
        for build in self.db.get_builds(200):
            params = build.get("params") or {}
            module = (
                params.get("slug")
                or params.get("malware")
                or params.get("payload")
                or "-"
            )
            rows.append(
                _row(
                    build.get("id", ""),
                    (
                        Text(build.get("id", ""), style="bold #B57BFF"),
                        module,
                        params.get("platform") or "-",
                        params.get("compiler") or "-",
                        _status(build.get("status")),
                        _clean(build.get("created"), 19),
                    ),
                    " ".join(
                        [
                            str(build.get("id") or ""),
                            str(module),
                            str(build.get("status") or ""),
                            json.dumps(params, default=str),
                        ]
                    ),
                    lambda record=build: self._build_detail(record),
                    record=build,
                    build_id=build.get("id", ""),
                )
            )
        return ViewData(
            "Build History",
            "Compiler results and generated artifacts",
            (
                Column("id", "BUILD", 14),
                Column("module", "MODULE", 30),
                Column("platform", "PLATFORM", 11),
                Column("compiler", "COMPILER", 13),
                Column("status", "STATUS", 11),
                Column("created", "CREATED", 20),
            ),
            rows,
        )

    def _build_detail(self, build: dict[str, Any]) -> str:
        output = re.sub(r"\x1b\[[0-9;]*m", "", str(build.get("output") or ""))
        lines = [
            f"# Build {_md(build.get('id'))}",
            "",
            f"**Status:** `{_md(build.get('status'))}`  ",
            f"**Created:** `{_md(build.get('created'))}`  ",
            f"**Return code:** `{build.get('returncode', '-')}`",
            "",
            "## Parameters",
            "",
            "```json",
            json.dumps(
                build.get("params") or {}, ensure_ascii=False, indent=2, default=str
            ),
            "```",
        ]
        if output:
            lines.extend(
                [
                    "",
                    "## Compiler output",
                    "",
                    "```text",
                    "\n".join(output.splitlines()[-45:]),
                    "```",
                ]
            )
        return "\n".join(lines)

    def _samples(self) -> ViewData:
        rows = []
        for sample in self.db.get_samples(200):
            files = sample.get("files") or []
            rows.append(
                _row(
                    sample.get("session_id", ""),
                    (
                        Text(sample.get("session_id", ""), style="bold #B57BFF"),
                        sample.get("actor", ""),
                        sample.get("ttps", 0),
                        len(files),
                        _human_size(sample.get("total_size", 0)),
                        _status(sample.get("status")),
                        _clean(sample.get("created"), 19),
                    ),
                    " ".join(
                        [
                            str(sample.get("session_id") or ""),
                            str(sample.get("actor") or ""),
                            " ".join(file.get("name", "") for file in files),
                            str(sample.get("status") or ""),
                        ]
                    ),
                    lambda record=sample: self._sample_detail(record),
                    record=sample,
                )
            )
        return ViewData(
            "Compiled Samples",
            "Campaign artifacts stored in the local filesystem",
            (
                Column("session", "SESSION", 11),
                Column("actor", "ACTOR / FAMILY", 24),
                Column("ttps", "TTPS", 7),
                Column("files", "FILES", 8),
                Column("size", "SIZE", 11),
                Column("status", "STATUS", 11),
                Column("created", "CREATED", 20),
            ),
            rows,
        )

    def _sample_detail(self, sample: dict[str, Any]) -> str:
        lines = [
            f"# Sample {_md(sample.get('session_id'))}",
            "",
            f"**Actor / family:** `{_md(sample.get('actor'))}`  ",
            f"**Status:** `{_md(sample.get('status'))}`  ",
            f"**Techniques:** **{sample.get('ttps', 0)}**  ",
            f"**Total:** **{_human_size(sample.get('total_size', 0))}**",
            "",
            "## Files",
            "",
            "| Name | Size |",
            "|---|---:|",
        ]
        for file in sample.get("files") or []:
            lines.append(
                f"| `{_md(file.get('name'))}` | {_human_size(file.get('size', 0))} |"
            )
        return "\n".join(lines)

    def _tools(self) -> ViewData:
        tools = [
            (
                "AI Assistant",
                "a",
                "interactive",
                "Ask project-specific questions with local blog grounding",
                "Press `a` to open the terminal AI assistant.",
            ),
            (
                "Module Builder",
                "b",
                "local write",
                "Compile the selected Research Library module",
                (
                    "Select a module in **Research Library**, then press `b`. "
                    "The build starts only after confirmation."
                ),
            ),
            (
                "YARA Generator",
                "y",
                "local",
                "Generate a rule from a selected successful build",
                "Select a row in **Build History**, then press `y`.",
            ),
            (
                "Shellcode Lab",
                "-",
                "classic CLI",
                "Analyse, transform and convert byte payloads",
                (
                    "```bash\npeekaboo shellcode analyse payload.bin\n"
                    "peekaboo shellcode convert payload.bin --to python\n```"
                ),
            ),
            (
                "VirusTotal",
                "-",
                "explicit network",
                "Lookup hashes or upload a build with consent",
                (
                    "```bash\npeekaboo vtscan lookup <sha256>\n"
                    "peekaboo vtscan scan <build-id> --yes\n```"
                ),
            ),
            (
                "Demo Doctor",
                "-",
                "read only",
                "Verify database, campaign assets and toolchain",
                "```bash\npeekaboo doctor --demo\n```",
            ),
            (
                "Web Dashboard",
                "-",
                "local service",
                "Run the browser dashboard on localhost",
                "```bash\npython3 dashboard/app.py\n```",
            ),
        ]
        rows = [
            _row(
                f"tool-{index}",
                (
                    Text(name, style="bold #EAE6FF"),
                    Text(key, style="bold #B57BFF"),
                    mode,
                    description,
                ),
                f"{name} {key} {mode} {description}",
                f"# {name}\n\n{description}\n\n{detail}",
            )
            for index, (name, key, mode, description, detail) in enumerate(tools)
        ]
        return ViewData(
            "Toolkit",
            "Interactive actions and classic command workflows",
            (
                Column("tool", "TOOL", 24),
                Column("key", "KEY", 7),
                Column("mode", "MODE", 18),
                Column("description", "WORKFLOW", 60),
            ),
            rows,
        )


class DetailScreen(ModalScreen[None]):
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "close", "Close", show=False),
        Binding("q", "close", "Close", show=False),
    ]

    def __init__(self, title: str, content: str) -> None:
        super().__init__()
        self.detail_title = title
        self.content = content

    def compose(self) -> ComposeResult:
        with Vertical(id="detail-dialog"):
            yield Static(self.detail_title, id="dialog-title", markup=False)
            yield Markdown(self.content, id="dialog-content")
            yield Static("esc close  |  arrows/page keys scroll", id="dialog-keybar")

    def action_close(self) -> None:
        self.dismiss()


class SourceScreen(Screen):
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "close", "Close", show=False),
        Binding("q", "close", "Close", show=False),
    ]

    def __init__(
        self,
        title: str,
        source_path: str,
        source: str,
        language: str,
    ) -> None:
        super().__init__()
        self.source_title = title
        self.source_path = source_path
        self.source = source
        self.language = language

    def compose(self) -> ComposeResult:
        line_count = len(self.source.splitlines())
        yield Static(f"SOURCE  /  {self.source_title}", id="source-title", markup=False)
        yield Static(
            f"{self.source_path}  |  {self.language.upper()}  |  {line_count:,} lines",
            id="source-meta",
            markup=False,
        )
        yield RichLog(
            min_width=80,
            wrap=False,
            highlight=False,
            markup=False,
            auto_scroll=False,
            id="source-code",
        )
        yield Static(
            "esc close  |  arrows scroll  |  page up/down  |  ctrl+page left/right",
            id="source-keybar",
            markup=False,
        )

    def on_mount(self) -> None:
        gutter = len(str(max(1, len(self.source.splitlines())))) + 4
        width = max(
            80,
            min(
                2000,
                max(
                    (len(line.expandtabs(4)) for line in self.source.splitlines()),
                    default=0,
                )
                + gutter,
            ),
        )
        source_log = self.query_one("#source-code", RichLog)
        source_log.write(
            Syntax(
                self.source,
                self.language,
                theme="monokai",
                line_numbers=True,
                word_wrap=False,
                indent_guides=True,
                background_color="#272822",
                padding=(1, 2),
            ),
            width=width,
            shrink=False,
            scroll_end=False,
        )
        source_log.focus()

    def action_close(self) -> None:
        self.app.pop_screen()


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("y", "confirm", "Confirm", show=False),
        Binding("n", "cancel", "Cancel", show=False),
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, title: str, message: str) -> None:
        super().__init__()
        self.confirm_title = title
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Static(self.confirm_title, id="confirm-title", markup=False)
            yield Static(self.message, id="confirm-message", markup=False)
            with Horizontal(id="confirm-buttons"):
                yield Button("Build", variant="primary", id="confirm-yes")
                yield Button("Cancel", id="confirm-no")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-yes")


class AssistantScreen(Screen):
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "close", "Back", show=False),
        Binding("ctrl+l", "clear", "Clear", show=False),
    ]

    def __init__(self, *, offline: bool = False) -> None:
        super().__init__()
        self.offline = offline
        self.messages: list[dict[str, str]] = []
        self.partial = ""

    def compose(self) -> ComposeResult:
        yield Static(
            "PEEKABOO AI  |  local knowledge-grounded assistant", id="assistant-title"
        )
        yield Markdown(
            "# AI Assistant\n\nAsk about the framework, a technique, a campaign, "
            "or a local blog implementation.",
            id="assistant-chat",
        )
        yield Static("ready", id="assistant-status")
        yield Input(placeholder="Ask a technical question...", id="assistant-input")
        yield Static("enter send  |  ctrl+l clear  |  esc back", id="assistant-keybar")

    def on_mount(self) -> None:
        self.query_one("#assistant-input", Input).focus()

    def action_close(self) -> None:
        self.app.pop_screen()

    def action_clear(self) -> None:
        self.messages.clear()
        self.partial = ""
        self.query_one("#assistant-chat", Markdown).update(
            "# AI Assistant\n\nConversation cleared."
        )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        prompt = event.value.strip()
        if not prompt:
            return
        if len(prompt) > 4000:
            self.notify("Question is limited to 4,000 characters", severity="warning")
            return
        if self.offline and not re.search(r"what is peekaboo", prompt, re.IGNORECASE):
            self.notify("Offline mode blocks the Ollama request", severity="warning")
            return
        self.messages.append({"role": "user", "content": prompt})
        self.messages = self.messages[-20:]
        event.input.value = ""
        event.input.disabled = True
        self.partial = ""
        self._render_conversation()
        self.query_one("#assistant-status", Static).update("generating...")
        self._ask(list(self.messages))

    def _render_conversation(self) -> None:
        lines = ["# AI Assistant", ""]
        for message in self.messages:
            title = "You" if message["role"] == "user" else "Peekaboo"
            lines.extend([f"## {title}", "", message["content"], ""])
        if self.partial:
            lines.extend(["## Peekaboo", "", self.partial])
        self.query_one("#assistant-chat", Markdown).update("\n".join(lines))

    def _show_partial(self, text: str) -> None:
        if self.is_mounted:
            self.partial = text
            self._render_conversation()

    def _set_status(self, status: str) -> None:
        if self.is_mounted:
            self.query_one("#assistant-status", Static).update(status)

    def _finish_response(self, text: str) -> None:
        if not self.is_mounted:
            return
        self.partial = ""
        self.messages.append({"role": "assistant", "content": text or "No response."})
        self.messages = self.messages[-20:]
        self._render_conversation()
        field = self.query_one("#assistant-input", Input)
        field.disabled = False
        field.focus()
        self.query_one("#assistant-status", Static).update("ready")

    @work(thread=True, exclusive=True, group="assistant")
    def _ask(self, messages: list[dict[str, str]]) -> None:
        try:
            import chatbot

            parts: list[str] = []
            update_at = 0
            for chunk in chatbot.stream_chat(messages):
                if isinstance(chunk, dict):
                    state = _clean(chunk.get("msg") or chunk.get("status"), 120)
                    self.app.call_from_thread(self._set_status, state)
                    continue
                parts.append(str(chunk))
                if len(parts) >= update_at + 8:
                    update_at = len(parts)
                    self.app.call_from_thread(self._show_partial, "".join(parts))
            self.app.call_from_thread(self._finish_response, "".join(parts))
        except Exception as exc:  # noqa: BLE001 - UI boundary must surface backend errors
            self.app.call_from_thread(
                self._finish_response, f"Assistant error: {_clean(exc, 500)}"
            )


NAV_ITEMS = (
    ("overview", "1  Overview"),
    ("campaigns", "2  APT Campaigns"),
    ("library", "3  Research Library"),
    ("attack", "4  MITRE ATT&CK"),
    ("detection", "5  Detection"),
    ("intel", "6  Threat Intel"),
    ("builds", "7  Build History"),
    ("samples", "8  Samples"),
    ("tools", "9  Toolkit"),
)

HELP_TEXT = """\
# Peekaboo terminal navigation

| Key | Action |
|---|---|
| `1`...`9` | Switch workspace |
| `[` / `]` | Previous / next workspace |
| `/` | Focus live search |
| `up` / `down`, `j` / `k` | Move through rows |
| `g` / `G` | First / last row |
| `enter` | Open the selected record |
| `s` | View source for a Library or ATT&CK implementation |
| `o` | Open the selected public URL |
| `b` | Build selected Research Library module |
| `y` | Generate YARA for selected successful build |
| `a` | Open AI Assistant |
| `r` | Reload the current workspace |
| `?` | Show this help |
| `q` | Quit |

Search is case-insensitive. Space-separated terms use AND matching, as in
`injection windows T1055`.
"""


class PeekabooApp(App[None]):
    TITLE = "Peekaboo"
    SUB_TITLE = "Threat Research and Detection Engineering Lab"
    ENABLE_COMMAND_PALETTE = False

    CSS = """
    Screen { background: #15121E; color: #EAE6FF; }
    #topbar {
        dock: top; height: 3; background: #15121E;
        border-bottom: solid #3D3860;
    }
    #brand {
        width: 21; height: 3; content-align: center middle;
        background: #B57BFF; color: #15121E; text-style: bold;
    }
    #app-title {
        width: 1fr; height: 3; content-align: left middle;
        padding-left: 2; color: #EAE6FF; text-style: bold;
    }
    #health {
        width: auto; min-width: 52; height: 3; content-align: right middle;
        padding: 0 2; color: #8A85A8;
    }
    #shell { height: 1fr; layout: horizontal; }
    #sidebar {
        width: 25; background: #1E1B2E; border-right: solid #3D3860;
    }
    .section-label {
        height: 3; padding: 1 2 0 2; color: #8A85A8; text-style: bold;
    }
    #nav {
        height: 1fr; padding: 0 1; background: transparent; border: none;
    }
    OptionList > .option-list--option { padding: 0 1; color: #B8B3D0; }
    OptionList > .option-list--option-highlighted {
        background: #312D52; color: #B57BFF; text-style: bold;
    }
    #scope {
        height: 3; padding: 1 2; color: #56D98A;
        border-top: solid #3D3860;
    }
    #workspace { width: 1fr; height: 1fr; }
    #viewbar {
        height: 4; padding: 0 2; background: #15121E;
        border-bottom: solid #3D3860;
    }
    #view-title {
        width: 1fr; height: 4; content-align: left middle;
        color: #EAE6FF; text-style: bold;
    }
    #search {
        width: 38; height: 3; margin-top: 1;
        background: #272440; border: tall #3D3860;
    }
    #search:focus { border: tall #B57BFF; }
    Input > .input--placeholder { color: #8A85A8; }
    #view-subtitle {
        height: 2; padding: 0 2; color: #8A85A8; content-align: left middle;
    }
    #body { height: 1fr; layout: horizontal; }
    #table { width: 5fr; height: 1fr; background: #15121E; border: none; }
    DataTable > .datatable--header {
        background: #272440; color: #8A85A8; text-style: bold;
    }
    DataTable > .datatable--cursor { background: #312D52; color: #EAE6FF; }
    DataTable > .datatable--even-row { background: #1E1B2E; }
    DataTable > .datatable--odd-row { background: #15121E; }
    #detail {
        width: 3fr; height: 1fr; padding: 1 2; background: #1E1B2E;
        border-left: solid #3D3860; scrollbar-color: #B57BFF;
        scrollbar-background: #272440;
    }
    #keybar, #assistant-keybar, #source-keybar {
        dock: bottom; height: 1; padding: 0 2;
        background: #272440; color: #8A85A8;
    }
    #shell.compact #sidebar, #shell.compact #detail { display: none; }
    #shell.compact #search { width: 30; }
    #shell.compact #table { width: 1fr; }
    DetailScreen, ConfirmScreen {
        align: center middle; background: #0C0A14BA;
    }
    #detail-dialog {
        width: 86%; height: 86%; background: #1E1B2E;
        border: solid #B57BFF;
    }
    #dialog-title {
        height: 3; padding: 1 2; background: #272440;
        color: #EAE6FF; text-style: bold;
    }
    #dialog-content { height: 1fr; padding: 1 2; }
    #dialog-keybar {
        height: 1; padding: 0 2; background: #272440; color: #8A85A8;
    }
    #confirm-dialog {
        width: 62; height: 13; padding: 1 2;
        background: #1E1B2E; border: solid #FFD166;
    }
    #confirm-title { height: 2; color: #FFD166; text-style: bold; }
    #confirm-message { height: 1fr; color: #EAE6FF; }
    #confirm-buttons { height: 3; align-horizontal: right; }
    #confirm-buttons Button { margin-left: 1; min-width: 12; }
    #assistant-title {
        dock: top; height: 3; padding: 0 2; background: #1E1B2E;
        content-align: left middle;
        color: #B57BFF; text-style: bold; border-bottom: solid #3D3860;
    }
    #assistant-chat { height: 1fr; padding: 1 3; background: #15121E; }
    #assistant-status { height: 1; padding: 0 2; color: #8A85A8; }
    #assistant-input {
        dock: bottom; height: 3; margin: 0 2 1 2;
        background: #272440; border: tall #B57BFF;
    }
    SourceScreen { background: #15121E; }
    #source-title {
        height: 3; padding: 0 2; background: #1E1B2E;
        content-align: left middle;
        color: #B57BFF; text-style: bold; border-bottom: solid #3D3860;
    }
    #source-meta {
        height: 2; padding: 0 2; background: #15121E;
        color: #8A85A8; content-align: left middle;
    }
    #source-code {
        height: 1fr; padding: 0 1; background: #272822; color: #F8F8F2;
        border-top: solid #3D3860; border-bottom: solid #3D3860;
        scrollbar-color: #B57BFF; scrollbar-background: #1E1B2E;
    }
    """

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("q", "quit", "Quit", show=False),
        Binding("?", "help", "Help", show=False),
        Binding("/", "search", "Search", show=False),
        Binding("escape", "escape", "Back", show=False),
        Binding("[", "previous_view", "Previous", show=False),
        Binding("]", "next_view", "Next", show=False),
        Binding("r", "refresh", "Refresh", show=False),
        Binding("a", "assistant", "Assistant", show=False),
        Binding("b", "build", "Build", show=False),
        Binding("s", "source", "Source", show=False),
        Binding("y", "yara", "YARA", show=False),
        Binding("o", "open_url", "Open URL", show=False),
        Binding("1", "view('overview')", "Overview", show=False),
        Binding("2", "view('campaigns')", "Campaigns", show=False),
        Binding("3", "view('library')", "Library", show=False),
        Binding("4", "view('attack')", "ATT&CK", show=False),
        Binding("5", "view('detection')", "Detection", show=False),
        Binding("6", "view('intel')", "Intel", show=False),
        Binding("7", "view('builds')", "Builds", show=False),
        Binding("8", "view('samples')", "Samples", show=False),
        Binding("9", "view('tools')", "Toolkit", show=False),
    ]

    def __init__(
        self,
        repository: PeekabooRepository | None = None,
        *,
        initial_view: str = "overview",
        offline: bool = False,
    ) -> None:
        super().__init__()
        self.repository = repository or PeekabooRepository()
        self.current_view = (
            initial_view if initial_view in dict(NAV_ITEMS) else "overview"
        )
        self.offline = offline
        self.view_data = ViewData("", "", (), [])
        self.visible_rows: list[dict[str, Any]] = []
        self.pending_build_slug = ""

    def compose(self) -> ComposeResult:
        with Horizontal(id="topbar"):
            yield Static("PEEKABOO", id="brand", markup=False)
            yield Static(self.SUB_TITLE, id="app-title", markup=False)
            yield Static("", id="health", markup=False)
        with Horizontal(id="shell"):
            with Vertical(id="sidebar"):
                yield Static("NAVIGATION", classes="section-label")
                yield OptionList(
                    *(Option(label, id=view) for view, label in NAV_ITEMS),
                    id="nav",
                )
                yield Static("LOCAL DATA  /  OFFLINE READY", id="scope", markup=False)
            with Vertical(id="workspace"):
                with Horizontal(id="viewbar"):
                    yield Static("", id="view-title", markup=False)
                    yield Input(placeholder="/ search current view", id="search")
                yield Static("", id="view-subtitle", markup=False)
                with Horizontal(id="body"):
                    yield DataTable(
                        id="table",
                        cursor_type="row",
                        zebra_stripes=True,
                        show_row_labels=False,
                    )
                    yield Markdown("", id="detail")
        yield Static(
            "1-9 views  / search  enter detail  s source  a assistant  b build  "
            "y yara  r reload  ? help  q quit",
            id="keybar",
            markup=False,
        )

    def on_mount(self) -> None:
        self._apply_viewport(self.size.width)
        self.query_one("#health", Static).update(self.repository.header_status())
        self.show_view(self.current_view)
        self.query_one("#table", DataTable).focus()

    def on_resize(self, event: Resize) -> None:
        self._apply_viewport(event.size.width)

    def _apply_viewport(self, width: int) -> None:
        self.query_one("#shell", Horizontal).set_class(width < 112, "compact")
        self.query_one("#health", Static).display = width >= 96

    def show_view(self, view: str) -> None:
        if view not in dict(NAV_ITEMS):
            return
        self.current_view = view
        self.view_data = self.repository.load(view)
        self.query_one("#nav", OptionList).highlighted = [
            item[0] for item in NAV_ITEMS
        ].index(view)
        self.query_one("#search", Input).value = ""
        self._populate_table()

    def _populate_table(self) -> None:
        query = self.query_one("#search", Input).value.strip().lower()
        terms = query.split()
        self.visible_rows = [
            row
            for row in self.view_data.rows
            if not terms or all(term in row["search"] for term in terms)
        ]
        self.query_one("#view-title", Static).update(
            f"{self.view_data.title}  [{len(self.visible_rows):,}]"
        )
        subtitle = self.view_data.subtitle + (f"  |  filter: {query}" if query else "")
        self.query_one("#view-subtitle", Static).update(subtitle)

        table = self.query_one("#table", DataTable)
        table.clear(columns=True)
        for column in self.view_data.columns:
            table.add_column(column.title, key=column.key, width=column.width)
        for index, row in enumerate(self.visible_rows):
            table.add_row(*row["cells"], key=f"{index}:{row['key']}")
        if self.visible_rows:
            table.move_cursor(row=0, column=0)
            self.call_later(self._update_detail, 0)
        else:
            self.query_one("#detail", Markdown).update(
                "# No results\n\nChange or clear the current search."
            )

    def _current_row(self) -> dict[str, Any] | None:
        if not self.visible_rows:
            return None
        index = max(
            0,
            min(
                self.query_one("#table", DataTable).cursor_row,
                len(self.visible_rows) - 1,
            ),
        )
        return self.visible_rows[index]

    def _detail_content(self, row: dict[str, Any]) -> str:
        try:
            detail = row["detail"]
            return detail() if callable(detail) else detail
        except Exception as exc:  # noqa: BLE001 - one bad detail must not crash the TUI
            return f"# Detail unavailable\n\n`{_md(exc, 500)}`"

    def _update_detail(self, index: int) -> None:
        if 0 <= index < len(self.visible_rows):
            self.query_one("#detail", Markdown).update(
                self._detail_content(self.visible_rows[index])
            )

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.show_view(event.option.id)
            self.query_one("#table", DataTable).focus()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._update_detail(event.cursor_row)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if 0 <= event.cursor_row < len(self.visible_rows):
            self.push_screen(
                DetailScreen(
                    self.view_data.title,
                    self._detail_content(self.visible_rows[event.cursor_row]),
                )
            )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search" and self.is_mounted:
            self._populate_table()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search":
            self.query_one("#table", DataTable).focus()

    def on_key(self, event: Key) -> None:
        table = self.query_one("#table", DataTable)
        if not table.has_focus:
            return
        if event.key == "j":
            table.action_cursor_down()
            event.stop()
        elif event.key == "k":
            table.action_cursor_up()
            event.stop()
        elif event.key == "g":
            table.move_cursor(row=0)
            event.stop()
        elif event.key == "G":
            table.move_cursor(row=max(0, len(self.visible_rows) - 1))
            event.stop()

    def action_view(self, view: str) -> None:
        self.show_view(view)
        self.query_one("#table", DataTable).focus()

    def action_previous_view(self) -> None:
        views = [item[0] for item in NAV_ITEMS]
        self.action_view(views[(views.index(self.current_view) - 1) % len(views)])

    def action_next_view(self) -> None:
        views = [item[0] for item in NAV_ITEMS]
        self.action_view(views[(views.index(self.current_view) + 1) % len(views)])

    def action_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_escape(self) -> None:
        search = self.query_one("#search", Input)
        if search.has_focus:
            search.value = ""
            self.query_one("#table", DataTable).focus()

    def action_refresh(self) -> None:
        self.view_data = self.repository.load(self.current_view)
        self.query_one("#health", Static).update(self.repository.header_status())
        self._populate_table()
        self.notify(f"{self.view_data.title} reloaded")

    def action_help(self) -> None:
        self.push_screen(DetailScreen("Keyboard reference", HELP_TEXT))

    def action_assistant(self) -> None:
        self.push_screen(AssistantScreen(offline=self.offline))

    def action_open_url(self) -> None:
        row = self._current_row()
        url = str((row or {}).get("context", {}).get("url") or "")
        if not url.startswith(("http://", "https://")):
            self.notify("Selected record has no public URL", severity="warning")
        elif webbrowser.open(url):
            self.notify("Opened public URL")
        else:
            self.notify("Could not open a browser", severity="error")

    def action_source(self) -> None:
        row = self._current_row()
        context = (row or {}).get("context", {})
        record = context.get("record") or {}
        if self.current_view not in {"library", "attack"}:
            self.notify(
                "Source is available in Research Library and MITRE ATT&CK",
                severity="warning",
            )
            return

        slug = str(
            context.get("slug") or record.get("slug") or record.get("blog_slug") or ""
        )
        if not record.get("src_path") and slug:
            source_record = getattr(self.repository, "source_record", None)
            if callable(source_record):
                record = source_record(slug) or record

        resolved_path = _resolve_source_path(record.get("src_path"))
        source = ""
        if resolved_path is not None:
            try:
                source = resolved_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.notify(
                    f"Could not read source: {_clean(exc, 180)}", severity="error"
                )
                return
        if not source:
            source = str(record.get("snippet") or "")
        if not source:
            self.notify(
                "Selected implementation has no local source", severity="warning"
            )
            return

        source_path = resolved_path or Path(str(record.get("src_path") or "snippet"))
        self.push_screen(
            SourceScreen(
                str(record.get("title") or slug or "Source"),
                str(source_path),
                source,
                _source_language(source_path, source),
            )
        )

    def action_build(self) -> None:
        row = self._current_row()
        slug = str((row or {}).get("context", {}).get("slug") or "")
        if self.current_view != "library" or not slug:
            self.notify("Select a Research Library module first", severity="warning")
            return
        self.pending_build_slug = slug
        self.push_screen(
            ConfirmScreen(
                "Compile research module",
                f"Build {slug} with the configured local toolchain?",
            ),
            self._confirmed_build,
        )

    def _confirmed_build(self, confirmed: bool | None) -> None:
        if confirmed and self.pending_build_slug:
            slug = self.pending_build_slug
            self.pending_build_slug = ""
            self.notify(f"Building {slug}...")
            self._run_build(slug)

    @work(thread=True, exclusive=True, group="local-action")
    def _run_build(self, slug: str) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(BASE / "peekaboo_cli.py"),
                "--json",
                "builder",
                "build",
                slug,
            ],
            cwd=BASE,
            env=os.environ.copy(),
            text=True,
            capture_output=True,
            check=False,
            timeout=180,
        )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            payload = {
                "id": "",
                "status": "failed",
                "output": result.stderr or result.stdout or "build returned no output",
            }
        self.app.call_from_thread(self._local_action_finished, "Build", payload)

    def action_yara(self) -> None:
        row = self._current_row()
        build_id = str((row or {}).get("context", {}).get("build_id") or "")
        if self.current_view != "builds" or not build_id:
            self.notify("Select a row in Build History first", severity="warning")
            return
        record = (row or {}).get("context", {}).get("record") or {}
        if record.get("status") != "success":
            self.notify("YARA requires a successful build", severity="warning")
            return
        self.notify(f"Generating YARA for {build_id}...")
        self._run_yara(build_id)

    @work(thread=True, exclusive=True, group="local-action")
    def _run_yara(self, build_id: str) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(BASE / "peekaboo_cli.py"),
                "--json",
                "yara",
                "gen-build",
                build_id,
            ],
            cwd=BASE,
            env=os.environ.copy(),
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            payload = {
                "ok": False,
                "error": result.stderr or result.stdout or "YARA returned no output",
            }
        self.app.call_from_thread(self._local_action_finished, "YARA", payload)

    def _local_action_finished(self, title: str, payload: dict[str, Any]) -> None:
        ok = payload.get("ok")
        if ok is None:
            ok = payload.get("status") == "success"
        if title == "YARA" and ok:
            body = (
                "# YARA generated\n\n```yara\n"
                f"{payload.get('rule') or payload.get('yara') or ''}\n```"
            )
        else:
            output = str(payload.get("output") or payload.get("error") or "")
            if len(output) > 8000:
                output = "... " + output[-8000:]
            body = (
                f"# {title} {'completed' if ok else 'failed'}\n\n```text\n{output}\n```"
            )
        self.push_screen(DetailScreen(title, body))
        self.query_one("#health", Static).update(self.repository.header_status())


def launch_tui(
    *,
    initial_view: str = "overview",
    db_path: Path | None = None,
    offline: bool = False,
) -> int:
    repository = PeekabooRepository(db_path)
    PeekabooApp(repository, initial_view=initial_view, offline=offline).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch_tui())
