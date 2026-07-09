#!/usr/bin/env python3
# command-first CLI for peekaboo.
# The CLI intentionally stays thin: it loads data from dashboard modules, renders
# compact Rich tables, and prints a small set of next-step hints.
# author: @cocomelonc

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

BASE = Path(__file__).resolve().parent
DASHBOARD = BASE / "dashboard"
sys.path.insert(0, str(DASHBOARD))

VERSION = "2026.07"
PAGE = 20

THEME = Theme(
    {
        "heading": "bold bright_white",
        "nav": "bold cyan",
        "meta": "grey70",
        "ok": "green",
        "warn": "yellow",
        "err": "red",
        "intel": "magenta",
        "dim": "grey50",
    }
)

console = Console(theme=THEME, highlight=False)
PLAIN = False
CLI_BOX = box.ASCII
RULE_WIDTH = 78
COLOR_ENABLED = True


# ---------------------------------------------------------------------------
# small rendering/helpers
def _mark(kind: str) -> str:
    marks = {"ok": "+", "warn": "!", "err": "x"}
    return marks.get(kind, "")

def _icon(value: str) -> str:
    return "" if PLAIN else value

def _short(value: Any, width: int) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= width else text[: max(0, width - 1)] + "…"

def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Text):
        return value.plain
    return str(value)

def _emit_json(value: Any) -> None:
    console.print(json.dumps(value, ensure_ascii=False, indent=2, default=_json_default))

def _configure_console(no_color: bool = False) -> None:
    global console, COLOR_ENABLED
    COLOR_ENABLED = not no_color
    console = Console(
        theme=THEME,
        highlight=False,
        no_color=no_color,
        force_terminal=not no_color,
        color_system="truecolor" if not no_color else "auto",
    )

def _hint(*commands: str) -> None:
    seen: set[str] = set()
    clean = []
    for command in commands:
        if command and command not in seen:
            seen.add(command)
            clean.append(command)
    if not clean:
        return
    console.print()
    console.print(f"  [heading]{'Hint' if PLAIN else '? Try'}:[/heading]")
    for command in clean:
        console.print(f"  [nav]{command}[/nav]")
    console.print()

def _strip_markup(value: str) -> str:
    return Text.from_markup(value).plain

def _hash_header(title: str, subtitle: str | None = None, style: str = "cyan") -> None:
    clean = _strip_markup(title)
    width = max(28, min(RULE_WIDTH, len(clean) + 8))
    rule = "#" * width
    console.print()
    console.print(f"[{style}]{rule}[/{style}]")
    console.print(f"[{style}]#[/{style}] [heading]{title}[/heading]")
    if subtitle:
        console.print(f"[{style}]#[/{style}] [meta]{subtitle}[/meta]")
    console.print(f"[{style}]{rule}[/{style}]")

def _import(name: str):
    try:
        return __import__(name)
    except Exception as exc:
        console.print(f"[err]{_mark('err')} cannot load {name}: {exc}[/err]")
        return None

def _resolve(key: str, values: list[str] | dict[str, Any], label: str) -> str | None:
    candidates = list(values)
    if key in candidates:
        return key
    hits = [item for item in candidates if key.lower() in item.lower()]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        console.print(f"  [warn]{_mark('warn')} ambiguous {label}: {', '.join(hits[:6])}[/warn]\n")
        return None
    console.print(f"  [err]{_mark('err')} {label} not found: {key}[/err]\n")
    return None

def _status_panel(title: str, body: str, style: str = "cyan") -> None:
    _hash_header(title, style=style)
    console.print(body.rstrip())
    console.print()

def _table(title: str) -> Table:
    return Table(
        title=title,
        box=CLI_BOX,
        show_header=True,
        header_style="heading",
        border_style="grey35",
        padding=(0, 1),
    )

def _rich_help(raw: str) -> Text:
    text = Text()
    command_line = re.compile(r"^    ([a-z][\w-]*)(\s+.*)?$")
    usage_line = re.compile(r"^(usage: )(.+)$")

    for line in raw.splitlines():
        usage = usage_line.match(line)
        if usage:
            text.append(usage.group(1), style="heading")
            text.append(usage.group(2), style="nav")
            text.append("\n")
            continue
        if line.endswith(":") and not line.startswith(" "):
            text.append(line, style="heading")
            text.append("\n")
            continue
        if line.startswith("  -"):
            parts = re.split(r"(\s{2,})", line[2:], maxsplit=1)
            text.append("  ")
            text.append(parts[0], style="nav")
            if len(parts) > 1:
                text.append(parts[1], style="meta")
                text.append(parts[2], style="meta")
            text.append("\n")
            continue
        command = command_line.match(line)
        if command:
            text.append("    ")
            text.append(command.group(1), style="nav")
            text.append(command.group(2) or "", style="meta")
            text.append("\n")
            continue
        if "`" in line:
            parts = line.split("`")
            for i, part in enumerate(parts):
                text.append(part, style="nav" if i % 2 else "")
            text.append("\n")
            continue
        text.append(line)
        text.append("\n")
    return text

class ColorHelpParser(argparse.ArgumentParser):
    def print_help(self, file=None) -> None:
        raw = self.format_help()
        if COLOR_ENABLED and file is None:
            console.print(_rich_help(raw), end="")
            return
        target = file or sys.stdout
        target.write(raw)

# ---------------------------------------------------------------------------
# home / examples
def render_home() -> None:
    if PLAIN:
        console.print("PEEKABOO")
        console.print("Threat Research & Detection Engineering Lab\n")
        console.print("Explore")
        console.print("  library      Browse research modules")
        console.print("  malpedia     Threat actors, families and reports")
        console.print("  ttp          Explore MITRE ATT&CK techniques")
        console.print("  artifacts    ATT&CK x Sigma detection coverage\n")
        console.print("Tools")
        console.print("  yara         Generate and inspect YARA rules")
        console.print("  vtscan       VirusTotal analysis")
        console.print("  builder      Research module build workflow")
        console.print("  shellcode    Local binary analysis tools\n")
        console.print("Quick examples")
        console.print("  peekaboo malpedia search lazarus")
        console.print("  peekaboo malpedia reports --limit 10")
        console.print("  peekaboo ttp show T1055")
        console.print("  peekaboo artifacts rules T1059.001 --level high\n")
        console.print("Run `peekaboo <command> --help` or `peekaboo examples`.")
        return

    _hash_header("PEEKABOO", "Threat Research & Detection Engineering Lab")
    console.print()
    console.print("  [heading]Explore[/heading]\n")
    console.print("  > [nav]library[/nav]      Browse research modules")
    console.print("  > [nav]malpedia[/nav]     Threat actors, families and reports")
    console.print("  > [nav]ttp[/nav]          Explore MITRE ATT&CK techniques")
    console.print("  > [nav]artifacts[/nav]    ATT&CK x Sigma detection coverage")
    console.print()
    console.print("  [heading]Tools[/heading]\n")
    console.print("  > [nav]yara[/nav]         Generate and inspect YARA rules")
    console.print("  > [nav]vtscan[/nav]       VirusTotal analysis")
    console.print("  > [nav]builder[/nav]      Research module build workflow")
    console.print("  > [nav]shellcode[/nav]    Local binary analysis tools")
    console.print()
    console.print("  [heading]Quick examples[/heading]\n")
    console.print("  [dim]$[/dim] peekaboo malpedia search lazarus")
    console.print("  [dim]$[/dim] peekaboo malpedia reports --limit 10")
    console.print("  [dim]$[/dim] peekaboo ttp show T1055")
    console.print("  [dim]$[/dim] peekaboo artifacts rules T1059.001 --level high")
    console.print()
    console.print("  ? Run [nav]peekaboo <command> --help[/nav]")
    console.print("  > Run [nav]peekaboo examples[/nav]\n")

def render_examples() -> None:
    body = """\
{actor}[heading]Explore a threat actor[/heading]

  [nav]peekaboo malpedia search lazarus[/nav]
  [nav]peekaboo malpedia actor lazarus_group[/nav]

{reports}[heading]Browse latest reports[/heading]

  [nav]peekaboo malpedia reports --limit 10[/nav]

{attack}[heading]Explore ATT&CK[/heading]

  [nav]peekaboo ttp search "process injection"[/nav]
  [nav]peekaboo ttp show T1055[/nav]

{detect}[heading]Check detection coverage[/heading]

  [nav]peekaboo artifacts show T1055[/nav]
  [nav]peekaboo artifacts rules T1059.001 --level high[/nav]

{library}[heading]Browse research library[/heading]

  [nav]peekaboo library list[/nav]
  [nav]peekaboo library list --category injection[/nav]
  [nav]peekaboo library search "APC"[/nav]
""".format(
        actor=_icon("> "),
        reports=_icon("> "),
        attack=_icon("> "),
        detect=_icon("> "),
        library=_icon("> "),
    )
    _hash_header("Quick Start", "Common Peekaboo workflows")
    console.print(body.rstrip())
    console.print()


# ---------------------------------------------------------------------------
# module loaders

def load_db():
    return _import("db")

def load_malpedia():
    mp = _import("malpedia")
    if mp is None:
        return None
    if not mp.available():
        console.print(f"  [err]{_mark('err')} malpediaclient is not installed[/err]\n")
        return None
    return mp

def load_discovery():
    return _import("discovery")

def load_compiler():
    return _import("compiler")

def load_yaragen():
    return _import("yaragen")

def load_vtscan():
    return _import("vtscan")

# ---------------------------------------------------------------------------
# library
def render_library(rows: list[dict], title: str) -> None:
    table = _table(f"{title} ({len(rows)})")
    table.add_column("#", style="meta", justify="right", no_wrap=True)
    table.add_column("slug", style="nav", no_wrap=True)
    table.add_column("category", style="meta", no_wrap=True)
    table.add_column("T-IDs", style="warn", no_wrap=True)
    table.add_column("impl", justify="center")
    table.add_column("title")
    for i, item in enumerate(rows, 1):
        tids = " ".join(item.get("attack_ids") or []) or "-"
        table.add_row(
            str(i),
            item.get("slug", "?"),
            item.get("category", "-"),
            _short(tids, 18),
            "[ok]yes[/ok]" if item.get("implemented") else "[meta]-[/meta]",
            _short(item.get("title", ""), 64),
        )
    console.print()
    console.print(table)

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
    ".yara": "yara",
    ".yar": "yara",
}

def detect_language(path: Path, source: str) -> str:
    if path.suffix in LANG_BY_EXT:
        return LANG_BY_EXT[path.suffix]
    try:
        from pygments.lexers import guess_lexer_for_filename

        lexer = guess_lexer_for_filename(path.name, source)
        if lexer.aliases:
            return lexer.aliases[0]
    except Exception:
        pass
    return "text"

def render_source(item: dict) -> None:
    meta = (
        f"  [ok]Slug[/ok]     [ok]:[/ok] [nav]{item.get('slug')}[/nav]\n"
        f"  [ok]Title[/ok]    [ok]:[/ok] [ok]{item.get('title')}[/ok]\n"
        f"  [ok]Category[/ok] [ok]:[/ok] {item.get('category')}\n"
        f"  [ok]T-IDs[/ok]    [ok]:[/ok] [warn]{', '.join(item.get('attack_ids') or []) or '-'}[/warn]\n"
        f"  [ok]URL[/ok]      [ok]:[/ok] {item.get('blog_url') or '-'}"
    )
    _status_panel(item.get("slug", "module"), meta)

    path = Path(item.get("src_path") or "")
    text = ""
    if path.exists():
        text = path.read_text(errors="replace")
    elif item.get("snippet"):
        text = item["snippet"]
    if not text:
        console.print("  [meta](no source available)[/meta]\n")
        return
    lang = detect_language(path, text)
    filename = path.name if path.name else "source"
    source = Syntax(
        text,
        lang,
        theme="monokai",
        line_numbers=True,
        word_wrap=True,
        indent_guides=True,
        background_color="#111827",
        padding=(1, 2),
    )
    _hash_header(f"Source: {filename} ({lang})", f"{text.count(chr(10)) + 1} lines")
    console.print(source)
    console.print()

def cmd_library(args: argparse.Namespace) -> int:
    db = load_db()
    if db is None:
        return 1
    rows = db.get_mitre_entries()
    if not rows:
        console.print(f"[warn]{_mark('warn')} module library is empty[/warn]")
        return 1

    if args.library_cmd is None:
        render_library(rows[:PAGE], "Module Library")
        _hint("peekaboo library search APC", "peekaboo library list --category injection")
        return 0

    if args.library_cmd == "list":
        filtered = rows
        if args.category:
            q = args.category.lower()
            filtered = [row for row in rows if q in row.get("category", "").lower()]
        filtered = filtered[: args.limit]
        if args.json:
            _emit_json(filtered)
        else:
            render_library(filtered, f"Library: {args.category}" if args.category else "Module Library")
            _hint(*(f"peekaboo library show {row['slug']}" for row in filtered[:3]))
        return 0 if filtered else 1

    if args.library_cmd == "search":
        q = args.query.lower()
        hits = [
            row
            for row in rows
            if q in row.get("slug", "").lower()
            or q in row.get("title", "").lower()
            or q in row.get("category", "").lower()
            or any(q in tid.lower() for tid in row.get("attack_ids", []))
        ][: args.limit]
        if args.json:
            _emit_json(hits)
        elif hits:
            render_library(hits, f"Search: {args.query}")
            _hint(*(f"peekaboo library show {row['slug']}" for row in hits[:3]))
        else:
            console.print(f"  [warn]{_mark('warn')} no results for {args.query!r}[/warn]\n")
        return 0 if hits else 1

    if args.library_cmd == "show":
        by_slug = {row["slug"]: row for row in rows}
        slug = _resolve(args.slug, by_slug, "module")
        if slug is None:
            return 1
        if args.json:
            _emit_json(by_slug[slug])
        else:
            render_source(by_slug[slug])
            _hint(f"peekaboo builder build {slug}", f"peekaboo library brief {slug}")
        return 0

    if args.library_cmd == "brief":
        summary = db.get_kb_summary_for_slug(args.slug)
        if args.json:
            _emit_json({"slug": args.slug, "summary": summary})
        elif summary:
            _status_panel(f"Brief: {args.slug}", summary, "magenta")
        else:
            console.print(f"  [warn]{_mark('warn')} no brief for {args.slug}[/warn]\n")
        return 0 if summary else 1

    if args.library_cmd == "cats":
        counts = Counter(row.get("category", "-") for row in rows)
        if args.json:
            _emit_json(dict(counts))
        else:
            table = _table("Library Categories")
            table.add_column("category", style="nav")
            table.add_column("modules", style="meta", justify="right")
            for category, count in sorted(counts.items()):
                table.add_row(category, str(count))
            console.print()
            console.print(table)
        return 0

    return 1


# ---------------------------------------------------------------------------
# Malpedia
def mp_local_search(mp, kind: str, query: str) -> list[str]:
    values = mp.list_actors() if kind == "actor" else mp.list_families()
    q = query.lower()
    return [value for value in values if q in value.lower()]

def render_ids(values: list[str], title: str, column: str) -> None:
    table = _table(f"{title} ({len(values)})")
    table.add_column("#", style="meta", justify="right")
    table.add_column(column, style="nav")
    for i, value in enumerate(values, 1):
        table.add_row(str(i), value)
    console.print()
    console.print(table)

def render_reports(reports: list[dict]) -> None:
    table = _table(f"Recent Reports ({len(reports)})")
    table.add_column("#", style="meta", justify="right")
    table.add_column("date", style="meta", no_wrap=True)
    table.add_column("org", style="nav")
    table.add_column("title")
    table.add_column("families", style="warn")
    for i, report in enumerate(reports, 1):
        table.add_row(
            str(i),
            _short(report.get("date", ""), 11),
            _short(report.get("org", ""), 16),
            _short(report.get("title", ""), 56),
            _short(" ".join(report.get("families", [])[:3]), 30) or "-",
        )
    console.print()
    console.print(table)

def render_actor(actor: dict) -> None:
    if actor.get("error"):
        console.print(f"  [err]{_mark('err')} {actor['error']}[/err]\n")
        return
    body = (
        f"  ID       : [nav]{actor.get('id')}[/nav]\n"
        f"  Name     : {actor.get('name') or actor.get('id')}\n"
        f"  Country  : [meta]{actor.get('country') or '-'}[/meta]\n"
        f"  Synonyms : [meta]{', '.join(actor.get('synonyms', [])[:8]) or '-'}[/meta]\n"
        f"  Families : [warn]{len(actor.get('families', []))}[/warn]"
    )
    _status_panel(f"Actor: {actor.get('name') or actor.get('id')}", body)
    families = [item["id"] for item in actor.get("families", [])[:12]]
    if families:
        render_ids(families, "Linked Malware Families", "family-id")

def render_family(family: dict) -> None:
    if family.get("error"):
        console.print(f"  [err]{_mark('err')} {family['error']}[/err]\n")
        return
    body = (
        f"  ID          : [nav]{family.get('id')}[/nav]\n"
        f"  Name        : {family.get('name') or family.get('id')}\n"
        f"  Alt names   : [meta]{', '.join(family.get('alt_names', [])[:8]) or '-'}[/meta]\n"
        f"  Attribution : [warn]{', '.join(family.get('attribution', [])[:8]) or '-'}[/warn]\n"
        f"  Updated     : [meta]{family.get('updated') or '-'}[/meta]"
    )
    _status_panel(f"Family: {family.get('name') or family.get('id')}", body)
    desc = (family.get("description") or "").strip()
    if desc:
        _hash_header("Description", style="grey50")
        console.print(_short(desc, 1200))
        console.print()

def cmd_malpedia(args: argparse.Namespace) -> int:
    mp = load_malpedia()
    if mp is None:
        return 1

    if args.malpedia_cmd is None:
        _hint("peekaboo malpedia search lazarus", "peekaboo malpedia reports --limit 10")
        return 0

    if args.malpedia_cmd == "status":
        status = mp.get_status()
        if args.json:
            _emit_json(status)
        elif status.get("ok"):
            body = "\n".join(
                [
                    f"  API version    : [nav]{status.get('version')}[/nav]",
                    f"  Last updated   : [meta]{status.get('date')}[/meta]",
                    f"  Authenticated  : {'[ok]yes[/ok]' if status.get('authenticated') else '[warn]no (public)[/warn]'}",
                    f"  Actors cached  : {status.get('actors_cached')}",
                    f"  Families cached: {status.get('families_cached')}",
                ]
            )
            _status_panel("Malpedia Status", body)
        else:
            console.print(f"  [err]{_mark('err')} {status.get('error')}[/err]\n")
        return 0 if status.get("ok") else 1

    if args.malpedia_cmd == "search":
        actors = mp_local_search(mp, "actor", args.query)
        families = mp_local_search(mp, "family", args.query)
        if not actors:
            actors = mp.find_actor(args.query)
        if not families:
            families = mp.find_family(args.query)
        actors = actors[: args.limit]
        families = families[: args.limit]
        if args.json:
            _emit_json({"query": args.query, "actors": actors, "families": families})
        else:
            console.print(f"\n  [heading]Search results for {args.query!r}[/heading]")
            render_ids(actors, "Actors", "actor-id") if actors else console.print("  [meta]no actor matches[/meta]")
            render_ids(families, "Families", "family-id") if families else console.print("  [meta]no family matches[/meta]")
            _hint(*(f"peekaboo malpedia actor {actor}" for actor in actors[:3]), *(f"peekaboo malpedia family {family}" for family in families[:3]))
        return 0 if actors or families else 1

    if args.malpedia_cmd in ("actors", "families"):
        kind = "actor" if args.malpedia_cmd == "actors" else "family"
        values = mp_local_search(mp, kind, args.query) if args.query else (mp.list_actors() if kind == "actor" else mp.list_families())
        values = values[: args.limit]
        if args.json:
            _emit_json(values)
        else:
            render_ids(values, "Threat Actors" if kind == "actor" else "Malware Families", f"{kind}-id")
            command = "actor" if kind == "actor" else "family"
            _hint(*(f"peekaboo malpedia {command} {value}" for value in values[:3]))
        return 0

    if args.malpedia_cmd == "actor":
        actor_id = _resolve(args.actor_id.lower(), mp.list_actors(), "actor")
        if actor_id is None:
            return 1
        actor = mp.get_actor(actor_id)
        if args.json:
            _emit_json(actor)
        else:
            render_actor(actor)
            families = [item["id"] for item in actor.get("families", [])[:3]] if not actor.get("error") else []
            _hint(*(f"peekaboo malpedia family {family}" for family in families), f"peekaboo malpedia brief {actor_id}")
        return 0 if not actor.get("error") else 1

    if args.malpedia_cmd == "family":
        family_id = _resolve(args.family_id.lower(), mp.list_families(), "family")
        if family_id is None:
            return 1
        family = mp.get_family(family_id)
        if args.json:
            _emit_json(family)
        else:
            render_family(family)
            _hint(f"peekaboo malpedia yara {family_id}", f"peekaboo malpedia brief {family_id}")
        return 0 if not family.get("error") else 1

    if args.malpedia_cmd == "reports":
        reports = mp.get_recent_reports(args.limit)
        if args.json:
            _emit_json(reports)
        else:
            render_reports(reports)
            _hint("peekaboo malpedia search <actor-or-family>", "peekaboo malpedia family <family-id>")
        return 0

    if args.malpedia_cmd == "brief":
        db = load_db()
        if db is None:
            return 1
        if args.id in mp.list_actors():
            summary = db.get_actor_summary(args.id)
        elif args.id in mp.list_families():
            summary = db.get_family_summary(args.id)
        else:
            summary = db.get_kb_summary_for_slug(args.id)
        if args.json:
            _emit_json({"id": args.id, "summary": summary})
        elif summary:
            _status_panel(f"Brief: {args.id}", summary, "magenta")
        else:
            console.print(f"  [warn]{_mark('warn')} no brief for {args.id}[/warn]\n")
        return 0 if summary else 1

    if args.malpedia_cmd == "yara":
        client = mp._get_client()
        if not client:
            console.print(f"  [err]{_mark('err')} Malpedia client unavailable[/err]\n")
            return 1
        raw = client.get_yara(args.family_id)
        if args.json:
            _emit_json(raw)
            return 0
        rules: list[str] = []
        if isinstance(raw, dict):
            for tlp, items in raw.items():
                if isinstance(items, dict):
                    for name, text in items.items():
                        rules.append(f"// {tlp} / {name}\n{text}")
        if not rules:
            console.print(f"  [warn]{_mark('warn')} no YARA rules for {args.family_id}[/warn]\n")
            return 1
        rule_text = "\n\n".join(rules)
        _hash_header(f"YARA: {args.family_id}", style="grey50")
        console.print(Syntax(rule_text, "yara", theme="monokai", line_numbers=True, word_wrap=True))
        console.print()
        if args.save:
            args.save.write_text(rule_text, encoding="utf-8")
            console.print(f"  [ok]{_mark('ok')} saved {args.save}[/ok]\n")
        return 0

    if args.malpedia_cmd == "refresh":
        actors = mp.list_actors(force_refresh=True)
        families = mp.list_families(force_refresh=True)
        if args.json:
            _emit_json({"actors": len(actors), "families": len(families)})
        else:
            console.print(f"  [ok]{_mark('ok')} refreshed {len(actors)} actors and {len(families)} families[/ok]\n")
        return 0

    return 1

# ---------------------------------------------------------------------------
# ATT&CK TTP and detection artifacts
def render_ttp(rows: list[dict], title: str) -> None:
    by_id: dict[str, dict] = {}
    for row in rows:
        attack_id = row["attack_id"]
        item = by_id.setdefault(
            attack_id,
            {
                "attack_id": attack_id,
                "tech_name": row.get("tech_name") or attack_id,
                "tactic": row.get("tactic") or "-",
                "impls": 0,
                "compilable": 0,
            },
        )
        item["impls"] += 1
        item["compilable"] += 1 if row.get("meow_slug") else 0
    table = _table(f"{title} ({len(by_id)} techniques / {len(rows)} impls)")
    table.add_column("T-ID", style="nav", no_wrap=True)
    table.add_column("technique")
    table.add_column("tactic", style="meta")
    table.add_column("impls", justify="right", style="meta")
    table.add_column("build", justify="right", style="ok")
    for item in sorted(by_id.values(), key=lambda x: x["attack_id"]):
        table.add_row(item["attack_id"], _short(item["tech_name"], 46), item["tactic"], str(item["impls"]), str(item["compilable"]))
    console.print()
    console.print(table)

def render_ttp_detail(attack_id: str, rows: list[dict]) -> None:
    if not rows:
        console.print(f"  [err]{_mark('err')} no implementations for {attack_id}[/err]\n")
        return
    first = rows[0]
    _status_panel(
        attack_id,
        f"  Technique : {first.get('tech_name') or attack_id}\n"
        f"  Tactic    : [meta]{first.get('tactic') or '-'}[/meta]\n"
        f"  Impls     : [nav]{len(rows)}[/nav]\n"
        f"  Buildable : [ok]{sum(1 for row in rows if row.get('meow_slug'))}[/ok]",
    )
    table = _table("Implementations")
    table.add_column("#", style="meta", justify="right")
    table.add_column("module", style="nav")
    table.add_column("platform", style="meta")
    table.add_column("notes")
    for i, row in enumerate(rows, 1):
        table.add_row(str(i), row.get("meow_slug") or row.get("blog_slug") or "-", row.get("platform") or "-", _short(row.get("notes", ""), 64))
    console.print(table)

def cmd_ttp(args: argparse.Namespace) -> int:
    db = load_db()
    if db is None:
        return 1
    rows = db.get_ttp_implementations()
    if args.ttp_cmd is None:
        render_ttp(rows[: args.limit], "ATT&CK TTP")
        return 0

    if args.ttp_cmd == "list":
        filtered = rows
        if args.tactic:
            filtered = [row for row in filtered if row.get("tactic") == args.tactic]
        if args.platform:
            filtered = [row for row in filtered if row.get("platform") == args.platform]
        filtered = filtered[: args.limit]
        if args.json:
            _emit_json(filtered)
        else:
            render_ttp(filtered, "ATT&CK TTP")
            _hint(*(f"peekaboo ttp show {row['attack_id']}" for row in filtered[:3]))
        return 0

    if args.ttp_cmd == "search":
        hits = db.get_ttp_implementations(q=args.query)[: args.limit]
        if args.json:
            _emit_json(hits)
        elif hits:
            render_ttp(hits, f"Search: {args.query}")
            _hint(*(f"peekaboo ttp show {row['attack_id']}" for row in hits[:3]))
        else:
            console.print(f"  [warn]{_mark('warn')} no results for {args.query!r}[/warn]\n")
        return 0 if hits else 1

    if args.ttp_cmd == "show":
        attack_id = args.attack_id.upper()
        detail = db.get_ttp_by_attack_id(attack_id)
        if not detail:
            detail = [row for row in rows if row["attack_id"].startswith(attack_id + ".")]
        if args.json:
            _emit_json(detail)
        elif detail and detail[0]["attack_id"] == attack_id:
            render_ttp_detail(attack_id, detail)
            first_buildable = next((row["meow_slug"] for row in detail if row.get("meow_slug")), None)
            _hint(f"peekaboo builder build {first_buildable}" if first_buildable else "", f"peekaboo artifacts show {attack_id}")
        elif detail:
            render_ttp(detail, f"Sub-techniques of {attack_id}")
        else:
            console.print(f"  [err]{_mark('err')} no implementations for {attack_id}[/err]\n")
        return 0 if detail else 1

    if args.ttp_cmd == "brief":
        summary = db.get_artifact_summary(args.attack_id.upper())
        if args.json:
            _emit_json({"attack_id": args.attack_id.upper(), "summary": summary})
        elif summary:
            _status_panel(f"Detection Brief: {args.attack_id.upper()}", summary, "magenta")
        else:
            console.print(f"  [warn]{_mark('warn')} no brief for {args.attack_id}[/warn]\n")
        return 0 if summary else 1
    return 1

def render_artifacts(rows: list[dict], title: str) -> None:
    table = _table(f"{title} ({len(rows)})")
    table.add_column("T-ID", style="nav", no_wrap=True)
    table.add_column("name")
    table.add_column("tactics", style="meta")
    table.add_column("rules", style="ok", justify="right")
    table.add_column("EventIDs", style="warn")
    for row in rows:
        table.add_row(
            row.get("tid", "?"),
            _short(row.get("name") or "", 42),
            _short(row.get("tactic") or "", 34),
            str(row.get("rule_count", 0)),
            _short(" ".join(map(str, row.get("event_ids", [])[:6])), 24) or "-",
        )
    console.print()
    console.print(table)

def render_artifact_detail(row: dict) -> None:
    _status_panel(
        f"{row['tid']} Detection Coverage",
        f"  Name     : {row.get('name') or '-'}\n"
        f"  Tactics  : [meta]{row.get('tactic') or '-'}[/meta]\n"
        f"  Rules    : [ok]{row.get('rule_count', 0)} Sigma rules[/ok]\n"
        f"  EventIDs : [warn]{', '.join(map(str, row.get('event_ids', []))) or '-'}[/warn]\n"
        f"  Cats     : [meta]{', '.join(row.get('categories', [])[:8]) or '-'}[/meta]",
    )
    rules = sorted(row.get("rules", []), key=lambda r: r.get("level") or "")[:15]
    if rules:
        render_rules(row["tid"], rules)

def render_rules(tid: str, rules: list[dict]) -> None:
    table = _table(f"Sigma Rules: {tid} ({len(rules)})")
    table.add_column("#", style="meta", justify="right")
    table.add_column("level", style="warn")
    table.add_column("category", style="meta")
    table.add_column("status", style="meta")
    table.add_column("title")
    for i, rule in enumerate(rules, 1):
        table.add_row(str(i), rule.get("level") or "-", rule.get("category") or "-", rule.get("status") or "-", _short(rule.get("title") or "", 62))
    console.print()
    console.print(table)

def cmd_artifacts(args: argparse.Namespace) -> int:
    db = load_db()
    if db is None:
        return 1
    rows = db.get_artifact_entries()
    by_tid = {row["tid"]: row for row in rows}

    if args.artifacts_cmd is None:
        render_artifacts(rows[:PAGE], "Detection Artifacts")
        return 0

    if args.artifacts_cmd == "stats":
        stats = db.get_artifact_stats()
        if args.json:
            _emit_json(stats)
        else:
            _status_panel(
                "Artifact Map Stats",
                f"  Techniques : [nav]{stats.get('total_techniques')}[/nav]\n"
                f"  Sigma rules: [ok]{stats.get('total_rules')}[/ok]\n"
                f"  Tactics    : [meta]{stats.get('unique_tactics')}[/meta]\n"
                f"  Event IDs  : [warn]{stats.get('unique_event_ids')}[/warn]",
            )
        return 0

    if args.artifacts_cmd == "list":
        filtered = rows
        if args.tactic:
            filtered = [row for row in rows if args.tactic.lower() in row.get("tactic", "").lower()]
        filtered = filtered[: args.limit]
        if args.json:
            _emit_json(filtered)
        else:
            render_artifacts(filtered, f"Artifacts: {args.tactic}" if args.tactic else "Detection Artifacts")
            _hint(*(f"peekaboo artifacts show {row['tid']}" for row in filtered[:3]))
        return 0 if filtered else 1

    if args.artifacts_cmd == "search":
        q = args.query.lower()
        hits = [
            row
            for row in rows
            if q in row.get("tid", "").lower()
            or q in (row.get("name") or "").lower()
            or q in (row.get("tactic") or "").lower()
            or any(q in str(cat).lower() for cat in row.get("categories", []))
        ][: args.limit]
        if args.json:
            _emit_json(hits)
        elif hits:
            render_artifacts(hits, f"Search: {args.query}")
            _hint(*(f"peekaboo artifacts show {row['tid']}" for row in hits[:3]))
        else:
            console.print(f"  [warn]{_mark('warn')} no results for {args.query!r}[/warn]\n")
        return 0 if hits else 1

    if args.artifacts_cmd == "show":
        tid = _resolve(args.tid.upper(), by_tid, "T-ID")
        if tid is None:
            return 1
        if args.json:
            _emit_json(by_tid[tid])
        else:
            render_artifact_detail(by_tid[tid])
            _hint(f"peekaboo artifacts rules {tid} --level high", f"peekaboo ttp show {tid.split('.')[0]}")
        return 0

    if args.artifacts_cmd == "rules":
        tid = _resolve(args.tid.upper(), by_tid, "T-ID")
        if tid is None:
            return 1
        rules = by_tid[tid].get("rules", [])
        if args.level:
            rules = [rule for rule in rules if (rule.get("level") or "").lower() == args.level]
        if args.json:
            _emit_json(rules)
        else:
            render_rules(tid, rules[: args.limit])
            _hint(f"peekaboo artifacts show {tid}", f"peekaboo ttp show {tid.split('.')[0]}")
        return 0

    if args.artifacts_cmd == "tactics":
        counts = Counter()
        for row in rows:
            for tactic in (row.get("tactic") or "").split(","):
                tactic = tactic.strip()
                if tactic:
                    counts[tactic] += 1
        if args.json:
            _emit_json(dict(counts))
        else:
            table = _table("ATT&CK Tactics")
            table.add_column("tactic", style="nav")
            table.add_column("techniques", style="meta", justify="right")
            for tactic, count in sorted(counts.items()):
                table.add_row(tactic, str(count))
            console.print()
            console.print(table)
        return 0

    if args.artifacts_cmd == "brief":
        summary = db.get_artifact_summary(args.tid.upper())
        if args.json:
            _emit_json({"tid": args.tid.upper(), "summary": summary})
        elif summary:
            _status_panel(f"Detection Brief: {args.tid.upper()}", summary, "magenta")
        else:
            console.print(f"  [warn]{_mark('warn')} no brief for {args.tid}[/warn]\n")
        return 0 if summary else 1

    return 1

# ---------------------------------------------------------------------------
# builder / YARA / VT
def build_files(build: dict) -> list[tuple[str, Path]]:
    params = build.get("params", {})
    stored = params.get("out_path")
    if not stored:
        return []
    path = Path(stored) if Path(stored).is_absolute() else BASE / stored
    files = [(path.name, path)] if path.exists() else []
    persistence = path.parent / "persistence.exe"
    if persistence.exists():
        files.append(("persistence.exe", persistence))
    return files

def render_builds(rows: list[dict], title: str) -> None:
    table = _table(f"{title} ({len(rows)})")
    table.add_column("build-id", style="nav")
    table.add_column("status", style="meta")
    table.add_column("module")
    table.add_column("date", style="meta")
    table.add_column("binaries", style="ok")
    for row in rows:
        params = row.get("params", {})
        module = params.get("slug") or params.get("stealer") or params.get("injection") or "-"
        files = " ".join(name for name, _ in build_files(row)) or "-"
        table.add_row(row.get("id", "?"), row.get("status", "-"), module, _short(row.get("created", ""), 16), files)
    console.print()
    console.print(table)

def cmd_builder(args: argparse.Namespace) -> int:
    db = load_db()
    discovery = load_discovery()
    if db is None or discovery is None:
        return 1

    if args.builder_cmd is None:
        _hint("peekaboo builder list --platform windows", "peekaboo builder search injection")
        return 0

    if args.builder_cmd in ("list", "search"):
        modules = [item for item in discovery.scan_all() if item.get("compilable", True)]
        if args.builder_cmd == "search":
            q = args.query.lower()
            modules = [item for item in modules if q in item.get("slug", "").lower() or q in item.get("title", "").lower() or q in item.get("category", "").lower()]
            title = f"Build Search: {args.query}"
        else:
            title = "Compilable Modules"
            if args.platform:
                modules = [item for item in modules if item.get("platform") == args.platform]
            if args.category:
                modules = [item for item in modules if args.category.lower() in item.get("category", "").lower()]
        modules = modules[: args.limit]
        if args.json:
            _emit_json(modules)
        else:
            table = _table(f"{title} ({len(modules)})")
            table.add_column("slug", style="nav")
            table.add_column("platform", style="meta")
            table.add_column("compiler", style="meta")
            table.add_column("category", style="warn")
            table.add_column("title")
            for item in modules:
                table.add_row(item["slug"], item.get("platform", "-"), item.get("compiler", "-"), item.get("category", "-"), _short(item.get("title", ""), 60))
            console.print()
            console.print(table)
            _hint(*(f"peekaboo builder build {item['slug']}" for item in modules[:3]))
        return 0 if modules else 1

    if args.builder_cmd == "history":
        builds = db.get_builds(args.limit)
        if args.json:
            _emit_json(builds)
        else:
            render_builds(builds, "Build History")
            _hint("peekaboo builder show <build-id>", "peekaboo yara gen-build <build-id>")
        return 0

    if args.builder_cmd == "show":
        build = db.get_build(args.build_id)
        if args.json:
            _emit_json(build or {})
        elif build:
            _status_panel(
                f"Build: {args.build_id}",
                f"  Status : {build.get('status')}\n"
                f"  Created: [meta]{build.get('created')}[/meta]\n"
                f"  Params : [meta]{json.dumps(build.get('params', {}), default=_json_default)}[/meta]",
            )
            render_builds([build], "Artifacts")
            _hint(f"peekaboo yara gen-build {args.build_id}", f"peekaboo vtscan scan {args.build_id}")
        else:
            console.print(f"  [err]{_mark('err')} build not found: {args.build_id}[/err]\n")
        return 0 if build else 1

    if args.builder_cmd == "build":
        compiler = load_compiler()
        if compiler is None:
            return 1
        modules = {item["slug"]: item for item in discovery.scan_all() if item.get("compilable", True)}
        slug = _resolve(args.slug, modules, "module")
        if slug is None:
            return 1
        module = modules[slug]
        session_id = uuid.uuid4().hex[:12]
        build_id = f"cli-{uuid.uuid4().hex[:8]}"
        started = datetime.now()
        if args.json:
            ok, log, out_path = compiler.compile_module(module["id"], session_id)
        else:
            _status_panel("Build", f"  Module   : [nav]{slug}[/nav]\n  Compiler : [meta]{module.get('compiler')}[/meta]\n  Source   : [meta]{module.get('src_path')}[/meta]")
            with console.status(f"[meta]compiling {slug}...[/meta]", spinner="dots"):
                ok, log, out_path = compiler.compile_module(module["id"], session_id)
        ended = datetime.now()
        record = {
            "id": build_id,
            "params": {
                "slug": slug,
                "platform": module.get("platform"),
                "compiler": module.get("compiler"),
                "out_path": str(out_path.relative_to(BASE)) if ok and out_path else None,
            },
            "status": "success" if ok else "failed",
            "output": log,
            "returncode": 0 if ok else 1,
            "created": started.isoformat(),
            "start_time": started.isoformat(),
            "end_time": ended.isoformat(),
        }
        db.save_build(record)
        if args.json:
            _emit_json(record)
        elif ok and out_path:
            _status_panel(
                f"{_mark('ok')} BUILD OK",
                f"  Build  : [nav]{build_id}[/nav]\n  Output : [nav]{out_path}[/nav]\n  Size   : [meta]{out_path.stat().st_size:,} bytes[/meta]",
                "green",
            )
            _hint(f"peekaboo yara gen-build {build_id}", f"peekaboo vtscan scan {build_id}")
        else:
            _hash_header(f"{_mark('err')} BUILD FAILED", style="red")
            console.print(log[-2000:])
            console.print()
        return 0 if ok else 1

    return 1

def cmd_yara(args: argparse.Namespace) -> int:
    yaragen = load_yaragen()
    db = load_db()
    if yaragen is None or db is None:
        return 1

    if args.yara_cmd is None:
        _hint("peekaboo yara gen /tmp/payload.exe --save /tmp/payload.yar", "peekaboo yara builds")
        return 0

    if args.yara_cmd == "builds":
        builds = [build for build in db.get_builds(args.limit) if build.get("status") == "success"]
        if args.json:
            _emit_json(builds)
        else:
            render_builds(builds, "YARA Source Builds")
            _hint("peekaboo yara gen-build <build-id>")
        return 0

    target: Path | None = None
    if args.yara_cmd == "gen":
        target = args.path.expanduser().resolve()
    if args.yara_cmd == "gen-build":
        build = db.get_build(args.build_id)
        if not build:
            console.print(f"  [err]{_mark('err')} build not found: {args.build_id}[/err]\n")
            return 1
        files = build_files(build)
        if args.filename:
            files = [(name, path) for name, path in files if name.lower() == args.filename.lower()]
        if len(files) != 1:
            console.print(f"  [warn]{_mark('warn')} choose one binary with --filename[/warn]\n")
            return 1
        target = files[0][1]
    if not target or not target.exists():
        console.print(f"  [err]{_mark('err')} file not found: {target}[/err]\n")
        return 1

    result = yaragen.generate_rule(target)
    if args.json:
        _emit_json(result)
        return 0 if result.get("ok") else 1
    if not result.get("ok"):
        console.print(f"  [err]{_mark('err')} {result.get('error', 'failed')}[/err]\n")
        return 1
    _hash_header(f"YARA: {target.name}", style="grey50")
    console.print(Syntax(result["rule"], "yara", theme="monokai", line_numbers=True, word_wrap=True))
    console.print()
    if args.save:
        args.save.write_text(result["rule"], encoding="utf-8")
        console.print(f"  [ok]{_mark('ok')} saved {args.save}[/ok]\n")
    _hint(f"peekaboo yara gen {target} --save {target.with_suffix('.yar')}", "peekaboo vtscan scan-file <path>")
    return 0

def render_vt(result: dict, label: str) -> None:
    stats = result.get("stats") or {}
    if not stats:
        _status_panel(
            "VirusTotal",
            f"  Label : [nav]{label}[/nav]\n  Status: [meta]{result.get('status') or '-'}[/meta]\n  ID    : [nav]{result.get('analysis_id') or result.get('sha256') or '-'}[/nav]",
            "green" if result.get("ok") else "red",
        )
        return
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0) + stats.get("clean", 0)
    undetected = stats.get("undetected", 0)
    _status_panel(
        f"VirusTotal: {label}",
        f"  Malicious  : [err]{malicious}[/err]\n"
        f"  Suspicious : [warn]{suspicious}[/warn]\n"
        f"  Clean      : [ok]{harmless}[/ok]\n"
        f"  Undetected : [meta]{undetected}[/meta]",
        "red" if malicious else "green",
    )

def cmd_vtscan(args: argparse.Namespace) -> int:
    vt = load_vtscan()
    db = load_db()
    if vt is None or db is None:
        return 1
    if args.vtscan_cmd is None:
        _hint("peekaboo vtscan list", "peekaboo vtscan lookup <sha256>")
        return 0
    if args.vtscan_cmd == "list":
        builds = [build for build in db.get_builds(args.limit) if build_files(build)]
        if args.json:
            _emit_json(builds)
        else:
            render_builds(builds, "Scannable Builds")
            _hint("peekaboo vtscan scan <build-id>", "peekaboo yara gen-build <build-id>")
        return 0
    if args.vtscan_cmd == "lookup":
        result = vt.get_by_hash(args.sha256)
        if args.json:
            _emit_json(result)
        elif result.get("ok"):
            render_vt(result, args.sha256[:16])
        else:
            console.print(f"  [err]{_mark('err')} {result.get('error')}[/err]\n")
        return 0 if result.get("ok") else 1
    if args.vtscan_cmd == "poll":
        result = vt.poll_analysis(args.analysis_id)
        if args.json:
            _emit_json(result)
        elif result.get("ok"):
            render_vt(result, args.analysis_id[:16])
        else:
            console.print(f"  [err]{_mark('err')} {result.get('error')}[/err]\n")
        return 0 if result.get("ok") else 1
    if args.vtscan_cmd in ("scan", "scan-file"):
        if args.vtscan_cmd == "scan-file":
            target = args.path.expanduser().resolve()
        else:
            build = db.get_build(args.build_id)
            files = build_files(build) if build else []
            if not files:
                console.print(f"  [err]{_mark('err')} build binary not found: {args.build_id}[/err]\n")
                return 1
            target = files[0][1]
        result = vt.upload_file(target)
        if args.json:
            _emit_json(result)
        elif result.get("ok"):
            render_vt(result, target.name)
            _hint(f"peekaboo vtscan poll {result.get('analysis_id')}" if result.get("analysis_id") else "", f"peekaboo vtscan lookup {result.get('sha256')}")
        else:
            console.print(f"  [err]{_mark('err')} {result.get('error')}[/err]\n")
        return 0 if result.get("ok") else 1
    return 1


# ---------------------------------------------------------------------------
# argparse
def build_parser() -> argparse.ArgumentParser:
    parser = ColorHelpParser(
        prog="peekaboo",
        description="Malware Emulation, Threat Research & Detection Engineering Lab",
        epilog="Run `peekaboo examples` for common workflows.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--json", action="store_true", help="emit JSON where supported")
    parser.add_argument("--plain", action="store_true", help="use the most minimal ASCII output")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color")
    parser.add_argument("--force-color", action="store_true", help="force ANSI color (default; kept for scripts)")

    sub = parser.add_subparsers(dest="command", parser_class=ColorHelpParser)
    sub.add_parser("examples", help="show quick workflows")

    library = sub.add_parser("library", help="browse research modules")
    sp = library.add_subparsers(dest="library_cmd", parser_class=ColorHelpParser)
    p = sp.add_parser("list"); p.add_argument("--category", "-c"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("search"); p.add_argument("query"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("show"); p.add_argument("slug")
    p = sp.add_parser("brief"); p.add_argument("slug")
    sp.add_parser("cats")

    malpedia = sub.add_parser("malpedia", help="actors, families and reports")
    sp = malpedia.add_subparsers(dest="malpedia_cmd", parser_class=ColorHelpParser)
    sp.add_parser("status")
    p = sp.add_parser("search"); p.add_argument("query"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("actors"); p.add_argument("query", nargs="?"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("families"); p.add_argument("query", nargs="?"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("actor"); p.add_argument("actor_id")
    p = sp.add_parser("family"); p.add_argument("family_id")
    p = sp.add_parser("reports"); p.add_argument("--limit", "-n", type=int, default=20)
    p = sp.add_parser("brief"); p.add_argument("id")
    p = sp.add_parser("yara"); p.add_argument("family_id"); p.add_argument("--save", type=Path)
    sp.add_parser("refresh")

    ttp = sub.add_parser("ttp", help="MITRE ATT&CK implementations")
    sp = ttp.add_subparsers(dest="ttp_cmd", parser_class=ColorHelpParser)
    p = sp.add_parser("list"); p.add_argument("--tactic"); p.add_argument("--platform", choices=["windows", "linux", "macos"]); p.add_argument("--limit", type=int, default=200)
    p = sp.add_parser("search"); p.add_argument("query"); p.add_argument("--limit", type=int, default=50)
    p = sp.add_parser("show"); p.add_argument("attack_id")
    p = sp.add_parser("brief"); p.add_argument("attack_id")

    artifacts = sub.add_parser("artifacts", help="ATT&CK x Sigma coverage")
    sp = artifacts.add_subparsers(dest="artifacts_cmd", parser_class=ColorHelpParser)
    p = sp.add_parser("list"); p.add_argument("--tactic"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("search"); p.add_argument("query"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("show"); p.add_argument("tid")
    p = sp.add_parser("rules"); p.add_argument("tid"); p.add_argument("--level", choices=["critical", "high", "medium", "low", "informational"]); p.add_argument("--limit", type=int, default=60)
    sp.add_parser("tactics")
    sp.add_parser("stats")
    p = sp.add_parser("brief"); p.add_argument("tid")

    builder = sub.add_parser("builder", help="build research modules")
    sp = builder.add_subparsers(dest="builder_cmd", parser_class=ColorHelpParser)
    p = sp.add_parser("list"); p.add_argument("--platform", choices=["windows", "linux", "macos"]); p.add_argument("--category"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("search"); p.add_argument("query"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("history"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("show"); p.add_argument("build_id")
    p = sp.add_parser("build"); p.add_argument("slug")

    yara = sub.add_parser("yara", help="generate YARA rules")
    sp = yara.add_subparsers(dest="yara_cmd", parser_class=ColorHelpParser)
    p = sp.add_parser("gen"); p.add_argument("path", type=Path); p.add_argument("--save", type=Path)
    p = sp.add_parser("gen-build"); p.add_argument("build_id"); p.add_argument("--filename"); p.add_argument("--save", type=Path)
    p = sp.add_parser("builds"); p.add_argument("--limit", type=int, default=50)

    vt = sub.add_parser("vtscan", help="VirusTotal analysis")
    sp = vt.add_subparsers(dest="vtscan_cmd", parser_class=ColorHelpParser)
    p = sp.add_parser("list"); p.add_argument("--limit", type=int, default=50)
    p = sp.add_parser("lookup"); p.add_argument("sha256")
    p = sp.add_parser("poll"); p.add_argument("analysis_id")
    p = sp.add_parser("scan"); p.add_argument("build_id")
    p = sp.add_parser("scan-file"); p.add_argument("path", type=Path)

    sub.add_parser("shellcode", help="show shellcode workflow hints")
    return parser

def main(argv: list[str] | None = None) -> int:
    global console, PLAIN
    argv = list(sys.argv[1:] if argv is None else argv)
    PLAIN = bool("--plain" in argv or os.environ.get("NO_EMOJI"))
    _configure_console(no_color="--no-color" in argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    PLAIN = bool(args.plain or os.environ.get("NO_EMOJI"))
    _configure_console(no_color=args.no_color)

    if args.command is None:
        render_home()
        return 0
    handlers = {
        "examples": lambda _args: (render_examples() or 0),
        "library": cmd_library,
        "malpedia": cmd_malpedia,
        "ttp": cmd_ttp,
        "artifacts": cmd_artifacts,
        "builder": cmd_builder,
        "yara": cmd_yara,
        "vtscan": cmd_vtscan,
        "shellcode": lambda _args: (_hint("peekaboo shellcode load <path>", "peekaboo shellcode analyse", "peekaboo shellcode format python") or 0),
    }
    return handlers[args.command](args)

if __name__ == "__main__":
    raise SystemExit(main())
