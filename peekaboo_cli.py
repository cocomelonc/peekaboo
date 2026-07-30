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
import shutil
import sqlite3
import sys
import uuid
from collections import Counter
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.syntax import Syntax
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
        "nav": "bold bright_cyan",   # identifiers, hints, links
        "title": "white",            # primary text / names
        "count": "bold bright_cyan", # numeric metrics
        "evt": "bold #5BC8FF",       # windows event ids
        "meta": "grey74",            # secondary
        "ok": "bold bright_green",
        "warn": "bold bright_yellow",
        "err": "bold bright_red",
        "intel": "bold bright_magenta",  # threat-intel briefs
        "dim": "grey46",             # tertiary
    }
)


class PeekabooConsole(Console):
    """Rich console that treats a closed consumer as a successful short read."""

    def on_broken_pipe(self) -> None:
        self.quiet = True
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)

# Data-driven color maps - color always carries meaning, never decoration.
# Tactics mirror the dashboard's TACTIC_COLORS so CLI and web read as one tool.
TACTIC_STYLE = {
    "reconnaissance": "#9CA3AF", "resource-development": "#A78BFA",
    "initial-access": "#F97316", "execution": "#30D158",
    "defense-evasion": "#FFD60A", "persistence": "#0A84FF",
    "command-and-control": "#FF453A", "privilege-escalation": "#FF9F0A",
    "credential-access": "#BF5AF2", "discovery": "#64D2FF",
    "lateral-movement": "#FF8FAD", "collection": "#FFD60A",
    "exfiltration": "#0A84FF", "impact": "#FF375F", "unknown": "#8A85A8",
}
console = PeekabooConsole(theme=THEME, highlight=False, color_system="auto")
err_console = PeekabooConsole(theme=THEME, highlight=False, color_system="auto", stderr=True)
QUIET = False
OFFLINE = False


def _configure_console(mode: str) -> None:
    """Configure output once, before argparse renders help or an error."""
    global console, err_console
    options: dict[str, Any] = {"theme": THEME, "highlight": False}
    if mode == "always":
        options.update(force_terminal=True, color_system="truecolor", no_color=False)
    elif mode == "never":
        options.update(force_terminal=False, color_system=None, no_color=True)
    else:
        options.update(color_system="auto")
    console = PeekabooConsole(**options)
    err_console = PeekabooConsole(**options, stderr=True)


# ---------------------------------------------------------------------------
# small rendering/helpers
def _mark(kind: str) -> str:
    marks = {"ok": "+", "warn": "!", "err": "x"}
    return marks.get(kind, "")

def _short(value: Any, width: int) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= width else text[: max(0, width - 1)] + "~"

def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Text):
        return value.plain
    return str(value)

def _emit_json(value: Any) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=False, indent=2, default=_json_default))
    sys.stdout.write("\n")

def _safe(value: Any) -> str:
    return escape("" if value is None else str(value))

def _write_text_atomic(path: Path, content: str) -> None:
    destination = path.expanduser()
    if not destination.parent.is_dir():
        raise OSError(f"directory not found: {destination.parent}")
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)

def _error(message: Any) -> None:
    err_console.print(f"[err]{_mark('err')} {_safe(message)}[/err]")

def _warning(message: Any) -> None:
    err_console.print(f"[warn]{_mark('warn')} {_safe(message)}[/warn]")

def _hint(*commands: str) -> None:
    if QUIET or not console.is_terminal:
        return
    seen: set[str] = set()
    clean = []
    for command in commands:
        if command and command not in seen:
            seen.add(command)
            clean.append(command)
    if not clean:
        return
    console.print()
    console.print("  [heading]? Try:[/heading]")
    for command in clean:
        console.print(f"  [nav]{_safe(command)}[/nav]")
    console.print()

def _hash_header(title: str, subtitle: str | None = None, style: str = "cyan") -> None:
    _rule(title, style, subtitle)

def _import(name: str):
    try:
        return __import__(name)
    except Exception as exc:
        _error(f"cannot load {name}: {exc}")
        return None

def _resolve(key: str, values: list[str] | dict[str, Any], label: str) -> str | None:
    candidates = list(values)
    if key in candidates:
        return key
    hits = [item for item in candidates if key.lower() in item.lower()]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        _warning(f"ambiguous {label}: {', '.join(hits[:6])}")
        return None
    _error(f"{label} not found: {key}")
    return None

def _status_panel(title: str, body: str, style: str = "cyan", *, markup: bool = True) -> None:
    _rule(title, style)
    rendered = Text.from_markup(body.rstrip()) if markup else Text(body.rstrip())
    console.print(rendered)
    console.print()

# header bars use a bright bg + black text so they pop and stay readable in any
# terminal font (pure color attributes, no box-drawing glyphs).
_BAR_BG = {
    "cyan": "bright_cyan", "red": "bright_red", "green": "bright_green",
    "magenta": "bright_magenta", "yellow": "bright_yellow", "blue": "#5BC8FF",
    "grey35": "grey62",
}

def _rule(title: str, style: str = "cyan", subtitle: str | None = None) -> None:
    """The one section header: a bright color bar + trailing rule (ASCII, font-safe)."""
    bg   = _BAR_BG.get(style, style)
    plain_title = str(title)
    dash = "-" * max(3, min(50, console.width - len(plain_title) - 5))
    line = Text("\n")
    line.append(f" {plain_title} ", style=f"bold black on {bg}")
    line.append(f" {dash}", style=bg)
    console.print(line, no_wrap=True, overflow="ellipsis")
    if subtitle:
        console.print(Text(f"  {subtitle}", style="meta"), no_wrap=True, overflow="ellipsis")

# --- frameless column primitives -------------------------------------------
# Rich markup counts style tags as width, so we pad the *plain* text first,
# then colorize. Four helpers replace every boxed Table in this file.

def _cell(text: Any, w: int, style: str | None = None, right: bool = False) -> str:
    s = _short("" if text is None else str(text), w)
    s = s.rjust(w) if right else s.ljust(w)
    safe = escape(s)
    return f"[{style}]{safe}[/]" if style else safe

def _row(*cells: str) -> None:
    row = Text.from_markup("  " + "  ".join(cells))
    row.truncate(max(20, console.width), overflow="ellipsis")
    console.print(row, no_wrap=True, overflow="ellipsis")

def _head(*specs: tuple) -> None:
    """Blank line + dim header row. Each spec is (label, width[, right])."""
    console.print()
    _row(*[_cell(s[0], s[1], "dim", s[2] if len(s) > 2 else False) for s in specs])

def _tac(tactic: str, w: int) -> str:
    """Tactic cell colored (bold) by its ATT&CK tactic (first tactic wins for lists)."""
    first = re.split(r"[,\s]+", (tactic or "").strip())[0]
    return _cell(tactic or "-", w, f"bold {TACTIC_STYLE.get(first, TACTIC_STYLE['unknown'])}")

# --- filled "chip" tokens (bright bg + readable fg), font-safe -------------

def _chip(text: str, fg: str, bg: str) -> str:
    return f"[bold {fg} on {bg}] {_safe(text)} [/]"

def _chip_cell(token: str, visible: int, w: int, right: bool = False) -> str:
    """Pad a pre-rendered chip (with known visible width) to fill a column."""
    pad = " " * max(0, w - visible)
    return pad + token if right else token + pad

# level -> (fg, bg) for Sigma severity chips
SEV_CHIP = {
    "critical":      ("bright_white", "#C1121F"),
    "high":          ("black",        "#FF7A45"),
    "medium":        ("black",        "#FFD60A"),
    "low":           ("black",        "#64D2FF"),
    "informational": ("bright_white", "grey42"),
    "info":          ("bright_white", "grey42"),
}

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
        if file is None:
            console.print(_rich_help(raw), end="")
            return
        (file or sys.stdout).write(raw)

# ---------------------------------------------------------------------------
# home / examples
def render_home() -> None:
    def command(name: str, description: str) -> None:
        _row(_cell(">", 1, "dim"), _cell(name, 12, "nav"),
             _cell(description, max(20, console.width - 21), "title"))

    def example(description: str) -> None:
        _row(_cell("$", 1, "dim"),
             _cell(description, max(20, console.width - 7), "title"))

    _hash_header("PEEKABOO", "Threat Research & Detection Engineering Lab")
    console.print()
    console.print("  [heading]Explore[/heading]\n")
    command("search", "Search all local intelligence")
    command("pipeline", "Campaign, hunt and evidence views")
    command("library", "Browse research modules")
    command("malpedia", "Threat actors, families and reports")
    command("ttp", "Explore MITRE ATT&CK techniques")
    command("artifacts", "ATT&CK x Sigma detection coverage")
    console.print()
    console.print("  [heading]Tools[/heading]\n")
    command("doctor", "Verify local demo readiness")
    command("builder", "Research module build workflow")
    command("shellcode", "Analyse and convert byte payloads")
    command("yara", "Generate and inspect YARA rules")
    command("vtscan", "VirusTotal analysis")
    console.print()
    console.print("  [heading]Quick examples[/heading]\n")
    example("peekaboo doctor --demo")
    example("peekaboo search \"process injection\"")
    example("peekaboo pipeline show <session> --view evidence")
    console.print()
    console.print("  [dim]?[/dim] Run [nav]peekaboo <command> --help[/nav]")
    console.print("  [dim]>[/dim] Run [nav]peekaboo examples[/nav]\n")

def render_examples() -> None:
    body = """\
  [dim]>[/dim] [heading]Validate the offline demo[/heading]

    [nav]peekaboo doctor --demo[/nav]
    [nav]peekaboo search "process injection"[/nav]

  [dim]>[/dim] [heading]Investigate a campaign[/heading]

    [nav]peekaboo pipeline list[/nav]
    [nav]peekaboo pipeline show <session> --view evidence[/nav]
    [nav]peekaboo pipeline export <session> --format navigator[/nav]

  [dim]>[/dim] [heading]Explore a threat actor[/heading]

    [nav]peekaboo malpedia search lazarus[/nav]
    [nav]peekaboo malpedia actor lazarus_group[/nav]

  [dim]>[/dim] [heading]Browse latest reports[/heading]

    [nav]peekaboo malpedia reports --limit 10[/nav]

  [dim]>[/dim] [heading]Explore ATT&CK[/heading]

    [nav]peekaboo ttp search "process injection"[/nav]
    [nav]peekaboo ttp show T1055[/nav]

  [dim]>[/dim] [heading]Check detection coverage[/heading]

    [nav]peekaboo artifacts show T1055[/nav]
    [nav]peekaboo artifacts rules T1059.001 --level high[/nav]

  [dim]>[/dim] [heading]Browse research library[/heading]

    [nav]peekaboo library list[/nav]
    [nav]peekaboo library list --category injection[/nav]
    [nav]peekaboo library search "APC"[/nav]

  [dim]>[/dim] [heading]Inspect and format bytes[/heading]

    [nav]peekaboo shellcode analyse payload.bin[/nav]
    [nav]peekaboo shellcode convert payload.bin --to python[/nav]
"""
    _hash_header("Quick Start", "Common Peekaboo workflows")
    console.print()
    console.print(body.rstrip())
    console.print()


# ---------------------------------------------------------------------------
# module loaders

def load_db(*, initialize: bool = True):
    db = _import("db")
    if db is None or not initialize:
        return db
    try:
        db.init()
    except (OSError, sqlite3.Error) as exc:
        _error(f"cannot initialize database: {exc}")
        return None
    return db

def load_malpedia():
    mp = _import("malpedia")
    if mp is None:
        return None
    if not mp.available():
        _error("malpediaclient is not installed")
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

def load_shellcode():
    return _import("shellcode")


def _network_allowed(action: str, json_mode: bool = False) -> bool:
    if not OFFLINE:
        return True
    error = f"offline mode blocks {action}"
    if json_mode:
        _emit_json({"ok": False, "error": error})
    else:
        _error(error)
    return False


def _offline_malpedia_ids(kind: str) -> list[str]:
    cache = BASE / "data" / f"malpedia_{kind}s_cache.json"
    try:
        values = json.loads(cache.read_text(encoding="utf-8"))
        return values if isinstance(values, list) else sorted(values)
    except (OSError, ValueError, TypeError):
        return []

# ---------------------------------------------------------------------------
# library
def render_library(rows: list[dict], title: str) -> None:
    _rule(f"{title} ({len(rows)})")
    _head(("#", 3, True), ("slug", 26), ("category", 13), ("t-ids", 17), ("impl", 4), ("title", 40))
    for i, item in enumerate(rows, 1):
        tids = " ".join(item.get("attack_ids") or []) or "-"
        impl = item.get("implemented")
        _row(
            _cell(i, 3, "dim", True),
            _cell(item.get("slug", "?"), 26, "nav"),
            _cell(item.get("category", "-"), 13, "meta"),
            _cell(tids, 17, "warn"),
            _cell("yes" if impl else "-", 4, "ok" if impl else "dim"),
            _cell(item.get("title", ""), 40, "title"),
        )
    console.print()

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
        f"  [ok]Slug[/ok]     [ok]:[/ok] [nav]{_safe(item.get('slug'))}[/nav]\n"
        f"  [ok]Title[/ok]    [ok]:[/ok] [ok]{_safe(item.get('title'))}[/ok]\n"
        f"  [ok]Category[/ok] [ok]:[/ok] {_safe(item.get('category'))}\n"
        f"  [ok]T-IDs[/ok]    [ok]:[/ok] [warn]{_safe(', '.join(item.get('attack_ids') or []) or '-')}[/warn]\n"
        f"  [ok]URL[/ok]      [ok]:[/ok] {_safe(item.get('blog_url') or '-')}"
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
        _warning("module library is empty")
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
            _warning(f"no results for {args.query!r}")
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
            _status_panel(f"Brief: {args.slug}", summary, "magenta", markup=False)
        else:
            _warning(f"no brief for {args.slug}")
        return 0 if summary else 1

    if args.library_cmd == "cats":
        counts = Counter(row.get("category", "-") for row in rows)
        if args.json:
            _emit_json(dict(counts))
        else:
            _rule("library categories")
            _head(("category", 22), ("modules", 8, True))
            for category, count in sorted(counts.items()):
                _row(_cell(category, 22, "nav"), _cell(count, 8, "count", True))
            console.print()
        return 0

    return 1


# ---------------------------------------------------------------------------
# Malpedia
def mp_local_search(mp, kind: str, query: str) -> list[str]:
    values = (_offline_malpedia_ids(kind) if OFFLINE else
              (mp.list_actors() if kind == "actor" else mp.list_families()))
    q = query.lower()
    return [value for value in values if q in value.lower()]

def render_ids(values: list[str], title: str, column: str) -> None:
    _rule(f"{title} ({len(values)})")
    _head(("#", 3, True), (column, 40))
    for i, value in enumerate(values, 1):
        _row(_cell(i, 3, "dim", True), _cell(value, 40, "nav"))
    console.print()

def render_reports(reports: list[dict]) -> None:
    _rule(f"recent reports ({len(reports)})")
    _head(("#", 3, True), ("date", 11), ("org", 16), ("title", 48), ("families", 26))
    for i, report in enumerate(reports, 1):
        fams = " ".join(report.get("families", [])[:3]) or "-"
        _row(
            _cell(i, 3, "dim", True),
            _cell(report.get("date", ""), 11, "dim"),
            _cell(report.get("org", ""), 16, "nav"),
            _cell(report.get("title", ""), 48, "title"),
            _cell(fams, 26, "warn"),
        )
    console.print()

def render_actor(actor: dict) -> None:
    if actor.get("error"):
        _error(actor["error"])
        return
    body = (
        f"  ID       : [nav]{_safe(actor.get('id'))}[/nav]\n"
        f"  Name     : {_safe(actor.get('name') or actor.get('id'))}\n"
        f"  Country  : [meta]{_safe(actor.get('country') or '-')}[/meta]\n"
        f"  Synonyms : [meta]{_safe(', '.join(actor.get('synonyms', [])[:8]) or '-')}[/meta]\n"
        f"  Families : [warn]{len(actor.get('families', []))}[/warn]"
    )
    _status_panel(f"Actor: {actor.get('name') or actor.get('id')}", body)
    families = [item["id"] for item in actor.get("families", [])[:12]]
    if families:
        render_ids(families, "Linked Malware Families", "family-id")

def render_family(family: dict) -> None:
    if family.get("error"):
        _error(family["error"])
        return
    body = (
        f"  ID          : [nav]{_safe(family.get('id'))}[/nav]\n"
        f"  Name        : {_safe(family.get('name') or family.get('id'))}\n"
        f"  Alt names   : [meta]{_safe(', '.join(family.get('alt_names', [])[:8]) or '-')}[/meta]\n"
        f"  Attribution : [warn]{_safe(', '.join(family.get('attribution', [])[:8]) or '-')}[/warn]\n"
        f"  Updated     : [meta]{_safe(family.get('updated') or '-')}[/meta]"
    )
    _status_panel(f"Family: {family.get('name') or family.get('id')}", body)
    desc = (family.get("description") or "").strip()
    if desc:
        _hash_header("Description", style="grey50")
        console.print(Text(_short(desc, 1200)))
        console.print()

def cmd_malpedia(args: argparse.Namespace) -> int:
    if args.malpedia_cmd == "brief":
        db = load_db()
        if db is None:
            return 1
        summary = (db.get_actor_summary(args.id)
                   or db.get_family_summary(args.id)
                   or db.get_kb_summary_for_slug(args.id))
        if args.json:
            _emit_json({"id": args.id, "summary": summary})
        elif summary:
            _status_panel(f"Brief: {args.id}", summary, "magenta", markup=False)
        else:
            _warning(f"no brief for {args.id}")
        return 0 if summary else 1

    mp = load_malpedia()
    if mp is None:
        return 1

    if args.malpedia_cmd is None:
        _hint("peekaboo malpedia search lazarus", "peekaboo malpedia reports --limit 10")
        return 0

    if args.malpedia_cmd == "status":
        if not _network_allowed("Malpedia status", args.json):
            return 1
        status = mp.get_status()
        if args.json:
            _emit_json(status)
        elif status.get("ok"):
            body = "\n".join(
                [
                    f"  API version    : [nav]{_safe(status.get('version'))}[/nav]",
                    f"  Last updated   : [meta]{_safe(status.get('date'))}[/meta]",
                    f"  Authenticated  : {'[ok]yes[/ok]' if status.get('authenticated') else '[warn]no (public)[/warn]'}",
                    f"  Actors cached  : {status.get('actors_cached')}",
                    f"  Families cached: {status.get('families_cached')}",
                ]
            )
            _status_panel("Malpedia Status", body)
        else:
            _error(status.get("error"))
        return 0 if status.get("ok") else 1

    if args.malpedia_cmd == "search":
        actors = mp_local_search(mp, "actor", args.query)
        families = mp_local_search(mp, "family", args.query)
        if not actors and not OFFLINE:
            actors = mp.find_actor(args.query)
        if not families and not OFFLINE:
            families = mp.find_family(args.query)
        actors = actors[: args.limit]
        families = families[: args.limit]
        if args.json:
            _emit_json({"query": args.query, "actors": actors, "families": families})
        else:
            console.print(f"\n  [heading]Search results for {_safe(args.query)!r}[/heading]")
            render_ids(actors, "Actors", "actor-id") if actors else console.print("  [meta]no actor matches[/meta]")
            render_ids(families, "Families", "family-id") if families else console.print("  [meta]no family matches[/meta]")
            _hint(*(f"peekaboo malpedia actor {actor}" for actor in actors[:3]), *(f"peekaboo malpedia family {family}" for family in families[:3]))
        return 0 if actors or families else 1

    if args.malpedia_cmd in ("actors", "families"):
        kind = "actor" if args.malpedia_cmd == "actors" else "family"
        if args.query:
            values = mp_local_search(mp, kind, args.query)
        elif OFFLINE:
            values = _offline_malpedia_ids(kind)
        else:
            values = mp.list_actors() if kind == "actor" else mp.list_families()
        values = values[: args.limit]
        if args.json:
            _emit_json(values)
        else:
            render_ids(values, "Threat Actors" if kind == "actor" else "Malware Families", f"{kind}-id")
            command = "actor" if kind == "actor" else "family"
            _hint(*(f"peekaboo malpedia {command} {value}" for value in values[:3]))
        return 0

    if args.malpedia_cmd == "actor":
        if not _network_allowed("Malpedia actor lookup", args.json):
            return 1
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
        if not _network_allowed("Malpedia family lookup", args.json):
            return 1
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
        if not _network_allowed("Malpedia reports", args.json):
            return 1
        reports = mp.get_recent_reports(args.limit)
        if args.json:
            _emit_json(reports)
        else:
            render_reports(reports)
            _hint("peekaboo malpedia search <actor-or-family>", "peekaboo malpedia family <family-id>")
        return 0

    if args.malpedia_cmd == "yara":
        if not _network_allowed("Malpedia YARA download", args.json):
            return 1
        client = mp._get_client()
        if not client:
            _error("Malpedia client unavailable")
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
            _warning(f"no YARA rules for {args.family_id}")
            return 1
        rule_text = "\n\n".join(rules)
        _hash_header(f"YARA: {args.family_id}", style="grey50")
        console.print(Syntax(rule_text, "yara", theme="monokai", line_numbers=True, word_wrap=True))
        console.print()
        if args.save:
            try:
                _write_text_atomic(args.save, rule_text)
            except OSError as exc:
                _error(exc)
                return 1
            console.print(f"  [ok]{_mark('ok')} saved {_safe(args.save)}[/ok]\n")
        return 0

    if args.malpedia_cmd == "refresh":
        if not _network_allowed("Malpedia refresh", args.json):
            return 1
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
    _rule(f"{title} ({len(by_id)} techniques / {len(rows)} impls)")
    _head(("t-id", 10), ("technique", 38), ("tactic", 20), ("impls", 6, True), ("build", 6, True))
    for item in sorted(by_id.values(), key=lambda x: x["attack_id"]):
        _row(
            _cell(item["attack_id"], 10, "nav"),
            _cell(item["tech_name"], 38, "title"),
            _tac(item["tactic"], 20),
            _cell(item["impls"], 6, "count", True),
            _cell(item["compilable"], 6, "ok", True),
        )
    console.print()

def render_ttp_detail(attack_id: str, rows: list[dict]) -> None:
    if not rows:
        _error(f"no implementations for {attack_id}")
        return
    first = rows[0]
    _status_panel(
        attack_id,
        f"  Technique : {_safe(first.get('tech_name') or attack_id)}\n"
        f"  Tactic    : [meta]{_safe(first.get('tactic') or '-')}[/meta]\n"
        f"  Impls     : [nav]{len(rows)}[/nav]\n"
        f"  Buildable : [ok]{sum(1 for row in rows if row.get('meow_slug'))}[/ok]",
    )
    _rule("implementations", "grey35")
    _head(("#", 3, True), ("module", 30), ("platform", 10), ("notes", 48))
    for i, row in enumerate(rows, 1):
        _row(
            _cell(i, 3, "dim", True),
            _cell(row.get("meow_slug") or row.get("blog_slug") or "-", 30, "nav"),
            _cell(row.get("platform") or "-", 10, "meta"),
            _cell(row.get("notes", ""), 48, "title"),
        )
    console.print()

def cmd_ttp(args: argparse.Namespace) -> int:
    db = load_db()
    if db is None:
        return 1
    rows = db.get_ttp_implementations()
    if args.ttp_cmd is None:
        render_ttp(rows[:PAGE], "ATT&CK TTP")
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
            _warning(f"no results for {args.query!r}")
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
            _error(f"no implementations for {attack_id}")
        return 0 if detail else 1

    if args.ttp_cmd == "brief":
        summary = db.get_artifact_summary(args.attack_id.upper())
        if args.json:
            _emit_json({"attack_id": args.attack_id.upper(), "summary": summary})
        elif summary:
            _status_panel(f"Detection Brief: {args.attack_id.upper()}", summary, "magenta", markup=False)
        else:
            _warning(f"no brief for {args.attack_id}")
        return 0 if summary else 1
    return 1

def render_artifacts(rows: list[dict], title: str) -> None:
    _rule(f"{title} ({len(rows)})")
    _head(("t-id", 10), ("name", 38), ("tactic", 20), ("rules", 6, True), ("eventids", 24))
    for row in rows:
        eids = " ".join(map(str, row.get("event_ids", [])[:6])) or "-"
        _row(
            _cell(row.get("tid", "?"), 10, "nav"),
            _cell(row.get("name") or "", 38, "title"),
            _tac(row.get("tactic") or "", 20),
            _cell(row.get("rule_count", 0), 6, "count", True),
            _cell(eids, 24, "evt"),
        )
    console.print()

def render_artifact_detail(row: dict) -> None:
    _status_panel(
        f"{row['tid']} Detection Coverage",
        f"  Name     : {_safe(row.get('name') or '-')}\n"
        f"  Tactics  : [meta]{_safe(row.get('tactic') or '-')}[/meta]\n"
        f"  Rules    : [ok]{row.get('rule_count', 0)} Sigma rules[/ok]\n"
        f"  EventIDs : [warn]{', '.join(map(str, row.get('event_ids', []))) or '-'}[/warn]\n"
        f"  Cats     : [meta]{_safe(', '.join(row.get('categories', [])[:8]) or '-')}[/meta]",
    )
    rules = sorted(row.get("rules", []), key=lambda r: r.get("level") or "")[:15]
    if rules:
        render_rules(row["tid"], rules)

def render_rules(tid: str, rules: list[dict]) -> None:
    _rule(f"sigma rules: {tid} ({len(rules)})")
    _head(("#", 3, True), ("level", 13), ("category", 16), ("status", 10), ("title", 46))
    for i, rule in enumerate(rules, 1):
        lvl = rule.get("level") or "-"
        key = lvl.lower()
        if key in SEV_CHIP:
            fg, bg = SEV_CHIP[key]
            level_cell = _chip_cell(_chip(lvl, fg, bg), len(lvl) + 2, 13)
        else:
            level_cell = _cell(lvl, 13, "dim")
        _row(
            _cell(i, 3, "dim", True),
            level_cell,
            _cell(rule.get("category") or "-", 16, "meta"),
            _cell(rule.get("status") or "-", 10, "meta"),
            _cell(rule.get("title") or "", 46, "title"),
        )
    console.print()

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
            _warning(f"no results for {args.query!r}")
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
            _rule("att&ck tactics")
            _head(("tactic", 24), ("techniques", 11, True))
            for tactic, count in sorted(counts.items()):
                _row(_tac(tactic, 24), _cell(count, 11, "count", True))
            console.print()
        return 0

    if args.artifacts_cmd == "brief":
        summary = db.get_artifact_summary(args.tid.upper())
        if args.json:
            _emit_json({"tid": args.tid.upper(), "summary": summary})
        elif summary:
            _status_panel(f"Detection Brief: {args.tid.upper()}", summary, "magenta", markup=False)
        else:
            _warning(f"no brief for {args.tid}")
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
    _rule(f"{title} ({len(rows)})")
    _head(("build-id", 12), ("status", 11), ("module", 20), ("date", 16), ("binaries", 28))
    for row in rows:
        params = row.get("params", {})
        module = params.get("slug") or params.get("stealer") or params.get("injection") or "-"
        files = " ".join(name for name, _ in build_files(row)) or "-"
        st = row.get("status", "-")
        if st == "success":
            st_cell = _chip_cell(_chip(st, "black", "bright_green"), len(st) + 2, 11)
        elif "fail" in st:
            st_cell = _chip_cell(_chip(st, "bright_white", "#C1121F"), len(st) + 2, 11)
        else:
            st_cell = _cell(st, 11, "meta")
        _row(
            _cell(row.get("id", "?"), 12, "nav"),
            st_cell,
            _cell(module, 20, "title"),
            _cell(row.get("created", ""), 16, "dim"),
            _cell(files, 28, "ok"),
        )
    console.print()

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
            _rule(f"{title} ({len(modules)})")
            _head(("slug", 26), ("platform", 9), ("compiler", 11), ("category", 13), ("title", 34))
            for item in modules:
                _row(
                    _cell(item["slug"], 26, "nav"),
                    _cell(item.get("platform", "-"), 9, "meta"),
                    _cell(item.get("compiler", "-"), 11, "meta"),
                    _cell(item.get("category", "-"), 13, "warn"),
                    _cell(item.get("title", ""), 34, "title"),
                )
            console.print()
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
                f"  Status : {_safe(build.get('status'))}\n"
                f"  Created: [meta]{_safe(build.get('created'))}[/meta]\n"
                f"  Params : [meta]{_safe(json.dumps(build.get('params', {}), default=_json_default))}[/meta]",
            )
            render_builds([build], "Artifacts")
            _hint(f"peekaboo yara gen-build {args.build_id}", f"peekaboo vtscan scan {args.build_id}")
        else:
            _error(f"build not found: {args.build_id}")
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
            _status_panel("Build", f"  Module   : [nav]{_safe(slug)}[/nav]\n  Compiler : [meta]{_safe(module.get('compiler'))}[/meta]\n  Source   : [meta]{_safe(module.get('src_path'))}[/meta]")
            with console.status(f"[meta]compiling {_safe(slug)}...[/meta]", spinner="dots"):
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
                f"  Build  : [nav]{_safe(build_id)}[/nav]\n  Output : [nav]{_safe(out_path)}[/nav]\n  Size   : [meta]{out_path.stat().st_size:,} bytes[/meta]",
                "green",
            )
            _hint(f"peekaboo yara gen-build {build_id}", f"peekaboo vtscan scan {build_id}")
        else:
            _hash_header(f"{_mark('err')} BUILD FAILED", style="red")
            console.print(Text(log[-2000:]))
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
            _error(f"build not found: {args.build_id}")
            return 1
        files = build_files(build)
        if args.filename:
            files = [(name, path) for name, path in files if name.lower() == args.filename.lower()]
        if len(files) != 1:
            _warning("choose one binary with --filename")
            return 1
        target = files[0][1]
    if not target or not target.exists():
        _error(f"file not found: {target}")
        return 1

    result = yaragen.generate_rule(target)
    if args.json:
        _emit_json(result)
        return 0 if result.get("ok") else 1
    if not result.get("ok"):
        _error(result.get("error", "failed"))
        return 1
    _hash_header(f"YARA: {target.name}", style="grey50")
    console.print(Syntax(result["rule"], "yara", theme="monokai", line_numbers=True, word_wrap=True))
    console.print()
    if args.save:
        try:
            _write_text_atomic(args.save, result["rule"])
        except OSError as exc:
            _error(exc)
            return 1
        console.print(f"  [ok]{_mark('ok')} saved {_safe(args.save)}[/ok]\n")
    _hint(f"peekaboo yara gen {target} --save {target.with_suffix('.yar')}", "peekaboo vtscan scan-file <path>")
    return 0

def render_vt(result: dict, label: str) -> None:
    stats = result.get("stats") or {}
    if not stats:
        _status_panel(
            "VirusTotal",
            f"  Label : [nav]{_safe(label)}[/nav]\n  Status: [meta]{_safe(result.get('status') or '-')}[/meta]\n  ID    : [nav]{_safe(result.get('analysis_id') or result.get('sha256') or '-')}[/nav]",
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
        if not _network_allowed("VirusTotal lookup", args.json):
            return 1
        result = vt.get_by_hash(args.sha256)
        if args.json:
            _emit_json(result)
        elif result.get("ok"):
            render_vt(result, args.sha256[:16])
        else:
            _error(result.get("error"))
        return 0 if result.get("ok") else 1
    if args.vtscan_cmd == "poll":
        if not _network_allowed("VirusTotal polling", args.json):
            return 1
        result = vt.poll_analysis(args.analysis_id)
        if args.json:
            _emit_json(result)
        elif result.get("ok"):
            render_vt(result, args.analysis_id[:16])
        else:
            _error(result.get("error"))
        return 0 if result.get("ok") else 1
    if args.vtscan_cmd in ("scan", "scan-file"):
        if not _network_allowed("VirusTotal upload", args.json):
            return 1
        if args.vtscan_cmd == "scan-file":
            target = args.path.expanduser().resolve()
        else:
            build = db.get_build(args.build_id)
            files = build_files(build) if build else []
            if not files:
                _error(f"build binary not found: {args.build_id}")
                return 1
            target = files[0][1]
        if not target.is_file():
            _error(f"file not found: {target}")
            return 1
        if not args.yes:
            if args.json or not sys.stdin.isatty():
                _error("VirusTotal upload requires --yes in non-interactive mode")
                return 1
            err_console.print(
                f"[warn]Upload {_safe(target.name)} ({target.stat().st_size:,} bytes) "
                "to VirusTotal? [y/N][/warn] ", end="",
            )
            if sys.stdin.readline().strip().lower() not in ("y", "yes"):
                _warning("upload cancelled")
                return 1
        result = vt.upload_file(target)
        if args.json:
            _emit_json(result)
        elif result.get("ok"):
            render_vt(result, target.name)
            _hint(f"peekaboo vtscan poll {result.get('analysis_id')}" if result.get("analysis_id") else "", f"peekaboo vtscan lookup {result.get('sha256')}")
        else:
            _error(result.get("error"))
        return 0 if result.get("ok") else 1
    return 1


def _doctor_check(name: str, level: str, detail: str) -> dict:
    return {"name": name, "level": level, "detail": detail}


def cmd_doctor(args: argparse.Namespace) -> int:
    """Read-only verification of the local database, demo assets and toolchain."""
    db = load_db(initialize=False)
    if db is None:
        return 1
    path = Path(db.DB_PATH)
    checks: list[dict] = []
    required_tables = {
        "artifact_map", "mitre_library", "pipeline_sessions", "report_ttp_sources",
        "report_ttps", "samples", "ttp_implementations",
    }

    if not path.is_file():
        checks.append(_doctor_check("database", "fail", f"not found: {path}"))
    else:
        try:
            with closing(sqlite3.connect(path)) as conn:
                quick = conn.execute("PRAGMA quick_check").fetchone()[0]
                tables = {row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
            checks.append(_doctor_check(
                "database", "pass" if quick == "ok" else "fail",
                f"{path} ({path.stat().st_size:,} bytes), quick_check={quick}",
            ))
            missing = sorted(required_tables - tables)
            checks.append(_doctor_check(
                "schema", "fail" if missing else "pass",
                f"missing: {', '.join(missing)}" if missing else f"{len(tables)} tables available",
            ))
        except sqlite3.Error as exc:
            checks.append(_doctor_check("database", "fail", str(exc)))

    def count(label: str, table: str, required: bool = True) -> int:
        try:
            with closing(sqlite3.connect(path)) as conn:
                value = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            level = "pass" if value else ("fail" if required else "warn")
            checks.append(_doctor_check(label, level, f"{value:,} rows"))
            return value
        except sqlite3.Error as exc:
            checks.append(_doctor_check(label, "fail" if required else "warn", str(exc)))
            return 0

    if path.is_file():
        count("ATT&CK artifacts", "artifact_map")
        count("blog modules", "mitre_library")
        count("TTP implementations", "ttp_implementations")
        count("precomputed report TTPs", "report_ttps", required=args.demo)

    if args.demo and path.is_file():
        try:
            sessions = db.get_pipeline_sessions(500)
            successful = [row for row in sessions if row.get("status") == "success"]
            checks.append(_doctor_check(
                "campaigns", "pass" if successful else "fail",
                f"{len(successful)}/{len(sessions)} successful",
            ))
            samples_dir = Path(os.getenv("PEEKABOO_SAMPLES_DIR", BASE / "samples"))
            reports_ready = links_ready = binaries_ready = 0
            for session in successful:
                params = session.get("params") or {}
                stages = params.get("stages") or []
                sid = session.get("session_id", "")
                has_reports = bool(params.get("report_sources")) or any(
                    stage.get("report_url") for stage in stages
                ) or bool(db.get_reports(sid))
                has_links = bool(stages) and all(
                    stage.get("blog_url") or stage.get("module_slug") or stage.get("module_id")
                    for stage in stages
                )
                expected = [Path(stage["_out_bin"]).name for stage in stages if stage.get("_out_bin")]
                sample_dir = samples_dir / sid
                has_binaries = bool(expected) and all((sample_dir / name).is_file() for name in expected)
                reports_ready += int(has_reports)
                links_ready += int(has_links)
                binaries_ready += int(has_binaries)

            total = len(successful)
            for name, value in (
                ("campaign reports", reports_ready),
                ("campaign blog links", links_ready),
                ("compiled samples", binaries_ready),
            ):
                checks.append(_doctor_check(
                    name, "pass" if total and value == total else "fail",
                    f"{value}/{total} sessions ready",
                ))
        except (OSError, sqlite3.Error) as exc:
            checks.append(_doctor_check("demo assets", "fail", str(exc)))

    toolchains = {
        "Linux C compiler": ("gcc", "clang"),
        "Windows C compiler": ("x86_64-w64-mingw32-gcc",),
        "NASM": ("nasm",),
    }
    for label, candidates in toolchains.items():
        found = next((shutil.which(candidate) for candidate in candidates if shutil.which(candidate)), None)
        checks.append(_doctor_check(label, "pass" if found else "warn", found or "not installed"))

    ready = not any(check["level"] == "fail" for check in checks)
    payload = {"ready": ready, "demo": args.demo, "database": str(path), "checks": checks}
    if args.json:
        _emit_json(payload)
    else:
        _rule("demo doctor" if args.demo else "peekaboo doctor")
        check_width = 20 if console.width < 72 else 24
        detail_width = max(18, console.width - check_width - 13)
        _head(("state", 7), ("check", check_width), ("detail", detail_width))
        for check in checks:
            style = {"pass": "ok", "warn": "warn", "fail": "err"}[check["level"]]
            _row(
                _cell(check["level"], 7, style),
                _cell(check["name"], check_width, "title"),
                _cell(check["detail"], detail_width, "meta"),
            )
        console.print()
    return 0 if ready else 1


def _summary_search(db_path: Path, table: str, id_column: str,
                    query: str, limit: int) -> list[dict]:
    pattern = f"%{query.lower()}%"
    try:
        with closing(sqlite3.connect(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"SELECT {id_column} AS ref, summary FROM {table} "
                f"WHERE lower({id_column}) LIKE ? OR lower(summary) LIKE ? "
                "ORDER BY summarized_at DESC LIMIT ?",
                (pattern, pattern, limit * 3),
            ).fetchall()
    except sqlite3.Error:
        return []
    seen: set[str] = set()
    results: list[dict] = []
    for row in rows:
        if row["ref"] in seen:
            continue
        seen.add(row["ref"])
        results.append({"ref": row["ref"], "title": _short(row["summary"], 100), "context": "local brief"})
        if len(results) >= limit:
            break
    return results


def cmd_search(args: argparse.Namespace) -> int:
    """Unified, deterministic search over data already present in peekaboo.db."""
    db = load_db()
    if db is None:
        return 1
    query = args.query.strip()
    q = query.lower()
    limit = max(1, args.limit)

    modules = [
        {"ref": row.get("slug", ""), "title": row.get("title", ""),
         "context": f"{row.get('category', '-')}  {' '.join(row.get('attack_ids') or [])}"}
        for row in db.get_mitre_entries()
        if q in " ".join([
            row.get("slug", ""), row.get("title", ""), row.get("category", ""),
            " ".join(row.get("attack_ids") or []),
        ]).lower()
    ][:limit]

    impl_rows = db.get_ttp_implementations(q=query)
    techniques: list[dict] = []
    seen_tids: set[str] = set()
    for row in impl_rows:
        tid = row.get("attack_id", "")
        if tid in seen_tids:
            continue
        seen_tids.add(tid)
        techniques.append({"ref": tid, "title": row.get("tech_name", ""),
                           "context": row.get("tactic", "")})
        if len(techniques) >= limit:
            break

    artifacts = [
        {"ref": row.get("tid", ""), "title": row.get("name", ""),
         "context": f"{row.get('rule_count', 0)} Sigma  {row.get('tactic', '')}"}
        for row in db.get_artifact_entries(q=query)[:limit]
    ]

    campaigns: list[dict] = []
    for session in db.get_pipeline_sessions(500):
        params = session.get("params") or {}
        stages = params.get("stages") or []
        if q in str(session.get("actor_id", "")).lower():
            campaigns.append({"ref": session.get("session_id", ""),
                              "title": session.get("actor_id", ""),
                              "context": f"{len(stages)} stages"})
        for stage in stages:
            haystack = " ".join(str(stage.get(key, "")) for key in (
                "ttp_id", "ttp_name", "tactic", "module_slug", "module_id", "evidence"
            )).lower()
            if q in haystack:
                campaigns.append({
                    "ref": session.get("session_id", ""),
                    "title": f"{stage.get('ttp_id', '')} {stage.get('ttp_name', '')}".strip(),
                    "context": f"{session.get('actor_id', '')}  {stage.get('module_slug') or stage.get('module_id') or '-'}",
                })
            if len(campaigns) >= limit:
                break
        if len(campaigns) >= limit:
            break

    groups = {
        "techniques": techniques,
        "blog modules": modules,
        "detection artifacts": artifacts,
        "campaigns": campaigns[:limit],
        "actors": _summary_search(Path(db.DB_PATH), "actor_summaries", "actor_id", query, limit),
        "families": _summary_search(Path(db.DB_PATH), "family_summaries", "family_id", query, limit),
    }
    payload = {"query": query, "results": groups,
               "total": sum(len(rows) for rows in groups.values())}
    if args.json:
        _emit_json(payload)
    elif payload["total"]:
        _rule(f"search: {query}")
        compact = console.width < 72
        for label, rows in groups.items():
            if not rows:
                continue
            console.print(Text(f"\n  {label} ({len(rows)})", style="heading"))
            if compact:
                _head(("ref", 18), ("title", 34))
            else:
                _head(("ref", 22), ("title", 42), ("context", 42))
            for row in rows:
                cells = [_cell(row["ref"], 18 if compact else 22, "nav"),
                         _cell(row["title"], 34 if compact else 42, "title")]
                if not compact:
                    cells.append(_cell(row["context"], 42, "meta"))
                _row(*cells)
        console.print()
    else:
        _warning(f"no local results for {query!r}")
    return 0 if payload["total"] else 1


SHELLCODE_FORMATS = (
    "c", "c_str", "python", "powershell", "csharp", "vba", "rust",
    "base64", "hex_0x", "hex_raw", "escaped",
)
SHELLCODE_TRANSFORMS = (
    "none", "xor_random", "xor_key", "base64_encode", "base64_decode",
    "zlib_compress", "zlib_decompress",
)


def _read_shellcode_input(source: str, engine) -> str:
    if source == "-":
        data = sys.stdin.buffer.read()
    else:
        data = Path(source).expanduser().read_bytes()
    if not data:
        raise ValueError("input is empty")
    try:
        text = data.decode("utf-8")
        engine.parse_input(text)
        return text
    except (UnicodeDecodeError, ValueError):
        return data.hex()


def cmd_shellcode(args: argparse.Namespace) -> int:
    engine = load_shellcode()
    if engine is None:
        return 1
    if args.shellcode_cmd is None:
        _hint("peekaboo shellcode analyse <path>",
              "peekaboo shellcode convert <path> --to c")
        return 0

    if args.shellcode_cmd == "formats":
        payload = {"formats": list(SHELLCODE_FORMATS),
                   "transforms": list(SHELLCODE_TRANSFORMS)}
        if args.json:
            _emit_json(payload)
        else:
            _rule("shellcode formats")
            _head(("output", 18), ("transform", 20))
            count = max(len(SHELLCODE_FORMATS), len(SHELLCODE_TRANSFORMS))
            for i in range(count):
                _row(
                    _cell(SHELLCODE_FORMATS[i] if i < len(SHELLCODE_FORMATS) else "", 18, "nav"),
                    _cell(SHELLCODE_TRANSFORMS[i] if i < len(SHELLCODE_TRANSFORMS) else "", 20, "meta"),
                )
            console.print()
        return 0

    try:
        raw = _read_shellcode_input(args.source, engine)
    except (OSError, ValueError) as exc:
        if args.json:
            _emit_json({"ok": False, "error": str(exc)})
        else:
            _error(exc)
        return 1

    if args.shellcode_cmd in ("analyse", "analyze"):
        result = engine.analyse_only(raw)
        if args.json:
            _emit_json(result)
        elif result.get("ok"):
            detected = result.get("detected") or "no known signature"
            _status_panel(
                "shellcode analysis",
                f"  Input    : [nav]{_safe(args.source)}[/nav]\n"
                f"  Format   : [meta]{_safe(result.get('detected_fmt'))}[/meta]\n"
                f"  Size     : [count]{result.get('size', 0):,} bytes[/count]\n"
                f"  Entropy  : [warn]{result.get('entropy', 0):.3f}[/warn]\n"
                f"  Arch     : [ok]{_safe(result.get('arch'))}[/ok]\n"
                f"  Signature: [meta]{_safe(detected)}[/meta]\n"
                f"  SHA-256  : [nav]{_safe(result.get('sha256'))}[/nav]",
            )
            top = result.get("top_bytes") or []
            if top:
                _head(("byte", 8), ("count", 8, True), ("share", 8, True))
                for row in top:
                    _row(_cell(row.get("byte"), 8, "nav"),
                         _cell(row.get("count"), 8, "count", True),
                         _cell(f"{row.get('pct', 0)}%", 8, "meta", True))
                console.print()
        else:
            _error(result.get("error", "analysis failed"))
        return 0 if result.get("ok") else 1

    result = engine.process(
        raw,
        output_format=args.to,
        transform=args.transform,
        xor_key_str=args.xor_key or "",
        var_name=args.var,
    )
    if args.json:
        _emit_json(result)
        return 0 if result.get("ok") else 1
    if not result.get("ok"):
        _error(result.get("error", "conversion failed"))
        return 1

    output = result["output"]
    if args.output:
        destination = args.output.expanduser()
        try:
            _write_text_atomic(destination, output + ("" if output.endswith("\n") else "\n"))
        except OSError as exc:
            _error(exc)
            return 1
        console.print(f"  [ok]{_mark('ok')} wrote {_safe(destination)}[/ok]\n")
    elif args.raw or not console.is_terminal:
        sys.stdout.write(output)
        if not output.endswith("\n"):
            sys.stdout.write("\n")
    else:
        _rule(f"shellcode -> {args.to}", subtitle=(
            f"{result.get('detected_fmt')} | {result.get('output_size', 0):,} bytes | "
            f"transform={args.transform}"
        ))
        console.print(Syntax(output, result.get("hljs_lang") or "text",
                             theme="monokai", word_wrap=True, padding=(1, 2)))
        if result.get("xor_key_hex"):
            console.print(Text(f"  XOR key: {result['xor_key_hex']}", style="warn"))
        console.print()
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Readiness check: is the local DB ready to serve, and is Ollama needed?"""
    db = load_db()
    if db is None:
        return 1
    semantic = None
    if not OFFLINE:
        try:
            import semantic
        except Exception:
            pass

    def _count(sql: str) -> int:
        try:
            with closing(sqlite3.connect(db.DB_PATH)) as c:
                return c.execute(sql).fetchone()[0]
        except Exception:
            return 0

    docs      = db.kb_stats().get("docs", 0) if hasattr(db, "kb_stats") else _count("SELECT COUNT(*) FROM kb_docs")
    embedded  = _count("SELECT COUNT(*) FROM kb_embeddings")
    summaries = _count("SELECT COUNT(*) FROM kb_summaries")
    art_total = _count("SELECT COUNT(*) FROM artifact_map")
    art_brief = _count("SELECT COUNT(*) FROM artifact_summaries")
    actors    = _count("SELECT COUNT(*) FROM actor_summaries")
    families  = _count("SELECT COUNT(*) FROM family_summaries")
    cached_q  = db.query_embedding_count() if hasattr(db, "query_embedding_count") else 0
    ollama    = bool(semantic and semantic.available())

    def _row(label: str, done: int, total: int | None = None) -> str:
        ok    = done > 0 and (total is None or done >= total)
        mark  = f"[ok]{_mark('ok')}[/ok]" if ok else f"[warn]{_mark('warn')}[/warn]"
        value = f"{done}/{total}" if total else str(done)
        return f"  {mark} {label:<20} {value}"

    if args.json:
        _emit_json({
            "docs": docs, "embeddings": embedded, "summaries": summaries,
            "artifact_techniques": art_total, "artifact_briefs": art_brief,
            "actor_briefs": actors, "family_briefs": families,
            "cached_queries": cached_q, "ollama_available": ollama,
            "offline": OFFLINE,
        })
        return 0

    body = "\n".join([
        _row("docs indexed",   docs, docs),
        _row("embeddings",     embedded, docs),
        _row("summaries",      summaries, docs),
        _row("artifact briefs", art_brief, art_total),
        _row("actor briefs",   actors),
        _row("family briefs",  families),
        f"  [dim]·[/dim] [meta]cached queries[/meta]       {cached_q}",
        "",
        (f"  [ok]{_mark('ok')}[/ok] Ollama reachable - live semantic search enabled"
         if ollama else
         f"  [warn]{_mark('warn')}[/warn] Ollama offline - precomputed briefs work; "
         "live semantic search paused.\n"
         "     start Ollama, or on the GPU box run: [nav]python worker.py embed[/nav]"),
    ])
    _rule("peekaboo readiness")
    console.print(body)
    console.print()
    return 0


def cmd_tui(args: argparse.Namespace) -> int:
    """Launch the full-screen terminal application."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        _error("the TUI requires an interactive terminal")
        return 1
    if args.color == "always":
        os.environ.pop("NO_COLOR", None)
        os.environ["TEXTUAL_COLOR_SYSTEM"] = "truecolor"
    elif args.color == "never":
        os.environ["NO_COLOR"] = "1"
    try:
        from peekaboo_tui import launch_tui
    except ModuleNotFoundError as exc:
        if exc.name == "textual" or str(exc.name).startswith("textual."):
            _error("the TUI requires Textual; install with `python3 -m pip install -e .`")
            return 1
        raise
    return launch_tui(
        initial_view=args.view,
        db_path=args.db,
        offline=args.offline,
    )


def _cov_style(pct: int) -> str:
    return "ok" if pct >= 80 else ("warn" if pct >= 50 else "err")


def _pipeline_session(db, key: str) -> dict | None:
    session = db.get_pipeline_session(key)
    if session:
        return session
    hits = [row for row in db.get_pipeline_sessions(500)
            if row.get("session_id", "").startswith(key)]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        _warning(f"ambiguous session prefix: {key}")
    else:
        _error(f"no session {key!r}")
    return None


def _campaign_header(session: dict) -> None:
    params = session.get("params") or {}
    stages = params.get("stages") or []
    detection = params.get("detection") or {}
    pct = detection.get("coverage_pct")
    _rule(f"campaign {session.get('session_id', '')}")
    compact = console.width < 72
    cells = [
        _cell(session.get("actor_id", "?"), 14 if compact else 20, "nav"),
        _cell(f"{len(stages)} stages", 9 if compact else 12, "meta"),
        _cell(f"{pct}% coverage" if pct is not None else "no overlay", 14 if compact else 16,
              _cov_style(pct or 0) if pct is not None else "dim"),
        _cell(f"{len(detection.get('gaps') or [])} gaps", 7 if compact else 9,
              "err" if detection.get("gaps") else "ok"),
    ]
    _row(*cells)


def _render_campaign_path(stages: list[dict]) -> None:
    _rule("campaign path", "grey35")
    compact = console.width < 72
    for index, stage in enumerate(stages, 1):
        if index > 1:
            console.print(Text("     |", style="dim"))
        if compact:
            _row(_cell(f"o {index:02}", 5, "nav"),
                 _cell(stage.get("ttp_id", ""), 10, "warn"),
                 _cell(stage.get("ttp_name", ""), 34, "title"))
            _row(_cell("", 5), _tac(stage.get("tactic", "unknown"), 22),
                 _cell(stage.get("module_slug") or stage.get("module_id") or "-", 22, "meta"))
        else:
            _row(_cell(f"o {index:02}", 5, "nav"),
                 _tac(stage.get("tactic", "unknown"), 22),
                 _cell(stage.get("ttp_id", ""), 10, "warn"),
                 _cell(stage.get("ttp_name", ""), 34, "title"),
                 _cell(stage.get("module_slug") or stage.get("module_id") or "-", 26, "meta"))
    console.print()


def _render_hunt_view(stages: list[dict], detection: dict) -> None:
    _rule("hunt coverage", "grey35")
    compact = console.width < 72
    if compact:
        _head(("t-id", 10), ("technique", 24), ("sigma", 7, True), ("eventids", 8))
    else:
        _head(("tactic", 20), ("t-id", 10), ("technique", 32),
              ("sigma", 7, True), ("eventids", max(8, console.width - 79)))
    for stage in stages:
        overlay = stage.get("detection") or {}
        sigma = overlay.get("sigma_count", 0) if overlay.get("covered") else 0
        eids = " ".join(str(value) for value in (overlay.get("event_ids") or [])[:6]) or "-"
        cells = [] if compact else [_tac(stage.get("tactic", "unknown"), 20)]
        cells.extend([
            _cell(stage.get("ttp_id", ""), 10, "warn"),
            _cell(stage.get("ttp_name", ""), 24 if compact else 32, "title"),
            _cell(sigma if overlay else "-", 7, "ok" if sigma else "err", True),
            _cell(eids, 8 if compact else max(8, console.width - 79), "evt"),
        ])
        _row(*cells)
    generated = detection.get("generated_yara") or []
    if generated:
        _rule("generated blind-spot detections", "green")
        for item in generated:
            _row(_cell(item.get("ttp_id", ""), 10, "warn"),
                 _cell(item.get("file", ""), 48, "nav"))
    console.print()


def _render_evidence_view(stages: list[dict]) -> None:
    _rule("evidence trail", "grey35")
    compact = console.width < 72
    value_width = max(20, console.width - 19)
    split_width = max(9, (value_width - 2) // 2)
    for index, stage in enumerate(stages, 1):
        overlay = stage.get("detection") or {}
        state = f"{overlay.get('sigma_count', 0)} Sigma" if overlay.get("covered") else "blind spot"
        _row(_cell(f"{index:02}", 3, "nav"),
             _cell(stage.get("ttp_id", ""), 10, "warn"),
             _cell(stage.get("ttp_name", ""), 34 if compact else 42, "title"),
             _cell(state, 10 if compact else 14, "ok" if overlay.get("covered") else "err"))
        _row(_cell("", 3), _cell("report", 10, "dim"),
             _cell(stage.get("report_url") or "-", value_width, "meta"))
        evidence = " ".join(str(stage.get("evidence") or "").split()) or "-"
        _row(_cell("", 3), _cell("evidence", 10, "dim"),
             _cell(evidence, value_width, "title"))
        implementation = stage.get("module_slug") or stage.get("module_id") or "-"
        output = stage.get("_out_bin") or "-"
        _row(_cell("", 3), _cell("module", 10, "dim"),
             _cell(implementation, split_width, "nav"),
             _cell(output, value_width - split_width - 2, "meta"))
        console.print()


def _pipeline_diff(left: dict, right: dict) -> dict:
    def stage_map(session: dict) -> dict[str, dict]:
        stages = (session.get("params") or {}).get("stages") or []
        return {stage.get("ttp_id", ""): stage for stage in stages if stage.get("ttp_id")}

    left_stages = stage_map(left)
    right_stages = stage_map(right)
    shared = sorted(left_stages.keys() & right_stages.keys())
    module_changes = []
    for tid in shared:
        old = left_stages[tid].get("module_slug") or left_stages[tid].get("module_id") or ""
        new = right_stages[tid].get("module_slug") or right_stages[tid].get("module_id") or ""
        if old != new:
            module_changes.append({"ttp_id": tid, "from": old, "to": new})

    def coverage(session: dict) -> int | None:
        return ((session.get("params") or {}).get("detection") or {}).get("coverage_pct")

    old_pct, new_pct = coverage(left), coverage(right)
    return {
        "from": left.get("session_id"), "to": right.get("session_id"),
        "actors": [left.get("actor_id"), right.get("actor_id")],
        "coverage": {"from": old_pct, "to": new_pct,
                     "delta": (new_pct - old_pct) if old_pct is not None and new_pct is not None else None},
        "added": [{"ttp_id": tid, "name": right_stages[tid].get("ttp_name", "")}
                  for tid in sorted(right_stages.keys() - left_stages.keys())],
        "removed": [{"ttp_id": tid, "name": left_stages[tid].get("ttp_name", "")}
                    for tid in sorted(left_stages.keys() - right_stages.keys())],
        "shared": len(shared), "module_changes": module_changes,
    }


def _navigator_layer(session: dict) -> dict:
    params = session.get("params") or {}
    stages = params.get("stages") or []
    techniques: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for stage in stages:
        tid = stage.get("ttp_id", "")
        tactic = stage.get("tactic", "")
        if not tid or (tid, tactic) in seen:
            continue
        seen.add((tid, tactic))
        overlay = stage.get("detection") or {}
        module = stage.get("module_slug") or stage.get("module_id") or "-"
        evidence = " ".join(str(stage.get("evidence") or "").split())
        item = {
            "techniqueID": tid,
            "score": 100 if overlay.get("covered") else 0,
            "comment": _short(evidence, 500),
            "metadata": [
                {"name": "stage", "value": str(stage.get("stage_num") or len(techniques) + 1)},
                {"name": "implementation", "value": module},
                {"name": "Sigma rules", "value": str(overlay.get("sigma_count", 0))},
            ],
        }
        if tactic and tactic != "unknown":
            item["tactic"] = tactic
        links = []
        for label, url in (("Threat report", stage.get("report_url")),
                           ("Blog implementation", stage.get("blog_url"))):
            if isinstance(url, str) and url.startswith(("https://", "http://")):
                links.append({"label": label, "url": url})
        if links:
            item["links"] = links
        techniques.append(item)
    return {
        "name": f"Peekaboo {session.get('actor_id', '')} {session.get('session_id', '')}",
        "versions": {"navigator": "5.3.2", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Campaign simulation with detection coverage generated by Peekaboo.",
        "sorting": 2,
        "layout": {"layout": "side", "showID": True, "showName": True,
                   "expandedSubtechniques": "annotated"},
        "techniques": techniques,
        "gradient": {"colors": ["#FF453A", "#FFD60A", "#30D158"],
                     "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "Detection gap", "color": "#FF453A"},
            {"label": "Covered", "color": "#30D158"},
        ],
        "metadata": [
            {"name": "session", "value": str(session.get("session_id", ""))},
            {"name": "actor", "value": str(session.get("actor_id", ""))},
        ],
    }


def _campaign_markdown(session: dict) -> str:
    params = session.get("params") or {}
    stages = params.get("stages") or []
    detection = params.get("detection") or {}

    def clean(value: Any) -> str:
        return " ".join(str(value or "-").replace("|", "\\|").split())

    lines = [
        f"# Peekaboo campaign: {clean(session.get('actor_id'))}", "",
        f"- Session: `{clean(session.get('session_id'))}`",
        f"- Status: `{clean(session.get('status'))}`",
        f"- Coverage: `{detection.get('coverage_pct', '-')}%`", "",
        "| # | Tactic | Technique | Detection | Implementation | Evidence |",
        "|---:|---|---|---|---|---|",
    ]
    for index, stage in enumerate(stages, 1):
        overlay = stage.get("detection") or {}
        state = f"{overlay.get('sigma_count', 0)} Sigma" if overlay.get("covered") else "gap"
        technique = f"{stage.get('ttp_id', '')} {stage.get('ttp_name', '')}".strip()
        module = stage.get("module_slug") or stage.get("module_id") or "-"
        lines.append(
            f"| {index} | {clean(stage.get('tactic'))} | {clean(technique)} | "
            f"{clean(state)} | {clean(module)} | {clean(stage.get('evidence'))} |"
        )
    lines.append("")
    return "\n".join(lines)


def cmd_pipeline(args: argparse.Namespace) -> int:
    """APT campaign sessions and their blue-team detection overlay."""
    db = load_db()
    if db is None:
        return 1

    if args.pipeline_cmd == "show":
        session = _pipeline_session(db, args.session_id)
        if not session:
            return 1
        params = session.get("params") or {}
        stages = params.get("stages") or []
        detection = params.get("detection") or {}
        if args.json:
            _emit_json({"view": args.view, "session": session.get("session_id"),
                        "actor": session.get("actor_id"),
                        "detection": detection, "stages": stages})
            return 0
        _campaign_header(session)
        if args.view == "campaign":
            _render_campaign_path(stages)
        elif args.view == "evidence":
            _render_evidence_view(stages)
        else:
            _render_hunt_view(stages, detection)
        return 0

    if args.pipeline_cmd == "diff":
        left = _pipeline_session(db, args.session_a)
        right = _pipeline_session(db, args.session_b)
        if not left or not right:
            return 1
        result = _pipeline_diff(left, right)
        if args.json:
            _emit_json(result)
            return 0
        _rule(f"campaign diff {result['from']} -> {result['to']}")
        coverage = result["coverage"]
        _row(_cell(result["actors"][0], 20, "nav"), _cell("->", 3, "dim"),
             _cell(result["actors"][1], 20, "nav"),
             _cell(f"coverage {coverage['from']} -> {coverage['to']} ({coverage['delta']:+}%)"
                   if coverage["delta"] is not None else "coverage unavailable", 34,
                   _cov_style(coverage.get("to") or 0)))
        for label, rows, style in (("added", result["added"], "ok"),
                                   ("removed", result["removed"], "err")):
            if rows:
                console.print(Text(f"\n  {label} ({len(rows)})", style="heading"))
                for row in rows:
                    _row(_cell(row["ttp_id"], 10, style), _cell(row["name"], 42, "title"))
        if result["module_changes"]:
            console.print(Text(f"\n  implementation changes ({len(result['module_changes'])})", style="heading"))
            for row in result["module_changes"]:
                _row(_cell(row["ttp_id"], 10, "warn"), _cell(row["from"], 30, "meta"),
                     _cell("->", 3, "dim"), _cell(row["to"], 30, "nav"))
        console.print()
        return 0

    if args.pipeline_cmd == "export":
        session = _pipeline_session(db, args.session_id)
        if not session:
            return 1
        if args.format == "navigator":
            content = json.dumps(_navigator_layer(session), ensure_ascii=False, indent=2) + "\n"
        else:
            content = _campaign_markdown(session)
        if args.output:
            try:
                _write_text_atomic(args.output, content)
            except OSError as exc:
                _error(exc)
                return 1
            if args.json:
                _emit_json({"ok": True, "format": args.format,
                            "output": str(args.output), "bytes": len(content.encode("utf-8"))})
            else:
                console.print(f"  [ok]{_mark('ok')} wrote {_safe(args.output)}[/ok]\n")
        else:
            sys.stdout.write(content)
        return 0

    # default: list
    sessions = db.get_pipeline_sessions(getattr(args, "limit", 100))
    if args.json:
        _emit_json(sessions)
        return 0
    if not sessions:
        _warning("no pipeline sessions yet; run one from the dashboard APT Campaign tab")
        return 0

    _rule("apt campaigns")
    compact = console.width < 72
    if compact:
        _head(("session", 8), ("actor", 14), ("stages", 6), ("coverage", 9), ("gaps", 4, True))
    else:
        _head(("session", 8), ("actor", 16), ("stages", 6), ("coverage", 16),
              ("gaps", 4, True), ("status", 9))
    for s in sessions:
        det = (s.get("params") or {}).get("detection") or {}
        pct = det.get("coverage_pct")
        if pct is None:
            cov = "-"
        elif compact:
            cov = f"{pct}%"
        else:
            filled = round(pct / 100 * 8)
            cov = f"[{'#' * filled}{'-' * (8 - filled)}] {pct:>3}%"
        gaps = len(det.get("gaps", []))
        st  = s.get("status", "?")
        st_c = "ok" if st == "success" else ("err" if st == "failed" else "warn")
        cells = [
            _cell(s.get("session_id", ""), 8, "nav"),
            _cell(s.get("actor_id", ""), 14 if compact else 16, "title"),
            _cell(det.get("stages_total", len((s.get("params") or {}).get("stages") or [])), 6, "count"),
            _cell(cov, 9 if compact else 16, _cov_style(pct or 0)),
            _cell(gaps, 4, "err" if gaps else "ok", True),
        ]
        if not compact:
            cells.append(_cell(st, 9, st_c))
        _row(*cells)
    console.print()
    _hint("peekaboo pipeline show <session>")
    return 0


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
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="color mode (default: auto)")
    parser.add_argument("--offline", action="store_true", help="disable network operations")
    parser.add_argument("--quiet", action="store_true", help="hide next-step hints")
    parser.add_argument("--db", type=Path, help="override the SQLite database path")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND", parser_class=ColorHelpParser)
    sub.add_parser("examples", help="show quick workflows")
    sub.add_parser("status", help="readiness check (indexed data + Ollama)")
    p = sub.add_parser("tui", help="launch the full-screen terminal application")
    p.add_argument(
        "--view",
        choices=(
            "overview",
            "campaigns",
            "library",
            "attack",
            "detection",
            "intel",
            "builds",
            "samples",
            "tools",
        ),
        default="overview",
    )
    p = sub.add_parser("doctor", help="verify local data, demo assets and toolchain")
    p.add_argument("--demo", action="store_true", help="require campaign demo assets")
    p = sub.add_parser("search", help="search all local intelligence")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=8, help="maximum results per section")

    pipeline = sub.add_parser("pipeline", help="APT campaigns + detection overlay")
    sp = pipeline.add_subparsers(dest="pipeline_cmd", metavar="COMMAND", parser_class=ColorHelpParser)
    p = sp.add_parser("list", help="list campaign sessions with coverage")
    p.add_argument("--limit", type=int, default=100)
    p = sp.add_parser("show", help="view campaign, hunt coverage or evidence")
    p.add_argument("session_id")
    p.add_argument("--view", choices=("campaign", "hunt", "evidence"), default="hunt")
    p = sp.add_parser("diff", help="compare techniques and implementations")
    p.add_argument("session_a")
    p.add_argument("session_b")
    p = sp.add_parser("export", help="export a session for sharing")
    p.add_argument("session_id")
    p.add_argument("--format", choices=("navigator", "markdown"), default="navigator")
    p.add_argument("--output", "-o", type=Path)

    library = sub.add_parser("library", help="browse research modules")
    sp = library.add_subparsers(dest="library_cmd", metavar="COMMAND", parser_class=ColorHelpParser)
    p = sp.add_parser("list"); p.add_argument("--category", "-c"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("search"); p.add_argument("query"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("show"); p.add_argument("slug")
    p = sp.add_parser("brief"); p.add_argument("slug")
    sp.add_parser("cats")

    malpedia = sub.add_parser("malpedia", help="actors, families and reports")
    sp = malpedia.add_subparsers(dest="malpedia_cmd", metavar="COMMAND", parser_class=ColorHelpParser)
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
    sp = ttp.add_subparsers(dest="ttp_cmd", metavar="COMMAND", parser_class=ColorHelpParser)
    p = sp.add_parser("list"); p.add_argument("--tactic"); p.add_argument("--platform", choices=["windows", "linux", "macos"]); p.add_argument("--limit", type=int, default=200)
    p = sp.add_parser("search"); p.add_argument("query"); p.add_argument("--limit", type=int, default=50)
    p = sp.add_parser("show"); p.add_argument("attack_id")
    p = sp.add_parser("brief"); p.add_argument("attack_id")

    artifacts = sub.add_parser("artifacts", help="ATT&CK x Sigma coverage")
    sp = artifacts.add_subparsers(dest="artifacts_cmd", metavar="COMMAND", parser_class=ColorHelpParser)
    p = sp.add_parser("list"); p.add_argument("--tactic"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("search"); p.add_argument("query"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("show"); p.add_argument("tid")
    p = sp.add_parser("rules"); p.add_argument("tid"); p.add_argument("--level", choices=["critical", "high", "medium", "low", "informational"]); p.add_argument("--limit", type=int, default=60)
    sp.add_parser("tactics")
    sp.add_parser("stats")
    p = sp.add_parser("brief"); p.add_argument("tid")

    builder = sub.add_parser("builder", help="build research modules")
    sp = builder.add_subparsers(dest="builder_cmd", metavar="COMMAND", parser_class=ColorHelpParser)
    p = sp.add_parser("list"); p.add_argument("--platform", choices=["windows", "linux", "macos"]); p.add_argument("--category"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("search"); p.add_argument("query"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("history"); p.add_argument("--limit", type=int, default=PAGE)
    p = sp.add_parser("show"); p.add_argument("build_id")
    p = sp.add_parser("build"); p.add_argument("slug")

    yara = sub.add_parser("yara", help="generate YARA rules")
    sp = yara.add_subparsers(dest="yara_cmd", metavar="COMMAND", parser_class=ColorHelpParser)
    p = sp.add_parser("gen"); p.add_argument("path", type=Path); p.add_argument("--save", type=Path)
    p = sp.add_parser("gen-build"); p.add_argument("build_id"); p.add_argument("--filename"); p.add_argument("--save", type=Path)
    p = sp.add_parser("builds"); p.add_argument("--limit", type=int, default=50)

    vt = sub.add_parser("vtscan", help="VirusTotal analysis")
    sp = vt.add_subparsers(dest="vtscan_cmd", metavar="COMMAND", parser_class=ColorHelpParser)
    p = sp.add_parser("list"); p.add_argument("--limit", type=int, default=50)
    p = sp.add_parser("lookup"); p.add_argument("sha256")
    p = sp.add_parser("poll"); p.add_argument("analysis_id")
    p = sp.add_parser("scan"); p.add_argument("build_id"); p.add_argument("--yes", action="store_true")
    p = sp.add_parser("scan-file"); p.add_argument("path", type=Path); p.add_argument("--yes", action="store_true")

    shellcode_parser = sub.add_parser("shellcode", help="analyse and convert local byte payloads")
    sp = shellcode_parser.add_subparsers(dest="shellcode_cmd", metavar="COMMAND",
                                         parser_class=ColorHelpParser)
    p = sp.add_parser("analyse", aliases=["analyze"], help="inspect a file or stdin without modifying it")
    p.add_argument("source", help="file path or - for stdin")
    p = sp.add_parser("convert", help="transform and format a file or stdin")
    p.add_argument("source", help="file path or - for stdin")
    p.add_argument("--to", choices=SHELLCODE_FORMATS, default="c")
    p.add_argument("--transform", choices=SHELLCODE_TRANSFORMS, default="none")
    p.add_argument("--xor-key", help="key for the xor_key transform")
    p.add_argument("--var", default="buf", help="output variable name")
    p.add_argument("--output", "-o", type=Path, help="write formatted output to a file")
    p.add_argument("--raw", action="store_true", help="emit only formatted output")
    sp.add_parser("formats", help="list output formats and transforms")
    return parser


_GLOBAL_FLAGS = {"--json", "--offline", "--quiet"}
_GLOBAL_VALUES = {"--color", "--db"}


def _normalize_global_options(argv: list[str]) -> list[str]:
    """Allow global flags before or after a subcommand without parser duplication."""
    global_args: list[str] = []
    command_args: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            command_args.extend(argv[i:])
            break
        if arg in _GLOBAL_FLAGS:
            global_args.append(arg)
        elif arg in _GLOBAL_VALUES:
            global_args.append(arg)
            if i + 1 < len(argv):
                i += 1
                global_args.append(argv[i])
        elif any(arg.startswith(f"{name}=") for name in _GLOBAL_VALUES):
            global_args.append(arg)
        else:
            command_args.append(arg)
        i += 1
    return global_args + command_args


def _option_value(argv: list[str], name: str, default: str) -> str:
    for i, arg in enumerate(argv):
        if arg == name and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(f"{name}="):
            return arg.split("=", 1)[1]
    return default

def main(argv: list[str] | None = None) -> int:
    global QUIET, OFFLINE
    argv = _normalize_global_options(list(sys.argv[1:] if argv is None else argv))
    _configure_console(_option_value(argv, "--color", "auto"))
    parser = build_parser()
    args = parser.parse_args(argv)
    QUIET = args.quiet
    OFFLINE = args.offline
    if args.db:
        os.environ["PEEKABOO_DB_PATH"] = str(args.db.expanduser().resolve())

    try:
        if args.command is None:
            if sys.stdin.isatty() and sys.stdout.isatty():
                args.view = "overview"
                return cmd_tui(args)
            render_home()
            return 0
        handlers = {
            "examples": lambda _args: (render_examples() or 0),
            "status": cmd_status,
            "tui": cmd_tui,
            "doctor": cmd_doctor,
            "search": cmd_search,
            "pipeline": cmd_pipeline,
            "library": cmd_library,
            "malpedia": cmd_malpedia,
            "ttp": cmd_ttp,
            "artifacts": cmd_artifacts,
            "builder": cmd_builder,
            "yara": cmd_yara,
            "vtscan": cmd_vtscan,
            "shellcode": cmd_shellcode,
        }
        return handlers[args.command](args)
    except KeyboardInterrupt:
        _warning("interrupted")
        return 130
    except BrokenPipeError:
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
            os.close(devnull)
        except OSError:
            pass
        return 0

if __name__ == "__main__":
    exit_code = main()
    try:
        sys.stdout.flush()
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)
        exit_code = 0
    raise SystemExit(exit_code)
