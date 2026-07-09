#!/usr/bin/env python3
# command-first CLI for peekaboo.
# The CLI intentionally stays thin: it loads data from dashboard modules, renders
# compact Rich tables, and prints a small set of next-step hints.
# author: @cocomelonc

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
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
SEV_STYLE = {
    "critical": "bold #FF453A", "high": "#FF453A", "medium": "#FFD60A",
    "low": "#64D2FF", "informational": "grey50", "info": "grey50",
}

# Always-on color: force truecolor even when output is piped or redirected.
console = Console(theme=THEME, highlight=False, force_terminal=True,
                  color_system="truecolor")


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
    console.print(json.dumps(value, ensure_ascii=False, indent=2, default=_json_default))

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
    console.print("  [heading]? Try:[/heading]")
    for command in clean:
        console.print(f"  [nav]{command}[/nav]")
    console.print()

def _strip_markup(value: str) -> str:
    return Text.from_markup(value).plain

def _hash_header(title: str, subtitle: str | None = None, style: str = "cyan") -> None:
    _rule(title, style, subtitle)

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
    _rule(title, style)
    console.print(body.rstrip())
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
    dash = "-" * max(4, 50 - len(_strip_markup(title)))
    console.print(f"\n[bold black on {bg}] {title} [/] [{bg}]{dash}[/]")
    if subtitle:
        console.print(f"  [meta]{subtitle}[/meta]")

def _bar(pct: int, width: int = 10) -> str:
    """ASCII progress bar `[####------]` colored by coverage level."""
    style  = "ok" if pct >= 80 else ("warn" if pct >= 50 else "err")
    filled = round(pct / 100 * width)
    # escape the literal opening bracket so rich doesn't parse it as markup
    return f"[{style}]\\[{'#' * filled}{'-' * (width - filled)}] {pct:>3}%[/]"

# --- frameless column primitives -------------------------------------------
# Rich markup counts style tags as width, so we pad the *plain* text first,
# then colorize. Four helpers replace every boxed Table in this file.

def _cell(text: Any, w: int, style: str | None = None, right: bool = False) -> str:
    s = _short("" if text is None else str(text), w)
    s = s.rjust(w) if right else s.ljust(w)
    return f"[{style}]{s}[/]" if style else s

def _row(*cells: str) -> None:
    console.print("  " + "  ".join(cells))

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
    return f"[bold {fg} on {bg}] {text} [/]"

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
    _hash_header("PEEKABOO", "Threat Research & Detection Engineering Lab")
    console.print()
    console.print("  [heading]Explore[/heading]\n")
    console.print("  [dim]>[/dim] [nav]library[/nav]      Browse research modules")
    console.print("  [dim]>[/dim] [nav]malpedia[/nav]     Threat actors, families and reports")
    console.print("  [dim]>[/dim] [nav]ttp[/nav]          Explore MITRE ATT&CK techniques")
    console.print("  [dim]>[/dim] [nav]artifacts[/nav]    ATT&CK x Sigma detection coverage")
    console.print()
    console.print("  [heading]Tools[/heading]\n")
    console.print("  [dim]>[/dim] [nav]yara[/nav]         Generate and inspect YARA rules")
    console.print("  [dim]>[/dim] [nav]vtscan[/nav]       VirusTotal analysis")
    console.print("  [dim]>[/dim] [nav]builder[/nav]      Research module build workflow")
    console.print("  [dim]>[/dim] [nav]shellcode[/nav]    Local binary analysis tools")
    console.print()
    console.print("  [heading]Quick examples[/heading]\n")
    console.print("  [dim]$[/dim] peekaboo malpedia search lazarus")
    console.print("  [dim]$[/dim] peekaboo malpedia reports --limit 10")
    console.print("  [dim]$[/dim] peekaboo ttp show T1055")
    console.print("  [dim]$[/dim] peekaboo artifacts rules T1059.001 --level high")
    console.print()
    console.print("  [dim]?[/dim] Run [nav]peekaboo <command> --help[/nav]")
    console.print("  [dim]>[/dim] Run [nav]peekaboo examples[/nav]\n")

def render_examples() -> None:
    body = """\
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
"""
    _hash_header("Quick Start", "Common Peekaboo workflows")
    console.print()
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
    values = mp.list_actors() if kind == "actor" else mp.list_families()
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


def cmd_status(args: argparse.Namespace) -> int:
    """Readiness check: is the local DB ready to serve, and is Ollama needed?"""
    import sqlite3
    db = load_db()
    try:
        import semantic
    except Exception:
        semantic = None

    def _count(sql: str) -> int:
        try:
            with sqlite3.connect(db.DB_PATH) as c:
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


def _cov_style(pct: int) -> str:
    return "ok" if pct >= 80 else ("warn" if pct >= 50 else "err")


def cmd_pipeline(args: argparse.Namespace) -> int:
    """APT campaign sessions and their blue-team detection overlay."""
    db = load_db()

    if args.pipeline_cmd == "show":
        sid  = args.session_id
        sess = db.get_pipeline_session(sid)
        if not sess:
            console.print(f"  [err]{_mark('err')} no session {sid!r}[/err]\n")
            return 1
        params = sess.get("params") or {}
        stages = params.get("stages") or []
        det    = params.get("detection") or {}

        if args.json:
            _emit_json({"session": sid, "actor": sess.get("actor_id"),
                        "detection": det, "stages": stages})
            return 0

        _rule(f"campaign {sid}")
        if not det:
            console.print(
                f"  actor [nav]{sess.get('actor_id','?')}[/nav]   "
                f"stages [meta]{len(stages)}[/meta]   "
                f"[dim]no detection overlay - re-run this actor to generate one[/dim]"
            )
        else:
            pct = det.get("coverage_pct", 0)
            console.print(
                f"  actor [nav]{sess.get('actor_id','?')}[/nav]   "
                f"stages [meta]{det.get('stages_total', len(stages))}[/meta]   "
                f"coverage {_bar(pct)}   "
                f"blind spots [err]{len(det.get('gaps', []))}[/err]"
            )

        _rule("kill chain", "grey35")
        for s in stages:
            d    = s.get("detection")
            tag  = f"[meta]{s.get('tactic','unknown'):<20}[/meta]"
            aid  = f"[warn]{s.get('ttp_id',''):<9}[/warn]"
            name = _short(s.get("ttp_name", ""), 30)
            if d is None:
                console.print(f"  {tag} {aid} {name:<32} [dim]module {_short(s.get('module_id',''),24)}[/dim]")
                continue
            if d.get("covered"):
                eids = ", ".join(str(e) for e in (d.get("event_ids") or [])[:6])
                console.print(f"  {tag} {aid} {name:<32} "
                              f"[ok]{d.get('sigma_count',0)} sigma[/ok]"
                              + (f"  [dim]eid {eids}[/dim]" if eids else ""))
            else:
                extra = (f"[ok]-> {d['yara_file']}[/ok]" if d.get("yara_file")
                         else f"[dim]{d.get('yara_hint','')}[/dim]")
                console.print(f"  {tag} {aid} {name:<32} [err]NO SIGMA[/err]  {extra}")

        gaps = det.get("gaps") or []
        yars = det.get("generated_yara") or []
        if yars:
            _rule("generated detections (blind-spot YARA)", "green")
            for y in yars:
                console.print(f"  [ok]{_mark('ok')}[/ok] {y['ttp_id']:<9} [nav]{y['file']}[/nav]")
        console.print()
        return 0

    # default: list
    sessions = db.get_pipeline_sessions()
    if args.json:
        _emit_json(sessions)
        return 0
    if not sessions:
        console.print(f"  [warn]{_mark('warn')} no pipeline sessions yet[/warn] - run one from the dashboard APT Campaign tab\n")
        return 0

    _rule("apt campaigns")
    console.print("  [dim]session   actor              stages  coverage         gaps  status[/dim]")
    for s in sessions:
        det = (s.get("params") or {}).get("detection") or {}
        pct = det.get("coverage_pct")
        cov = _bar(pct) if pct is not None else "[dim]     -      [/dim]"
        gaps = len(det.get("gaps", []))
        st  = s.get("status", "?")
        st_c = "ok" if st == "success" else ("err" if st == "failed" else "warn")
        console.print(
            f"  [nav]{s.get('session_id',''):<8}[/nav]  "
            f"{_short(s.get('actor_id',''), 16):<16}  "
            f"{det.get('stages_total', 0):<6}  {cov}  "
            f"[err]{gaps:<4}[/err]  [{st_c}]{st}[/{st_c}]"
        )
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

    sub = parser.add_subparsers(dest="command", parser_class=ColorHelpParser)
    sub.add_parser("examples", help="show quick workflows")
    sub.add_parser("status", help="readiness check (indexed data + Ollama)")

    pipeline = sub.add_parser("pipeline", help="APT campaigns + detection overlay")
    sp = pipeline.add_subparsers(dest="pipeline_cmd", parser_class=ColorHelpParser)
    sp.add_parser("list", help="list campaign sessions with coverage")
    p = sp.add_parser("show", help="purple-team hunt sheet for a session")
    p.add_argument("session_id")

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
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        render_home()
        return 0
    handlers = {
        "examples": lambda _args: (render_examples() or 0),
        "status": cmd_status,
        "pipeline": cmd_pipeline,
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
