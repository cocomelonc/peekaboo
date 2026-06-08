#!/usr/bin/env python3
"""
peekaboo_cli.py - interactive CLI for the peekaboo red/blue team lab
DEFCON Demo Labs Singapore 2026

Usage:
    /home/cocomelonc/hacking/peekaboo/py3/bin/python3 peekaboo_cli.py
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

# -- make dashboard modules importable ----------------------------------------
DASHBOARD = Path(__file__).parent / "dashboard"
sys.path.insert(0, str(DASHBOARD))

# -- rich ----------------------------------------------------------------------
from rich.console import Console
from rich.theme import Theme
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich.columns import Columns
from rich import box

# -- prompt_toolkit ------------------------------------------------------------
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style as PtStyle

# -- custom theme (ASCII-safe colors only, no Unicode symbols) -----------------
THEME = Theme({
    "banner":   "bold green",
    "prompt":   "bold cyan",
    "cmd":      "bold yellow",
    "ok":       "bold green",
    "warn":     "bold yellow",
    "err":      "bold red",
    "info":     "cyan",
    "dim":      "grey50",
    "heading":  "bold white",
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "good":     "green",
})

console = Console(theme=THEME, highlight=False)

# -- severity -> style map -----------------------------------------------------
SEV_STYLE = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "ok":       "good",
    "info":     "info",
}

SEV_TAG = {
    "critical": "[CRIT]",
    "high":     "[HIGH]",
    "medium":   "[MED] ",
    "low":      "[LOW] ",
    "ok":       "[ OK ]",
    "info":     "[INFO]",
}

# -- prompt_toolkit style ------------------------------------------------------
PT_STYLE = PtStyle.from_dict({
    "prompt": "ansicyan bold",
})

BANNER = r"""[=^..^=]
[=^..^=] #####  ###### #    #         ##         #####   ####   ####
[=^..^=] #    # #      #   #         #  #        #    # #    # #    #
[=^..^=] #    # #####  ####   ##### #    # ##### #####  #    # #    #
[=^..^=] #####  #      #  #         ######       #    # #    # #    #
[=^..^=] #      #      #   #        #    #       #    # #    # #    #
[=^..^=] #      ###### #    #       #    #       #####   ####   ####
[=^..^=]
[=^..^=] Malware Development Framework (for trainings, education and research)
[=^..^=] by @cocomelonc - https://cocomelonc.github.io
"""


def print_banner() -> None:
    console.print(BANNER, style="banner")


# -- top-level commands --------------------------------------------------------
TOP_COMMANDS = [
    "evasion", "library", "help", "exit", "quit",
]

TOP_HELP = [
    ("evasion",  "PE evasion scorer + surgical patch transforms"),
    ("library",  "MITRE ATT&CK module library -- browse, search, view source"),
    ("help",     "show this help"),
    ("exit",     "quit peekaboo-cli"),
]


def print_top_help() -> None:
    t = Table(box=box.ASCII, show_header=True, header_style="heading",
              border_style="dim", padding=(0, 1))
    t.add_column("command", style="cmd",  no_wrap=True, min_width=14)
    t.add_column("description", style="info")
    for cmd, desc in TOP_HELP:
        t.add_row(cmd, desc)
    console.print()
    console.print(t)
    console.print()


# -- module library ------------------------------------------------------------

_EXT_LANG = {
    ".c":   "c",
    ".cpp": "cpp",
    ".cc":  "cpp",
    ".asm": "nasm",
    ".s":   "gas",
    ".nim": "nim",
    ".py":  "python",
    ".go":  "go",
    ".rs":  "rust",
}

LIB_PAGE_SIZE = 20

LIBRARY_COMMANDS = [
    "list", "search", "show", "cats", "help", "back",
]

LIBRARY_HELP = [
    ("list [category]",   "list modules, optionally filtered by category"),
    ("search <query>",    "search by title, T-ID or slug (case-insensitive)"),
    ("show <slug>",       "show details + source code for a module"),
    ("cats",              "list all categories with entry counts"),
    ("help",              "show this help"),
    ("back",              "return to main menu"),
]


def _library_help() -> None:
    t = Table(box=box.ASCII, show_header=True, header_style="heading",
              border_style="dim", padding=(0, 1))
    t.add_column("command",     style="cmd",  no_wrap=True, min_width=22)
    t.add_column("description", style="info")
    for cmd, desc in LIBRARY_HELP:
        t.add_row(cmd, desc)
    console.print()
    console.print(t)
    console.print()


def _impl_badge(impl: bool) -> Text:
    return Text("[yes]", style="ok") if impl else Text("[ - ]", style="dim")


def _tids_str(ids: list) -> str:
    if not ids:
        return "-"
    return " ".join(ids[:3]) + ("+" if len(ids) > 3 else "")


def _render_library_table(entries: list[dict], title: str = "Module Library",
                           page: int = 0) -> int:
    """Render one page of the library table. Returns total page count."""
    total   = len(entries)
    pages   = max(1, (total + LIB_PAGE_SIZE - 1) // LIB_PAGE_SIZE)
    start   = page * LIB_PAGE_SIZE
    chunk   = entries[start:start + LIB_PAGE_SIZE]

    t = Table(box=box.ASCII, show_header=True, header_style="heading",
              border_style="dim", padding=(0, 1),
              title=f"{title}  [{start+1}-{min(start+len(chunk), total)} / {total}]",
              show_lines=False)
    t.add_column("#",        style="dim",  min_width=4,  justify="right", no_wrap=True)
    t.add_column("slug",     style="cmd",  min_width=22, no_wrap=True)
    t.add_column("category", style="info", min_width=14, no_wrap=True)
    t.add_column("T-IDs",    style="warn", min_width=12, no_wrap=True)
    t.add_column("impl",     min_width=5,  no_wrap=True)
    t.add_column("title",    min_width=40)

    for i, e in enumerate(chunk, start + 1):
        t.add_row(
            str(i),
            e["slug"],
            e["category"],
            _tids_str(e["attack_ids"]),
            _impl_badge(e["implemented"]),
            e["title"][:60] + ("..." if len(e["title"]) > 60 else ""),
        )

    console.print()
    console.print(t)
    if pages > 1:
        console.print(
            f"  [dim]page {page+1}/{pages} -- "
            f"press Enter for next page, or  show <slug>  to open[/dim]\n"
        )
    return pages


def _render_module_detail(e: dict) -> None:
    """Render full module detail + source code inside the pager."""
    tids = ", ".join(e["attack_ids"]) if e["attack_ids"] else "none"
    impl = "yes" if e["implemented"] else "no"
    meta = (
        f"  Slug     : {e['slug']}\n"
        f"  Title    : {e['title']}\n"
        f"  Category : {e['category']}\n"
        f"  Date     : {e['date']}\n"
        f"  T-IDs    : {tids}\n"
        f"  Impl     : {impl}\n"
    )
    if e.get("module"):
        meta += f"  Module   : {e['module']}\n"
    if e.get("blog_url"):
        meta += f"  URL      : {e['blog_url']}\n"

    console.print()
    console.print(Panel(meta.rstrip(),
                        title=f"[heading] {e['slug']} [/heading]",
                        border_style="cyan", box=box.ASCII))

    # source code
    src_text: str | None = None
    lang = "text"

    src_path = e.get("src_path", "")
    if src_path:
        p = Path(src_path)
        lang = _EXT_LANG.get(p.suffix.lower(), "text")
        if p.exists():
            try:
                src_text = p.read_text(errors="replace")
            except Exception:
                src_text = None

    if src_text is None and e.get("snippet"):
        src_text = e["snippet"]

    if not src_text:
        console.print("  [dim](no source available)[/dim]\n")
        return

    # choose whether to use pager (file > 60 lines)
    lines = src_text.count("\n")
    syn = Syntax(
        src_text,
        lang,
        theme="monokai",
        line_numbers=True,
        word_wrap=False,
    )

    if lines > 55:
        with console.pager(styles=True):
            console.print(Panel(syn,
                                title=f"[heading] {Path(src_path).name if src_path else 'snippet'} "
                                      f"({lang}, {lines} lines) [/heading]",
                                border_style="dim", box=box.ASCII))
    else:
        console.print(Panel(syn,
                            title=f"[heading] {Path(src_path).name if src_path else 'snippet'} "
                                  f"({lang}, {lines} lines) [/heading]",
                            border_style="dim", box=box.ASCII))
    console.print()


def run_library() -> None:
    """Interactive module library sub-REPL."""
    try:
        import db as _db
    except ImportError as e:
        console.print(f"[err][!] db module unavailable: {e}[/err]")
        return

    all_entries = _db.get_mitre_entries()
    if not all_entries:
        console.print("[warn][!] module library is empty - run the dashboard rebuild first[/warn]")
        return

    # build category -> entries map
    from collections import Counter
    cat_counts: Counter = Counter(e["category"] for e in all_entries)
    all_cats = sorted(cat_counts.keys())

    # slug -> entry lookup
    slug_map = {e["slug"]: e for e in all_entries}

    completer = WordCompleter(
        LIBRARY_COMMANDS + all_cats + list(slug_map.keys()),
        ignore_case=True,
    )
    session: PromptSession = PromptSession(
        history=InMemoryHistory(),
        completer=completer,
        style=PT_STYLE,
    )

    console.print()
    console.print(Panel(
        f"  {len(all_entries)} modules across {len(all_cats)} categories\n"
        f"  type  help  for commands,  cats  for category list,  back  to return",
        title="[heading] Module Library [/heading]",
        border_style="cyan",
        box=box.ASCII,
    ))
    console.print()

    # state for pagination
    current_view: list[dict] = all_entries
    current_title = "Module Library"
    current_page  = 0
    total_pages   = 0

    while True:
        try:
            raw = session.prompt(
                "peekaboo [library] > ",
                style=PT_STYLE,
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]use  back  to return[/dim]")
            continue

        if not raw:
            # empty enter = next page
            if total_pages > 1 and current_page + 1 < total_pages:
                current_page += 1
                total_pages = _render_library_table(
                    current_view, current_title, current_page
                )
            continue

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        # -- back -------------------------------------------------------------
        if cmd in ("back", "exit", "quit"):
            break

        # -- help -------------------------------------------------------------
        elif cmd == "help":
            _library_help()

        # -- cats -------------------------------------------------------------
        elif cmd == "cats":
            t = Table(box=box.ASCII, show_header=True, header_style="heading",
                      border_style="dim", padding=(0, 1), title="Categories")
            t.add_column("category",  style="cmd",  min_width=22)
            t.add_column("entries",   style="info", min_width=8, justify="right")
            t.add_column("bar",       min_width=30)
            max_n = max(cat_counts.values())
            for cat in all_cats:
                n     = cat_counts[cat]
                width = int(n / max_n * 28)
                bar   = Text("[" + "#" * width + "." * (28 - width) + "]",
                             style="cyan")
                t.add_row(cat, str(n), bar)
            console.print()
            console.print(t)
            console.print()

        # -- list [category] ---------------------------------------------------
        elif cmd == "list":
            if args:
                cat = args[0].lower()
                current_view = [e for e in all_entries
                                if e["category"].lower() == cat]
                if not current_view:
                    # fuzzy: contains match
                    current_view = [e for e in all_entries
                                    if cat in e["category"].lower()]
                if not current_view:
                    console.print(
                        f"[warn][!] no entries for category '{cat}' "
                        f"-- type  cats  to see valid categories[/warn]"
                    )
                    continue
                current_title = f"Library: {cat}"
            else:
                current_view  = all_entries
                current_title = "Module Library"
            current_page = 0
            total_pages  = _render_library_table(
                current_view, current_title, current_page
            )

        # -- search ------------------------------------------------------------
        elif cmd == "search":
            if not args:
                console.print("[warn][!] usage: search <query>[/warn]")
                continue
            q = " ".join(args).lower()
            hits = [
                e for e in all_entries
                if q in e["title"].lower()
                or q in e["slug"].lower()
                or q in e["category"].lower()
                or any(q in tid.lower() for tid in e["attack_ids"])
            ]
            if not hits:
                console.print(f"  [warn][!] no results for '{q}'[/warn]\n")
                continue
            current_view  = hits
            current_title = f"Search: {q}"
            current_page  = 0
            total_pages   = _render_library_table(
                current_view, current_title, current_page
            )

        # -- show --------------------------------------------------------------
        elif cmd == "show":
            if not args:
                console.print("[warn][!] usage: show <slug>[/warn]")
                continue
            slug = args[0]
            entry = slug_map.get(slug)
            if not entry:
                # try partial match
                matches = [s for s in slug_map if slug in s]
                if len(matches) == 1:
                    entry = slug_map[matches[0]]
                elif len(matches) > 1:
                    console.print(
                        f"  [warn][!] ambiguous slug '{slug}', "
                        f"matches: {', '.join(matches[:5])}[/warn]\n"
                    )
                    continue
                else:
                    console.print(
                        f"  [err][!] slug not found: '{slug}'[/err]\n"
                    )
                    continue
            _render_module_detail(entry)

        else:
            console.print(
                f"[warn][!] unknown command: {cmd}  "
                f"(type  help  for commands)[/warn]"
            )


# -- evasion module ------------------------------------------------------------

def _load_evasion_module():
    try:
        import evasion as _ev
        return _ev
    except ImportError as e:
        console.print(f"[err][!] evasion module unavailable: {e}[/err]")
        return None


EVASION_COMMANDS = [
    "load", "analyse", "patches", "patch", "apply", "info", "help", "back",
]

EVASION_HELP = [
    ("load <path>",          "load a PE / binary file for analysis"),
    ("analyse",              "run evasion score analysis on loaded file"),
    ("patches",              "list available patch transforms for loaded file"),
    ("patch <id> [id ...]",  "select patches to apply (space-separated IDs)"),
    ("apply [output]",       "apply selected patches and save patched binary"),
    ("info",                 "show loaded file metadata"),
    ("help",                 "show this help"),
    ("back",                 "return to main menu"),
]


def _evasion_help() -> None:
    t = Table(box=box.ASCII, show_header=True, header_style="heading",
              border_style="dim", padding=(0, 1))
    t.add_column("command", style="cmd",  no_wrap=True, min_width=24)
    t.add_column("description", style="info")
    for cmd, desc in EVASION_HELP:
        t.add_row(cmd, desc)
    console.print()
    console.print(t)
    console.print()


def _score_style(score: int) -> str:
    if score >= 80: return "ok"
    if score >= 65: return "low"
    if score >= 50: return "medium"
    if score >= 35: return "warn"
    return "err"


def _grade_label(g: str) -> str:
    return {"A": "excellent", "B": "good", "C": "moderate",
            "D": "poor", "F": "critical"}.get(g, "")


def _render_evasion_results(result: dict) -> None:
    score = result["score"]
    grade = result["grade"]
    ss    = _score_style(score)

    # -- score summary panel ---------------------------------------------------
    lines = [
        f"  Score : [{ss}]{score}/100  Grade: {grade} ({_grade_label(grade)})[/{ss}]",
        f"  File  : {result.get('filename','?')}  |  "
        f"{result['size']//1024} KB  |  "
        f"entropy {result['file_entropy']}  |  "
        f"{'PE' if result['is_pe'] else 'non-PE'}",
        f"  MD5   : [dim]{result['md5']}[/dim]",
    ]
    console.print()
    console.print(Panel(
        "\n".join(lines),
        title="[heading] Evasion Score [/heading]",
        border_style=ss,
        box=box.ASCII,
    ))

    # -- category breakdown ----------------------------------------------------
    cats = Table(box=box.ASCII, show_header=True, header_style="heading",
                 border_style="dim", padding=(0, 1), title="Score Breakdown")
    cats.add_column("category",  style="info",    min_width=14)
    cats.add_column("score",     style="heading",  min_width=6, justify="right")
    cats.add_column("bar",       min_width=26, no_wrap=True)
    cats.add_column("/ 25",      style="dim",      min_width=4)

    def _bar(val: int, width: int = 20) -> Text:
        filled = int(val / 25 * width)
        t = Text()
        t.append("[" + "#" * filled + "." * (width - filled) + "]",
                 style=_score_style(val * 4))
        return t

    for label, key in [
        ("Entropy",      "score_entropy"),
        ("Imports",      "score_imports"),
        ("Strings",      "score_strings"),
        ("PE Structure", "score_structure"),
    ]:
        v = result[key]
        cats.add_row(label, str(v), _bar(v), "/ 25")

    console.print(cats)

    # -- findings --------------------------------------------------------------
    findings = [f for f in result["findings"] if f["severity"] != "ok"]
    if findings:
        ft = Table(box=box.ASCII, show_header=True, header_style="heading",
                   border_style="dim", padding=(0, 1), title="Findings",
                   show_lines=True)
        ft.add_column("sev",        min_width=7,  no_wrap=True)
        ft.add_column("category",   style="info", min_width=10, no_wrap=True)
        ft.add_column("title",      min_width=36)
        ft.add_column("suggestion", style="dim",  min_width=30)

        for f in findings:
            sev   = f["severity"]
            style = SEV_STYLE.get(sev, "info")
            tag   = SEV_TAG.get(sev, f"[{sev}]")
            sugg  = (f.get("suggestion") or "")[:60]
            ft.add_row(
                Text(tag, style=style),
                f["category"],
                f["title"],
                sugg,
            )
        console.print(ft)

    # -- suspicious imports ----------------------------------------------------
    si = result.get("suspicious_imports", [])
    if si:
        it = Table(box=box.ASCII, show_header=True, header_style="heading",
                   border_style="dim", padding=(0, 1), title="Flagged Imports")
        it.add_column("API name",   style="err",  min_width=28)
        it.add_column("reason",     style="dim")
        for imp in si[:12]:
            it.add_row(imp["name"], imp["reason"])
        console.print(it)

    # -- sections --------------------------------------------------------------
    secs = result.get("sections", [])
    if secs:
        st = Table(box=box.ASCII, show_header=True, header_style="heading",
                   border_style="dim", padding=(0, 1), title="PE Sections")
        st.add_column("name",    style="cmd",   min_width=10)
        st.add_column("entropy", min_width=8,   justify="right")
        st.add_column("size",    style="dim",   min_width=10, justify="right")
        st.add_column("flags",   style="info",  min_width=10)

        for s in secs:
            flags = []
            if s["exec"]:  flags.append("X")
            if s["write"]: flags.append("W")
            if s["read"]:  flags.append("R")
            flag_str = "/".join(flags)
            ent_style = "err" if s["entropy"] > 7.2 else \
                        "warn" if s["entropy"] > 6.5 else "ok"
            row_ent = Text(str(s["entropy"]), style=ent_style)
            rwx_style = "err" if s["rwx"] else "dim"
            st.add_row(s["name"], row_ent,
                       f"{s['size']//1024} KB",
                       Text(flag_str, style=rwx_style))
        console.print(st)

    console.print()


def _render_patches_table(patches: list[dict],
                           selected: set[str]) -> None:
    if not patches:
        console.print("[warn][!] no patches available for this binary[/warn]")
        return
    t = Table(box=box.ASCII, show_header=True, header_style="heading",
              border_style="dim", padding=(0, 1), title="Available Patches")
    t.add_column("sel", min_width=4, no_wrap=True)
    t.add_column("id",             style="cmd",  min_width=22, no_wrap=True)
    t.add_column("label",          style="info", min_width=32)
    t.add_column("description",    style="dim")
    for p in patches:
        sel = Text("[x]", style="ok") if p["id"] in selected \
              else Text("[ ]", style="dim")
        t.add_row(sel, p["id"], p["label"], p["desc"])
    console.print(t)
    console.print(
        f"  [dim]{len(selected)} of {len(patches)} selected - "
        f"use  patch <id> [id ...]  to toggle[/dim]"
    )
    console.print()


def run_evasion(ev_mod) -> None:
    """Interactive evasion sub-REPL."""
    loaded_path: Path | None = None
    raw_data:    bytes | None = None
    result:      dict  | None = None
    selected:    set[str]     = set()

    completer = WordCompleter(EVASION_COMMANDS, ignore_case=True)
    session: PromptSession = PromptSession(
        history=InMemoryHistory(),
        completer=completer,
        style=PT_STYLE,
    )

    console.print()
    console.print(Panel(
        "  PE evasion scorer + surgical patch transforms\n"
        "  type  help  for commands,  back  to return",
        title="[heading] Evasion Lab [/heading]",
        border_style="cyan",
        box=box.ASCII,
    ))
    console.print()

    while True:
        try:
            fname_hint = f" ({loaded_path.name})" if loaded_path else ""
            raw = session.prompt(
                f"peekaboo [evasion{fname_hint}] > ",
                style=PT_STYLE,
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]use  back  or  exit  to quit[/dim]")
            continue

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        # -- back / exit -------------------------------------------------------
        if cmd in ("back", "exit", "quit"):
            break

        # -- help --------------------------------------------------------------
        elif cmd == "help":
            _evasion_help()

        # -- load --------------------------------------------------------------
        elif cmd == "load":
            if not args:
                console.print("[warn][!] usage: load <path>[/warn]")
                continue
            p = Path(" ".join(args)).expanduser().resolve()
            if not p.exists():
                console.print(f"[err][!] file not found: {p}[/err]")
                continue
            try:
                raw_data = p.read_bytes()
                loaded_path = p
                result   = None
                selected = set()
                console.print(
                    f"[ok][+] loaded:[/ok] [cmd]{p.name}[/cmd]  "
                    f"[dim]{len(raw_data)//1024} KB[/dim]"
                )
            except Exception as e:
                console.print(f"[err][!] read error: {e}[/err]")

        # -- info --------------------------------------------------------------
        elif cmd == "info":
            if raw_data is None:
                console.print("[warn][!] no file loaded - use  load <path>[/warn]")
                continue
            is_pe = raw_data[:2] == b'MZ'
            console.print(
                f"\n  [info]file   :[/info] [cmd]{loaded_path}[/cmd]\n"
                f"  [info]size   :[/info] {len(raw_data):,} bytes "
                f"({len(raw_data)//1024} KB)\n"
                f"  [info]type   :[/info] {'PE (MZ)' if is_pe else 'non-PE / shellcode'}\n"
                f"  [info]result :[/info] "
                f"{'analysed' if result else 'not yet analysed - run  analyse'}\n"
            )

        # -- analyse -----------------------------------------------------------
        elif cmd == "analyse":
            if raw_data is None:
                console.print("[warn][!] no file loaded - use  load <path>[/warn]")
                continue
            with console.status("[info]analysing...[/info]", spinner="dots"):
                result = ev_mod.analyse(raw_data, loaded_path.name)
            # pre-select all available patches
            selected = {p["id"] for p in result.get("patches_available", [])}
            _render_evasion_results(result)

        # -- patches -----------------------------------------------------------
        elif cmd == "patches":
            if result is None:
                console.print("[warn][!] run  analyse  first[/warn]")
                continue
            _render_patches_table(result["patches_available"], selected)

        # -- patch (toggle) ----------------------------------------------------
        elif cmd == "patch":
            if result is None:
                console.print("[warn][!] run  analyse  first[/warn]")
                continue
            if not args:
                _render_patches_table(result["patches_available"], selected)
                continue
            valid_ids = {p["id"] for p in result["patches_available"]}
            toggled   = []
            unknown   = []
            for pid in args:
                if pid in valid_ids:
                    if pid in selected:
                        selected.discard(pid)
                        toggled.append(f"[-] {pid}")
                    else:
                        selected.add(pid)
                        toggled.append(f"[+] {pid}")
                else:
                    unknown.append(pid)
            for t in toggled:
                style = "ok" if t.startswith("[+]") else "warn"
                console.print(f"  [{style}]{t}[/{style}]")
            for u in unknown:
                console.print(f"  [err][!] unknown patch id: {u}[/err]")
            console.print(
                f"\n  [dim]{len(selected)} patch(es) selected[/dim]\n"
            )

        # -- apply -------------------------------------------------------------
        elif cmd == "apply":
            if raw_data is None:
                console.print("[warn][!] no file loaded[/warn]")
                continue
            if result is None:
                console.print("[warn][!] run  analyse  first[/warn]")
                continue
            if not selected:
                console.print("[warn][!] no patches selected - use  patch <id>[/warn]")
                continue

            if args:
                out_path = Path(" ".join(args)).expanduser().resolve()
            else:
                stem = loaded_path.stem
                out_path = loaded_path.parent / f"{stem}_patched{loaded_path.suffix}"

            console.print(f"\n  [info]applying {len(selected)} patch(es)...[/info]")
            with console.status("[info]patching...[/info]", spinner="dots"):
                patched, applied = ev_mod.apply_patches(
                    raw_data, list(selected)
                )

            if not applied:
                console.print("[warn][!] no patches were applied[/warn]")
                continue

            try:
                out_path.write_bytes(patched)
            except Exception as e:
                console.print(f"[err][!] write error: {e}[/err]")
                continue

            # applied summary table
            at = Table(box=box.ASCII, show_header=True, header_style="heading",
                       border_style="ok", padding=(0, 1), title="Patches Applied")
            at.add_column("#",      style="dim",  min_width=3,  justify="right")
            at.add_column("result", style="info")
            for i, desc in enumerate(applied, 1):
                at.add_row(str(i), desc)
            console.print(at)

            delta = len(patched) - len(raw_data)
            delta_str = (f"+{delta//1024} KB" if delta > 0
                         else f"{delta//1024} KB" if delta < 0
                         else "no size change")
            console.print(
                f"\n  [ok][+] saved:[/ok] [cmd]{out_path}[/cmd]  "
                f"[dim]{len(patched)//1024} KB  ({delta_str})[/dim]\n"
            )

        else:
            console.print(
                f"[warn][!] unknown command: {cmd}  "
                f"(type  help  for commands)[/warn]"
            )


# -- top-level REPL ------------------------------------------------------------

def main() -> None:
    print_banner()

    ev_mod = _load_evasion_module()

    top_completer = WordCompleter(TOP_COMMANDS, ignore_case=True)
    session: PromptSession = PromptSession(
        history=InMemoryHistory(),
        completer=top_completer,
        style=PT_STYLE,
    )

    while True:
        try:
            raw = session.prompt("peekaboo > ", style=PT_STYLE).strip()
        except KeyboardInterrupt:
            console.print("\n[dim]use  exit  to quit[/dim]")
            continue
        except EOFError:
            break

        if not raw:
            continue

        cmd = raw.split()[0].lower()

        if cmd in ("exit", "quit"):
            console.print("[dim]goodbye.[/dim]\n")
            break

        elif cmd == "help":
            print_top_help()

        elif cmd == "evasion":
            if ev_mod is None:
                console.print("[err][!] evasion module not available[/err]")
            else:
                run_evasion(ev_mod)

        elif cmd == "library":
            run_library()

        else:
            console.print(
                f"[warn][!] unknown command: {cmd}  "
                f"(type  help  for available modules)[/warn]"
            )


if __name__ == "__main__":
    main()
