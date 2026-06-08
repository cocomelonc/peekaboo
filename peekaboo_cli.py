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
from rich.markdown import Markdown
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

# -- documentation strings (Markdown, rendered by rich) -----------------------

_DOCS: dict[str, dict[str, str]] = {

    # ── top-level ─────────────────────────────────────────────────────────────
    "_top": {
        "_overview": """\
# peekaboo-cli

Interactive red/blue team simulation lab CLI.
DEFCON Demo Labs Singapore 2026 | by @cocomelonc

## Modules

| module      | description                                              |
|-------------|----------------------------------------------------------|
| `evasion`   | PE evasion scorer and surgical patch transforms          |
| `library`   | MITRE ATT&CK module library -- browse, search, view code |
| `artifacts` | Artifact map: 410 techniques mapped to 4799 Sigma rules  |

## Global commands

| command          | description                  |
|------------------|------------------------------|
| `help`           | show this overview           |
| `help <module>`  | full docs for a module       |
| `exit` / `quit`  | quit peekaboo-cli            |

## Quick start

    peekaboo > evasion
    peekaboo [evasion] > load /path/to/payload.exe
    peekaboo [evasion] > analyse
    peekaboo [evasion] > patch fake_timestamp stomp_dos_header
    peekaboo [evasion] > apply /tmp/patched.exe

    peekaboo > library
    peekaboo [library] > list injection
    peekaboo [library] > show malware-injection-17

    peekaboo > artifacts
    peekaboo [artifacts] > show T1055
    peekaboo [artifacts] > rules T1059.001 high
""",
    },

    # ── evasion ───────────────────────────────────────────────────────────────
    "evasion": {
        "_overview": """\
# Evasion Lab

Score a PE binary 0-100 across four categories, then apply surgical
byte-level transforms to reduce its detection surface.

**Score categories** (25 pts each):

- **Entropy** -- file and section entropy; packed/encrypted content scores low
- **Imports** -- 49 red-flagged APIs (VirtualAlloc, WriteProcessMemory, ...) and
  a secondary yellow set; each hit deducts points
- **Strings** -- 12 regex patterns: hardcoded IPs, tool names, privilege constants, etc.
- **PE Structure** -- timestamp, Rich header, PDB path, default section names,
  DOS stub, missing ASLR/DEP, console subsystem, overlay, DataDirectory entries

**Grade scale:** A (>=80) B (>=65) C (>=50) D (>=35) F (<35)

## Commands

| command                   | description                                    |
|---------------------------|------------------------------------------------|
| `load <path>`             | load a PE or raw binary file                   |
| `analyse`                 | run the full evasion score analysis            |
| `patches`                 | list available patch transforms                |
| `patch <id> [id ...]`     | toggle patches on/off by ID                    |
| `apply [output-path]`     | apply selected patches and save patched binary |
| `info`                    | show loaded file metadata                      |
| `help [cmd]`              | show this help, or docs for a specific command |
| `back`                    | return to main menu                            |
""",
        "load": """\
## load

Load a PE binary (`.exe`, `.dll`, `.sys`) or raw shellcode file for analysis.

**Usage:**

    load <path>

**Parameters:**

- `path` -- absolute or relative path; `~` expansion supported

**Examples:**

    load /tmp/payload.exe
    load ~/samples/beacon.dll
    load ./shellcode.bin

**Notes:**

- Maximum recommended size: 32 MB
- The file is read into memory; the original is never modified by `load`
- After loading, run `analyse` before using `patches` or `apply`
""",
        "analyse": """\
## analyse

Run the full evasion score analysis on the currently loaded file.

**Usage:**

    analyse

**Output sections:**

1. **Evasion Score panel** -- total score, grade, file metadata, MD5
2. **Score Breakdown table** -- per-category scores with bar charts
3. **Findings table** -- severity-tagged issues with suggestions
4. **Flagged Imports table** -- red-listed API names with reasons
5. **PE Sections table** -- per-section entropy, size, R/W/X flags

**Notes:**

- All available patch transforms are pre-selected after analysis
- Re-running `analyse` after patching re-scores the patched bytes
- Non-PE files (ELF, raw shellcode) are scored on entropy and strings only
""",
        "patches": """\
## patches

List all patch transforms available for the loaded file.

**Usage:**

    patches

**Output:** table of patch IDs, labels, and descriptions.
Patches are only listed when the analyser detects a relevant condition.

**Patch IDs reference:**

| ID                   | what it does                                              |
|----------------------|-----------------------------------------------------------|
| `timestamp`          | zero the COFF TimeDateStamp field                         |
| `fake_timestamp`     | replace timestamp with a realistic Windows DLL date       |
| `rich_header`        | zero the Rich/DanS compiler fingerprint block             |
| `debug_dir`          | zero debug directory + PDB path string                    |
| `dos_stub`           | overwrite the default MSVC DOS stub string with spaces    |
| `stomp_dos_header`   | zero unused MZ header bytes (offsets 0x02-0x3B)           |
| `checksum`           | zero the OptionalHeader checksum field                    |
| `section_rename`     | rename .text/.data/.rdata/.bss to non-standard names      |
| `entropy_padding`    | append 64 KB null bytes to dilute file entropy            |
| `set_aslr_dep`       | set DYNAMIC_BASE + NX_COMPAT in DllCharacteristics        |
| `clear_high_entropy_va` | clear the HIGH_ENTROPY_VA bit in DllCharacteristics    |
| `flip_subsystem`     | change subsystem CONSOLE (3) to GUI (2)                   |
| `stomp_rwx_flags`    | remove WRITE flag from executable sections (RWX -> RX)    |
| `spoof_imagebase`    | set ImageBase to 0x10000000 (non-default DLL address)     |
| `wipe_overlay`       | truncate bytes appended after the last PE section         |
| `zero_bound_imports` | zero DataDirectory[11] (bound import pre-binding data)    |
| `zero_load_config`   | zero DataDirectory[10] (CFG/SafeSEH/stack cookie metadata)|
| `zero_exports`       | zero DataDirectory[0]  (export table reference)           |
| `zero_security_dir`  | zero DataDirectory[4]  (Authenticode certificate pointer) |
""",
        "patch": """\
## patch

Toggle one or more patch transforms on or off.

**Usage:**

    patch <id> [id ...]

**Parameters:**

- `id` -- one or more patch IDs from the `patches` table
- Running `patch` with no arguments shows the current selection

**Examples:**

    patch fake_timestamp stomp_dos_header
    patch section_rename checksum dos_stub
    patch set_aslr_dep flip_subsystem wipe_overlay

**Notes:**

- Patches start pre-selected (all enabled) after `analyse`
- Toggling an already-selected patch removes it; toggling an unselected one adds it
- Run `patches` to see current selection and available IDs
""",
        "apply": """\
## apply

Apply all selected patch transforms to the loaded binary and save the result.

**Usage:**

    apply [output-path]

**Parameters:**

- `output-path` -- optional; defaults to `<original-stem>_patched<ext>`
  in the same directory as the original file

**Examples:**

    apply
    apply /tmp/patched_payload.exe
    apply ~/staging/beacon_clean.dll

**Output:**

- Applied patches summary table
- Output file path and size delta

**Notes:**

- The original file is never modified
- Run `analyse` on the output path to verify the new score
- Patch history is saved to the peekaboo database automatically
""",
        "info": """\
## info

Show metadata for the currently loaded file.

**Usage:**

    info

**Output:** file path, size, PE/non-PE type, analysis status.
""",
    },

    # ── library ───────────────────────────────────────────────────────────────
    "library": {
        "_overview": """\
# Module Library

Browse, search and read source code for 205 malware research modules
mapped to MITRE ATT&CK techniques.

Each entry has: slug, title, category, ATT&CK T-IDs, implementation status,
blog URL, and full source code (C, C++, ASM, Nim).

## Commands

| command               | description                                        |
|-----------------------|----------------------------------------------------|
| `list [category]`     | paginated module table; Enter = next page          |
| `search <query>`      | search title, slug, T-ID or category               |
| `show <slug>`         | metadata panel + syntax-highlighted source code    |
| `cats`                | all categories with entry counts and bar chart     |
| `help [cmd]`          | show this help, or docs for a specific command     |
| `back`                | return to main menu                                |

## Categories

`analysis` `android` `c2` `credential-access` `cryptography` `discovery`
`evasion` `execution` `exploitation` `hooking` `injection` `linux`
`macos` `network` `other` `persistence` `privesc` `shellcoding`
`syscalls` `tricks`
""",
        "list": """\
## list

Show a paginated table of modules, optionally filtered by category.

**Usage:**

    list [category]

**Parameters:**

- `category` -- optional; exact or partial category name

**Examples:**

    list
    list injection
    list persistence
    list crypto

**Notes:**

- 20 entries per page; press **Enter** on an empty prompt to advance pages
- After filtering, paging resets to page 1
- Use `cats` to see all valid category names
""",
        "search": """\
## search

Full-text search across module titles, slugs, T-IDs and categories.

**Usage:**

    search <query>

**Parameters:**

- `query` -- case-insensitive; matches any field

**Examples:**

    search T1055
    search process injection
    search hollowing
    search nim
    search persistence

**Notes:**

- Results replace the current list view and support paging
- Combine with `show` to drill into a result: `show malware-injection-17`
""",
        "show": """\
## show

Display full metadata and syntax-highlighted source code for a module.

**Usage:**

    show <slug>

**Parameters:**

- `slug` -- the module slug from the list/search table
- Partial slug matching: if only one result matches, it opens automatically

**Examples:**

    show malware-injection-17
    show malware-tricks-54
    show malware-cryptography-44

**Output:**

1. Metadata panel: slug, title, category, date, T-IDs, module ref, blog URL
2. Source code panel with syntax highlighting and line numbers

**Notes:**

- Files longer than 55 lines open in a pager (`less`); press `q` to exit
- Supported languages: C, C++, ASM (NASM/GAS), Nim, Python, Go, Rust
""",
        "cats": """\
## cats

List all categories with entry counts and a proportional bar chart.

**Usage:**

    cats
""",
    },

    # ── artifacts ─────────────────────────────────────────────────────────────
    "artifacts": {
        "_overview": """\
# Artifact Map

410 ATT&CK techniques mapped to 4799 Sigma detection rules, Sysmon EventIDs,
registry keys, process images and command line patterns.
Built from the ~/hacking/sigma rule corpus.

## Commands

| command                   | description                                       |
|---------------------------|---------------------------------------------------|
| `list [tactic]`           | paginated technique table; Enter = next page      |
| `search <query>`          | search T-ID, name, tactic or Sysmon category      |
| `show <T-ID>`             | full detail: rules, EventIDs, registry, processes |
| `rules <T-ID> [level]`    | all Sigma rules for a technique                   |
| `tactics`                 | tactic overview with technique counts             |
| `stats`                   | global artifact map statistics                    |
| `help [cmd]`              | show this help, or docs for a specific command    |
| `back`                    | return to main menu                               |

## Tactics

`collection` `command-and-control` `credential-access` `defense-evasion`
`discovery` `execution` `exfiltration` `impact` `initial-access`
`lateral-movement` `persistence` `privilege-escalation`
`reconnaissance` `resource-development`
""",
        "list": """\
## list

Show a paginated table of ATT&CK techniques, optionally filtered by tactic.

**Usage:**

    list [tactic]

**Parameters:**

- `tactic` -- optional tactic name (partial match supported)

**Columns:** T-ID | name | tactics | rule count | top EventIDs

**Examples:**

    list
    list execution
    list lateral-movement
    list cred

**Notes:**

- Sorted by Sigma rule count descending (highest coverage first)
- 20 entries per page; press **Enter** to advance
""",
        "search": """\
## search

Search techniques by T-ID, name, tactic or Sysmon log category.

**Usage:**

    search <query>

**Examples:**

    search T1055
    search process injection
    search lsass
    search pipe_created
    search lateral

**Notes:**

- Case-insensitive; matches T-ID prefix, technique name, tactic string,
  and Sysmon category names
""",
        "show": """\
## show

Show full detail for one ATT&CK technique.

**Usage:**

    show <T-ID>

**Parameters:**

- `T-ID` -- e.g. `T1055`, `T1059.001`; case-insensitive; partial match supported

**Examples:**

    show T1055
    show T1059.001
    show t1003

**Output sections:**

1. Header panel -- T-ID, name, tactics, rule count, EventIDs with labels, Sysmon categories
2. Top Sigma Rules table -- up to 20 rules sorted by severity (critical first)
3. Registry Keys table -- registry paths observed in rules
4. Process Images table -- process names observed in rules
5. Command Line Patterns table -- CLI patterns from detection logic

**Notes:**

- If a technique has more than 20 rules, use `rules <T-ID>` for the full list
""",
        "rules": """\
## rules

Show all Sigma rules for a technique, with optional severity filter.

**Usage:**

    rules <T-ID> [level]

**Parameters:**

- `T-ID`  -- technique ID (e.g. `T1059.001`)
- `level` -- optional filter: `critical` `high` `medium` `low` `informational`

**Examples:**

    rules T1055
    rules T1059.001 high
    rules T1003 critical
    rules T1218 medium

**Notes:**

- Results are sorted by severity (critical -> high -> medium -> low)
- Tables with more than 60 rules open in a pager; press `q` to exit
""",
        "tactics": """\
## tactics

Show all MITRE ATT&CK tactics with technique counts and a bar chart.

**Usage:**

    tactics
""",
        "stats": """\
## stats

Show global artifact map statistics.

**Usage:**

    stats

**Output:** technique count, total Sigma rules, unique tactics, unique Sysmon EventIDs, build timestamp.
""",
    },
}


def show_help(module: str = "_top", cmd: str | None = None) -> None:
    """Render documentation from _DOCS using rich Markdown."""
    mod_docs = _DOCS.get(module)
    if mod_docs is None:
        console.print(f"  [warn][!] no docs for module '{module}'[/warn]\n")
        return

    if cmd:
        text = mod_docs.get(cmd)
        if not text:
            console.print(
                f"  [warn][!] no docs for '{cmd}' in module '{module}'\n"
                f"  available: {', '.join(k for k in mod_docs if not k.startswith('_'))}[/warn]\n"
            )
            return
        console.print()
        console.print(Panel(Markdown(text), box=box.ASCII, border_style="cyan",
                            padding=(1, 2)))
        console.print()
    else:
        text = mod_docs.get("_overview", "")
        if text:
            console.print()
            console.print(Panel(Markdown(text), box=box.ASCII, border_style="cyan",
                                padding=(1, 2)))
            console.print()


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
    "evasion", "library", "artifacts", "help", "exit", "quit",
]

TOP_HELP = [
    ("evasion",   "PE evasion scorer + surgical patch transforms"),
    ("library",   "MITRE ATT&CK module library -- browse, search, view source"),
    ("artifacts", "Artifact map -- 410 techniques, 4799 Sigma rules, EventID coverage"),
    ("help",      "show this help"),
    ("exit",      "quit peekaboo-cli"),
]


def print_top_help(module: str | None = None) -> None:
    if module:
        show_help(module)
    else:
        show_help("_top")


# -- artifact map --------------------------------------------------------------

ART_PAGE_SIZE = 20

# Sysmon EventID -> short label
_EID_LABEL = {
    1:    "ProcessCreate",
    2:    "FileTime",
    3:    "NetConn",
    4:    "SysmonState",
    5:    "ProcessTerm",
    6:    "DriverLoad",
    7:    "ImageLoad",
    8:    "CreateRemoteThread",
    9:    "RawAccess",
    10:   "ProcessAccess",
    11:   "FileCreate",
    12:   "RegObjChange",
    13:   "RegValueSet",
    14:   "RegKeyRename",
    15:   "FileStreamHash",
    16:   "ServiceConfig",
    17:   "PipeCreated",
    18:   "PipeConnected",
    19:   "WmiFilter",
    20:   "WmiConsumer",
    21:   "WmiBinding",
    22:   "DnsQuery",
    23:   "FileDelete",
    4103: "PS-ModuleLog",
    4104: "PS-ScriptBlock",
    4688: "ProcessCreate(Sec)",
    4698: "TaskScheduled",
    4702: "TaskModified",
    7045: "ServiceInstalled",
}

_RULE_LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                     "informational": 4, "unknown": 5}
_RULE_LEVEL_STYLE = {"critical": "critical", "high": "high",
                     "medium": "medium",     "low": "low",
                     "informational": "dim", "unknown": "dim"}

ARTIFACT_COMMANDS = [
    "list", "search", "show", "rules", "tactics", "stats", "help", "back",
]

ARTIFACT_HELP = [
    ("list [tactic]",        "list techniques, optionally filtered by tactic"),
    ("search <query>",       "search T-ID, name or tactic"),
    ("show <T-ID>",          "full detail: rules, EventIDs, registry keys, processes"),
    ("rules <T-ID> [level]", "all Sigma rules for a technique (filter: high/medium/low)"),
    ("tactics",              "tactic overview with technique counts"),
    ("stats",                "global artifact map statistics"),
    ("help",                 "show this help"),
    ("back",                 "return to main menu"),
]


def _artifact_help() -> None:
    t = Table(box=box.ASCII, show_header=True, header_style="heading",
              border_style="dim", padding=(0, 1))
    t.add_column("command",     style="cmd",  no_wrap=True, min_width=26)
    t.add_column("description", style="info")
    for cmd, desc in ARTIFACT_HELP:
        t.add_row(cmd, desc)
    console.print()
    console.print(t)
    console.print()


def _tactic_short(tactic_str: str, max_n: int = 2) -> str:
    parts = [t.strip() for t in tactic_str.split(",") if t.strip()]
    shown = parts[:max_n]
    tail  = f" +{len(parts)-max_n}" if len(parts) > max_n else ""
    return ", ".join(shown) + tail


def _eids_short(eids: list, max_n: int = 4) -> str:
    if not eids:
        return "-"
    labels = [_EID_LABEL.get(int(e), str(e)) for e in eids[:max_n]]
    tail   = f" +{len(eids)-max_n}" if len(eids) > max_n else ""
    return " ".join(labels) + tail


def _render_artifact_table(entries: list[dict], title: str = "Artifact Map",
                            page: int = 0) -> int:
    total  = len(entries)
    pages  = max(1, (total + ART_PAGE_SIZE - 1) // ART_PAGE_SIZE)
    start  = page * ART_PAGE_SIZE
    chunk  = entries[start:start + ART_PAGE_SIZE]

    t = Table(box=box.ASCII, show_header=True, header_style="heading",
              border_style="dim", padding=(0, 1),
              title=f"{title}  [{start+1}-{min(start+len(chunk), total)} / {total}]",
              show_lines=False)
    t.add_column("#",       style="dim",  min_width=4,  justify="right", no_wrap=True)
    t.add_column("T-ID",    style="warn", min_width=12, no_wrap=True)
    t.add_column("name",    style="cmd",  min_width=22, no_wrap=True)
    t.add_column("tactics", style="info", min_width=28)
    t.add_column("rules",   style="ok",   min_width=6,  justify="right", no_wrap=True)
    t.add_column("EventIDs",              min_width=28)

    for i, e in enumerate(chunk, start + 1):
        t.add_row(
            str(i),
            e["tid"],
            (e["name"] or e["tid"])[:22],
            _tactic_short(e["tactic"], 2),
            str(e["rule_count"]),
            _eids_short(e["event_ids"], 4),
        )

    console.print()
    console.print(t)
    if pages > 1:
        console.print(
            f"  [dim]page {page+1}/{pages} -- "
            f"press Enter for next page,  show <T-ID>  to drill in[/dim]\n"
        )
    return pages


def _render_artifact_detail(e: dict) -> None:
    tactics = [t.strip() for t in e["tactic"].split(",") if t.strip()]
    eids    = e["event_ids"]
    cats    = e["categories"]
    rules   = sorted(e["rules"],
                     key=lambda r: _RULE_LEVEL_ORDER.get(r.get("level",""), 5))

    # ── header panel ─────────────────────────────────────────────────────────
    eid_lines = ""
    if eids:
        eid_parts = [f"{eid}:{_EID_LABEL.get(int(eid), '?')}" for eid in eids]
        eid_lines = "\n  EventIDs : " + "  ".join(eid_parts)

    meta = (
        f"  T-ID     : {e['tid']}\n"
        f"  Name     : {e['name'] or '(unnamed)'}\n"
        f"  Tactics  : {', '.join(tactics)}\n"
        f"  Rules    : {e['rule_count']} Sigma rules"
        f"{eid_lines}"
    )
    if cats:
        meta += f"\n  Sysmon   : {', '.join(cats[:6])}"
        if len(cats) > 6:
            meta += f" +{len(cats)-6}"

    console.print()
    console.print(Panel(meta,
                        title=f"[heading] {e['tid']} - {e['name'] or ''} [/heading]",
                        border_style="cyan", box=box.ASCII))

    # ── top sigma rules ───────────────────────────────────────────────────────
    top_rules = rules[:20]
    if top_rules:
        rt = Table(box=box.ASCII, show_header=True, header_style="heading",
                   border_style="dim", padding=(0, 1),
                   title=f"Top Sigma Rules (showing {len(top_rules)} of {len(rules)})",
                   show_lines=False)
        rt.add_column("level",    min_width=8,  no_wrap=True)
        rt.add_column("status",   style="dim",  min_width=10, no_wrap=True)
        rt.add_column("category", style="info", min_width=16, no_wrap=True)
        rt.add_column("title",    min_width=44)
        rt.add_column("author",   style="dim",  min_width=20)

        for r in top_rules:
            lvl   = r.get("level", "unknown")
            style = _RULE_LEVEL_STYLE.get(lvl, "dim")
            rt.add_row(
                Text(lvl, style=style),
                r.get("status", ""),
                r.get("category", ""),
                (r.get("title") or "")[:44],
                (r.get("author") or "").split(",")[0][:20],
            )
        console.print(rt)
        if len(rules) > 20:
            console.print(
                f"  [dim]... {len(rules)-20} more -- "
                f"use  rules {e['tid']}  for full list[/dim]"
            )

    # ── registry keys ─────────────────────────────────────────────────────────
    reg_keys = e.get("reg_keys", [])
    if reg_keys:
        rkt = Table(box=box.ASCII, show_header=True, header_style="heading",
                    border_style="dim", padding=(0, 1), title="Registry Keys")
        rkt.add_column("key", style="warn")
        for k in reg_keys[:15]:
            rkt.add_row(k)
        if len(reg_keys) > 15:
            console.print(f"  [dim]... +{len(reg_keys)-15} more[/dim]")
        console.print(rkt)

    # ── processes ─────────────────────────────────────────────────────────────
    procs = e.get("processes", [])
    if procs:
        pt = Table(box=box.ASCII, show_header=True, header_style="heading",
                   border_style="dim", padding=(0, 1), title="Process Images")
        pt.add_column("process", style="cmd")
        for p in procs[:12]:
            pt.add_row(p)
        if len(procs) > 12:
            console.print(f"  [dim]... +{len(procs)-12} more[/dim]")
        console.print(pt)

    # ── command line patterns ─────────────────────────────────────────────────
    cmdlines = e.get("cmdlines", [])
    if cmdlines:
        ct = Table(box=box.ASCII, show_header=True, header_style="heading",
                   border_style="dim", padding=(0, 1), title="Command Line Patterns")
        ct.add_column("pattern", style="info")
        for c in cmdlines[:12]:
            ct.add_row(str(c)[:80])
        if len(cmdlines) > 12:
            console.print(f"  [dim]... +{len(cmdlines)-12} more[/dim]")
        console.print(ct)

    console.print()


def _render_all_rules(e: dict, level_filter: str | None = None) -> None:
    rules = sorted(e["rules"],
                   key=lambda r: _RULE_LEVEL_ORDER.get(r.get("level", ""), 5))
    if level_filter:
        rules = [r for r in rules if r.get("level", "").lower() == level_filter]

    title = f"Sigma Rules: {e['tid']}"
    if level_filter:
        title += f"  [level={level_filter}]"
    title += f"  ({len(rules)} rules)"

    if not rules:
        console.print(f"  [warn][!] no rules match level '{level_filter}'[/warn]\n")
        return

    rt = Table(box=box.ASCII, show_header=True, header_style="heading",
               border_style="dim", padding=(0, 1), title=title, show_lines=False)
    rt.add_column("#",        style="dim",  min_width=4,  justify="right", no_wrap=True)
    rt.add_column("level",    min_width=8,  no_wrap=True)
    rt.add_column("category", style="info", min_width=16, no_wrap=True)
    rt.add_column("status",   style="dim",  min_width=10, no_wrap=True)
    rt.add_column("title",    min_width=44)

    for i, r in enumerate(rules, 1):
        lvl   = r.get("level", "unknown")
        style = _RULE_LEVEL_STYLE.get(lvl, "dim")
        rt.add_row(
            str(i),
            Text(lvl, style=style),
            r.get("category", ""),
            r.get("status", ""),
            (r.get("title") or "")[:44],
        )

    if len(rules) > 60:
        with console.pager(styles=True):
            console.print(rt)
    else:
        console.print()
        console.print(rt)
        console.print()


def run_artifacts() -> None:
    """Interactive artifact map sub-REPL."""
    try:
        import db as _db
    except ImportError as e:
        console.print(f"[err][!] db module unavailable: {e}[/err]")
        return

    with console.status("[info]loading artifact map...[/info]", spinner="dots"):
        all_entries = _db.get_artifact_entries()
        stats       = _db.get_artifact_stats()

    if not all_entries:
        console.print(
            "[warn][!] artifact map is empty -- "
            "open the dashboard and click Rebuild in the Artifact Map panel[/warn]"
        )
        return

    # build lookup structures
    from collections import Counter
    tid_map: dict[str, dict] = {e["tid"]: e for e in all_entries}
    tactic_counts: Counter = Counter()
    for e in all_entries:
        for t in e["tactic"].split(","):
            t = t.strip()
            if t:
                tactic_counts[t] += 1
    all_tactics = sorted(tactic_counts.keys())
    all_tids    = sorted(tid_map.keys())

    completer = WordCompleter(
        ARTIFACT_COMMANDS + all_tactics + all_tids,
        ignore_case=True,
    )
    session: PromptSession = PromptSession(
        history=InMemoryHistory(),
        completer=completer,
        style=PT_STYLE,
    )

    built_at = all_entries[0].get("built_at", "?")[:16] if all_entries else "?"
    console.print()
    console.print(Panel(
        f"  {stats['total_techniques']} techniques  |  "
        f"{stats['total_rules']} Sigma rules  |  "
        f"{stats['unique_tactics']} tactics  |  "
        f"{stats['unique_event_ids']} Sysmon EventIDs\n"
        f"  built: {built_at}\n"
        f"  type  help  for commands,  tactics  for tactic list,  back  to return",
        title="[heading] Artifact Map [/heading]",
        border_style="cyan",
        box=box.ASCII,
    ))
    console.print()

    current_view:  list[dict] = all_entries
    current_title: str        = "Artifact Map"
    current_page:  int        = 0
    total_pages:   int        = 0

    while True:
        try:
            raw = session.prompt(
                "peekaboo [artifacts] > ",
                style=PT_STYLE,
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]use  back  to return[/dim]")
            continue

        if not raw:
            if total_pages > 1 and current_page + 1 < total_pages:
                current_page += 1
                total_pages = _render_artifact_table(
                    current_view, current_title, current_page
                )
            continue

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        # ── back ─────────────────────────────────────────────────────────────
        if cmd in ("back", "exit", "quit"):
            break

        # ── help ─────────────────────────────────────────────────────────────
        elif cmd == "help":
            show_help("artifacts", args[0] if args else None)

        # ── stats ─────────────────────────────────────────────────────────────
        elif cmd == "stats":
            t = Table(box=box.ASCII, show_header=False, border_style="dim",
                      padding=(0, 2), title="Artifact Map Statistics")
            t.add_column("key",   style="info",    min_width=22)
            t.add_column("value", style="heading", min_width=12, justify="right")
            t.add_row("Techniques",   str(stats["total_techniques"]))
            t.add_row("Sigma Rules",  str(stats["total_rules"]))
            t.add_row("Tactics",      str(stats["unique_tactics"]))
            t.add_row("Sysmon EIDs",  str(stats["unique_event_ids"]))
            t.add_row("Last Built",   built_at)
            console.print()
            console.print(t)
            console.print()

        # ── tactics ──────────────────────────────────────────────────────────
        elif cmd == "tactics":
            max_n = max(tactic_counts.values())
            t = Table(box=box.ASCII, show_header=True, header_style="heading",
                      border_style="dim", padding=(0, 1), title="Tactics")
            t.add_column("tactic",     style="cmd",  min_width=26)
            t.add_column("techniques", style="info", min_width=10, justify="right")
            t.add_column("bar",        min_width=34)
            for tac in sorted(tactic_counts, key=lambda x: -tactic_counts[x]):
                n     = tactic_counts[tac]
                w     = int(n / max_n * 32)
                bar   = Text("[" + "#" * w + "." * (32 - w) + "]", style="cyan")
                t.add_row(tac, str(n), bar)
            console.print()
            console.print(t)
            console.print()

        # ── list [tactic] ─────────────────────────────────────────────────────
        elif cmd == "list":
            if args:
                tac = args[0].lower()
                current_view = [
                    e for e in all_entries
                    if tac in e["tactic"].lower()
                ]
                if not current_view:
                    console.print(
                        f"[warn][!] no techniques for tactic '{tac}' "
                        f"-- type  tactics  to see valid names[/warn]"
                    )
                    continue
                current_title = f"Artifact Map: {tac}"
            else:
                current_view  = all_entries
                current_title = "Artifact Map"
            current_page = 0
            total_pages  = _render_artifact_table(
                current_view, current_title, current_page
            )

        # ── search ────────────────────────────────────────────────────────────
        elif cmd == "search":
            if not args:
                console.print("[warn][!] usage: search <query>[/warn]")
                continue
            q = " ".join(args).lower()
            hits = [
                e for e in all_entries
                if q in e["tid"].lower()
                or q in (e["name"] or "").lower()
                or q in e["tactic"].lower()
                or any(q in (cat or "").lower() for cat in e["categories"])
            ]
            if not hits:
                console.print(f"  [warn][!] no results for '{q}'[/warn]\n")
                continue
            current_view  = hits
            current_title = f"Search: {q}"
            current_page  = 0
            total_pages   = _render_artifact_table(
                current_view, current_title, current_page
            )

        # ── show <T-ID> ───────────────────────────────────────────────────────
        elif cmd == "show":
            if not args:
                console.print("[warn][!] usage: show <T-ID>  e.g.  show T1055[/warn]")
                continue
            tid = args[0].upper()
            entry = tid_map.get(tid)
            if not entry:
                # partial match
                matches = [k for k in tid_map if tid in k]
                if len(matches) == 1:
                    entry = tid_map[matches[0]]
                elif len(matches) > 1:
                    console.print(
                        f"  [warn][!] ambiguous '{tid}': "
                        f"{', '.join(matches[:6])}"
                        f"{'...' if len(matches) > 6 else ''}[/warn]\n"
                    )
                    continue
                else:
                    console.print(f"  [err][!] T-ID not found: '{tid}'[/err]\n")
                    continue
            _render_artifact_detail(entry)

        # ── rules <T-ID> [level] ──────────────────────────────────────────────
        elif cmd == "rules":
            if not args:
                console.print(
                    "[warn][!] usage: rules <T-ID> [level]  "
                    "e.g.  rules T1055 high[/warn]"
                )
                continue
            tid = args[0].upper()
            level_filter = args[1].lower() if len(args) > 1 else None
            entry = tid_map.get(tid)
            if not entry:
                matches = [k for k in tid_map if tid in k]
                if len(matches) == 1:
                    entry = tid_map[matches[0]]
                else:
                    console.print(f"  [err][!] T-ID not found: '{tid}'[/err]\n")
                    continue
            _render_all_rules(entry, level_filter)

        else:
            console.print(
                f"[warn][!] unknown command: {cmd}  "
                f"(type  help  for commands)[/warn]"
            )


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
            show_help("library", args[0] if args else None)

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
            show_help("evasion", args[0] if args else None)

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
            parts = raw.split()
            print_top_help(parts[1] if len(parts) > 1 else None)

        elif cmd == "evasion":
            if ev_mod is None:
                console.print("[err][!] evasion module not available[/err]")
            else:
                run_evasion(ev_mod)

        elif cmd == "library":
            run_library()

        elif cmd == "artifacts":
            run_artifacts()

        else:
            console.print(
                f"[warn][!] unknown command: {cmd}  "
                f"(type  help  for available modules)[/warn]"
            )


if __name__ == "__main__":
    main()
