#!/usr/bin/env python3
"""
peekaboo_cli.py - interactive CLI for the peekaboo red/blue team lab
DEFCON Demo Labs Singapore 2026

Usage:
    /home/cocomelonc/hacking/peekaboo/py3/bin/python3 peekaboo_cli.py
"""
from __future__ import annotations
import re
import sys
import uuid
from collections import Counter, defaultdict
from datetime import datetime
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
from rich.rule import Rule
from rich.syntax import Syntax
from rich.columns import Columns
from rich.markdown import Markdown
from rich import box

# -- prompt_toolkit ------------------------------------------------------------
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.completion import WordCompleter, PathCompleter, Completer, Completion
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.filters import has_completions
from prompt_toolkit.styles import Style as PtStyle

# -- cyberpunk color theme (xterm-256 + true-color; degrades gracefully) -------
THEME = Theme({
    # base
    "banner":   "bold bright_green",
    "prompt":   "bold bright_cyan",
    "cmd":      "bold bright_yellow",
    "ok":       "bold bright_green",
    "warn":     "bold yellow",
    "err":      "bold bright_red",
    "info":     "bright_cyan",
    "dim":      "grey50",
    "heading":  "bold bright_white",
    # severity
    "critical": "bold bright_white on red",
    "high":     "bold red",
    "medium":   "bold yellow",
    "low":      "bright_cyan",
    "good":     "bright_green",
    # extras
    "accent":   "bold medium_purple",
    "kw":       "bold bright_yellow",
    "hi":       "bold bright_white",
    "label":    "grey74",
    "mono":     "bright_white",
    "tag":      "bold black on bright_cyan",
    "sep":      "bright_black",
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
    "prompt":                              "ansibrightyellow bold",
    "completion-menu.completion":          "bg:ansiblack ansiwhite",
    "completion-menu.completion.current":  "bg:ansicyan ansiblack bold",
    "completion-menu.meta.completion":     "bg:ansiblack ansigray",
    "scrollbar.background":                "bg:ansiblack",
    "scrollbar.button":                    "bg:ansiwhite",
})


_PATH_COMPLETER = PathCompleter(expanduser=True)


class CmdPathCompleter(Completer):
    """
    Completes command words at position 0; switches to filesystem path
    completion when the first token is a command that takes a path argument.
    """
    def __init__(self, words: list[str], path_cmds: frozenset[str]) -> None:
        self._word = WordCompleter(words, ignore_case=True)
        self._path_cmds = path_cmds

    def get_completions(self, document, complete_event):
        from prompt_toolkit.document import Document as _Doc
        text = document.text_before_cursor.lstrip()
        parts = text.split()
        # still typing the first word, or nothing typed yet
        if len(parts) == 0 or (len(parts) == 1 and not text.endswith(" ")):
            yield from self._word.get_completions(document, complete_event)
            return
        # first word is a path command - hand PathCompleter just the path fragment
        if parts[0].lower() in self._path_cmds:
            # find where the argument starts (after the command word + whitespace)
            after_cmd = text[len(parts[0]):].lstrip()
            path_doc = _Doc(after_cmd, len(after_cmd))
            yield from _PATH_COMPLETER.get_completions(path_doc, complete_event)
            return
        # otherwise word-complete (catches sub-commands, slugs, etc.)
        yield from self._word.get_completions(document, complete_event)


# Key bindings for sessions that include path completion.
# Problem: prompt_toolkit's default Enter both selects the highlighted completion
# AND submits the line, so picking a directory immediately triggers an error.
# Fix: when the completion menu is open, Enter only applies the current selection
# (closing the menu) without submitting.  A second Enter then submits normally.
def _make_path_kb() -> KeyBindings:
    kb = KeyBindings()

    @kb.add("enter", filter=has_completions)
    def _enter_selects(event):
        buf = event.current_buffer
        state = buf.complete_state
        if state and state.current_completion is not None:
            buf.apply_completion(state.current_completion)
        buf.cancel_completion()

    return kb


_PATH_KB = _make_path_kb()


def _make_session(words: list[str],
                  path_cmds: frozenset[str] | None = None) -> PromptSession:
    completer: Completer
    if path_cmds:
        completer = CmdPathCompleter(words, path_cmds)
        kb = _PATH_KB
    else:
        completer = WordCompleter(words, ignore_case=True)
        kb = None
    return PromptSession(
        history=InMemoryHistory(),
        completer=completer,
        key_bindings=kb,
        style=PT_STYLE,
    )


PAGE_SIZE = 20  # default page size for all sub-REPL tables

# -- documentation strings (Markdown, rendered by rich) -----------------------

_DOCS: dict[str, dict[str, str]] = {

    # -- top-level -------------------------------------------------------------
    "_top": {
        "_overview": """\
# peekaboo-cli

Interactive red/blue team simulation lab CLI.
DEFCON Demo Labs Singapore 2026 | by @cocomelonc

## Modules

| module          | description                                                        |
|-----------------|--------------------------------------------------------------------|
| `evasion`       | PE evasion scorer and surgical patch transforms                    |
| `library`       | MITRE ATT&CK module library -- browse, search, view code           |
| `artifacts`     | Artifact map: 410 techniques mapped to 4799 Sigma rules            |
| `builder`       | Compile malware research modules; browse build history             |
| `shellcode`     | Parse, analyse, transform and reformat shellcode                   |
| `yara`          | Generate YARA rules from binaries; scan with yara-python           |
| `malpedia`      | APT actors, malware families, reports, YARA from Malpedia          |
| `ttp`           | TTPs, unique ATT&CK sub-techniques implementations from lib        |
| `pe`            | PE Anatomy Inspector -- sections, imports, entropy, threat score   |
| `vtscan`        | Scan compiled binaries or files with VirusTotal (70+ AV)           |
| `hellsgate`     | Hell's Gate -- SSN extraction, EDR hook detection, stub gen        |
| `scemu`         | Shellcode Emulator -- Unicorn Engine, trace, API intercept, SMC    |
| `antianalysis`  | Anti-Analysis Scanner -- anti-debug/anti-VM patterns, MITRE map    |
| `rop`           | ROP Chain Builder -- gadget finder, chain assembly, C/Python gen   |

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

    peekaboo > builder
    peekaboo [builder] > list windows
    peekaboo [builder] > build malware-injection-17
    peekaboo [builder] > history

    peekaboo > shellcode
    peekaboo [shellcode] > load /tmp/payload.bin
    peekaboo [shellcode] > analyse
    peekaboo [shellcode] > transform xor_random
    peekaboo [shellcode] > format python
    peekaboo [shellcode] > generate

    peekaboo > yara
    peekaboo [yara] > gen /tmp/payload.exe
    peekaboo [yara] > save /tmp/payload_rule.yar
    peekaboo [yara] > scan /tmp/payload_copy.exe

    peekaboo > malpedia
    peekaboo [malpedia] > reports 10
    peekaboo [malpedia] > actors lazarus
    peekaboo [malpedia] > actor lazarus_group
    peekaboo [malpedia] > search apt28

    peekaboo > ttp
    peekaboo [ttp] > list persistence
    peekaboo [ttp] > show T1547.001
    peekaboo [ttp] > search APC injection
    peekaboo [ttp] > build T1055.004
    peekaboo [ttp] > refresh

    peekaboo > hellsgate
    peekaboo [hellsgate] > scan /mnt/win/ntdll.dll
    peekaboo [hellsgate] > filter hooked
    peekaboo [hellsgate] > select-common
    peekaboo [hellsgate] > generate nasm

    peekaboo > scemu
    peekaboo [scemu] > arch x64
    peekaboo [scemu] > run /tmp/payload.bin
    peekaboo [scemu] > trace
    peekaboo [scemu] > strings

    peekaboo > antianalysis
    peekaboo [antianalysis] > scan /tmp/sample.exe
    peekaboo [antianalysis] > filter anti_debug
    peekaboo [antianalysis] > list
    peekaboo [antianalysis] > export /tmp/findings.json

    peekaboo > rop
    peekaboo [rop] > scan /tmp/ntdll.dll
    peekaboo [rop] > filter reg_load
    peekaboo [rop] > list
    peekaboo [rop] > chain-add 3
    peekaboo [rop] > chain-arg 0 0x0000000000000001
    peekaboo [rop] > generate c
""",
    },

    # -- evasion ---------------------------------------------------------------
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

    # -- library ---------------------------------------------------------------
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

    # -- artifacts -------------------------------------------------------------
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

    # -- shellcode -------------------------------------------------------------
    "shellcode": {
        "_overview": """\
# Shellcode Lab

Parse, analyse, transform and reformat shellcode in any supported format.
All operations are local -- nothing leaves the machine.

## Workflow

    load <path>            -- load raw binary shellcode from a file
    paste                  -- paste shellcode in any text format
    analyse                -- detailed analysis: entropy, arch, patterns, bytes
    format <id>            -- set output format (default: c)
    transform <id> [key]   -- set transform (default: none)
    varname <name>         -- set variable name in generated code (default: buf)
    generate               -- run and display the formatted output
    save <path>            -- save transformed raw bytes to a binary file
    export <path>          -- export formatted code output to a text file
    formats                -- list all output format IDs
    transforms             -- list all transform IDs

## Input formats (auto-detected)

- Python bytes literal:  `b"\\x90\\x90"`
- C / 0x array:          `0x90, 0x90, 0x90`
- Escaped hex:           `\\x90\\x90\\x90`
- Space/comma hex:       `90 90 90`
- Raw hex string:        `909090`
- Base64:                `kJCQ`

## Output formats

`c`  `c_str`  `python`  `powershell`  `csharp`  `vba`  `rust`
`base64`  `hex_0x`  `hex_raw`  `escaped`

## Transforms

`none`  `xor_random`  `xor_key`  `base64_encode`  `base64_decode`
`zlib_compress`  `zlib_decompress`
""",
        "load": """\
## load

Load raw binary shellcode from a file.

**Usage:**

    load <path>

**Parameters:**

- `path` -- absolute or relative path; `~` expansion supported

**Examples:**

    load /tmp/shellcode.bin
    load ~/payloads/beacon_x64.bin
    load samples/malware-injection-17/payload.exe

**Notes:**

- The file is read as raw bytes (no format parsing)
- Non-PE files (raw shellcode) are recommended; PE files are accepted but
  the output may be very large
- After loading, run `analyse` to inspect the shellcode
""",
        "paste": """\
## paste

Enter multi-line paste mode to load shellcode from text (any format).

**Usage:**

    paste

Then paste your shellcode in any supported format and press **Enter** on an
empty line to finish.

**Accepted formats:**

    \\x90\\x90\\x90\\xcc
    0x90, 0x90, 0x90
    90 90 90 cc
    909090cc
    kJCQ (base64)
    b"\\x90\\x90" (Python bytes literal)

**Notes:**

- Multi-line input is supported (e.g. a C array split across lines)
- The format is auto-detected
- If detection fails, use `load` to read raw bytes from a file
""",
        "analyse": """\
## analyse

Show detailed analysis of the currently loaded shellcode.

**Usage:**

    analyse

**Output sections:**

1. **Summary panel** -- size, entropy, arch, MD5, SHA256
2. **Detection panel** -- known pattern match (Metasploit, Cobalt Strike, etc.)
3. **Byte distribution** -- top 6 most frequent bytes with percentage bars
4. **Null byte info** -- count and percentage of zero bytes

**Entropy guide:**

| entropy | interpretation                           |
|---------|------------------------------------------|
| 0 - 3.5 | low -- mostly null/repeated bytes        |
| 3.5 - 6 | moderate -- typical shellcode            |
| 6 - 7.2 | high -- possibly encoded/encrypted       |
| 7.2 +   | very high -- likely packed/encrypted     |
""",
        "format": """\
## format

Set the output format used by `generate` and `export`.

**Usage:**

    format <id>

**Available format IDs:**

| id          | output                              |
|-------------|-------------------------------------|
| `c`         | C `unsigned char buf[] = {...};`    |
| `c_str`     | C `\\x` string literal              |
| `python`    | Python `b"\\x90..."`                |
| `powershell`| PowerShell `[Byte[]] $buf = @(...)` |
| `csharp`    | C# `byte[] buf = new byte[]{...};`  |
| `vba`       | VBA function with hex-decode loop   |
| `rust`      | Rust `let buf: &[u8] = &[...];`     |
| `base64`    | Base64 encoded string               |
| `hex_0x`    | Space-separated `0xNN` values       |
| `hex_raw`   | Continuous hex string               |
| `escaped`   | `\\xNN` escaped hex string          |

**Examples:**

    format python
    format powershell
    format base64
""",
        "transform": """\
## transform

Set the transform applied to the shellcode before formatting.

**Usage:**

    transform <id> [key]

**Parameters:**

- `id`  -- transform ID (see table below)
- `key` -- XOR key; required for `xor_key` only

**Available transforms:**

| id               | description                                |
|------------------|--------------------------------------------|
| `none`           | no transform (default)                     |
| `xor_random`     | XOR with a random 4-byte key               |
| `xor_key`        | XOR with a specified key                   |
| `base64_encode`  | encode to Base64                           |
| `base64_decode`  | decode from Base64                         |
| `zlib_compress`  | zlib compress at level 9                   |
| `zlib_decompress`| zlib decompress                            |

**Key formats for `xor_key`:**

    transform xor_key 0x41              single byte 0x41
    transform xor_key 0xde,0xad,0xbe,0xef   multi-byte
    transform xor_key deadbeef          4-byte raw hex
    transform xor_key mysecret          passphrase

**Notes:**

- `xor_random` generates a new key each time `generate` is called
- The XOR key used is shown in the output summary panel
- Transforms are cumulative with the selected format: the transform is
  applied first, then the formatter encodes the result
""",
        "varname": """\
## varname

Set the variable name used in generated code output.

**Usage:**

    varname <name>

**Parameters:**

- `name` -- identifier name; non-alphanumeric characters are replaced with `_`

**Examples:**

    varname shellcode
    varname payload
    varname inject_buf

**Notes:**

- Only affects code-generating formats (`c`, `c_str`, `python`, `powershell`,
  `csharp`, `vba`, `rust`)
- Has no effect on `base64`, `hex_0x`, `hex_raw`, `escaped`
""",
        "generate": """\
## generate

Run the full pipeline and display the formatted shellcode output.

**Usage:**

    generate [format]

**Parameters:**

- `format` -- optional; override the current format for this run only

**Examples:**

    generate
    generate python
    generate powershell

**Output:**

1. Current settings summary (format, transform, variable name)
2. XOR key details (if xor_random or xor_key transform is active)
3. Syntax-highlighted code output

**Notes:**

- Output longer than 40 lines opens in a pager; press `q` to exit
- The transform is applied every time `generate` is called;
  use `xor_random` carefully -- each call produces a different key
""",
        "save": """\
## save

Save the transformed raw bytes to a binary file.

**Usage:**

    save <path>

**Parameters:**

- `path` -- output file path; `~` expansion supported

**Examples:**

    save /tmp/payload_xored.bin
    save ~/staging/encoded.bin

**Notes:**

- The current transform is applied before saving
- The file contains raw binary bytes (not formatted text)
- Use `export` to save the formatted code output as text
""",
        "export": """\
## export

Export the formatted code output to a text file.

**Usage:**

    export <path>

**Parameters:**

- `path` -- output file path; `~` expansion supported

**Examples:**

    export /tmp/shellcode.py
    export ~/staging/payload.c

**Notes:**

- Uses the current format and transform settings
- The file contains the text output from `generate` (not raw bytes)
- Use `save` to write raw transformed bytes to a binary file
""",
        "formats": """\
## formats

List all available output format IDs with descriptions.

**Usage:**

    formats
""",
        "transforms": """\
## transforms

List all available transform IDs with descriptions.

**Usage:**

    transforms
""",
    },

    # -- malpedia --------------------------------------------------------------
    "malpedia": {
        "_overview": """\
# Malpedia

Browse 1007 APT threat actors, 3750 malware families, recent threat intel
reports and per-family YARA rules from Malpedia
(https://malpedia.caad.fkie.fraunhofer.de).

Works unauthenticated for public data.
Set `config/malpedia_config.json -> api_token` for full access.

## Commands

| command           | description                                         |
|-------------------|-----------------------------------------------------|
| `status`          | API version, auth status, cache info                |
| `reports [N]`     | recent threat intel reports (default 20)            |
| `actors [query]`  | list or search threat actors (paginated)            |
| `families [query]`| list or search malware families (paginated)         |
| `actor <id>`      | full actor detail: country, families, TTPs, refs    |
| `family <id>`     | full family detail: description, attribution, URLs  |
| `yara <id>`       | YARA rules for a malware family from Malpedia       |
| `search <query>`  | search actors + families simultaneously             |
| `refresh`         | force refresh cached actor/family lists             |
| `help [cmd]`      | show this help, or docs for a specific command      |
| `back`            | return to main menu                                 |

## Quick start

    status                          -- check API connectivity
    reports 10                      -- latest 10 threat intel reports
    actors lazarus                  -- find Lazarus Group actor entry
    actor lazarus_group             -- full detail: country, TTPs, 136 families
    families cobalt                 -- find Cobalt Strike family entry
    family win.cobalt_strike        -- description, attribution, reference URLs
    yara win.cobalt_strike          -- fetch + display YARA rules
    yara win.mimikatz save /tmp/mimi.yar  -- fetch and save to file
    search apt29                    -- search actors and families at once
""",
        "status": """\
## status

Show Malpedia API status, version, authentication state and cache info.

**Usage:**

    status
""",
        "reports": """\
## reports

Fetch and display recent threat intelligence reports from the Malpedia library.

**Usage:**

    reports [N]

**Parameters:**

- `N` -- optional; number of reports to fetch (default 20, max 100)

**Examples:**

    reports
    reports 10
    reports 50

**Output:** table with date, organisation, title and tagged malware families,
followed by a numbered URL list for easy copy-paste.

**Notes:**

- Scrapes the public Malpedia library page; no API token required
- Report URLs are absolute (https://malpedia.caad.fkie.fraunhofer.de/...)
  unless the report is hosted externally, in which case the original URL is shown
""",
        "actors": """\
## actors

List or search threat actors.

**Usage:**

    actors [query]

**Parameters:**

- `query` -- optional; searches actor ID, common name and synonyms via the
  Malpedia search API

**Examples:**

    actors
    actors lazarus
    actors apt28
    actors china

**Notes:**

- 20 entries per page; press **Enter** to advance
- Use `actor <id>` to drill into full detail for any listed actor
- Without a query, actors are listed alphabetically from the local cache
""",
        "families": """\
## families

List or search malware families.

**Usage:**

    families [query]

**Parameters:**

- `query` -- optional; searches family ID and alt names via the Malpedia API

**Examples:**

    families
    families cobalt
    families win.mimikatz
    families ransomware

**Notes:**

- 20 entries per page; press **Enter** to advance
- Family IDs follow the format `platform.name` (e.g. `win.cobalt_strike`)
- Use `family <id>` to drill into full detail
""",
        "actor": """\
## actor

Show full detail for a threat actor.

**Usage:**

    actor <id>

**Parameters:**

- `id` -- actor ID (e.g. `lazarus_group`, `apt28`); partial match supported

**Examples:**

    actor lazarus_group
    actor apt28
    actor cozy_bear

**Output:**

1. Header panel: ID, name, country, synonyms, target categories, victims
2. Malware families table: family ID, common name, attribution
3. External reference URLs
""",
        "family": """\
## family

Show full detail for a malware family.

**Usage:**

    family <id>

**Parameters:**

- `id` -- family ID in `platform.name` format; partial match supported

**Examples:**

    family win.cobalt_strike
    family win.mimikatz
    family apk.888_rat

**Output:**

1. Header panel: ID, common name, alt names, updated date, attribution
2. Description (full text, pager for long entries)
3. Reference URLs (up to 10)
""",
        "yara": """\
## yara

Fetch and display YARA rules for a malware family from Malpedia.

**Usage:**

    yara <family-id> [save <path>]

**Parameters:**

- `family-id` -- Malpedia family ID (e.g. `win.cobalt_strike`)
- `save <path>` -- optional; save the rules to a file

**Examples:**

    yara win.cobalt_strike
    yara win.mimikatz save /tmp/mimikatz.yar
    yara elf.bashlite

**Output:** syntax-highlighted YARA rules (pager for long rule sets).

**Notes:**

- Only `tlp_white` rules are returned for unauthenticated access
- Some families have no rules available
""",
        "search": """\
## search

Search actors and malware families simultaneously.

**Usage:**

    search <query>

**Parameters:**

- `query` -- case-insensitive; searches actor names/synonyms and family IDs/alt names

**Examples:**

    search lazarus
    search cobalt strike
    search ransomware
    search apt29

**Output:** two sections -- Actor Matches and Family Matches.
""",
        "refresh": """\
## refresh

Force-refresh the local actor and family ID caches from the Malpedia API.

**Usage:**

    refresh

**Notes:**

- Caches are stored in `data/malpedia_actors_cache.json` and
  `data/malpedia_families_cache.json`
- On first run the caches are populated automatically; use `refresh` after
  Malpedia updates its data or when the local cache is stale
- Actor list: ~979 entries; Family list: ~3700+ entries
""",
    },

    # -- yara ------------------------------------------------------------------
    "yara": {
        "_overview": """\
# YARA Lab

Generate a YARA detection rule from any PE or raw binary file.
Optionally scan a target file against the generated rule.

The generator extracts:

- **PE metadata** -- imphash, section count, entry-point byte pattern
- **Interesting strings** -- 10 suspicious ASCII strings (imports, registry
  keys, C2 APIs, tool names); 4 wide strings
- **Filesize bounds** -- +/-25% around the original file size
- **Condition** -- requires >= 2 string matches + PE structural checks

## Workflow

    gen <path>                    -- generate YARA rule from a file
    gen-build <id> [filename]     -- generate from a compiled build binary
    builds                        -- list successful builds with their binaries
    show                          -- display the last generated rule
    save <path>                   -- save rule to a .yar file
    info                          -- metadata for last generated rule (hashes, sections)
    scan <path>                   -- scan a target file against the current rule

## Condition logic

The generated rule uses AND-chained conditions:

    $ep at pe.entry_point           (entry-point byte pattern)
    pe.imphash() == "..."           (import hash)
    pe.number_of_sections == N
    2 of ($s0, $s1, ..., $w12, ...) (string indicators)
    filesize >= LO and filesize <= HI

Non-PE files skip the PE-specific conditions and rely on strings + filesize.
""",
        "gen": """\
## gen

Generate a YARA rule from a binary file.

**Usage:**

    gen <path>

**Parameters:**

- `path` -- path to PE (.exe/.dll/.sys) or raw binary; `~` expansion supported

**Examples:**

    gen /tmp/payload.exe
    gen ~/samples/beacon.dll
    gen samples/malware-injection-17/malware-injection-17.exe

**Output:**

1. Metadata panel: file, size, MD5, SHA256, PE sections with entropy bars
2. Syntax-highlighted YARA rule

**Notes:**

- Requires `pefile` for PE analysis (already installed in peekaboo venv)
- The generated rule is held in memory; use `save` to write it to disk
- Rule name is derived from the filename (non-alphanumeric -> underscore)
""",
        "show": """\
## show

Display the last generated YARA rule.

**Usage:**

    show

**Notes:**

- Requires a prior `gen` call in this session
- Long rules open in a pager; press `q` to exit
""",
        "save": """\
## save

Save the last generated rule to a file.

**Usage:**

    save <path>

**Parameters:**

- `path` -- output file path; conventionally `.yar` or `.yara` extension

**Examples:**

    save /tmp/beacon_rule.yar
    save ~/rules/malware-trick-52.yar

**Notes:**

- Overwrites existing files without prompting
- Requires a prior `gen` call in this session
""",
        "info": """\
## info

Show metadata for the last generated rule.

**Usage:**

    info

**Output:**

- Rule name, file path, MD5, SHA256, file size
- PE sections table with entropy bars (if PE file)
- Import hash (imphash), string count, high-entropy section count
""",
        "scan": """\
## scan

Scan a file against the last generated YARA rule.

**Usage:**

    scan <path>

**Parameters:**

- `path` -- target file to scan

**Examples:**

    scan /tmp/unknown.exe
    scan ~/samples/test.bin

**Requirements:**

- `yara-python` must be installed:  pip install yara-python
- Requires a prior `gen` call in this session

**Output:**

- MATCH or NO MATCH result
- For each match: rule name and matched strings with file offsets
""",
        "gen-build": """\
## gen-build

Generate a YARA rule directly from a compiled build binary.

**Usage:**

    gen-build <build-id> [filename]

**Parameters:**

- `build-id` -- ID from the build history (use  builds  to list)
- `filename`  -- optional; pick a specific binary when the build produced
                 multiple files (e.g. `persistence.exe`)

**Examples:**

    gen-build a1b2c3d4
    gen-build a1b2c3d4 persistence.exe

**Notes:**

- When a build has exactly one binary the filename is inferred automatically
- When a build produced two files (main + persistence) and no filename is
  given, both are listed and you are prompted to specify one
- After generation the rule is available via  show / save / scan  as usual
""",
        "builds": """\
## builds

List all successful builds together with their compiled binaries.

**Usage:**

    builds

**Output:**

A table with columns: build-id, type, module, date, binaries.
The binaries column shows every file on disk for that build
(e.g. `peekaboo.exe  persistence.exe`).
Use the build-id with  gen-build  to generate a YARA rule.
""",
    },

    # -- ttp -------------------------------------------------------------------
    "ttp": {
        "_overview": """\
# TTP

Map MITRE ATT&CK technique IDs to real implementations from the blog
and compile them directly.

Data is stored in the peekaboo database (ttp_implementations table).
Each row is one (attack_id, blog_post) pair with the compilable meow slug.

**Commands:**

| command                | description                                          |
|------------------------|------------------------------------------------------|
| `list [filter]`        | list all techniques with implementations             |
| `show <id>`            | show all implementations for a specific TTP          |
| `search <query>`       | search by keyword, tactic, technique name or notes   |
| `build <id>`           | compile the implementation for a given technique     |
| `refresh`              | re-seed implementations from source data             |
| `help [cmd]`           | show this help or detailed help for a command        |
| `back`                 | return to main menu                                  |

**Quick start:**

    ttp> list persistence          list all persistence technique implementations
    ttp> show T1547.001            show all registry run key implementations
    ttp> search APC injection      search by technique description keyword
    ttp> build T1055.004           compile APC injection implementation
    ttp> refresh                   rebuild the implementations table
""",
        "list": """\
## list

List techniques with implementations, optionally filtered.

**Usage:**

    list [filter]

**Filter options:**

- tactic name: `persistence`, `defense-evasion`, `execution`, `privilege-escalation`, ...
- platform:    `windows`, `linux`, `macos`
- attack ID:   `T1055`, `T1547`  (shows all sub-techniques)
- (no filter)  shows all techniques grouped by tactic

**Examples:**

    list
    list persistence
    list defense-evasion
    list windows
    list macos
    list T1055

**Columns:** attack_id | technique name | tactic | impls | compile

- `impls`   -- number of blog post implementations for this technique
- `compile` -- YES if at least one has a compilable meow module
""",
        "show": """\
## show

Show all implementations for a specific ATT&CK technique.

**Usage:**

    show <attack_id>

**Examples:**

    show T1547.001
    show T1055.004
    show T1546.002

**Output:**

1. Technique panel: name, tactic, ATT&CK description
2. Implementations table: blog post | platform | notes | meow slug | blog URL
3. Hint for  build  command if compilable implementations exist
""",
        "search": """\
## search

Full-text search across technique names, tactics, notes and blog slugs.

**Usage:**

    search <query>

**Examples:**

    search APC
    search registry run
    search screensaver
    search NtCreateSection
    search macos launchagent

**Output:** table of matching (attack_id, blog_slug) pairs with notes.
""",
        "build": """\
## build

Compile the implementation for a given ATT&CK technique.

**Usage:**

    build <attack_id>

**Examples:**

    build T1547.001
    build T1055.004
    build T1546.002

**Flow:**

1. All compilable implementations for the technique are listed
2. If more than one, enter the number to select which to compile
3. Module is compiled via the meow backend
4. Output: `samples/<session-id>/<slug>.exe`
5. Build result saved to the peekaboo database

**Notes:**

- Only implementations with a meow_slug in the database are compilable
- Entries without a meow_slug show blog_url only (no binary output)
""",
        "refresh": """\
## refresh

Re-seed the ttp_implementations table from source data.
Resolves tech_name and tactic from the STIX bundle.
Resolves blog_url from the mitre_library table.

**Usage:**

    refresh

Use this after adding new TTP_IMPLEMENTATIONS entries in mitre.py
or after updating the STIX bundle.
""",
    },

    # -- builder ---------------------------------------------------------------
    "builder": {
        "_overview": """\
# Builder

Compile peekaboo malware research modules directly from the CLI.
Uses the same MingW / GCC backend as the dashboard builder.

Output binaries are written to `samples/<session-id>/`.
Each build is saved to the peekaboo database automatically.

**Supported compilers:**

| compiler    | targets                         |
|-------------|---------------------------------|
| `mingw-gcc` | Windows x64 (C)                 |
| `mingw-gpp` | Windows x64 (C++)               |
| `gcc`       | Linux x64 (C)                   |
| `gpp`       | Linux x64 (C++)                 |

Note: `nasm` and `nim` modules are listed but cannot be built via
the CLI builder (the dashboard handles them separately).

## Commands

| command               | description                                       |
|-----------------------|---------------------------------------------------|
| `list [filter]`       | list compilable modules; filter by platform/cat   |
| `list stealer`        | list standalone stealer modules                   |
| `list persistence`    | list persistence mechanisms                       |
| `search <query>`      | search meow modules + stealers simultaneously     |
| `build <slug>`        | compile meow module -- colorized compiler log     |
| `build <stealer>`     | compile stealer + choose persistence mechanism    |
| `history [N]`         | last N builds from DB (default 20)                |
| `show <build-id>`     | full compiler log for a specific build            |
| `clear`               | delete build history from DB + binaries from disk |
| `help [cmd]`          | show this help, or docs for a specific command    |
| `back`                | return to main menu                               |

## Filters for list

    list windows       -- only Windows/MingW modules
    list linux         -- only Linux/GCC modules
    list stealer       -- standalone stealers (angelcam, azure, bitbucket, github, slack, telegram, virustotal)
    list persistence   -- persistence mechanisms (registry_run, screensaver, filetype_hijack, winlogon)
    list injection     -- only modules in the injection category

## Quick start

    list stealer                    -- browse available stealers
    build virustotal                -- compile virustotal stealer (prompts for persistence)
    build telegram                  -- compile telegram stealer
    build slack                     -- compile slack stealer
    list persistence                -- see all persistence options
    search lazarus                  -- search meow modules + stealers for lazarus
    history 10                      -- last 10 builds
""",
        "list": """\
## list

Show a paginated table of compilable modules, with optional filter.

**Usage:**

    list [filter]

**Parameters:**

- `filter` -- optional; platform name (`windows`, `linux`), special keyword
  (`stealer`, `persistence`), or partial category name (`injection`, `evasion`, etc.)

**Examples:**

    list
    list windows
    list linux
    list stealer
    list persistence
    list injection
    list crypto

**Columns:** # | slug | platform | compiler | category | T-IDs | title

**Notes:**

- 20 entries per page; press **Enter** to advance
- Modules marked non-compilable (nasm, nim) are excluded
- `list stealer` shows the 7 standalone stealers from `malware/stealer/`
- `list persistence` shows the 4 persistence mechanisms from `malware/persistence/`
- Use `build <slug>` or `build <stealer-name>` to compile
""",
        "search": """\
## search

Search meow modules and standalone stealers simultaneously.

**Usage:**

    search <query>

**Parameters:**

- `query` -- case-insensitive; matches slug, title, T-ID, category (meow modules)
  and stealer name (standalone stealers)

**Examples:**

    search T1055
    search process injection
    search telegram
    search virustotal
    search stealer
    search persistence

**Output:**

- Stealer matches shown first as a compact table (if any)
- Meow module matches shown below as the standard paginated table

**Notes:**

- Non-compilable meow modules are excluded from results
- Stealer partial names match (e.g. `search viru` finds `virustotal`)
""",
        "build": """\
## build

Compile a meow module or a stealer and save output to `samples/<session-id>/`.

**Usage:**

    build <slug>           -- compile a meow module (injection, evasion, etc.)
    build <stealer-name>   -- compile a stealer with optional persistence

**Parameters:**

- `slug`         -- module slug from `list` / `search`; partial match supported
- `stealer-name` -- stealer name from `list stealer`; partial match supported

**Examples (meow modules):**

    build malware-injection-17
    build malware-tricks-54
    build malware-evasion-12

**Examples (stealers):**

    build virustotal
    build github
    build telegram
    build viru          -- partial match, resolves to virustotal

**Stealer build flow:**

1. Persistence mechanism table is shown (name + description)
2. Enter a persistence name from the table, or press Enter to skip
3. Stealer is compiled  -> `samples/<session-id>/peekaboo.exe`
4. If persistence chosen, it is compiled too -> `samples/<session-id>/persistence.exe`
5. Deployment instructions panel is shown
6. Build result saved to the peekaboo database

**Output (meow module):**

1. Pre-build summary: slug, platform, compiler, source file
2. Compiler command and live log output (colorized)
3. BUILD OK / BUILD FAILED panel with output path and file size

**Notes:**

- The original source files are never modified (copied to a temp dir)
- Credential placeholders (Telegram token, GitHub PAT, etc.) are
  automatically substituted from `config/*.json` before compilation
- Stealer output: `samples/<session-id>/peekaboo.exe`
- Meow module output: `samples/<session-id>/<slug>.exe` (Windows)
  or `samples/<session-id>/<slug>` (Linux)
- The build result is saved to the peekaboo database automatically
- If the compiler is not installed, an error is shown with the
  expected binary name (e.g. `x86_64-w64-mingw32-gcc`)
""",
        "history": """\
## history

Show recent build history from the peekaboo database.

**Usage:**

    history [N]

**Parameters:**

- `N` -- optional; number of builds to show (default 20, max 100)

**Examples:**

    history
    history 5
    history 50

**Columns:** # | build-id | slug | status | date | duration | rc

**Notes:**

- Builds from both the CLI and the dashboard are listed
- Use `show <build-id>` for the full compiler log of any listed build
""",
        "show": """\
## show

Show full details and compiler log for a specific build.

**Usage:**

    show <build-id>

**Parameters:**

- `build-id` -- the ID from the `history` table (e.g. `cli-a3f9b1c2`)
- Partial prefix match is supported (first 6+ chars usually unique)

**Examples:**

    show cli-a3f9b1c2
    show cli-a3f9

**Output:**

1. Build metadata panel: ID, slug, platform, compiler, status, date, duration
2. Full compiler log with colorized `[ok]` / `[fail]` / `[warn]` markers
   (long logs open in a pager; press `q` to exit)
""",
        "clear": """\
## clear

Delete all build history from the database **and** delete all compiled
binaries (`peekaboo.exe`, `persistence.exe`) from the `malware/` tree.

Does **not** touch TTPs, Sigma rules, MITRE ATT&CK data, or Malpedia.

**Usage:**

    clear

A confirmation prompt is shown before anything is deleted.

**What is removed:**

- All rows in the `builds` DB table
- Every `peekaboo.exe` found under `malware/**`
- Every `persistence.exe` found under `malware/**`

**Examples:**

    clear
""",
    },

    # -- vtscan ----------------------------------------------------------------
    "vtscan": {
        "_overview": """\
# VirusTotal Scanner

Scan compiled binaries or any local file with 70+ AV/EDR engines via VirusTotal.
Requires a VirusTotal API key in `config/virustotal_config.json`.

## Commands

| command              | description                                        |
|----------------------|----------------------------------------------------|
| `list`               | show successful builds that have binaries on disk  |
| `scan <build-id>`    | upload build binary to VirusTotal and show results |
| `scan-file <path>`   | upload any local PE file to VirusTotal             |
| `poll <analysis-id>` | check status of a pending analysis                 |
| `lookup <sha256>`    | fetch existing report from VT by SHA256 hash       |
| `help [cmd]`         | show this help or docs for a specific command      |
| `back`               | return to main menu                                |

## Notes

- If VT already has the file (matching SHA256), cached results are shown instantly.
- New uploads are queued; use `poll` to check when the analysis is done.
- Results show detection rate and all engine verdicts.
""",
        "scan": """\
## scan

Upload a compiled build binary to VirusTotal by build ID.

**Usage:**

    scan <build-id>

**Examples:**

    scan cli-a1b2c3d4
    scan 9f3e1a2b

**Notes:**

- Use `list` to find available build IDs with binaries on disk.
- If VT already has the file, cached results are shown immediately.
- Otherwise an analysis ID is returned; use `poll <id>` to check status.
""",
        "scan-file": """\
## scan-file

Upload any local file to VirusTotal.

**Usage:**

    scan-file <path>

**Examples:**

    scan-file /tmp/payload.exe
    scan-file ~/samples/beacon.dll

**Notes:**

- Tab completion works for the path argument.
- File must be accessible and non-empty.
""",
        "poll": """\
## poll

Check the status of a pending VirusTotal analysis.

**Usage:**

    poll <analysis-id>

**Examples:**

    poll NjI4NGQxZmI...

**Notes:**

- Copy the analysis ID from the output of `scan` or `scan-file`.
- Returns status (queued / in-progress / completed) and results when done.
""",
        "lookup": """\
## lookup

Fetch an existing VirusTotal file report by SHA256 hash.

**Usage:**

    lookup <sha256>

**Examples:**

    lookup 4b3a2e1f...
""",
    },

    # -- hellsgate -------------------------------------------------------------
    "hellsgate": {
        "_overview": """\
# Hell's Gate / Halo's Gate / Tartarus Gate

Parse a Windows `ntdll.dll` to extract System Service Numbers (SSNs) for all
`Nt*` / `Zw*` exports, detect EDR inline hooks, recover hooked SSNs, and
generate ready-to-compile direct-syscall stubs.

## Commands

| command                   | description                                              |
|---------------------------|----------------------------------------------------------|
| `scan <path>`             | parse ntdll.dll and extract SSN table                    |
| `filter all|clean|hooked` | filter SSN table by hook status                          |
| `search <name>`           | filter by function name substring                        |
| `show [page]`             | show current SSN table (paginated)                       |
| `select <name…>`          | toggle functions for code generation                     |
| `select-all`              | select all currently filtered functions                  |
| `select-hooked`           | select all hooked / patched functions                    |
| `select-common`           | select 19 common injection APIs                          |
| `deselect-all`            | clear selection                                          |
| `generate nasm|c`         | emit NASM x64 or C `__declspec(naked)` stubs             |
| `save <path>`             | save last generated code to file                         |
| `help [cmd]`              | show this help or docs for a specific command            |
| `back`                    | return to main menu                                      |

## Hook types detected

| type          | bytes           | description                       |
|---------------|-----------------|-----------------------------------|
| `jmp_rel32`   | E9 xx xx xx xx  | relative JMP trampoline           |
| `jmp_abs`     | FF 25 ...       | indirect JMP via pointer          |
| `int3`        | CC              | INT3 breakpoint                   |
| `push_ret`    | 68 ... C3       | PUSH addr / RET trampoline        |
| `partial`     | partial prologue| prologue bytes overwritten        |

## SSN recovery methods

- **Halo's Gate** -- finds nearest clean neighbour in RVA order; SSNs are contiguous in ntdll's EAT.
- **Tartarus Gate** -- forward-scans the stub for a `B8 xx xx xx xx` sequence with a value < 0x600.

## Quick start

    peekaboo > hellsgate
    peekaboo [hellsgate] > scan /mnt/win/ntdll.dll
    peekaboo [hellsgate] > filter hooked
    peekaboo [hellsgate] > select-common
    peekaboo [hellsgate] > generate nasm
    peekaboo [hellsgate] > save /tmp/syscalls.asm
""",
        "scan": """\
## scan

Parse a ntdll.dll binary and extract the SSN table.

**Usage:**

    scan <path>

**Examples:**

    scan /mnt/win/ntdll.dll
    scan ~/samples/ntdll_edr.dll

**Notes:**

- Architecture is auto-detected from the PE Machine field.
- Use `filter hooked` after scanning to focus on patched stubs.
""",
        "generate": """\
## generate

Emit direct-syscall stubs for all selected functions.

**Usage:**

    generate nasm
    generate c

**Examples:**

    generate nasm    # NASM x64 .asm file
    generate c       # C __declspec(naked) stubs

**Notes:**

- Select functions first with `select`, `select-common`, or `select-hooked`.
- Use `save <path>` to write the output to disk.
""",
        "select-common": """\
## select-common

Select a preset list of 19 commonly used injection / execution APIs:

    NtAllocateVirtualMemory  NtWriteVirtualMemory   NtProtectVirtualMemory
    NtCreateThreadEx         NtOpenProcess           NtReadVirtualMemory
    NtFreeVirtualMemory      NtClose                 NtQuerySystemInformation
    NtQueryInformationProcess NtSetInformationThread NtCreateSection
    NtMapViewOfSection       NtUnmapViewOfSection    NtQueueApcThread
    NtResumeThread           NtSuspendThread         NtTerminateProcess
    NtFlushInstructionCache
""",
    },

    # -- scemu -----------------------------------------------------------------
    "scemu": {
        "_overview": """\
# Shellcode Emulator

x86/x64 shellcode emulator powered by Unicorn Engine with Capstone disassembly.
Runs shellcode in an isolated virtual CPU -- no kernel interaction.

## Commands

| command              | description                                               |
|----------------------|-----------------------------------------------------------|
| `run <path>`         | emulate a raw shellcode binary file                       |
| `hex <hex_string>`   | emulate shellcode from hex (`\\xNN`, `0xNN,`, raw hex)    |
| `disasm <path>`      | disassemble-only mode (no CPU execution)                  |
| `arch x64|x86`       | set architecture for next run (default: x64)              |
| `maxinsns <N>`       | set instruction count limit (default: 10 000, max: 50 000)|
| `trace`              | show per-instruction execution trace                      |
| `regs`               | show final register state                                 |
| `mem`                | show memory read/write log                                |
| `api`                | show intercepted API calls                                |
| `strings`            | show extracted strings from emulated memory               |
| `smc`                | show self-modifying code detection result                 |
| `help [cmd]`         | show this help or docs for a specific command             |
| `back`               | return to main menu                                       |

## Memory layout

| region    | address      | size   |
|-----------|--------------|--------|
| shellcode | 0x00400000   | 1 MB   |
| stack     | 0x00200000   | 512 KB |
| heap      | 0x00600000   | 512 KB |

## Stop conditions

- Instruction count limit reached
- Wall-clock timeout (10 s)
- Clean `ret` to sentinel address
- CPU exception

## Quick start

    peekaboo > scemu
    peekaboo [scemu] > arch x64
    peekaboo [scemu] > run /tmp/payload.bin
    peekaboo [scemu] > trace
    peekaboo [scemu] > api
    peekaboo [scemu] > strings
""",
        "run": """\
## run

Load and emulate a raw shellcode binary file.

**Usage:**

    run <path>

**Examples:**

    run /tmp/payload.bin
    run ~/samples/beacon.raw

**Notes:**

- File is loaded as raw bytes at the shellcode base address (0x00400000).
- Use `trace`, `regs`, `mem`, `api`, `strings`, `smc` to inspect results.
""",
        "hex": """\
## hex

Emulate shellcode supplied as a hex string inline.

**Usage:**

    hex <hex_string>

**Accepted formats:**

    hex \\x48\\x31\\xc0\\xc3
    hex 0x48, 0x31, 0xc0, 0xc3
    hex 4831c0c3

**Notes:**

- All three formats are parsed identically.
- Prefix and separator characters are stripped automatically.
""",
        "arch": """\
## arch

Set the CPU architecture for the next emulation run.

**Usage:**

    arch x64
    arch x86

**Notes:**

- Default is x64.
- Must be set before `run` or `hex`.
""",
        "maxinsns": """\
## maxinsns

Set the maximum instruction count before emulation stops.

**Usage:**

    maxinsns <N>

**Examples:**

    maxinsns 5000
    maxinsns 50000

**Notes:**

- Default: 10 000. Hard cap: 50 000.
- Use lower values for faster analysis of known-short shellcode.
""",
    },

    # -- antianalysis ----------------------------------------------------------
    "antianalysis": {
        "_overview": """\
# Anti-Analysis Pattern Scanner

Static Capstone scanner for anti-debug, anti-VM, timing, and sandbox-evasion
techniques. Disassembles all executable sections; no code is executed.

## Commands

| command                                           | description                                  |
|---------------------------------------------------|----------------------------------------------|
| `scan <path>`                                     | scan a PE binary or raw shellcode file       |
| `scan-build [id] [fname]`                         | scan a compiled build binary                 |
| `scan-session <sid> <file>`                       | scan a session sample                        |
| `arch auto|x64|x86`                               | set architecture (default: auto from PE)     |
| `filter all|anti_debug|anti_vm|timing|evasion`    | filter findings by category                  |
| `list [page]`                                     | show findings table (paginated)              |
| `export <path>`                                   | export findings as JSON                      |
| `builds`                                          | list available compiled builds               |
| `help [cmd]`                                      | show this help or docs for a specific command|
| `back`                                            | return to main menu                          |

## Pattern catalog

| ID         | Technique                              | Category    | MITRE       | Sev    |
|------------|----------------------------------------|-------------|-------------|--------|
| RDTSC      | Read timestamp counter                 | Timing      | T1497.003   | High   |
| CPUID      | Hypervisor bit / vendor string probe   | Anti-VM     | T1497.001   | Medium |
| INT2D      | INT 2D kernel debug interrupt          | Anti-Debug  | T1622       | High   |
| INT3_AA    | Inline INT 3 breakpoint trap           | Anti-Debug  | T1622       | Medium |
| IN_DX      | VMware I/O backdoor (port 0x5658)      | Anti-VM     | T1497.001   | High   |
| SIDT       | IDT location probe (Red Pill)          | Anti-VM     | T1497.001   | High   |
| SGDT       | GDT base fingerprint                   | Anti-VM     | T1497.001   | High   |
| SLDT       | LDT selector check                     | Anti-VM     | T1497.001   | Medium |
| STR_REG    | Task Register selector (VMware = 0x40) | Anti-VM     | T1497.001   | Medium |
| RDPMC      | Performance counter timing side-channel| Timing      | T1497.003   | Medium |
| PEB_READ   | PEB.BeingDebugged via FS:[30h]/GS:[60h]| Anti-Debug  | T1622       | High   |
| NOP_SLED   | ≥8 consecutive NOPs (emulator stall)   | Evasion     | T1497.003   | Low    |
| PUSHFD     | PUSHFD/POPFD Trap Flag probe           | Anti-Debug  | T1622       | High   |
| VPC_MAGIC  | VPC/Hyper-V magic bytes (0F 3F 07 0B)  | Anti-VM     | T1497.001   | High   |
| DIV_ZERO   | DIV/IDIV register -- SEH trap          | Anti-Debug  | T1622       | Medium |

## Quick start

    peekaboo > antianalysis
    peekaboo [antianalysis] > scan /tmp/sample.exe
    peekaboo [antianalysis] > filter anti_debug
    peekaboo [antianalysis] > list
    peekaboo [antianalysis] > export /tmp/findings.json
""",
        "scan": """\
## scan

Scan a PE binary or raw shellcode file for anti-analysis patterns.

**Usage:**

    scan <path>

**Examples:**

    scan /tmp/sample.exe
    scan ~/samples/loader.dll

**Notes:**

- Architecture is auto-detected from the PE header; override with `arch`.
- All executable sections are scanned (IMAGE_SCN_MEM_EXECUTE).
- If the file is not a valid PE, it is treated as raw shellcode.
""",
        "filter": """\
## filter

Filter the findings table by category.

**Usage:**

    filter all
    filter anti_debug
    filter anti_vm
    filter timing
    filter evasion

**Notes:**

- `all` resets the filter and shows everything.
- Use `list` after filtering to see the narrowed results.
""",
        "export": """\
## export

Export the current findings to a JSON file.

**Usage:**

    export <path>

**Examples:**

    export /tmp/findings.json
    export ~/reports/sample_antianalysis.json

**Notes:**

- Exports all findings from the last scan (ignores active filter).
- File is created or overwritten.
""",
    },

    # -- rop -------------------------------------------------------------------
    "rop": {
        "_overview": """\
# ROP Chain Builder

Find Return-Oriented Programming gadgets in Windows PE / DLL / SYS binaries
(x64 and x86), build exploit chains, and generate C or Python payloads.

## Commands

| command                        | description                                          |
|--------------------------------|------------------------------------------------------|
| `scan <path>`                  | scan a PE/DLL/SYS binary for ROP gadgets             |
| `scan-build [id] [fname]`      | scan a compiled build binary                         |
| `scan-session <sid> <file>`    | scan a session sample                                |
| `arch auto|x64|x86`            | set architecture (default: auto from PE header)      |
| `base <hex>`                   | override image base (e.g. `base 0x180000000`)        |
| `filter <semantic>`            | filter by semantic class                             |
| `search <keyword>`             | text search across mnemonics / address / semantic    |
| `list [page]`                  | show gadget table (paginated, 20/page)               |
| `chain-add <#>`                | add gadget by table row number to chain              |
| `chain-add-addr <addr>`        | add gadget by hex address to chain                   |
| `chain-arg <slot> <value>`     | set stack argument for a chain slot                  |
| `chain-show`                   | print current chain                                  |
| `chain-clear`                  | clear the chain                                      |
| `generate c|py`                | generate C ULONG_PTR array or Python payload         |
| `save <path>`                  | save last generated code to file                     |
| `builds`                       | list available compiled builds                       |
| `help [cmd]`                   | show this help or docs for a specific command        |
| `back`                         | return to main menu                                  |

## Semantic classes

| class        | pattern                                      |
|--------------|----------------------------------------------|
| `ret_only`   | bare ret (no preceding instructions)         |
| `reg_load`   | pop reg; ret                                 |
| `multi_pop`  | multiple consecutive pop instructions        |
| `stack_pivot`| xchg rsp / mov rsp / leave                  |
| `syscall`    | syscall / sysenter / int 0x2e; ret           |
| `reg_mov`    | mov reg, reg; ret                            |
| `mem_write`  | mov [reg…], reg; ret                         |
| `mem_read`   | mov reg, [reg…]; ret                         |
| `arithmetic` | add/sub/xor/and/or/neg/shl/shr/ror/rol; ret  |
| `nop_ret`    | all-NOP body + ret                           |
| `misc`       | anything else ending in ret                  |

## Gadget limits

- Max instructions before terminator: 6
- Max raw bytes per gadget: 24
- Hard cap per binary: 4 000 gadgets

## Quick start

    peekaboo > rop
    peekaboo [rop] > scan /tmp/ntdll.dll
    peekaboo [rop] > filter reg_load
    peekaboo [rop] > list
    peekaboo [rop] > chain-add 3
    peekaboo [rop] > chain-add 7
    peekaboo [rop] > chain-arg 0 0x0000000000000001
    peekaboo [rop chain:2] > generate c
    peekaboo [rop chain:2] > save /tmp/rop_chain.c
""",
        "scan": """\
## scan

Find ROP gadgets in a PE binary, DLL, or SYS driver.

**Usage:**

    scan <path>

**Examples:**

    scan /tmp/ntdll.dll
    scan ~/samples/kernel32.dll

**Notes:**

- Only executable sections (IMAGE_SCN_MEM_EXECUTE) are scanned.
- Architecture and image base are read from the PE header automatically.
- Override arch with `arch` and base with `base` before scanning.
""",
        "filter": """\
## filter

Filter the gadget list by semantic class.

**Usage:**

    filter <semantic>
    filter all

**Valid classes:**

    all  ret_only  reg_load  multi_pop  stack_pivot  syscall
    reg_mov  mem_write  mem_read  arithmetic  nop_ret  misc

**Examples:**

    filter reg_load
    filter stack_pivot
    filter all
""",
        "chain-add": """\
## chain-add

Append a gadget to the chain by its row number in the current `list` view.

**Usage:**

    chain-add <row_number>

**Examples:**

    chain-add 3
    chain-add 12

**Notes:**

- Row numbers start at 1 (as shown in the `list` output).
- Use `chain-show` to review the chain after adding.
- Alternatively use `chain-add-addr <hex_address>` to add by address.
""",
        "generate": """\
## generate

Generate an exploit chain payload from the current chain.

**Usage:**

    generate c
    generate py

**Output (C):**

    ULONG_PTR rop_chain[] = {
        0x7ffb12340000ULL,  /* pop rax; ret */
        0x0000000000000001ULL,  /* arg */
        ...
    };

**Output (Python):**

    import struct
    rop = b""
    rop += struct.pack("<Q", 0x7ffb12340000)  # pop rax; ret
    rop += struct.pack("<Q", 0x0000000000000001)  # arg

**Notes:**

- Build the chain first with `chain-add` / `chain-arg`.
- Use `save <path>` to write to disk.
""",
    },
}


def show_help(module: str = "_top", cmd: str | None = None) -> None:
    """Render documentation from _DOCS using rich Markdown."""
    mod_docs = _DOCS.get(module)
    if mod_docs is None:
        console.print(f"  [warn][=^..^=] no docs for module '{module}'[/warn]\n")
        return

    if cmd:
        text = mod_docs.get(cmd)
        if not text:
            console.print(
                f"  [warn][=^..^=] no docs for '{cmd}' in module '{module}'\n"
                f"  available: {', '.join(k for k in mod_docs if not k.startswith('_'))}[/warn]\n"
            )
            return
        console.print()
        console.print(Panel(Markdown(text), box=box.ROUNDED, border_style="bright_cyan",
                            padding=(1, 2)))
        console.print()
    else:
        text = mod_docs.get("_overview", "")
        if text:
            console.print()
            console.print(Panel(Markdown(text), box=box.ROUNDED, border_style="bright_cyan",
                                padding=(1, 2)))
            console.print()


_BANNER_LINES = [
    "",
    " #####  ###### #    #         ##         #####   ####   ####",
    " #    # #      #   #         #  #        #    # #    # #    #",
    " #    # #####  ####   ##### #    # ##### #####  #    # #    #",
    " #####  #      #  #         ######       #    # #    # #    #",
    " #      #      #   #        #    #       #    # #    # #    #",
    " #      ###### #    #       #    #       #####   ####   ####",
    "",
]
# alternating green shades create a subtle gradient down the logo
_BANNER_STYLES = [
    "bold bright_green",
    "bold bright_green",
    "bold green",
    "bold bright_green",
    "bold green",
    "bold bright_green",
    "bold bright_green",
    "bold bright_green",
]


def print_banner() -> None:
    console.print()
    for i, line in enumerate(_BANNER_LINES):
        t = Text()
        t.append("[=^..^=]", style="bold bright_cyan")
        t.append(line, style=_BANNER_STYLES[i])
        console.print(t)

    console.print()
    console.print(Rule(style="bright_black"))

    badge = Text()
    badge.append("  ")
    badge.append(" [=^..^=] DEFCON Demo Labs Singapore 2026 ", style="bold black on bright_cyan")
    badge.append("   ")
    badge.append("Malware Development Framework", style="bold bright_white")
    badge.append("  ·  ", style="dim")
    badge.append("by @cocomelonc", style="dim")
    badge.append("  ·  ", style="dim")
    badge.append("https://cocomelonc.github.io", style="dim")
    console.print(badge)

    console.print(Rule(style="bright_black"))
    console.print()


# -- top-level commands --------------------------------------------------------
TOP_COMMANDS = [
    "evasion", "library", "artifacts", "builder", "shellcode", "yara",
    "malpedia", "ttp", "pe", "vtscan",
    "hellsgate", "scemu", "antianalysis", "rop",
    "help", "exit", "quit",
]

TOP_HELP = [
    ("evasion",       "PE evasion scorer + surgical patch transforms"),
    ("library",       "MITRE ATT&CK module library -- browse, search, view source"),
    ("artifacts",     "Artifact map -- 410 techniques, 4799 Sigma rules, EventID coverage"),
    ("builder",       "Compile malware research modules; browse build history"),
    ("shellcode",     "Parse, analyse, transform and reformat shellcode"),
    ("yara",          "Generate YARA rules from binaries; scan with yara-python"),
    ("malpedia",      "APT actors, malware families, reports, YARA from Malpedia"),
    ("ttp",           "TTP -> implementation map: browse ATT&CK techniques and compile"),
    ("pe",            "PE Anatomy Inspector -- sections, imports, entropy, threat score"),
    ("vtscan",        "Scan compiled binaries or files with VirusTotal (70+ AV/EDR)"),
    ("hellsgate",     "Hell's Gate -- SSN extraction, EDR hook detection, direct-syscall stub gen"),
    ("scemu",         "Shellcode Emulator -- x86/x64 Unicorn Engine, trace, API intercept, SMC"),
    ("antianalysis",  "Anti-Analysis Scanner -- detect anti-debug/anti-VM patterns, MITRE ATT&CK"),
    ("rop",           "ROP Chain Builder -- gadget finder, classifier, chain assembly, C/Python gen"),
    ("help",          "show this help"),
    ("exit",          "quit peekaboo-cli"),
]


def print_top_help(module: str | None = None) -> None:
    if module:
        show_help(module)
    else:
        show_help("_top")


# -- artifact map --------------------------------------------------------------

ART_PAGE_SIZE = PAGE_SIZE

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
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1))
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

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1),
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

    # -- header panel ---------------------------------------------------------
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
                        border_style="bright_cyan", box=box.ROUNDED))

    # -- top sigma rules -------------------------------------------------------
    top_rules = rules[:20]
    if top_rules:
        rt = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                   border_style="bright_black", padding=(0, 1),
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

    # -- registry keys ---------------------------------------------------------
    reg_keys = e.get("reg_keys", [])
    if reg_keys:
        rkt = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                    border_style="bright_black", padding=(0, 1), title="Registry Keys")
        rkt.add_column("key", style="warn")
        for k in reg_keys[:15]:
            rkt.add_row(k)
        if len(reg_keys) > 15:
            console.print(f"  [dim]... +{len(reg_keys)-15} more[/dim]")
        console.print(rkt)

    # -- processes -------------------------------------------------------------
    procs = e.get("processes", [])
    if procs:
        pt = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                   border_style="bright_black", padding=(0, 1), title="Process Images")
        pt.add_column("process", style="cmd")
        for p in procs[:12]:
            pt.add_row(p)
        if len(procs) > 12:
            console.print(f"  [dim]... +{len(procs)-12} more[/dim]")
        console.print(pt)

    # -- command line patterns -------------------------------------------------
    cmdlines = e.get("cmdlines", [])
    if cmdlines:
        ct = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                   border_style="bright_black", padding=(0, 1), title="Command Line Patterns")
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
        console.print(f"  [warn][=^..^=] no rules match level '{level_filter}'[/warn]\n")
        return

    rt = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
               border_style="bright_black", padding=(0, 1), title=title, show_lines=False)
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
        console.print(f"[err][=^..^=] db module unavailable: {e}[/err]")
        return

    with console.status("[info]loading artifact map...[/info]", spinner="dots"):
        all_entries = _db.get_artifact_entries()
        stats       = _db.get_artifact_stats()

    if not all_entries:
        console.print(
            "[warn][=^..^=] artifact map is empty -- "
            "open the dashboard and click Rebuild in the Artifact Map panel[/warn]"
        )
        return

    # build lookup structures
    tid_map: dict[str, dict] = {e["tid"]: e for e in all_entries}
    tactic_counts: Counter = Counter()
    for e in all_entries:
        for t in e["tactic"].split(","):
            t = t.strip()
            if t:
                tactic_counts[t] += 1
    all_tactics = sorted(tactic_counts.keys())
    all_tids    = sorted(tid_map.keys())

    session = _make_session(ARTIFACT_COMMANDS + all_tactics + all_tids)

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
        border_style="bright_cyan",
        box=box.ROUNDED,
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

        # -- back -------------------------------------------------------------
        if cmd in ("back", "exit", "quit"):
            break

        # -- help -------------------------------------------------------------
        elif cmd == "help":
            show_help("artifacts", args[0] if args else None)

        # -- stats -------------------------------------------------------------
        elif cmd == "stats":
            t = Table(box=box.ROUNDED, show_header=False, border_style="bright_black",
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

        # -- tactics ----------------------------------------------------------
        elif cmd == "tactics":
            max_n = max(tactic_counts.values())
            t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                      border_style="bright_black", padding=(0, 1), title="Tactics")
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

        # -- list [tactic] -----------------------------------------------------
        elif cmd == "list":
            if args:
                tac = args[0].lower()
                current_view = [
                    e for e in all_entries
                    if tac in e["tactic"].lower()
                ]
                if not current_view:
                    console.print(
                        f"[warn][=^..^=] no techniques for tactic '{tac}' "
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

        # -- search ------------------------------------------------------------
        elif cmd == "search":
            if not args:
                console.print("[warn][=^..^=] usage: search <query>[/warn]")
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
                console.print(f"  [warn][=^..^=] no results for '{q}'[/warn]\n")
                continue
            current_view  = hits
            current_title = f"Search: {q}"
            current_page  = 0
            total_pages   = _render_artifact_table(
                current_view, current_title, current_page
            )

        # -- show <T-ID> -------------------------------------------------------
        elif cmd == "show":
            if not args:
                console.print("[warn][=^..^=] usage: show <T-ID>  e.g.  show T1055[/warn]")
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
                        f"  [warn][=^..^=] ambiguous '{tid}': "
                        f"{', '.join(matches[:6])}"
                        f"{'...' if len(matches) > 6 else ''}[/warn]\n"
                    )
                    continue
                else:
                    console.print(f"  [err][=^..^=] T-ID not found: '{tid}'[/err]\n")
                    continue
            _render_artifact_detail(entry)

        # -- rules <T-ID> [level] ----------------------------------------------
        elif cmd == "rules":
            if not args:
                console.print(
                    "[warn][=^..^=] usage: rules <T-ID> [level]  "
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
                    console.print(f"  [err][=^..^=] T-ID not found: '{tid}'[/err]\n")
                    continue
            _render_all_rules(entry, level_filter)

        else:
            console.print(
                f"[warn][=^..^=] unknown command: {cmd}  "
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

LIB_PAGE_SIZE = PAGE_SIZE

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
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1))
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

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1),
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
                        border_style="bright_cyan", box=box.ROUNDED))

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
                                border_style="bright_black", box=box.ROUNDED))
    else:
        console.print(Panel(syn,
                            title=f"[heading] {Path(src_path).name if src_path else 'snippet'} "
                                  f"({lang}, {lines} lines) [/heading]",
                            border_style="bright_black", box=box.ROUNDED))
    console.print()


def run_library() -> None:
    """Interactive module library sub-REPL."""
    try:
        import db as _db
    except ImportError as e:
        console.print(f"[err][=^..^=] db module unavailable: {e}[/err]")
        return

    all_entries = _db.get_mitre_entries()
    if not all_entries:
        console.print("[warn][=^..^=] module library is empty - run the dashboard rebuild first[/warn]")
        return

    # build category -> entries map
    cat_counts: Counter = Counter(e["category"] for e in all_entries)
    all_cats = sorted(cat_counts.keys())

    # slug -> entry lookup
    slug_map = {e["slug"]: e for e in all_entries}

    session = _make_session(LIBRARY_COMMANDS + all_cats + list(slug_map.keys()))

    console.print()
    console.print(Panel(
        f"  {len(all_entries)} modules across {len(all_cats)} categories\n"
        f"  type  help  for commands,  cats  for category list,  back  to return",
        title="[heading] Module Library [/heading]",
        border_style="bright_cyan",
        box=box.ROUNDED,
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
            t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                      border_style="bright_black", padding=(0, 1), title="Categories")
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
                        f"[warn][=^..^=] no entries for category '{cat}' "
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
                console.print("[warn][=^..^=] usage: search <query>[/warn]")
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
                console.print(f"  [warn][=^..^=] no results for '{q}'[/warn]\n")
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
                console.print("[warn][=^..^=] usage: show <slug>[/warn]")
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
                        f"  [warn][=^..^=] ambiguous slug '{slug}', "
                        f"matches: {', '.join(matches[:5])}[/warn]\n"
                    )
                    continue
                else:
                    console.print(
                        f"  [err][=^..^=] slug not found: '{slug}'[/err]\n"
                    )
                    continue
            _render_module_detail(entry)

        else:
            console.print(
                f"[warn][=^..^=] unknown command: {cmd}  "
                f"(type  help  for commands)[/warn]"
            )


# -- evasion module ------------------------------------------------------------

def _load_evasion_module():
    try:
        import evasion as _ev
        return _ev
    except ImportError as e:
        console.print(f"[err][=^..^=] evasion module unavailable: {e}[/err]")
        return None


EVASION_COMMANDS = [
    "load", "load-build", "builds", "analyse", "patches", "patch", "apply", "info", "help", "back",
]

EVASION_HELP = [
    ("load <path>",                   "load a PE / binary file for analysis"),
    ("load-build <id> [filename]",    "load a compiled build binary directly (use  builds  to list)"),
    ("builds",                        "list successful builds with their compiled binaries"),
    ("analyse",                       "run evasion score analysis on loaded file"),
    ("patches",                       "list available patch transforms for loaded file"),
    ("patch <id> [id ...]",           "select patches to apply (space-separated IDs)"),
    ("apply [output]",                "apply selected patches and save patched binary"),
    ("info",                          "show loaded file metadata"),
    ("help",                          "show this help"),
    ("back",                          "return to main menu"),
]


def _evasion_help() -> None:
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1))
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
        box=box.ROUNDED,
    ))

    # -- category breakdown ----------------------------------------------------
    cats = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                 border_style="bright_black", padding=(0, 1), title="Score Breakdown")
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
        ft = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                   border_style="bright_black", padding=(0, 1), title="Findings",
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
        it = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                   border_style="bright_black", padding=(0, 1), title="Flagged Imports")
        it.add_column("API name",   style="err",  min_width=28)
        it.add_column("reason",     style="dim")
        for imp in si[:12]:
            it.add_row(imp["name"], imp["reason"])
        console.print(it)

    # -- sections --------------------------------------------------------------
    secs = result.get("sections", [])
    if secs:
        st = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                   border_style="bright_black", padding=(0, 1), title="PE Sections")
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
        console.print("[warn][=^..^=] no patches available for this binary[/warn]")
        return
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1), title="Available Patches")
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

    session = _make_session(EVASION_COMMANDS,
                           path_cmds=frozenset({"load", "apply"}))

    console.print()
    console.print(Panel(
        "  PE evasion scorer + surgical patch transforms\n"
        "  type  help  for commands,  back  to return",
        title="[heading] Evasion Lab [/heading]",
        border_style="bright_cyan",
        box=box.ROUNDED,
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
                console.print("[warn][=^..^=] usage: load <path>[/warn]")
                continue
            p = Path(" ".join(args)).expanduser().resolve()
            if not p.exists():
                console.print(f"[err][=^..^=] file not found: {p}[/err]")
                continue
            try:
                raw_data = p.read_bytes()
                loaded_path = p
                result   = None
                selected = set()
                console.print(
                    f"[ok][=^..^=] loaded:[/ok] [cmd]{p.name}[/cmd]  "
                    f"[dim]{len(raw_data)//1024} KB[/dim]"
                )
            except Exception as e:
                console.print(f"[err][=^..^=] read error: {e}[/err]")

        # -- builds ------------------------------------------------------------
        elif cmd == "builds":
            try:
                import db as _db2
            except ImportError:
                console.print("[err][=^..^=] db module unavailable[/err]")
                continue
            fresh = _db2.get_builds(limit=50)
            t = Table(box=box.ROUNDED, show_header=True,
                      header_style="bold bright_white on bright_black",
                      border_style="bright_black", padding=(0, 1))
            t.add_column("build-id", style="cmd",  no_wrap=True, min_width=14)
            t.add_column("type",     style="info",  min_width=10)
            t.add_column("module",   style="info",  min_width=18)
            t.add_column("date",     style="dim",   min_width=16)
            t.add_column("binaries", style="ok",    min_width=30)
            shown = 0
            for b in fresh:
                if b.get("status") != "success":
                    continue
                files = _vtscan_resolve_files(b)
                pa    = b.get("params", {})
                pa_slug = pa.get("slug")
                if pa_slug:
                    mod = pa_slug
                elif pa.get("malware") == "stealer":
                    mod = pa.get("stealer") or "?"
                else:
                    mod = pa.get("injection") or "?"
                mtype   = "module" if pa_slug else (pa.get("malware") or "-")
                bin_txt = "  ".join(n for n, _ in files) if files else "[dim]not on disk[/dim]"
                t.add_row(b["id"], mtype, mod, (b.get("created") or "")[:16], bin_txt)
                shown += 1
            if shown:
                console.print()
                console.print(t)
                console.print()
            else:
                console.print("  [dim]no successful builds found[/dim]\n")

        # -- load-build --------------------------------------------------------
        elif cmd == "load-build":
            if not args:
                console.print("[warn][=^..^=] usage: load-build <build-id> [filename][/warn]")
                continue
            try:
                import db as _db2
            except ImportError:
                console.print("[err][=^..^=] db module unavailable[/err]")
                continue
            build_id = args[0]
            want_fname = args[1] if len(args) > 1 else None
            build = _db2.get_build(build_id)
            if not build:
                console.print(f"  [err][=^..^=] build not found: {build_id}[/err]")
                continue
            if build.get("status") != "success":
                console.print(f"  [warn][=^..^=] build status is '{build.get('status')}', not success[/warn]")
                continue
            files = _vtscan_resolve_files(build)
            if not files:
                console.print(f"  [err][=^..^=] no binaries found on disk for build {build_id}[/err]")
                continue
            if want_fname:
                match = [(n, p) for n, p in files if n.lower() == want_fname.lower()]
                if not match:
                    avail = "  ".join(n for n, _ in files)
                    console.print(f"  [err][=^..^=] '{want_fname}' not found; available: {avail}[/err]")
                    continue
                chosen = match[0][1]
            elif len(files) > 1:
                console.print()
                for i, (n, fp2) in enumerate(files, 1):
                    console.print(f"  [{i}] [cmd]{n}[/cmd]  [dim]{fp2.stat().st_size:,} bytes[/dim]")
                console.print(f"\n  Use  [cmd]load-build {build_id} <filename>[/cmd]  to pick one.\n")
                continue
            else:
                chosen = files[0][1]
            try:
                raw_data    = chosen.read_bytes()
                loaded_path = chosen
                result      = None
                selected    = set()
                console.print(
                    f"[ok][=^..^=] loaded:[/ok] [cmd]{chosen.name}[/cmd]  "
                    f"[dim]{len(raw_data)//1024} KB  (build {build_id})[/dim]"
                )
            except Exception as e:
                console.print(f"[err][=^..^=] read error: {e}[/err]")

        # -- info --------------------------------------------------------------
        elif cmd == "info":
            if raw_data is None:
                console.print("[warn][=^..^=] no file loaded - use  load <path>[/warn]")
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
                console.print("[warn][=^..^=] no file loaded - use  load <path>[/warn]")
                continue
            with console.status("[info]analysing...[/info]", spinner="dots"):
                result = ev_mod.analyse(raw_data, loaded_path.name)
            # pre-select all available patches
            selected = {p["id"] for p in result.get("patches_available", [])}
            _render_evasion_results(result)

        # -- patches -----------------------------------------------------------
        elif cmd == "patches":
            if result is None:
                console.print("[warn][=^..^=] run  analyse  first[/warn]")
                continue
            _render_patches_table(result["patches_available"], selected)

        # -- patch (toggle) ----------------------------------------------------
        elif cmd == "patch":
            if result is None:
                console.print("[warn][=^..^=] run  analyse  first[/warn]")
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
                        toggled.append(f"[=^..^=] {pid}")
                    else:
                        selected.add(pid)
                        toggled.append(f"[=^..^=] {pid}")
                else:
                    unknown.append(pid)
            for t in toggled:
                style = "ok" if t.startswith("[=^..^=]") else "warn"
                console.print(f"  [{style}]{t}[/{style}]")
            for u in unknown:
                console.print(f"  [err][=^..^=] unknown patch id: {u}[/err]")
            console.print(
                f"\n  [dim]{len(selected)} patch(es) selected[/dim]\n"
            )

        # -- apply -------------------------------------------------------------
        elif cmd == "apply":
            if raw_data is None:
                console.print("[warn][=^..^=] no file loaded[/warn]")
                continue
            if result is None:
                console.print("[warn][=^..^=] run  analyse  first[/warn]")
                continue
            if not selected:
                console.print("[warn][=^..^=] no patches selected - use  patch <id>[/warn]")
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
                console.print("[warn][=^..^=] no patches were applied[/warn]")
                continue

            try:
                out_path.write_bytes(patched)
            except Exception as e:
                console.print(f"[err][=^..^=] write error: {e}[/err]")
                continue

            # applied summary table
            at = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                       border_style="bright_green", padding=(0, 1), title="Patches Applied")
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
                f"\n  [ok][=^..^=] saved:[/ok] [cmd]{out_path}[/cmd]  "
                f"[dim]{len(patched)//1024} KB  ({delta_str})[/dim]\n"
            )

        else:
            console.print(
                f"[warn][=^..^=] unknown command: {cmd}  "
                f"(type  help  for commands)[/warn]"
            )


# -- malpedia lab -------------------------------------------------------------

MALPEDIA_PAGE_SIZE = PAGE_SIZE

MALPEDIA_COMMANDS = [
    "status", "reports", "actors", "families", "actor", "family",
    "yara", "search", "refresh", "help", "back",
]

_MALPEDIA_BASE = "https://malpedia.caad.fkie.fraunhofer.de"


def _mp_abs_url(url: str) -> str:
    if url.startswith("http"):
        return url
    return _MALPEDIA_BASE + ("" if url.startswith("/") else "/") + url


def _render_reports(reports: list[dict]) -> None:
    if not reports:
        console.print("  [warn][=^..^=] no reports returned[/warn]\n")
        return

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1),
              title=f"Recent Threat Intel Reports  ({len(reports)})",
              show_lines=True)
    t.add_column("#",        style="dim",  min_width=3,  justify="right", no_wrap=True)
    t.add_column("date",     style="dim",  min_width=11, no_wrap=True)
    t.add_column("org",      style="info", min_width=14, no_wrap=True)
    t.add_column("title",    style="cmd",  min_width=44)
    t.add_column("families", style="warn", min_width=24)

    for i, r in enumerate(reports, 1):
        fams = " ".join(r.get("families", [])[:3])
        if len(r.get("families", [])) > 3:
            fams += f" +{len(r['families'])-3}"
        t.add_row(
            str(i),
            r.get("date", "")[:11],
            (r.get("org") or "")[:14],
            (r.get("title") or "")[:44],
            fams or "-",
        )

    console.print()
    console.print(t)

    # URL list (Markdown-style, clickable in modern terminals)
    console.print()
    console.print("  [heading]URLs[/heading]")
    for i, r in enumerate(reports, 1):
        url   = _mp_abs_url(r.get("url", ""))
        title = (r.get("title") or url)[:60]
        console.print(f"  [dim]{i:>2}.[/dim] [link={url}][cyan]{title}[/cyan][/link]")
        console.print(f"       [dim]{url}[/dim]")
    console.print()


def _render_actors_table(actors: list, title: str = "Threat Actors",
                          page: int = 0, rich_mode: bool = False) -> int:
    total = len(actors)
    pages = max(1, (total + MALPEDIA_PAGE_SIZE - 1) // MALPEDIA_PAGE_SIZE)
    start = page * MALPEDIA_PAGE_SIZE
    chunk = actors[start:start + MALPEDIA_PAGE_SIZE]

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1),
              title=f"{title}  [{start+1}-{min(start+len(chunk), total)} / {total}]",
              show_lines=False)
    t.add_column("#",           style="dim",  min_width=4,  justify="right", no_wrap=True)
    t.add_column("actor-id",    style="cmd",  min_width=22, no_wrap=True)
    if rich_mode:
        t.add_column("common name", style="info", min_width=22)
        t.add_column("synonyms",    style="dim",  min_width=30)

    for i, a in enumerate(chunk, start + 1):
        if isinstance(a, dict):
            row = [str(i), a.get("name", "?")]
            if rich_mode:
                row += [
                    a.get("common_name", "")[:22],
                    ", ".join(a.get("synonyms", [])[:3]),
                ]
            t.add_row(*row)
        else:
            row = [str(i), str(a)]
            if rich_mode:
                row += ["", ""]
            t.add_row(*row)

    console.print()
    console.print(t)
    if pages > 1:
        console.print(
            f"  [dim]page {page+1}/{pages} -- "
            f"press Enter for next page,  actor <id>  to drill in[/dim]\n"
        )
    return pages


def _render_families_table(families: list, title: str = "Malware Families",
                            page: int = 0) -> int:
    total = len(families)
    pages = max(1, (total + MALPEDIA_PAGE_SIZE - 1) // MALPEDIA_PAGE_SIZE)
    start = page * MALPEDIA_PAGE_SIZE
    chunk = families[start:start + MALPEDIA_PAGE_SIZE]

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1),
              title=f"{title}  [{start+1}-{min(start+len(chunk), total)} / {total}]",
              show_lines=False)
    t.add_column("#",          style="dim",  min_width=4,  justify="right", no_wrap=True)
    t.add_column("family-id",  style="cmd",  min_width=24, no_wrap=True)
    has_meta = isinstance(chunk[0] if chunk else None, dict)
    if has_meta:
        t.add_column("common name", style="info", min_width=22)
        t.add_column("alt names",   style="dim",  min_width=22)

    for i, f in enumerate(chunk, start + 1):
        if isinstance(f, dict):
            alts = ", ".join(f.get("alt_names", [])[:2])
            t.add_row(str(i), f.get("name", "?"),
                      f.get("common_name", "")[:22], alts[:22])
        else:
            row = [str(i), str(f)]
            if has_meta:
                row += ["", ""]
            t.add_row(*row)

    console.print()
    console.print(t)
    if pages > 1:
        console.print(
            f"  [dim]page {page+1}/{pages} -- "
            f"press Enter for next page,  family <id>  to drill in[/dim]\n"
        )
    return pages


def _render_actor_detail(a: dict) -> None:
    if "error" in a:
        console.print(f"  [err][=^..^=] {a['error']}[/err]\n")
        return

    synonyms = ", ".join(a.get("synonyms", [])[:6])
    if len(a.get("synonyms", [])) > 6:
        synonyms += f" +{len(a['synonyms'])-6}"
    targets = ", ".join(a.get("targets", [])[:4])
    victims = ", ".join(a.get("victims", [])[:4])
    if len(a.get("victims", [])) > 4:
        victims += f" +{len(a['victims'])-4}"

    meta = (
        f"  ID       : {a['id']}\n"
        f"  Name     : {a.get('name', a['id'])}\n"
        f"  Country  : {a.get('country') or '?'}\n"
        f"  Synonyms : {synonyms or '-'}\n"
        + (f"  Targets  : {targets}\n" if targets else "")
        + (f"  Victims  : {victims}\n" if victims else "")
        + (f"  Incident : {a['incident_type']}\n" if a.get("incident_type") else "")
    )
    console.print()
    console.print(Panel(meta.rstrip(),
                        title=f"[heading] Actor: {a.get('name', a['id'])} [/heading]",
                        border_style="bright_cyan", box=box.ROUNDED))

    desc = (a.get("description") or "").strip()
    if desc:
        n_lines = desc.count("\n") + (len(desc) // 80) + 1
        if n_lines > 12:
            with console.pager(styles=True):
                console.print(f"\n  [dim]{desc}[/dim]\n")
        else:
            console.print(f"\n  [dim]{desc[:600]}{'...' if len(desc)>600 else ''}[/dim]\n")

    fams = a.get("families", [])
    if fams:
        ft = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                   border_style="bright_black", padding=(0, 1),
                   title=f"Malware Families ({len(fams)})", show_lines=False)
        ft.add_column("family-id",   style="cmd",  min_width=24, no_wrap=True)
        ft.add_column("report URLs", style="dim",  min_width=4,  justify="right")
        for f in fams[:20]:
            ft.add_row(f["id"], str(len(f.get("urls", []))))
        if len(fams) > 20:
            console.print(f"  [dim]... +{len(fams)-20} more families[/dim]")
        console.print(ft)

    refs = a.get("refs", [])
    if refs:
        console.print()
        console.print("  [heading]References[/heading]")
        for i, ref in enumerate(refs[:10], 1):
            url = _mp_abs_url(ref) if ref else ""
            console.print(f"  [dim]{i:>2}.[/dim] [link={url}][cyan]{url[:80]}[/cyan][/link]")
    console.print()


def _render_family_detail(f: dict) -> None:
    if "error" in f:
        console.print(f"  [err][=^..^=] {f['error']}[/err]\n")
        return

    alts  = ", ".join(f.get("alt_names", [])[:6])
    attrs = ", ".join(f.get("attribution", [])[:6])
    if len(f.get("attribution", [])) > 6:
        attrs += f" +{len(f['attribution'])-6}"

    meta = (
        f"  ID          : {f['id']}\n"
        f"  Common name : {f.get('name', f['id'])}\n"
        f"  Alt names   : {alts or '-'}\n"
        f"  Updated     : {f.get('updated') or '?'}\n"
        + (f"  Attribution : {attrs}\n" if attrs else "")
    )
    console.print()
    console.print(Panel(meta.rstrip(),
                        title=f"[heading] Family: {f.get('name', f['id'])} [/heading]",
                        border_style="bright_cyan", box=box.ROUNDED))

    desc = (f.get("description") or "").strip()
    if desc:
        n_lines = (len(desc) // 80) + 1
        if n_lines > 12:
            with console.pager(styles=True):
                console.print(f"\n{desc}\n")
        else:
            console.print(f"\n  [dim]{desc[:800]}{'...' if len(desc)>800 else ''}[/dim]\n")

    urls = f.get("urls", [])
    if urls:
        console.print("  [heading]Reference URLs[/heading]")
        for i, url in enumerate(urls[:10], 1):
            abs_url = _mp_abs_url(url)
            console.print(f"  [dim]{i:>2}.[/dim] [link={abs_url}][cyan]{abs_url[:80]}[/cyan][/link]")
        if len(urls) > 10:
            console.print(f"  [dim]  ... +{len(urls)-10} more[/dim]")
    console.print()


def run_malpedia() -> None:
    """Interactive Malpedia sub-REPL."""
    try:
        import malpedia as _mp
    except ImportError as exc:
        console.print(f"[err][=^..^=] malpedia module unavailable: {exc}[/err]")
        return

    if not _mp.available():
        console.print(
            "  [err][=^..^=] malpediaclient not installed[/err]\n"
            "  [dim]Install with: pip install malpediaclient[/dim]\n"
        )
        return

    with console.status("[info]loading actor/family lists...[/info]", spinner="dots"):
        actor_list   = _mp.list_actors()
        family_list  = _mp.list_families()

    session = _make_session(MALPEDIA_COMMANDS + actor_list[:200] + family_list[:200])

    console.print()
    console.print(Panel(
        f"  {len(actor_list)} threat actors  |  {len(family_list)} malware families\n"
        f"  type  help  for commands,  reports  for latest threat intel,  back  to return",
        title="[heading] Malpedia [/heading]",
        border_style="bright_cyan",
        box=box.ROUNDED,
    ))
    console.print()

    current_view: list  = []
    current_title: str  = ""
    current_page: int   = 0
    total_pages: int    = 0
    view_mode: str      = ""   # "actors" or "families"
    view_rich: bool     = False

    while True:
        try:
            raw = session.prompt("peekaboo [malpedia] > ", style=PT_STYLE).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]use  back  to return[/dim]")
            continue

        if not raw:
            if total_pages > 1 and current_page + 1 < total_pages:
                current_page += 1
                if view_mode == "actors":
                    total_pages = _render_actors_table(
                        current_view, current_title, current_page, view_rich
                    )
                else:
                    total_pages = _render_families_table(
                        current_view, current_title, current_page
                    )
            continue

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        if cmd in ("back", "exit", "quit"):
            break

        elif cmd == "help":
            show_help("malpedia", args[0] if args else None)

        # -- status -----------------------------------------------------------
        elif cmd == "status":
            with console.status("[info]checking API...[/info]", spinner="dots"):
                st = _mp.get_status()
            if not st.get("ok"):
                console.print(f"  [err][=^..^=] {st.get('error')}[/err]\n")
                continue
            t = Table(box=box.ROUNDED, show_header=False, border_style="bright_black",
                      padding=(0, 2), title="Malpedia Status")
            t.add_column("key",   style="info",    min_width=20)
            t.add_column("value", style="heading", min_width=16)
            t.add_row("API Version",    str(st.get("version", "?")))
            t.add_row("Last Updated",   (st.get("date") or "?")[:19])
            t.add_row("Authenticated",  "[ok]yes[/ok]" if st.get("authenticated") else "[warn]no (public)[/warn]")
            t.add_row("Actors (cache)", str(len(actor_list)))
            t.add_row("Families (cache)", str(len(family_list)))
            t.add_row("Actors cached",  "[ok]yes[/ok]" if st.get("actors_cached") else "[warn]no[/warn]")
            t.add_row("Families cached","[ok]yes[/ok]" if st.get("families_cached") else "[warn]no[/warn]")
            console.print()
            console.print(t)
            console.print()

        # -- reports [N] ------------------------------------------------------
        elif cmd == "reports":
            limit = 20
            if args:
                try:
                    limit = max(1, min(int(args[0]), 100))
                except ValueError:
                    console.print("[warn][=^..^=] usage: reports [N][/warn]")
                    continue
            with console.status(
                f"[info]fetching {limit} recent reports...[/info]", spinner="dots"
            ):
                reports = _mp.get_recent_reports(limit)
            _render_reports(reports)

        # -- actors [query] ---------------------------------------------------
        elif cmd == "actors":
            if args:
                q = " ".join(args)
                with console.status(f"[info]searching actors: {q}...[/info]", spinner="dots"):
                    hits = _mp.find_actor(q)
                if not hits:
                    console.print(f"  [warn][=^..^=] no actors found for '{q}'[/warn]\n")
                    continue
                current_view  = hits
                current_title = f"Actor search: {q}"
                view_rich     = True
            else:
                current_view  = actor_list
                current_title = "Threat Actors"
                view_rich     = False
            current_page = 0
            view_mode    = "actors"
            total_pages  = _render_actors_table(
                current_view, current_title, current_page, view_rich
            )

        # -- families [query] -------------------------------------------------
        elif cmd == "families":
            if args:
                q = " ".join(args)
                with console.status(f"[info]searching families: {q}...[/info]", spinner="dots"):
                    hits = _mp.find_family(q)
                if not hits:
                    console.print(f"  [warn][=^..^=] no families found for '{q}'[/warn]\n")
                    continue
                current_view  = hits
                current_title = f"Family search: {q}"
            else:
                current_view  = family_list
                current_title = "Malware Families"
            current_page = 0
            view_mode    = "families"
            total_pages  = _render_families_table(
                current_view, current_title, current_page
            )

        # -- actor <id> -------------------------------------------------------
        elif cmd == "actor":
            if not args:
                console.print("[warn][=^..^=] usage: actor <id>  e.g.  actor lazarus_group[/warn]")
                continue
            aid = "_".join(args).lower()
            # try partial match in cached list
            if aid not in actor_list:
                matches = [a for a in actor_list if aid in a]
                if len(matches) == 1:
                    aid = matches[0]
                elif len(matches) > 1:
                    console.print(
                        f"  [warn][=^..^=] ambiguous '{aid}': "
                        f"{', '.join(matches[:5])}"
                        f"{'...' if len(matches)>5 else ''}[/warn]\n"
                    )
                    continue
                elif not matches:
                    console.print(f"  [err][=^..^=] actor not found: '{aid}'[/err]\n")
                    continue
            with console.status(f"[info]loading actor: {aid}...[/info]", spinner="dots"):
                detail = _mp.get_actor(aid)
            _render_actor_detail(detail)

        # -- family <id> ------------------------------------------------------
        elif cmd == "family":
            if not args:
                console.print("[warn][=^..^=] usage: family <id>  e.g.  family win.cobalt_strike[/warn]")
                continue
            fid = args[0].lower()
            if fid not in family_list:
                matches = [f for f in family_list if fid in f]
                if len(matches) == 1:
                    fid = matches[0]
                elif len(matches) > 1:
                    console.print(
                        f"  [warn][=^..^=] ambiguous '{fid}': "
                        f"{', '.join(matches[:5])}"
                        f"{'...' if len(matches)>5 else ''}[/warn]\n"
                    )
                    continue
                elif not matches:
                    console.print(f"  [err][=^..^=] family not found: '{fid}'[/err]\n")
                    continue
            with console.status(f"[info]loading family: {fid}...[/info]", spinner="dots"):
                detail = _mp.get_family(fid)
            _render_family_detail(detail)

        # -- yara <family-id> [save <path>] -----------------------------------
        elif cmd == "yara":
            if not args:
                console.print("[warn][=^..^=] usage: yara <family-id> [save <path>][/warn]")
                continue
            fid      = args[0].lower()
            save_arg = None
            if len(args) >= 3 and args[1].lower() == "save":
                save_arg = Path(" ".join(args[2:])).expanduser().resolve()

            try:
                c = _mp._get_client()
                if not c:
                    console.print("  [err][=^..^=] malpedia client unavailable[/err]\n")
                    continue
                with console.status(
                    f"[info]fetching YARA rules for {fid}...[/info]", spinner="dots"
                ):
                    raw = c.get_yara(fid)
            except Exception as exc:
                console.print(f"  [err][=^..^=] API error: {exc}[/err]\n")
                continue

            if not raw or not isinstance(raw, dict):
                console.print(f"  [warn][=^..^=] no YARA rules found for '{fid}'[/warn]\n")
                continue

            # raw = {tlp_level: {rule_name: rule_text, ...}, ...}
            all_rules: list[tuple[str, str, str]] = []
            for tlp, rules in raw.items():
                if isinstance(rules, dict):
                    for rname, rtext in rules.items():
                        all_rules.append((tlp, rname, rtext))

            if not all_rules:
                console.print(f"  [warn][=^..^=] no public rules for '{fid}'[/warn]\n")
                continue

            combined = "\n\n".join(f"// {tlp} / {rname}\n{rtext}"
                                   for tlp, rname, rtext in all_rules)
            n_lines  = combined.count("\n") + 1

            try:
                syn = Syntax(combined, "yara", theme="monokai",
                             line_numbers=True, word_wrap=False)
            except Exception:
                syn = Syntax(combined, "text", theme="monokai",
                             line_numbers=True, word_wrap=False)

            panel = Panel(
                syn,
                title=f"[heading] YARA: {fid}  ({len(all_rules)} rule(s)) [/heading]",
                border_style="bright_black", box=box.ROUNDED,
            )
            if n_lines > 40:
                with console.pager(styles=True):
                    console.print(panel)
            else:
                console.print()
                console.print(panel)
                console.print()

            if save_arg:
                try:
                    save_arg.write_text(combined, encoding="utf-8")
                    console.print(
                        f"  [ok][=^..^=] saved:[/ok] [cmd]{save_arg}[/cmd]  "
                        f"[dim]{len(combined)} chars[/dim]\n"
                    )
                except Exception as exc:
                    console.print(f"  [err][=^..^=] write error: {exc}[/err]\n")

        # -- search <query> ---------------------------------------------------
        elif cmd == "search":
            if not args:
                console.print("[warn][=^..^=] usage: search <query>[/warn]")
                continue
            q = " ".join(args)
            with console.status(f"[info]searching '{q}'...[/info]", spinner="dots"):
                actor_hits  = _mp.find_actor(q)
                family_hits = _mp.find_family(q)

            console.print()
            if actor_hits:
                _render_actors_table(
                    actor_hits, f"Actor matches: {q}", 0, rich_mode=True
                )
            else:
                console.print(f"  [dim]no actor matches for '{q}'[/dim]")

            if family_hits:
                _render_families_table(
                    family_hits, f"Family matches: {q}", 0
                )
            else:
                console.print(f"  [dim]no family matches for '{q}'[/dim]")

            if not actor_hits and not family_hits:
                console.print(f"\n  [warn][=^..^=] no results for '{q}'[/warn]\n")

        # -- refresh ----------------------------------------------------------
        elif cmd == "refresh":
            with console.status("[info]refreshing caches...[/info]", spinner="dots"):
                actor_list  = _mp.list_actors(force_refresh=True)
                family_list = _mp.list_families(force_refresh=True)
            console.print(
                f"  [ok][=^..^=] refreshed:[/ok] "
                f"[dim]{len(actor_list)} actors, {len(family_list)} families[/dim]\n"
            )

        else:
            console.print(
                f"[warn][=^..^=] unknown command: {cmd}  "
                f"(type  help  for commands)[/warn]"
            )


# -- yara lab ------------------------------------------------------------------

YARA_COMMANDS = ["gen", "gen-build", "builds", "show", "save", "info", "scan", "help", "back"]


def _render_yara_meta(result: dict) -> None:
    ent_col = "ok"
    hi = result.get("high_entropy_count", 0)
    if hi:
        ent_col = "err" if hi > 2 else "warn"

    meta = (
        f"  File      : {result.get('_filepath','?')}\n"
        f"  Rule name : {result['rule_name']}\n"
        f"  Size      : {result['size']:,} bytes\n"
        f"  MD5       : [dim]{result['md5']}[/dim]\n"
        f"  SHA256    : [dim]{result['sha256']}[/dim]\n"
        f"  Strings   : {result['string_count']} indicators extracted\n"
        f"  PE        : {'yes' if result['has_pe'] else 'no (non-PE / raw)'}\n"
        + (f"  Imphash   : [dim]{result['pe_imphash']}[/dim]\n"
           if result.get("pe_imphash") else "")
        + (f"  Hi-ent sec: [{ent_col}]{hi}[/{ent_col}]"
           if result["has_pe"] else "")
    )
    console.print()
    console.print(Panel(meta.rstrip(),
                        title="[heading] YARA Rule Info [/heading]",
                        border_style="bright_cyan", box=box.ROUNDED))

    secs = result.get("pe_sections", [])
    if secs:
        t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                  border_style="bright_black", padding=(0, 1), title="PE Sections")
        t.add_column("name",    style="cmd",  min_width=10)
        t.add_column("entropy", min_width=7,  justify="right")
        t.add_column("size",    style="dim",  min_width=10, justify="right")
        t.add_column("bar",                   min_width=24)
        for s in secs:
            ent = s["entropy"]
            w   = int(min(ent, 8.0) / 8.0 * 22)
            bar = Text("[" + "#" * w + "." * (22 - w) + "]",
                       style="err" if ent > 7.2 else "warn" if ent > 6.5 else "ok")
            ent_s = Text(f"{ent:.2f}",
                         style="err" if ent > 7.2 else "warn" if ent > 6.5 else "dim")
            t.add_row(s["name"], ent_s, f"{s['size']:,}", bar)
        console.print(t)
    console.print()


def _render_yara_rule(rule_text: str) -> None:
    n_lines = rule_text.count("\n") + 1
    try:
        syn = Syntax(rule_text, "yara", theme="monokai",
                     line_numbers=True, word_wrap=False)
    except Exception:
        syn = Syntax(rule_text, "text", theme="monokai",
                     line_numbers=True, word_wrap=False)

    panel = Panel(syn, title="[heading] YARA Rule [/heading]",
                  border_style="bright_black", box=box.ROUNDED)
    if n_lines > 40:
        with console.pager(styles=True):
            console.print(panel)
    else:
        console.print()
        console.print(panel)
        console.print()


def run_yara() -> None:
    """Interactive YARA lab sub-REPL."""
    try:
        import yaragen as _yg
    except ImportError as exc:
        console.print(f"[err][=^..^=] yaragen module unavailable: {exc}[/err]")
        return

    yr_result: dict | None = None

    session = _make_session(YARA_COMMANDS,
                           path_cmds=frozenset({"gen", "scan", "save", "load"}))

    console.print()
    console.print(Panel(
        "  Generate YARA detection rules from PE or raw binary files\n"
        "  type  help  for commands,  back  to return",
        title="[heading] YARA Lab [/heading]",
        border_style="bright_cyan",
        box=box.ROUNDED,
    ))
    console.print()

    while True:
        hint = f" ({yr_result['rule_name']})" if yr_result else ""
        try:
            raw = session.prompt(
                f"peekaboo [yara{hint}] > ",
                style=PT_STYLE,
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]use  back  to return[/dim]")
            continue

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        # -- back -------------------------------------------------------------
        if cmd in ("back", "exit", "quit"):
            break

        # -- help -------------------------------------------------------------
        elif cmd == "help":
            show_help("yara", args[0] if args else None)

        # -- gen <path> -------------------------------------------------------
        elif cmd == "gen":
            if not args:
                console.print("[warn][=^..^=] usage: gen <path>[/warn]")
                continue
            p = Path(" ".join(args)).expanduser().resolve()
            if not p.exists():
                console.print(f"[err][=^..^=] file not found: {p}[/err]")
                continue

            with console.status(
                f"[info]generating YARA rule for {p.name}...[/info]",
                spinner="dots"
            ):
                result = _yg.generate_rule(p)

            if not result.get("ok"):
                console.print(f"  [err][=^..^=] {result.get('error','failed')}[/err]\n")
                continue

            result["_filepath"] = str(p)
            yr_result = result

            _render_yara_meta(yr_result)
            _render_yara_rule(yr_result["rule"])
            console.print(
                f"  [dim]use  save <path>  to write the rule to a file\n"
                f"  use  scan <path>  to test it against another binary[/dim]\n"
            )

        # -- builds -----------------------------------------------------------
        elif cmd == "builds":
            try:
                import db as _db_yr
            except ImportError:
                console.print("[err][=^..^=] db module unavailable[/err]")
                continue
            fresh = _db_yr.get_builds(limit=50)
            t = Table(box=box.ROUNDED, show_header=True,
                      header_style="bold bright_white on bright_black",
                      border_style="bright_black", padding=(0, 1))
            t.add_column("build-id", style="cmd",  no_wrap=True, min_width=14)
            t.add_column("type",     style="info",  min_width=10)
            t.add_column("module",   style="info",  min_width=18)
            t.add_column("date",     style="dim",   min_width=16)
            t.add_column("binaries", style="ok",    min_width=30)
            shown = 0
            for b in fresh:
                if b.get("status") != "success":
                    continue
                files = _vtscan_resolve_files(b)
                pa    = b.get("params", {})
                pa_slug = pa.get("slug")
                if pa_slug:
                    mod = pa_slug
                elif pa.get("malware") == "stealer":
                    mod = pa.get("stealer") or "?"
                else:
                    mod = pa.get("injection") or "?"
                mtype   = "module" if pa_slug else (pa.get("malware") or "-")
                bin_txt = "  ".join(n for n, _ in files) if files else "[dim]not on disk[/dim]"
                t.add_row(b["id"], mtype, mod, (b.get("created") or "")[:16], bin_txt)
                shown += 1
            if shown:
                console.print()
                console.print(t)
                console.print()
            else:
                console.print("  [dim]no successful builds found[/dim]\n")

        # -- gen-build --------------------------------------------------------
        elif cmd == "gen-build":
            if not args:
                console.print("[warn][=^..^=] usage: gen-build <build-id> [filename][/warn]")
                continue
            try:
                import db as _db_yr
            except ImportError:
                console.print("[err][=^..^=] db module unavailable[/err]")
                continue
            build_id   = args[0]
            want_fname = args[1] if len(args) > 1 else None
            build = _db_yr.get_build(build_id)
            if not build:
                console.print(f"  [err][=^..^=] build not found: {build_id}[/err]")
                continue
            if build.get("status") != "success":
                console.print(f"  [warn][=^..^=] build status is '{build.get('status')}', not success[/warn]")
                continue
            files = _vtscan_resolve_files(build)
            if not files:
                console.print(f"  [err][=^..^=] no binaries found on disk for build {build_id}[/err]")
                continue
            if want_fname:
                match = [(n, p) for n, p in files if n.lower() == want_fname.lower()]
                if not match:
                    avail = "  ".join(n for n, _ in files)
                    console.print(f"  [err][=^..^=] '{want_fname}' not found; available: {avail}[/err]")
                    continue
                chosen = match[0][1]
            elif len(files) > 1:
                console.print()
                for i, (n, fp2) in enumerate(files, 1):
                    console.print(f"  [{i}] [cmd]{n}[/cmd]  [dim]{fp2.stat().st_size:,} bytes[/dim]")
                console.print(f"\n  Use  [cmd]gen-build {build_id} <filename>[/cmd]  to pick one.\n")
                continue
            else:
                chosen = files[0][1]

            with console.status(
                f"[info]generating YARA rule for {chosen.name}  (build {build_id})...[/info]",
                spinner="dots"
            ):
                result = _yg.generate_rule(chosen)

            if not result.get("ok"):
                console.print(f"  [err][=^..^=] {result.get('error','failed')}[/err]\n")
                continue

            result["_filepath"] = str(chosen)
            yr_result = result

            _render_yara_meta(yr_result)
            _render_yara_rule(yr_result["rule"])
            console.print(
                f"  [dim]use  save <path>  to write the rule to a file\n"
                f"  use  scan <path>  to test it against another binary[/dim]\n"
            )

        # -- show -------------------------------------------------------------
        elif cmd == "show":
            if yr_result is None:
                console.print("[warn][=^..^=] no rule generated yet -- use  gen <path>[/warn]")
                continue
            _render_yara_rule(yr_result["rule"])

        # -- info -------------------------------------------------------------
        elif cmd == "info":
            if yr_result is None:
                console.print("[warn][=^..^=] no rule generated yet -- use  gen <path>[/warn]")
                continue
            _render_yara_meta(yr_result)

        # -- save <path> ------------------------------------------------------
        elif cmd == "save":
            if yr_result is None:
                console.print("[warn][=^..^=] no rule generated yet -- use  gen <path>[/warn]")
                continue
            if not args:
                console.print("[warn][=^..^=] usage: save <path>[/warn]")
                continue
            out_p = Path(" ".join(args)).expanduser().resolve()
            try:
                out_p.write_text(yr_result["rule"], encoding="utf-8")
                console.print(
                    f"  [ok][=^..^=] saved:[/ok] [cmd]{out_p}[/cmd]  "
                    f"[dim]{len(yr_result['rule'])} chars[/dim]\n"
                )
            except Exception as exc:
                console.print(f"  [err][=^..^=] write error: {exc}[/err]\n")

        # -- scan <path> ------------------------------------------------------
        elif cmd == "scan":
            if yr_result is None:
                console.print("[warn][=^..^=] no rule generated yet -- use  gen <path>[/warn]")
                continue
            if not args:
                console.print("[warn][=^..^=] usage: scan <path>[/warn]")
                continue
            target = Path(" ".join(args)).expanduser().resolve()
            if not target.exists():
                console.print(f"[err][=^..^=] file not found: {target}[/err]")
                continue

            try:
                import yara as _yara
            except ImportError:
                console.print(
                    "  [err][=^..^=] yara-python not installed[/err]\n"
                    "  [dim]Install with: pip install yara-python[/dim]\n"
                )
                continue

            try:
                with console.status("[info]compiling rule...[/info]", spinner="dots"):
                    compiled = _yara.compile(source=yr_result["rule"])
                with console.status(
                    f"[info]scanning {target.name}...[/info]", spinner="dots"
                ):
                    matches = compiled.match(str(target))
            except Exception as exc:
                console.print(f"  [err][=^..^=] yara error: {exc}[/err]\n")
                continue

            if matches:
                console.print()
                console.print(Panel(
                    f"  Target    : {target}\n"
                    f"  Rule      : {yr_result['rule_name']}\n"
                    f"  Matches   : {len(matches)}",
                    title="[ok] MATCH [/ok]",
                    border_style="bright_green", box=box.ROUNDED,
                ))
                for m in matches:
                    mt = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                               border_style="bright_black", padding=(0, 1),
                               title=f"Matched Strings: {m.rule}")
                    mt.add_column("variable", style="warn", min_width=10, no_wrap=True)
                    mt.add_column("offset",   style="dim",  min_width=10, justify="right")
                    mt.add_column("data",     style="cmd",  min_width=30)
                    for s in m.strings:
                        offset   = s.instances[0].offset if s.instances else 0
                        raw_data = s.instances[0].matched_data if s.instances else b""
                        try:
                            preview = raw_data.decode("ascii", errors="replace")[:40]
                        except Exception:
                            preview = raw_data.hex()[:40]
                        mt.add_row(s.identifier, f"0x{offset:08x}", preview)
                    console.print(mt)
                console.print()
            else:
                console.print()
                console.print(Panel(
                    f"  Target : {target}\n"
                    f"  Rule   : {yr_result['rule_name']}\n"
                    f"  Result : no matches",
                    title="[warn] NO MATCH [/warn]",
                    border_style="yellow", box=box.ROUNDED,
                ))
                console.print()

        else:
            console.print(
                f"[warn][=^..^=] unknown command: {cmd}  "
                f"(type  help  for commands)[/warn]"
            )


# -- shellcode lab -------------------------------------------------------------

SHELLCODE_COMMANDS = [
    "load", "paste", "analyse", "format", "transform", "varname",
    "generate", "formats", "transforms", "save", "export", "help", "back",
]

_SC_FORMAT_INFO = [
    ("c",          "C unsigned char array"),
    ("c_str",      "C \\x string literal"),
    ("python",     "Python bytes"),
    ("powershell", "PowerShell [Byte[]]"),
    ("csharp",     "C# byte[]"),
    ("vba",        "VBA function"),
    ("rust",       "Rust &[u8]"),
    ("base64",     "Base64 string"),
    ("hex_0x",     "0x-prefixed hex"),
    ("hex_raw",    "raw hex string"),
    ("escaped",    "\\x escaped hex"),
]

_SC_TRANSFORM_INFO = [
    ("none",             "no transform (pass-through)"),
    ("xor_random",       "XOR with random 4-byte key (new key each generate)"),
    ("xor_key",          "XOR with specified key -- usage: transform xor_key 0x41"),
    ("base64_encode",    "encode to Base64"),
    ("base64_decode",    "decode from Base64"),
    ("zlib_compress",    "zlib compress at level 9"),
    ("zlib_decompress",  "zlib decompress"),
]

_SC_FORMAT_LANG = {
    "c": "c", "c_str": "c", "python": "python", "powershell": "powershell",
    "csharp": "csharp", "vba": "vbnet", "rust": "rust",
    "base64": "text", "hex_0x": "text", "hex_raw": "text", "escaped": "text",
}


def _render_sc_analysis(stats: dict, label: str = "Shellcode Analysis") -> None:
    entropy = stats["entropy"]
    ent_w   = int(min(entropy, 8.0) / 8.0 * 28)
    ent_bar = "[" + "#" * ent_w + "." * (28 - ent_w) + "]"
    ent_style = ("err" if entropy > 7.2 else
                 "warn" if entropy > 6.5 else
                 "medium" if entropy > 3.5 else "ok")

    size_kb = stats["size"] / 1024
    detected = stats.get("detected") or stats.get("detected_fmt") or "unknown"

    meta = (
        f"  Size     : {stats['size']:,} bytes  ({size_kb:.1f} KB)\n"
        f"  Entropy  : [{ent_style}]{entropy}  {ent_bar}[/{ent_style}]\n"
        f"  Arch     : {stats.get('arch','?')}\n"
        f"  Detected : {detected}\n"
        f"  Null     : {stats['null_bytes']} bytes  ({stats['null_pct']}%)\n"
        f"  MD5      : [dim]{stats['md5']}[/dim]\n"
        f"  SHA256   : [dim]{stats['sha256']}[/dim]"
    )
    console.print()
    console.print(Panel(meta, title=f"[heading] {label} [/heading]",
                        border_style="bright_cyan", box=box.ROUNDED))

    top = stats.get("top_bytes", [])
    if top:
        t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                  border_style="bright_black", padding=(0, 1),
                  title="Byte Distribution (top 6)")
        t.add_column("byte",  style="warn", min_width=6,  no_wrap=True)
        t.add_column("count", style="info", min_width=6,  justify="right", no_wrap=True)
        t.add_column("pct",   style="dim",  min_width=6,  justify="right", no_wrap=True)
        t.add_column("bar",                 min_width=28)
        max_pct = max(e["pct"] for e in top) or 1.0
        for e in top:
            w   = int(e["pct"] / max_pct * 26)
            bar = Text("[" + "#" * w + "." * (26 - w) + "]", style="cyan")
            t.add_row(e["byte"], str(e["count"]), f"{e['pct']}%", bar)
        console.print(t)
    console.print()


def _sc_settings_line(fmt: str, xform: str, xkey: str, vname: str) -> str:
    key_hint = f"  key={xkey}" if xkey and xform.startswith("xor_key") else ""
    return (
        f"  format=[cmd]{fmt}[/cmd]  "
        f"transform=[warn]{xform}[/warn]{key_hint}  "
        f"varname=[info]{vname}[/info]"
    )


def run_shellcode() -> None:
    """Interactive shellcode lab sub-REPL."""
    try:
        import shellcode as _sc
    except ImportError as exc:
        console.print(f"[err][=^..^=] shellcode module unavailable: {exc}[/err]")
        return

    sc_raw:   bytes | None = None   # raw loaded bytes
    sc_fmt    = "c"
    sc_xform  = "none"
    sc_xkey   = ""
    sc_vname  = "buf"
    sc_label  = None                # filename or "(pasted)"

    all_fmt_ids   = [f[0] for f in _SC_FORMAT_INFO]
    all_xform_ids = [f[0] for f in _SC_TRANSFORM_INFO]

    session = _make_session(SHELLCODE_COMMANDS + all_fmt_ids + all_xform_ids,
                           path_cmds=frozenset({"load", "save"}))

    console.print()
    console.print(Panel(
        "  Parse, analyse, transform and reformat shellcode\n"
        "  type  help  for commands,  formats / transforms  for ID lists,  back  to return",
        title="[heading] Shellcode Lab [/heading]",
        border_style="bright_cyan",
        box=box.ROUNDED,
    ))
    console.print()

    while True:
        hint = f" ({sc_label})" if sc_label else ""
        try:
            raw = session.prompt(
                f"peekaboo [shellcode{hint}] > ",
                style=PT_STYLE,
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]use  back  to return[/dim]")
            continue

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        # -- back -------------------------------------------------------------
        if cmd in ("back", "exit", "quit"):
            break

        # -- help -------------------------------------------------------------
        elif cmd == "help":
            show_help("shellcode", args[0] if args else None)

        # -- load <path> ------------------------------------------------------
        elif cmd == "load":
            if not args:
                console.print("[warn][=^..^=] usage: load <path>[/warn]")
                continue
            p = Path(" ".join(args)).expanduser().resolve()
            if not p.exists():
                console.print(f"[err][=^..^=] file not found: {p}[/err]")
                continue
            try:
                sc_raw   = p.read_bytes()
                sc_label = p.name
                console.print(
                    f"  [ok][=^..^=] loaded:[/ok] [cmd]{p.name}[/cmd]  "
                    f"[dim]{len(sc_raw):,} bytes[/dim]"
                )
                console.print(
                    f"  [dim]run  analyse  to inspect, or  generate  to format[/dim]\n"
                )
            except Exception as exc:
                console.print(f"[err][=^..^=] read error: {exc}[/err]")

        # -- paste ------------------------------------------------------------
        elif cmd == "paste":
            console.print(
                "  [info]Paste shellcode in any format.[/info]\n"
                "  [dim]Accepted: \\x90\\x90  0x90,0x90  90 90  9090  base64  b\"\\x90\"[/dim]\n"
                "  [dim]Press Enter on an empty line to finish.[/dim]\n"
            )
            lines: list[str] = []
            while True:
                try:
                    line = session.prompt("  paste> ", style=PT_STYLE)
                except (KeyboardInterrupt, EOFError):
                    break
                if not line.strip():
                    break
                lines.append(line)
            raw_text = "\n".join(lines).strip()
            if not raw_text:
                console.print("  [warn][=^..^=] no input received[/warn]\n")
                continue
            try:
                sc_raw, detected = _sc.parse_input(raw_text)
                sc_label = "pasted"
                console.print(
                    f"  [ok][=^..^=] {len(sc_raw):,} bytes loaded[/ok]  "
                    f"[dim]detected as: {detected}[/dim]\n"
                )
            except ValueError as exc:
                console.print(f"  [err][=^..^=] parse error: {exc}[/err]\n")

        # -- analyse ----------------------------------------------------------
        elif cmd == "analyse":
            if sc_raw is None:
                console.print("[warn][=^..^=] no shellcode loaded -- use  load  or  paste[/warn]")
                continue
            stats = _sc.analyse(sc_raw)
            _render_sc_analysis(stats, sc_label or "Analysis")

        # -- formats ----------------------------------------------------------
        elif cmd == "formats":
            t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                      border_style="bright_black", padding=(0, 1), title="Output Formats")
            t.add_column("id",          style="cmd",  min_width=12, no_wrap=True)
            t.add_column("description", style="info")
            for fid, desc in _SC_FORMAT_INFO:
                marker = Text("*", style="ok") if fid == sc_fmt else Text(" ", style="dim")
                t.add_column("", min_width=1, no_wrap=True) if False else None
                t.add_row(fid, desc)
            console.print()
            console.print(t)
            console.print(
                f"  [dim]current: [cmd]{sc_fmt}[/cmd]  "
                f"-- use  format <id>  to change[/dim]\n"
            )

        # -- transforms -------------------------------------------------------
        elif cmd == "transforms":
            t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                      border_style="bright_black", padding=(0, 1), title="Transforms")
            t.add_column("id",          style="warn", min_width=18, no_wrap=True)
            t.add_column("description", style="info")
            for xid, desc in _SC_TRANSFORM_INFO:
                t.add_row(xid, desc)
            console.print()
            console.print(t)
            console.print(
                f"  [dim]current: [warn]{sc_xform}[/warn]"
                + (f"  key={sc_xkey}" if sc_xkey else "")
                + "  -- use  transform <id> [key]  to change[/dim]\n"
            )

        # -- format <id> ------------------------------------------------------
        elif cmd == "format":
            if not args:
                console.print(
                    f"  [info]current format: [cmd]{sc_fmt}[/cmd][/info]\n"
                    f"  [dim]usage: format <id>  -- type  formats  for IDs[/dim]\n"
                )
                continue
            fid = args[0].lower()
            if fid not in all_fmt_ids:
                console.print(
                    f"  [err][=^..^=] unknown format '{fid}'[/err]\n"
                    f"  [dim]valid: {' '.join(all_fmt_ids)}[/dim]\n"
                )
                continue
            sc_fmt = fid
            console.print(f"  [ok][=^..^=] format set to: [cmd]{sc_fmt}[/cmd][/ok]\n")

        # -- transform <id> [key] ---------------------------------------------
        elif cmd == "transform":
            if not args:
                console.print(
                    f"  [info]current transform: [warn]{sc_xform}[/warn][/info]\n"
                    f"  [dim]usage: transform <id> [key]  -- type  transforms  for IDs[/dim]\n"
                )
                continue
            xid = args[0].lower()
            if xid not in all_xform_ids:
                console.print(
                    f"  [err][=^..^=] unknown transform '{xid}'[/err]\n"
                    f"  [dim]valid: {' '.join(all_xform_ids)}[/dim]\n"
                )
                continue
            sc_xform = xid
            sc_xkey  = " ".join(args[1:]) if len(args) > 1 else ""
            if sc_xform == "xor_key" and not sc_xkey:
                console.print(
                    "  [warn][=^..^=] xor_key requires a key argument\n"
                    "  example: transform xor_key 0x41\n"
                    "           transform xor_key 0xde,0xad,0xbe,0xef\n"
                    "           transform xor_key deadbeef[/warn]\n"
                )
                sc_xform = "none"
                continue
            msg = f"  [ok][=^..^=] transform set to: [warn]{sc_xform}[/warn]"
            if sc_xkey:
                msg += f"  [dim]key={sc_xkey}[/dim]"
            console.print(msg + "[/ok]\n")

        # -- varname <name> ---------------------------------------------------
        elif cmd == "varname":
            if not args:
                console.print(
                    f"  [info]current varname: [info]{sc_vname}[/info][/info]\n"
                    f"  [dim]usage: varname <name>[/dim]\n"
                )
                continue
            sc_vname = args[0]
            console.print(f"  [ok][=^..^=] variable name set to: [info]{sc_vname}[/info][/ok]\n")

        # -- generate [format] ------------------------------------------------
        elif cmd == "generate":
            if sc_raw is None:
                console.print("[warn][=^..^=] no shellcode loaded -- use  load  or  paste[/warn]")
                continue
            run_fmt = args[0].lower() if args else sc_fmt
            if run_fmt not in all_fmt_ids:
                console.print(
                    f"  [err][=^..^=] unknown format '{run_fmt}'[/err]\n"
                    f"  [dim]valid: {' '.join(all_fmt_ids)}[/dim]\n"
                )
                continue

            raw_text = " ".join(f"0x{b:02x}" for b in sc_raw)

            with console.status("[info]processing...[/info]", spinner="dots"):
                result = _sc.process(
                    raw_text,
                    output_format=run_fmt,
                    transform=sc_xform,
                    xor_key_str=sc_xkey,
                    var_name=sc_vname,
                )

            if not result.get("ok"):
                console.print(f"  [err][=^..^=] {result.get('error','unknown error')}[/err]\n")
                continue

            # settings summary
            console.print()
            console.print(_sc_settings_line(run_fmt, sc_xform, sc_xkey, sc_vname))
            in_s  = result["input_stats"]
            out_s = result["output_stats"]
            console.print(
                f"  [dim]input: {in_s['size']:,} bytes  entropy={in_s['entropy']}  "
                f"-> output: {out_s['size']:,} bytes  entropy={out_s['entropy']}[/dim]"
            )
            if result.get("xor_key_hex"):
                console.print(
                    f"  [warn]XOR key (\\x) : {result['xor_key_hex']}[/warn]\n"
                    f"  [warn]XOR key (0x) : {result['xor_key_0x']}[/warn]"
                )

            # syntax-highlighted output
            lang   = _SC_FORMAT_LANG.get(run_fmt, "text")
            output = result["output"]
            n_lines = output.count("\n") + 1

            syn = Syntax(output, lang, theme="monokai",
                         line_numbers=(n_lines > 4 and lang not in ("text",)),
                         word_wrap=False)

            if n_lines > 40:
                with console.pager(styles=True):
                    console.print(Panel(
                        syn,
                        title=f"[heading] {run_fmt}  ({out_s['size']:,} bytes) [/heading]",
                        border_style="bright_black", box=box.ROUNDED,
                    ))
            else:
                console.print(Panel(
                    syn,
                    title=f"[heading] {run_fmt}  ({out_s['size']:,} bytes) [/heading]",
                    border_style="bright_black", box=box.ROUNDED,
                ))
            console.print()

        # -- save <path> ------------------------------------------------------
        elif cmd == "save":
            if sc_raw is None:
                console.print("[warn][=^..^=] no shellcode loaded[/warn]")
                continue
            if not args:
                console.print("[warn][=^..^=] usage: save <path>[/warn]")
                continue
            out_p = Path(" ".join(args)).expanduser().resolve()

            raw_hex = " ".join(f"0x{b:02x}" for b in sc_raw)
            if sc_xform != "none":
                with console.status("[info]applying transform...[/info]", spinner="dots"):
                    res = _sc.process(raw_hex, output_format="hex_raw",
                                      transform=sc_xform, xor_key_str=sc_xkey)
                if not res.get("ok"):
                    console.print(f"  [err][=^..^=] transform error: {res.get('error')}[/err]\n")
                    continue
                save_bytes = bytes.fromhex(res["output"])
            else:
                save_bytes = sc_raw

            try:
                out_p.write_bytes(save_bytes)
                console.print(
                    f"  [ok][=^..^=] saved:[/ok] [cmd]{out_p}[/cmd]  "
                    f"[dim]{len(save_bytes):,} bytes[/dim]\n"
                )
            except Exception as exc:
                console.print(f"  [err][=^..^=] write error: {exc}[/err]\n")

        # -- export <path> ----------------------------------------------------
        elif cmd == "export":
            if sc_raw is None:
                console.print("[warn][=^..^=] no shellcode loaded[/warn]")
                continue
            if not args:
                console.print("[warn][=^..^=] usage: export <path>[/warn]")
                continue
            out_p = Path(" ".join(args)).expanduser().resolve()

            raw_hex = " ".join(f"0x{b:02x}" for b in sc_raw)
            with console.status("[info]generating...[/info]", spinner="dots"):
                res = _sc.process(raw_hex, output_format=sc_fmt,
                                  transform=sc_xform, xor_key_str=sc_xkey,
                                  var_name=sc_vname)
            if not res.get("ok"):
                console.print(f"  [err][=^..^=] {res.get('error')}[/err]\n")
                continue

            try:
                out_p.write_text(res["output"], encoding="utf-8")
                console.print(
                    f"  [ok][=^..^=] exported:[/ok] [cmd]{out_p}[/cmd]  "
                    f"[dim]{len(res['output'])} chars[/dim]\n"
                )
            except Exception as exc:
                console.print(f"  [err][=^..^=] write error: {exc}[/err]\n")

        else:
            console.print(
                f"[warn][=^..^=] unknown command: {cmd}  "
                f"(type  help  for commands)[/warn]"
            )


# -- PE Inspector --------------------------------------------------------------

PE_COMMANDS = ["analyse", "open", "dos-header", "file-header", "opt-header",
               "sections", "imports", "exports", "rich", "overlay", "packer",
               "suspicious", "score", "builds", "load-build", "load-session",
               "help", "back"]

_THREAT_LABEL = {
    range(0,  20): ("LOW",      "good"),
    range(20, 50): ("MEDIUM",   "medium"),
    range(50, 75): ("HIGH",     "high"),
    range(75, 101):("CRITICAL", "critical"),
}


def _threat_label(score: int) -> tuple[str, str]:
    for r, (label, style) in _THREAT_LABEL.items():
        if score in r:
            return label, style
    return "LOW", "good"


def _pe_score_bar(score: int, width: int = 30) -> str:
    filled = int(score / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + f"] {score}/100"


def _render_pe_header(r: dict) -> None:
    label, style = _threat_label(r["threat_score"])
    console.print()
    console.print(Panel(
        f"  file      : [cmd]{r['file_name']}[/cmd]  ({r['file_size']:,} bytes)\n"
        f"  sha256    : [dim]{r['sha256']}[/dim]\n"
        f"  arch      : {r['arch']}  |  type: {r['pe_type']}  |  subsystem: {r['subsystem']}\n"
        f"  timestamp : {r['timestamp']}\n"
        f"  entry     : {r['entry_point']}  |  image_base: {r['image_base']}\n"
        f"  packer    : {r['packer'] or 'none detected'}  |  packed: {r['is_packed']}\n"
        f"  overlay   : {r['overlay'] or 'none'}\n"
        f"  threat    : [{style}]{_pe_score_bar(r['threat_score'])}  {label}[/{style}]",
        title="[heading]PE Header[/heading]",
        border_style="bright_black",
    ))


def _render_kv_table(rows: list[tuple[str, str]], title: str) -> None:
    t = Table(box=box.ROUNDED, show_header=False,
              border_style="bright_black", padding=(0, 1), title=title)
    t.add_column("field", style="info",  no_wrap=True, min_width=30)
    t.add_column("value", style="cmd",   min_width=30)
    for k, v in rows:
        t.add_row(k, str(v))
    console.print()
    console.print(t)
    console.print()


def _render_dos_header(r: dict) -> None:
    dh = r.get("dos_header")
    if not dh:
        console.print("  [warn]DOS header data not available - re-analyse the file[/warn]\n")
        return
    rows = [
        ("e_magic   (signature)",         dh["e_magic"]),
        ("e_cblp    (bytes on last page)", str(dh["e_cblp"])),
        ("e_cp      (pages in file)",      str(dh["e_cp"])),
        ("e_crlc    (relocations)",        str(dh["e_crlc"])),
        ("e_cparhdr (header paragraphs)",  str(dh["e_cparhdr"])),
        ("e_minalloc",                     str(dh["e_minalloc"])),
        ("e_maxalloc",                     str(dh["e_maxalloc"])),
        ("e_ss      (initial SS)",         dh["e_ss"]),
        ("e_sp      (initial SP)",         dh["e_sp"]),
        ("e_csum    (checksum)",           dh["e_csum"]),
        ("e_ip      (initial IP)",         dh["e_ip"]),
        ("e_cs      (initial CS)",         dh["e_cs"]),
        ("e_lfarlc  (reloc table offset)", dh["e_lfarlc"]),
        ("e_ovno    (overlay number)",     str(dh["e_ovno"])),
        ("e_oemid",                        str(dh["e_oemid"])),
        ("e_oeminfo",                      str(dh["e_oeminfo"])),
        ("e_lfanew  (PE offset)",          dh["e_lfanew"]),
    ]
    _render_kv_table(rows, "[heading]DOS Header[/heading]")


def _render_file_header(r: dict) -> None:
    fh = r.get("file_header")
    if not fh:
        console.print("  [warn]File header data not available - re-analyse the file[/warn]\n")
        return
    flags_str = "  ".join(fh["characteristics_flags"]) or "none"
    rows = [
        ("Machine",                  f"{fh['machine']}  ({fh['machine_str']})"),
        ("NumberOfSections",         str(fh["number_of_sections"])),
        ("TimeDateStamp",            fh["time_date_stamp"]),
        ("TimeDateStamp (raw)",      fh["time_date_stamp_raw"]),
        ("PointerToSymbolTable",     fh["pointer_to_symbol_table"]),
        ("NumberOfSymbols",          str(fh["number_of_symbols"])),
        ("SizeOfOptionalHeader",     str(fh["size_of_optional_header"])),
        ("Characteristics",          fh["characteristics"]),
        ("Characteristics (flags)",  flags_str),
    ]
    _render_kv_table(rows, "[heading]File Header (COFF)[/heading]")


def _render_opt_header(r: dict) -> None:
    oh = r.get("optional_header")
    if not oh:
        console.print("  [warn]Optional header data not available - re-analyse the file[/warn]\n")
        return
    dll_flags = "  ".join(oh["dll_characteristics_flags"]) or "none"
    rows = [
        ("Magic",                    f"{oh['magic']}  ({oh['magic_str']})"),
        ("LinkerVersion",            oh["linker_version"]),
        ("SizeOfCode",               f"{oh['size_of_code']:,}"),
        ("SizeOfInitializedData",    f"{oh['size_of_initialized_data']:,}"),
        ("SizeOfUninitializedData",  f"{oh['size_of_uninitialized_data']:,}"),
        ("AddressOfEntryPoint",      oh["address_of_entry_point"]),
        ("BaseOfCode",               oh["base_of_code"]),
    ]
    if "base_of_data" in oh:
        rows.append(("BaseOfData", oh["base_of_data"]))
    rows += [
        ("ImageBase",                oh["image_base"]),
        ("SectionAlignment",         f"{oh['section_alignment']:,}"),
        ("FileAlignment",            f"{oh['file_alignment']:,}"),
        ("OSVersion",                oh["os_version"]),
        ("ImageVersion",             oh["image_version"]),
        ("SubsystemVersion",         oh["subsystem_version"]),
        ("Win32VersionValue",        str(oh["win32_version_value"])),
        ("SizeOfImage",              f"{oh['size_of_image']:,}"),
        ("SizeOfHeaders",            f"{oh['size_of_headers']:,}"),
        ("CheckSum",                 oh["checksum"]),
        ("Subsystem",                f"{oh['subsystem']}  ({oh['subsystem_str']})"),
        ("DllCharacteristics",       oh["dll_characteristics"]),
        ("DllCharacteristics (flags)", dll_flags),
        ("SizeOfStackReserve",       f"{oh['size_of_stack_reserve']:,}"),
        ("SizeOfStackCommit",        f"{oh['size_of_stack_commit']:,}"),
        ("SizeOfHeapReserve",        f"{oh['size_of_heap_reserve']:,}"),
        ("SizeOfHeapCommit",         f"{oh['size_of_heap_commit']:,}"),
        ("NumberOfRvaAndSizes",      str(oh["number_of_rva_and_sizes"])),
    ]
    _render_kv_table(rows, "[heading]Optional Header[/heading]")


def _render_pe_sections(r: dict) -> None:
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1))
    t.add_column("Name",          style="cmd",  no_wrap=True)
    t.add_column("Virt Addr",     style="dim",  no_wrap=True)
    t.add_column("Virt Size",     justify="right")
    t.add_column("Raw Offset",    style="dim",  no_wrap=True)
    t.add_column("Raw Size",      justify="right")
    t.add_column("Entropy",       justify="right")
    t.add_column("Chars",         style="dim",  no_wrap=True)
    t.add_column("RWX",           no_wrap=True)
    t.add_column("Note",          style="warn")

    for s in r["sections"]:
        rwx = ("r" if s["readable"] else "-") + ("w" if s["writable"] else "-") + ("x" if s["executable"] else "-")
        ent = s["entropy"]
        ent_style = "err" if ent > 6.8 else ("warn" if ent > 6.0 else "good")
        note = "[err]high entropy[/err]" if ent > 6.8 else ("[warn]W+X[/warn]" if s["writable"] and s["executable"] else "")
        t.add_row(
            s["name"],
            s["virt_addr"],
            f"{s['virt_size']:,}",
            s.get("pointer_to_raw_data", "-"),
            f"{s['raw_size']:,}",
            f"[{ent_style}]{ent:.3f}[/{ent_style}]",
            s.get("characteristics", "-"),
            rwx,
            note,
        )
    console.print()
    console.print(t)
    console.print(
        f"  [dim]sections: {r['section_count']}  |  "
        f"high-entropy: {r['high_entropy_secs']}  |  "
        f"overall entropy: {r['overall_entropy']:.3f}[/dim]\n"
    )


def _render_pe_imports(r: dict) -> None:
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1))
    t.add_column("DLL",          style="cmd",  no_wrap=True)
    t.add_column("Functions",    justify="right")
    t.add_column("Suspicious",   justify="right")
    t.add_column("Sample APIs",  style="dim")

    for imp in r["imports"]:
        susp_count = imp["suspicious_count"]
        susp_style = "err" if susp_count > 3 else ("warn" if susp_count > 0 else "good")
        sample = ", ".join(imp["functions"][:4])
        if len(imp["functions"]) > 4:
            sample += f" ... +{len(imp['functions']) - 4}"
        t.add_row(
            imp["dll"],
            str(imp["function_count"]),
            f"[{susp_style}]{susp_count}[/{susp_style}]",
            sample,
        )
    console.print(t)
    console.print(
        f"  [dim]dlls: {r['import_count']}  |  total functions: {r['total_import_fns']}[/dim]\n"
    )


def _render_pe_suspicious(r: dict) -> None:
    by_cat = r.get("suspicious_by_category", {})
    if not by_cat:
        console.print("  [good][=^..^=] no suspicious imports detected[/good]\n")
        return
    CAT_STYLE = {
        "injection":    "critical",
        "hollowing":    "critical",
        "anti_debug":   "high",
        "anti_vm":      "high",
        "network":      "medium",
        "credential":   "medium",
        "execution":    "warn",
        "persistence":  "warn",
        "keylog_screen":"warn",
    }
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1))
    t.add_column("Category",  no_wrap=True)
    t.add_column("APIs", style="dim")

    for cat, apis in sorted(by_cat.items()):
        style = CAT_STYLE.get(cat, "info")
        t.add_row(
            f"[{style}]{cat}[/{style}]",
            ", ".join(apis),
        )
    console.print(t)
    console.print()


def _render_pe_exports(r: dict) -> None:
    exports = r.get("exports", [])
    if not exports:
        console.print("  [dim]no exports found[/dim]\n")
        return
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1),
              title=f"Exports  ({len(exports)})")
    t.add_column("Name",    style="cmd",  min_width=32)
    t.add_column("Ordinal", style="dim",  min_width=8,  justify="right")
    t.add_column("Address", style="info", min_width=14, no_wrap=True)
    for exp in exports:
        t.add_row(exp.get("name") or "(unnamed)", str(exp.get("ordinal", "")), exp.get("addr", ""))
    console.print()
    console.print(t)
    console.print()


def _render_pe_rich(r: dict) -> None:
    entries = r.get("rich_header")
    if not entries:
        console.print("  [dim]no Rich header found (or header was zeroed)[/dim]\n")
        return
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1),
              title=f"Rich Header  ({len(entries)} entries)")
    t.add_column("Tool",    style="cmd",  min_width=28)
    t.add_column("Prod ID", style="dim",  min_width=10, justify="right")
    t.add_column("Build",   style="info", min_width=8,  justify="right")
    t.add_column("Count",   style="warn", min_width=6,  justify="right")
    for e in entries:
        t.add_row(e.get("tool", "?"), hex(e.get("prod_id", 0)), str(e.get("build", 0)), str(e.get("count", 0)))
    console.print()
    console.print(t)
    console.print()


def _render_pe_overlay(r: dict) -> None:
    ov = r.get("overlay")
    if not ov:
        console.print("  [dim]no overlay detected[/dim]\n")
        return
    rows = [
        ("Offset",  hex(ov["offset"])),
        ("Size",    f"{ov['size']:,} bytes  ({ov['size'] // 1024} KB)"),
        ("Entropy", str(ov["entropy"])),
    ]
    _render_kv_table(rows, "[heading]Overlay[/heading]")


def run_pe() -> None:
    """Interactive PE Anatomy Inspector sub-REPL."""
    session = _make_session(PE_COMMANDS,
                           path_cmds=frozenset({"analyse", "open"}))
    current: dict | None = None

    console.print()
    console.print(Panel(
        "  Analyze PE binaries: sections, imports, entropy, threat score\n"
        "  type  help  for commands,  back  to return",
        title="[heading] PE Inspector [/heading]",
        border_style="bright_cyan",
        box=box.ROUNDED,
    ))
    console.print()

    while True:
        prompt = "peekaboo [pe] > " if current is None else f"peekaboo [pe [{current['file_name']}]]> "
        try:
            raw = session.prompt(prompt, style=PT_STYLE).strip()
        except KeyboardInterrupt:
            console.print("\n[dim]use  back  to return[/dim]")
            continue
        except EOFError:
            break

        if not raw:
            continue
        parts = raw.split(None, 1)
        cmd   = parts[0].lower()
        arg   = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("back", "exit", "quit"):
            break

        elif cmd == "help":
            t = Table(box=box.ROUNDED, show_header=False, border_style="bright_black", padding=(0, 1))
            for c, desc in [
                ("analyse <path>",              "load and fully analyse a PE file"),
                ("open <path>",                 "alias for analyse"),
                ("builds",                      "list successful builds with compiled binaries"),
                ("load-build <id> [filename]",  "load a compiled build binary directly"),
                ("load-session <sid> <file>",   "load a binary from a session (samples/)"),
                ("dos-header",                  "show DOS (MZ) header fields"),
                ("file-header",                 "show COFF file header fields"),
                ("opt-header",                  "show optional header fields"),
                ("sections",                    "show section table with entropy + characteristics"),
                ("imports",                     "show import table"),
                ("exports",                     "show export table"),
                ("rich",                        "show Rich header (compiler fingerprint)"),
                ("overlay",                     "show overlay info (appended data)"),
                ("packer",                      "show packer detection result"),
                ("suspicious",                  "show suspicious API hits by category"),
                ("score",                       "show threat score breakdown"),
                ("help",                        "show this help"),
                ("back",                        "return to main menu"),
            ]:
                t.add_row(f"[cmd]{c}[/cmd]", desc)
            console.print(t)
            console.print()

        elif cmd in ("analyse", "open"):
            if not arg:
                console.print("  [warn][=^..^=] usage: analyse <path>[/warn]\n")
                continue
            p = Path(arg).expanduser()
            if not p.exists():
                console.print(f"  [err][=^..^=] file not found: {p}[/err]\n")
                continue
            with console.status("[info]analysing...[/info]", spinner="dots"):
                try:
                    from pe_inspector import analyze as _pe_analyze
                    current = _pe_analyze(p)
                except Exception as e:
                    console.print(f"  [err][=^..^=] {e}[/err]\n")
                    continue
            if not current["ok"]:
                console.print(f"  [err][=^..^=] {current['error']}[/err]\n")
                current = None
                continue
            _render_pe_header(current)
            _render_pe_sections(current)

        elif cmd == "dos-header":
            if current is None:
                console.print("  [warn][=^..^=] no file loaded -- use  analyse <path>  first[/warn]\n")
            else:
                _render_dos_header(current)

        elif cmd == "file-header":
            if current is None:
                console.print("  [warn][=^..^=] no file loaded -- use  analyse <path>  first[/warn]\n")
            else:
                _render_file_header(current)

        elif cmd == "opt-header":
            if current is None:
                console.print("  [warn][=^..^=] no file loaded -- use  analyse <path>  first[/warn]\n")
            else:
                _render_opt_header(current)

        elif cmd == "sections":
            if current is None:
                console.print("  [warn][=^..^=] no file loaded -- use  analyse <path>  first[/warn]\n")
            else:
                _render_pe_sections(current)

        elif cmd == "imports":
            if current is None:
                console.print("  [warn][=^..^=] no file loaded -- use  analyse <path>  first[/warn]\n")
            else:
                _render_pe_imports(current)

        elif cmd == "suspicious":
            if current is None:
                console.print("  [warn][=^..^=] no file loaded -- use  analyse <path>  first[/warn]\n")
            else:
                _render_pe_suspicious(current)

        elif cmd == "exports":
            if current is None:
                console.print("  [warn][=^..^=] no file loaded -- use  analyse <path>  first[/warn]\n")
            else:
                _render_pe_exports(current)

        elif cmd == "rich":
            if current is None:
                console.print("  [warn][=^..^=] no file loaded -- use  analyse <path>  first[/warn]\n")
            else:
                _render_pe_rich(current)

        elif cmd == "overlay":
            if current is None:
                console.print("  [warn][=^..^=] no file loaded -- use  analyse <path>  first[/warn]\n")
            else:
                _render_pe_overlay(current)

        elif cmd == "packer":
            if current is None:
                console.print("  [warn][=^..^=] no file loaded -- use  analyse <path>  first[/warn]\n")
            else:
                pck = current.get("packer")
                if pck:
                    console.print(f"\n  [warn]packer detected:[/warn] [cmd]{pck}[/cmd]\n")
                else:
                    console.print("  [good][=^..^=] no packer signature detected[/good]\n")

        elif cmd == "builds":
            try:
                import db as _db_pe
            except ImportError:
                console.print("[err][=^..^=] db module unavailable[/err]")
                continue
            fresh = _db_pe.get_builds(limit=50)
            t = Table(box=box.ROUNDED, show_header=True,
                      header_style="bold bright_white on bright_black",
                      border_style="bright_black", padding=(0, 1))
            t.add_column("build-id", style="cmd",  no_wrap=True, min_width=14)
            t.add_column("type",     style="info",  min_width=10)
            t.add_column("module",   style="info",  min_width=18)
            t.add_column("date",     style="dim",   min_width=16)
            t.add_column("binaries", style="ok",    min_width=30)
            shown = 0
            for b in fresh:
                if b.get("status") != "success":
                    continue
                files = _vtscan_resolve_files(b)
                pa    = b.get("params", {})
                pa_slug = pa.get("slug")
                if pa_slug:
                    mod = pa_slug
                elif pa.get("malware") == "stealer":
                    mod = pa.get("stealer") or "?"
                else:
                    mod = pa.get("injection") or "?"
                mtype   = "module" if pa_slug else (pa.get("malware") or "-")
                bin_txt = "  ".join(n for n, _ in files) if files else "[dim]not on disk[/dim]"
                t.add_row(b["id"], mtype, mod, (b.get("created") or "")[:16], bin_txt)
                shown += 1
            if shown:
                console.print()
                console.print(t)
                console.print()
            else:
                console.print("  [dim]no successful builds found[/dim]\n")

        elif cmd == "load-build":
            if not arg:
                console.print("  [warn][=^..^=] usage: load-build <build-id> [filename][/warn]\n")
                continue
            try:
                import db as _db_pe
            except ImportError:
                console.print("[err][=^..^=] db module unavailable[/err]")
                continue
            lb_parts   = arg.split(None, 1)
            build_id   = lb_parts[0]
            want_fname = lb_parts[1] if len(lb_parts) > 1 else None
            build = _db_pe.get_build(build_id)
            if not build:
                console.print(f"  [err][=^..^=] build not found: {build_id}[/err]\n")
                continue
            if build.get("status") != "success":
                console.print(f"  [warn][=^..^=] build status is '{build.get('status')}', not success[/warn]\n")
                continue
            files = _vtscan_resolve_files(build)
            if not files:
                console.print(f"  [err][=^..^=] no binaries on disk for build {build_id}[/err]\n")
                continue
            if want_fname:
                match = [(n, p) for n, p in files if n.lower() == want_fname.lower()]
                if not match:
                    avail = "  ".join(n for n, _ in files)
                    console.print(f"  [err][=^..^=] '{want_fname}' not found; available: {avail}[/err]\n")
                    continue
                chosen = match[0][1]
            elif len(files) > 1:
                console.print()
                for i, (n, fp2) in enumerate(files, 1):
                    console.print(f"  [{i}] [cmd]{n}[/cmd]  [dim]{fp2.stat().st_size:,} bytes[/dim]")
                console.print(f"\n  Use  [cmd]load-build {build_id} <filename>[/cmd]  to pick one.\n")
                continue
            else:
                chosen = files[0][1]
            with console.status("[info]analysing...[/info]", spinner="dots"):
                try:
                    from pe_inspector import analyze as _pe_analyze2
                    current = _pe_analyze2(chosen)
                except Exception as exc:
                    console.print(f"  [err][=^..^=] {exc}[/err]\n")
                    continue
            if not current["ok"]:
                console.print(f"  [err][=^..^=] {current['error']}[/err]\n")
                current = None
                continue
            console.print(f"  [ok][=^..^=] loaded:[/ok] [cmd]{chosen.name}[/cmd]  [dim](build {build_id})[/dim]")
            _render_pe_header(current)
            _render_pe_sections(current)

        elif cmd == "load-session":
            ls_parts = arg.split(None, 1)
            if len(ls_parts) < 2:
                sdir = Path(__file__).parent / "samples"
                if sdir.exists():
                    console.print()
                    for sd in sorted(sdir.iterdir()):
                        if not sd.is_dir():
                            continue
                        exes = [f.name for f in sorted(sd.iterdir())
                                if f.suffix.lower() in (".exe", ".dll", ".sys", ".bin")]
                        if exes:
                            console.print(f"  [cmd]{sd.name}[/cmd]  [dim]{' '.join(exes)}[/dim]")
                    console.print()
                console.print("  [warn]usage: load-session <session-id> <filename>[/warn]\n")
                continue
            sid, fname = ls_parts[0], ls_parts[1]
            if "/" in fname or "\\" in fname:
                console.print("  [err][=^..^=] filename must not contain path separators[/err]\n")
                continue
            sdir     = Path(__file__).parent / "samples"
            fpath    = (sdir / sid / fname).resolve()
            if not str(fpath).startswith(str(sdir.resolve())):
                console.print("  [err][=^..^=] path traversal detected[/err]\n")
                continue
            if not fpath.exists():
                console.print(f"  [err][=^..^=] file not found: {fpath}[/err]\n")
                continue
            with console.status("[info]analysing...[/info]", spinner="dots"):
                try:
                    from pe_inspector import analyze as _pe_analyze3
                    current = _pe_analyze3(fpath)
                except Exception as exc:
                    console.print(f"  [err][=^..^=] {exc}[/err]\n")
                    continue
            if not current["ok"]:
                console.print(f"  [err][=^..^=] {current['error']}[/err]\n")
                current = None
                continue
            console.print(f"  [ok][=^..^=] loaded:[/ok] [cmd]{fpath.name}[/cmd]  [dim](session {sid})[/dim]")
            _render_pe_header(current)
            _render_pe_sections(current)

        elif cmd == "score":
            if current is None:
                console.print("  [warn][=^..^=] no file loaded -- use  analyse <path>  first[/warn]\n")
            else:
                label, style = _threat_label(current["threat_score"])
                console.print()
                console.print(Panel(
                    f"  [{style}]{_pe_score_bar(current['threat_score'])}  {label}[/{style}]\n\n"
                    f"  packed          : {current['is_packed']}  (packer: {current['packer'] or 'none'})\n"
                    f"  high-entropy sections : {current['high_entropy_secs']}\n"
                    f"  suspicious API cats   : {', '.join(current['suspicious_by_category'].keys()) or 'none'}\n"
                    f"  overlay         : {'yes' if current['overlay'] else 'no'}\n"
                    f"  total imports   : {current['total_import_fns']}",
                    title="[heading]Threat Score[/heading]",
                    border_style="bright_black",
                ))
                console.print()

        else:
            console.print(
                f"[warn][=^..^=] unknown command: {cmd}  "
                f"(type  help  for commands)[/warn]"
            )


# -- builder -------------------------------------------------------------------

BUILD_PAGE_SIZE = PAGE_SIZE

BUILDER_COMMANDS = [
    "list", "search", "build", "history", "show", "clear", "help", "back",
]

BUILDER_HELP = [
    ("list [filter]",    "list compilable modules; filter by platform or category"),
    ("search <query>",   "search by slug, title, T-ID or category"),
    ("build <slug>",     "compile module and save to samples/"),
    ("history [N]",      "show last N builds from DB (default 20)"),
    ("show <build-id>",  "full compiler log for a specific build"),
    ("clear",            "delete build history from DB + compiled binaries from disk"),
    ("help",             "show this help"),
    ("back",             "return to main menu"),
]


def _render_build_table(entries: list[dict], title: str = "Compilable Modules",
                         page: int = 0) -> int:
    total  = len(entries)
    pages  = max(1, (total + BUILD_PAGE_SIZE - 1) // BUILD_PAGE_SIZE)
    start  = page * BUILD_PAGE_SIZE
    chunk  = entries[start:start + BUILD_PAGE_SIZE]

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1),
              title=f"{title}  [{start+1}-{min(start+len(chunk), total)} / {total}]",
              show_lines=False)
    t.add_column("#",         style="dim",  min_width=4,  justify="right", no_wrap=True)
    t.add_column("slug",      style="cmd",  min_width=24, no_wrap=True)
    t.add_column("platform",  style="info", min_width=8,  no_wrap=True)
    t.add_column("compiler",  style="warn", min_width=10, no_wrap=True)
    t.add_column("category",  style="dim",  min_width=14, no_wrap=True)
    t.add_column("T-IDs",                   min_width=14, no_wrap=True)
    t.add_column("title",                   min_width=36)

    for i, e in enumerate(chunk, start + 1):
        tids = " ".join(e["attack_ids"][:2])
        if len(e["attack_ids"]) > 2:
            tids += f" +{len(e['attack_ids'])-2}"
        t.add_row(
            str(i),
            e["slug"],
            e["platform"],
            e["compiler"],
            e["category"],
            tids or "-",
            e["title"][:36] + ("..." if len(e["title"]) > 36 else ""),
        )

    console.print()
    console.print(t)
    if pages > 1:
        console.print(
            f"  [dim]page {page+1}/{pages} -- "
            f"press Enter for next page,  build <slug>  to compile[/dim]\n"
        )
    return pages


def _render_history_table(builds: list[dict]) -> None:
    if not builds:
        console.print("  [dim](no builds yet)[/dim]\n")
        return

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1), title=f"Build History ({len(builds)} runs)",
              show_lines=False)
    t.add_column("#",        style="dim",    min_width=4,  justify="right", no_wrap=True)
    t.add_column("build-id", style="cmd",    min_width=14, no_wrap=True)
    t.add_column("slug",     style="info",   min_width=24, no_wrap=True)
    t.add_column("status",                   min_width=8,  no_wrap=True)
    t.add_column("date",     style="dim",    min_width=16, no_wrap=True)
    t.add_column("duration", style="dim",    min_width=8,  justify="right", no_wrap=True)
    t.add_column("rc",       style="dim",    min_width=4,  justify="right", no_wrap=True)

    for i, b in enumerate(builds, 1):
        status  = b.get("status", "?")
        s_style = "ok" if status == "success" else \
                  "err" if status == "failed" else "warn"
        s_tag   = "[OK]" if status == "success" else \
                  "[FAIL]" if status == "failed" else f"[{status}]"

        params  = b.get("params", {})
        if params.get("slug"):
            slug = params["slug"][:24]
        elif params.get("malware") == "stealer":
            s    = params.get("stealer", "")
            pers = params.get("persistence", "")
            slug = f"stealer/{s}" + (f"+{pers}" if pers and pers != "none" else "")
            slug = slug[:28]
        elif params.get("malware") or params.get("injection"):
            parts = [params.get("malware",""), params.get("injection","")]
            slug  = "/".join(p for p in parts if p)[:24]
        else:
            slug = b.get("id", "?")[:24]

        created = (b.get("created") or "")[:16]

        dur = ""
        try:
            if b.get("start_time") and b.get("end_time"):
                s = datetime.fromisoformat(b["start_time"])
                e2 = datetime.fromisoformat(b["end_time"])
                secs = (e2 - s).total_seconds()
                dur = f"{secs:.1f}s"
        except Exception:
            pass

        rc = "" if b.get("returncode") is None else str(b["returncode"])

        t.add_row(
            str(i),
            b.get("id", "?")[:14],
            slug,
            Text(s_tag, style=s_style),
            created,
            dur,
            rc,
        )

    console.print()
    console.print(t)
    console.print()


def _render_build_log(log: str, ok: bool) -> None:
    """Print colorized compiler log lines."""
    if not log:
        return
    console.print()
    for line in log.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("[ok]"):
            console.print(f"  [ok]{stripped}[/ok]")
        elif stripped.startswith("[fail]"):
            console.print(f"  [err]{stripped}[/err]")
        elif stripped.startswith("[warn]"):
            console.print(f"  [warn]{stripped}[/warn]")
        elif stripped.startswith("[compile]"):
            console.print(f"  [cmd]{stripped}[/cmd]")
        elif "error:" in stripped.lower():
            console.print(f"  [err]{stripped}[/err]")
        elif "warning:" in stripped.lower():
            console.print(f"  [warn]{stripped}[/warn]")
        else:
            console.print(f"  [dim]{stripped}[/dim]")
    console.print()


def _render_build_detail(b: dict) -> None:
    params  = b.get("params", {})
    status  = b.get("status", "?")
    s_style = "ok" if status == "success" else "err" if status == "failed" else "warn"

    dur = ""
    try:
        if b.get("start_time") and b.get("end_time"):
            s = datetime.fromisoformat(b["start_time"])
            e2 = datetime.fromisoformat(b["end_time"])
            dur = f"{(e2-s).total_seconds():.1f}s"
    except Exception:
        pass

    meta = (
        f"  ID       : {b.get('id','?')}\n"
        f"  Slug     : {params.get('slug', '?')}\n"
        f"  Platform : {params.get('platform', '?')}\n"
        f"  Compiler : {params.get('compiler', '?')}\n"
        f"  Status   : {status}\n"
        f"  Date     : {(b.get('created') or '')[:19]}\n"
        f"  Duration : {dur or '?'}\n"
        f"  rc       : {b.get('returncode','?')}"
    )
    console.print()
    console.print(Panel(meta,
                        title=f"[heading] Build: {b.get('id','?')} [/heading]",
                        border_style=s_style, box=box.ROUNDED))

    log = b.get("output") or b.get("log", "") or ""
    if log:
        lines = log.splitlines()
        if len(lines) > 60:
            with console.pager(styles=True):
                _render_build_log(log, status == "success")
        else:
            _render_build_log(log, status == "success")


# -- ttp module ----------------------------------------------------------------

TTP_COMMANDS = [
    "list", "show", "search", "build", "refresh", "help", "back", "exit",
]

_TTP_TACTICS_ORDER = [
    "persistence", "defense-evasion", "privilege-escalation", "execution",
    "exfiltration", "command-and-control", "collection", "discovery",
    "credential-access", "lateral-movement", "impact", "initial-access",
]


def _ttp_tactic_style(tactic: str) -> str:
    return {
        "persistence":          "cyan",
        "defense-evasion":      "yellow",
        "privilege-escalation": "magenta",
        "execution":            "green",
        "exfiltration":         "red",
        "command-and-control":  "red",
        "collection":           "blue",
        "discovery":            "dim",
        "credential-access":    "magenta",
    }.get(tactic, "dim")


def _render_ttp_list(rows: list[dict], title: str) -> None:
    """Group rows by tactic and render a summary table (one row per attack_id)."""
    # aggregate by attack_id
    by_id: dict[str, dict] = {}
    for r in rows:
        aid = r["attack_id"]
        if aid not in by_id:
            by_id[aid] = {
                "attack_id": aid,
                "tech_name": r["tech_name"] or aid,
                "tactic":    r["tactic"],
                "impls":     0,
                "compilable": False,
            }
        by_id[aid]["impls"] += 1
        if r["meow_slug"]:
            by_id[aid]["compilable"] = True

    # sort: by tactic order then attack_id
    def _sort_key(e):
        t = e["tactic"]
        try:
            ti = _TTP_TACTICS_ORDER.index(t)
        except ValueError:
            ti = 99
        return (ti, e["attack_id"])

    entries = sorted(by_id.values(), key=_sort_key)

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1),
              title=f"{title}  ({len(entries)} techniques / {len(rows)} impls)")
    t.add_column("attack_id",  style="cmd",    min_width=12, no_wrap=True)
    t.add_column("technique",  style="info",   min_width=42)
    t.add_column("tactic",     min_width=22,   no_wrap=True)
    t.add_column("impls",      style="dim",    min_width=5,  justify="right")
    t.add_column("compile",    min_width=7,    justify="center")

    for e in entries:
        tac   = e["tactic"]
        ts    = _ttp_tactic_style(tac)
        comp  = Text("YES", style="ok") if e["compilable"] else Text("-", style="dim")
        t.add_row(
            e["attack_id"],
            e["tech_name"][:42],
            Text(tac, style=ts),
            str(e["impls"]),
            comp,
        )

    console.print()
    console.print(t)
    console.print(
        f"  [dim]use  show <attack_id>  to see implementations"
        f"  |  build <attack_id>  to compile[/dim]\n"
    )


def _render_ttp_show(attack_id: str, rows: list[dict]) -> None:
    """Render the detail view for one attack_id."""
    if not rows:
        console.print(f"  [err][=^..^=] no implementations found for {attack_id}[/err]\n")
        return

    tech_name = rows[0]["tech_name"] or attack_id
    tactic    = rows[0]["tactic"]

    # technique header panel
    ts = _ttp_tactic_style(tactic)
    console.print()
    console.print(Panel(
        f"  [{ts}]{tech_name}[/{ts}]\n"
        f"  Tactic : [dim]{tactic}[/dim]\n"
        f"  Impls  : {len(rows)}  |  "
        f"Compilable: {sum(1 for r in rows if r['meow_slug'])}",
        title=f"[heading] {attack_id} [/heading]",
        border_style=ts,
        box=box.ROUNDED,
    ))

    # implementations table
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1),
              title=f"Implementations  ({len(rows)})")
    t.add_column("#",          style="dim",   min_width=3,  justify="right")
    t.add_column("blog_slug",  style="cmd",   min_width=28, no_wrap=True)
    t.add_column("platform",   min_width=8,   no_wrap=True)
    t.add_column("notes",      style="info",  min_width=46)
    t.add_column("compile",    min_width=7,   justify="center")

    for i, r in enumerate(rows, 1):
        comp = Text("YES", style="ok") if r["meow_slug"] else Text("-", style="dim")
        t.add_row(
            str(i),
            r["blog_slug"],
            r["platform"],
            r["notes"][:46],
            comp,
        )

    console.print(t)

    # show blog URLs
    console.print()
    for r in rows:
        if r["blog_url"]:
            console.print(f"  [dim]{r['blog_slug']}[/dim]  ->  [link]{r['blog_url']}[/link]")

    compilable = [r for r in rows if r["meow_slug"]]
    if compilable:
        console.print(
            f"\n  [dim]use  build {attack_id}  to compile one of the "
            f"{len(compilable)} compilable implementations[/dim]"
        )
    console.print()


def run_ttp() -> None:
    """Interactive TTP sub-REPL."""
    try:
        import db as _db
    except ImportError as e:
        console.print(f"[err][=^..^=] db module unavailable: {e}[/err]")
        return
    try:
        import discovery as _disc
    except ImportError as e:
        console.print(f"[err][=^..^=] discovery module unavailable: {e}[/err]")
        return

    # load all rows once; refresh updates this
    all_rows = _db.get_ttp_implementations()
    if not all_rows:
        console.print(
            "[warn][=^..^=] ttp_implementations table is empty -- run  refresh  to seed[/warn]\n"
        )

    # build completer tokens from attack_ids + tactics
    attack_ids = sorted({r["attack_id"] for r in all_rows})
    tactics    = sorted({r["tactic"] for r in all_rows if r["tactic"]})
    platforms  = ["windows", "linux", "macos"]

    session = _make_session(TTP_COMMANDS + attack_ids + tactics + platforms)

    n_techs = _db.count_ttp_techniques()
    n_impls = _db.count_ttp_implementations()

    console.print()
    console.print(Panel(
        f"  {n_techs} ATT&CK techniques  |  {n_impls} implementations\n"
        f"  type  help  for commands,  list  to browse,  back  to return",
        title="[heading] TTP -> Implementation Map [/heading]",
        border_style="bright_cyan",
        box=box.ROUNDED,
    ))
    console.print()

    while True:
        try:
            raw = session.prompt("peekaboo [ttp] > ", style=PT_STYLE).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]use  back  to return[/dim]")
            continue

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].upper() if parts[0].upper().startswith("T1") else parts[0].lower()
        args  = parts[1:]

        # bare attack_id typed directly -> treat as show
        if cmd.startswith("T1") and len(cmd) >= 5:
            rows = _db.get_ttp_by_attack_id(cmd)
            _render_ttp_show(cmd, rows)
            continue

        if cmd in ("back", "exit", "quit"):
            break

        elif cmd == "help":
            show_help("ttp", args[0] if args else None)

        # -- list [filter] -------------------------------------------------------
        elif cmd == "list":
            f = args[0].lower() if args else ""
            if not f:
                _render_ttp_list(all_rows, "All TTP Implementations")
            elif f in tactics:
                filtered = [r for r in all_rows if r["tactic"] == f]
                _render_ttp_list(filtered, f"Tactic: {f}")
            elif f in platforms:
                filtered = [r for r in all_rows if r["platform"] == f]
                _render_ttp_list(filtered, f"Platform: {f}")
            elif f.upper().startswith("T1"):
                aid = f.upper()
                filtered = [r for r in all_rows
                            if r["attack_id"] == aid
                            or r["attack_id"].startswith(aid + ".")]
                if not filtered:
                    console.print(f"  [warn][=^..^=] no implementations for {aid}[/warn]\n")
                else:
                    _render_ttp_list(filtered, f"Technique: {aid}")
            else:
                # try as tactic partial match
                matches = [t for t in tactics if f in t]
                if len(matches) == 1:
                    filtered = [r for r in all_rows if r["tactic"] == matches[0]]
                    _render_ttp_list(filtered, f"Tactic: {matches[0]}")
                else:
                    console.print(
                        f"  [warn][=^..^=] unknown filter '{f}' -- "
                        f"use a tactic, platform, or T-ID[/warn]\n"
                    )

        # -- show <attack_id> ----------------------------------------------------
        elif cmd == "show":
            if not args:
                console.print("[warn][=^..^=] usage: show <attack_id>[/warn]")
                continue
            aid  = args[0].upper()
            rows = _db.get_ttp_by_attack_id(aid)
            if not rows:
                # try partial: show all sub-techniques
                sub = [r for r in all_rows if r["attack_id"].startswith(aid + ".")]
                if sub:
                    _render_ttp_list(sub, f"Sub-techniques of {aid}")
                else:
                    console.print(f"  [err][=^..^=] no implementations for {aid}[/err]\n")
            else:
                _render_ttp_show(aid, rows)

        # -- search <query> ------------------------------------------------------
        elif cmd == "search":
            if not args:
                console.print("[warn][=^..^=] usage: search <query>[/warn]")
                continue
            q       = " ".join(args)
            results = _db.get_ttp_implementations(q=q)
            if not results:
                console.print(f"  [warn][=^..^=] no results for '{q}'[/warn]\n")
            else:
                t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                          border_style="bright_black", padding=(0, 1),
                          title=f"Search: '{q}'  ({len(results)} results)")
                t.add_column("attack_id", style="cmd",  min_width=12, no_wrap=True)
                t.add_column("tactic",    min_width=20, no_wrap=True)
                t.add_column("blog_slug", style="info", min_width=28, no_wrap=True)
                t.add_column("platform",  min_width=8,  no_wrap=True)
                t.add_column("notes",     style="dim",  min_width=40)
                for r in results:
                    ts = _ttp_tactic_style(r["tactic"])
                    t.add_row(
                        r["attack_id"],
                        Text(r["tactic"], style=ts),
                        r["blog_slug"],
                        r["platform"],
                        r["notes"][:40],
                    )
                console.print()
                console.print(t)
                console.print(
                    f"  [dim]use  show <attack_id>  for full detail[/dim]\n"
                )

        # -- build <attack_id> ---------------------------------------------------
        elif cmd == "build":
            if not args:
                console.print("[warn][=^..^=] usage: build <attack_id>[/warn]")
                continue

            aid  = args[0].upper()
            rows = _db.get_ttp_by_attack_id(aid)
            if not rows:
                console.print(f"  [err][=^..^=] no implementations for {aid}[/err]\n")
                continue

            compilable = [r for r in rows if r["meow_slug"]]
            if not compilable:
                console.print(
                    f"  [warn][=^..^=] {aid} has {len(rows)} implementation(s) "
                    f"but none have a compilable meow module[/warn]"
                )
                for r in rows:
                    if r["blog_url"]:
                        console.print(f"  [dim]-> {r['blog_url']}[/dim]")
                console.print()
                continue

            # pick which implementation to compile
            chosen = None
            if len(compilable) == 1:
                chosen = compilable[0]
                console.print(
                    f"  [dim]one compilable implementation: {chosen['blog_slug']}[/dim]"
                )
            else:
                t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                          border_style="bright_black", padding=(0, 1),
                          title=f"Compilable implementations of {aid}")
                t.add_column("#",          style="dim",  min_width=3,  justify="right")
                t.add_column("blog_slug",  style="cmd",  min_width=28)
                t.add_column("platform",   min_width=8,  no_wrap=True)
                t.add_column("notes",      style="info", min_width=46)
                for i, r in enumerate(compilable, 1):
                    t.add_row(str(i), r["blog_slug"], r["platform"], r["notes"][:46])
                console.print()
                console.print(t)
                try:
                    raw_pick = session.prompt(
                        "  select # to compile (Enter to cancel): ",
                        style=PT_STYLE,
                    ).strip()
                except (KeyboardInterrupt, EOFError):
                    console.print()
                    continue
                if not raw_pick:
                    continue
                try:
                    idx = int(raw_pick) - 1
                    if not (0 <= idx < len(compilable)):
                        raise ValueError
                    chosen = compilable[idx]
                except ValueError:
                    console.print("  [err][=^..^=] invalid selection[/err]\n")
                    continue

            # resolve meow module via discovery
            meow_slug  = chosen["meow_slug"]
            slug_map   = {m["slug"]: m for m in _disc.scan_all()}
            mod        = slug_map.get(meow_slug)
            if not mod:
                console.print(
                    f"  [err][=^..^=] meow module '{meow_slug}' not found in discovery[/err]\n"
                )
                continue

            session_id = uuid.uuid4().hex[:12]

            console.print()
            console.print(Panel(
                f"  TTP      : [cmd]{aid}[/cmd]  {chosen['tech_name']}\n"
                f"  module   : [dim]{meow_slug}[/dim]\n"
                f"  platform : {chosen['platform']}\n"
                f"  session  : [dim]{session_id}[/dim]",
                title="[heading] Build [/heading]",
                border_style="bright_cyan",
                box=box.ROUNDED,
            ))
            console.print()

            t0 = datetime.now()
            ok, log, out_path = _compiler.compile_module(mod["id"], session_id)
            elapsed = (datetime.now() - t0).total_seconds()

            _render_build_log(log, ok)

            status = "success" if ok else "failed"
            if ok and out_path:
                size_kb = out_path.stat().st_size // 1024
                console.print(Panel(
                    f"  [ok]BUILD OK[/ok]  {out_path.name}  {size_kb} KB  ({elapsed:.1f}s)\n"
                    f"  path: [dim]{out_path}[/dim]",
                    title="[heading] Result [/heading]",
                    border_style="bright_green",
                    box=box.ROUNDED,
                ))
            else:
                console.print(Panel(
                    f"  [err]BUILD FAILED[/err]  ({elapsed:.1f}s)",
                    title="[heading] Result [/heading]",
                    border_style="err",
                    box=box.ROUNDED,
                ))

            _db.save_build({
                "id":         session_id,
                "params":     {"malware": "ttp", "attack_id": aid, "meow_slug": meow_slug},
                "status":     status,
                "output":     log,
                "returncode": 0 if ok else 1,
                "created":    t0.isoformat(),
                "start_time": t0.isoformat(),
                "end_time":   datetime.now().isoformat(),
            })
            console.print()

        # -- refresh -------------------------------------------------------------
        elif cmd == "refresh":
            console.print("  [dim]seeding ttp_implementations...[/dim]")
            try:
                import mitre as _mitre
                n = _mitre.seed_ttp_implementations()
                all_rows[:] = _db.get_ttp_implementations()
                attack_ids[:] = sorted({r["attack_id"] for r in all_rows})
                tactics[:] = sorted({r["tactic"] for r in all_rows if r["tactic"]})
                n_techs2 = _db.count_ttp_techniques()
                n_impls2 = _db.count_ttp_implementations()
                console.print(
                    f"  [ok][=^..^=] seeded {n} rows  |  "
                    f"{n_techs2} techniques  {n_impls2} implementations[/ok]\n"
                )
            except Exception as ex:
                console.print(f"  [err][=^..^=] refresh failed: {ex}[/err]\n")

        else:
            console.print(
                f"[warn][=^..^=] unknown command: {cmd}  "
                f"(type  help  for commands)[/warn]"
            )


def run_builder() -> None:
    """Interactive builder sub-REPL."""
    try:
        import discovery as _disc
    except ImportError as exc:
        console.print(f"[err][=^..^=] discovery module unavailable: {exc}[/err]")
        return
    try:
        import compiler as _compiler
    except ImportError as exc:
        console.print(f"[err][=^..^=] compiler module unavailable: {exc}[/err]")
        return
    try:
        import db as _db
    except ImportError as exc:
        console.print(f"[err][=^..^=] db module unavailable: {exc}[/err]")
        return

    with console.status("[info]scanning modules...[/info]", spinner="dots"):
        all_mods = [m for m in _disc.scan_all() if m.get("compilable", True)]

    slug_map: dict[str, dict] = {m["slug"]: m for m in all_mods}
    all_slugs = sorted(slug_map.keys())

    # stealer + persistence discovery (malware/stealer/ and malware/persistence/)
    _mal_dir      = Path(__file__).parent / "malware"
    _stealer_dir  = _mal_dir / "stealer"
    _pers_dir     = _mal_dir / "persistence"
    stealer_names = sorted(f.stem for f in _stealer_dir.glob("*.c")) if _stealer_dir.exists() else []
    pers_names    = sorted(f.stem for f in _pers_dir.glob("*.c"))    if _pers_dir.exists()  else []
    stealer_set   = set(stealer_names)

    _PERS_DESC = {
        "registry_run":    "HKCU\\Run key  (user-level, no elevation needed)",
        "screensaver":     "Screensaver hijack  (HKCU\\Control Panel\\Desktop)",
        "filetype_hijack": "File type association hijack  (HKCU\\Classes)",
        "winlogon":        "Winlogon Shell/Userinit  (requires SYSTEM privileges)",
    }

    session = _make_session(BUILDER_COMMANDS + all_slugs + stealer_names + pers_names)

    win_n = sum(1 for m in all_mods if m["platform"] == "windows")
    lin_n = sum(1 for m in all_mods if m["platform"] == "linux")

    console.print()
    console.print(Panel(
        f"  {len(all_mods)} compilable modules  |  "
        f"{win_n} Windows  {lin_n} Linux\n"
        f"  {len(stealer_names)} stealers  |  {len(pers_names)} persistence mechanisms\n"
        f"  type  help  for commands,  list  to browse,  back  to return",
        title="[heading] Builder [/heading]",
        border_style="bright_cyan",
        box=box.ROUNDED,
    ))
    console.print()

    current_view: list[dict] = all_mods
    current_title = "Compilable Modules"
    current_page  = 0
    total_pages   = 0

    while True:
        try:
            raw = session.prompt("peekaboo [builder] > ", style=PT_STYLE).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]use  back  to return[/dim]")
            continue

        if not raw:
            if total_pages > 1 and current_page + 1 < total_pages:
                current_page += 1
                total_pages = _render_build_table(
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
            show_help("builder", args[0] if args else None)

        # -- list [filter] ----------------------------------------------------
        elif cmd == "list":
            if args:
                f = args[0].lower()
                if f == "stealer":
                    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                              border_style="bright_black", padding=(0, 1),
                              title=f"Stealers  ({len(stealer_names)})")
                    t.add_column("#",       style="dim", min_width=3,  justify="right")
                    t.add_column("name",    style="cmd", min_width=18)
                    t.add_column("source",  style="dim", min_width=26)
                    for i, n in enumerate(stealer_names, 1):
                        t.add_row(str(i), n, f"malware/stealer/{n}.c")
                    console.print()
                    console.print(t)
                    console.print(
                        f"  [dim]use  build <name>  to compile with persistence choice[/dim]\n"
                    )
                    continue
                elif f == "persistence":
                    t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                              border_style="bright_black", padding=(0, 1),
                              title=f"Persistence Mechanisms  ({len(pers_names)})")
                    t.add_column("#",           style="dim",  min_width=3,  justify="right")
                    t.add_column("name",        style="cmd",  min_width=18)
                    t.add_column("description", style="dim",  min_width=46)
                    t.add_column("source",      style="dim",  min_width=28)
                    for i, n in enumerate(pers_names, 1):
                        t.add_row(str(i), n, _PERS_DESC.get(n, ""), f"malware/persistence/{n}.c")
                    console.print()
                    console.print(t)
                    console.print(
                        f"  [dim]persistence is selected automatically during  build <stealer>[/dim]\n"
                    )
                    continue
                elif f in ("windows", "linux", "macos"):
                    current_view = [m for m in all_mods if m["platform"] == f]
                    current_title = f"Compilable Modules: platform={f}"
                else:
                    current_view = [m for m in all_mods
                                    if f in m["category"].lower()]
                    current_title = f"Compilable Modules: category~{f}"
                if not current_view:
                    console.print(
                        f"  [warn][=^..^=] no compilable modules matching '{f}'[/warn]\n"
                    )
                    continue
            else:
                current_view  = all_mods
                current_title = "Compilable Modules"
            current_page = 0
            total_pages  = _render_build_table(
                current_view, current_title, current_page
            )

        # -- search -----------------------------------------------------------
        elif cmd == "search":
            if not args:
                console.print("[warn][=^..^=] usage: search <query>[/warn]")
                continue
            q = " ".join(args).lower()

            # search stealers
            st_hits = [n for n in stealer_names if q in n]
            if st_hits:
                t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                          border_style="bright_black", padding=(0, 1),
                          title=f"Stealer Matches  ({len(st_hits)})")
                t.add_column("#",    style="dim", min_width=3, justify="right")
                t.add_column("name", style="cmd", min_width=18)
                t.add_column("source", style="dim", min_width=26)
                for i, n in enumerate(st_hits, 1):
                    t.add_row(str(i), n, f"malware/stealer/{n}.c")
                console.print()
                console.print(t)
                console.print(
                    f"  [dim]use  build <name>  to compile with persistence choice[/dim]\n"
                )

            # search meow modules
            hits = [
                m for m in all_mods
                if q in m["slug"].lower()
                or q in m["title"].lower()
                or q in m["category"].lower()
                or any(q in tid.lower() for tid in m["attack_ids"])
            ]
            if hits:
                current_view  = hits
                current_title = f"Search: {q}"
                current_page  = 0
                total_pages   = _render_build_table(
                    current_view, current_title, current_page
                )
            elif not st_hits:
                console.print(f"  [warn][=^..^=] no results for '{q}'[/warn]\n")

        # -- build <slug> -----------------------------------------------------
        elif cmd == "build":
            if not args:
                console.print("[warn][=^..^=] usage: build <slug>  (or: build <stealer-name>)[/warn]")
                continue
            slug = args[0]

            # partial stealer name match (e.g. "viru" -> "virustotal")
            if slug not in stealer_set:
                st_matches = [n for n in stealer_names if slug in n]
                if len(st_matches) == 1:
                    slug = st_matches[0]
                elif len(st_matches) > 1:
                    console.print(
                        f"  [warn][=^..^=] ambiguous stealer '{slug}': "
                        f"{', '.join(st_matches)}[/warn]\n"
                    )
                    continue

            # -- stealer build path -------------------------------------------
            if slug in stealer_set:
                console.print()
                # persistence selection table
                t = Table(box=box.ROUNDED, show_header=True, header_style="bold bright_white on bright_black",
                          border_style="bright_black", padding=(0, 1),
                          title="Persistence Mechanisms")
                t.add_column("#",    style="dim", min_width=3, justify="right")
                t.add_column("name", style="cmd", min_width=18)
                t.add_column("description", style="dim", min_width=46)
                for i, pn in enumerate(pers_names, 1):
                    t.add_row(str(i), pn, _PERS_DESC.get(pn, ""))
                t.add_row(str(len(pers_names) + 1), "none", "skip persistence")
                console.print(t)
                console.print()

                try:
                    pers_raw = session.prompt(
                        "  persistence [registry_run]: ", style=PT_STYLE
                    ).strip().lower()
                except (KeyboardInterrupt, EOFError):
                    console.print("\n[dim]build cancelled[/dim]\n")
                    continue
                pers_choice = pers_raw if pers_raw in pers_names else (
                    None if pers_raw == "none" else "registry_run"
                )

                session_id = uuid.uuid4().hex[:12]
                build_id   = f"cli-{uuid.uuid4().hex[:8]}"
                start_t    = datetime.now()

                # compile stealer
                console.print()
                with console.status(
                    f"[info]compiling stealer: {slug}...[/info]", spinner="dots"
                ):
                    s_ok, s_log, s_out = _compiler.compile_stealer(slug, session_id)
                end_t = datetime.now()
                _render_build_log(s_log, s_ok)

                p_ok, p_log, p_out = True, "", None
                if s_ok and pers_choice:
                    with console.status(
                        f"[info]compiling persistence: {pers_choice}...[/info]",
                        spinner="dots"
                    ):
                        p_ok, p_log, p_out = _compiler.compile_persistence(
                            pers_choice, s_out.parent
                        )
                    _render_build_log(p_log, p_ok)

                elapsed = (datetime.now() - start_t).total_seconds()

                if s_ok:
                    s_size = s_out.stat().st_size if s_out and s_out.exists() else 0
                    p_size = p_out.stat().st_size if p_out and p_out.exists() else 0
                    body = (
                        f"  peekaboo.exe   : {s_out}  ({s_size:,} bytes)\n"
                        + (f"  persistence.exe: {p_out}  ({p_size:,} bytes)\n"
                           if p_out else "")
                        + f"  Time           : {elapsed:.2f}s"
                    )
                    console.print(Panel(body,
                                        title="[ok] BUILD OK [/ok]",
                                        border_style="bright_green", box=box.ROUNDED))
                    console.print()

                    # deployment instructions
                    pers_note = pers_choice or "none"
                    priv_note = ""
                    if pers_choice == "winlogon":
                        priv_note = "\n  [warn]note: winlogon requires SYSTEM/admin privileges[/warn]"
                    instr = (
                        f"  1. drop files to target machine:\n"
                        f"       peekaboo.exe     - stealer ({slug})\n"
                        + (f"       persistence.exe  - persistence installer ({pers_note})\n"
                           if p_out else "")
                        + f"  2. run stealer: peekaboo.exe\n"
                        + (f"  3. run persistence: persistence.exe\n"
                           f"       (optionally: persistence.exe C:\\Users\\Public\\peekaboo.exe)\n"
                           if p_out else "")
                        + priv_note
                    )
                    console.print(Panel(instr,
                                        title="[heading] Deployment Instructions [/heading]",
                                        border_style="bright_black", box=box.ROUNDED))
                else:
                    console.print(Panel(
                        f"  Stealer  : {slug}\n"
                        f"  Elapsed  : {elapsed:.2f}s\n"
                        f"  [dim]Check log above for error details[/dim]",
                        title="[err] BUILD FAILED [/err]",
                        border_style="err", box=box.ROUNDED,
                    ))

                console.print()

                try:
                    _db.save_build({
                        "id":         build_id,
                        "params":     {
                            "malware":     "stealer",
                            "stealer":     slug,
                            "persistence": pers_choice or "none",
                            "out_path":    str(s_out.relative_to(Path(__file__).parent)) if s_ok and s_out else None,
                            "pers_path":   str(p_out.relative_to(Path(__file__).parent)) if p_ok and p_out and p_out.exists() else None,
                        },
                        "status":     "success" if s_ok else "failed",
                        "output":     s_log + ("\n" + p_log if p_log else ""),
                        "returncode": 0 if s_ok else 1,
                        "created":    start_t.isoformat(),
                        "start_time": start_t.isoformat(),
                        "end_time":   end_t.isoformat(),
                    })
                    console.print(f"  [dim]build saved: {build_id}[/dim]\n")
                except Exception as exc:
                    console.print(f"  [warn][=^..^=] db save error: {exc}[/warn]\n")
                continue

            # -- meow module path ---------------------------------------------
            mod = slug_map.get(slug)
            if not mod:
                matches = [s for s in slug_map if slug in s]
                if len(matches) == 1:
                    slug = matches[0]
                    mod  = slug_map[slug]
                elif len(matches) > 1:
                    console.print(
                        f"  [warn][=^..^=] ambiguous '{slug}': "
                        f"{', '.join(matches[:5])}"
                        f"{'...' if len(matches) > 5 else ''}[/warn]\n"
                    )
                    continue
                else:
                    console.print(f"  [err][=^..^=] module not found: '{slug}'[/err]\n")
                    continue

            # pre-build summary
            console.print()
            console.print(Panel(
                f"  Slug     : {mod['slug']}\n"
                f"  Title    : {mod['title']}\n"
                f"  Platform : {mod['platform']}\n"
                f"  Compiler : {mod['compiler']}\n"
                f"  Source   : {mod['src_path']}",
                title="[heading] Build: Pre-flight [/heading]",
                border_style="bright_cyan", box=box.ROUNDED,
            ))
            console.print()

            session_id = uuid.uuid4().hex[:12]
            build_id   = f"cli-{uuid.uuid4().hex[:8]}"
            start_t    = datetime.now()

            with console.status(
                f"[info]compiling {mod['slug']} ({mod['compiler']})...[/info]",
                spinner="dots"
            ):
                ok, log, out_path = _compiler.compile_module(mod["id"], session_id)

            end_t   = datetime.now()
            elapsed = (end_t - start_t).total_seconds()

            _render_build_log(log, ok)

            if ok:
                out_size = out_path.stat().st_size if out_path and out_path.exists() else 0
                console.print(Panel(
                    f"  Output : {out_path}\n"
                    f"  Size   : {out_size:,} bytes  ({out_size//1024} KB)\n"
                    f"  Time   : {elapsed:.2f}s",
                    title="[ok] BUILD OK [/ok]",
                    border_style="bright_green", box=box.ROUNDED,
                ))
            else:
                console.print(Panel(
                    f"  Slug     : {mod['slug']}\n"
                    f"  Compiler : {mod['compiler']}\n"
                    f"  Elapsed  : {elapsed:.2f}s\n"
                    f"  [dim]Check log above for error details[/dim]",
                    title="[err] BUILD FAILED [/err]",
                    border_style="err", box=box.ROUNDED,
                ))

            console.print()

            # save to db
            try:
                _db.save_build({
                    "id":         build_id,
                    "params":     {
                        "slug":     mod["slug"],
                        "platform": mod["platform"],
                        "compiler": mod["compiler"],
                        "out_path": str(out_path.relative_to(Path(__file__).parent)) if ok and out_path else None,
                    },
                    "status":     "success" if ok else "failed",
                    "output":     log,
                    "returncode": 0 if ok else 1,
                    "created":    start_t.isoformat(),
                    "start_time": start_t.isoformat(),
                    "end_time":   end_t.isoformat(),
                })
                console.print(f"  [dim]build saved: {build_id}[/dim]\n")
            except Exception as exc:
                console.print(f"  [warn][=^..^=] db save error: {exc}[/warn]\n")

        # -- history [N] ------------------------------------------------------
        elif cmd == "history":
            limit = 20
            if args:
                try:
                    limit = max(1, min(int(args[0]), 100))
                except ValueError:
                    console.print("[warn][=^..^=] usage: history [N]  (N is a number)[/warn]")
                    continue
            try:
                builds = _db.get_builds(limit)
                _render_history_table(builds)
            except Exception as exc:
                console.print(f"  [err][=^..^=] db error: {exc}[/err]\n")

        # -- clear ------------------------------------------------------------
        elif cmd == "clear":
            console.print(
                "\n  [warn]This will delete ALL build history from the database[/warn]\n"
                "  [warn]and ALL compiled binaries (peekaboo.exe / persistence.exe)[/warn]\n"
                "  [warn]from the malware/ directory tree.[/warn]\n"
            )
            try:
                confirm = session.prompt("  Type  yes  to confirm: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                console.print("  [dim]cancelled[/dim]\n")
                continue
            if confirm != "yes":
                console.print("  [dim]cancelled[/dim]\n")
                continue
            try:
                _db.clear_builds()
            except Exception as exc:
                console.print(f"  [err][=^..^=] db error: {exc}[/err]\n")
                continue
            deleted = []
            for pattern in ("peekaboo.exe", "persistence.exe"):
                for f in _mal_dir.rglob(pattern):
                    try:
                        f.unlink()
                        deleted.append(f)
                    except Exception:
                        pass
            console.print(
                f"  [ok][=^..^=] build history cleared  |  "
                f"{len(deleted)} binary file{'s' if len(deleted) != 1 else ''} deleted[/ok]\n"
            )

        # -- show <build-id> --------------------------------------------------
        elif cmd == "show":
            if not args:
                console.print("[warn][=^..^=] usage: show <build-id>[/warn]")
                continue
            bid = args[0]
            try:
                b = _db.get_build(bid)
            except Exception as exc:
                console.print(f"  [err][=^..^=] db error: {exc}[/err]\n")
                continue
            if not b:
                # try prefix match from recent builds
                try:
                    recent = _db.get_builds(100)
                    matches = [x for x in recent if x["id"].startswith(bid)]
                    if len(matches) == 1:
                        b = matches[0]
                    elif len(matches) > 1:
                        console.print(
                            f"  [warn][=^..^=] ambiguous id prefix '{bid}': "
                            f"{', '.join(x['id'] for x in matches[:4])}[/warn]\n"
                        )
                        continue
                    else:
                        console.print(f"  [err][=^..^=] build not found: '{bid}'[/err]\n")
                        continue
                except Exception as exc:
                    console.print(f"  [err][=^..^=] db error: {exc}[/err]\n")
                    continue
            _render_build_detail(b)

        else:
            console.print(
                f"[warn][=^..^=] unknown command: {cmd}  "
                f"(type  help  for commands)[/warn]"
            )


# -- VirusTotal scanner --------------------------------------------------------

VTSCAN_COMMANDS = ["list", "scan", "scan-file", "poll", "lookup", "help", "back"]

VTSCAN_HELP = [
    ("list",             "list successful builds with binaries available on disk"),
    ("scan <build-id>",  "upload build binary to VirusTotal and show results"),
    ("scan-file <path>", "upload any local PE/binary file to VirusTotal"),
    ("poll <id>",        "check status of a pending analysis by ID"),
    ("lookup <sha256>",  "fetch existing VT report by SHA256 hash"),
    ("help",             "show this help"),
    ("back",             "return to main menu"),
]


def _vtscan_resolve_binary(build: dict) -> Path | None:
    """Resolve the primary compiled binary path for a DB build record."""
    params = build.get("params", {})
    stored = params.get("out_path", "")
    if stored:
        base = Path(__file__).parent
        p = Path(stored) if Path(stored).is_absolute() else base / stored
        if p.exists():
            return p
    malware_type = params.get("malware", "")
    base = Path(__file__).parent
    if malware_type == "stealer":
        p = base / "malware" / "stealer" / params.get("stealer", "") / "peekaboo.exe"
    elif "injection" in params or malware_type == "injection":
        p = base / "malware" / "injection" / params.get("injection", "") / "peekaboo.exe"
    else:
        return None
    return p if p.exists() else None


def _vtscan_resolve_files(build: dict) -> list:
    """Return list of (name, Path) tuples for all compiled binaries in a build."""
    p = _vtscan_resolve_binary(build)
    if not p:
        return []
    files = [(p.name, p)]
    pers = p.parent / "persistence.exe"
    if pers.exists():
        files.append(("persistence.exe", pers))
    return files


def _vtscan_render_results(r: dict, label: str) -> None:
    stats = r.get("stats", {})
    results = r.get("results", {})
    mal  = stats.get("malicious",   0)
    sus  = stats.get("suspicious",  0)
    cln  = stats.get("harmless", 0) + stats.get("clean", 0)
    undet = stats.get("undetected", 0)
    total = mal + sus + cln + undet + stats.get("failure", 0) + stats.get("type_unsupported", 0)
    rate  = round(mal / total * 100) if total > 0 else 0
    rate_style = "err" if rate > 50 else "warn" if rate > 15 else "ok"

    summary = (
        f"  [err]Malicious   :[/err]  {mal}\n"
        f"  [warn]Suspicious  :[/warn]  {sus}\n"
        f"  [ok]Clean       :[/ok]  {cln}\n"
        f"  [dim]Undetected  :[/dim]  {undet}\n"
        f"  [dim]Total engines:[/dim] {total}\n"
        f"  [{rate_style}]Detection rate: {rate}%[/{rate_style}]"
    )
    border = "err" if rate > 50 else "warn" if rate > 15 else "bright_green"
    console.print()
    console.print(Panel(summary, title=f"[heading] VT: {label} [/heading]",
                        border_style=border, box=box.ROUNDED))

    if results:
        t = Table(box=box.ROUNDED, show_header=True,
                  header_style="bold bright_white on bright_black",
                  border_style="bright_black", padding=(0, 1))
        t.add_column("engine",   style="cmd",  no_wrap=True, min_width=20)
        t.add_column("category", style="info", min_width=12)
        t.add_column("result",   style="warn", min_width=20)
        detections = sorted(
            ((eng, v) for eng, v in results.items() if v.get("category") in ("malicious", "suspicious")),
            key=lambda x: x[0].lower()
        )
        for eng, v in detections[:40]:
            cat    = v.get("category", "")
            result_name = v.get("result") or "-"
            sty    = "err" if cat == "malicious" else "warn"
            t.add_row(eng, f"[{sty}]{cat}[/{sty}]", result_name)
        if detections:
            console.print()
            console.print(t)
    console.print()


def run_vtscan() -> None:
    """Interactive VirusTotal scanner sub-REPL."""
    try:
        import vtscan as _vt
    except ImportError as exc:
        console.print(f"[err][=^..^=] vtscan module unavailable: {exc}[/err]")
        return
    try:
        import db as _db
    except ImportError as exc:
        console.print(f"[err][=^..^=] db module unavailable: {exc}[/err]")
        return

    builds     = _db.get_builds(limit=200)
    build_ids  = [b["id"] for b in builds if b.get("status") == "success"]
    session    = _make_session(VTSCAN_COMMANDS + build_ids,
                               path_cmds=frozenset({"scan-file"}))

    console.print()
    console.print(Panel(
        "  Scan compiled binaries or any local file with 70+ AV/EDR engines\n"
        "  type  help  for commands,  list  to browse builds,  back  to return",
        title="[heading] VirusTotal Scanner [/heading]",
        border_style="bright_cyan",
        box=box.ROUNDED,
    ))
    console.print()

    while True:
        try:
            raw = session.prompt("peekaboo [vtscan] > ", style=PT_STYLE).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]use  back  to return[/dim]")
            continue

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        if cmd in ("back", "exit", "quit"):
            break

        elif cmd == "help":
            if args:
                show_help("vtscan", args[0])
            else:
                show_help("vtscan")

        elif cmd == "list":
            fresh = _db.get_builds(limit=50)
            t = Table(box=box.ROUNDED, show_header=True,
                      header_style="bold bright_white on bright_black",
                      border_style="bright_black", padding=(0, 1))
            t.add_column("build-id",  style="cmd",  no_wrap=True, min_width=14)
            t.add_column("type",      style="info",  min_width=10)
            t.add_column("module",    style="info",  min_width=18)
            t.add_column("date",      style="dim",   min_width=16)
            t.add_column("binaries",  style="ok",    min_width=30)
            shown = 0
            for b in fresh:
                if b.get("status") != "success":
                    continue
                files = _vtscan_resolve_files(b)
                pa    = b.get("params", {})
                pa_slug = pa.get("slug")
                if pa_slug:
                    mod = pa_slug
                elif pa.get("malware") == "stealer":
                    mod = pa.get("stealer") or "?"
                else:
                    mod = pa.get("injection") or "?"
                mtype   = "module" if pa_slug else (pa.get("malware") or "-")
                bin_txt = "  ".join(n for n, _ in files) if files else "[dim]not on disk[/dim]"
                t.add_row(b["id"], mtype, mod, (b.get("created") or "")[:16], bin_txt)
                shown += 1
            if shown:
                console.print()
                console.print(t)
                console.print()
            else:
                console.print("  [dim]no successful builds found[/dim]\n")

        elif cmd == "scan":
            if not args:
                console.print("  [warn]usage: scan <build-id> [filename][/warn]\n")
                continue
            build_id = args[0]
            want_fname = args[1] if len(args) > 1 else None
            build = _db.get_build(build_id)
            if not build:
                console.print(f"  [err][=^..^=] build not found: {build_id}[/err]\n")
                continue
            if build.get("status") != "success":
                console.print(f"  [warn][=^..^=] build status is '{build.get('status')}', not success[/warn]\n")
                continue
            files = _vtscan_resolve_files(build)
            if not files:
                console.print(f"  [err][=^..^=] no binaries found on disk for build {build_id}[/err]\n")
                continue
            if want_fname:
                # exact filename match (case-insensitive)
                match = [(n, p) for n, p in files if n.lower() == want_fname.lower()]
                if not match:
                    avail = "  ".join(n for n, _ in files)
                    console.print(f"  [err][=^..^=] '{want_fname}' not found; available: {avail}[/err]\n")
                    continue
                p = match[0][1]
            elif len(files) > 1:
                # multiple binaries - show list and ask user to specify
                console.print()
                for i, (n, fp2) in enumerate(files, 1):
                    console.print(f"  [{i}] [cmd]{n}[/cmd]  [dim]{fp2.stat().st_size:,} bytes[/dim]")
                console.print(f"\n  Use  [cmd]scan {build_id} <filename>[/cmd]  to pick one.\n")
                continue
            else:
                p = files[0][1]
            console.print(f"  [dim]uploading {p.name} ({p.stat().st_size:,} bytes)…[/dim]")
            with console.status("[info]contacting VirusTotal…[/info]", spinner="dots"):
                r = _vt.upload_file(p)
            if not r.get("ok"):
                console.print(f"  [err][=^..^=] {r.get('error', 'unknown error')}[/err]\n")
                continue
            if r.get("cached"):
                console.print("  [dim](cached result)[/dim]")
                _vtscan_render_results(r, p.name)
            else:
                aid = r.get("analysis_id", "")
                console.print(Panel(
                    f"  File uploaded successfully.\n"
                    f"  Analysis ID : [cmd]{aid}[/cmd]\n"
                    f"  SHA256      : [dim]{r.get('sha256', '?')}[/dim]\n\n"
                    f"  Run  [cmd]poll {aid}[/cmd]  to check when analysis is complete\n"
                    f"  (VirusTotal typically takes 1-3 minutes)",
                    title="[heading] Uploaded [/heading]",
                    border_style="bright_cyan", box=box.ROUNDED,
                ))
                console.print()

        elif cmd == "scan-file":
            if not args:
                console.print("  [warn]usage: scan-file <path>[/warn]\n")
                continue
            fp = Path(args[0]).expanduser()
            if not fp.exists():
                console.print(f"  [err][=^..^=] file not found: {fp}[/err]\n")
                continue
            console.print(f"  [dim]uploading {fp.name} ({fp.stat().st_size:,} bytes)…[/dim]")
            with console.status("[info]contacting VirusTotal…[/info]", spinner="dots"):
                r = _vt.upload_file(fp)
            if not r.get("ok"):
                console.print(f"  [err][=^..^=] {r.get('error', 'unknown error')}[/err]\n")
                continue
            if r.get("cached"):
                console.print("  [dim](cached result)[/dim]")
                _vtscan_render_results(r, fp.name)
            else:
                aid = r.get("analysis_id", "")
                console.print(Panel(
                    f"  File uploaded successfully.\n"
                    f"  Analysis ID : [cmd]{aid}[/cmd]\n"
                    f"  SHA256      : [dim]{r.get('sha256', '?')}[/dim]\n\n"
                    f"  Run  [cmd]poll {aid}[/cmd]  to check when analysis is complete",
                    title="[heading] Uploaded [/heading]",
                    border_style="bright_cyan", box=box.ROUNDED,
                ))
                console.print()

        elif cmd == "poll":
            if not args:
                console.print("  [warn]usage: poll <analysis-id>[/warn]\n")
                continue
            with console.status("[info]polling VirusTotal…[/info]", spinner="dots"):
                r = _vt.poll_analysis(args[0])
            if not r.get("ok"):
                console.print(f"  [err][=^..^=] {r.get('error', 'unknown error')}[/err]\n")
                continue
            status = r.get("status", "?")
            if status == "completed":
                _vtscan_render_results(r, args[0])
            else:
                console.print(
                    f"  [warn]status: {status}[/warn]  "
                    f"(analysis still in progress - try again in a moment)\n"
                )

        elif cmd == "lookup":
            if not args:
                console.print("  [warn]usage: lookup <sha256>[/warn]\n")
                continue
            with console.status("[info]fetching from VirusTotal…[/info]", spinner="dots"):
                r = _vt.get_by_hash(args[0])
            if not r.get("ok"):
                console.print(f"  [err][=^..^=] {r.get('error', 'unknown error')}[/err]\n")
                continue
            _vtscan_render_results(r, r.get("name") or args[0][:16])

        else:
            console.print(
                f"  [warn][=^..^=] unknown command: {cmd}  "
                f"(type  help  for commands)[/warn]\n"
            )


# ══════════════════════════════════════════════════════════════════════════════
# Hell's Gate / Direct Syscall Lab sub-REPL
# ══════════════════════════════════════════════════════════════════════════════

HG_COMMANDS = ["scan", "filter", "search", "show", "select", "select-all",
               "select-hooked", "select-common", "deselect-all",
               "generate", "save", "help", "back"]

_HG_COMMON = [
    "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory",
    "NtCreateThreadEx", "NtOpenProcess", "NtReadVirtualMemory",
    "NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection",
    "NtQueueApcThread", "NtResumeThread", "NtSuspendThread",
    "NtClose", "NtWaitForSingleObject", "NtQuerySystemInformation",
    "NtQueryInformationProcess", "NtSetInformationThread",
    "NtFreeVirtualMemory", "NtTerminateProcess",
]

_HG_HOOK_STYLE = {
    "clean":        "good",
    "jmp_hook":     "err",
    "int3_hook":    "err",
    "ind_jmp_hook": "high",
    "push_ret_hook":"high",
    "partial_hook": "medium",
    "deep_hook":    "medium",
    "unknown_hook": "warn",
    "unknown":      "dim",
}

_HG_METHOD_STYLE = {
    "direct":       "good",
    "halos_gate":   "medium",
    "tartarus_gate":"warn",
}


def _hg_render_table(entries: list[dict], selected: set[str],
                     page: int = 0) -> None:
    start = page * PAGE_SIZE
    chunk = entries[start : start + PAGE_SIZE]
    if not chunk:
        console.print("  [dim]no entries to show[/dim]\n")
        return

    t = Table(box=box.ROUNDED, show_header=True,
              header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1))
    t.add_column("*",        width=2, no_wrap=True)
    t.add_column("Function", style="cmd",  min_width=30, no_wrap=True)
    t.add_column("SSN",      style="info", min_width=6,  no_wrap=True)
    t.add_column("Method",   min_width=12, no_wrap=True)
    t.add_column("Hook",     min_width=14, no_wrap=True)
    t.add_column("Stub (first 8 bytes)", style="dim", min_width=24)

    for e in chunk:
        name  = e["name"]
        ssn   = f"0x{e['ssn']:04X}" if e.get("ssn") is not None else "?"
        meth  = e.get("ssn_method", "direct")
        hook  = e.get("hook_type",  "unknown")
        stub  = " ".join(e.get("stub_hex", "").split()[:8])
        check = "[ok]✓[/ok]" if name in selected else " "
        hs    = _HG_HOOK_STYLE.get(hook, "dim")
        ms    = _HG_METHOD_STYLE.get(meth, "dim")
        t.add_row(check, name, ssn,
                  f"[{ms}]{meth}[/{ms}]",
                  f"[{hs}]{hook}[/{hs}]",
                  stub)

    console.print()
    console.print(t)
    total = len(entries)
    pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
    console.print(f"  [dim]page {page+1}/{pages}  ({total} entries)  "
                  f"[ok]{len(selected)} selected[/ok][/dim]\n")


def run_hellsgate() -> None:
    """Interactive Hell's Gate / Direct Syscall Lab sub-REPL."""
    session = _make_session(HG_COMMANDS, path_cmds=frozenset({"scan", "save"}))

    scan_result: dict | None = None
    entries:     list[dict]  = []
    filtered:    list[dict]  = []
    selected:    set[str]    = set()
    generated:   str         = ""
    _filter      = "all"
    _search      = ""
    _page        = 0

    console.print()
    console.print(Panel(
        "  Extract SSNs from ntdll.dll · detect EDR hooks · Halo's/Tartarus Gate recovery\n"
        "  generate NASM x64 or C __declspec(naked) direct-syscall stubs\n"
        "  type  help  for commands,  back  to return",
        title="[heading] Hell's Gate - Direct Syscall Lab [/heading]",
        border_style="bright_cyan", box=box.ROUNDED,
    ))
    console.print()

    def _apply_filter() -> None:
        nonlocal filtered, _page
        _page = 0
        result = entries
        if _filter == "clean":
            result = [e for e in entries if e.get("hook_type") == "clean"]
        elif _filter == "hooked":
            result = [e for e in entries if e.get("hook_type") != "clean"]
        if _search:
            q = _search.lower()
            result = [e for e in result if q in e["name"].lower()]
        filtered = result

    while True:
        prompt = "peekaboo [hellsgate] > "
        try:
            raw = session.prompt(prompt, style=PT_STYLE).strip()
        except KeyboardInterrupt:
            console.print("\n[dim]use  back  to return[/dim]")
            continue
        except EOFError:
            break

        if not raw:
            continue
        parts = raw.split(None, 2)
        cmd   = parts[0].lower()
        arg   = parts[1].strip() if len(parts) > 1 else ""
        arg2  = parts[2].strip() if len(parts) > 2 else ""

        if cmd in ("back", "exit", "quit"):
            break

        elif cmd == "help":
            show_help("hellsgate", arg or None)

        elif cmd == "scan":
            if not arg:
                console.print("  [warn]usage: scan <path/to/ntdll.dll>[/warn]\n")
                continue
            p = Path(arg).expanduser()
            if not p.exists():
                console.print(f"  [err][=^..^=] file not found: {p}[/err]\n")
                continue
            with console.status("[info]scanning ntdll.dll…[/info]", spinner="dots"):
                try:
                    from hellsgate import scan as _hg_scan
                    scan_result = _hg_scan(p)
                except Exception as e:
                    console.print(f"  [err][=^..^=] {e}[/err]\n")
                    continue
            if not scan_result.get("ok"):
                console.print(f"  [err][=^..^=] {scan_result.get('error')}[/err]\n")
                scan_result = None
                continue
            entries  = scan_result.get("entries", [])
            selected = set()
            generated = ""
            _filter = "all"
            _search = ""
            _apply_filter()
            hooked = scan_result.get("hooked", 0)
            total  = scan_result.get("total",  0)
            clean  = scan_result.get("clean",  0)
            console.print()
            console.print(Panel(
                f"  [ok]Total  :[/ok] {total}\n"
                f"  [good]Clean  :[/good] {clean}\n"
                f"  [err]Hooked :[/err] {hooked}",
                title=f"[heading] {p.name} [/heading]",
                border_style="bright_black", box=box.ROUNDED,
            ))
            _hg_render_table(filtered, selected)

        elif cmd == "filter":
            if arg not in ("all", "clean", "hooked"):
                console.print("  [warn]usage: filter all|clean|hooked[/warn]\n")
                continue
            _filter = arg
            _apply_filter()
            _hg_render_table(filtered, selected)

        elif cmd == "search":
            _search = arg
            _apply_filter()
            _hg_render_table(filtered, selected)

        elif cmd == "show":
            if not entries:
                console.print("  [dim]no scan loaded - use  scan <ntdll.dll>[/dim]\n")
                continue
            try:
                _page = max(0, int(arg) - 1) if arg else _page
            except ValueError:
                _page = 0
            _hg_render_table(filtered, selected, _page)

        elif cmd == "select":
            if not arg:
                console.print("  [warn]usage: select <FuncName> [FuncName2…][/warn]\n")
                continue
            names = raw.split()[1:]
            valid = {e["name"] for e in entries}
            for n in names:
                if n in valid:
                    selected.add(n)
                else:
                    console.print(f"  [warn]{n} not found in scan[/warn]")
            console.print(f"  [ok]{len(selected)} functions selected[/ok]\n")

        elif cmd == "select-all":
            selected = {e["name"] for e in filtered}
            console.print(f"  [ok]{len(selected)} functions selected[/ok]\n")

        elif cmd == "select-hooked":
            selected = {e["name"] for e in entries if e.get("hook_type") != "clean"}
            console.print(f"  [ok]{len(selected)} hooked functions selected[/ok]\n")

        elif cmd == "select-common":
            valid = {e["name"] for e in entries}
            selected = {n for n in _HG_COMMON if n in valid}
            console.print(f"  [ok]{len(selected)} common injection APIs selected[/ok]\n")

        elif cmd == "deselect-all":
            selected = set()
            console.print("  [dim]selection cleared[/dim]\n")

        elif cmd == "generate":
            if not selected:
                console.print("  [warn]no functions selected - use  select-all  or  select-common[/warn]\n")
                continue
            lang = arg.lower() if arg else "nasm"
            if lang not in ("nasm", "c"):
                console.print("  [warn]usage: generate nasm|c[/warn]\n")
                continue
            fns = [e for e in entries if e["name"] in selected]
            try:
                from hellsgate import generate_asm as _hg_gen
                generated = _hg_gen(fns, lang)
            except Exception as e:
                console.print(f"  [err][=^..^=] {e}[/err]\n")
                continue
            lines = generated.splitlines()
            preview = "\n".join(lines[:40])
            if len(lines) > 40:
                preview += f"\n... ({len(lines) - 40} more lines)"
            console.print()
            console.print(Syntax(preview, "nasm" if lang == "nasm" else "c",
                                 theme="monokai", line_numbers=False,
                                 background_color="default"))
            console.print(f"\n  [ok]{len(fns)} stubs generated - use  save <path>  to write[/ok]\n")

        elif cmd == "save":
            if not generated:
                console.print("  [warn]nothing to save - run  generate  first[/warn]\n")
                continue
            if not arg:
                console.print("  [warn]usage: save <path>[/warn]\n")
                continue
            out = Path(arg).expanduser()
            try:
                out.write_text(generated)
                console.print(f"  [ok]saved → {out}[/ok]\n")
            except Exception as e:
                console.print(f"  [err][=^..^=] {e}[/err]\n")

        else:
            console.print(f"  [warn]unknown command: {cmd}  (type  help)[/warn]\n")


# ══════════════════════════════════════════════════════════════════════════════
# Shellcode Emulator sub-REPL
# ══════════════════════════════════════════════════════════════════════════════

SCEMU_COMMANDS = ["run", "hex", "disasm", "arch", "maxinsns",
                  "trace", "regs", "mem", "api", "strings", "smc",
                  "help", "back"]


def _scemu_render_result(r: dict) -> None:
    stop   = r.get("stop_reason", "?")
    insns  = r.get("insn_count",  0)
    smc    = r.get("smc",         False)
    api_n  = len(r.get("api_calls", []))
    strs   = r.get("strings",    [])
    smc_s  = "[err]YES[/err]" if smc else "[good]no[/good]"
    stop_s = f"[ok]{stop}[/ok]" if stop == "clean_exit" else f"[warn]{stop}[/warn]"
    console.print()
    console.print(Panel(
        f"  arch          : {r.get('arch','?')}\n"
        f"  instructions  : {insns}\n"
        f"  stop reason   : {stop_s}\n"
        f"  SMC detected  : {smc_s}\n"
        f"  API intercepts: {api_n}\n"
        f"  strings found : {len(strs)}",
        title="[heading] Emulation Result [/heading]",
        border_style="bright_cyan", box=box.ROUNDED,
    ))
    console.print()


def run_scemu() -> None:
    """Interactive Shellcode Emulator sub-REPL."""
    session = _make_session(SCEMU_COMMANDS, path_cmds=frozenset({"run", "disasm"}))

    result: dict | None = None
    _arch    = "x64"
    _maxinsns = 10000

    console.print()
    console.print(Panel(
        "  x86/x64 Unicorn Engine emulation · per-instruction trace · API intercept\n"
        "  SMC detection · string extraction · Capstone disassembly-only mode\n"
        "  type  help  for commands,  back  to return",
        title="[heading] Shellcode Emulator [/heading]",
        border_style="bright_cyan", box=box.ROUNDED,
    ))
    console.print()

    while True:
        try:
            raw = session.prompt(f"peekaboo [scemu/{_arch}] > ", style=PT_STYLE).strip()
        except KeyboardInterrupt:
            console.print("\n[dim]use  back  to return[/dim]")
            continue
        except EOFError:
            break

        if not raw:
            continue
        parts = raw.split(None, 1)
        cmd   = parts[0].lower()
        arg   = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("back", "exit", "quit"):
            break

        elif cmd == "help":
            show_help("scemu", arg or None)

        elif cmd == "arch":
            if arg not in ("x64", "x86"):
                console.print("  [warn]usage: arch x64|x86[/warn]\n")
                continue
            _arch = arg
            console.print(f"  [ok]arch set to {_arch}[/ok]\n")

        elif cmd == "maxinsns":
            try:
                n = max(100, min(50000, int(arg)))
                _maxinsns = n
                console.print(f"  [ok]max instructions set to {n}[/ok]\n")
            except ValueError:
                console.print("  [warn]usage: maxinsns <number>[/warn]\n")

        elif cmd == "run":
            if not arg:
                console.print("  [warn]usage: run <path>[/warn]\n")
                continue
            p = Path(arg).expanduser()
            if not p.exists():
                console.print(f"  [err][=^..^=] file not found: {p}[/err]\n")
                continue
            with console.status("[info]emulating…[/info]", spinner="dots"):
                try:
                    from sc_emulator import emulate as _emu
                    result = _emu(p.read_bytes(), arch=_arch, max_insns=_maxinsns)
                except Exception as e:
                    console.print(f"  [err][=^..^=] {e}[/err]\n")
                    continue
            if not result.get("ok"):
                console.print(f"  [err][=^..^=] {result.get('error')}[/err]\n")
                result = None
                continue
            _scemu_render_result(result)

        elif cmd == "hex":
            if not arg:
                console.print("  [warn]usage: hex <\\xNN\\xNN…>[/warn]\n")
                continue
            # parse: \xNN, 0xNN, or bare hex
            cleaned = arg.strip().strip('"\'')
            tokens  = re.findall(r'[0-9a-fA-F]{2}',
                                  cleaned.replace("\\x", "").replace("0x", "").replace(",", "").replace(" ", ""))
            if not tokens:
                console.print("  [err][=^..^=] could not parse hex bytes[/err]\n")
                continue
            raw_bytes = bytes(int(b, 16) for b in tokens)
            with console.status("[info]emulating…[/info]", spinner="dots"):
                try:
                    from sc_emulator import emulate as _emu
                    result = _emu(raw_bytes, arch=_arch, max_insns=_maxinsns)
                except Exception as e:
                    console.print(f"  [err][=^..^=] {e}[/err]\n")
                    continue
            if not result.get("ok"):
                console.print(f"  [err][=^..^=] {result.get('error')}[/err]\n")
                result = None
                continue
            _scemu_render_result(result)

        elif cmd == "disasm":
            if not arg:
                console.print("  [warn]usage: disasm <path>[/warn]\n")
                continue
            p = Path(arg).expanduser()
            if not p.exists():
                console.print(f"  [err][=^..^=] file not found: {p}[/err]\n")
                continue
            with console.status("[info]disassembling…[/info]", spinner="dots"):
                try:
                    import capstone
                    raw_b = p.read_bytes()
                    md    = capstone.Cs(capstone.CS_ARCH_X86,
                                        capstone.CS_MODE_64 if _arch == "x64"
                                        else capstone.CS_MODE_32)
                    insns = list(md.disasm(raw_b, 0x400000))[:200]
                except Exception as e:
                    console.print(f"  [err][=^..^=] {e}[/err]\n")
                    continue
            if not insns:
                console.print("  [warn]no instructions decoded[/warn]\n")
                continue
            t = Table(box=box.ROUNDED, show_header=True,
                      header_style="bold bright_white on bright_black",
                      border_style="bright_black", padding=(0, 1))
            t.add_column("offset",  style="dim",  no_wrap=True, min_width=10)
            t.add_column("bytes",   style="dim",  no_wrap=True, min_width=20)
            t.add_column("mnem",    style="cmd",  no_wrap=True, min_width=10)
            t.add_column("operands",style="info")
            for i in insns:
                t.add_row(
                    hex(i.address),
                    bytes(i.bytes).hex(" "),
                    i.mnemonic,
                    i.op_str,
                )
            console.print()
            console.print(t)
            if len(insns) == 200:
                console.print("  [dim](first 200 instructions shown)[/dim]")
            console.print()

        elif cmd in ("trace", "regs", "mem", "api", "strings", "smc"):
            if result is None:
                console.print("  [dim]no emulation result - use  run  or  hex  first[/dim]\n")
                continue

            if cmd == "smc":
                smc = result.get("smc", False)
                smc_addr = result.get("smc_address")
                if smc:
                    msg = f"[err]DETECTED[/err]" + (f" at {hex(smc_addr)}" if smc_addr else "")
                else:
                    msg = "[good]not detected[/good]"
                console.print(f"\n  Self-Modifying Code: {msg}\n")

            elif cmd == "strings":
                strs = result.get("strings", [])
                if not strs:
                    console.print("  [dim]no strings extracted[/dim]\n")
                else:
                    console.print()
                    for s in strs:
                        console.print(f"  [ok]→[/ok] [cmd]{s}[/cmd]")
                    console.print()

            elif cmd == "api":
                calls = result.get("api_calls", [])
                if not calls:
                    console.print("  [dim]no API calls intercepted[/dim]\n")
                else:
                    t = Table(box=box.ROUNDED, show_header=True,
                              header_style="bold bright_white on bright_black",
                              border_style="bright_black", padding=(0, 1))
                    t.add_column("#",       style="dim",  width=4)
                    t.add_column("target",  style="err",  no_wrap=True)
                    t.add_column("caller",  style="dim",  no_wrap=True)
                    t.add_column("note",    style="warn")
                    for i, c in enumerate(calls, 1):
                        t.add_row(str(i),
                                  c.get("target", "?"),
                                  c.get("caller", "?"),
                                  c.get("note", ""))
                    console.print()
                    console.print(t)
                    console.print()

            elif cmd == "regs":
                regs = result.get("regs_final", {})
                if not regs:
                    console.print("  [dim]no register data[/dim]\n")
                else:
                    t = Table(box=box.ROUNDED, show_header=False,
                              border_style="bright_black", padding=(0, 1))
                    t.add_column("reg",   style="info",  no_wrap=True, min_width=6)
                    t.add_column("value", style="cmd",   no_wrap=True)
                    for k, v in sorted(regs.items()):
                        t.add_row(k, hex(v) if isinstance(v, int) else str(v))
                    console.print()
                    console.print(t)
                    console.print()

            elif cmd == "mem":
                log = result.get("mem_log", [])
                if not log:
                    console.print("  [dim]no memory accesses recorded[/dim]\n")
                else:
                    t = Table(box=box.ROUNDED, show_header=True,
                              header_style="bold bright_white on bright_black",
                              border_style="bright_black", padding=(0, 1))
                    t.add_column("type",  style="info", width=5, no_wrap=True)
                    t.add_column("addr",  style="dim",  no_wrap=True)
                    t.add_column("size",  style="dim",  no_wrap=True)
                    t.add_column("value", style="cmd",  no_wrap=True)
                    for m in log[:100]:
                        acc  = m.get("access", "?")
                        sty  = "err" if acc == "W" else "good"
                        t.add_row(f"[{sty}]{acc}[/{sty}]",
                                  m.get("addr", "?"),
                                  str(m.get("size", "?")),
                                  m.get("value", "?"))
                    console.print()
                    console.print(t)
                    if len(log) > 100:
                        console.print(f"  [dim](first 100 of {len(log)} entries)[/dim]")
                    console.print()

            elif cmd == "trace":
                trace = result.get("trace", [])
                if not trace:
                    console.print("  [dim]no trace data[/dim]\n")
                else:
                    t = Table(box=box.ROUNDED, show_header=True,
                              header_style="bold bright_white on bright_black",
                              border_style="bright_black", padding=(0, 1))
                    t.add_column("#",      style="dim",  width=5)
                    t.add_column("addr",   style="dim",  no_wrap=True, min_width=12)
                    t.add_column("bytes",  style="dim",  no_wrap=True, min_width=16)
                    t.add_column("mnem",   style="cmd",  no_wrap=True, min_width=8)
                    t.add_column("ops",    style="info")
                    for i, step in enumerate(trace[:100], 1):
                        t.add_row(str(i),
                                  step.get("addr",  "?"),
                                  step.get("bytes", "?"),
                                  step.get("mnem",  "?"),
                                  step.get("ops",   ""))
                    console.print()
                    console.print(t)
                    if len(trace) > 100:
                        console.print(f"  [dim](first 100 of {len(trace)} steps)[/dim]")
                    console.print()

        else:
            console.print(f"  [warn]unknown command: {cmd}  (type  help)[/warn]\n")


# ══════════════════════════════════════════════════════════════════════════════
# Anti-Analysis Pattern Scanner sub-REPL
# ══════════════════════════════════════════════════════════════════════════════

AA_COMMANDS = ["scan", "scan-build", "scan-session", "arch",
               "filter", "list", "export", "builds", "help", "back"]

_AA_SEV_STYLE = {"high": "err", "medium": "warn", "low": "good"}
_AA_CAT_LABEL = {"anti_debug": "Anti-Debug", "anti_vm": "Anti-VM",
                 "timing": "Timing", "evasion": "Evasion"}


def _aa_render_findings(findings: list[dict], page: int = 0) -> None:
    start = page * PAGE_SIZE
    chunk = findings[start : start + PAGE_SIZE]
    if not chunk:
        console.print("  [dim]no findings[/dim]\n")
        return
    t = Table(box=box.ROUNDED, show_header=True,
              header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1))
    t.add_column("Sev",      width=7,  no_wrap=True)
    t.add_column("ID",       style="cmd",  no_wrap=True, min_width=12)
    t.add_column("Category", style="info", no_wrap=True, min_width=12)
    t.add_column("MITRE",    style="accent", no_wrap=True, min_width=12)
    t.add_column("Section",  style="dim",  no_wrap=True, min_width=8)
    t.add_column("Offset",   style="dim",  no_wrap=True, min_width=10)
    t.add_column("Bytes",    style="dim",  no_wrap=True, min_width=20)
    for f in chunk:
        sev = f.get("severity", "?")
        sty = _AA_SEV_STYLE.get(sev, "dim")
        t.add_row(
            f"[{sty}]{sev.upper()[:3]}[/{sty}]",
            f.get("id", "?"),
            _AA_CAT_LABEL.get(f.get("category", ""), f.get("category", "?")),
            f.get("mitre", "?"),
            f.get("section", "?"),
            f.get("va", hex(f.get("offset", 0))),
            f.get("bytes", ""),
        )
    console.print()
    console.print(t)
    total = len(findings)
    pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
    console.print(f"  [dim]page {page+1}/{pages}  ({total} findings)[/dim]\n")


def run_antianalysis() -> None:
    """Interactive Anti-Analysis Pattern Scanner sub-REPL."""
    session = _make_session(AA_COMMANDS, path_cmds=frozenset({"scan", "export"}))

    result:   dict | None = None
    findings: list[dict]  = []
    filtered: list[dict]  = []
    _arch    = "auto"
    _filter  = "all"
    _page    = 0

    console.print()
    console.print(Panel(
        "  Static Capstone scan for anti-debug, anti-VM, timing and evasion patterns\n"
        "  15 rules mapped to MITRE ATT&CK T1622 · T1497.001 · T1497.003\n"
        "  type  help  for commands,  back  to return",
        title="[heading] Anti-Analysis Pattern Scanner [/heading]",
        border_style="bright_cyan", box=box.ROUNDED,
    ))
    console.print()

    def _apply_filter():
        nonlocal filtered, _page
        _page = 0
        filtered = findings if _filter == "all" else \
                   [f for f in findings if f.get("category") == _filter]

    def _show_summary():
        if result is None:
            return
        by = result.get("by_category", {})
        fname = result.get("file_name", "")
        console.print()
        console.print(Panel(
            f"  file        : [cmd]{fname}[/cmd]\n"
            f"  arch        : {result.get('arch','?')}\n"
            f"  total       : [warn]{result.get('total',0)}[/warn] findings\n"
            f"  anti_debug  : [err]{by.get('anti_debug',0)}[/err]\n"
            f"  anti_vm     : [high]{by.get('anti_vm',0)}[/high]\n"
            f"  timing      : [medium]{by.get('timing',0)}[/medium]\n"
            f"  evasion     : [low]{by.get('evasion',0)}[/low]",
            title="[heading] Scan Summary [/heading]",
            border_style="bright_black", box=box.ROUNDED,
        ))
        mitre = result.get("mitre_summary", [])
        if mitre:
            console.print("  MITRE ATT&CK: " +
                          "  ".join(f"[accent]{m['id']}[/accent]" for m in mitre))
        console.print()

    while True:
        try:
            raw = session.prompt("peekaboo [antianalysis] > ", style=PT_STYLE).strip()
        except KeyboardInterrupt:
            console.print("\n[dim]use  back  to return[/dim]")
            continue
        except EOFError:
            break

        if not raw:
            continue
        parts = raw.split(None, 3)
        cmd   = parts[0].lower()
        arg   = parts[1].strip() if len(parts) > 1 else ""
        arg2  = parts[2].strip() if len(parts) > 2 else ""

        if cmd in ("back", "exit", "quit"):
            break

        elif cmd == "help":
            show_help("antianalysis", arg or None)

        elif cmd == "arch":
            if arg not in ("auto", "x64", "x86"):
                console.print("  [warn]usage: arch auto|x64|x86[/warn]\n")
                continue
            _arch = arg
            console.print(f"  [ok]arch set to {_arch}[/ok]\n")

        elif cmd == "scan":
            if not arg:
                console.print("  [warn]usage: scan <path>[/warn]\n")
                continue
            p = Path(arg).expanduser()
            if not p.exists():
                console.print(f"  [err][=^..^=] not found: {p}[/err]\n")
                continue
            with console.status("[info]scanning…[/info]", spinner="dots"):
                try:
                    from anti_analysis import scan_pe as _aa_pe, scan_raw as _aa_raw
                    result = _aa_pe(p, arch=_arch)
                    if not result.get("ok"):
                        result = _aa_raw(p.read_bytes(),
                                         arch="x64" if _arch == "auto" else _arch)
                    result["file_name"] = p.name
                except Exception as e:
                    console.print(f"  [err][=^..^=] {e}[/err]\n")
                    continue
            findings = result.get("findings", [])
            _filter  = "all"
            _apply_filter()
            _show_summary()
            _aa_render_findings(filtered)

        elif cmd == "scan-build":
            if not arg:
                console.print("  [warn]usage: scan-build <build-id> [fname][/warn]\n")
                continue
            try:
                import db as _db2
                build = _db2.get_build(arg)
            except Exception:
                build = None
            if not build:
                console.print(f"  [err][=^..^=] build {arg} not found[/err]\n")
                continue
            files = _vtscan_resolve_files(build)
            if not files:
                console.print("  [err][=^..^=] no binary found for this build[/err]\n")
                continue
            fname = arg2
            p = next((path for name, path in files if name == fname), files[0][1])
            with console.status("[info]scanning…[/info]", spinner="dots"):
                try:
                    from anti_analysis import scan_pe as _aa_pe, scan_raw as _aa_raw
                    result = _aa_pe(p, arch=_arch)
                    if not result.get("ok"):
                        result = _aa_raw(p.read_bytes(),
                                         arch="x64" if _arch == "auto" else _arch)
                    result["file_name"] = p.name
                except Exception as e:
                    console.print(f"  [err][=^..^=] {e}[/err]\n")
                    continue
            findings = result.get("findings", [])
            _filter  = "all"
            _apply_filter()
            _show_summary()
            _aa_render_findings(filtered)

        elif cmd == "scan-session":
            if not arg or not arg2:
                console.print("  [warn]usage: scan-session <session-id> <filename>[/warn]\n")
                continue
            base  = Path(__file__).parent
            p     = (base / "samples" / arg / arg2).resolve()
            guard = (base / "samples").resolve()
            if not str(p).startswith(str(guard)) or not p.exists():
                console.print(f"  [err][=^..^=] file not found or invalid path[/err]\n")
                continue
            with console.status("[info]scanning…[/info]", spinner="dots"):
                try:
                    from anti_analysis import scan_pe as _aa_pe, scan_raw as _aa_raw
                    result = _aa_pe(p, arch=_arch)
                    if not result.get("ok"):
                        result = _aa_raw(p.read_bytes(),
                                         arch="x64" if _arch == "auto" else _arch)
                    result["file_name"] = p.name
                except Exception as e:
                    console.print(f"  [err][=^..^=] {e}[/err]\n")
                    continue
            findings = result.get("findings", [])
            _filter  = "all"
            _apply_filter()
            _show_summary()
            _aa_render_findings(filtered)

        elif cmd == "filter":
            cats = ("all", "anti_debug", "anti_vm", "timing", "evasion")
            if arg not in cats:
                console.print(f"  [warn]usage: filter {' | '.join(cats)}[/warn]\n")
                continue
            _filter = arg
            _apply_filter()
            _aa_render_findings(filtered)

        elif cmd == "list":
            if not findings:
                console.print("  [dim]no scan loaded - use  scan  first[/dim]\n")
                continue
            try:
                _page = max(0, int(arg) - 1) if arg else _page
            except ValueError:
                _page = 0
            _aa_render_findings(filtered, _page)

        elif cmd == "builds":
            try:
                import db as _db2
                builds = _db2.get_builds(limit=30)
            except Exception:
                builds = []
            t = Table(box=box.ROUNDED, show_header=True,
                      header_style="bold bright_white on bright_black",
                      border_style="bright_black", padding=(0, 1))
            t.add_column("build-id", style="cmd",  no_wrap=True, min_width=12)
            t.add_column("module",   style="info", min_width=18)
            t.add_column("date",     style="dim",  min_width=16)
            t.add_column("binaries", style="ok",   min_width=20)
            for b in builds:
                if b.get("status") != "success":
                    continue
                pa  = b.get("params", {})
                mod = pa.get("slug") or pa.get("injection") or pa.get("stealer") or b["id"]
                fls = _vtscan_resolve_files(b)
                t.add_row(b["id"], mod, (b.get("created") or "")[:16],
                          "  ".join(n for n, _ in fls) if fls else "-")
            console.print()
            console.print(t)
            console.print()

        elif cmd == "export":
            if not findings:
                console.print("  [warn]nothing to export - run  scan  first[/warn]\n")
                continue
            if not arg:
                console.print("  [warn]usage: export <path>[/warn]\n")
                continue
            import json as _json
            out = Path(arg).expanduser()
            try:
                out.write_text(_json.dumps({"findings": findings}, indent=2))
                console.print(f"  [ok]exported {len(findings)} findings → {out}[/ok]\n")
            except Exception as e:
                console.print(f"  [err][=^..^=] {e}[/err]\n")

        else:
            console.print(f"  [warn]unknown command: {cmd}  (type  help)[/warn]\n")


# ══════════════════════════════════════════════════════════════════════════════
# ROP Chain Builder sub-REPL
# ══════════════════════════════════════════════════════════════════════════════

ROP_COMMANDS = ["scan", "scan-build", "scan-session", "arch", "base",
                "filter", "search", "list", "chain-add", "chain-add-addr",
                "chain-clear", "chain-show", "chain-arg",
                "generate", "save", "builds", "help", "back"]

_ROP_SEM_STYLE = {
    "reg_load":    "good",
    "multi_pop":   "good",
    "stack_pivot": "err",
    "syscall":     "accent",
    "arithmetic":  "medium",
    "reg_mov":     "info",
    "mem_write":   "high",
    "mem_read":    "info",
    "nop_ret":     "dim",
    "ret_only":    "dim",
    "misc":        "dim",
}


def _rop_render_gadgets(gadgets: list[dict], page: int = 0) -> None:
    start = page * PAGE_SIZE
    chunk = gadgets[start : start + PAGE_SIZE]
    if not chunk:
        console.print("  [dim]no gadgets to show[/dim]\n")
        return
    t = Table(box=box.ROUNDED, show_header=True,
              header_style="bold bright_white on bright_black",
              border_style="bright_black", padding=(0, 1))
    t.add_column("#",        style="dim", width=5)
    t.add_column("Address",  style="cmd", no_wrap=True, min_width=14)
    t.add_column("RVA",      style="dim", no_wrap=True, min_width=10)
    t.add_column("Semantic", no_wrap=True, min_width=12)
    t.add_column("Instructions", min_width=36)
    t.add_column("Bytes",    style="dim", no_wrap=True, min_width=20)
    for idx, g in enumerate(chunk, start + 1):
        sem = g.get("semantic", "misc")
        sty = _ROP_SEM_STYLE.get(sem, "dim")
        t.add_row(
            str(idx),
            g.get("addr", "?"),
            g.get("rva",  "?"),
            f"[{sty}]{sem}[/{sty}]",
            "  ;  ".join(g.get("insns", [])),
            " ".join(g.get("bytes", "").split()[:8]),
        )
    console.print()
    console.print(t)
    total = len(gadgets)
    pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
    console.print(f"  [dim]page {page+1}/{pages}  ({total} gadgets)[/dim]\n")


def run_rop() -> None:
    """Interactive ROP Chain Builder sub-REPL."""
    session = _make_session(ROP_COMMANDS, path_cmds=frozenset({"scan", "save"}))

    result:  dict | None = None
    gadgets: list[dict]  = []
    filtered: list[dict] = []
    chain:   list[dict]  = []   # [{gadget, arg}]
    generated: str       = ""
    _arch    = "auto"
    _base: str | None    = None
    _filter  = "all"
    _search  = ""
    _page    = 0

    console.print()
    console.print(Panel(
        "  Find ROP gadgets in Windows PE / DLL / SYS or raw shellcode\n"
        "  Classify: reg_load · stack_pivot · syscall · arithmetic · mem_write · …\n"
        "  Assemble a chain, generate C array or Python payload\n"
        "  type  help  for commands,  back  to return",
        title="[heading] ROP Chain Builder [/heading]",
        border_style="bright_cyan", box=box.ROUNDED,
    ))
    console.print()

    def _apply_filter():
        nonlocal filtered, _page
        _page = 0
        result2 = gadgets if _filter == "all" else \
                  [g for g in gadgets if g.get("semantic") == _filter]
        if _search:
            q = _search.lower()
            result2 = [g for g in result2
                       if q in " ".join(g.get("insns", [])).lower()
                       or q in g.get("addr", "").lower()
                       or q in g.get("semantic", "").lower()]
        filtered = result2

    while True:
        chain_n = f" chain:{len(chain)}" if chain else ""
        try:
            raw = session.prompt(f"peekaboo [rop{chain_n}] > ", style=PT_STYLE).strip()
        except KeyboardInterrupt:
            console.print("\n[dim]use  back  to return[/dim]")
            continue
        except EOFError:
            break

        if not raw:
            continue
        parts = raw.split(None, 3)
        cmd   = parts[0].lower()
        arg   = parts[1].strip() if len(parts) > 1 else ""
        arg2  = parts[2].strip() if len(parts) > 2 else ""

        if cmd in ("back", "exit", "quit"):
            break

        elif cmd == "help":
            show_help("rop", arg or None)

        elif cmd == "arch":
            if arg not in ("auto", "x64", "x86"):
                console.print("  [warn]usage: arch auto|x64|x86[/warn]\n")
                continue
            _arch = arg
            console.print(f"  [ok]arch set to {_arch}[/ok]\n")

        elif cmd == "base":
            if not arg:
                console.print("  [warn]usage: base <hex_address>   e.g. base 0x180001000[/warn]\n")
                continue
            _base = arg
            console.print(f"  [ok]image base override: {_base}[/ok]\n")

        elif cmd in ("scan", "scan-build", "scan-session"):
            p_path: Path | None = None

            if cmd == "scan":
                if not arg:
                    console.print("  [warn]usage: scan <path>[/warn]\n")
                    continue
                p_path = Path(arg).expanduser()
                if not p_path.exists():
                    console.print(f"  [err][=^..^=] not found: {p_path}[/err]\n")
                    continue

            elif cmd == "scan-build":
                if not arg:
                    console.print("  [warn]usage: scan-build <build-id> [fname][/warn]\n")
                    continue
                try:
                    import db as _db2
                    build = _db2.get_build(arg)
                except Exception:
                    build = None
                if not build:
                    console.print(f"  [err][=^..^=] build {arg} not found[/err]\n")
                    continue
                files = _vtscan_resolve_files(build)
                if not files:
                    console.print("  [err][=^..^=] no binary for this build[/err]\n")
                    continue
                p_path = next((path for name, path in files if name == arg2), files[0][1])

            elif cmd == "scan-session":
                if not arg or not arg2:
                    console.print("  [warn]usage: scan-session <sid> <file>[/warn]\n")
                    continue
                base_dir = Path(__file__).parent
                p_path   = (base_dir / "samples" / arg / arg2).resolve()
                guard    = (base_dir / "samples").resolve()
                if not str(p_path).startswith(str(guard)) or not p_path.exists():
                    console.print("  [err][=^..^=] file not found or invalid path[/err]\n")
                    continue

            ib: int | None = None
            if _base:
                try:
                    ib = int(_base, 16) if _base.startswith("0x") else int(_base, 0)
                except ValueError:
                    pass

            with console.status("[info]scanning for gadgets…[/info]", spinner="dots"):
                try:
                    from rop_builder import scan_pe as _rop_pe, scan_raw as _rop_raw
                    result = _rop_pe(p_path, arch=_arch, image_base=ib)
                    if not result.get("ok"):
                        result = _rop_raw(p_path.read_bytes(),
                                          arch="x64" if _arch == "auto" else _arch,
                                          image_base=ib or 0x400000)
                    result["file_name"] = p_path.name
                except Exception as e:
                    console.print(f"  [err][=^..^=] {e}[/err]\n")
                    continue

            gadgets  = result.get("gadgets", [])
            chain    = []
            generated = ""
            _filter  = "all"
            _search  = ""
            _apply_filter()

            by_sem = result.get("by_semantic", {})
            console.print()
            console.print(Panel(
                f"  file         : [cmd]{result.get('file_name','')}[/cmd]\n"
                f"  arch         : {result.get('arch','?')}  |  base: {result.get('base','?')}\n"
                f"  total gadgets: [warn]{result.get('total',0)}[/warn]\n"
                f"  reg_load     : [good]{by_sem.get('reg_load',0) + by_sem.get('multi_pop',0)}[/good]  "
                f"  stack_pivot  : [err]{by_sem.get('stack_pivot',0)}[/err]  "
                f"  syscall      : [accent]{by_sem.get('syscall',0)}[/accent]  "
                f"  arithmetic   : [medium]{by_sem.get('arithmetic',0)}[/medium]",
                title="[heading] Gadget Scan [/heading]",
                border_style="bright_black", box=box.ROUNDED,
            ))
            _rop_render_gadgets(filtered)

        elif cmd == "filter":
            _filter = arg if arg else "all"
            _apply_filter()
            _rop_render_gadgets(filtered)

        elif cmd == "search":
            _search = arg
            _apply_filter()
            _rop_render_gadgets(filtered)

        elif cmd == "list":
            if not gadgets:
                console.print("  [dim]no scan loaded - use  scan  first[/dim]\n")
                continue
            try:
                _page = max(0, int(arg) - 1) if arg else _page
            except ValueError:
                _page = 0
            _rop_render_gadgets(filtered, _page)

        elif cmd == "chain-add":
            if not filtered:
                console.print("  [dim]gadget list is empty - run  scan  first[/dim]\n")
                continue
            try:
                row = int(arg) - 1
                g   = filtered[row]
            except (ValueError, IndexError):
                console.print(f"  [warn]usage: chain-add <row-number>  (1–{len(filtered)})[/warn]\n")
                continue
            needs_arg = g.get("semantic") in ("reg_load", "multi_pop")
            chain.append({"gadget": g, "arg": "" if needs_arg else None})
            console.print(f"  [ok]added #{len(chain)}: {' ; '.join(g['insns'])}[/ok]\n")

        elif cmd == "chain-add-addr":
            if not gadgets:
                console.print("  [dim]no gadgets loaded[/dim]\n")
                continue
            addr = arg.lower()
            found = next((g for g in gadgets if g.get("addr", "").lower() == addr), None)
            if not found:
                console.print(f"  [warn]{addr} not found in gadget list[/warn]\n")
                continue
            needs_arg = found.get("semantic") in ("reg_load", "multi_pop")
            chain.append({"gadget": found, "arg": "" if needs_arg else None})
            console.print(f"  [ok]added #{len(chain)}: {' ; '.join(found['insns'])}[/ok]\n")

        elif cmd == "chain-arg":
            if not arg or not arg2:
                console.print("  [warn]usage: chain-arg <chain-index> <value>[/warn]\n")
                continue
            try:
                idx = int(arg) - 1
                chain[idx]["arg"] = arg2
                console.print(f"  [ok]slot #{idx+1} arg = {arg2}[/ok]\n")
            except (ValueError, IndexError):
                console.print(f"  [warn]invalid chain index - chain has {len(chain)} entries[/warn]\n")

        elif cmd == "chain-show":
            if not chain:
                console.print("  [dim]chain is empty - use  chain-add  to build[/dim]\n")
            else:
                t = Table(box=box.ROUNDED, show_header=True,
                          header_style="bold bright_white on bright_black",
                          border_style="bright_black", padding=(0, 1))
                t.add_column("#",      style="dim", width=4)
                t.add_column("Address",style="cmd", no_wrap=True)
                t.add_column("Insns",  style="info")
                t.add_column("Stack arg", style="warn")
                for i, item in enumerate(chain, 1):
                    g   = item["gadget"]
                    arg_v = item.get("arg")
                    t.add_row(str(i), g.get("addr","?"),
                              " ; ".join(g.get("insns",[])),
                              arg_v if arg_v is not None else "[dim]-[/dim]")
                console.print()
                console.print(t)
                console.print()

        elif cmd == "chain-clear":
            chain = []
            generated = ""
            console.print("  [dim]chain cleared[/dim]\n")

        elif cmd == "generate":
            if not chain:
                console.print("  [warn]chain is empty - add gadgets first[/warn]\n")
                continue
            lang = arg.lower() if arg in ("c", "py") else "c"
            fname = result.get("file_name", "") if result else ""
            arch_out = result.get("arch", "x64") if result else _arch

            if lang == "c":
                ptr = "ULONG_PTR" if arch_out == "x64" else "DWORD"
                lines = [
                    f"/* ROP chain - {fname}  ({arch_out}) */",
                    f"/* Generated by peekaboo ROP Builder */",
                    f"#include <windows.h>",
                    f"",
                    f"{ptr} rop_chain[] = {{",
                ]
                for item in chain:
                    g   = item["gadget"]
                    cmt = " ; ".join(g.get("insns", []))
                    lines.append(f"    {g['addr']},  /* {cmt} */")
                    if item.get("arg") is not None:
                        pops = sum(1 for l in g.get("insns", []) if l.strip().startswith("pop"))
                        val  = item["arg"] or "0x0"
                        for pi in range(pops):
                            reg = g["insns"][pi].split()[-1] if pi < len(g["insns"]) else "?"
                            lines.append(f"    {val},  /* {reg} = {val} */")
                lines.append("};")
                lines.append("")
                lines.append(f"/* Pack with memcpy into the target stack buffer */")
                generated = "\n".join(lines)
            else:  # py
                lines = [
                    f"# ROP chain - {fname}  ({arch_out})",
                    f"# Generated by peekaboo ROP Builder",
                    f"",
                    f"chain = [",
                ]
                for item in chain:
                    g   = item["gadget"]
                    cmt = " ; ".join(g.get("insns", []))
                    lines.append(f"    {g['addr']},  # {cmt}")
                    if item.get("arg") is not None:
                        pops = sum(1 for l in g.get("insns", []) if l.strip().startswith("pop"))
                        val  = item["arg"] or "0x0"
                        for pi in range(pops):
                            reg = g["insns"][pi].split()[-1] if pi < len(g["insns"]) else "?"
                            lines.append(f"    {val},  # {reg} = {val}")
                lines.append("]")
                lines.append("")
                lines.append("import struct")
                lines.append("payload = b''.join(struct.pack('<Q', a) for a in chain)")
                generated = "\n".join(lines)

            ext = "c" if lang == "c" else "py"
            console.print()
            console.print(Syntax(generated[:2000], lang if lang != "py" else "python",
                                 theme="monokai", line_numbers=False,
                                 background_color="default"))
            console.print(f"\n  [ok]{len(chain)} gadgets - use  save <path>  to write  chain.{ext}[/ok]\n")

        elif cmd == "save":
            if not generated:
                console.print("  [warn]nothing to save - run  generate  first[/warn]\n")
                continue
            if not arg:
                console.print("  [warn]usage: save <path>[/warn]\n")
                continue
            out = Path(arg).expanduser()
            try:
                out.write_text(generated)
                console.print(f"  [ok]saved → {out}[/ok]\n")
            except Exception as e:
                console.print(f"  [err][=^..^=] {e}[/err]\n")

        elif cmd == "builds":
            try:
                import db as _db2
                builds = _db2.get_builds(limit=30)
            except Exception:
                builds = []
            t = Table(box=box.ROUNDED, show_header=True,
                      header_style="bold bright_white on bright_black",
                      border_style="bright_black", padding=(0, 1))
            t.add_column("build-id", style="cmd",  no_wrap=True, min_width=12)
            t.add_column("module",   style="info", min_width=18)
            t.add_column("date",     style="dim",  min_width=16)
            t.add_column("binaries", style="ok",   min_width=20)
            for b in builds:
                if b.get("status") != "success":
                    continue
                pa  = b.get("params", {})
                mod = pa.get("slug") or pa.get("injection") or pa.get("stealer") or b["id"]
                fls = _vtscan_resolve_files(b)
                t.add_row(b["id"], mod, (b.get("created") or "")[:16],
                          "  ".join(n for n, _ in fls) if fls else "-")
            console.print()
            console.print(t)
            console.print()

        else:
            console.print(f"  [warn]unknown command: {cmd}  (type  help)[/warn]\n")


# -- top-level REPL ------------------------------------------------------------

def main() -> None:
    print_banner()

    ev_mod = _load_evasion_module()

    _dispatch: dict[str, object] = {
        "library":      run_library,
        "artifacts":    run_artifacts,
        "builder":      run_builder,
        "shellcode":    run_shellcode,
        "yara":         run_yara,
        "malpedia":     run_malpedia,
        "ttp":          run_ttp,
        "pe":           run_pe,
        "vtscan":       run_vtscan,
        "hellsgate":    run_hellsgate,
        "scemu":        run_scemu,
        "antianalysis": run_antianalysis,
        "rop":          run_rop,
    }

    session = _make_session(TOP_COMMANDS)

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

        parts = raw.split()
        cmd   = parts[0].lower()

        if cmd in ("exit", "quit"):
            console.print("[dim]goodbye.[/dim]\n")
            break
        elif cmd == "help":
            print_top_help(parts[1] if len(parts) > 1 else None)
        elif cmd == "evasion":
            if ev_mod is None:
                console.print("[err][=^..^=] evasion module not available[/err]")
            else:
                run_evasion(ev_mod)
        elif cmd in _dispatch:
            _dispatch[cmd]()  # type: ignore[operator]
        else:
            console.print(
                f"[warn][=^..^=] unknown command: {cmd}  "
                f"(type  help  for available modules)[/warn]"
            )


if __name__ == "__main__":
    main()
