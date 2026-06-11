"""
hellsgate.py – Hell's Gate / Direct Syscall SSN extractor
==========================================================
Parses a Windows ntdll.dll (PE format, runs on Linux via pefile) to:
  - Extract System Service Numbers for all Nt*/Zw* stubs
  - Detect EDR inline hooks (JMP rel32, FF25, INT3, ...)
  - Recover hooked SSNs via Halo's Gate (nearest clean neighbour)
  - Recover via Tartarus Gate (forward scan for mov eax pattern)
  - Generate NASM x64 or C __declspec(naked) direct-syscall stubs

References:
  Hell's Gate       – am0nsec / smelly__vx  (VX-Underground)
  Halo's Gate       – trickster0 / Alice Climent-Monde
  Tartarus Gate     – trickster0
  SysWhispers3      – klezVirus
"""
from __future__ import annotations

import struct
from pathlib import Path

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(ntdll_path: Path) -> dict:
    """
    Parse ntdll_path (a Windows ntdll.dll) and return a dict:
      ok       : bool
      total    : int  – Nt*/Zw* exports found
      clean    : int
      hooked   : int
      entries  : list[EntryDict]
    """
    try:
        import pefile
    except ImportError:
        return {"ok": False, "error": "pefile not installed – run: pip install pefile"}

    try:
        pe = pefile.PE(str(ntdll_path), fast_load=False)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return {"ok": False, "error": "no export directory – is this really ntdll.dll?"}

    try:
        raw = bytearray(pe.get_memory_mapped_image())
    except Exception as exc:
        return {"ok": False, "error": f"memory-map failed: {exc}"}

    # ---- collect Nt* / Zw* exports, sort by RVA -------------------------
    nt_exports: list[tuple[str, int]] = []
    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not sym.name:
            continue
        try:
            name = sym.name.decode("utf-8", errors="ignore")
        except Exception:
            continue
        if name.startswith("Nt") or name.startswith("Zw"):
            nt_exports.append((name, int(sym.address)))

    nt_exports.sort(key=lambda x: x[1])

    entries: list[dict] = []
    for name, rva in nt_exports:
        stub = bytes(raw[rva : rva + 32])
        entries.append(_analyze_stub(name, rva, stub))

    # ---- Halo's Gate pass: recover SSNs for hooked stubs -----------------
    # SSNs are allocated contiguously in RVA order, so:
    #   SSN[i] = SSN[nearest_clean_below] + distance
    for i, entry in enumerate(entries):
        if entry["ssn"] is not None:
            continue
        recovered: int | None = None
        # look backward
        for j in range(i - 1, -1, -1):
            if entries[j]["ssn"] is not None:
                recovered = entries[j]["ssn"] + (i - j)
                break
        # look forward
        if recovered is None:
            for j in range(i + 1, len(entries)):
                if entries[j]["ssn"] is not None:
                    recovered = entries[j]["ssn"] - (j - i)
                    break
        if recovered is not None and recovered >= 0:
            entry["ssn"]        = recovered
            entry["ssn_method"] = "halos_gate"

    hooked = sum(1 for e in entries if e["hook_type"] != "clean")
    return {
        "ok":      True,
        "total":   len(entries),
        "clean":   len(entries) - hooked,
        "hooked":  hooked,
        "entries": entries,
    }


def generate_asm(functions: list[dict], language: str = "nasm") -> str:
    """Generate direct-syscall stubs for the given function list."""
    if language == "c":
        return _gen_c(functions)
    return _gen_nasm(functions)


# ---------------------------------------------------------------------------
# Internal: stub analysis
# ---------------------------------------------------------------------------

def _analyze_stub(name: str, rva: int, stub: bytes) -> dict:
    entry: dict = {
        "name":         name,
        "rva":          hex(rva),
        "ssn":          None,
        "ssn_method":   "direct",
        "hook_type":    "unknown",
        "stub_hex":     stub[:16].hex(" "),
        "disasm":       _disasm(stub[:20]),
    }

    if len(stub) < 4:
        entry["hook_type"] = "truncated"
        return entry

    # --- canonical clean x64 stub -------------------------------------------
    # 4C 8B D1          mov r10, rcx
    # B8 xx xx xx xx    mov eax, <SSN>
    # ...
    if stub[0] == 0x4C and stub[1] == 0x8B and stub[2] == 0xD1 and stub[3] == 0xB8:
        entry["ssn"]       = int.from_bytes(stub[4:8], "little")
        entry["ssn_method"] = "direct"
        entry["hook_type"] = "clean"
        return entry

    # --- JMP rel32 (E9) – most common EDR inline hook -----------------------
    if stub[0] == 0xE9 and len(stub) >= 5:
        raw_rel = int.from_bytes(stub[1:5], "little", signed=False)
        signed_rel = struct.unpack_from("<i", stub, 1)[0]
        hook_target = (rva + 5 + signed_rel) & 0xFFFFFFFFFFFFFFFF
        entry["hook_type"]   = "jmp_hook"
        entry["hook_target"] = hex(hook_target)
        ssn = _tartarus_scan(stub)
        if ssn is not None:
            entry["ssn"]       = ssn
            entry["ssn_method"] = "tartarus_gate"
        return entry

    # --- indirect JMP via memory (FF 25 xx xx xx xx) ------------------------
    if stub[0] == 0xFF and stub[1] == 0x25:
        entry["hook_type"] = "ind_jmp_hook"
        ssn = _tartarus_scan(stub)
        if ssn is not None:
            entry["ssn"]       = ssn
            entry["ssn_method"] = "tartarus_gate"
        return entry

    # --- INT3 breakpoint (CC) – some AV/AMSI hooks --------------------------
    if stub[0] == 0xCC:
        entry["hook_type"] = "int3_hook"
        return entry

    # --- PUSH / RET trampoline (68 xx xx xx xx C3) --------------------------
    if stub[0] == 0x68 and len(stub) >= 6 and stub[5] == 0xC3:
        entry["hook_type"] = "push_ret_hook"
        ssn = _tartarus_scan(stub)
        if ssn is not None:
            entry["ssn"]       = ssn
            entry["ssn_method"] = "tartarus_gate"
        return entry

    # --- partially displaced stub (mov eax found, but not at expected offset)
    if stub[3] == 0xB8 and len(stub) >= 8:
        entry["ssn"]       = int.from_bytes(stub[4:8], "little")
        entry["ssn_method"] = "direct"
        entry["hook_type"] = "partial_hook"
        return entry

    # --- Tartarus Gate: forward scan for mov eax anywhere in stub -----------
    ssn = _tartarus_scan(stub)
    if ssn is not None:
        entry["ssn"]       = ssn
        entry["ssn_method"] = "tartarus_gate"
        entry["hook_type"] = "deep_hook"
        return entry

    entry["hook_type"] = "unknown_hook"
    return entry


def _tartarus_scan(stub: bytes) -> int | None:
    """Scan forward looking for  B8 xx xx xx xx  (mov eax, imm32) with SSN < 0x600."""
    for off in range(1, len(stub) - 4):
        if stub[off] == 0xB8:
            val = int.from_bytes(stub[off + 1 : off + 5], "little")
            if val < 0x600:     # plausible SSN range for any known Windows version
                return val
    return None


# ---------------------------------------------------------------------------
# Internal: mini disassembler (no external deps)
# ---------------------------------------------------------------------------

def _disasm(stub: bytes) -> list[str]:
    """Decode the first few instructions of a syscall stub into readable mnemonics."""
    lines: list[str] = []
    i = 0
    while i < len(stub) and len(lines) < 5:
        b = stub[i]

        if i + 3 <= len(stub) and stub[i : i + 3] == b"\x4C\x8B\xD1":
            lines.append("mov r10, rcx")
            i += 3

        elif b == 0xB8 and i + 5 <= len(stub):
            val = int.from_bytes(stub[i + 1 : i + 5], "little")
            lines.append(f"mov eax, {val:#06x}")
            i += 5

        elif b == 0xE9 and i + 5 <= len(stub):
            rel = struct.unpack_from("<i", stub, i + 1)[0]
            lines.append(f"jmp {rel + 5:+#x}   ; EDR hook →")
            i += 5

        elif stub[i : i + 2] == b"\xFF\x25":
            lines.append("jmp [rip+...]   ; indirect hook")
            i += 6

        elif stub[i : i + 2] == b"\x0F\x05":
            lines.append("syscall")
            i += 2

        elif stub[i : i + 2] == b"\xF6\x04":
            lines.append("test byte [SharedUserData], 1")
            i += 7          # test byte ptr ds:[abs], imm8 = 7 bytes on x64

        elif b == 0x75:
            lines.append(f"jnz +{stub[i+1]:#04x}")
            i += 2

        elif b == 0x7F and i + 2 <= len(stub):
            lines.append(f"jg +{stub[i+1]:#04x}")
            i += 2

        elif b == 0xC3:
            lines.append("ret")
            i += 1
            break

        elif b == 0xCC:
            lines.append("int3   ; breakpoint hook")
            i += 1

        elif b == 0x68 and i + 5 <= len(stub):
            val = int.from_bytes(stub[i + 1 : i + 5], "little")
            lines.append(f"push {val:#010x}   ; trampoline hook")
            i += 5

        else:
            lines.append(f"db {b:#04x}")
            i += 1

    return lines


# ---------------------------------------------------------------------------
# Code generators
# ---------------------------------------------------------------------------

_NASM_HEADER = """\
; =============================================================
;  Direct Syscall Stubs – peekaboo Hell's Gate Lab
;  Target  : Windows x64
;  Assemble: nasm -f win64 syscalls.asm -o syscalls.obj
;            link syscalls.obj into your project
; =============================================================

bits 64
default rel

section .text

"""

_C_HEADER = """\
/*
 * Direct Syscall Stubs – peekaboo Hell's Gate Lab
 * Target  : Windows x64 (MSVC or MinGW with naked-function support)
 * Usage   : #include "syscalls.h"
 */
#pragma once
#include <windows.h>

"""


def _gen_nasm(functions: list[dict]) -> str:
    lines: list[str] = [_NASM_HEADER]

    # emit global declarations first
    for fn in functions:
        if fn.get("ssn") is not None:
            lines.append(f"global {fn['name']}")
    lines.append("")

    for fn in functions:
        name   = fn["name"]
        ssn    = fn.get("ssn")
        method = fn.get("ssn_method", "direct")
        hook   = fn.get("hook_type", "clean")

        if ssn is None:
            lines += [f"; {name}  — SSN unknown (hook recovery failed), skipped", ""]
            continue

        tail = ""
        if hook != "clean":
            tail = f"   ; recovered via {method}  (original hook: {hook})"

        lines += [
            f"{name}:",
            f"    mov r10, rcx",
            f"    mov eax, 0x{ssn:04X}{tail}",
            f"    syscall",
            f"    ret",
            "",
        ]

    return "\n".join(lines)


def _gen_c(functions: list[dict]) -> str:
    lines: list[str] = [_C_HEADER]

    for fn in functions:
        name   = fn["name"]
        ssn    = fn.get("ssn")
        hook   = fn.get("hook_type", "clean")
        method = fn.get("ssn_method", "direct")

        if ssn is None:
            lines += [f"/* {name}  — SSN unknown, skipped */", ""]
            continue

        note = f"/* SSN 0x{ssn:04X}"
        if hook != "clean":
            note += f"  — recovered via {method}, original hook: {hook}"
        note += " */"

        lines += [
            note,
            f"__declspec(naked) NTSTATUS {name}(",
            f"    PVOID a1, PVOID a2, PVOID a3, PVOID a4,",
            f"    PVOID a5, PVOID a6, PVOID a7, PVOID a8)",
            f"{{",
            f"    __asm {{",
            f"        mov r10, rcx",
            f"        mov eax, 0x{ssn:04X}",
            f"        syscall",
            f"        ret",
            f"    }}",
            f"}}",
            "",
        ]

    return "\n".join(lines)
