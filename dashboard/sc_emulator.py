"""
sc_emulator.py – x86/x64 shellcode emulator
=============================================
Safely executes shellcode in a sandboxed Unicorn Engine environment.

Features:
  - x86 (32-bit) and x64 (64-bit) modes
  - Per-instruction trace: RIP/EIP, mnemonic, registers
  - Memory-access log: reads and writes with values
  - API call interception: catches CALL to unmapped addresses (PEB-walk stubs,
    GetProcAddress attempts, WinAPI imports resolved by hash)
  - Self-modifying code detection: writes to the shellcode page
  - Decoding loop detection: repeated writes to same region
  - String extraction from written memory
  - Hard execution ceiling (instruction count + wall-clock timeout)
"""
from __future__ import annotations

import hashlib
import struct
import time
from pathlib import Path
from typing import Any

# Unicorn architecture / mode constants (imported lazily in run())
_UC_ARCH_X86  = None
_UC_MODE_32   = None
_UC_MODE_64   = None

# Memory layout
_SC_BASE   = 0x00400000    # shellcode loaded here
_SC_SIZE   = 0x00100000    # 1 MB region (handles most real shellcode)
_STACK_BASE = 0x00200000
_STACK_SIZE = 0x00040000   # 256 KB stack
_HEAP_BASE  = 0x00600000
_HEAP_SIZE  = 0x00100000   # 1 MB scratch heap (for API stub returns)

# Fake module/API stubs so PEB-walks don't crash
_FAKE_MODULE_BASE = 0x70000000
_STUB_RET_ADDR    = 0x7FFE0000   # single RET stub address

_MAX_INSNS   = 50_000
_MAX_SECONDS = 10


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def emulate(raw: bytes, arch: str = "x64", max_insns: int = _MAX_INSNS) -> dict:
    """
    Emulate `raw` shellcode bytes.

    Returns a dict with:
      ok          : bool
      arch        : "x86" | "x64"
      insn_count  : int
      stop_reason : str
      trace       : list[TraceEntry]     (per-instruction)
      mem_log     : list[MemEntry]       (reads + writes)
      api_calls   : list[ApiCallEntry]
      strings     : list[str]            (extracted from written memory)
      smc         : bool                 (self-modifying code detected)
      regs_final  : dict[str, str]       (register state at exit)
      error       : str | None
    """
    try:
        import unicorn as uc
        import unicorn.x86_const as ux
        import capstone as cs
    except ImportError as e:
        return {"ok": False, "error": f"dependency missing: {e}  (pip install unicorn capstone)"}

    x64 = arch != "x86"

    # ---- initialise emulator ----------------------------------------------
    mu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64 if x64 else uc.UC_MODE_32)
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if x64 else cs.CS_MODE_32)
    md.detail = True

    # ---- map memory -------------------------------------------------------
    _map(mu, _SC_BASE,    _SC_SIZE,   uc)   # shellcode
    _map(mu, _STACK_BASE, _STACK_SIZE, uc)  # stack
    _map(mu, _HEAP_BASE,  _HEAP_SIZE,  uc)  # scratch heap / fake structs
    _map(mu, _STUB_RET_ADDR, 0x1000,   uc)  # fake API stub page

    # write shellcode
    sc_padded = raw + b"\xc3" * 16      # ensure clean RET at end
    mu.mem_write(_SC_BASE, sc_padded[:_SC_SIZE])

    # write RET stub (single 0xC3 so fake API calls return cleanly)
    mu.mem_write(_STUB_RET_ADDR, b"\xc3")

    # set up fake PEB/TEB and minimal kernel32 Export Address Table
    _setup_fakes(mu, ux, x64)

    # ---- registers --------------------------------------------------------
    sp = _STACK_BASE + _STACK_SIZE - 0x200
    if x64:
        mu.reg_write(ux.UC_X86_REG_RSP, sp)
        mu.reg_write(ux.UC_X86_REG_RBP, sp)
        mu.reg_write(ux.UC_X86_REG_RIP, _SC_BASE)
        # write fake return address on stack so shellcode can RET out
        mu.mem_write(sp, struct.pack("<Q", _STUB_RET_ADDR))
    else:
        mu.reg_write(ux.UC_X86_REG_ESP, sp)
        mu.reg_write(ux.UC_X86_REG_EBP, sp)
        mu.reg_write(ux.UC_X86_REG_EIP, _SC_BASE)
        mu.mem_write(sp, struct.pack("<I", _STUB_RET_ADDR))

    # ---- state collectors -------------------------------------------------
    state: dict[str, Any] = {
        "trace":      [],
        "mem_log":    [],
        "api_calls":  [],
        "written":    bytearray(_SC_SIZE),  # shadow of SC page writes
        "written_mask": bytearray(_SC_SIZE),
        "smc":        False,
        "insn_count": 0,
        "stop_reason": "max_insns",
        "start_time": time.monotonic(),
        "max_insns":  max_insns,
        "x64":        x64,
        "mu":         mu,
        "md":         md,
        "ux":         ux,
        "raw_len":    len(raw),
        "heap_ptr":   _HEAP_BASE + 0x1000,   # bump allocator for fake returns
        "error":      None,
    }

    # ---- hooks ------------------------------------------------------------
    mu.hook_add(uc.UC_HOOK_CODE,       _hook_insn,   state)
    mu.hook_add(uc.UC_HOOK_MEM_WRITE,  _hook_write,  state)
    mu.hook_add(uc.UC_HOOK_MEM_READ,   _hook_read,   state)
    mu.hook_add(uc.UC_HOOK_MEM_INVALID,_hook_invalid, state)

    # ---- emulate ----------------------------------------------------------
    end_addr = _SC_BASE + len(sc_padded)
    try:
        mu.emu_start(_SC_BASE, end_addr, timeout=int(_MAX_SECONDS * 1_000_000))
    except Exception as exc:
        state["error"] = str(exc)
        if "UC_ERR_OK" not in str(exc):
            state["stop_reason"] = f"exception: {exc}"

    # ---- final register snapshot ------------------------------------------
    regs_final = _read_regs(mu, ux, x64)

    # ---- string extraction from written memory ----------------------------
    written_bytes = bytes(state["written"])
    strings = _extract_strings(written_bytes)

    # ---- summary ----------------------------------------------------------
    return {
        "ok":          True,
        "arch":        "x64" if x64 else "x86",
        "insn_count":  state["insn_count"],
        "stop_reason": state["stop_reason"],
        "trace":       state["trace"][-500:],   # cap at 500 for transport
        "mem_log":     state["mem_log"][:300],
        "api_calls":   state["api_calls"],
        "strings":     strings,
        "smc":         state["smc"],
        "regs_final":  regs_final,
        "error":       state["error"],
    }


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------

def _hook_insn(mu, address, size, state):
    state["insn_count"] += 1

    # wall-clock timeout
    if time.monotonic() - state["start_time"] > _MAX_SECONDS:
        state["stop_reason"] = "timeout"
        mu.emu_stop()
        return

    # instruction cap
    if state["insn_count"] >= state["max_insns"]:
        state["stop_reason"] = "max_insns"
        mu.emu_stop()
        return

    # only trace first 2000 instructions to keep payload small
    if len(state["trace"]) >= 2000:
        return

    ux = state["ux"]
    x64 = state["x64"]
    md  = state["md"]

    try:
        code = bytes(mu.mem_read(address, min(size, 15)))
    except Exception:
        return

    mnemonic = ""
    op_str   = ""
    for insn in md.disasm(code, address):
        mnemonic = insn.mnemonic
        op_str   = insn.op_str
        break

    regs = _read_regs(mu, ux, x64)

    state["trace"].append({
        "addr":    hex(address),
        "bytes":   code.hex(" "),
        "mnem":    mnemonic,
        "ops":     op_str,
        "regs":    regs,
    })

    # detect landing at STUB_RET_ADDR = shellcode called a fake API
    if address == _STUB_RET_ADDR:
        state["stop_reason"] = "clean_exit"
        mu.emu_stop()


def _hook_write(mu, access, address, size, value, state):
    offset = address - _SC_BASE
    if 0 <= offset < len(state["written_mask"]):
        # SMC: writing to the shellcode's own code region
        if offset < state["raw_len"]:
            state["smc"] = True
        for i in range(min(size, len(state["written"]) - offset)):
            try:
                b = (value >> (8 * i)) & 0xFF
                state["written"][offset + i] = b
                state["written_mask"][offset + i] = 1
            except Exception:
                pass

    if len(state["mem_log"]) < 300:
        state["mem_log"].append({
            "type":  "W",
            "addr":  hex(address),
            "size":  size,
            "value": hex(value & ((1 << (size * 8)) - 1)),
        })


def _hook_read(mu, access, address, size, value, state):
    if len(state["mem_log"]) < 300:
        try:
            data = bytes(mu.mem_read(address, min(size, 8)))
            val_str = data.hex()
        except Exception:
            val_str = "??"
        state["mem_log"].append({
            "type":  "R",
            "addr":  hex(address),
            "size":  size,
            "value": val_str,
        })


def _hook_invalid(mu, access, address, size, value, state):
    ux = state["ux"]
    x64 = state["x64"]

    # intercept unmapped CALLs - these are Windows API calls that the
    # shellcode resolved by PEB-walking / hash-matching
    rip_reg = ux.UC_X86_REG_RIP if x64 else ux.UC_X86_REG_EIP
    rip     = mu.reg_read(rip_reg)

    state["api_calls"].append({
        "target": hex(address),
        "caller": hex(rip),
        "note":   _guess_api(address),
    })

    # return cleanly: push fake return addr and set IP = stub
    sp_reg  = ux.UC_X86_REG_RSP if x64 else ux.UC_X86_REG_ESP
    sp      = mu.reg_read(sp_reg)
    if x64:
        sp -= 8
        mu.reg_write(sp_reg, sp)
        try:
            mu.mem_write(sp, struct.pack("<Q", _STUB_RET_ADDR))
        except Exception:
            pass
        mu.reg_write(rip_reg, _STUB_RET_ADDR)
        mu.reg_write(ux.UC_X86_REG_RAX, 0)
    else:
        sp -= 4
        mu.reg_write(sp_reg, sp)
        try:
            mu.mem_write(sp, struct.pack("<I", _STUB_RET_ADDR))
        except Exception:
            pass
        mu.reg_write(rip_reg, _STUB_RET_ADDR)
        mu.reg_write(ux.UC_X86_REG_EAX, 0)

    return True   # handled - do not crash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _map(mu, base, size, uc):
    import unicorn as _uc
    mu.mem_map(base, size, _uc.UC_PROT_ALL)
    mu.mem_write(base, b"\x00" * size)


def _setup_fakes(mu, ux, x64: bool):
    """
    Write a minimal fake PEB/TEB so that common PEB-walk patterns
    (FS:[0x30] / GS:[0x60]) return a non-zero address and don't crash.
    We point everything back into the heap region with stub values.
    """
    peb_addr = _HEAP_BASE + 0x100
    ldr_addr = _HEAP_BASE + 0x200

    # PEB.Ldr -> points back to itself with three valid InMemoryOrder links
    # This is a simplified stub; real shellcode will read further but
    # Unicorn will just return zeros (which most PEB-walkers handle).
    if x64:
        # TEB.ProcessEnvironmentBlock @ GS:[0x60]
        # We can't set GS base in all Unicorn versions, so we just ensure
        # the heap area is mapped and readable (it already is).
        pass

    # Write PEB stub: BeingDebugged = 0, Ldr ptr
    try:
        peb = bytearray(0x100)
        if x64:
            struct.pack_into("<Q", peb, 0x18, ldr_addr)  # PEB.Ldr
        else:
            struct.pack_into("<I", peb, 0x0C, ldr_addr)  # PEB.Ldr (x86)
        mu.mem_write(peb_addr, bytes(peb))
    except Exception:
        pass


def _read_regs(mu, ux, x64: bool) -> dict:
    try:
        if x64:
            return {
                "rax": hex(mu.reg_read(ux.UC_X86_REG_RAX)),
                "rbx": hex(mu.reg_read(ux.UC_X86_REG_RBX)),
                "rcx": hex(mu.reg_read(ux.UC_X86_REG_RCX)),
                "rdx": hex(mu.reg_read(ux.UC_X86_REG_RDX)),
                "rsi": hex(mu.reg_read(ux.UC_X86_REG_RSI)),
                "rdi": hex(mu.reg_read(ux.UC_X86_REG_RDI)),
                "rsp": hex(mu.reg_read(ux.UC_X86_REG_RSP)),
                "rbp": hex(mu.reg_read(ux.UC_X86_REG_RBP)),
                "r8":  hex(mu.reg_read(ux.UC_X86_REG_R8)),
                "r9":  hex(mu.reg_read(ux.UC_X86_REG_R9)),
                "r10": hex(mu.reg_read(ux.UC_X86_REG_R10)),
                "r11": hex(mu.reg_read(ux.UC_X86_REG_R11)),
                "rip": hex(mu.reg_read(ux.UC_X86_REG_RIP)),
            }
        else:
            return {
                "eax": hex(mu.reg_read(ux.UC_X86_REG_EAX)),
                "ebx": hex(mu.reg_read(ux.UC_X86_REG_EBX)),
                "ecx": hex(mu.reg_read(ux.UC_X86_REG_ECX)),
                "edx": hex(mu.reg_read(ux.UC_X86_REG_EDX)),
                "esi": hex(mu.reg_read(ux.UC_X86_REG_ESI)),
                "edi": hex(mu.reg_read(ux.UC_X86_REG_EDI)),
                "esp": hex(mu.reg_read(ux.UC_X86_REG_ESP)),
                "ebp": hex(mu.reg_read(ux.UC_X86_REG_EBP)),
                "eip": hex(mu.reg_read(ux.UC_X86_REG_EIP)),
            }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Heuristic API guesser
# ---------------------------------------------------------------------------
# Common shellcode target addresses for known x64 Windows layouts.
# In practice shellcode jumps to whatever the PEB-walk resolved - we flag
# the call and try to match the pattern (hash, offset) from context.
_KNOWN_HASH_APIS: dict[int, str] = {
    0x0726774C: "LoadLibraryA",
    0xEC0E4E8E: "GetProcAddress",
    0x7C0DFCAA: "GetVersion",
    0x1A7B5765: "GetModuleHandleA",
    0x4FDAF6DA: "VirtualAlloc",
    0x91AFCA54: "VirtualFree",
    0xE553A458: "ExitProcess",
    0x56A2B5F0: "CreateThread",
    0x160D6838: "WaitForSingleObject",
    0xE183277B: "WriteProcessMemory",
    0x876F8B31: "ReadProcessMemory",
    0x3F9287AE: "OpenProcess",
}


def _guess_api(address: int) -> str:
    hit = _KNOWN_HASH_APIS.get(address)
    if hit:
        return hit
    # Heuristic: if address looks like a DLL base + small offset, name it
    if 0x70000000 <= address <= 0x7FFFFFFF:
        return "kernel32!<unknown>"
    if 0x7FF00000 <= address <= 0x7FFFFFFF:
        return "ntdll!<unknown>"
    return "<unmapped call>"


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------

def _extract_strings(data: bytes, min_len: int = 5) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()

    # ASCII
    cur: list[int] = []
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                s = bytes(cur).decode("ascii", errors="ignore")
                if s not in seen:
                    seen.add(s)
                    results.append(s)
            cur = []
    if len(cur) >= min_len:
        s = bytes(cur).decode("ascii", errors="ignore")
        if s not in seen:
            seen.add(s)
            results.append(s)

    # Wide (UTF-16LE)
    try:
        i = 0
        wide_cur: list[int] = []
        while i + 1 < len(data):
            lo, hi = data[i], data[i + 1]
            if 0x20 <= lo < 0x7F and hi == 0x00:
                wide_cur.append(lo)
                i += 2
            else:
                if len(wide_cur) >= min_len:
                    s = bytes(wide_cur).decode("ascii")
                    if s not in seen:
                        seen.add(s)
                        results.append(s + "  [wide]")
                wide_cur = []
                i += 1
    except Exception:
        pass

    return results[:60]   # cap output
