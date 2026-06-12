"""
rop_builder.py - ROP Chain Builder
===================================
Finds Return-Oriented Programming gadgets in PE binaries (x64/x86)
or raw shellcode blobs using Capstone disassembly.

Gadget types detected:
  ret           - plain RET / RETN N / RETF
  jmp_reg       - JMP reg / JMP [reg]
  call_reg      - CALL reg / CALL [reg]
  syscall       - SYSCALL; RET  (x64 direct-syscall gadget)
  int            - INT 0x2e; RET  (x86 syscall)

Semantic classification:
  stack_pivot   - xchg rsp/esp with any reg
  reg_load      - pop <reg>; ret
  reg_mov       - mov <reg>, <reg>; ret
  mem_write     - mov [reg], reg; ret  /  mov [reg+N], reg; ret
  mem_read      - mov reg, [reg]; ret
  arithmetic    - add/sub/xor/and/or <reg>, <reg|imm>; ret
  nop_ret       - single NOP; ret  (padding gadget)
  syscall       - syscall; ret  (direct-syscall)
  conditional   - test/cmp + jz/jnz + ...  (branching gadgets)
  misc          - anything that ends in ret but doesn't fit above
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
MAX_GADGET_LEN  = 6   # instructions before the terminator
MAX_GADGET_BYTES = 24  # raw bytes budget
MAX_GADGETS     = 4000 # hard cap per binary (perf guard)

# Terminators we care about
_RET_MNEMS   = {"ret", "retn", "retf", "retq"}
_JMP_REG     = {"jmp"}
_CALL_REG    = {"call"}

# Registers (Capstone lower-case names)
_REGS_64 = {"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
             "r8","r9","r10","r11","r12","r13","r14","r15"}
_REGS_32 = {"eax","ebx","ecx","edx","esi","edi","ebp","esp"}
_REGS_ALL = _REGS_64 | _REGS_32


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_pe(pe_path: Path, arch: str = "auto",
            image_base: Optional[int] = None) -> dict:
    """Find ROP gadgets in all executable sections of a PE file."""
    try:
        import pefile
        pe = pefile.PE(str(pe_path), fast_load=False)
    except ImportError:
        return {"ok": False, "error": "pefile not installed - run: pip install pefile"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    if arch == "auto":
        arch = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"

    base = image_base if image_base is not None else pe.OPTIONAL_HEADER.ImageBase

    gadgets: list[dict] = []
    sections_info: list[dict] = []

    for section in pe.sections:
        if not (section.Characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
            continue
        data = section.get_data()
        va   = base + section.VirtualAddress
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        sections_info.append({"name": name, "va": hex(va), "size": len(data)})
        new_gadgets = _find_gadgets(data, arch, va, name)
        gadgets.extend(new_gadgets)
        if len(gadgets) >= MAX_GADGETS:
            gadgets = gadgets[:MAX_GADGETS]
            break

    pe.close()
    return _build_result(gadgets, arch, base, sections_info,
                         file_name=pe_path.name)


def scan_raw(raw: bytes, arch: str = "x64",
             image_base: int = 0x400000) -> dict:
    """Find ROP gadgets in a raw shellcode or PE blob."""
    gadgets = _find_gadgets(raw, arch, image_base, "raw")
    return _build_result(gadgets, arch, image_base, [], file_name="raw")


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------

def _build_result(gadgets: list[dict], arch: str, base: int,
                  sections: list[dict], file_name: str = "") -> dict:
    by_type: dict[str, int] = {}
    by_sem:  dict[str, int] = {}
    for g in gadgets:
        by_type[g["term_type"]] = by_type.get(g["term_type"], 0) + 1
        by_sem[g["semantic"]]   = by_sem.get(g["semantic"],   0) + 1

    return {
        "ok":        True,
        "arch":      arch,
        "base":      hex(base),
        "file_name": file_name,
        "total":     len(gadgets),
        "by_type":   by_type,
        "by_semantic": by_sem,
        "sections":  sections,
        "gadgets":   gadgets,
    }


# ---------------------------------------------------------------------------
# Core gadget finder
# ---------------------------------------------------------------------------

def _find_gadgets(data: bytes, arch: str, base_va: int,
                  section: str) -> list[dict]:
    try:
        import capstone
    except ImportError:
        raise RuntimeError("capstone not installed - run: pip install capstone")

    md = capstone.Cs(
        capstone.CS_ARCH_X86,
        capstone.CS_MODE_64 if arch == "x64" else capstone.CS_MODE_32,
    )
    md.detail = False

    # Disassemble the whole section once into a list for offset lookup
    insns = list(md.disasm(data, base_va))

    # Build offset->index map for fast reverse lookup
    addr_to_idx: dict[int, int] = {ins.address: i for i, ins in enumerate(insns)}

    gadgets: list[dict] = []

    for idx, insn in enumerate(insns):
        mnem = insn.mnemonic.lower()
        ops  = insn.op_str.lower().strip()

        # ---- Determine if this instruction terminates a gadget ----
        term_type = _terminator_type(mnem, ops)
        if term_type is None:
            continue

        # Walk backwards up to MAX_GADGET_LEN instructions
        for depth in range(1, MAX_GADGET_LEN + 1):
            start_idx = idx - depth
            if start_idx < 0:
                break

            # Check the gadget slice is contiguous in memory
            # (no gaps - instruction sequence must be sequential bytes)
            start_insn = insns[start_idx]
            if not _is_contiguous(insns, start_idx, idx):
                break

            raw_bytes = data[
                start_insn.address - base_va : insn.address - base_va + len(insn.bytes)
            ]
            if len(raw_bytes) > MAX_GADGET_BYTES:
                break

            # Build instruction text for the gadget
            slice_insns = insns[start_idx : idx + 1]
            asm_lines = [f"{i.mnemonic} {i.op_str}".strip() for i in slice_insns]

            semantic = _classify_semantic(slice_insns, arch)

            gadgets.append({
                "addr":      hex(start_insn.address),
                "rva":       hex(start_insn.address - base_va),
                "section":   section,
                "term_type": term_type,
                "semantic":  semantic,
                "insns":     asm_lines,
                "bytes":     raw_bytes.hex(" "),
                "depth":     depth,         # number of instructions before terminator
            })

            if len(gadgets) >= MAX_GADGETS:
                return gadgets

    return gadgets


def _is_contiguous(insns: list, start: int, end: int) -> bool:
    """Return True if insns[start..end] form a contiguous byte sequence."""
    for i in range(start, end):
        expected_next = insns[i].address + len(insns[i].bytes)
        if expected_next != insns[i + 1].address:
            return False
    return True


# ---------------------------------------------------------------------------
# Terminator classification
# ---------------------------------------------------------------------------

def _terminator_type(mnem: str, ops: str) -> Optional[str]:
    if mnem in _RET_MNEMS:
        return "ret"

    if mnem in _JMP_REG:
        if _is_reg_or_mem_reg(ops):
            return "jmp_reg"

    if mnem in _CALL_REG:
        if _is_reg_or_mem_reg(ops):
            return "call_reg"

    return None


def _is_reg_or_mem_reg(ops: str) -> bool:
    """True if operand is a plain register or [register] / [register+offset]."""
    ops = ops.strip()
    # plain register
    if ops in _REGS_ALL:
        return True
    # [reg] or [reg+N] or [reg-N] or qword ptr [reg]
    if "[" in ops:
        inner = ops[ops.index("[") + 1 : ops.rindex("]")]
        base  = inner.split("+")[0].split("-")[0].strip()
        return base in _REGS_ALL
    return False


# ---------------------------------------------------------------------------
# Semantic classifier
# ---------------------------------------------------------------------------

def _classify_semantic(insns: list, arch: str) -> str:
    """Assign a human-readable semantic category to a gadget."""
    # Single-instruction gadgets (just the terminator)
    if len(insns) == 1:
        return "ret_only"

    # Everything except the terminator
    body = insns[:-1]
    first = body[0]
    m0    = first.mnemonic.lower()
    o0    = first.op_str.lower().strip()

    # syscall; ret  /  int 0x2e; ret  (direct-syscall gadgets)
    if len(body) == 1 and m0 in ("syscall", "sysenter"):
        return "syscall"
    if len(body) == 1 and m0 == "int" and o0 in ("0x2e", "2e"):
        return "syscall"

    # stack pivot: xchg rsp/esp ↔ anything  or  mov rsp, reg
    for ins in body:
        m = ins.mnemonic.lower()
        o = ins.op_str.lower()
        if m == "xchg" and ("rsp" in o or "esp" in o):
            return "stack_pivot"
        if m == "mov" and o.startswith(("rsp,", "esp,")):
            return "stack_pivot"
        if m in ("leave",):
            return "stack_pivot"

    # reg_load: pop <reg> ; ret
    if len(body) == 1 and m0 == "pop" and o0 in _REGS_ALL:
        return "reg_load"

    # reg_mov: mov <reg>, <reg>
    if len(body) == 1 and m0 == "mov":
        parts = [p.strip() for p in o0.split(",")]
        if len(parts) == 2 and parts[0] in _REGS_ALL and parts[1] in _REGS_ALL:
            return "reg_mov"

    # mem_write: mov [reg...], reg
    if m0 == "mov" and "[" in o0:
        parts = [p.strip() for p in o0.split(",", 1)]
        if len(parts) == 2 and parts[0].startswith("[") and parts[1] in _REGS_ALL:
            return "mem_write"

    # mem_read: mov reg, [reg...]
    if m0 == "mov" and "[" in o0:
        parts = [p.strip() for p in o0.split(",", 1)]
        if len(parts) == 2 and parts[0] in _REGS_ALL and "[" in parts[1]:
            return "mem_read"

    # arithmetic: add/sub/xor/and/or/neg/not/inc/dec
    if m0 in ("add", "sub", "xor", "and", "or", "neg", "not", "inc", "dec",
              "imul", "mul", "shl", "shr", "sar", "ror", "rol"):
        return "arithmetic"

    # nop_ret
    if all(i.mnemonic.lower() == "nop" for i in body):
        return "nop_ret"

    # multi-pop sequence
    if all(i.mnemonic.lower() == "pop" for i in body):
        return "multi_pop"

    return "misc"
