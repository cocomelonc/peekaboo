"""
anti_analysis.py - Anti-Analysis Pattern Scanner
=================================================
Static Capstone-based scanner that detects anti-debug, anti-VM, timing,
and sandbox-evasion patterns in PE binaries or raw shellcode.

Techniques covered:
  RDTSC          T1497.003  - timing side-channel vs debugger/emulator
  CPUID          T1497.001  - hypervisor bit / vendor string probe
  INT 2D         T1622      - kernel debug interrupt (absorbs next opcode in debugger)
  INT 3 (inline) T1622      - software breakpoint trap outside normal handler
  IN EAX,DX      T1497.001  - VMware I/O backdoor port 0x5658
  SIDT / SGDT    T1497.001  - IDT/GDT location fingerprinting (Red Pill)
  SLDT / STR     T1497.001  - segment selector VM detection
  RDPMC          T1497.003  - performance counter timing
  PEB FS/GS read T1622      - BeingDebugged check via segment register
  NOP sled (≥8)  T1497.003  - emulator budget exhaustion
  PUSHFD/POPFD   T1622      - Trap Flag check / single-step detection
  VPC magic bytes T1497.001 - Virtual PC / Hyper-V detection sequence
  DIV reg        T1622      - intentional divide-by-zero SEH trap
"""
from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Pattern catalog  (id -> metadata)
# ---------------------------------------------------------------------------

CATALOG: list[dict] = [
    dict(id="RDTSC",   category="timing",     mitre="T1497.003", severity="high",
         name="RDTSC timing check",
         desc="Read timestamp counter used to detect single-step debuggers or emulators via delta measurement"),
    dict(id="CPUID",   category="anti_vm",    mitre="T1497.001", severity="medium",
         name="CPUID hypervisor probe",
         desc="CPU identification query - EAX=1 ECX[31] returns hypervisor-present bit; EAX=0x40000000 returns vendor string"),
    dict(id="INT2D",   category="anti_debug", mitre="T1622",     severity="high",
         name="INT 2D (kernel debug interrupt)",
         desc="Triggers a kernel debug path; a debugger absorbs the following opcode byte, causing an instruction skip"),
    dict(id="INT3_AA", category="anti_debug", mitre="T1622",     severity="medium",
         name="INT 3 anti-debug trap (inline CC)",
         desc="Deliberate INT 3 outside a normal exception handler - detects debuggers that intercept breakpoints"),
    dict(id="IN_DX",   category="anti_vm",    mitre="T1497.001", severity="high",
         name="IN EAX,DX - VMware I/O backdoor",
         desc="VMware magic I/O port 0x5658 ('VX'): if EAX=0x564D5868 and DX=0x5658, response confirms VMware"),
    dict(id="SIDT",    category="anti_vm",    mitre="T1497.001", severity="high",
         name="SIDT - IDT location probe (Red Pill)",
         desc="IDT base is 0xFFxxxxxx on real hardware, 0x80xxxxxx in VMs - classic Red Pill / ScoopyNG technique"),
    dict(id="SGDT",    category="anti_vm",    mitre="T1497.001", severity="high",
         name="SGDT - GDT base fingerprint",
         desc="GDT base address leaks VM presence; combined with SIDT gives strong bare-metal vs. virtualized signal"),
    dict(id="SLDT",    category="anti_vm",    mitre="T1497.001", severity="medium",
         name="SLDT - LDT selector check",
         desc="LDT selector is 0 on real hardware, non-zero in some hypervisors (VMware, Virtual PC)"),
    dict(id="STR_REG", category="anti_vm",    mitre="T1497.001", severity="medium",
         name="STR - task register selector",
         desc="Task Register selector 0x40 in VMware vs 0x28 on bare metal - used by Red Pill variants"),
    dict(id="RDPMC",   category="timing",     mitre="T1497.003", severity="medium",
         name="RDPMC - performance counter read",
         desc="Performance counters increment differently in VMs; also used for high-resolution timing side-channels"),
    dict(id="PEB_READ",category="anti_debug", mitre="T1622",     severity="high",
         name="PEB.BeingDebugged read (FS/GS segment)",
         desc="Direct PEB read: FS:[30h] (x86 PEB) or GS:[60h] (x64 PEB) - checks NtCurrentPeb()->BeingDebugged"),
    dict(id="NOP_SLED",category="evasion",    mitre="T1497.003", severity="low",
         name="NOP sled (≥8 consecutive NOPs)",
         desc="Long NOP sleds burn emulator instruction budgets before payload executes - anti-sandbox stall tactic"),
    dict(id="PUSHFD",  category="anti_debug", mitre="T1622",     severity="high",
         name="PUSHFD/POPFD - Trap Flag probe",
         desc="Push/pop EFLAGS to inspect or clear the Trap Flag (bit 8), detecting hardware single-step debugging"),
    dict(id="VPC_MAGIC",category="anti_vm",   mitre="T1497.001", severity="high",
         name="VPC/Hyper-V magic instruction (0F 3F 07 0B)",
         desc="Microsoft Virtual PC intercepts this illegal-instruction sequence; used by VPC/Hyper-V detection code"),
    dict(id="DIV_ZERO",category="anti_debug", mitre="T1622",     severity="medium",
         name="DIV/IDIV register - potential SEH trap",
         desc="Division by a register that may be zero triggers an exception; debuggers catch it instead of the SEH handler"),
]

_BY_ID = {c["id"]: c for c in CATALOG}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_pe(pe_path: Path, arch: str = "auto") -> dict:
    """Scan all executable sections of a PE file."""
    try:
        import pefile
        pe = pefile.PE(str(pe_path), fast_load=False)
    except ImportError:
        return {"ok": False, "error": "pefile not installed - run: pip install pefile"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    if arch == "auto":
        arch = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"

    findings: list[dict] = []
    total_bytes = 0

    for section in pe.sections:
        if not (section.Characteristics & 0x20000000):   # IMAGE_SCN_MEM_EXECUTE
            continue
        data = section.get_data()
        va   = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        total_bytes += len(data)
        findings.extend(_scan_bytes(data, arch, base_va=va, section=name))

    pe.close()
    return _build_result(findings, total_bytes, arch)


def scan_raw(raw: bytes, arch: str = "x64", base_va: int = 0x400000) -> dict:
    """Scan raw shellcode or a full PE blob."""
    findings = _scan_bytes(raw, arch, base_va=base_va, section="raw")
    return _build_result(findings, len(raw), arch)


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------

def _build_result(findings: list[dict], total_bytes: int, arch: str) -> dict:
    by_cat: dict[str, int] = {}
    mitre_map: dict[str, set] = {}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
        mitre_map.setdefault(f["mitre"], set()).add(f["id"])

    mitre_summary = [
        {"id": mid, "techniques": sorted(ids)}
        for mid, ids in sorted(mitre_map.items())
    ]

    _sev = {"high": 0, "medium": 1, "low": 2}
    findings_sorted = sorted(findings, key=lambda f: (_sev.get(f["severity"], 9), f["offset"]))

    return {
        "ok":            True,
        "arch":          arch,
        "bytes_scanned": total_bytes,
        "total":         len(findings),
        "by_category":   by_cat,
        "mitre_summary": mitre_summary,
        "findings":      findings_sorted,
    }


# ---------------------------------------------------------------------------
# Core byte scanner (Capstone-driven)
# ---------------------------------------------------------------------------

def _scan_bytes(data: bytes, arch: str, base_va: int = 0, section: str = "?") -> list[dict]:
    try:
        import capstone
    except ImportError:
        raise RuntimeError("capstone not installed - run: pip install capstone")

    md = capstone.Cs(
        capstone.CS_ARCH_X86,
        capstone.CS_MODE_64 if arch == "x64" else capstone.CS_MODE_32,
    )
    md.detail = False

    findings: list[dict] = []
    insns    = list(md.disasm(data, base_va))

    nop_run   = 0
    nop_off   = 0
    nop_va    = 0

    for idx, insn in enumerate(insns):
        offset = insn.address - base_va
        mnem   = insn.mnemonic.lower()
        ops    = insn.op_str.lower()
        raw    = bytes(insn.bytes)

        # --- NOP sled tracking ---
        if mnem == "nop" and len(raw) == 1:
            if nop_run == 0:
                nop_off = offset
                nop_va  = insn.address
            nop_run += 1
        else:
            if nop_run >= 8:
                findings.append(_hit("NOP_SLED", nop_off, nop_va, section,
                                     bytes([0x90] * min(nop_run, 16)),
                                     extra=f"{nop_run} consecutive NOPs"))
            nop_run = 0

        # --- Check raw bytes first for patterns Capstone may decode oddly ---
        if len(raw) >= 4 and raw[:4] == bytes([0x0F, 0x3F, 0x07, 0x0B]):
            findings.append(_hit("VPC_MAGIC", offset, insn.address, section, raw))
            continue

        hit = None

        if mnem == "rdtsc":
            hit = "RDTSC"

        elif mnem == "cpuid":
            hit = "CPUID"

        elif mnem == "int" and ops.strip() in ("0x2d", "2d", "45"):
            hit = "INT2D"

        elif mnem == "int3":
            hit = "INT3_AA"

        elif mnem in ("in", "inb", "inw", "inl") and "dx" in ops:
            hit = "IN_DX"

        elif mnem == "sidt":
            hit = "SIDT"

        elif mnem == "sgdt":
            hit = "SGDT"

        elif mnem == "sldt":
            hit = "SLDT"

        elif mnem == "str":
            hit = "STR_REG"

        elif mnem == "rdpmc":
            hit = "RDPMC"

        elif mnem in ("pushfd", "pushfq"):
            if idx + 1 < len(insns):
                nx = insns[idx + 1].mnemonic.lower()
                if "popf" in nx or "and" in nx or "or" in nx or "test" in nx:
                    hit = "PUSHFD"
            else:
                hit = "PUSHFD"

        elif mnem == "mov":
            # x86: FS:[0x30] = PEB, FS:[0x18] = TEB.Self
            if re.search(r"fs:\s*(?:\[?\s*0x30\s*\]?|\[?\s*0x18\s*\]?|\[?\s*0x24\s*\]?)", ops):
                hit = "PEB_READ"
            # x64: GS:[0x60] = PEB, GS:[0x30] = TEB.Self
            elif re.search(r"gs:\s*(?:\[?\s*0x60\s*\]?|\[?\s*0x30\s*\]?|\[?\s*0x28\s*\]?)", ops):
                hit = "PEB_READ"

        elif mnem in ("div", "idiv"):
            # Only flag if operand is a plain register (potential zero-div trap)
            if ops and not any(c.isdigit() for c in ops.replace("0x", "").replace("ptr", "")):
                hit = "DIV_ZERO"

        if hit:
            findings.append(_hit(hit, offset, insn.address, section, raw))

    # flush trailing NOP sled
    if nop_run >= 8:
        findings.append(_hit("NOP_SLED", nop_off, nop_va, section,
                              bytes([0x90] * min(nop_run, 16)),
                              extra=f"{nop_run} consecutive NOPs"))

    return findings


def _hit(pattern_id: str, offset: int, va: int, section: str,
         raw: bytes, extra: str = "") -> dict:
    cat = _BY_ID[pattern_id]
    return {
        "id":       pattern_id,
        "name":     cat["name"],
        "category": cat["category"],
        "mitre":    cat["mitre"],
        "severity": cat["severity"],
        "desc":     cat["desc"] + (f"  [{extra}]" if extra else ""),
        "offset":   offset,
        "va":       hex(va),
        "section":  section,
        "bytes":    raw[:8].hex(" "),
    }
