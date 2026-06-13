"""
evasion.py - PE evasion score analyser + patch transforms.

Scores a binary 0-100 (higher = harder to detect) across four categories
(entropy, imports, strings, PE structure) and applies surgical PE transforms
(timestamp, Rich header, debug dir, sections, checksum, …).

Public API (kept stable):
  - analyse(data, filename="") -> dict
  - apply_patches(data, patch_ids) -> (patched_bytes, applied_messages)
  - PATCH_IDS: frozenset[str]      # single source of truth for valid IDs
  - HAS_PEFILE: bool

Design after the refactor:
  * Patches are typed `Patch` records in a `_PATCHES` registry. The previous
    19-branch if/elif chain in apply_patches() is now a single loop.
  * analyse() orchestrates four pure sub-scorers (_score_entropy / _score_imports
    / _score_strings / _score_structure). Each returns (score, findings, extras)
    so the public API shape doesn't change but the function is readable.
"""
from __future__ import annotations

import hashlib
import math
import random
import re
import struct
from dataclasses import dataclass
from typing import Callable, Optional

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# =============================================================================
# 1. Static data: indicator dictionaries, PE constants
# =============================================================================

_RED_IMPORTS = {
    "VirtualAlloc":           "allocates RWX memory - classic shellcode loader",
    "VirtualAllocEx":         "cross-process RWX allocation - injection primitive",
    "VirtualProtect":         "changes memory permissions - common after allocation",
    "WriteProcessMemory":     "writes into another process - injection primitive",
    "CreateRemoteThread":     "spawns thread in remote process - classic DLL injection",
    "NtAllocateVirtualMemory":"low-level alloc - NTAPI injection",
    "NtWriteVirtualMemory":   "low-level write - NTAPI injection",
    "NtCreateThreadEx":       "NTAPI thread creation - stealth injection",
    "QueueUserAPC":           "APC injection primitive",
    "SetWindowsHookEx":       "hook injection / keylogger",
    "CreateProcess":          "process creation - execution primitive",
    "OpenProcess":            "opens target process - injection prerequisite",
    "GetProcAddress":         "runtime API resolution - dynamic loading / obfuscation bypass",
    "LoadLibrary":            "dynamic DLL load - can bypass import scanning",
    "LoadLibraryA":           "dynamic DLL load (A)",
    "LoadLibraryW":           "dynamic DLL load (W)",
    "GetModuleHandle":        "enumerates loaded modules - reconnaissance",
    "WinExec":                "legacy process execution - simple backdoor pattern",
    "ShellExecute":           "shell execution - UAC bypass chains",
    "ShellExecuteA":          "shell execution (A)",
    "ShellExecuteW":          "shell execution (W)",
    "CreateThread":           "spawns local thread - payload kickoff",
    "ResumeThread":           "resumes suspended thread - process hollowing final step",
    "SuspendThread":          "suspends thread - process hollowing setup",
    "ReadProcessMemory":      "cross-process read - credential harvesting / LSASS dump",
    "AdjustTokenPrivileges":  "token manipulation - privilege escalation setup",
    "OpenProcessToken":       "opens process token - privilege manipulation",
    "IsDebuggerPresent":      "anti-debug check",
    "CheckRemoteDebuggerPresent": "anti-debug check (remote)",
    "OutputDebugString":      "debug string - may indicate debug-aware code",
    "MiniDumpWriteDump":      "process dump - LSASS / credential theft",
    "CryptEncrypt":           "encryption - possible C2 channel or data exfil",
    "CryptDecrypt":           "decryption - possible payload decoding",
    "InternetOpen":           "WinINet C2 - network communication",
    "InternetConnect":        "WinINet connect - C2 callback",
    "HttpSendRequest":        "HTTP C2 request",
    "URLDownloadToFile":      "downloads file from URL - dropper pattern",
    "WSAStartup":             "WinSock init - network communication",
    "socket":                 "raw socket - possible C2",
    "connect":                "socket connect - C2 callback",
    "send":                   "socket send - data exfil",
    "recv":                   "socket receive - C2 command",
    "RegOpenKey":             "registry access - persistence / credential theft",
    "RegOpenKeyEx":           "registry access (Ex)",
    "RegSetValue":            "registry write - persistence",
    "RegSetValueEx":          "registry write (Ex) - persistence",
    "RegCreateKey":           "registry create - persistence",
    "RegCreateKeyEx":         "registry create (Ex)",
    "RtlDecompressBuffer":    "decompresses data - packed payload",
}

_YELLOW_IMPORTS = {
    "CreateFile", "ReadFile", "WriteFile", "DeleteFile",
    "CopyFile", "MoveFile", "FindFirstFile", "FindNextFile",
    "GetTempPath", "GetTempFileName",
    "SetFileAttributes",
    "NetUserGetInfo", "NetGroupGetUsers",
    "CryptAcquireContext", "CryptCreateHash", "CryptHashData",
    "CoCreateInstance", "OleInitialize",
}

_STRING_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
     "IP-based C2 URL",            "high"),
    (re.compile(r'https?://[a-z0-9\-]{3,}\.[a-z]{2,6}', re.I),
     "hardcoded URL",              "medium"),
    (re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}'),
     "IP:port C2 address",         "high"),
    (re.compile(r'(?:password|passwd|secret|apikey|token|credential)', re.I),
     "credential keyword",         "medium"),
    (re.compile(r'(?:mimikatz|meterpreter|beacon|cobalt.?strike|metasploit)', re.I),
     "offensive tool name",        "critical"),
    (re.compile(r'cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe', re.I),
     "shell binary reference",     "medium"),
    (re.compile(r'\\\\\.\\(?:PhysicalDrive|pipe\\)', re.I),
     "raw device / named pipe",    "high"),
    (re.compile(r'HKEY_|HKLM|HKCU|HKCR', re.I),
     "registry root reference",    "low"),
    (re.compile(r'SeDebugPrivilege|SeTcbPrivilege|SeImpersonatePrivilege'),
     "privilege constant",         "medium"),
    (re.compile(r'(?:inject|shellcode|payload|exploit|backdoor|trojan)', re.I),
     "malware-related keyword",    "high"),
    (re.compile(r'(?:\.exe|\.dll|\.bat|\.ps1|\.vbs|\.hta)$', re.I),
     "executable extension",       "low"),
    (re.compile(r'(?:RUNME|autorun|startup|persistence)', re.I),
     "persistence keyword",        "medium"),
]

_STRING_SUGGESTIONS: dict[str, str] = {
    "IP-based C2 URL":        "Move C2 address to runtime config or resolve via DGA; never hardcode IPs.",
    "hardcoded URL":          "Store the C2 URL encrypted/encoded and decode at runtime.",
    "IP:port C2 address":     "Use domain-based C2 with DGA or dynamic DNS instead of raw IPs.",
    "credential keyword":     "Never embed credentials in binary; use external config or registry.",
    "offensive tool name":    "Remove all references to known tool names; they trigger exact-match signatures.",
    "shell binary reference": "Load shell paths dynamically via GetSystemDirectory instead of hardcoding.",
    "raw device / named pipe":"Obfuscate named pipe strings; build them at runtime.",
    "registry root reference":"Build registry paths at runtime using string concatenation.",
    "privilege constant":     "Use numeric values instead of string constant names.",
    "malware-related keyword":"Rename all functions/variables; strip debug symbols.",
    "executable extension":   "Minor concern - consider encoding extension strings.",
    "persistence keyword":    "Rename to innocuous identifiers.",
}

_SUSPICIOUS_SECTION_NAMES = {'.text', '.data', '.rdata', '.bss', '.idata', '.edata', '.reloc', '.rsrc'}

_SECTION_RENAME_MAP = {
    '.text':  '.code', '.data':  '.cfg',  '.rdata': '.init', '.bss':   '.heap',
    '.idata': '.api',  '.edata': '.exp',  '.reloc': '.fix',  '.rsrc':  '.res',
}

# Curated compile timestamps from known Windows system DLLs
_LEGIT_TIMESTAMPS: list[tuple[int, str]] = [
    (0x5C4C9FE0, "ntdll.dll Win10 1809"),
    (0x5C4CA0A5, "kernel32.dll Win10 1809"),
    (0x5E45D5C1, "ntdll.dll Win10 2004"),
    (0x5F78B0D1, "kernel32.dll Win10 20H2"),
    (0x60B7A4A0, "ntdll.dll Win10 21H1"),
    (0x6196C6BE, "kernel32.dll Win10 21H2"),
    (0x62AA6F30, "ntdll.dll Win11 22H2"),
    (0x63571F12, "kernel32.dll Win11 22H2"),
    (0x5D5B2C52, "ntdll.dll Win10 1903"),
    (0x5D5B2B81, "kernel32.dll Win10 1903"),
    (0x5E8B7B85, "ntdll.dll Win10 1909"),
    (0x5E92B0D4, "combase.dll Win10 1909"),
    (0x60563C6B, "ntdll.dll Win10 2009"),
    (0x64B83E56, "ntdll.dll Win11 23H2"),
    (0x65C40392, "kernel32.dll Win11 23H2"),
]

# PE DllCharacteristics flags
_DYNAMIC_BASE    = 0x0040
_NX_COMPAT       = 0x0100
_HIGH_ENTROPY_VA = 0x0020

_SUBSYSTEM_GUI     = 2
_SUBSYSTEM_CONSOLE = 3

# DataDirectory indices
_DIR_EXPORT       = 0
_DIR_SECURITY     = 4
_DIR_LOAD_CONFIG  = 10
_DIR_BOUND_IMPORT = 11

_DOS_STUB_STRING = b'This program cannot be run in DOS mode'

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "ok": 5}


# =============================================================================
# 2. Small utilities
# =============================================================================

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return round(-sum((f / n) * math.log2(f / n) for f in freq if f), 3)


_ASCII_STRING_RE = re.compile(rb'[\x20-\x7e]{6,}')


def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    rx = _ASCII_STRING_RE if min_len == 6 else re.compile(
        rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
    )
    return [m.group().decode('ascii', errors='ignore') for m in rx.finditer(data)]


def _find_rich_header(data: bytes) -> Optional[tuple[int, int]]:
    rich = data.find(b'Rich')
    if rich == -1 or rich > 0x200:
        return None
    dans = data.find(b'DanS')
    if dans == -1 or dans > rich:
        return None
    return (dans, rich + 8)


def _find_pe_timestamp_offset(data: bytes) -> Optional[int]:
    try:
        if data[:2] != b'MZ':
            return None
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_off + 8 > len(data) or data[pe_off:pe_off+4] != b'PE\x00\x00':
            return None
        return pe_off + 8
    except Exception:
        return None


def _find_pdb_path(data: bytes) -> Optional[str]:
    pos = data.find(b'RSDS')
    if pos == -1:
        return None
    try:
        path_start = pos + 4 + 16 + 4
        if path_start >= len(data):
            return None
        end = data.find(b'\x00', path_start)
        if end == -1 or end - path_start > 260:
            return None
        path = data[path_start:end].decode('utf-8', errors='ignore')
        return path if path.endswith('.pdb') or '.pdb' in path.lower() else None
    except Exception:
        return None


def _dd_file_offset(data: bytes, index: int) -> Optional[int]:
    try:
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        magic  = struct.unpack_from('<H', data, pe_off + 24)[0]
        dd_base = pe_off + 24 + (96 if magic == 0x010b else 112)
        return dd_base + index * 8
    except Exception:
        return None


def _string_suggestion(label: str) -> Optional[str]:
    return _STRING_SUGGESTIONS.get(label)


def _safe_open_pe(data: bytes, fast: bool = False):
    """Open a PE; return None on failure. Caller is responsible for .close()."""
    if not HAS_PEFILE or data[:2] != b'MZ':
        return None
    try:
        return pefile.PE(data=data, fast_load=fast)
    except Exception:
        return None


# =============================================================================
# 3. Per-category scorers - each returns (score:int, findings:list, extras:dict)
# =============================================================================

def _score_entropy(data: bytes) -> tuple[int, list[dict], dict]:
    e = _entropy(data)
    if e > 7.5:
        return 5, [{"severity": "high", "category": "entropy",
            "title": f"Very high file entropy ({e})",
            "detail": "Values above 7.5 strongly suggest packed, encrypted, or compressed content.",
            "suggestion": "Add entropy-lowering padding: insert a .rsrc section with repetitive data, or use compression-then-encrypt instead of encrypt-only."}], {"file_entropy": e}
    if e > 7.0:
        return 12, [{"severity": "medium", "category": "entropy",
            "title": f"High file entropy ({e})",
            "detail": "AV heuristics flag high-entropy executables as potentially packed.",
            "suggestion": "Embed null-byte padding or a large icon resource to dilute entropy below 7.0."}], {"file_entropy": e}
    if e > 6.5:
        return 18, [{"severity": "low", "category": "entropy",
            "title": f"Elevated file entropy ({e})",
            "detail": "Slightly above typical for compiled C code (5.5-6.5).",
            "suggestion": "Minor concern - consider adding a padding resource if targeting strict AV."}], {"file_entropy": e}
    return 25, [{"severity": "ok", "category": "entropy",
        "title": f"Normal file entropy ({e})",
        "detail": "Within the expected range for compiled executables.",
        "suggestion": None}], {"file_entropy": e}


def _score_imports(data: bytes, pe) -> tuple[int, list[dict], dict]:
    if data[:2] != b'MZ':
        return 10, [{"severity": "medium", "category": "imports",
            "title": "Not a PE file - no import table",
            "detail": "Raw shellcode or non-PE binary. AV will rely on byte patterns and entropy.",
            "suggestion": "If this is shellcode, consider embedding in a legitimate PE loader."}], {
            "suspicious_imports": [], "sections": []}

    findings: list[dict] = []
    sections_info: list[dict] = []
    red_hits: list[dict] = []
    yellow_hits: list[str] = []

    if pe is None:
        return 25, [], {"suspicious_imports": [], "sections": []}

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if not imp.name:
                    continue
                name = imp.name.decode('utf-8', errors='ignore')
                if name in _RED_IMPORTS:
                    red_hits.append({"name": name, "reason": _RED_IMPORTS[name]})
                elif name in _YELLOW_IMPORTS:
                    yellow_hits.append(name)

    deduction = min(25, len(red_hits) * 4 + len(yellow_hits))
    score = max(0, 25 - deduction)

    if len(red_hits) >= 5:
        findings.append({"severity": "critical", "category": "imports",
            "title": f"{len(red_hits)} high-risk API imports detected",
            "detail": f"Flagged: {', '.join(h['name'] for h in red_hits[:6])}{'...' if len(red_hits)>6 else ''}",
            "suggestion": "Resolve critical APIs at runtime using import-by-hash (djb2 or ROR13). Avoid keeping VirtualAlloc, WriteProcessMemory in the IAT."})
    elif len(red_hits) >= 2:
        findings.append({"severity": "high", "category": "imports",
            "title": f"{len(red_hits)} suspicious API imports",
            "detail": f"Flagged: {', '.join(h['name'] for h in red_hits)}",
            "suggestion": "Use GetProcAddress at runtime or direct syscalls for the most flagged APIs."})
    elif red_hits:
        findings.append({"severity": "medium", "category": "imports",
            "title": f"{len(red_hits)} mildly suspicious import(s)",
            "detail": red_hits[0]["name"] + ": " + red_hits[0]["reason"],
            "suggestion": "Consider resolving via GetProcAddress to remove from static IAT."})
    else:
        findings.append({"severity": "ok", "category": "imports",
            "title": "No high-risk imports in IAT",
            "detail": "Static import table looks clean.",
            "suggestion": None})

    # per-section analysis lives here because it's the same pefile.PE() we just used
    for sec in pe.sections:
        sname = sec.Name.rstrip(b'\x00').decode('utf-8', errors='replace')
        sdata = sec.get_data()
        sent  = _entropy(sdata) if sdata else 0.0
        ch    = sec.Characteristics
        is_x  = bool(ch & 0x20000000)
        is_w  = bool(ch & 0x80000000)
        is_r  = bool(ch & 0x40000000)
        sections_info.append({
            "name": sname, "entropy": round(sent, 3),
            "size": sec.SizeOfRawData, "vsize": sec.Misc_VirtualSize,
            "exec": is_x, "write": is_w, "read": is_r,
            "rwx":  is_x and is_w,
        })
        if is_x and sent > 7.2:
            findings.append({"severity": "high", "category": "entropy",
                "title": f"Executable section '{sname}' has very high entropy ({round(sent,2)})",
                "detail": "High-entropy executable sections are a strong heuristic for packed/encrypted shellcode.",
                "suggestion": "Decrypt at runtime into a separate allocation; keep the .text section itself low-entropy."})
        if is_x and is_w:
            findings.append({"severity": "critical", "category": "structure",
                "title": f"Section '{sname}' is simultaneously executable and writable (RWX)",
                "detail": "RWX sections are flagged by most modern AV/EDR as shellcode containers.",
                "suggestion": "Use VirtualProtect to switch W->X at runtime; never create the section with both flags."})

    return score, findings, {
        "suspicious_imports": red_hits[:20],
        "sections": sections_info,
    }


def _score_strings(data: bytes) -> tuple[int, list[dict], dict]:
    strings = _extract_strings(data)
    findings: list[dict] = []
    suspicious: list[str] = []
    seen: set[str] = set()
    n_findings = 0

    for pattern, label, severity in _STRING_PATTERNS:
        for s in strings:
            if pattern.search(s) and s not in seen:
                seen.add(s)
                suspicious.append(s)
                if n_findings < 4:
                    findings.append({"severity": severity, "category": "strings",
                        "title": f"String indicator: {label}",
                        "detail": repr(s[:80]),
                        "suggestion": _string_suggestion(label)})
                n_findings += 1
                break  # one finding per pattern type

    score = max(0, 25 - min(25, n_findings * 5))
    if n_findings == 0:
        findings.append({"severity": "ok", "category": "strings",
            "title": "No obvious string indicators",
            "detail": "No hardcoded IPs, URLs, credentials, or tool names found.",
            "suggestion": None})

    return score, findings, {"suspicious_strings": suspicious[:20]}


def _score_structure(data: bytes, pe) -> tuple[int, list[dict], dict]:
    if data[:2] != b'MZ':
        return 25, [], {}

    findings: list[dict] = []
    deductions = 0

    # timestamp
    ts_off = _find_pe_timestamp_offset(data)
    if ts_off is not None:
        ts_val = struct.unpack_from('<I', data, ts_off)[0]
        if ts_val != 0:
            deductions += 3
            findings.append({"severity": "low", "category": "structure",
                "title": f"Non-zero PE compile timestamp (0x{ts_val:08x})",
                "detail": "Compile timestamps are used for binary correlation and threat intel pivoting.",
                "suggestion": "Zero the TimeDateStamp field at offset in Optional Header to prevent correlation."})

    if _find_rich_header(data):
        deductions += 5
        findings.append({"severity": "medium", "category": "structure",
            "title": "Rich header present (compiler fingerprint)",
            "detail": "The Rich header encodes MSVC version + object file metadata, used by threat intel to cluster samples.",
            "suggestion": "Wipe the Rich header: XOR region to zero (the key is embedded in the header)."})

    if (pdb := _find_pdb_path(data)):
        deductions += 4
        findings.append({"severity": "medium", "category": "structure",
            "title": f"Debug directory / PDB path: {pdb[:60]}",
            "detail": "PDB paths expose developer usernames, build system paths, and project names.",
            "suggestion": "Zero the debug directory entry or strip the PDB path before distribution."})

    if pe is not None:
        default_names = [s.Name.rstrip(b'\x00').decode('utf-8','ignore')
                         for s in pe.sections
                         if s.Name.rstrip(b'\x00').decode('utf-8','ignore') in _SUSPICIOUS_SECTION_NAMES]
        if len(default_names) >= 3:
            deductions += 5
            findings.append({"severity": "medium", "category": "structure",
                "title": f"Default MSVC section names ({', '.join(default_names[:4])})",
                "detail": "Default section names are a reliable compiler fingerprint.",
                "suggestion": "Rename sections to non-standard names (e.g. .code, .cfg, .init) using a PE editor."})
        elif default_names:
            deductions += 2

    if _DOS_STUB_STRING in data[:0x100]:
        deductions += 2
        findings.append({"severity": "low", "category": "structure",
            "title": "Default DOS stub message present",
            "detail": "The standard MSVC 'This program cannot be run in DOS mode' string is a reliable compiler fingerprint.",
            "suggestion": "Replace the DOS stub with a custom message or zero it out."})

    if pe is not None:
        try:
            dll_char  = pe.OPTIONAL_HEADER.DllCharacteristics
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            if not (dll_char & _DYNAMIC_BASE) or not (dll_char & _NX_COMPAT):
                deductions += 3
                missing = []
                if not (dll_char & _DYNAMIC_BASE): missing.append("ASLR")
                if not (dll_char & _NX_COMPAT):    missing.append("DEP")
                findings.append({"severity": "medium", "category": "structure",
                    "title": f"Missing security flags: {', '.join(missing)}",
                    "detail": "ASLR/DEP absence is flagged by sandboxes as unusual for modern binaries.",
                    "suggestion": "Set DYNAMIC_BASE (0x0040) and NX_COMPAT (0x0100) in DllCharacteristics."})
            if dll_char & _HIGH_ENTROPY_VA:
                deductions += 2
                findings.append({"severity": "low", "category": "structure",
                    "title": "HIGH_ENTROPY_VA flag set (64-bit ASLR indicator)",
                    "detail": "Triggers strict memory-layout analysis in some sandboxes.",
                    "suggestion": "Clear bit 0x0020 in DllCharacteristics."})
            if subsystem == _SUBSYSTEM_CONSOLE:
                deductions += 2
                findings.append({"severity": "low", "category": "structure",
                    "title": "Console subsystem - visible terminal window on launch",
                    "detail": "Console applications spawn a visible cmd window, making execution obvious to users.",
                    "suggestion": "Set Subsystem to GUI (2) to suppress the console window."})
            last_end = max((s.PointerToRawData + s.SizeOfRawData for s in pe.sections), default=0)
            if last_end and last_end < len(data):
                deductions += 2
                findings.append({"severity": "low", "category": "structure",
                    "title": f"File overlay: {len(data) - last_end} bytes appended after last section",
                    "detail": "Appended data is plainly visible in tools like pestudio/CFF Explorer.",
                    "suggestion": "Wipe the overlay or embed the data as a proper PE section."})
        except Exception:
            pass

    score = max(0, 25 - deductions)
    if deductions == 0:
        findings.append({"severity": "ok", "category": "structure",
            "title": "PE structure looks clean",
            "detail": "No significant timestamp, Rich header, or debug path issues.",
            "suggestion": None})

    return score, findings, {}


# =============================================================================
# 4. Patches catalogue - what's available given the current bytes
# =============================================================================

def _patches_available(data: bytes, file_entropy: float, pe) -> list[dict]:
    """Return [{id, label, desc}] of patches that would actually do something."""
    out: list[dict] = []
    if data[:2] != b'MZ':
        return out

    ts_off = _find_pe_timestamp_offset(data)
    if ts_off is not None and struct.unpack_from('<I', data, ts_off)[0] != 0:
        out.append({"id": "timestamp", "label": "Zero compile timestamp",
            "desc": "Sets TimeDateStamp to 0 in the COFF header"})
        out.append({"id": "fake_timestamp", "label": "Spoof timestamp (legit DLL date)",
            "desc": "Replaces TimeDateStamp with a realistic Windows system DLL compile date"})
    if _find_rich_header(data):
        out.append({"id": "rich_header", "label": "Wipe Rich header",
            "desc": "Zeros out the Rich/DanS compiler fingerprint block"})
    if _find_pdb_path(data):
        out.append({"id": "debug_dir", "label": "Wipe debug directory / PDB path",
            "desc": "Zeros the debug directory entry and PDB path string"})
    if _DOS_STUB_STRING in data[:0x100]:
        out.append({"id": "dos_stub", "label": "Replace DOS stub message",
            "desc": "Overwrites the default MSVC DOS stub string with spaces"})
    out.append({"id": "stomp_dos_header", "label": "Stomp DOS header reserved fields",
        "desc": "Zeros unused MZ header bytes (offsets 0x02-0x3B), keeping MZ magic and e_lfanew"})
    if file_entropy > 6.5:
        out.append({"id": "entropy_padding", "label": "Entropy-lowering padding",
            "desc": "Appends 64 KB of null bytes to dilute overall file entropy"})

    if pe is None:
        return out

    try:
        dll_char  = pe.OPTIONAL_HEADER.DllCharacteristics
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        if any(s.Name.rstrip(b'\x00').decode('utf-8','ignore') in _SUSPICIOUS_SECTION_NAMES
               for s in pe.sections):
            out.append({"id": "section_rename", "label": "Rename default sections",
                "desc": "Renames .text/.data/.rdata/.bss to non-standard names"})
        ck_off = pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
        if struct.unpack_from('<I', data, ck_off)[0] != 0:
            out.append({"id": "checksum", "label": "Zero PE checksum",
                "desc": "Sets the OptionalHeader checksum field to 0"})
        if not (dll_char & _DYNAMIC_BASE) or not (dll_char & _NX_COMPAT):
            out.append({"id": "set_aslr_dep", "label": "Enable ASLR + DEP flags",
                "desc": "Sets DYNAMIC_BASE (0x0040) and NX_COMPAT (0x0100) in DllCharacteristics"})
        if dll_char & _HIGH_ENTROPY_VA:
            out.append({"id": "clear_high_entropy_va", "label": "Clear HIGH_ENTROPY_VA flag",
                "desc": "Removes the 64-bit ASLR indicator (bit 0x0020) from DllCharacteristics"})
        if subsystem == _SUBSYSTEM_CONSOLE:
            out.append({"id": "flip_subsystem", "label": "Flip subsystem CONSOLE->GUI",
                "desc": "Changes subsystem from 3 (CUI) to 2 (GUI) - no console window spawned"})
        if any((s.Characteristics & 0x20000000) and (s.Characteristics & 0x80000000)
               for s in pe.sections):
            out.append({"id": "stomp_rwx_flags", "label": "Clear RWX section flags",
                "desc": "Removes the WRITE flag from executable sections to eliminate RWX memory"})
        out.append({"id": "spoof_imagebase", "label": "Spoof ImageBase address",
            "desc": "Sets preferred load address to 0x10000000 (non-default, mimics a DLL)"})
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(dd) > _DIR_BOUND_IMPORT and dd[_DIR_BOUND_IMPORT].Size > 0:
            out.append({"id": "zero_bound_imports", "label": "Zero bound import directory",
                "desc": "Clears DataDirectory[11] to remove pre-binding fingerprint"})
        if len(dd) > _DIR_LOAD_CONFIG and dd[_DIR_LOAD_CONFIG].Size > 0:
            out.append({"id": "zero_load_config", "label": "Zero load config directory",
                "desc": "Clears DataDirectory[10] to strip CFG/SafeSEH/stack cookie metadata"})
        if len(dd) > _DIR_EXPORT and dd[_DIR_EXPORT].Size > 0:
            out.append({"id": "zero_exports", "label": "Zero export directory",
                "desc": "Clears DataDirectory[0] to hide exported function names"})
        if len(dd) > _DIR_SECURITY and dd[_DIR_SECURITY].Size > 0:
            out.append({"id": "zero_security_dir", "label": "Zero Authenticode security dir",
                "desc": "Clears DataDirectory[4] to remove the Authenticode certificate reference"})
        last_end = max((s.PointerToRawData + s.SizeOfRawData for s in pe.sections), default=0)
        if last_end and last_end < len(data):
            out.append({"id": "wipe_overlay", "label": "Wipe file overlay",
                "desc": f"Truncates {len(data) - last_end} bytes of data appended after the last section"})
    except Exception:
        pass

    return out


# =============================================================================
# 5. Public analyse() - small orchestrator over the four scorers
# =============================================================================

def analyse(data: bytes, filename: str = "") -> dict:
    is_pe = data[:2] == b'MZ'
    pe    = _safe_open_pe(data, fast=False) if is_pe else None

    findings: list[dict] = []

    se, fe, xe = _score_entropy(data)
    findings += fe
    file_entropy = xe["file_entropy"]

    si, fi, xi = _score_imports(data, pe)
    findings += fi

    ss, fs, xs = _score_strings(data)
    findings += fs

    sx, fx, _  = _score_structure(data, pe)
    findings += fx

    total = se + si + ss + sx
    grade = "A" if total >= 80 else "B" if total >= 65 else "C" if total >= 50 else "D" if total >= 35 else "F"
    findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 9))

    patches = _patches_available(data, file_entropy, pe)

    if pe is not None:
        try: pe.close()
        except Exception: pass

    return {
        "ok":                 True,
        "score":              total,
        "grade":              grade,
        "score_entropy":      se,
        "score_imports":      si,
        "score_strings":      ss,
        "score_structure":    sx,
        "findings":           findings,
        "sections":           xi.get("sections", []),
        "suspicious_imports": xi.get("suspicious_imports", []),
        "suspicious_strings": xs.get("suspicious_strings", []),
        "patches_available":  patches,
        "is_pe":              is_pe,
        "file_entropy":       file_entropy,
        "size":               len(data),
        "md5":                hashlib.md5(data).hexdigest(),
        "sha256":             hashlib.sha256(data).hexdigest(),
        "filename":           filename,
    }


# =============================================================================
# 6. Patch registry - each patch is a typed record; apply_patches loops once.
# =============================================================================

@dataclass(frozen=True)
class Patch:
    id:     str
    apply:  Callable[[bytearray, bytes], Optional[str]]   # (buf, orig_data) -> msg or None


def _p_timestamp(buf: bytearray, data: bytes) -> Optional[str]:
    off = _find_pe_timestamp_offset(data)
    if off is None:
        return None
    struct.pack_into('<I', buf, off, 0)
    return "PE compile timestamp -> 0x00000000"


def _p_fake_timestamp(buf: bytearray, data: bytes) -> Optional[str]:
    off = _find_pe_timestamp_offset(data)
    if off is None:
        return None
    ts, desc = random.choice(_LEGIT_TIMESTAMPS)
    struct.pack_into('<I', buf, off, ts)
    return f"PE timestamp spoofed -> 0x{ts:08x} ({desc})"


def _p_rich_header(buf: bytearray, data: bytes) -> Optional[str]:
    rich = _find_rich_header(data)
    if not rich:
        return None
    start, end = rich
    for i in range(start, min(end, len(buf))):
        buf[i] = 0
    return f"Rich header zeroed ({end - start} bytes at 0x{start:04x})"


def _p_debug_dir(buf: bytearray, _data: bytes) -> Optional[str]:
    pe = _safe_open_pe(bytes(buf), fast=False)
    if pe is None:
        return None
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                off_dbg = dbg.struct.get_file_offset()
                struct.pack_into('<I', buf, off_dbg + 4,  0)   # TimeDateStamp
                struct.pack_into('<I', buf, off_dbg + 16, 0)   # PointerToRawData
                struct.pack_into('<I', buf, off_dbg + 20, 0)   # SizeOfData
        rsds_pos = bytes(buf).find(b'RSDS')
        if rsds_pos != -1:
            end_pos = bytes(buf).find(b'\x00', rsds_pos + 24)
            if end_pos == -1:
                end_pos = rsds_pos + 300
            for i in range(rsds_pos, min(end_pos + 1, len(buf))):
                buf[i] = 0
        return "Debug directory + PDB path zeroed"
    finally:
        try: pe.close()
        except Exception: pass


def _p_section_rename(buf: bytearray, _data: bytes) -> Optional[str]:
    pe = _safe_open_pe(bytes(buf), fast=True)
    if pe is None:
        return None
    try:
        renamed: list[str] = []
        for sec in pe.sections:
            sname = sec.Name.rstrip(b'\x00').decode('utf-8', 'ignore')
            new_name = _SECTION_RENAME_MAP.get(sname)
            if new_name:
                off = sec.get_file_offset()
                buf[off:off + 8] = new_name.encode('ascii').ljust(8, b'\x00')
                renamed.append(f"{sname}->{new_name}")
        return f"Sections renamed: {', '.join(renamed)}" if renamed else None
    finally:
        try: pe.close()
        except Exception: pass


def _p_checksum(buf: bytearray, _data: bytes) -> Optional[str]:
    pe = _safe_open_pe(bytes(buf), fast=True)
    if pe is None:
        return None
    try:
        off = pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
        struct.pack_into('<I', buf, off, 0)
        return "PE checksum -> 0x00000000"
    finally:
        try: pe.close()
        except Exception: pass


def _p_dos_stub(buf: bytearray, _data: bytes) -> Optional[str]:
    pos = bytes(buf).find(_DOS_STUB_STRING)
    if pos == -1:
        return None
    for i in range(pos, pos + len(_DOS_STUB_STRING)):
        buf[i] = 0x20
    return "DOS stub message replaced with spaces"


def _p_stomp_dos_header(buf: bytearray, _data: bytes) -> Optional[str]:
    for i in range(2, 0x3C):
        buf[i] = 0
    return "DOS header reserved fields zeroed (0x02-0x3B)"


def _p_entropy_padding(buf: bytearray, _data: bytes) -> Optional[str]:
    buf.extend(b'\x00' * 65536)
    return "Entropy-lowering padding: 64 KB of null bytes appended"


def _p_set_aslr_dep(buf: bytearray, _data: bytes) -> Optional[str]:
    pe = _safe_open_pe(bytes(buf), fast=True)
    if pe is None:
        return None
    try:
        off = pe.OPTIONAL_HEADER.get_field_absolute_offset('DllCharacteristics')
        old = struct.unpack_from('<H', buf, off)[0]
        new = old | _DYNAMIC_BASE | _NX_COMPAT
        struct.pack_into('<H', buf, off, new)
        return f"DllCharacteristics ASLR+DEP set (0x{old:04x}->0x{new:04x})"
    finally:
        try: pe.close()
        except Exception: pass


def _p_clear_high_entropy_va(buf: bytearray, _data: bytes) -> Optional[str]:
    pe = _safe_open_pe(bytes(buf), fast=True)
    if pe is None:
        return None
    try:
        off = pe.OPTIONAL_HEADER.get_field_absolute_offset('DllCharacteristics')
        old = struct.unpack_from('<H', buf, off)[0]
        new = old & ~_HIGH_ENTROPY_VA & 0xFFFF
        struct.pack_into('<H', buf, off, new)
        return f"HIGH_ENTROPY_VA cleared (0x{old:04x}->0x{new:04x})"
    finally:
        try: pe.close()
        except Exception: pass


def _p_flip_subsystem(buf: bytearray, _data: bytes) -> Optional[str]:
    pe = _safe_open_pe(bytes(buf), fast=True)
    if pe is None:
        return None
    try:
        off = pe.OPTIONAL_HEADER.get_field_absolute_offset('Subsystem')
        old = struct.unpack_from('<H', buf, off)[0]
        struct.pack_into('<H', buf, off, _SUBSYSTEM_GUI)
        return f"Subsystem {old}->{_SUBSYSTEM_GUI} (CONSOLE->GUI)"
    finally:
        try: pe.close()
        except Exception: pass


def _p_stomp_rwx_flags(buf: bytearray, _data: bytes) -> Optional[str]:
    pe = _safe_open_pe(bytes(buf), fast=True)
    if pe is None:
        return None
    try:
        stomped: list[str] = []
        for sec in pe.sections:
            ch = sec.Characteristics
            if (ch & 0x20000000) and (ch & 0x80000000):
                off = sec.get_file_offset() + 36   # Characteristics is at +36
                struct.pack_into('<I', buf, off, ch & ~0x80000000)
                stomped.append(sec.Name.rstrip(b'\x00').decode('utf-8', 'ignore'))
        return f"RWX->RX cleared for: {', '.join(stomped)}" if stomped else None
    finally:
        try: pe.close()
        except Exception: pass


def _p_spoof_imagebase(buf: bytearray, _data: bytes) -> Optional[str]:
    pe = _safe_open_pe(bytes(buf), fast=True)
    if pe is None:
        return None
    try:
        magic  = pe.OPTIONAL_HEADER.Magic
        off_ib = pe.OPTIONAL_HEADER.get_field_absolute_offset('ImageBase')
        old_ib = pe.OPTIONAL_HEADER.ImageBase
        if magic == 0x020b:  # PE32+
            new_ib = 0x0000000180000000
            struct.pack_into('<Q', buf, off_ib, new_ib)
        else:                # PE32
            new_ib = 0x10000000
            struct.pack_into('<I', buf, off_ib, new_ib)
        return f"ImageBase 0x{old_ib:x}->0x{new_ib:x}"
    finally:
        try: pe.close()
        except Exception: pass


def _p_wipe_overlay(buf: bytearray, _data: bytes) -> Optional[str]:
    pe = _safe_open_pe(bytes(buf), fast=True)
    if pe is None:
        return None
    try:
        last_end = max((s.PointerToRawData + s.SizeOfRawData for s in pe.sections), default=0)
        if last_end and last_end < len(buf):
            n = len(buf) - last_end
            del buf[last_end:]
            return f"Overlay wiped: {n} bytes truncated"
        return None
    finally:
        try: pe.close()
        except Exception: pass


def _make_dir_zeroer(idx: int, name: str) -> Callable[[bytearray, bytes], Optional[str]]:
    def _apply(buf: bytearray, _data: bytes) -> Optional[str]:
        off = _dd_file_offset(bytes(buf), idx)
        if off is None or off + 8 > len(buf):
            return None
        struct.pack_into('<I', buf, off,     0)  # VirtualAddress
        struct.pack_into('<I', buf, off + 4, 0)  # Size
        return f"DataDirectory[{idx}] ({name}) zeroed"
    return _apply


_PATCHES: dict[str, Patch] = {
    p.id: p for p in (
        Patch("timestamp",             _p_timestamp),
        Patch("fake_timestamp",        _p_fake_timestamp),
        Patch("rich_header",           _p_rich_header),
        Patch("debug_dir",             _p_debug_dir),
        Patch("section_rename",        _p_section_rename),
        Patch("checksum",              _p_checksum),
        Patch("dos_stub",              _p_dos_stub),
        Patch("stomp_dos_header",      _p_stomp_dos_header),
        Patch("entropy_padding",       _p_entropy_padding),
        Patch("set_aslr_dep",          _p_set_aslr_dep),
        Patch("clear_high_entropy_va", _p_clear_high_entropy_va),
        Patch("flip_subsystem",        _p_flip_subsystem),
        Patch("stomp_rwx_flags",       _p_stomp_rwx_flags),
        Patch("spoof_imagebase",       _p_spoof_imagebase),
        Patch("wipe_overlay",          _p_wipe_overlay),
        Patch("zero_exports",          _make_dir_zeroer(_DIR_EXPORT,       "export")),
        Patch("zero_security_dir",     _make_dir_zeroer(_DIR_SECURITY,     "security")),
        Patch("zero_load_config",      _make_dir_zeroer(_DIR_LOAD_CONFIG,  "load config")),
        Patch("zero_bound_imports",    _make_dir_zeroer(_DIR_BOUND_IMPORT, "bound import")),
    )
}

#: The single source of truth for valid patch IDs (used by app.py for validation).
PATCH_IDS: frozenset[str] = frozenset(_PATCHES.keys())


def apply_patches(data: bytes, patch_ids: list[str]) -> tuple[bytes, list[str]]:
    """Apply a list of patch transforms to PE bytes. Returns (patched, messages)."""
    buf = bytearray(data)
    applied: list[str] = []

    if data[:2] != b'MZ':
        return bytes(buf), ["not a PE file - no patches applied"]

    for pid in patch_ids:
        patch = _PATCHES.get(pid)
        if patch is None:
            continue
        try:
            msg = patch.apply(buf, data)
            if msg:
                applied.append(msg)
        except Exception as e:
            applied.append(f"{pid} failed: {e}")

    return bytes(buf), applied
