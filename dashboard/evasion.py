"""
evasion.py - PE evasion score analyser + patch transforms for peekaboo
scores a binary 0-100 (higher = harder to detect) across four categories:
  entropy · import fingerprint · string indicators · PE structure
also applies surgical PE transforms: timestamp, Rich header, debug dir, sections, checksum
"""
from __future__ import annotations
import hashlib
import io
import math
import random
import re
import struct
from pathlib import Path
from typing import Optional

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

# -- entropy ------------------------------------------------------------------

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return round(-sum((f / n) * math.log2(f / n) for f in freq if f), 3)


# -- suspicious import patterns -----------------------------------------------

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

# -- suspicious string patterns ------------------------------------------------

_STRING_PATTERNS = [
    (re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
     "IP-based C2 URL",          "high"),
    (re.compile(r'https?://[a-z0-9\-]{3,}\.[a-z]{2,6}', re.I),
     "hardcoded URL",             "medium"),
    (re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}'),
     "IP:port C2 address",        "high"),
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

# -- PE structure checks -------------------------------------------------------

_SUSPICIOUS_SECTION_NAMES = {'.text', '.data', '.rdata', '.bss', '.idata', '.edata', '.reloc', '.rsrc'}
_COMMON_SECTION_NAMES = {'.text', '.data', '.rdata', '.bss', '.idata', '.edata', '.reloc', '.rsrc',
                          '.pdata', '.xdata', '.tls', '.debug', '.sxdata'}


def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    ascii_re = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    return [m.group().decode('ascii', errors='ignore') for m in ascii_re.finditer(data)]


def _find_rich_header(data: bytes) -> Optional[tuple[int, int]]:
    """Return (start, end) byte offsets of Rich header, or None."""
    rich_pos = data.find(b'Rich')
    if rich_pos == -1 or rich_pos > 0x200:
        return None
    # Dans header starts at offset 0x80 typically; look for DanS marker
    dans_pos = data.find(b'DanS')
    if dans_pos == -1 or dans_pos > rich_pos:
        return None
    return (dans_pos, rich_pos + 8)  # include 4-byte checksum after "Rich"


# -- main analyser -------------------------------------------------------------

def analyse(data: bytes, filename: str = "") -> dict:
    md5    = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    size   = len(data)
    is_pe  = data[:2] == b'MZ'

    findings: list[dict] = []
    sections_info: list[dict] = []
    suspicious_imports: list[dict] = []
    suspicious_strings: list[str] = []

    score_entropy  = 25
    score_imports  = 25
    score_strings  = 25
    score_structure= 25

    # -- 1. Entropy ----------------------------------------------------------
    file_entropy = _entropy(data)

    if file_entropy > 7.5:
        score_entropy = 5
        findings.append({"severity": "high", "category": "entropy",
            "title": f"Very high file entropy ({file_entropy})",
            "detail": "Values above 7.5 strongly suggest packed, encrypted, or compressed content.",
            "suggestion": "Add entropy-lowering padding: insert a .rsrc section with repetitive data, or use compression-then-encrypt instead of encrypt-only."})
    elif file_entropy > 7.0:
        score_entropy = 12
        findings.append({"severity": "medium", "category": "entropy",
            "title": f"High file entropy ({file_entropy})",
            "detail": "AV heuristics flag high-entropy executables as potentially packed.",
            "suggestion": "Embed null-byte padding or a large icon resource to dilute entropy below 7.0."})
    elif file_entropy > 6.5:
        score_entropy = 18
        findings.append({"severity": "low", "category": "entropy",
            "title": f"Elevated file entropy ({file_entropy})",
            "detail": "Slightly above typical for compiled C code (5.5-6.5).",
            "suggestion": "Minor concern - consider adding a padding resource if targeting strict AV."})
    else:
        findings.append({"severity": "ok", "category": "entropy",
            "title": f"Normal file entropy ({file_entropy})",
            "detail": "Within the expected range for compiled executables.",
            "suggestion": None})

    # -- 2. Imports (PE only) -------------------------------------------------
    if is_pe and HAS_PEFILE:
        try:
            pe = pefile.PE(data=data, fast_load=False)
            red_hits, yellow_hits = [], []
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

            suspicious_imports = red_hits[:20]
            deduction = min(25, len(red_hits) * 4 + len(yellow_hits))
            score_imports = max(0, 25 - deduction)

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

            # per-section analysis
            for sec in pe.sections:
                sname = sec.Name.rstrip(b'\x00').decode('utf-8', errors='replace')
                sdata = sec.get_data()
                sent  = _entropy(sdata) if sdata else 0.0
                char  = sec.Characteristics
                is_x  = bool(char & 0x20000000)
                is_w  = bool(char & 0x80000000)
                is_r  = bool(char & 0x40000000)
                sections_info.append({
                    "name":      sname,
                    "entropy":   round(sent, 3),
                    "size":      sec.SizeOfRawData,
                    "vsize":     sec.Misc_VirtualSize,
                    "exec":      is_x,
                    "write":     is_w,
                    "read":      is_r,
                    "rwx":       is_x and is_w,
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

            pe.close()
        except Exception as pe_err:
            findings.append({"severity": "info", "category": "imports",
                "title": f"PE parse warning: {str(pe_err)[:80]}",
                "detail": "Import analysis may be incomplete.",
                "suggestion": None})
    elif not is_pe:
        score_imports = 10  # raw shellcode / non-PE has no import table - suspicious by itself
        findings.append({"severity": "medium", "category": "imports",
            "title": "Not a PE file - no import table",
            "detail": "Raw shellcode or non-PE binary. AV will rely on byte patterns and entropy.",
            "suggestion": "If this is shellcode, consider embedding in a legitimate PE loader."})

    # -- 3. Strings -----------------------------------------------------------
    strings = _extract_strings(data)
    string_findings_count = 0
    seen_patterns: set[str] = set()
    for pattern, label, severity in _STRING_PATTERNS:
        for s in strings:
            if pattern.search(s) and s not in seen_patterns:
                seen_patterns.add(s)
                suspicious_strings.append(s)
                if string_findings_count < 4:
                    findings.append({"severity": severity, "category": "strings",
                        "title": f"String indicator: {label}",
                        "detail": repr(s[:80]),
                        "suggestion": _string_suggestion(label)})
                string_findings_count += 1
                break  # one finding per pattern type

    deduction = min(25, string_findings_count * 5)
    score_strings = max(0, 25 - deduction)

    if string_findings_count == 0:
        findings.append({"severity": "ok", "category": "strings",
            "title": "No obvious string indicators",
            "detail": "No hardcoded IPs, URLs, credentials, or tool names found.",
            "suggestion": None})

    # -- 4. PE Structure ------------------------------------------------------
    struct_deductions = 0
    if is_pe:
        # timestamp
        ts_offset = _find_pe_timestamp_offset(data)
        if ts_offset is not None:
            ts_val = struct.unpack_from('<I', data, ts_offset)[0]
            if ts_val != 0:
                struct_deductions += 3
                findings.append({"severity": "low", "category": "structure",
                    "title": f"Non-zero PE compile timestamp (0x{ts_val:08x})",
                    "detail": "Compile timestamps are used for binary correlation and threat intel pivoting.",
                    "suggestion": "Zero the TimeDateStamp field at offset in Optional Header to prevent correlation."})

        # Rich header
        rich = _find_rich_header(data)
        if rich:
            struct_deductions += 5
            findings.append({"severity": "medium", "category": "structure",
                "title": "Rich header present (compiler fingerprint)",
                "detail": "The Rich header encodes MSVC version + object file metadata, used by threat intel to cluster samples.",
                "suggestion": "Wipe the Rich header: XOR region to zero (the key is embedded in the header)."})

        # debug directory (PDB path)
        pdb = _find_pdb_path(data)
        if pdb:
            struct_deductions += 4
            findings.append({"severity": "medium", "category": "structure",
                "title": f"Debug directory / PDB path: {pdb[:60]}",
                "detail": "PDB paths expose developer usernames, build system paths, and project names.",
                "suggestion": "Zero the debug directory entry or strip the PDB path before distribution."})

        # section names
        if HAS_PEFILE:
            try:
                pe2 = pefile.PE(data=data, fast_load=True)
                default_names = [s.Name.rstrip(b'\x00').decode('utf-8','ignore')
                                 for s in pe2.sections
                                 if s.Name.rstrip(b'\x00').decode('utf-8','ignore') in _SUSPICIOUS_SECTION_NAMES]
                pe2.close()
                if len(default_names) >= 3:
                    struct_deductions += 5
                    findings.append({"severity": "medium", "category": "structure",
                        "title": f"Default MSVC section names ({', '.join(default_names[:4])})",
                        "detail": "Default section names are a reliable compiler fingerprint.",
                        "suggestion": "Rename sections to non-standard names (e.g. .code, .cfg, .init) using a PE editor."})
                elif len(default_names) >= 1:
                    struct_deductions += 2
            except Exception:
                pass

        # DOS stub message
        if b'This program cannot be run in DOS mode' in data[:0x100]:
            struct_deductions += 2
            findings.append({"severity": "low", "category": "structure",
                "title": "Default DOS stub message present",
                "detail": "The standard MSVC 'This program cannot be run in DOS mode' string is a reliable compiler fingerprint.",
                "suggestion": "Replace the DOS stub with a custom message or zero it out."})

        # DllCharacteristics flags, subsystem, overlay
        if HAS_PEFILE:
            try:
                pe_s = pefile.PE(data=data, fast_load=True)
                dll_char = pe_s.OPTIONAL_HEADER.DllCharacteristics
                subsystem = pe_s.OPTIONAL_HEADER.Subsystem
                if not (dll_char & _DYNAMIC_BASE) or not (dll_char & _NX_COMPAT):
                    struct_deductions += 3
                    missing = []
                    if not (dll_char & _DYNAMIC_BASE): missing.append("ASLR")
                    if not (dll_char & _NX_COMPAT):    missing.append("DEP")
                    findings.append({"severity": "medium", "category": "structure",
                        "title": f"Missing security flags: {', '.join(missing)}",
                        "detail": "ASLR/DEP absence is flagged by sandboxes as unusual for modern binaries.",
                        "suggestion": "Set DYNAMIC_BASE (0x0040) and NX_COMPAT (0x0100) in DllCharacteristics."})
                if dll_char & _HIGH_ENTROPY_VA:
                    struct_deductions += 2
                    findings.append({"severity": "low", "category": "structure",
                        "title": "HIGH_ENTROPY_VA flag set (64-bit ASLR indicator)",
                        "detail": "Triggers strict memory-layout analysis in some sandboxes.",
                        "suggestion": "Clear bit 0x0020 in DllCharacteristics."})
                if subsystem == _SUBSYSTEM_CONSOLE:
                    struct_deductions += 2
                    findings.append({"severity": "low", "category": "structure",
                        "title": "Console subsystem - visible terminal window on launch",
                        "detail": "Console applications spawn a visible cmd window, making execution obvious to users.",
                        "suggestion": "Set Subsystem to GUI (2) to suppress the console window."})
                last_end = max((s.PointerToRawData + s.SizeOfRawData for s in pe_s.sections), default=0)
                if last_end > 0 and last_end < len(data):
                    struct_deductions += 2
                    findings.append({"severity": "low", "category": "structure",
                        "title": f"File overlay: {len(data) - last_end} bytes appended after last section",
                        "detail": "Appended data is plainly visible in tools like pestudio/CFF Explorer.",
                        "suggestion": "Wipe the overlay or embed the data as a proper PE section."})
                pe_s.close()
            except Exception:
                pass

    score_structure = max(0, 25 - struct_deductions)
    if struct_deductions == 0 and is_pe:
        findings.append({"severity": "ok", "category": "structure",
            "title": "PE structure looks clean",
            "detail": "No significant timestamp, Rich header, or debug path issues.",
            "suggestion": None})

    # -- final score ----------------------------------------------------------
    total = score_entropy + score_imports + score_strings + score_structure
    grade = "A" if total >= 80 else "B" if total >= 65 else "C" if total >= 50 else "D" if total >= 35 else "F"

    # sort findings: critical first
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "ok": 5}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 9))

    # generate patch capabilities list
    patches = []
    if is_pe:
        ts_off = _find_pe_timestamp_offset(data)
        if ts_off is not None:
            ts_val = struct.unpack_from('<I', data, ts_off)[0]
            if ts_val != 0:
                patches.append({"id": "timestamp", "label": "Zero compile timestamp",
                    "desc": "Sets TimeDateStamp to 0 in the COFF header"})
                patches.append({"id": "fake_timestamp", "label": "Spoof timestamp (legit DLL date)",
                    "desc": "Replaces TimeDateStamp with a realistic Windows system DLL compile date"})
        if _find_rich_header(data):
            patches.append({"id": "rich_header", "label": "Wipe Rich header",
                "desc": "Zeros out the Rich/DanS compiler fingerprint block"})
        if _find_pdb_path(data):
            patches.append({"id": "debug_dir", "label": "Wipe debug directory / PDB path",
                "desc": "Zeros the debug directory entry and PDB path string"})
        if b'This program cannot be run in DOS mode' in data[:0x100]:
            patches.append({"id": "dos_stub", "label": "Replace DOS stub message",
                "desc": "Overwrites the default MSVC DOS stub string with spaces"})
        patches.append({"id": "stomp_dos_header", "label": "Stomp DOS header reserved fields",
            "desc": "Zeros unused MZ header bytes (offsets 0x02-0x3B), keeping MZ magic and e_lfanew"})
        if file_entropy > 6.5:
            patches.append({"id": "entropy_padding", "label": "Entropy-lowering padding",
                "desc": "Appends 64 KB of null bytes to dilute overall file entropy"})
        if HAS_PEFILE:
            try:
                pe3 = pefile.PE(data=data, fast_load=True)
                dll_char  = pe3.OPTIONAL_HEADER.DllCharacteristics
                subsystem = pe3.OPTIONAL_HEADER.Subsystem
                if any(s.Name.rstrip(b'\x00').decode('utf-8','ignore') in _SUSPICIOUS_SECTION_NAMES
                       for s in pe3.sections):
                    patches.append({"id": "section_rename", "label": "Rename default sections",
                        "desc": "Renames .text/.data/.rdata/.bss to non-standard names"})
                ck_val = struct.unpack_from('<I', data,
                    pe3.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'))[0]
                if ck_val != 0:
                    patches.append({"id": "checksum", "label": "Zero PE checksum",
                        "desc": "Sets the OptionalHeader checksum field to 0"})
                if not (dll_char & _DYNAMIC_BASE) or not (dll_char & _NX_COMPAT):
                    patches.append({"id": "set_aslr_dep", "label": "Enable ASLR + DEP flags",
                        "desc": "Sets DYNAMIC_BASE (0x0040) and NX_COMPAT (0x0100) in DllCharacteristics"})
                if dll_char & _HIGH_ENTROPY_VA:
                    patches.append({"id": "clear_high_entropy_va", "label": "Clear HIGH_ENTROPY_VA flag",
                        "desc": "Removes the 64-bit ASLR indicator (bit 0x0020) from DllCharacteristics"})
                if subsystem == _SUBSYSTEM_CONSOLE:
                    patches.append({"id": "flip_subsystem", "label": "Flip subsystem CONSOLE->GUI",
                        "desc": "Changes subsystem from 3 (CUI) to 2 (GUI) - no console window spawned"})
                if any(s.Characteristics & 0x20000000 and s.Characteristics & 0x80000000
                       for s in pe3.sections):
                    patches.append({"id": "stomp_rwx_flags", "label": "Clear RWX section flags",
                        "desc": "Removes the WRITE flag from executable sections to eliminate RWX memory"})
                patches.append({"id": "spoof_imagebase", "label": "Spoof ImageBase address",
                    "desc": "Sets preferred load address to 0x10000000 (non-default, mimics a DLL)"})
                dd = pe3.OPTIONAL_HEADER.DATA_DIRECTORY
                if len(dd) > _DIR_BOUND_IMPORT and dd[_DIR_BOUND_IMPORT].Size > 0:
                    patches.append({"id": "zero_bound_imports", "label": "Zero bound import directory",
                        "desc": "Clears DataDirectory[11] to remove pre-binding fingerprint"})
                if len(dd) > _DIR_LOAD_CONFIG and dd[_DIR_LOAD_CONFIG].Size > 0:
                    patches.append({"id": "zero_load_config", "label": "Zero load config directory",
                        "desc": "Clears DataDirectory[10] to strip CFG/SafeSEH/stack cookie metadata"})
                if len(dd) > _DIR_EXPORT and dd[_DIR_EXPORT].Size > 0:
                    patches.append({"id": "zero_exports", "label": "Zero export directory",
                        "desc": "Clears DataDirectory[0] to hide exported function names"})
                if len(dd) > _DIR_SECURITY and dd[_DIR_SECURITY].Size > 0:
                    patches.append({"id": "zero_security_dir", "label": "Zero Authenticode security dir",
                        "desc": "Clears DataDirectory[4] to remove the Authenticode certificate reference"})
                last_end = max((s.PointerToRawData + s.SizeOfRawData for s in pe3.sections), default=0)
                if last_end > 0 and last_end < len(data):
                    patches.append({"id": "wipe_overlay", "label": "Wipe file overlay",
                        "desc": f"Truncates {len(data) - last_end} bytes of data appended after the last section"})
                pe3.close()
            except Exception:
                pass

    return {
        "ok":                 True,
        "score":              total,
        "grade":              grade,
        "score_entropy":      score_entropy,
        "score_imports":      score_imports,
        "score_strings":      score_strings,
        "score_structure":    score_structure,
        "findings":           findings,
        "sections":           sections_info,
        "suspicious_imports": suspicious_imports,
        "suspicious_strings": suspicious_strings[:20],
        "patches_available":  patches,
        "is_pe":              is_pe,
        "file_entropy":       file_entropy,
        "size":               size,
        "md5":                md5,
        "sha256":             sha256,
        "filename":           filename,
    }


def _string_suggestion(label: str) -> Optional[str]:
    sug = {
        "IP-based C2 URL":       "Move C2 address to runtime config or resolve via DGA; never hardcode IPs.",
        "hardcoded URL":         "Store the C2 URL encrypted/encoded and decode at runtime.",
        "IP:port C2 address":    "Use domain-based C2 with DGA or dynamic DNS instead of raw IPs.",
        "credential keyword":    "Never embed credentials in binary; use external config or registry.",
        "offensive tool name":   "Remove all references to known tool names; they trigger exact-match signatures.",
        "shell binary reference":"Load shell paths dynamically via GetSystemDirectory instead of hardcoding.",
        "raw device / named pipe":"Obfuscate named pipe strings; build them at runtime.",
        "registry root reference":"Build registry paths at runtime using string concatenation.",
        "privilege constant":    "Use numeric values instead of string constant names.",
        "malware-related keyword":"Rename all functions/variables; strip debug symbols.",
        "executable extension":  "Minor concern - consider encoding extension strings.",
        "persistence keyword":   "Rename to innocuous identifiers.",
    }
    return sug.get(label)


def _find_pe_timestamp_offset(data: bytes) -> Optional[int]:
    """Return absolute file offset of TimeDateStamp in COFF header."""
    try:
        if data[:2] != b'MZ':
            return None
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_offset + 8 > len(data):
            return None
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return None
        return pe_offset + 8  # TimeDateStamp is at COFF header offset 4 (+4 machine)
    except Exception:
        return None


def _find_pdb_path(data: bytes) -> Optional[str]:
    """Scan for RSDS debug signature and return PDB path string."""
    pos = data.find(b'RSDS')
    if pos == -1:
        return None
    try:
        path_start = pos + 4 + 16 + 4  # sig(4) + guid(16) + age(4)
        if path_start >= len(data):
            return None
        end = data.find(b'\x00', path_start)
        if end == -1 or end - path_start > 260:
            return None
        path = data[path_start:end].decode('utf-8', errors='ignore')
        if path.endswith('.pdb') or '.pdb' in path.lower():
            return path
        return None
    except Exception:
        return None


# -- patch transforms ----------------------------------------------------------

_SECTION_RENAME_MAP = {
    '.text':  '.code',
    '.data':  '.cfg',
    '.rdata': '.init',
    '.bss':   '.heap',
    '.idata': '.api',
    '.edata': '.exp',
    '.reloc': '.fix',
    '.rsrc':  '.res',
}

# Curated compile timestamps from known Windows system DLLs
# format: (unix_timestamp, description)
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
_NO_SEH          = 0x0400
_GUARD_CF        = 0x4000

# PE Subsystem values
_SUBSYSTEM_GUI     = 2
_SUBSYSTEM_CONSOLE = 3

# DataDirectory indices
_DIR_EXPORT       = 0
_DIR_SECURITY     = 4
_DIR_LOAD_CONFIG  = 10
_DIR_BOUND_IMPORT = 11


def _dd_file_offset(data: bytes, index: int) -> Optional[int]:
    """Return the file offset of DataDirectory[index].VirtualAddress."""
    try:
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        magic  = struct.unpack_from('<H', data, pe_off + 24)[0]
        dd_base = pe_off + 24 + (96 if magic == 0x010b else 112)
        return dd_base + index * 8
    except Exception:
        return None


def apply_patches(data: bytes, patch_ids: list[str]) -> tuple[bytes, list[str]]:
    """
    Apply a list of patch transforms to PE bytes.
    Returns (patched_bytes, applied_descriptions).
    """
    buf = bytearray(data)
    applied: list[str] = []

    if not data[:2] == b'MZ':
        return bytes(buf), ["not a PE file - no patches applied"]

    for pid in patch_ids:
        if pid == "timestamp":
            off = _find_pe_timestamp_offset(data)
            if off is not None:
                struct.pack_into('<I', buf, off, 0)
                applied.append("PE compile timestamp -> 0x00000000")

        elif pid == "rich_header":
            rich = _find_rich_header(data)
            if rich:
                start, end = rich
                for i in range(start, min(end, len(buf))):
                    buf[i] = 0
                applied.append(f"Rich header zeroed ({end - start} bytes at 0x{start:04x})")

        elif pid == "debug_dir" and HAS_PEFILE:
            try:
                pe = pefile.PE(data=bytes(buf), fast_load=False)
                if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                    for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                        off_dbg = dbg.struct.get_file_offset()
                        struct.pack_into('<I', buf, off_dbg + 4, 0)   # TimeDateStamp
                        struct.pack_into('<I', buf, off_dbg + 16, 0)  # PointerToRawData
                        struct.pack_into('<I', buf, off_dbg + 20, 0)  # SizeOfData
                # also zero RSDS block
                rsds_pos = bytes(buf).find(b'RSDS')
                if rsds_pos != -1:
                    end_pos = bytes(buf).find(b'\x00', rsds_pos + 24)
                    if end_pos == -1:
                        end_pos = rsds_pos + 300
                    for i in range(rsds_pos, min(end_pos + 1, len(buf))):
                        buf[i] = 0
                pe.close()
                applied.append("Debug directory + PDB path zeroed")
            except Exception as e:
                applied.append(f"Debug dir patch failed: {e}")

        elif pid == "section_rename" and HAS_PEFILE:
            try:
                pe = pefile.PE(data=bytes(buf), fast_load=True)
                renamed = []
                for sec in pe.sections:
                    sname = sec.Name.rstrip(b'\x00').decode('utf-8', 'ignore')
                    new_name = _SECTION_RENAME_MAP.get(sname)
                    if new_name:
                        off = sec.get_file_offset()
                        # section name is 8 bytes at start of section header
                        new_bytes = new_name.encode('ascii').ljust(8, b'\x00')
                        buf[off:off + 8] = new_bytes
                        renamed.append(f"{sname}->{new_name}")
                pe.close()
                if renamed:
                    applied.append(f"Sections renamed: {', '.join(renamed)}")
            except Exception as e:
                applied.append(f"Section rename failed: {e}")

        elif pid == "checksum" and HAS_PEFILE:
            try:
                pe = pefile.PE(data=bytes(buf), fast_load=True)
                ck_off = pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
                struct.pack_into('<I', buf, ck_off, 0)
                pe.close()
                applied.append("PE checksum -> 0x00000000")
            except Exception as e:
                applied.append(f"Checksum patch failed: {e}")

        elif pid == "dos_stub":
            target = b'This program cannot be run in DOS mode'
            pos = bytes(buf).find(target)
            if pos != -1:
                for i in range(pos, pos + len(target)):
                    buf[i] = 0x20  # replace with spaces
                applied.append("DOS stub message replaced with spaces")

        elif pid == "fake_timestamp":
            off = _find_pe_timestamp_offset(data)
            if off is not None:
                ts, desc = random.choice(_LEGIT_TIMESTAMPS)
                struct.pack_into('<I', buf, off, ts)
                applied.append(f"PE timestamp spoofed -> 0x{ts:08x} ({desc})")

        elif pid == "stomp_dos_header":
            # zero bytes 0x02..0x3B, preserving MZ magic (0-1) and e_lfanew (0x3C-0x3F)
            for i in range(2, 0x3C):
                buf[i] = 0
            applied.append("DOS header reserved fields zeroed (0x02-0x3B)")

        elif pid == "entropy_padding":
            buf.extend(b'\x00' * 65536)
            applied.append("Entropy-lowering padding: 64 KB of null bytes appended")

        elif pid == "set_aslr_dep" and HAS_PEFILE:
            try:
                pe = pefile.PE(data=bytes(buf), fast_load=True)
                off_dc = pe.OPTIONAL_HEADER.get_field_absolute_offset('DllCharacteristics')
                old = struct.unpack_from('<H', buf, off_dc)[0]
                new_dc = old | _DYNAMIC_BASE | _NX_COMPAT
                struct.pack_into('<H', buf, off_dc, new_dc)
                pe.close()
                applied.append(f"DllCharacteristics ASLR+DEP set (0x{old:04x}->0x{new_dc:04x})")
            except Exception as e:
                applied.append(f"set_aslr_dep failed: {e}")

        elif pid == "clear_high_entropy_va" and HAS_PEFILE:
            try:
                pe = pefile.PE(data=bytes(buf), fast_load=True)
                off_dc = pe.OPTIONAL_HEADER.get_field_absolute_offset('DllCharacteristics')
                old = struct.unpack_from('<H', buf, off_dc)[0]
                new_dc = old & ~_HIGH_ENTROPY_VA & 0xFFFF
                struct.pack_into('<H', buf, off_dc, new_dc)
                pe.close()
                applied.append(f"HIGH_ENTROPY_VA cleared (0x{old:04x}->0x{new_dc:04x})")
            except Exception as e:
                applied.append(f"clear_high_entropy_va failed: {e}")

        elif pid == "flip_subsystem" and HAS_PEFILE:
            try:
                pe = pefile.PE(data=bytes(buf), fast_load=True)
                off_ss = pe.OPTIONAL_HEADER.get_field_absolute_offset('Subsystem')
                old = struct.unpack_from('<H', buf, off_ss)[0]
                struct.pack_into('<H', buf, off_ss, _SUBSYSTEM_GUI)
                pe.close()
                applied.append(f"Subsystem {old}->{_SUBSYSTEM_GUI} (CONSOLE->GUI)")
            except Exception as e:
                applied.append(f"flip_subsystem failed: {e}")

        elif pid == "stomp_rwx_flags" and HAS_PEFILE:
            try:
                pe = pefile.PE(data=bytes(buf), fast_load=True)
                stomped = []
                for sec in pe.sections:
                    char = sec.Characteristics
                    if (char & 0x20000000) and (char & 0x80000000):
                        # Characteristics is at offset 36 in the section header struct
                        off_char = sec.get_file_offset() + 36
                        struct.pack_into('<I', buf, off_char, char & ~0x80000000)
                        stomped.append(sec.Name.rstrip(b'\x00').decode('utf-8', 'ignore'))
                pe.close()
                if stomped:
                    applied.append(f"RWX->RX cleared for: {', '.join(stomped)}")
            except Exception as e:
                applied.append(f"stomp_rwx_flags failed: {e}")

        elif pid == "spoof_imagebase" and HAS_PEFILE:
            try:
                pe = pefile.PE(data=bytes(buf), fast_load=True)
                magic  = pe.OPTIONAL_HEADER.Magic
                off_ib = pe.OPTIONAL_HEADER.get_field_absolute_offset('ImageBase')
                old_ib = pe.OPTIONAL_HEADER.ImageBase
                pe.close()
                if magic == 0x020b:  # PE32+
                    new_ib = 0x0000000180000000
                    struct.pack_into('<Q', buf, off_ib, new_ib)
                else:                # PE32
                    new_ib = 0x10000000
                    struct.pack_into('<I', buf, off_ib, new_ib)
                applied.append(f"ImageBase 0x{old_ib:x}->0x{new_ib:x}")
            except Exception as e:
                applied.append(f"spoof_imagebase failed: {e}")

        elif pid == "wipe_overlay" and HAS_PEFILE:
            try:
                pe = pefile.PE(data=bytes(buf), fast_load=True)
                last_end = max((s.PointerToRawData + s.SizeOfRawData for s in pe.sections), default=0)
                pe.close()
                if last_end > 0 and last_end < len(buf):
                    overlay_size = len(buf) - last_end
                    del buf[last_end:]
                    applied.append(f"Overlay wiped: {overlay_size} bytes truncated")
            except Exception as e:
                applied.append(f"wipe_overlay failed: {e}")

        elif pid in ("zero_bound_imports", "zero_load_config", "zero_exports", "zero_security_dir"):
            _DIR_MAP = {
                "zero_exports":       (_DIR_EXPORT,       "export"),
                "zero_security_dir":  (_DIR_SECURITY,     "security"),
                "zero_load_config":   (_DIR_LOAD_CONFIG,  "load config"),
                "zero_bound_imports": (_DIR_BOUND_IMPORT, "bound import"),
            }
            dir_idx, dir_name = _DIR_MAP[pid]
            off_dd = _dd_file_offset(bytes(buf), dir_idx)
            if off_dd is not None and off_dd + 8 <= len(buf):
                struct.pack_into('<I', buf, off_dd,     0)  # VirtualAddress
                struct.pack_into('<I', buf, off_dd + 4, 0)  # Size
                applied.append(f"DataDirectory[{dir_idx}] ({dir_name}) zeroed")

    return bytes(buf), applied
