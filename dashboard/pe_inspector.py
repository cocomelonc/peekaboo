"""
pe_inspector.py - PE binary anatomy analyzer for peekaboo
"""
from __future__ import annotations

import hashlib
import math
import struct
from pathlib import Path
from typing import Any

import pefile

# ---------------------------------------------------------------------------
# Suspicious API catalog
# ---------------------------------------------------------------------------

_SUSP_IMPORTS: dict[str, list[str]] = {
    "injection": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx",
        "NtCreateThreadEx", "RtlCreateUserThread",
        "QueueUserAPC", "NtQueueApcThread",
        "SetThreadContext", "GetThreadContext",
        "OpenProcess", "NtOpenProcess",
    ],
    "hollowing": [
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "NtMapViewOfSection", "CreateSection",
    ],
    "anti_debug": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
        "FindWindowA", "FindWindowW",
        "GetTickCount", "QueryPerformanceCounter",
        "NtSetInformationThread",
    ],
    "anti_vm": [
        "GetSystemFirmwareTable", "EnumSystemFirmwareTables",
        "GetComputerNameA", "GetComputerNameW",
        "RegOpenKeyExA", "RegOpenKeyExW",
    ],
    "network": [
        "InternetOpenA", "InternetOpenW",
        "InternetOpenUrlA", "InternetOpenUrlW",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "WSAStartup", "WSAConnect", "WSASend", "WSARecv",
        "connect", "send", "recv", "socket",
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
        "HttpOpenRequestA", "HttpSendRequestA",
    ],
    "execution": [
        "WinExec", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExA", "ShellExecuteExW",
        "CreateProcessA", "CreateProcessW",
        "NtCreateProcess", "RtlCreateUserProcess",
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress",
    ],
    "persistence": [
        "RegSetValueExA", "RegSetValueExW",
        "RegCreateKeyExA", "RegCreateKeyExW",
        "SHGetSpecialFolderPathA", "SHGetSpecialFolderPathW",
        "WriteFile", "CopyFileA", "CopyFileW", "MoveFileA", "MoveFileW",
        "CreateServiceA", "CreateServiceW",
        "OpenSCManagerA", "OpenSCManagerW",
    ],
    "credential": [
        "CryptAcquireContextA", "CryptAcquireContextW",
        "CryptDecrypt", "CryptEncrypt",
        "LsaOpenPolicy", "SamOpenDomain",
        "CredReadA", "CredReadW",
        "NtlmDecryptMessage",
    ],
    "keylog_screen": [
        "GetAsyncKeyState", "GetKeyState", "SetWindowsHookExA", "SetWindowsHookExW",
        "BitBlt", "GetDC", "CreateCompatibleBitmap",
        "OpenClipboard", "GetClipboardData",
    ],
}

# flat lookup: api_name -> category
_SUSP_FLAT: dict[str, str] = {
    fn: cat
    for cat, fns in _SUSP_IMPORTS.items()
    for fn in fns
}

# ---------------------------------------------------------------------------
# Known packer signatures (section name based heuristics)
# ---------------------------------------------------------------------------

_PACKER_SIGS: list[tuple[str, str]] = [
    ("UPX0",   "UPX"),
    ("UPX1",   "UPX"),
    ("UPX2",   "UPX"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    ("themida",  "Themida"),
    (".vmp0",    "VMProtect"),
    (".vmp1",    "VMProtect"),
    (".vmp2",    "VMProtect"),
    ("ASPack",   "ASPack"),
    (".aspack",  "ASPack"),
    (".ByDzyne", "ByDzyne"),
    (".netshrink","NetShrink"),
    ("PELock",   "PELock"),
    ("Obsidium", "Obsidium"),
]

_PACKER_SECTION_SET = {s.lower() for s, _ in _PACKER_SIGS}

# ---------------------------------------------------------------------------
# Rich header tool IDs (partial)
# ---------------------------------------------------------------------------

_RICH_TOOL: dict[int, str] = {
    0x0000: "Unknown",
    0x0001: "Import",
    0x0002: "Linker",
    0x0004: "Resource",
    0x0006: "Export",
    0x000A: "MASM",
    0x000B: "MASM",
    0x000E: "CVTRES",
    0x000F: "CVTRES",
    0x0010: "CVTRES",
    0x001C: "C",
    0x001D: "C++",
    0x0021: "C",
    0x0022: "C++",
    0x005A: "C",
    0x005B: "C++",
    0x006D: "MASM",
    0x007C: "C",
    0x007D: "C++",
    0x00AA: "C",
    0x00AB: "C++",
    0x00FF: "C",
    0x0100: "C++",
}

# ---------------------------------------------------------------------------
# Subsystem names
# ---------------------------------------------------------------------------

_SUBSYSTEM: dict[int, str] = {
    0:  "unknown",
    1:  "native",
    2:  "windows_gui",
    3:  "windows_cui",
    5:  "os2_cui",
    7:  "posix_cui",
    9:  "windows_ce_gui",
    10: "efi_application",
    11: "efi_boot_service",
    12: "efi_runtime",
    14: "xbox",
    16: "windows_boot",
}

# ---------------------------------------------------------------------------
# Machine types
# ---------------------------------------------------------------------------

_MACHINE: dict[int, str] = {
    0x0000: "unknown",  0x014C: "x86",     0x0200: "ia64",
    0x8664: "x86_64",   0xAA64: "arm64",   0x01C0: "arm",
    0x01C4: "arm_thumb",0x5032: "riscv32", 0x5064: "riscv64",
    0x0EBC: "efi_byte_code",
}

# File header characteristic flags
_FILE_CHARS: list[tuple[int, str]] = [
    (0x0001, "RELOCS_STRIPPED"),      (0x0002, "EXECUTABLE_IMAGE"),
    (0x0004, "LINE_NUMS_STRIPPED"),   (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0010, "AGGRESSIVE_WS_TRIM"),   (0x0020, "LARGE_ADDRESS_AWARE"),
    (0x0080, "BYTES_REVERSED_LO"),    (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"),       (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "NET_RUN_FROM_SWAP"),    (0x1000, "SYSTEM"),
    (0x2000, "DLL"),                  (0x4000, "UP_SYSTEM_ONLY"),
    (0x8000, "BYTES_REVERSED_HI"),
]

# DLL characteristic flags
_DLL_CHARS: list[tuple[int, str]] = [
    (0x0020, "HIGH_ENTROPY_VA"),      (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),      (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),         (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),              (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),           (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
]

# Section characteristic flags
_SEC_CHARS: list[tuple[int, str]] = [
    (0x00000008, "NO_PAD"),           (0x00000020, "CNT_CODE"),
    (0x00000040, "CNT_INITIALIZED"),  (0x00000080, "CNT_UNINITIALIZED"),
    (0x00000200, "LNK_INFO"),         (0x00000800, "LNK_REMOVE"),
    (0x00001000, "LNK_COMDAT"),       (0x00004000, "NO_DEFER_SPEC_EXC"),
    (0x00008000, "GPREL"),            (0x01000000, "LNK_NRELOC_OVFL"),
    (0x02000000, "MEM_DISCARDABLE"), (0x04000000, "MEM_NOT_CACHED"),
    (0x08000000, "MEM_NOT_PAGED"),   (0x10000000, "MEM_SHARED"),
    (0x20000000, "MEM_EXECUTE"),     (0x40000000, "MEM_READ"),
    (0x80000000, "MEM_WRITE"),
]


def _flags(value: int, table: list[tuple[int, str]]) -> list[str]:
    return [name for mask, name in table if value & mask]


# ---------------------------------------------------------------------------
# Entropy helper
# ---------------------------------------------------------------------------

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((f / n) * math.log2(f / n) for f in freq if f)


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze(source: str | Path | bytes) -> dict[str, Any]:
    """
    Analyze a PE file. source can be a file path or raw bytes.
    Returns a structured dict with all findings.
    """
    if isinstance(source, (str, Path)):
        path = Path(source)
        raw = path.read_bytes()
        file_name = path.name
    else:
        raw = source
        file_name = "buffer"

    result: dict[str, Any] = {
        "ok":         False,
        "error":      None,
        "file_name":  file_name,
        "file_size":  len(raw),
        "md5":        hashlib.md5(raw).hexdigest(),
        "sha1":       hashlib.sha1(raw).hexdigest(),
        "sha256":     hashlib.sha256(raw).hexdigest(),
    }

    try:
        pe = pefile.PE(data=raw, fast_load=False)
    except pefile.PEFormatError as e:
        result["error"] = f"not a valid PE: {e}"
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

    # -- basic header info --------------------------------------------------
    is64 = pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
    result["arch"]       = "x64" if is64 else "x86"
    result["pe_type"]    = _pe_type(pe)
    result["timestamp"]  = _ts(pe.FILE_HEADER.TimeDateStamp)
    result["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    result["image_base"]  = hex(pe.OPTIONAL_HEADER.ImageBase)
    result["subsystem"]   = _SUBSYSTEM.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))
    result["image_size"]  = pe.OPTIONAL_HEADER.SizeOfImage

    # -- DOS header ---------------------------------------------------------
    def _gh(obj: Any, field: str, default: Any = 0) -> Any:
        """Safe getattr for pefile Structure objects."""
        return getattr(obj, field, default)

    dh = pe.DOS_HEADER
    result["dos_header"] = {
        "e_magic":    hex(_gh(dh, "e_magic")),
        "e_cblp":     _gh(dh, "e_cblp"),
        "e_cp":       _gh(dh, "e_cp"),
        "e_crlc":     _gh(dh, "e_crlc"),
        "e_cparhdr":  _gh(dh, "e_cparhdr"),
        "e_minalloc": _gh(dh, "e_minalloc"),
        "e_maxalloc": _gh(dh, "e_maxalloc"),
        "e_ss":       hex(_gh(dh, "e_ss")),
        "e_sp":       hex(_gh(dh, "e_sp")),
        "e_csum":     hex(_gh(dh, "e_csum")),
        "e_ip":       hex(_gh(dh, "e_ip")),
        "e_cs":       hex(_gh(dh, "e_cs")),
        "e_lfarlc":   hex(_gh(dh, "e_lfarlc")),
        "e_ovno":     _gh(dh, "e_ovno"),
        "e_oemid":    _gh(dh, "e_oemid"),
        "e_oeminfo":  _gh(dh, "e_oeminfo"),
        "e_lfanew":   hex(_gh(dh, "e_lfanew")),
    }

    # -- File header (COFF) -------------------------------------------------
    fh = pe.FILE_HEADER
    fh_chars = _gh(fh, "Characteristics")
    result["file_header"] = {
        "machine":                  hex(_gh(fh, "Machine")),
        "machine_str":              _MACHINE.get(_gh(fh, "Machine"), hex(_gh(fh, "Machine"))),
        "number_of_sections":       _gh(fh, "NumberOfSections"),
        "time_date_stamp":          _ts(_gh(fh, "TimeDateStamp")),
        "time_date_stamp_raw":      hex(_gh(fh, "TimeDateStamp")),
        "pointer_to_symbol_table":  hex(_gh(fh, "PointerToSymbolTable")),
        "number_of_symbols":        _gh(fh, "NumberOfSymbols"),
        "size_of_optional_header":  _gh(fh, "SizeOfOptionalHeader"),
        "characteristics":          hex(fh_chars),
        "characteristics_flags":    _flags(fh_chars, _FILE_CHARS),
    }

    # -- Optional header ----------------------------------------------------
    oh = pe.OPTIONAL_HEADER
    dll_chars = _gh(oh, "DllCharacteristics")
    maj_link  = _gh(oh, "MajorLinkerVersion")
    min_link  = _gh(oh, "MinorLinkerVersion")
    maj_os    = _gh(oh, "MajorOperatingSystemVersion")
    min_os    = _gh(oh, "MinorOperatingSystemVersion")
    maj_img   = _gh(oh, "MajorImageVersion")
    min_img   = _gh(oh, "MinorImageVersion")
    maj_sub   = _gh(oh, "MajorSubsystemVersion")
    min_sub   = _gh(oh, "MinorSubsystemVersion")
    subsys    = _gh(oh, "Subsystem")
    opt: dict[str, Any] = {
        "magic":                      hex(_gh(oh, "Magic")),
        "magic_str":                  "PE32+" if is64 else "PE32",
        "linker_version":             f"{maj_link}.{min_link}",
        "size_of_code":               _gh(oh, "SizeOfCode"),
        "size_of_initialized_data":   _gh(oh, "SizeOfInitializedData"),
        "size_of_uninitialized_data": _gh(oh, "SizeOfUninitializedData"),
        "address_of_entry_point":     hex(_gh(oh, "AddressOfEntryPoint")),
        "base_of_code":               hex(_gh(oh, "BaseOfCode")),
        "image_base":                 hex(_gh(oh, "ImageBase")),
        "section_alignment":          _gh(oh, "SectionAlignment"),
        "file_alignment":             _gh(oh, "FileAlignment"),
        "os_version":                 f"{maj_os}.{min_os}",
        "image_version":              f"{maj_img}.{min_img}",
        "subsystem_version":          f"{maj_sub}.{min_sub}",
        "win32_version_value":        _gh(oh, "Win32VersionValue"),
        "size_of_image":              _gh(oh, "SizeOfImage"),
        "size_of_headers":            _gh(oh, "SizeOfHeaders"),
        "checksum":                   hex(_gh(oh, "CheckSum")),
        "subsystem":                  subsys,
        "subsystem_str":              _SUBSYSTEM.get(subsys, str(subsys)),
        "dll_characteristics":        hex(dll_chars),
        "dll_characteristics_flags":  _flags(dll_chars, _DLL_CHARS),
        "size_of_stack_reserve":      _gh(oh, "SizeOfStackReserve"),
        "size_of_stack_commit":       _gh(oh, "SizeOfStackCommit"),
        "size_of_heap_reserve":       _gh(oh, "SizeOfHeapReserve"),
        "size_of_heap_commit":        _gh(oh, "SizeOfHeapCommit"),
        "number_of_rva_and_sizes":    _gh(oh, "NumberOfRvaAndSizes"),
    }
    bd = _gh(oh, "BaseOfData", None)
    if bd is not None:
        opt["base_of_data"] = hex(bd)
    result["optional_header"] = opt

    # -- sections -----------------------------------------------------------
    sections = []
    total_entropy = 0.0
    high_entropy_count = 0
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        data = s.get_data()
        ent  = _entropy(data)
        total_entropy += ent
        if ent > 6.8:
            high_entropy_count += 1
        chars = s.Characteristics
        sections.append({
            "name":                    name,
            "virt_addr":               hex(s.VirtualAddress),
            "virt_size":               s.Misc_VirtualSize,
            "raw_size":                s.SizeOfRawData,
            "pointer_to_raw_data":     hex(s.PointerToRawData),
            "pointer_to_relocations":  hex(s.PointerToRelocations),
            "pointer_to_linenumbers":  hex(s.PointerToLinenumbers),
            "number_of_relocations":   s.NumberOfRelocations,
            "number_of_linenumbers":   s.NumberOfLinenumbers,
            "characteristics":         hex(chars),
            "characteristics_flags":   _flags(chars, _SEC_CHARS),
            "entropy":                 round(ent, 3),
            "readable":                bool(chars & 0x40000000),
            "writable":                bool(chars & 0x80000000),
            "executable":              bool(chars & 0x20000000),
            "suspicious":              ent > 6.8 or (bool(chars & 0x80000000) and bool(chars & 0x20000000)),
        })
    result["sections"]         = sections
    result["section_count"]    = len(sections)
    result["high_entropy_secs"] = high_entropy_count
    result["overall_entropy"]  = round(total_entropy / len(sections), 3) if sections else 0.0

    # -- imports ------------------------------------------------------------
    imports      = []
    susp_hits:   list[dict] = []
    all_imp_fns: set[str]   = set()

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace") if entry.dll else ""
            fns = []
            for imp in entry.imports:
                fn = imp.name.decode("ascii", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                fns.append(fn)
                all_imp_fns.add(fn)
                cat = _SUSP_FLAT.get(fn)
                if cat:
                    susp_hits.append({"dll": dll, "api": fn, "category": cat})
            imports.append({
                "dll":             dll,
                "functions":       fns,
                "function_count":  len(fns),
                "suspicious_count": sum(1 for f in fns if f in _SUSP_FLAT),
            })

    result["imports"]            = imports
    result["import_count"]       = len(imports)
    result["total_import_fns"]   = len(all_imp_fns)
    result["suspicious_imports"] = susp_hits

    # group by category
    by_cat: dict[str, list[str]] = {}
    for h in susp_hits:
        by_cat.setdefault(h["category"], []).append(h["api"])
    result["suspicious_by_category"] = by_cat

    # -- exports ------------------------------------------------------------
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode("ascii", errors="replace") if exp.name else f"ord_{exp.ordinal}"
            exports.append({"name": name, "ordinal": exp.ordinal, "addr": hex(exp.address)})
    result["exports"] = exports

    # -- rich header --------------------------------------------------------
    result["rich_header"] = _parse_rich(raw)

    # -- overlay ------------------------------------------------------------
    result["overlay"] = _detect_overlay(pe, raw)

    # -- packer detection ---------------------------------------------------
    result["packer"] = _detect_packer(pe, sections, high_entropy_count, len(all_imp_fns))

    # -- is_packed heuristic ------------------------------------------------
    result["is_packed"] = (
        result["packer"] is not None
        or high_entropy_count >= 2
        or (len(all_imp_fns) < 5 and len(sections) > 0)
    )

    # -- threat score (0-100) -----------------------------------------------
    result["threat_score"] = _threat_score(result)

    result["ok"] = True
    pe.close()
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pe_type(pe: pefile.PE) -> str:
    if pe.is_dll():
        return "dll"
    if pe.is_driver():
        return "sys"
    if pe.is_exe():
        return "exe"
    return "unknown"


def _ts(ts: int) -> str:
    if ts == 0:
        return "not set"
    from datetime import datetime
    try:
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError):
        return f"invalid ({hex(ts)})"


def _detect_packer(pe: pefile.PE, sections: list[dict], high_ent: int, imp_count: int) -> str | None:
    sec_names = {s["name"].lower() for s in sections}
    for sig_name, label in _PACKER_SIGS:
        if sig_name.lower() in sec_names:
            return label
    # UPX without section names: check e_ident
    if hasattr(pe, "DOS_HEADER"):
        try:
            stub = pe.get_data(0, 256)
            if b"UPX!" in stub or b"UPX0" in stub:
                return "UPX"
        except Exception:
            pass
    return None


def _detect_overlay(pe: pefile.PE, raw: bytes) -> dict | None:
    overlay_off = pe.get_overlay_data_start_offset()
    if overlay_off and overlay_off < len(raw):
        size = len(raw) - overlay_off
        return {"offset": overlay_off, "size": size,
                "entropy": round(_entropy(raw[overlay_off:]), 3)}
    return None


def _parse_rich(raw: bytes) -> list[dict] | None:
    """Parse the Rich header if present."""
    # Rich header sits between DOS stub and PE signature, XOR-masked with a key
    try:
        rich_pos = raw.find(b"Rich")
        if rich_pos < 0 or rich_pos > 0x200:
            return None
        key = struct.unpack_from("<I", raw, rich_pos + 4)[0]
        dans_pos = raw.find(
            struct.pack("<I", key ^ 0x536E6144), 0, rich_pos
        )
        if dans_pos < 0:
            return None
        entries = []
        pos = dans_pos + 8  # skip DanS + 3 padding dwords
        while pos + 8 <= rich_pos:
            dw1, dw2 = struct.unpack_from("<II", raw, pos)
            comp_id = dw1 ^ key
            count   = dw2 ^ key
            prod_id = (comp_id >> 16) & 0xFFFF
            build   = comp_id & 0xFFFF
            tool    = _RICH_TOOL.get(prod_id >> 4, f"id_{prod_id:#06x}")
            entries.append({"tool": tool, "prod_id": prod_id, "build": build, "count": count})
            pos += 8
        return entries if entries else None
    except Exception:
        return None


def _threat_score(r: dict) -> int:
    score = 0
    # packer
    if r.get("is_packed"):
        score += 20
    # high entropy sections
    score += min(r.get("high_entropy_secs", 0) * 8, 24)
    # suspicious API categories
    cats = set(r.get("suspicious_by_category", {}).keys())
    score += len(cats & {"injection", "hollowing"}) * 15
    score += len(cats & {"anti_debug", "anti_vm"}) * 10
    score += len(cats & {"network", "credential"}) * 8
    score += len(cats & {"execution", "persistence", "keylog_screen"}) * 5
    # overlay
    if r.get("overlay"):
        score += 5
    # very few imports (evasion)
    if 0 < r.get("total_import_fns", 0) < 5:
        score += 10
    return min(score, 100)
