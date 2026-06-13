"""
shellcode.py — peekaboo's shellcode swiss-army knife.

Pipeline:
    parse_input(text) -> bytes (auto-detect format)
                     -> Transform.apply()   (xor / b64 / zlib / none)
                     -> Formatter.render()  (c / python / powershell / ...)
                     -> analyse()           (entropy, arch, top bytes, hashes)

Design goals of this rewrite:
  * One row-batching helper (_grouped) — the seven near-identical
    to_c_array/to_python/to_powershell/... funcs collapsed into typed
    Formatter records.
  * Typed Formatter and Transform dataclasses so the dispatch is data
    not control flow (no more "if output_format in (...)" specials).
  * Public API kept stable: parse_input, parse_xor_key, xor_encode,
    analyse, analyse_only, process, VALID_FORMATS — all importable
    exactly as before.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import math
import os
import re
import zlib
from dataclasses import dataclass
from typing import Callable, Optional


# =============================================================================
# 1. Input parsers — each tries to decode `text` as a specific format.
#    A parser returns the bytes on a confident match, or None otherwise.
#    They're tried in `_PARSERS` order: most specific first, base64 last.
# =============================================================================

def _try_python_literal(s: str) -> Optional[bytes]:
    if not re.match(r"^b['\"]", s):
        return None
    try:
        v = ast.literal_eval(s)
        return v if isinstance(v, bytes) else None
    except Exception:
        return None


def _try_0x_values(s: str) -> Optional[bytes]:
    vals = re.findall(r"0[xX]([0-9a-fA-F]{1,2})", s)
    if len(vals) < 2:
        return None
    try:
        return bytes(int(v, 16) for v in vals)
    except Exception:
        return None


def _try_escaped(s: str) -> Optional[bytes]:
    vals = re.findall(r"\\[xX]([0-9a-fA-F]{2})", s)
    if len(vals) < 2:
        return None
    return bytes(int(v, 16) for v in vals)


def _try_separated(s: str) -> Optional[bytes]:
    tokens = [t for t in re.split(r"[\s,:\-|]+", s.strip()) if t]
    if len(tokens) < 2:
        return None
    if not all(re.match(r"^[0-9a-fA-F]{1,2}$", t) for t in tokens):
        return None
    try:
        return bytes(int(t, 16) for t in tokens)
    except Exception:
        return None


def _try_continuous_hex(s: str) -> Optional[bytes]:
    clean = re.sub(r"\s+", "", s)
    if not (re.match(r"^[0-9a-fA-F]+$", clean) and len(clean) % 2 == 0 and len(clean) >= 4):
        return None
    try:
        return bytes.fromhex(clean)
    except Exception:
        return None


def _try_base64(s: str) -> Optional[bytes]:
    clean = re.sub(r"\s+", "", s)
    if not re.match(r"^[A-Za-z0-9+/]+=*$", clean) or len(clean) < 8:
        return None
    try:
        return base64.b64decode(clean, validate=True)
    except Exception:
        return None


_PARSERS: list[tuple[str, Callable[[str], Optional[bytes]]]] = [
    ("Python bytes literal", _try_python_literal),
    ("C / 0x hex array",     _try_0x_values),
    ("\\x escaped hex",      _try_escaped),
    ("space / comma hex",    _try_separated),
    ("raw hex string",       _try_continuous_hex),
    ("base64",               _try_base64),
]


def parse_input(raw: str) -> tuple[bytes, str]:
    """Parse `raw` into bytes; return (data, human-readable format name)."""
    s = raw.strip()
    if not s:
        raise ValueError("input is empty")
    for label, fn in _PARSERS:
        result = fn(s)
        if result is not None and len(result) > 0:
            return result, label
    raise ValueError(
        "could not detect format — try: 0x90,0x90 · \\x90\\x90 · 9090 · base64"
    )


# =============================================================================
# 2. XOR key parser — separate from input parsing because the key has its
#    own grammar (single byte, multi-byte, or passphrase).
# =============================================================================

def parse_xor_key(s: str) -> bytes:
    """Accept '0x41', '65', '0x41,0x42', '\\x41\\x42', or any string."""
    s = s.strip()
    if not s:
        raise ValueError("empty XOR key")

    multi = re.findall(r"(?:0[xX]|\\[xX])([0-9a-fA-F]{1,2})", s)
    if len(multi) > 1:
        return bytes(int(v, 16) for v in multi)

    m = re.match(r"^0[xX]([0-9a-fA-F]{1,4})$", s)
    if m:
        v = int(m.group(1), 16)
        return bytes([v]) if v <= 0xFF else v.to_bytes((v.bit_length() + 7) // 8, "big")

    try:
        v = int(s)
        if 0 <= v <= 255:
            return bytes([v])
    except ValueError:
        pass

    return s.encode("utf-8")


# =============================================================================
# 3. Formatters — typed records so the dispatcher is just data.
#    `_grouped()` is the single byte-row helper that replaced the seven
#    near-identical to_* functions.
# =============================================================================

def _grouped(data: bytes, per_row: int, byte_fmt: str, sep: str, indent: str = "  ") -> list[str]:
    """Return formatted byte rows, e.g. ['  0x90, 0x90, ...', '  0x90, ...']."""
    rows: list[str] = []
    for i in range(0, len(data), per_row):
        chunk = data[i:i + per_row]
        rows.append(indent + sep.join(byte_fmt % b for b in chunk))
    return rows


def _fmt_c_array(data: bytes, var: str) -> str:
    rows = _grouped(data, 12, "0x%02x", ", ")
    body = ",\n".join(rows)
    return (
        f"unsigned char {var}[] = {{\n{body}\n}};\n"
        f"unsigned int {var}_len = {len(data)};"
    )


def _fmt_c_string(data: bytes, var: str) -> str:
    rows = ['"' + "".join(f"\\x{b:02x}" for b in data[i:i + 15]) + '"'
            for i in range(0, len(data), 15)]
    body = "\n".join(rows)
    return (
        f"unsigned char {var}[] =\n{body};\n"
        f"unsigned int {var}_len = {len(data)};"
    )


def _fmt_python(data: bytes, var: str) -> str:
    if len(data) <= 15:
        return f'{var} = b"' + "".join(f"\\x{b:02x}" for b in data) + '"'
    rows = ['    b"' + "".join(f"\\x{b:02x}" for b in data[i:i + 15]) + '"'
            for i in range(0, len(data), 15)]
    return f"{var} = (\n" + "\n".join(rows) + "\n)"


def _fmt_powershell(data: bytes, var: str) -> str:
    rows = _grouped(data, 16, "0x%02x", ",", indent="    ")
    return f"[Byte[]] ${var} = @(\n" + ",\n".join(rows) + "\n)"


def _fmt_csharp(data: bytes, var: str) -> str:
    rows = _grouped(data, 12, "0x%02x", ", ", indent="    ")
    return f"byte[] {var} = new byte[]\n{{\n" + ",\n".join(rows) + "\n};"


def _fmt_rust(data: bytes, var: str) -> str:
    rows = _grouped(data, 10, "0x%02xu8", ", ", indent="    ")
    return f"let {var}: &[u8] = &[\n" + ",\n".join(rows) + "\n];"


def _fmt_vba(data: bytes, var: str) -> str:
    """VBA can't keep huge strings on one line; chunk to 80 hex chars per line."""
    hex_str = data.hex().upper()
    chunks  = [hex_str[i:i + 80] for i in range(0, len(hex_str), 80)]
    if len(chunks) == 1:
        h_lines = f'    h = "{chunks[0]}"'
    else:
        parts = [f'    h = "{chunks[0]}" & _']
        for c in chunks[1:-1]:
            parts.append(f'        "{c}" & _')
        parts.append(f'        "{chunks[-1]}"')
        h_lines = "\n".join(parts)
    return (
        f"Private Function {var}() As Byte()\n"
        f"    Dim h As String\n"
        f"{h_lines}\n"
        f"    Dim b() As Byte\n"
        f"    ReDim b({len(data) - 1})\n"
        f"    Dim i As Integer\n"
        f"    For i = 0 To {len(data) - 1}\n"
        f'        b(i) = CByte("&H" & Mid(h, i * 2 + 1, 2))\n'
        f"    Next i\n"
        f"    {var} = b\n"
        f"End Function"
    )


# Var-less raw formats. var argument is accepted but ignored so every
# formatter has the same signature — the dispatcher needs no special-cases.
def _fmt_base64(data: bytes, var: str = "") -> str: return base64.b64encode(data).decode("ascii")
def _fmt_hex_0x(data: bytes, var: str = "") -> str: return " ".join(f"0x{b:02x}" for b in data)
def _fmt_hex_raw(data: bytes, var: str = "") -> str: return data.hex()
def _fmt_escaped(data: bytes, var: str = "") -> str: return "".join(f"\\x{b:02x}" for b in data)


@dataclass(frozen=True)
class Formatter:
    name:         str
    hljs_lang:    str
    accepts_var:  bool
    render:       Callable[[bytes, str], str]


_FORMATTERS: dict[str, Formatter] = {
    "c":          Formatter("c",          "c",          True,  _fmt_c_array),
    "c_str":      Formatter("c_str",      "c",          True,  _fmt_c_string),
    "python":     Formatter("python",     "python",     True,  _fmt_python),
    "powershell": Formatter("powershell", "powershell", True,  _fmt_powershell),
    "csharp":     Formatter("csharp",     "csharp",     True,  _fmt_csharp),
    "vba":        Formatter("vba",        "vbnet",      True,  _fmt_vba),
    "rust":       Formatter("rust",       "rust",       True,  _fmt_rust),
    "base64":     Formatter("base64",     "plaintext",  False, _fmt_base64),
    "hex_0x":     Formatter("hex_0x",     "plaintext",  False, _fmt_hex_0x),
    "hex_raw":    Formatter("hex_raw",    "plaintext",  False, _fmt_hex_raw),
    "escaped":    Formatter("escaped",    "plaintext",  False, _fmt_escaped),
}

VALID_FORMATS = list(_FORMATTERS.keys())


# =============================================================================
# 4. Transforms — typed records, dispatched by registry instead of if/elif.
# =============================================================================

def xor_encode(data: bytes, key: bytes) -> bytes:
    kl = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(data))


@dataclass(frozen=True)
class Transform:
    name:          str
    requires_key:  bool                                  # whether `key` arg is needed
    apply:         Callable[[bytes, bytes], bytes]       # (data, key_or_empty) -> bytes


def _t_xor_random(data: bytes, key: bytes) -> bytes:
    # ignored caller key; we generate our own 4-byte key inside process()
    return xor_encode(data, key)


def _t_xor_key(data: bytes, key: bytes) -> bytes:
    return xor_encode(data, key)


def _t_base64_encode(data: bytes, _: bytes) -> bytes:
    return base64.b64encode(data)


def _t_base64_decode(data: bytes, _: bytes) -> bytes:
    return base64.b64decode(data)


def _t_zlib_compress(data: bytes, _: bytes) -> bytes:
    return zlib.compress(data, level=9)


def _t_zlib_decompress(data: bytes, _: bytes) -> bytes:
    return zlib.decompress(data)


def _t_none(data: bytes, _: bytes) -> bytes:
    return data


_TRANSFORMS: dict[str, Transform] = {
    "none":            Transform("none",            False, _t_none),
    "xor_random":      Transform("xor_random",      False, _t_xor_random),
    "xor_key":         Transform("xor_key",         True,  _t_xor_key),
    "base64_encode":   Transform("base64_encode",   False, _t_base64_encode),
    "base64_decode":   Transform("base64_decode",   False, _t_base64_decode),
    "zlib_compress":   Transform("zlib_compress",   False, _t_zlib_compress),
    "zlib_decompress": Transform("zlib_decompress", False, _t_zlib_decompress),
}


# =============================================================================
# 5. Analysis — pure inspection, no transforms.
# =============================================================================

@dataclass(frozen=True)
class _Sig:
    """Signature scanned for in the leading bytes of a buffer."""
    prefix: bytes
    label:  str


_SIGNATURES: list[_Sig] = [
    _Sig(b"\xfc\x48\x83\xe4", "x64 Metasploit/Cobalt Strike (stack align stub)"),
    _Sig(b"\xfc\x48\x89",     "x64 shellcode"),
    _Sig(b"\xfc\xe8\x82",     "x86 Metasploit (classic stub)"),
    _Sig(b"\xfc\xe8",         "x86 shellcode"),
    _Sig(b"\x4d\x5a",         "Windows PE / MZ header"),
    _Sig(b"\x7fELF",          "ELF binary"),
    _Sig(b"\xd9\xeb\x9b",     "x86 FNSTENV decoder"),
]


def _detect_signature(data: bytes) -> Optional[str]:
    """Return a human-readable signature label, or None."""
    for sig in _SIGNATURES:
        if data[:len(sig.prefix)] == sig.prefix:
            return sig.label
        if len(data) > 64 and sig.prefix in data[:128]:
            return sig.label
    return None


_ARCH_HINTS: list[tuple[tuple[bytes, ...], str]] = [
    ((b"\xfc\x48\x83\xe4",), "x64"),
    ((b"\x48\x83", b"\x48\x89"), "x64"),
    ((b"\xfc\xe8", b"\xeb\xfe", b"\x31\xc9"), "x86"),
    ((b"\x4d\x5a",), "PE"),
]


def _detect_arch(data: bytes) -> str:
    if len(data) < 4:
        return "unknown"
    head4 = data[:4]
    head3 = data[:3]
    head2 = data[:2]
    for prefixes, arch in _ARCH_HINTS:
        for p in prefixes:
            if len(p) == 4 and head4 == p:    return arch
            if len(p) == 3 and head3 == p:    return arch
            if len(p) == 2 and head2 == p:    return arch
    return "unknown"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return round(-sum((f / n) * math.log2(f / n) for f in freq if f), 3)


def _top_bytes(data: bytes, n: int = 6) -> list[dict]:
    if not data:
        return []
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    return [{"byte":  f"0x{b:02x}",
             "count": c,
             "pct":   round(c / total * 100, 1)}
            for b, c in sorted(freq.items(), key=lambda x: -x[1])[:n]]


def analyse(data: bytes) -> dict:
    size = len(data)
    if size == 0:
        return {
            "size": 0, "entropy": 0.0, "null_bytes": 0, "null_pct": 0.0,
            "arch": "unknown", "detected": None, "top_bytes": [],
            "md5": "", "sha256": "",
        }
    null_count = data.count(0)
    return {
        "size":       size,
        "entropy":    _entropy(data),
        "null_bytes": null_count,
        "null_pct":   round(null_count / size * 100, 1),
        "arch":       _detect_arch(data),
        "detected":   _detect_signature(data),
        "top_bytes":  _top_bytes(data),
        "md5":        hashlib.md5(data).hexdigest(),
        "sha256":     hashlib.sha256(data).hexdigest(),
    }


# =============================================================================
# 6. Pipeline.
# =============================================================================

_VAR_NAME_OK = re.compile(r"[^A-Za-z0-9_]")


def _safe_var_name(name: str) -> str:
    return _VAR_NAME_OK.sub("_", name) or "buf"


def _apply_transform(data: bytes, name: str, key_str: str) -> tuple[bytes, Optional[bytes]]:
    """Run the named transform, return (new_data, key_used_or_None)."""
    if name in ("", None):
        name = "none"
    tx = _TRANSFORMS.get(name)
    if tx is None:
        raise ValueError(f"unknown transform '{name}'")

    if name == "xor_random":
        key = os.urandom(4)
        return tx.apply(data, key), key

    if tx.requires_key:
        if not key_str:
            raise ValueError(f"{name} transform requires a key value")
        try:
            key = parse_xor_key(key_str)
        except Exception as e:
            raise ValueError(f"bad XOR key: {e}")
        return tx.apply(data, key), key

    return tx.apply(data, b""), None


def process(
    raw_input:     str,
    output_format: str = "c",
    transform:     str = "none",
    xor_key_str:   str = "",
    var_name:      str = "buf",
) -> dict:
    # 1. parse
    try:
        data, detected_fmt = parse_input(raw_input)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    input_stats = analyse(data)

    # 2. transform
    try:
        data, xor_key_used = _apply_transform(data, transform, xor_key_str)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"transform failed: {e}"}

    # 3. format — unified signature, no per-format special-cases
    fmt = _FORMATTERS.get(output_format)
    if fmt is None:
        return {"ok": False, "error": f"unknown output format '{output_format}'"}
    var = _safe_var_name(var_name) if fmt.accepts_var else ""

    try:
        output = fmt.render(data, var)
    except Exception as e:
        return {"ok": False, "error": f"formatter error: {e}"}

    return {
        "ok":            True,
        "output":        output,
        "hljs_lang":     fmt.hljs_lang,
        "detected_fmt":  detected_fmt,
        "output_size":   len(data),
        "xor_key_hex":   "".join(f"\\x{b:02x}" for b in xor_key_used) if xor_key_used else None,
        "xor_key_0x":    ", ".join(f"0x{b:02x}" for b in xor_key_used) if xor_key_used else None,
        "xor_key_bytes": list(xor_key_used) if xor_key_used else [],
        "input_stats":   input_stats,
        "output_stats":  analyse(data),
    }


def analyse_only(raw_input: str) -> dict:
    """Fast path: parse + analyse, no transform or formatting."""
    try:
        data, detected_fmt = parse_input(raw_input)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    stats = analyse(data)
    stats["detected_fmt"] = detected_fmt
    stats["ok"] = True
    return stats
