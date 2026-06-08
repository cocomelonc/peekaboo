"""
shellcode.py - shellcode swiss-army knife for peekaboo
parse any format -> optional transform -> output in any format
"""
from __future__ import annotations
import ast
import base64
import hashlib
import math
import os
import re
import zlib
from typing import Optional


# ── input parsers (tried in order of specificity) ─────────────────────────────

def _try_python_literal(s: str) -> Optional[bytes]:
    if not re.match(r"^b['\"]", s):
        return None
    try:
        result = ast.literal_eval(s)
        return result if isinstance(result, bytes) else None
    except Exception:
        return None


def _try_0x_values(s: str) -> Optional[bytes]:
    vals = re.findall(r'0[xX]([0-9a-fA-F]{1,2})', s)
    if len(vals) < 2:
        return None
    try:
        return bytes(int(v, 16) for v in vals)
    except Exception:
        return None


def _try_escaped(s: str) -> Optional[bytes]:
    vals = re.findall(r'\\[xX]([0-9a-fA-F]{2})', s)
    if len(vals) < 2:
        return None
    return bytes(int(v, 16) for v in vals)


def _try_separated(s: str) -> Optional[bytes]:
    tokens = [t for t in re.split(r'[\s,:\-|]+', s.strip()) if t]
    if len(tokens) < 2:
        return None
    if all(re.match(r'^[0-9a-fA-F]{1,2}$', t) for t in tokens):
        try:
            return bytes(int(t, 16) for t in tokens)
        except Exception:
            return None
    return None


def _try_continuous_hex(s: str) -> Optional[bytes]:
    clean = re.sub(r'\s+', '', s)
    if re.match(r'^[0-9a-fA-F]+$', clean) and len(clean) % 2 == 0 and len(clean) >= 4:
        try:
            return bytes.fromhex(clean)
        except Exception:
            return None
    return None


def _try_base64(s: str) -> Optional[bytes]:
    clean = re.sub(r'\s+', '', s)
    if not re.match(r'^[A-Za-z0-9+/]+=*$', clean) or len(clean) < 8:
        return None
    try:
        return base64.b64decode(clean, validate=True)
    except Exception:
        return None


def parse_input(raw: str) -> tuple[bytes, str]:
    """Parse raw text into bytes. Returns (data, detected_format_label)."""
    s = raw.strip()
    if not s:
        raise ValueError("input is empty")
    for fn, label in [
        (_try_python_literal,  "Python bytes literal"),
        (_try_0x_values,       "C / 0x hex array"),
        (_try_escaped,         "\\x escaped hex"),
        (_try_separated,       "space / comma hex"),
        (_try_continuous_hex,  "raw hex string"),
        (_try_base64,          "base64"),
    ]:
        result = fn(s)
        if result is not None and len(result) > 0:
            return result, label
    raise ValueError(
        "could not detect format — try: 0x90,0x90 · \\x90\\x90 · 9090 · base64"
    )


# ── XOR key parser ─────────────────────────────────────────────────────────────

def parse_xor_key(s: str) -> bytes:
    """Parse XOR key: '0x41', '65', '0x41,0x42', '\\x41\\x42', or 'string'."""
    s = s.strip()
    # multi-byte 0x or \x notation
    vals = re.findall(r'(?:0[xX]|\\[xX])([0-9a-fA-F]{1,2})', s)
    if len(vals) > 1:
        return bytes(int(v, 16) for v in vals)
    # single 0x value
    m = re.match(r'^0[xX]([0-9a-fA-F]{1,4})$', s)
    if m:
        v = int(m.group(1), 16)
        return bytes([v]) if v <= 0xFF else v.to_bytes((v.bit_length() + 7) // 8, 'big')
    # decimal
    try:
        v = int(s)
        if 0 <= v <= 255:
            return bytes([v])
    except ValueError:
        pass
    # string passphrase
    if s:
        return s.encode('utf-8')
    raise ValueError("empty XOR key")


# ── output formatters ─────────────────────────────────────────────────────────

def to_c_array(data: bytes, var_name: str = "buf") -> str:
    vals = [f'0x{b:02x}' for b in data]
    rows = []
    for i in range(0, len(vals), 12):
        chunk = vals[i:i + 12]
        rows.append('  ' + ', '.join(chunk) + (',' if i + 12 < len(vals) else ''))
    return (
        f'unsigned char {var_name}[] = {{\n'
        + '\n'.join(rows)
        + f'\n}};\nunsigned int {var_name}_len = {len(data)};'
    )


def to_c_string(data: bytes, var_name: str = "buf") -> str:
    rows = []
    for i in range(0, len(data), 15):
        rows.append('"' + ''.join(f'\\x{b:02x}' for b in data[i:i + 15]) + '"')
    inner = '\n'.join(rows)
    return (
        f'unsigned char {var_name}[] =\n{inner};\n'
        f'unsigned int {var_name}_len = {len(data)};'
    )


def to_python(data: bytes, var_name: str = "buf") -> str:
    if len(data) <= 15:
        return f'{var_name} = b"' + ''.join(f'\\x{b:02x}' for b in data) + '"'
    rows = ['    b"' + ''.join(f'\\x{b:02x}' for b in data[i:i + 15]) + '"'
            for i in range(0, len(data), 15)]
    return f'{var_name} = (\n' + '\n'.join(rows) + '\n)'


def to_powershell(data: bytes, var_name: str = "buf") -> str:
    vals = [f'0x{b:02x}' for b in data]
    rows = ['    ' + ','.join(vals[i:i + 16]) for i in range(0, len(vals), 16)]
    return f'[Byte[]] ${var_name} = @(\n' + ',\n'.join(rows) + '\n)'


def to_csharp(data: bytes, var_name: str = "buf") -> str:
    vals = [f'0x{b:02x}' for b in data]
    rows = ['    ' + ', '.join(vals[i:i + 12]) for i in range(0, len(vals), 12)]
    return f'byte[] {var_name} = new byte[]\n{{\n' + ',\n'.join(rows) + '\n};'


def to_vba(data: bytes, var_name: str = "buf") -> str:
    hex_str = data.hex().upper()
    # split hex string across VBA line continuations (max 80 hex chars = 40 bytes per line)
    chunks = [hex_str[i:i + 80] for i in range(0, len(hex_str), 80)]
    if len(chunks) == 1:
        h_lines = f'    h = "{chunks[0]}"'
    else:
        parts = [f'    h = "{chunks[0]}" & _']
        for c in chunks[1:-1]:
            parts.append(f'        "{c}" & _')
        parts.append(f'        "{chunks[-1]}"')
        h_lines = '\n'.join(parts)
    return (
        f"Private Function {var_name}() As Byte()\n"
        f"    Dim h As String\n"
        f"{h_lines}\n"
        f"    Dim b() As Byte\n"
        f"    ReDim b({len(data) - 1})\n"
        f"    Dim i As Integer\n"
        f"    For i = 0 To {len(data) - 1}\n"
        f"        b(i) = CByte(\"&H\" & Mid(h, i * 2 + 1, 2))\n"
        f"    Next i\n"
        f"    {var_name} = b\n"
        f"End Function"
    )


def to_rust(data: bytes, var_name: str = "buf") -> str:
    vals = [f'0x{b:02x}u8' for b in data]
    rows = ['    ' + ', '.join(vals[i:i + 10]) for i in range(0, len(vals), 10)]
    return f'let {var_name}: &[u8] = &[\n' + ',\n'.join(rows) + '\n];'


def to_base64_str(data: bytes, **_) -> str:
    return base64.b64encode(data).decode('ascii')


def to_hex_0x(data: bytes, **_) -> str:
    return ' '.join(f'0x{b:02x}' for b in data)


def to_hex_raw(data: bytes, **_) -> str:
    return data.hex()


def to_escaped(data: bytes, **_) -> str:
    return ''.join(f'\\x{b:02x}' for b in data)


# format_id -> (function, hljs_language)
_FORMATS: dict[str, tuple] = {
    'c':          (to_c_array,    'c'),
    'c_str':      (to_c_string,   'c'),
    'python':     (to_python,     'python'),
    'powershell': (to_powershell, 'powershell'),
    'csharp':     (to_csharp,     'csharp'),
    'vba':        (to_vba,        'vbnet'),
    'rust':       (to_rust,       'rust'),
    'base64':     (to_base64_str, 'plaintext'),
    'hex_0x':     (to_hex_0x,     'plaintext'),
    'hex_raw':    (to_hex_raw,    'plaintext'),
    'escaped':    (to_escaped,    'plaintext'),
}

VALID_FORMATS = list(_FORMATS.keys())


# ── transforms ─────────────────────────────────────────────────────────────────

def xor_encode(data: bytes, key: bytes) -> bytes:
    kl = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(data))


# ── analysis ──────────────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return round(-sum((f / n) * math.log2(f / n) for f in freq if f), 3)


_PATTERNS = [
    (b'\xfc\x48\x83\xe4', 'x64 Metasploit/Cobalt Strike (stack align stub)'),
    (b'\xfc\x48\x89',     'x64 shellcode'),
    (b'\xfc\xe8\x82',     'x86 Metasploit (classic stub)'),
    (b'\xfc\xe8',         'x86 shellcode'),
    (b'\x4d\x5a',         'Windows PE / MZ header'),
    (b'\x7fELF',          'ELF binary'),
    (b'\xd9\xeb\x9b',     'x86 FNSTENV decoder'),
]


def analyse(data: bytes) -> dict:
    size = len(data)
    if size == 0:
        return {"size": 0, "entropy": 0.0, "null_bytes": 0, "null_pct": 0.0,
                "arch": "unknown", "detected": None, "top_bytes": [],
                "md5": "", "sha256": ""}

    null_count = data.count(0)
    null_pct   = round(null_count / size * 100, 1)
    entropy    = _entropy(data)

    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    top = sorted(freq.items(), key=lambda x: -x[1])[:6]
    top_fmt = [{"byte": f"0x{b:02x}", "count": c,
                "pct": round(c / size * 100, 1)} for b, c in top]

    detected = None
    for pat, label in _PATTERNS:
        if data[:len(pat)] == pat or (size > 64 and pat in data[:128]):
            detected = label
            break

    arch = "unknown"
    if size >= 4:
        if data[:4] == b'\xfc\x48\x83\xe4' or data[:3] in (b'\x48\x83', b'\x48\x89'):
            arch = "x64"
        elif data[:2] in (b'\xfc\xe8', b'\xeb\xfe', b'\x31\xc9'):
            arch = "x86"
        elif data[:2] == b'\x4d\x5a':
            arch = "PE"

    return {
        "size":       size,
        "entropy":    entropy,
        "null_bytes": null_count,
        "null_pct":   null_pct,
        "arch":       arch,
        "detected":   detected,
        "top_bytes":  top_fmt,
        "md5":        hashlib.md5(data).hexdigest(),
        "sha256":     hashlib.sha256(data).hexdigest(),
    }


# ── main pipeline ─────────────────────────────────────────────────────────────

def process(
    raw_input: str,
    output_format: str   = 'c',
    transform: str       = 'none',
    xor_key_str: str     = '',
    var_name: str        = 'buf',
) -> dict:
    # 1 — parse
    try:
        data, detected_fmt = parse_input(raw_input)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    input_stats = analyse(data)
    xor_key_used: Optional[bytes] = None

    # 2 — transform
    if transform == 'xor_random':
        xor_key_used = os.urandom(4)
        data = xor_encode(data, xor_key_used)
    elif transform == 'xor_key':
        if not xor_key_str:
            return {"ok": False, "error": "xor_key transform requires a key value"}
        try:
            xor_key_used = parse_xor_key(xor_key_str)
        except Exception as e:
            return {"ok": False, "error": f"bad XOR key: {e}"}
        data = xor_encode(data, xor_key_used)
    elif transform == 'base64_encode':
        data = base64.b64encode(data)
    elif transform == 'base64_decode':
        try:
            data = base64.b64decode(data)
        except Exception as e:
            return {"ok": False, "error": f"base64 decode failed: {e}"}
    elif transform == 'zlib_compress':
        data = zlib.compress(data, level=9)
    elif transform == 'zlib_decompress':
        try:
            data = zlib.decompress(data)
        except Exception as e:
            return {"ok": False, "error": f"zlib decompress failed: {e}"}
    elif transform not in ('none', ''):
        return {"ok": False, "error": f"unknown transform '{transform}'"}

    # 3 — format
    if output_format not in _FORMATS:
        return {"ok": False, "error": f"unknown output format '{output_format}'"}

    formatter, hljs_lang = _FORMATS[output_format]
    try:
        if output_format in ('base64', 'hex_0x', 'hex_raw', 'escaped'):
            output = formatter(data)
        else:
            safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', var_name) or 'buf'
            output = formatter(data, safe_name)
    except Exception as e:
        return {"ok": False, "error": f"formatter error: {e}"}

    return {
        "ok":            True,
        "output":        output,
        "hljs_lang":     hljs_lang,
        "detected_fmt":  detected_fmt,
        "output_size":   len(data),
        "xor_key_hex":   ''.join(f'\\x{b:02x}' for b in xor_key_used) if xor_key_used else None,
        "xor_key_0x":    ', '.join(f'0x{b:02x}' for b in xor_key_used) if xor_key_used else None,
        "xor_key_bytes": list(xor_key_used) if xor_key_used else [],
        "input_stats":   input_stats,
        "output_stats":  analyse(data),
    }


def analyse_only(raw_input: str) -> dict:
    """Fast analysis path — no transform or formatting."""
    try:
        data, detected_fmt = parse_input(raw_input)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    stats = analyse(data)
    stats["detected_fmt"] = detected_fmt
    stats["ok"] = True
    return stats
