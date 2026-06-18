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
from typing import Optional

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


import cfg as _cfg


def _load_config(name: str) -> dict | None:
    """Read a legacy-named config dict from .env via cfg.py."""
    return _cfg.get(name)


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
        _db.clear_patch_history()
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
        _db.clear_patch_history()
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


@app.route("/api/config/<name>")
def api_config(name: str):
    """Read-only: return the masked config dict loaded from .env."""
    if name not in _cfg.names():
        return jsonify({"error": "unknown config"}), 400
    out = _cfg.masked(name)
    if out is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(out)


@app.route("/api/config/<name>", methods=["POST"])
def api_config_save(name: str):
    """Configs are now read-only; edit `.env` directly and restart."""
    return jsonify({
        "ok": False,
        "error": "configs are read-only since the .env migration. "
                 "edit .env and restart the app.",
    }), 405


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
                    from semantic import embedded_count
                    n = embedded_count()
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
        from semantic import available, embedded_count, tagged_count, data_source
        return jsonify({
            "available":      available(),
            "embedded_posts": embedded_count(),
            "tagged_posts":   tagged_count(),
            "source":         data_source(),
        })
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
        _db.clear_patch_history()
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
        _db.clear_patch_history()
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


_SC_MAX_INPUT_BYTES = 8 * 1024 * 1024   # 8 MB applies to text input and uploads


def _sc_get_text_input() -> tuple[Optional[str], Optional[tuple[dict, int]]]:
    """Pull and validate the {input: str} payload shared by /process and /analyse."""
    if not HAS_SHELLCODE:
        return None, ({"ok": False, "error": "shellcode module not available"}, 503)
    data = request.get_json(force=True, silent=True) or {}
    raw  = data.get("input", "")
    if not isinstance(raw, str) or not raw:
        return None, ({"ok": False, "error": "input is required"}, 400)
    if len(raw) > _SC_MAX_INPUT_BYTES:
        return None, ({"ok": False, "error": "input too large (max 8 MB)"}, 413)
    return raw, None


@app.route("/api/shellcode/process", methods=["POST"])
def api_shellcode_process():
    raw, err = _sc_get_text_input()
    if err:
        body, code = err
        return jsonify(body), code

    data       = request.get_json(force=True, silent=True) or {}
    fmt        = data.get("output_format", "c")
    transform  = data.get("transform",     "none")
    xor_key    = data.get("xor_key",       "")
    var_name   = data.get("var_name",      "buf")

    if fmt not in _shellcode.VALID_FORMATS:
        return jsonify({"ok": False, "error": f"unknown format '{fmt}'"}), 400
    return jsonify(_shellcode.process(raw, fmt, transform, xor_key, var_name))


@app.route("/api/shellcode/analyse", methods=["POST"])
def api_shellcode_analyse():
    raw, err = _sc_get_text_input()
    if err:
        body, code = err
        return jsonify(body), code
    return jsonify(_shellcode.analyse_only(raw))


@app.route("/api/shellcode/upload", methods=["POST"])
def api_shellcode_upload():
    """Receive a binary file, return hex representation + analysis."""
    if not HAS_SHELLCODE:
        return jsonify({"ok": False, "error": "shellcode module not available"}), 503
    f = request.files.get("file")
    if not f:
        return jsonify({"ok": False, "error": "no file provided"}), 400
    # +1 so we can detect the "too large" case rather than silently truncating
    blob = f.read(_SC_MAX_INPUT_BYTES + 1)
    if not blob:
        return jsonify({"ok": False, "error": "empty file"}), 400
    if len(blob) > _SC_MAX_INPUT_BYTES:
        return jsonify({"ok": False, "error": "file too large (max 8 MB)"}), 413
    stats = _shellcode.analyse(blob)
    stats["ok"]  = True
    stats["hex"] = blob.hex()
    return jsonify(stats)


# -- Artifact Map (Sigma -> ATT&CK technique artifacts) -------------------------

try:
    import artifact_parser as _artifact_parser
    HAS_ARTIFACT = True
except ImportError:
    HAS_ARTIFACT = False

_SIGMA_DIR = Path.home() / "hacking" / "sigma"


_TID_RE_API = re.compile(r"^T\d{4}(\.\d{3})?$")


def _artifacts_empty_stats() -> dict:
    return {
        "total_techniques": 0, "total_rules": 0,
        "unique_tactics":   0, "unique_event_ids": 0,
        "tactics": [], "built": False,
    }


@app.route("/api/artifacts")
def api_artifacts():
    tactic = request.args.get("tactic", "all").strip()
    q      = request.args.get("q",      "").strip()
    if _db.count_artifact_entries() == 0:
        return jsonify([])
    return jsonify(_db.get_artifact_entries(tactic, q))


@app.route("/api/artifacts/stats")
def api_artifacts_stats():
    if _db.count_artifact_entries() == 0:
        return jsonify(_artifacts_empty_stats())
    stats = _db.get_artifact_stats()
    stats["built"] = True
    return jsonify(stats)


@app.route("/api/artifacts/<tid>")
def api_artifact_entry(tid: str):
    if not _TID_RE_API.match(tid):
        return jsonify({"error": "invalid technique id"}), 400
    entry = _db.get_artifact_entry(tid)
    if not entry:
        return jsonify({"error": "not found"}), 404
    return jsonify(entry)


@app.route("/api/artifacts/rebuild")
def api_artifacts_rebuild():
    """
    SSE stream that emits real progress updates while parsing the Sigma corpus.

    The parser is run on a background thread because build_artifact_map() is a
    blocking call and we want the SSE consumer to see incremental progress.
    The progress_cb pushes (current, total) into a queue that the main thread
    drains and forwards as SSE events.
    """
    if not HAS_ARTIFACT:
        return jsonify({"error": "artifact_parser module not available"}), 503

    import queue as _q

    sigma_path = _SIGMA_DIR

    def generate():
        def evt(status: str, msg: str, **kw) -> str:
            return f"data: {json.dumps({'status': status, 'msg': msg, **kw})}\n\n"

        if not sigma_path.exists():
            yield evt("error", f"sigma dir not found: {sigma_path}")
            yield "data: [DONE]\n\n"
            return

        yield evt("running", f"scanning {sigma_path} …", current=0, total=0)

        events: _q.Queue = _q.Queue()
        result: dict = {"entries": None, "error": None}

        def progress(current: int, total: int, filename: str) -> None:
            events.put({"type": "progress", "current": current,
                        "total": total, "file": filename})

        def runner() -> None:
            try:
                result["entries"] = _artifact_parser.build_artifact_map(
                    sigma_path, progress,
                )
            except Exception as exc:
                result["error"] = str(exc)
            finally:
                events.put(None)   # sentinel: runner finished

        threading.Thread(target=runner, daemon=True).start()

        try:
            while True:
                try:
                    ev = events.get(timeout=20)
                except _q.Empty:
                    yield evt("running", "still parsing…", heartbeat=True)
                    continue
                if ev is None:
                    break
                if ev["type"] == "progress":
                    pct = int(ev["current"] / ev["total"] * 100) if ev["total"] else 0
                    yield evt("running",
                              f"parsed {ev['current']}/{ev['total']} rules ({pct}%)",
                              current=ev["current"], total=ev["total"], file=ev["file"])

            if result["error"]:
                yield evt("error", result["error"])
                yield "data: [DONE]\n\n"
                return

            _db.save_artifact_entries(result["entries"] or [])
            stats = _db.get_artifact_stats()
            yield evt(
                "done",
                f"built artifact map: {stats['total_techniques']} techniques "
                f"from {stats['total_rules']} Sigma rules",
                stats=stats,
            )
            yield "data: [DONE]\n\n"
        except GeneratorExit:
            # client navigated away - runner thread will still finish and
            # save_artifact_entries on its own iff we're past the runner call,
            # but at this point we're between events so just propagate cleanly.
            raise

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
