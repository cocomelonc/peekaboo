"""
peekaboo APT simulation pipeline
Malpedia -> Reports -> TTPs -> Modules -> Build
"""
from __future__ import annotations
import json
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Generator

_BASE     = Path(__file__).parent.parent
_SESSIONS = Path(__file__).parent / "sessions"
_SAMPLES  = _BASE / "samples"
_CFG      = _BASE / "config"

sys.path.insert(0, str(_BASE / "dashboard"))
import db as _db

ATTACK_RE = re.compile(r'\bT1\d{3}(?:\.\d{3})?\b')

_TACTIC_MAP = {
    "T1059": "execution",      "T1106": "execution",      "T1204": "execution",
    "T1027": "defense-evasion","T1055": "defense-evasion","T1562": "defense-evasion",
    "T1564": "defense-evasion","T1622": "defense-evasion","T1112": "defense-evasion",
    "T1036": "defense-evasion","T1070": "defense-evasion",
    "T1547": "persistence",    "T1546": "persistence",    "T1053": "persistence",
    "T1543": "persistence",    "T1183": "persistence",
    "T1102": "command-and-control","T1041": "command-and-control",
    "T1071": "command-and-control","T1567": "command-and-control",
    "T1134": "privilege-escalation","T1055": "privilege-escalation",
    "T1003": "credential-access",
    "T1082": "discovery",      "T1012": "discovery",
}


def _load_cfg(name: str) -> dict:
    p = _CFG / f"{name}.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


# --- Agent 1: Malpedia fetch -------------------------------------------------

def agent_fetch(actor_id: str) -> tuple[bool, dict]:
    try:
        import malpedia
        # try actor first, then family
        if "/" in actor_id or "win." in actor_id or "elf." in actor_id:
            data = malpedia.get_family(actor_id)
        else:
            data = malpedia.get_actor(actor_id)
            if "error" in data:
                data = malpedia.get_family(actor_id)
        return "error" not in data, data
    except Exception as e:
        return False, {"error": str(e)}


# --- Agent 2: Report downloader ----------------------------------------------

def agent_download(actor_data: dict, session_id: str):
    """Download reports, store each in DB, yield SSE-style dicts as they land."""
    try:
        import requests as _req
    except ImportError:
        return

    urls: list[str] = []
    for fam in actor_data.get("families", []):
        urls.extend(fam.get("urls", [])[:3])
    urls.extend(actor_data.get("refs", [])[:6])
    urls = list(dict.fromkeys(urls))[:10]

    idx = 0
    for url in urls:
        try:
            r = _req.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                # store raw HTML so the frontend can render it properly
                raw_html = r.text[:120000]
                _db.save_report(session_id, idx, url, raw_html)
                # plain text for the live event preview only
                plain = re.sub(r'<[^>]+>', ' ', raw_html)
                plain = re.sub(r'\s+', ' ', plain).strip()
                yield {"report_idx": idx, "url": url,
                       "preview": plain[:300], "chars": len(raw_html)}
                idx += 1
        except Exception:
            continue


# --- Agent 3: TTP extractor --------------------------------------------------

def _extract_regex(contents: list[str]) -> list[dict]:
    found: dict[str, dict] = {}
    for i, text in enumerate(contents):
        for m in ATTACK_RE.finditer(text):
            aid = m.group()
            if aid not in found:
                base   = aid.split(".")[0]
                tactic = _TACTIC_MAP.get(aid) or _TACTIC_MAP.get(base) or "unknown"
                found[aid] = {"id": aid, "name": aid, "tactic": tactic,
                               "source": f"report_{i:02d}"}
    return list(found.values())


def _extract_claude(contents: list[str]) -> list[dict]:
    try:
        import anthropic
        cfg     = _load_cfg("anthropic_config")
        api_key = cfg.get("api_key") or cfg.get("anthropic_api_key", "")
        if not api_key or "xxx" in api_key:
            return []

        chunks = [c[:8000] for c in contents[:4] if c]
        if not chunks:
            return []

        text = "\n\n---\n\n".join(chunks)[:24000]

        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            messages=[{
                "role": "user",
                "content": (
                    "Extract MITRE ATT&CK TTPs from this threat intelligence report.\n"
                    "Focus on execution, defense-evasion, persistence, command-and-control.\n\n"
                    "Return ONLY a JSON array:\n"
                    '[{"id":"T1055","name":"Process Injection","tactic":"defense-evasion",'
                    '"evidence":"short quote from report"}]\n\n'
                    "No markdown, no explanation, just the JSON array.\n\n"
                    f"Report:\n{text}"
                ),
            }],
        )

        raw = msg.content[0].text.strip()
        m   = re.search(r'\[.*\]', raw, re.DOTALL)
        if m:
            return json.loads(m.group())
    except Exception:
        pass
    return []


def agent_extract_ttps(report_contents: list[str], actor_data: dict) -> list[dict]:
    ttps = _extract_claude(report_contents)
    if not ttps:
        ttps = _extract_regex(report_contents)

    seen: set[str]      = set()
    validated: list[dict] = []
    for t in ttps:
        aid = t.get("id", "")
        if not re.match(r'^T1\d{3}(\.\d{3})?$', aid):
            continue
        if aid in seen:
            continue
        seen.add(aid)
        base = aid.split(".")[0]
        if not t.get("tactic"):
            t["tactic"] = _TACTIC_MAP.get(aid) or _TACTIC_MAP.get(base) or "unknown"
        if not t.get("name") or t["name"] == aid:
            t["name"] = aid
        validated.append(t)

    return validated


# --- Agent 4: Module selector ------------------------------------------------

def agent_select_modules(ttps: list[dict]) -> dict:
    import discovery

    registry = discovery.scan_all()

    by_aid: dict[str, list[dict]] = {}
    for mod in registry:
        for aid in mod["attack_ids"]:
            by_aid.setdefault(aid, []).append(mod)

    params: dict = {
        "payload":    "meow",
        "encryption": "speck",
        "malware":    "injection",
        "injection":  "virtualallocex",
        "stealer":    "telegram",
        "persistence":"none",
        "selected_modules": [],
    }

    for ttp in ttps:
        aid  = ttp["id"]
        base = aid.split(".")[0]
        mods = by_aid.get(aid, []) or by_aid.get(base, [])
        if mods:
            best = mods[0]
            params["selected_modules"].append({
                "attack_id": aid,
                "module_id": best["id"],
                "title":     best["title"],
                "category":  best["category"],
                "platform":  best["platform"],
            })

    # map category -> build param overrides
    cats = {m["category"] for m in params["selected_modules"]}
    if "cryptography" in cats:
        # find a suitable crypto module from peekaboo templates
        from mitre import PEEKABOO_MODULES
        crypto_algos = [a for a in ["speck", "mars", "lucifer", "feal8", "treyfer"]
                        if (Path(_BASE) / "malware/crypto" / a).exists()]
        if crypto_algos:
            params["encryption"] = crypto_algos[0]

    return params


# --- Agent 5: Builder --------------------------------------------------------

def agent_build(params: dict, session_id: str) -> tuple[bool, str, list[Path]]:
    samples_dir = _SAMPLES / session_id
    samples_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, str(_BASE / "peekaboo.py"),
        "-p", params.get("payload", "meow"),
        "-e", params.get("encryption", "speck"),
        "-m", params.get("malware", "injection"),
        "-i", params.get("injection", "virtualallocex"),
        "-s", params.get("stealer", "telegram"),
        "-r", params.get("persistence", "none"),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=str(_BASE))
        log    = result.stdout + result.stderr

        if result.returncode == 0:
            # copy produced binaries to samples dir
            malware_dir   = _BASE / "malware"
            injection_type = params.get("injection", "virtualallocex")
            src_dir        = malware_dir / "injection" / injection_type
            if params.get("malware") == "stealer":
                src_dir = malware_dir / "stealer" / params.get("stealer", "telegram")

            copied: list[Path] = []
            for name in ("peekaboo.exe", "persistence.exe"):
                src = src_dir / name
                if src.exists():
                    dst = samples_dir / name
                    shutil.copy2(src, dst)
                    copied.append(dst)

            return True, log, copied
        return False, log, []
    except subprocess.TimeoutExpired:
        return False, "build timed out (120s)", []
    except Exception as e:
        return False, str(e), []


# --- Main pipeline -----------------------------------------------------------

def run_pipeline(actor_id: str) -> Generator[dict, None, None]:
    session_id  = uuid.uuid4().hex[:8]
    session_dir = _SESSIONS / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now().isoformat()

    # persist session skeleton immediately so the UI can track it
    _db.save_pipeline_session({
        "session_id": session_id, "actor_id": actor_id,
        "started": started, "status": "running",
    })

    # 1. Fetch
    yield {"step": 1, "status": "running", "msg": f"fetching actor data: {actor_id}"}
    ok, actor_data = agent_fetch(actor_id)
    if not ok:
        _db.update_pipeline_session(session_id, status="failed",
                                    finished=datetime.now().isoformat())
        yield {"step": 1, "status": "error", "msg": actor_data.get("error", "malpedia fetch failed")}
        return
    actor_name = actor_data.get("name", actor_id)
    yield {"step": 1, "status": "done", "msg": f"fetched: {actor_name}",
           "data": {k: v for k, v in actor_data.items() if k not in ("snippet", "related_posts")}}

    # 2. Download reports - stream one event per report as they land in DB
    yield {"step": 2, "status": "running", "msg": "downloading threat reports…"}
    report_contents: list[str] = []
    for ev in agent_download(actor_data, session_id):
        raw = _db.get_reports(session_id)[ev["report_idx"]]["content"]
        plain = re.sub(r'<[^>]+>', ' ', raw)
        plain = re.sub(r'\s+', ' ', plain).strip()[:60000]
        report_contents.append(plain)
        yield {"step": 2, "status": "running",
               "msg": f"downloaded report {ev['report_idx']+1}: {ev['url'][:60]}",
               "data": {"report": ev}}
    yield {"step": 2, "status": "done",
           "msg": f"{len(report_contents)} report(s) downloaded",
           "data": {"count": len(report_contents)}}

    # 3. Extract TTPs
    yield {"step": 3, "status": "running", "msg": "extracting TTPs (Claude API + regex)…"}
    ttps = agent_extract_ttps(report_contents, actor_data)
    _db.update_pipeline_session(session_id, ttps=ttps)
    yield {"step": 3, "status": "done", "msg": f"{len(ttps)} TTPs extracted", "data": ttps}

    # 4. Select modules
    yield {"step": 4, "status": "running", "msg": "mapping TTPs to modules…"}
    params = agent_select_modules(ttps)
    _db.update_pipeline_session(session_id, params=params)
    yield {"step": 4, "status": "done",
           "msg": f"{len(params['selected_modules'])} module(s) selected", "data": params}

    # 5. Build
    yield {"step": 5, "status": "running", "msg": "compiling sample binary…"}
    ok, log, files = agent_build(params, session_id)
    finished = datetime.now().isoformat()
    if ok:
        _db.update_pipeline_session(session_id, status="success", finished=finished)
        yield {"step": 5, "status": "done", "msg": f"binary compiled ({len(files)} file(s))",
               "data": {"session_id": session_id, "files": [f.name for f in files]}}
    else:
        _db.update_pipeline_session(session_id, status="failed", finished=finished)
        yield {"step": 5, "status": "error", "msg": log[:300]}
        return

    yield {"step": 0, "status": "complete", "msg": "pipeline complete",
           "data": {"session_id": session_id}}


def list_sessions() -> list[dict]:
    return _db.get_pipeline_sessions()
