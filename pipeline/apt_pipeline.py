"""
peekaboo APT simulation pipeline
Malpedia -> Reports -> TTPs -> per-stage malware (one per TTP).

Local-only by design: no Claude / Gemini APIs are called from this pipeline.
TTP extraction uses regex (reliable for ATT&CK IDs). Per-stage source files
come straight from ~/hacking/meow via discovery.scan_all(). Compilation is
opt-in via config; default is source-only so a CPU box can run the whole
kill chain in under a minute.

Optional: a tiny local Ollama narration per stage (config flag, OFF by
default) writes a 1-2 sentence "why this module fits this TTP" line into
the per-session manifest.json.
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

ATTACK_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")

# Curated MITRE ID -> tactic map. Covers the most common APT report TTPs.
# Sub-techniques inherit from their base (T1547.001 -> persistence via T1547).
_TACTIC_MAP = {
    # execution
    "T1059": "execution",            "T1106": "execution",
    "T1204": "execution",            "T1129": "execution",
    "T1047": "execution",            "T1569": "execution",
    # defense evasion
    "T1027": "defense-evasion",      "T1055": "defense-evasion",
    "T1562": "defense-evasion",      "T1564": "defense-evasion",
    "T1622": "defense-evasion",      "T1112": "defense-evasion",
    "T1036": "defense-evasion",      "T1070": "defense-evasion",
    "T1574": "defense-evasion",      "T1140": "defense-evasion",
    # persistence
    "T1547": "persistence",          "T1546": "persistence",
    "T1053": "persistence",          "T1543": "persistence",
    "T1183": "persistence",          "T1136": "persistence",
    # privilege escalation
    "T1134": "privilege-escalation",
    # credential access
    "T1003": "credential-access",    "T1555": "credential-access",
    "T1056": "credential-access",
    # discovery
    "T1082": "discovery",            "T1012": "discovery",
    "T1057": "discovery",            "T1083": "discovery",
    "T1518": "discovery",
    # command and control
    "T1102": "command-and-control",  "T1041": "command-and-control",
    "T1071": "command-and-control",  "T1567": "command-and-control",
    "T1090": "command-and-control",  "T1573": "command-and-control",
    "T1132": "command-and-control",
    # exfiltration
    "T1029": "exfiltration",         "T1048": "exfiltration",
    # impact
    "T1486": "impact",               "T1490": "impact",
    "T1489": "impact",
}

# Kill-chain ordering: stages render in this order in the manifest and UI.
_KILL_CHAIN_ORDER = [
    "discovery",
    "execution",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "persistence",
    "command-and-control",
    "exfiltration",
    "impact",
    "unknown",
]


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
    """Download a handful of family/ref URLs, persist to DB, yield SSE events."""
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
                raw_html = r.text[:120000]
                _db.save_report(session_id, idx, url, raw_html)
                plain = re.sub(r"<[^>]+>", " ", raw_html)
                plain = re.sub(r"\s+", " ", plain).strip()
                yield {"report_idx": idx, "url": url,
                       "preview": plain[:300], "chars": len(raw_html)}
                idx += 1
        except Exception:
            continue


# --- Agent 3: TTP extractor (regex-only, no LLM API) -------------------------

def _ttp_name(aid: str) -> str:
    """Use the curated peekaboo MITRE library for a human-readable name."""
    try:
        sys.path.insert(0, str(_BASE / "dashboard"))
        from mitre import PEEKABOO_MODULES  # local fast lookup
        info = PEEKABOO_MODULES.get(aid) or PEEKABOO_MODULES.get(aid.split(".")[0])
        if isinstance(info, dict) and info.get("name"):
            return info["name"]
    except Exception:
        pass
    return aid


def agent_extract_ttps(report_contents: list[str], actor_data: dict) -> list[dict]:
    """
    Regex-based MITRE ATT&CK ID extraction across all report bodies.
    Sorted by appearance frequency (most-cited TTPs first).
    Optionally enriched from actor.attack_ids if Malpedia returned them.
    """
    counts: dict[str, int]            = {}
    evidence_map: dict[str, str]      = {}

    for i, text in enumerate(report_contents):
        if not text:
            continue
        for m in ATTACK_RE.finditer(text):
            aid = m.group()
            counts[aid] = counts.get(aid, 0) + 1
            if aid not in evidence_map:
                start = max(0, m.start() - 60)
                end   = min(len(text), m.end() + 80)
                snippet = text[start:end].strip().replace("\n", " ")
                snippet = re.sub(r"\s+", " ", snippet)
                evidence_map[aid] = snippet

    # actor-level Malpedia metadata sometimes lists TTPs directly
    for aid in actor_data.get("attack_ids", []) or []:
        if ATTACK_RE.fullmatch(aid):
            counts[aid] = counts.get(aid, 0) + 1

    ttps: list[dict] = []
    for aid, n in counts.items():
        base   = aid.split(".")[0]
        tactic = _TACTIC_MAP.get(aid) or _TACTIC_MAP.get(base) or "unknown"
        ttps.append({
            "id":       aid,
            "name":     _ttp_name(aid),
            "tactic":   tactic,
            "evidence": evidence_map.get(aid, "")[:160],
            "mentions": n,
        })

    # sort: kill-chain order first, then by mention count desc
    order_key = {t: i for i, t in enumerate(_KILL_CHAIN_ORDER)}
    ttps.sort(key=lambda t: (order_key.get(t["tactic"], 99), -t["mentions"]))
    return ttps


# --- Agent 4: per-TTP module selection ---------------------------------------

def _index_registry() -> tuple[list[dict], dict[str, list[dict]]]:
    """Return (full_registry, attack_id -> [modules])."""
    import discovery
    registry = discovery.scan_all()
    by_aid: dict[str, list[dict]] = {}
    for mod in registry:
        for aid in mod.get("attack_ids", []):
            by_aid.setdefault(aid, []).append(mod)
    return registry, by_aid


def _score_module(mod: dict, ttp: dict) -> int:
    """Prefer modules whose category aligns with the TTP tactic."""
    cat_to_tactic = {
        "persistence":  "persistence",
        "injection":    "defense-evasion",
        "evasion":      "defense-evasion",
        "cryptography": "defense-evasion",
        "syscalls":     "defense-evasion",
        "c2":           "command-and-control",
        "privesc":      "privilege-escalation",
        "shellcoding":  "execution",
        "hooking":      "credential-access",
    }
    score = 0
    if cat_to_tactic.get(mod.get("category", "")) == ttp.get("tactic"):
        score += 5
    if mod.get("platform") == "windows":
        score += 1  # demo target is Windows
    if mod.get("has_post"):
        score += 1  # prefer documented modules
    return score


def agent_select_modules(ttps: list[dict]) -> dict:
    """
    For each TTP, pick the best KB module and produce a self-contained 'stage'
    record. Stages are numbered by kill-chain order so the output looks like a
    real adversary kill chain.
    """
    registry, by_aid = _index_registry()
    stages: list[dict] = []

    for ttp in ttps:
        aid  = ttp["id"]
        base = aid.split(".")[0]
        candidates = by_aid.get(aid, []) or by_aid.get(base, [])
        if not candidates:
            continue

        best = max(candidates, key=lambda m: _score_module(m, ttp))
        stages.append({
            "stage_num":   len(stages) + 1,
            "ttp_id":      aid,
            "ttp_name":    ttp.get("name", aid),
            "tactic":      ttp.get("tactic", "unknown"),
            "evidence":    ttp.get("evidence", ""),
            "mentions":    ttp.get("mentions", 1),
            "module_id":   best["id"],
            "module_title": best["title"],
            "category":    best["category"],
            "platform":    best["platform"],
            "compiler":    best.get("compiler", ""),
            "extra_libs":  best.get("extra_libs", []),
            "src_path":    best["src_path"],
            "src_name":    best["src_name"],
            "blog_url":    best.get("blog_url", ""),
            "snippet":     (best.get("snippet") or "")[:600],
        })

    # legacy shape kept so the existing frontend can still render a flat list
    selected_modules = [{
        "attack_id": s["ttp_id"],
        "module_id": s["module_id"],
        "title":     s["module_title"],
        "category":  s["category"],
        "platform":  s["platform"],
    } for s in stages]

    return {"stages": stages, "selected_modules": selected_modules}


# --- Agent 5: per-stage assembly ---------------------------------------------

_INVALID = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe(name: str) -> str:
    return _INVALID.sub("_", name).strip("_") or "stage"


def _compile_one(stage: dict, out_dir: Path) -> Path | None:
    """Best-effort compile of a single stage. Failure is logged, not fatal."""
    compiler = stage.get("compiler", "")
    src      = Path(stage["src_path"])
    out      = out_dir / f"{Path(stage['_out_src']).stem}.exe"

    cmd: list[str] = []
    if compiler == "mingw-gcc":
        cmd = ["x86_64-w64-mingw32-gcc", str(src), "-o", str(out)]
    elif compiler == "mingw-gpp":
        cmd = ["x86_64-w64-mingw32-g++", str(src), "-o", str(out)]
    elif compiler == "gcc":
        cmd = ["gcc", str(src), "-o", str(out.with_suffix(""))]
    elif compiler == "gpp":
        cmd = ["g++", str(src), "-o", str(out.with_suffix(""))]
    else:
        return None
    cmd += stage.get("extra_libs", [])

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        if r.returncode == 0 and out.exists():
            return out
    except Exception:
        pass
    return None


def agent_build_stages(stages: list[dict], session_id: str,
                       compile_each: bool = False) -> tuple[list[Path], dict]:
    """
    Copy each stage's source into samples/{sid}/ with a kill-chain prefix and
    write a manifest.json. Optionally invoke the matching compiler per stage.

    Returns (produced_files, manifest).
    """
    out_dir = _SAMPLES / session_id
    out_dir.mkdir(parents=True, exist_ok=True)

    produced: list[Path] = []
    seen_names: set[str] = set()

    for s in stages:
        src = Path(s["src_path"])
        if not src.exists():
            continue

        # name: stage_03_persistence_T1547_pers.c (sortable, descriptive)
        tactic_tag = _safe(s["tactic"])
        aid_tag    = _safe(s["ttp_id"])
        base       = f"stage_{s['stage_num']:02d}_{tactic_tag}_{aid_tag}_{_safe(src.stem)}{src.suffix}"
        # collision guard (shouldn't usually fire, kill-chain order is unique)
        name = base
        n    = 1
        while name in seen_names:
            name = f"{base[:-len(src.suffix)]}_{n}{src.suffix}"
            n   += 1
        seen_names.add(name)

        dst = out_dir / name
        try:
            shutil.copy2(src, dst)
            s["_out_src"] = dst.name
            produced.append(dst)
        except Exception:
            continue

        if compile_each:
            bin_path = _compile_one(s, out_dir)
            if bin_path is not None:
                produced.append(bin_path)
                s["_out_bin"] = bin_path.name

    manifest = {
        "session_id":  session_id,
        "built_at":    datetime.now().isoformat(),
        "kill_chain":  _KILL_CHAIN_ORDER,
        "compile_each": compile_each,
        "stages":      stages,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    produced.append(out_dir / "manifest.json")

    return produced, manifest


# --- Optional Ollama per-stage narrator (local, off by default) --------------

def _ollama_narrate(stage: dict, base_url: str, model: str, timeout: int = 25) -> str:
    """
    Tiny local Ollama call. ~80-token output describing why this module fits
    the TTP. Returns "" on any error so the pipeline never breaks because of it.
    """
    import urllib.request as _ur
    prompt = (
        "You are a malware research assistant. In 2 short sentences explain why "
        f"the module '{stage['module_title']}' (category {stage['category']}) is "
        f"a reasonable implementation for MITRE ATT&CK technique {stage['ttp_id']} "
        f"({stage['ttp_name']}, tactic: {stage['tactic']}). Be concrete, no fluff."
    )
    payload = json.dumps({
        "model":  model,
        "stream": False,
        "think":  False,
        "options": {"temperature": 0.2, "num_predict": 120, "num_ctx": 1024},
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    try:
        req = _ur.Request(f"{base_url.rstrip('/')}/api/chat", data=payload,
                          headers={"Content-Type": "application/json"},
                          method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            return (data.get("message", {}).get("content") or "").strip()
    except Exception:
        return ""


# --- Main pipeline -----------------------------------------------------------

def run_pipeline(actor_id: str) -> Generator[dict, None, None]:
    session_id  = uuid.uuid4().hex[:8]
    session_dir = _SESSIONS / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now().isoformat()

    _db.save_pipeline_session({
        "session_id": session_id, "actor_id": actor_id,
        "started": started, "status": "running",
    })

    pipeline_cfg = _load_cfg("apt_pipeline_config")
    compile_each = bool(pipeline_cfg.get("compile_each", False))
    use_ollama   = bool(pipeline_cfg.get("ollama_narration", False))
    ollama_url   = pipeline_cfg.get("ollama_base_url", "http://localhost:11434")
    ollama_model = pipeline_cfg.get("ollama_model", "qwen3:0.6b")

    # 1. Fetch actor / family
    yield {"step": 1, "status": "running", "msg": f"fetching actor data: {actor_id}"}
    ok, actor_data = agent_fetch(actor_id)
    if not ok:
        _db.update_pipeline_session(session_id, status="failed",
                                    finished=datetime.now().isoformat())
        yield {"step": 1, "status": "error", "msg": actor_data.get("error", "malpedia fetch failed")}
        return
    actor_name = actor_data.get("name", actor_id)
    yield {"step": 1, "status": "done", "msg": f"fetched: {actor_name}",
           "data": {k: v for k, v in actor_data.items()
                    if k not in ("snippet", "related_posts")}}

    # 2. Download reports
    yield {"step": 2, "status": "running", "msg": "downloading threat reports…"}
    report_contents: list[str] = []
    for ev in agent_download(actor_data, session_id):
        raw = _db.get_reports(session_id)[ev["report_idx"]]["content"]
        plain = re.sub(r"<[^>]+>", " ", raw)
        plain = re.sub(r"\s+", " ", plain).strip()[:60000]
        report_contents.append(plain)
        yield {"step": 2, "status": "running",
               "msg": f"downloaded report {ev['report_idx']+1}: {ev['url'][:60]}",
               "data": {"report": ev}}
    yield {"step": 2, "status": "done",
           "msg": f"{len(report_contents)} report(s) downloaded",
           "data": {"count": len(report_contents)}}

    # 3. Extract TTPs (local regex only - no API calls)
    yield {"step": 3, "status": "running", "msg": "extracting TTPs (regex, local)…"}
    ttps = agent_extract_ttps(report_contents, actor_data)
    _db.update_pipeline_session(session_id, ttps=ttps)
    yield {"step": 3, "status": "done",
           "msg": f"{len(ttps)} TTP(s) extracted", "data": ttps}

    # 4. Select per-TTP modules
    yield {"step": 4, "status": "running", "msg": "mapping each TTP to a KB module…"}
    sel = agent_select_modules(ttps)
    stages = sel["stages"]
    _db.update_pipeline_session(session_id, params=sel)
    yield {"step": 4, "status": "done",
           "msg": f"{len(stages)} kill-chain stage(s) mapped",
           "data": sel}

    if not stages:
        finished = datetime.now().isoformat()
        _db.update_pipeline_session(session_id, status="failed", finished=finished)
        yield {"step": 5, "status": "error",
               "msg": "no KB modules matched any extracted TTP - try a different actor"}
        return

    # 5. Assemble per-stage malware (one artefact per TTP)
    yield {"step": 5, "status": "running",
           "msg": f"assembling {len(stages)} per-TTP artefact(s) "
                  f"({'compile' if compile_each else 'source-only'})…"}

    if use_ollama:
        for s in stages:
            yield {"step": 5, "status": "running",
                   "msg": f"narrating stage {s['stage_num']}/{len(stages)}: "
                          f"{s['ttp_id']} -> {s['module_title'][:40]}"}
            s["narration"] = _ollama_narrate(s, ollama_url, ollama_model)

    files, manifest = agent_build_stages(stages, session_id,
                                         compile_each=compile_each)
    finished = datetime.now().isoformat()

    if files:
        _db.update_pipeline_session(session_id, status="success",
                                    finished=finished, params=sel)
        yield {"step": 5, "status": "done",
               "msg": f"{len(stages)} stage artefact(s) written "
                      f"({len(files)} file(s) total)",
               "data": {
                   "session_id": session_id,
                   "files":      [f.name for f in files],
                   "stages":     stages,
                   "manifest":   "manifest.json",
               }}
    else:
        _db.update_pipeline_session(session_id, status="failed", finished=finished)
        yield {"step": 5, "status": "error",
               "msg": "no source files could be copied (check ~/hacking/meow paths)"}
        return

    yield {"step": 0, "status": "complete", "msg": "pipeline complete",
           "data": {"session_id": session_id}}


def list_sessions() -> list[dict]:
    return _db.get_pipeline_sessions()
