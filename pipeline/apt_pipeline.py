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
import random
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


import cfg as _cfg


def _load_cfg(name: str) -> dict:
    """Back-compat shim - configs now live in .env via cfg.py."""
    return _cfg.get(name) or {}


def _truthy(v) -> bool:
    """Parse an env-style boolean (`True`/`true`/`1`/`yes` -> True)."""
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


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


def _attack_reference() -> tuple[set[str], dict[str, str], dict[str, str]]:
    """Canonical ATT&CK reference from the DB `artifact_map` (400+ real techniques):
    (valid_ids, id->name, id->tactic).

    This is what makes extraction accurate instead of a regex free-for-all:
    - `valid_ids` lets us drop garbage T-codes that aren't real techniques.
    - `id->name` lets us catch techniques mentioned by NAME in report prose.
    - `id->tactic` gives real kill-chain placement for 400+ techniques instead
      of the ~50-entry curated fallback.

    Local, no LLM. Falls back to the curated `_TACTIC_MAP` if the DB has no
    artifact data yet, so the pipeline still runs on a bare install.
    """
    valid: set[str]           = set()
    names: dict[str, str]     = {}
    tactics: dict[str, str]   = {}
    try:
        sys.path.insert(0, str(_BASE / "dashboard"))
        import db
        for e in db.get_artifact_entries():
            tid = (e.get("tid") or "").upper()
            if not ATTACK_RE.fullmatch(tid):
                continue
            valid.add(tid)
            valid.add(tid.split(".")[0])           # base id counts as valid too
            if e.get("name"):
                names[tid] = e["name"]
            tac = (e.get("tactic") or "").split(",")[0].strip()
            if tac:
                tactics[tid] = tac
    except Exception:
        pass
    return valid, names, tactics


def _precomputed_report_ttps(actor_data: dict) -> list[dict]:
    """Return GPU-precomputed report TTPs for this actor/family, if present.

    These rows are produced by `worker.py reports` after HTML/PDF parsing and
    LLM extraction. When present they make the APT pipeline offline and richer
    than live regex scraping. Empty result means "fall back to live reports".
    """
    subject_id = actor_data.get("id") or ""
    if not subject_id:
        return []
    subject_type = "family" if ("/" in subject_id or "." in subject_id) else "actor"
    try:
        rows = _db.get_report_ttps(subject_id, subject_type=subject_type)
    except Exception:
        rows = []
    if not rows:
        try:
            rows = _db.get_report_ttps(subject_id)
        except Exception:
            rows = []
    if not rows:
        return []

    valid_ids, ref_names, ref_tactics = _attack_reference()
    by_tid: dict[str, dict] = {}
    conf_rank = {"high": 3, "medium": 2, "low": 1}
    for row in rows:
        tid = (row.get("tid") or "").upper()
        if not ATTACK_RE.fullmatch(tid):
            continue
        if valid_ids and tid not in valid_ids and tid.split(".")[0] not in valid_ids:
            continue
        base = tid.split(".")[0]
        tactic = (_TACTIC_MAP.get(tid) or _TACTIC_MAP.get(base)
                  or row.get("tactic") or ref_tactics.get(tid)
                  or ref_tactics.get(base) or "unknown")
        name = row.get("name") or ref_names.get(tid) or ref_names.get(base) or _ttp_name(tid)
        cur = by_tid.setdefault(tid, {
            "id": tid,
            "name": name,
            "tactic": tactic,
            "evidence": row.get("evidence", "")[:160],
            "mentions": 0,
            "confidence": row.get("confidence", "low"),
            "source": "precomputed-reports",
        })
        cur["mentions"] += 1
        if conf_rank.get(row.get("confidence", "low"), 1) > conf_rank.get(cur.get("confidence", "low"), 1):
            cur["confidence"] = row.get("confidence", "low")
            cur["evidence"] = row.get("evidence", "")[:160]

    order_key = {t: i for i, t in enumerate(_KILL_CHAIN_ORDER)}
    ttps = list(by_tid.values())
    ttps.sort(key=lambda t: (order_key.get(t["tactic"], 99), -t["mentions"], t["id"]))
    return ttps


def _precomputed_report_sources(actor_data: dict) -> list[dict]:
    subject_id = actor_data.get("id") or ""
    if not subject_id:
        return []
    subject_type = "family" if ("/" in subject_id or "." in subject_id) else "actor"
    try:
        rows = _db.get_report_ttp_sources(subject_type, subject_id)
    except Exception:
        rows = []
    if not rows:
        try:
            rows = _db.get_report_ttp_sources("actor", subject_id) + _db.get_report_ttp_sources("family", subject_id)
        except Exception:
            rows = []
    return [{
        "url": r.get("url", ""),
        "title": r.get("title", ""),
        "status": r.get("status", ""),
        "content_type": r.get("content_type", ""),
        "text_chars": r.get("text_chars", 0),
        "model": r.get("model", ""),
    } for r in rows if r.get("url")]


def agent_extract_ttps(report_contents: list[str], actor_data: dict) -> list[dict]:
    """
    Local ATT&CK extraction across all report bodies (no LLM, no network):

      1. explicit T-codes, VALIDATED against the real technique set (garbage
         like `T1999` or a random `T1234` string is dropped);
      2. techniques mentioned by NAME in prose (e.g. "process injection",
         "registry run keys") mapped back to their ATT&CK ID - this is what
         regex-only missed entirely;
      3. actor-level Malpedia `attack_ids`, also validated.

    Sorted kill-chain order first, then by mention count.
    """
    precomputed = actor_data.get("_precomputed_report_ttps")
    if precomputed:
        return precomputed

    valid_ids, ref_names, ref_tactics = _attack_reference()

    counts:   dict[str, int] = {}
    evidence: dict[str, str] = {}

    def _add(aid: str, snippet: str = "") -> None:
        aid = aid.upper()
        counts[aid] = counts.get(aid, 0) + 1
        if snippet and aid not in evidence:
            evidence[aid] = re.sub(r"\s+", " ", snippet.strip().replace("\n", " "))

    def _is_valid(aid: str) -> bool:
        # if we have no reference set (bare install), accept anything (old behavior)
        return (not valid_ids) or aid in valid_ids or aid.split(".")[0] in valid_ids

    # prose matcher: one alternation regex over real technique names (>=6 chars,
    # specific enough to be signal). Longest names first so we match greedily.
    name_to_id: dict[str, str] = {}
    for tid, n in ref_names.items():
        # index the full name AND each "/"-separated segment, since ATT&CK sub-
        # technique names take the form "Registry Run Keys / Startup Folder" and
        # reports usually cite just one half.
        for variant in [n, *n.split("/")]:
            v = variant.strip()
            if len(v) >= 6:
                name_to_id.setdefault(v.lower(), tid)
    name_pat = None
    if name_to_id:
        alt = "|".join(re.escape(n) for n in sorted(name_to_id, key=len, reverse=True))
        name_pat = re.compile(r"(?<![\w-])(" + alt + r")(?![\w-])", re.I)

    for text in report_contents:
        if not text:
            continue
        # 1. explicit, validated ATT&CK IDs
        for m in ATTACK_RE.finditer(text):
            aid = m.group().upper()
            if not _is_valid(aid):
                continue
            s, e = max(0, m.start() - 60), min(len(text), m.end() + 80)
            _add(aid, text[s:e])
        # 2. techniques named in prose -> real IDs
        if name_pat:
            for m in name_pat.finditer(text):
                tid = name_to_id.get(m.group(1).lower())
                if tid:
                    s, e = max(0, m.start() - 40), min(len(text), m.end() + 90)
                    _add(tid, text[s:e])

    # 3. actor-level Malpedia metadata, validated
    for aid in actor_data.get("attack_ids", []) or []:
        aid = (aid or "").upper()
        if ATTACK_RE.fullmatch(aid) and _is_valid(aid):
            _add(aid)

    ttps: list[dict] = []
    for aid, n in counts.items():
        base   = aid.split(".")[0]
        # curated map has the correct PRIMARY tactic; artifact_map's comma-list
        # (from Sigma) is only a fallback for techniques the curated map misses.
        tactic = (_TACTIC_MAP.get(aid) or _TACTIC_MAP.get(base)
                  or ref_tactics.get(aid) or ref_tactics.get(base) or "unknown")
        name   = ref_names.get(aid) or ref_names.get(base) or _ttp_name(aid)
        ttps.append({
            "id":       aid,
            "name":     name,
            "tactic":   tactic,
            "evidence": evidence.get(aid, "")[:160],
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


_CAT_TO_TACTIC = {
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


# General markers of an "advanced" trick - signals, not a per-module allowlist.
# Their presence in a title nudges selection toward the interesting posts over
# the 101 examples (classic VirtualAllocEx etc.).
_ADVANCED_MARKERS = (
    "syscall", "undocumented", "native api", "callback", "unhook", "apc",
    "hijack", "stomp", "reflective", "manual map", "hell", "halo", "ghost",
    "hollow", "doppel", "phantom", "tls callback", "hardware breakpoint",
    "indirect", "direct syscall", "ntcreate", "zwcreate", "ntmap", "ntalloc",
    "zwqueue", "enumchild", "enumdesktop", "kernelcallbacktable", "module stomp",
    "fiber", "thread pool", "obfuscat", "encrypt", "hashing",
)


def _sophistication(mod: dict) -> float:
    """Heuristic 'coolness' derived from real metadata - no hardcoded list.

    Two signals that track how the blog is actually organized:
      - the numbered series suffix: later posts (`-21`) are the advanced tricks,
        early ones (`-1`) are the classic 101 examples;
      - an advanced-API marker in the title (KernelCallbackTable, undocumented
        Native API, syscalls, ...).

    This is what stops the pipeline picking the boring example when a cooler one
    is mapped to the same technique.
    """
    score = 0.0
    slug = mod.get("slug", "") or mod.get("id", "")
    m = re.search(r"(\d+)\s*$", slug)                # trailing series number
    if m:
        score += min(int(m.group(1)), 30) * 0.12     # up to +3.6 for late posts
    title = (mod.get("title", "") or "").lower()
    if any(k in title for k in _ADVANCED_MARKERS):
        score += 1.8
    return score


def _score_module(mod: dict, ttp: dict) -> float:
    """Base score: tactic alignment + quality + sophistication. No randomness here."""
    score = 0.0
    if _CAT_TO_TACTIC.get(mod.get("category", "")) == ttp.get("tactic"):
        score += 5
    if mod.get("platform") == "windows":
        score += 1
    if mod.get("has_post"):
        score += 1
    score += _sophistication(mod)   # bias toward the interesting tricks
    return score


def _recent_module_ids(limit: int = 10) -> set[str]:
    """Module IDs used across the last N sessions - used to deprioritize repeats."""
    try:
        used: set[str] = set()
        for s in _db.get_pipeline_sessions(limit=limit):
            for stage in (s.get("params") or {}).get("stages", []):
                mid = stage.get("module_id")
                if mid:
                    used.add(mid)
        return used
    except Exception:
        return set()


def _pick_module(candidates: list[dict], ttp: dict,
                 used_srcs: set[str], recent_ids: set[str]) -> dict | None:
    """
    Weighted random pick from the top-5 candidates.

    Scoring layers (applied in order, jitter last so equal-scorers vary):
      +5  tactic/category alignment
      +1  windows platform
      +1  has blog post
      -10 src_path already used in this session  (hard avoid same file twice)
      -3  module_id seen in a recent session      (soft deprioritize repeats)
      +[0,2) random jitter                        (vary picks across runs)

    Top-5 by adjusted score get weights proportional to (score - min + 1),
    then random.choices picks one. This keeps quality first while ensuring
    lower-scoring alternatives get a real shot.
    """
    if not candidates:
        return None

    scored: list[tuple[dict, float]] = []
    for m in candidates:
        s = _score_module(m, ttp)
        if m.get("src_path") in used_srcs:
            s -= 10
        if m.get("id") in recent_ids:
            s -= 3
        s += random.uniform(0, 2.0)
        scored.append((m, s))

    scored.sort(key=lambda x: x[1], reverse=True)
    top = scored[:5]

    min_s = top[-1][1]
    weights = [max(0.1, s - min_s + 1.0) for _, s in top]
    return random.choices([m for m, _ in top], weights=weights, k=1)[0]


def agent_select_modules(ttps: list[dict]) -> dict:
    """
    For each TTP, pick a KB module and produce a kill-chain stage record.
    Selection is randomized (weighted by score) so repeated runs of the same
    actor produce different malware assemblies - better coverage for blue teams.
    """
    registry, by_aid = _index_registry()
    recent_ids  = _recent_module_ids()
    used_srcs: set[str] = set()   # no duplicate source files within one session
    stages: list[dict] = []

    for ttp in ttps:
        aid  = ttp["id"]
        base = aid.split(".")[0]
        candidates = by_aid.get(aid, []) or by_aid.get(base, [])
        if not candidates:
            continue

        best = _pick_module(candidates, ttp, used_srcs, recent_ids)
        if best is None:
            continue

        selection_score = _score_module(best, ttp)
        sophistication = _sophistication(best)
        used_srcs.add(best.get("src_path", ""))
        stages.append({
            "stage_num":    len(stages) + 1,
            "ttp_id":       aid,
            "ttp_name":     ttp.get("name", aid),
            "tactic":       ttp.get("tactic", "unknown"),
            "evidence":     ttp.get("evidence", ""),
            "mentions":     ttp.get("mentions", 1),
            "module_id":    best["id"],
            "module_slug":  best.get("slug", best["id"]),
            "module_title": best["title"],
            "category":     best["category"],
            "platform":     best["platform"],
            "compiler":     best.get("compiler", ""),
            "extra_libs":   best.get("extra_libs", []),
            "src_path":     best["src_path"],
            "src_name":     best["src_name"],
            "blog_url":     best.get("blog_url", ""),
            "selection_score": round(selection_score, 2),
            "sophistication": round(sophistication, 2),
            "snippet":      (best.get("snippet") or "")[:600],
        })

    selected_modules = [{
        "attack_id": s["ttp_id"],
        "module_id": s["module_id"],
        "title":     s["module_title"],
        "category":  s["category"],
        "platform":  s["platform"],
        "slug":      s.get("module_slug", s["module_id"]),
        "blog_url":  s.get("blog_url", ""),
        "selection_score": s.get("selection_score", 0),
        "sophistication":  s.get("sophistication", 0),
    } for s in stages]

    return {"stages": stages, "selected_modules": selected_modules}


# --- Agent 5: per-stage assembly ---------------------------------------------

_INVALID = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe(name: str) -> str:
    return _INVALID.sub("_", name).strip("_") or "stage"


def _compile_one(stage: dict, out_dir: Path) -> tuple[Path | None, str, str]:
    """
    Build one stage via dashboard/compiler.build(). Failure is logged on the
    stage, not raised. Returns (out_path | None, kind, log).

    `kind` is "exe", "dll", or "elf" so the manifest / frontend can group output
    by what was actually produced.
    """
    src      = Path(stage["src_path"])
    compiler = stage.get("compiler", "")
    if compiler not in ("mingw-gcc", "mingw-gpp", "gcc", "gpp"):
        return None, "", f"unsupported compiler: {compiler}"

    try:
        sys.path.insert(0, str(_BASE / "dashboard"))
        from compiler import build, BuildSpec, looks_like_dll  # type: ignore
    except Exception as e:
        return None, "", f"compiler import failed: {e}"

    is_dll  = compiler.startswith("mingw") and looks_like_dll(src)
    windows = compiler.startswith("mingw")
    if is_dll:
        ext, kind = ".dll", "dll"
    elif windows:
        ext, kind = ".exe", "exe"
    else:
        ext, kind = "",     "elf"

    out = out_dir / f"{Path(stage['_out_src']).stem}{ext}"

    spec = BuildSpec(
        name=stage["module_id"],
        src_path=src,
        out_path=out,
        compiler=compiler,
        extra_libs=list(stage.get("extra_libs", [])),
        is_dll=is_dll,
        # Pipeline stages don't carry secrets and the cred-sub layer is for the
        # build form; keep it off here for predictability + speed.
        apply_creds=False,
        timeout=45,
    )
    r = build(spec)
    return (r.out_path if r.ok else None), kind, r.log


def agent_build_stages(stages: list[dict], session_id: str,
                       compile_each: bool = False,
                       detection: dict | None = None) -> tuple[list[Path], dict]:
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
            s["_out_src"]      = dst.name
            s["_out_src_size"] = dst.stat().st_size
            produced.append(dst)
        except Exception:
            continue

        if compile_each:
            bin_path, kind, log = _compile_one(s, out_dir)
            if bin_path is not None:
                produced.append(bin_path)
                s["_out_bin"]      = bin_path.name
                s["_out_bin_kind"] = kind   # exe | dll | elf
                s["_out_bin_size"] = bin_path.stat().st_size
            else:
                s["_compile_error"] = (log or "compile failed").splitlines()[-1][:200]

    # Close the loop: a blind-spot TTP (no Sigma coverage) that produced a binary
    # gets a starter YARA rule auto-generated from that binary, so the gap ships
    # with a detection instead of just a warning. Source-only stages get a hint.
    generated_yara: list[dict] = []
    for s in stages:
        det = s.get("detection") or {}
        if det.get("covered"):
            continue
        binf = s.get("_out_bin")
        if not binf:
            det["yara_hint"] = "compile this stage (compile_each) to auto-generate a YARA rule"
            continue
        try:
            from yaragen import generate_rule
            res = generate_rule(out_dir / binf)
            if res.get("ok"):
                yname = f"hunt_{_safe(s['ttp_id'])}_stage{s['stage_num']:02d}.yar"
                (out_dir / yname).write_text(res["rule"])
                det["yara_file"] = yname
                s["_out_yara"]   = yname
                produced.append(out_dir / yname)
                generated_yara.append({
                    "stage_num": s["stage_num"], "ttp_id": s["ttp_id"], "file": yname,
                })
        except Exception:
            continue
    if detection is not None:
        detection["generated_yara"] = generated_yara

    manifest = {
        "session_id":  session_id,
        "built_at":    datetime.now().isoformat(),
        "kill_chain":  _KILL_CHAIN_ORDER,
        "compile_each": compile_each,
        "detection":   detection or {},
        "stages":      stages,
        # quick rollups so the UI can render counts without re-scanning stages
        "counts":      {
            "source": sum(1 for s in stages if s.get("_out_src")),
            "binary": sum(1 for s in stages if s.get("_out_bin")),
            "failed": sum(1 for s in stages if s.get("_compile_error")),
        },
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


# --- Agent 6: detection overlay (purple-team view, no LLM) --------------------

def agent_detection_overlay(stages: list[dict]) -> dict:
    """Cross-reference each kill-chain stage against the Artifact Map so the
    session doubles as a blue-team hunt sheet: for every simulated TTP, what a
    defender should expect to see (Sigma rules, Windows EventIDs, registry keys,
    processes, command-line indicators).

    Pure DB lookup - no LLM, no network. Mutates each stage in place, adding a
    `detection` block, and returns a session-level rollup. TTPs with no Sigma
    coverage are surfaced as `gaps` - the blind spots defenders care about most.
    """
    covered_rules: set[str] = set()
    event_ids:     set[str] = set()
    gaps:          list[dict] = []

    for s in stages:
        aid   = s["ttp_id"]
        entry = _db.get_artifact_entry(aid) or _db.get_artifact_entry(aid.split(".")[0])
        rules = (entry or {}).get("rules", [])
        eids  = (entry or {}).get("event_ids", [])
        count = (entry or {}).get("rule_count", len(rules))
        covered = bool(rules) or count > 0

        s["detection"] = {
            "sigma_count": count,
            "event_ids":   [str(e) for e in eids][:12],
            "reg_keys":    (entry or {}).get("reg_keys", [])[:8],
            "processes":   (entry or {}).get("processes", [])[:8],
            "cmdlines":    (entry or {}).get("cmdlines", [])[:6],
            "sigma_rules": [
                {"title": r.get("title", ""), "level": r.get("level", "")}
                if isinstance(r, dict) else {"title": str(r), "level": ""}
                for r in rules[:8]
            ],
            "covered":     covered,
        }

        for r in rules:
            title = r.get("title") if isinstance(r, dict) else str(r)
            if title:
                covered_rules.add(title)
        for e in eids:
            event_ids.add(str(e))
        if not covered:
            gaps.append({
                "ttp_id":   aid,
                "ttp_name": s.get("ttp_name", aid),
                "tactic":   s.get("tactic", "unknown"),
            })

    total   = len(stages)
    covered = sum(1 for s in stages if s.get("detection", {}).get("covered"))
    return {
        "stages_total":     total,
        "stages_covered":   covered,
        "coverage_pct":     round(100 * covered / total) if total else 0,
        "unique_sigma":     len(covered_rules),
        "unique_event_ids": sorted(event_ids, key=lambda x: (len(x), x)),
        "gaps":             gaps,
    }


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
    compile_each = _truthy(pipeline_cfg.get("compile_each", False))
    use_ollama   = _truthy(pipeline_cfg.get("ollama_narration", False))
    ollama_url   = pipeline_cfg.get("ollama_base_url") or "http://localhost:11434"
    ollama_model = pipeline_cfg.get("ollama_model")    or "qwen3:0.6b"

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

    precomputed_ttps = _precomputed_report_ttps(actor_data)
    precomputed_sources: list[dict] = []
    if precomputed_ttps:
        actor_data["_precomputed_report_ttps"] = precomputed_ttps
        precomputed_sources = _precomputed_report_sources(actor_data)
        report_contents: list[str] = []
        yield {"step": 2, "status": "done",
               "msg": f"using {len(precomputed_ttps)} precomputed report TTP(s) from local DB",
               "data": {"count": len(precomputed_sources),
                        "source": "precomputed-reports",
                        "report_sources": precomputed_sources}}
    else:
        # 2. Download reports (fallback only; demo path should be precomputed)
        yield {"step": 2, "status": "running", "msg": "downloading threat reports…"}
        report_contents = []
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
               "data": {"count": len(report_contents), "source": "live-download"}}

    # 3. Extract TTPs (precomputed DB first, local regex fallback)
    source_msg = "precomputed report TTPs" if precomputed_ttps else "regex, local"
    yield {"step": 3, "status": "running", "msg": f"extracting TTPs ({source_msg})…"}
    ttps = agent_extract_ttps(report_contents, actor_data)
    _db.update_pipeline_session(session_id, ttps=ttps)
    yield {"step": 3, "status": "done",
           "msg": f"{len(ttps)} TTP(s) extracted", "data": ttps}

    # 4. Select per-TTP modules
    yield {"step": 4, "status": "running", "msg": "mapping each TTP to a KB module…"}
    sel = agent_select_modules(ttps)
    stages = sel["stages"]

    # Detection overlay: turn the attack chain into a blue-team hunt sheet.
    # Mutates stages in place (adds per-stage `detection`) and returns a rollup.
    detection = agent_detection_overlay(stages)
    sel["detection"] = detection
    if precomputed_sources:
        sel["report_sources"] = precomputed_sources

    _db.update_pipeline_session(session_id, params=sel)
    yield {"step": 4, "status": "done",
           "msg": f"{len(stages)} kill-chain stage(s) mapped "
                  f"- detection coverage {detection['coverage_pct']}% "
                  f"({detection['stages_covered']}/{detection['stages_total']}), "
                  f"{len(detection['gaps'])} blind spot(s)",
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
                                         compile_each=compile_each,
                                         detection=detection)
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
                   "manifest":   manifest["session_id"],
                   "counts":     manifest["counts"],
                   "stages":     stages,
               }}
    else:
        _db.update_pipeline_session(session_id, status="failed", finished=finished)
        yield {"step": 5, "status": "error",
               "msg": "no artefacts written (source paths missing?)"}
        return

    yield {"step": 0, "status": "complete", "msg": "pipeline complete",
           "data": {"session_id": session_id}}


def list_sessions() -> list[dict]:
    return _db.get_pipeline_sessions()
