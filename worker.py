#!/usr/bin/env python3
"""
peekaboo worker - GPU-side KB enrichment
standalone script; writes to dashboard/peekaboo.db

commands:
  scan     scan local _posts/*.markdown -> library_cache.json (no network)
  init     import library_cache.json -> kb_docs           (idempotent)
  embed    compute embedding vectors for new docs         (resumable)
  tag      classify each doc with a constrained tag set   (resumable, LLM)
  refresh  scan? + init + embed pending + tag pending + re-tag stale-source docs
  status   show table row counts + stale count

rebuild knobs:
  embed --rebuild               wipe embeddings for model, then embed all
  tag   --rebuild               wipe tags for model, then tag all
  tag   --rebuild-changed       re-tag docs whose meow source is newer than tagged_at
  refresh --rebuild             wipe both, then init + embed + tag

other flags:
  --watch N     loop every N seconds after first pass (default: off)
  --model M     Ollama model (defaults differ per stage)
  --url URL     Ollama base URL (default: http://localhost:11434)
  --meow-root P local meow repo (default: $MEOW_ROOT, then stored absolute path)

typical workflows:
  # daily: pick up new blog posts / new meow code
  python3 worker.py refresh

  # after editing existing meow code, force re-tag
  python3 worker.py tag --rebuild-changed

  # nuclear: re-do everything from scratch
  python3 worker.py refresh --rebuild
"""
from __future__ import annotations

import argparse
import json
import os
import re as _re
import sys
import time
import urllib.request
from pathlib import Path

# -- path setup so we can import dashboard/db.py without installing the app
_ROOT = Path(__file__).parent

# Load .env so MEOW_ROOT (and any other shared knobs) work without an export.
try:
    from dotenv import load_dotenv
    load_dotenv(_ROOT / ".env")
except Exception:
    pass
sys.path.insert(0, str(_ROOT / "dashboard"))
import db  # noqa: E402  (dashboard/db.py)

_DATA       = _ROOT / "data"
_LIB_CACHE  = _DATA / "library_cache.json"


# --------------------------------------------------------------------------- #
# Ollama helpers                                                               #
# --------------------------------------------------------------------------- #

def _embed_batch(texts: list[str], model: str, base_url: str) -> list[list[float]] | None:
    url     = base_url.rstrip("/") + "/api/embed"
    payload = json.dumps({"model": model, "input": texts}).encode()
    req     = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())["embeddings"]
    except Exception as e:
        print(f"[embed] error: {e}", flush=True)
        return None


def _ollama_has_model(model: str, base_url: str) -> tuple[bool, list[str]]:
    """Return (ok, names). Match is exact on the user-supplied model:tag.
    A bare 'name' (no :tag) is accepted iff 'name:latest' is present."""
    try:
        req = urllib.request.Request(base_url.rstrip("/") + "/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            names = [m["name"] for m in json.loads(resp.read()).get("models", [])]
    except Exception:
        return False, []
    if model in names:
        return True, names
    if ":" not in model and f"{model}:latest" in names:
        return True, names
    return False, names


# --------------------------------------------------------------------------- #
# Commands                                                                     #
# --------------------------------------------------------------------------- #

def cmd_scan(args: argparse.Namespace) -> None:
    """Re-scan local _posts/*.markdown -> data/library_cache.json (no network).

    Honors $BLOG_POSTS_ROOT and $MEOW_ROOT. CLI flags override env if set.
    """
    if args.posts:
        os.environ["BLOG_POSTS_ROOT"] = args.posts
    if args.meow_root:
        os.environ["MEOW_ROOT"] = args.meow_root

    sys.path.insert(0, str(_ROOT / "dashboard"))
    # Re-import to pick up env overrides (paths are bound at module import time).
    import importlib
    import mitre
    importlib.reload(mitre)

    posts_root = mitre._POSTS
    meow_root  = mitre._MEOW
    print(f"[scan] _posts:    {posts_root}", flush=True)
    print(f"[scan] meow root: {meow_root}",  flush=True)
    if not posts_root.exists():
        print(f"[scan] posts dir not found: {posts_root}", flush=True)
        sys.exit(1)

    entries = mitre.build_library_cache()
    print(f"[scan] wrote {len(entries)} entries to data/library_cache.json", flush=True)


def cmd_init(args: argparse.Namespace) -> None:
    """Import library_cache.json into kb_docs (idempotent upsert)."""
    if not _LIB_CACHE.exists():
        print(f"[init] library_cache not found: {_LIB_CACHE}", flush=True)
        sys.exit(1)

    db.init()

    library: list[dict] = json.loads(_LIB_CACHE.read_text())
    print(f"[init] loading {len(library)} docs from library_cache.json …", flush=True)

    inserted = 0
    for entry in library:
        if not entry.get("slug"):
            continue
        db.upsert_kb_doc({
            "slug":        entry["slug"],
            "title":       entry.get("title", ""),
            "date":        entry.get("date", ""),
            "blog_url":    entry.get("blog_url", ""),
            "category":    entry.get("category", ""),
            "attack_ids":  entry.get("attack_ids", []),
            "src_path":    entry.get("src_path", ""),
            "implemented": entry.get("implemented", False),
        })
        inserted += 1

    stats = db.kb_stats()
    print(f"[init] done - kb_docs: {stats['docs']} rows ({inserted} upserted)", flush=True)


def cmd_embed(args: argparse.Namespace) -> None:
    """Compute nomic-embed-text vectors for unembedded docs. Resumable."""
    model    = args.model
    base_url = args.url
    batch_sz = args.batch

    db.init()

    ok, installed = _ollama_has_model(model, base_url)
    if not ok:
        print(f"[embed] model not available: {model}", flush=True)
        print(f"[embed] installed: {', '.join(installed) or '(none)'}", flush=True)
        print(f"[embed] fix: ollama pull {model}", flush=True)
        sys.exit(1)

    if getattr(args, "rebuild", False):
        n = db.delete_kb_embeddings(model)
        print(f"[embed] --rebuild: wiped {n} embedding rows for model={model}", flush=True)

    def _run_once() -> int:
        pending = db.get_kb_docs_without_embedding(model)
        if not pending:
            print(f"[embed] nothing to do - all docs already embedded with {model}", flush=True)
            return 0

        print(f"[embed] {len(pending)} docs to embed with {model} …", flush=True)
        done = 0

        for i in range(0, len(pending), batch_sz):
            batch = pending[i:i + batch_sz]
            texts = [_post_text(d) for d in batch]

            vecs = _embed_batch(texts, model, base_url)
            if vecs is None:
                print(f"[embed] batch {i//batch_sz + 1} failed - stopping", flush=True)
                break

            for doc, vec in zip(batch, vecs):
                db.upsert_kb_embedding(doc["id"], model, vec)
                done += 1

            pct = min(100, int((i + len(batch)) / len(pending) * 100))
            _progress(pct, f"{done}/{len(pending)}", tag="embed")

        print(f"\n[embed] embedded {done} docs", flush=True)
        return done

    _run_once()

    if args.watch:
        interval = int(args.watch)
        print(f"[embed] --watch {interval}s - polling for new docs …", flush=True)
        while True:
            time.sleep(interval)
            _run_once()


# --------------------------------------------------------------------------- #
# Tag taxonomy (constrained - keeps LLM output deterministic and queryable)    #
# --------------------------------------------------------------------------- #

_TECHNIQUE_TAGS = [
    "injection", "persistence", "evasion", "crypto", "c2",
    "stealer", "anti-analysis", "anti-vm", "anti-debug", "hooking",
    "kernel", "shellcode", "loader", "packer",
    "amsi-bypass", "etw-bypass", "syscalls", "api-hashing",
    "dll-hijacking", "process-hollowing", "reflective-loading",
    "lateral-movement", "privilege-escalation", "exfiltration",
]
_PLATFORM_TAGS = ["windows", "linux", "macos", "cross-platform"]
_LANG_TAGS     = ["c", "cpp", "nim", "rust", "go", "python", "asm", "powershell", "csharp"]


def _build_tag_prompt(doc: dict, code: str) -> str:
    aids = doc.get("attack_ids") or []
    if isinstance(aids, str):
        try:
            aids = json.loads(aids)
        except Exception:
            aids = []
    aids_s = ", ".join(aids) if aids else "(none)"
    code_block = code.strip()[:6000] if code else "(no source code)"

    return f"""You are a malware research classifier. Read this offensive-security blog post and output ONLY a JSON object with three string-array fields: "techniques", "platform", "lang".

Only pick values from these allowed lists. Pick all that apply; pick none if uncertain.

Allowed techniques: {", ".join(_TECHNIQUE_TAGS)}
Allowed platforms: {", ".join(_PLATFORM_TAGS)}
Allowed languages: {", ".join(_LANG_TAGS)}

Post metadata:
- Title: {doc.get("title", "")}
- Category: {doc.get("category", "")}
- ATT&CK: {aids_s}

Source snippet:
{code_block}

Output the JSON object only. No prose, no markdown fences."""


def _chat_json(prompt: str, model: str, base_url: str,
               timeout: int = 300, label: str = "worker") -> tuple[dict | None, str]:
    """Single-turn Ollama chat in JSON mode. Returns (parsed_json, raw_text)."""
    payload = json.dumps({
        "model":      model,
        "stream":     False,
        "format":     "json",
        "think":      False,
        "keep_alive": "10m",
        "options":    {"temperature": 0.0, "num_ctx": 4096},
        "messages":   [{"role": "user", "content": prompt}],
    }).encode()
    url = base_url.rstrip("/") + "/api/chat"
    try:
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        raw  = data.get("message", {}).get("content", "")
    except Exception as e:
        print(f"\n[{label}] chat error: {e}", flush=True)
        return None, ""
    try:
        return json.loads(raw), raw
    except Exception:
        return None, raw


def _normalize_tags(parsed: dict) -> list[str]:
    """Flatten {techniques, platform, lang} into one deduped, allow-listed tag list.
    Tolerates the small-model failure mode of returning a bare string in place of a list."""
    out: list[str] = []
    allow = set(_TECHNIQUE_TAGS) | set(_PLATFORM_TAGS) | set(_LANG_TAGS)
    for key in ("techniques", "platform", "lang"):
        val = parsed.get(key)
        if val is None:
            continue
        items = val if isinstance(val, list) else [val]
        for t in items:
            if isinstance(t, str):
                t = t.strip().lower()
                if t in allow and t not in out:
                    out.append(t)
    return out


def _resolve_src(src_path: str, meow_root: str | None) -> Path | None:
    """Resolve src_path to a real file on this machine.

    1. If the stored absolute path exists, use it.
    2. Otherwise, if MEOW_ROOT is set and the stored path contains `/meow/`,
       rewrite the prefix: <anything>/meow/<tail>  ->  <MEOW_ROOT>/<tail>
    """
    if not src_path:
        return None
    p = Path(src_path)
    if not p.is_absolute():
        p = _ROOT / src_path
    if p.is_file():
        return p
    if meow_root and "/meow/" in src_path:
        tail = src_path.split("/meow/", 1)[1]
        candidate = Path(meow_root).expanduser() / tail
        if candidate.is_file():
            return candidate
    return None


def _read_code(src_path: str, max_lines: int, meow_root: str | None = None) -> str:
    p = _resolve_src(src_path, meow_root)
    if p is None:
        return ""
    try:
        lines = p.read_text(errors="replace").splitlines()
        return "\n".join(lines[:max_lines])
    except Exception:
        return ""


def _stale_doc_ids(model: str, meow_root: str) -> list[int]:
    """Doc IDs whose meow source file mtime > tagged_at for this model."""
    from datetime import datetime
    stale: list[int] = []
    for r in db.get_kb_tagged_docs(model):
        resolved = _resolve_src(r.get("src_path", ""), meow_root)
        if resolved is None:
            continue
        try:
            src_mtime = datetime.fromtimestamp(resolved.stat().st_mtime)
            tagged_at = datetime.fromisoformat(r["tagged_at"])
        except Exception:
            continue
        if src_mtime > tagged_at:
            stale.append(r["id"])
    return stale


# --------------------------------------------------------------------------- #
# KB summaries (precomputed chatbot answers, baked once on GPU)               #
# --------------------------------------------------------------------------- #

def _read_blog_markdown(slug: str, date: str) -> str:
    """Return the blog post body (frontmatter stripped). Located via $BLOG_POSTS_ROOT."""
    root = os.environ.get("BLOG_POSTS_ROOT") or ""
    if not root or not slug:
        return ""
    base = Path(root).expanduser()
    candidates = []
    if date:
        candidates.append(base / f"{date}-{slug}.markdown")
    candidates.extend(base.glob(f"*-{slug}.markdown"))
    p = next((c for c in candidates if c.is_file()), None)
    if not p:
        return ""
    try:
        text = p.read_text(errors="replace")
    except Exception:
        return ""
    m = _re.match(r'^---\s*\n.*?\n---\s*\n', text, _re.S)
    body = text[m.end():] if m else text
    return body.strip()


def _build_summary_prompt(doc: dict, post_body: str, code: str) -> str:
    aids = doc.get("attack_ids") or []
    if isinstance(aids, str):
        try: aids = json.loads(aids)
        except Exception: aids = []
    aids_s = ", ".join(aids) if aids else "(none)"
    post_block = (post_body or "").strip()[:5000] or "(no blog body)"
    code_block = (code or "").strip()[:3000] or "(no source code)"

    return f"""You are writing one short reference card for a malware research blog post. Read BOTH the blog body and the source snippet, then summarize the technique. Output PLAIN TEXT only - no markdown headings, no code fences, no lists, no bullets.

Write exactly 3 sentences, separated by single spaces:
1. What the technique does and why an attacker uses it (offensive mechanism + intent).
2. The key API calls, syscalls, or primitives implementing it (cite real names from the code or post).
3. One detection / telemetry signal (Sysmon event ID, ETW provider, registry key, or process artifact).

Hard limit: 420 characters total. No preamble. No 'In this post' or 'This post explains'. Start with the verb or noun directly. Ground every claim in the post or code below; do not invent facts.

Post:
- Title: {doc.get("title", "")}
- Category: {doc.get("category", "")}
- ATT&CK: {aids_s}

Blog body:
{post_block}

Source snippet:
{code_block}"""


def _normalize_summary(raw: str) -> str:
    if not raw:
        return ""
    s = raw.strip()
    # strip JSON if model wrapped it
    if s.startswith("{") and s.endswith("}"):
        try:
            obj = json.loads(s)
            for k in ("summary", "text", "answer", "response"):
                if isinstance(obj.get(k), str):
                    s = obj[k].strip()
                    break
        except Exception:
            pass
    # drop think blocks if any slipped through
    s = _re.sub(r"<think>.*?</think>", "", s, flags=_re.S).strip()
    # collapse whitespace, keep single spaces
    s = _re.sub(r"\s+", " ", s)
    return s[:600]


def _chat_text(prompt: str, model: str, base_url: str,
               timeout: int = 300, label: str = "worker") -> str:
    """Single-turn Ollama chat in plain-text mode. Returns the message content."""
    payload = json.dumps({
        "model":      model,
        "stream":     False,
        "think":      False,
        "keep_alive": "10m",
        "options":    {"temperature": 0.15, "num_ctx": 4096, "num_predict": 200},
        "messages":   [{"role": "user", "content": prompt}],
    }).encode()
    url = base_url.rstrip("/") + "/api/chat"
    try:
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        return data.get("message", {}).get("content", "")
    except Exception as e:
        print(f"\n[{label}] chat error: {e}", flush=True)
        return ""


def _stale_summary_doc_ids(model: str, meow_root: str) -> list[int]:
    from datetime import datetime
    stale: list[int] = []
    for r in db.get_kb_summarized_docs(model):
        resolved = _resolve_src(r.get("src_path", ""), meow_root)
        if resolved is None:
            continue
        try:
            src_mtime     = datetime.fromtimestamp(resolved.stat().st_mtime)
            summarized_at = datetime.fromisoformat(r["summarized_at"])
        except Exception:
            continue
        if src_mtime > summarized_at:
            stale.append(r["id"])
    return stale


def cmd_summarize(args: argparse.Namespace) -> None:
    """Precompute a 3-sentence summary per doc via LLM. CPU just renders these later."""
    model     = args.model
    base_url  = args.url
    max_lines = args.code_lines
    timeout   = args.timeout
    meow_root = args.meow_root or os.environ.get("MEOW_ROOT") or ""

    if getattr(args, "posts", None):
        os.environ["BLOG_POSTS_ROOT"] = args.posts
    posts_root = os.environ.get("BLOG_POSTS_ROOT") or ""

    if meow_root:
        print(f"[sum] meow_root: {meow_root}", flush=True)
    if posts_root:
        print(f"[sum] posts:     {posts_root}", flush=True)
    else:
        print("[sum] posts:     (none - summaries will fall back to code-only)", flush=True)

    db.init()

    ok, installed = _ollama_has_model(model, base_url)
    if not ok:
        print(f"[sum] model not available: {model}", flush=True)
        print(f"[sum] installed: {', '.join(installed) or '(none)'}", flush=True)
        print(f"[sum] fix: ollama pull {model}", flush=True)
        sys.exit(1)

    if getattr(args, "rebuild", False):
        n = db.delete_kb_summaries(model)
        print(f"[sum] --rebuild: wiped {n} summary rows for model={model}", flush=True)
    elif getattr(args, "rebuild_changed", False):
        stale = _stale_summary_doc_ids(model, meow_root)
        if stale:
            n = db.delete_kb_summaries(model, doc_ids=stale)
            print(f"[sum] --rebuild-changed: wiped {n} stale summary rows", flush=True)
        else:
            print("[sum] --rebuild-changed: nothing stale", flush=True)

    def _run_once() -> int:
        pending = db.get_kb_docs_without_summary(model)
        if not pending:
            print(f"[sum] nothing to do - all docs already summarized with {model}", flush=True)
            return 0

        print(f"[sum] {len(pending)} docs to summarize with {model} …", flush=True)
        done = failed = 0

        for i, doc in enumerate(pending, 1):
            code      = _read_code(doc.get("src_path", ""), max_lines, meow_root)
            post_body = _read_blog_markdown(doc.get("slug", ""), doc.get("date", ""))
            prompt    = _build_summary_prompt(doc, post_body, code)
            raw       = _chat_text(prompt, model, base_url, timeout=timeout, label="sum")
            summary   = _normalize_summary(raw)
            if not summary:
                failed += 1
            db.upsert_kb_summary(doc["id"], model, summary, raw)
            done += 1

            pct    = int(i / len(pending) * 100)
            srcs   = "+".join(s for s in (["blog"] if post_body else []) + (["code"] if code else []))
            label  = f"{i}/{len(pending)} - {doc['slug'][:28]:28s} [{srcs or '-'}] -> {len(summary)}ch"
            _progress(pct, label, tag="sum")

        print(f"\n[sum] summarized {done} docs ({failed} empty)", flush=True)
        return done

    _run_once()

    if args.watch:
        interval = int(args.watch)
        print(f"[sum] --watch {interval}s - polling for new docs …", flush=True)
        while True:
            time.sleep(interval)
            _run_once()


# --------------------------------------------------------------------------- #
# TTP extraction (ATT&CK ID mapping via LLM)                                  #
# --------------------------------------------------------------------------- #

_ATTACK_TACTICS = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

_ATTACK_ID_RE = _re.compile(r'^T\d{4}(\.\d{3})?$')


def _normalize_ttps(parsed: dict) -> tuple[list[str], list[str], str, str]:
    """Validate and sanitize LLM JSON output.
    Returns (attack_ids, tactics, confidence, rationale)."""
    raw_ids = parsed.get("attack_ids", [])
    if isinstance(raw_ids, str):
        raw_ids = [raw_ids]
    attack_ids: list[str] = []
    for t in raw_ids[:5]:
        if isinstance(t, str):
            t = t.strip().upper()
            if _ATTACK_ID_RE.match(t) and t not in attack_ids:
                attack_ids.append(t)

    raw_tactics = parsed.get("tactics", [])
    if isinstance(raw_tactics, str):
        raw_tactics = [raw_tactics]
    allow = set(_ATTACK_TACTICS)
    tactics: list[str] = []
    for t in raw_tactics:
        if isinstance(t, str):
            t = t.strip().lower()
            if t in allow and t not in tactics:
                tactics.append(t)

    confidence = (parsed.get("confidence") or "low").strip().lower()
    if confidence not in ("high", "medium", "low"):
        confidence = "low"

    rationale = (parsed.get("rationale") or "").strip()[:200]
    return attack_ids, tactics, confidence, rationale


def _build_ttp_prompt(doc: dict, code: str) -> str:
    aids = doc.get("attack_ids") or []
    if isinstance(aids, str):
        try:
            aids = json.loads(aids)
        except Exception:
            aids = []
    aids_s = ", ".join(aids) if aids else "(none in metadata)"
    code_block = code.strip()[:8000] if code else "(no source code available)"

    return f"""You are a MITRE ATT&CK analyst. Analyze this offensive-security source code and identify the ATT&CK techniques it implements.

Source: {doc.get('slug', '')} ({doc.get('category', '')})
Title: {doc.get('title', '')}
Known ATT&CK from metadata: {aids_s}

--- CODE ---
{code_block}
--- END ---

Return ONLY valid JSON (no markdown fences, no commentary):
{{
  "attack_ids": [...],
  "tactics":    [...],
  "confidence": "...",
  "rationale":  "..."
}}

Rules:
- attack_ids: up to 5 IDs in format "T1234" or "T1234.567"; only IDs you are confident about
- tactics: ATT&CK tactic slugs from this list only: {", ".join(_ATTACK_TACTICS)}
- confidence: exactly one of "high", "medium", or "low"
- rationale: one sentence (≤120 chars) naming the dominant API calls or code patterns
- If the file is a utility/helper with no clear ATT&CK mapping, return empty arrays and "low"
- Do not invent IDs. Prefer fewer high-confidence IDs over many guesses."""


def _stale_ttp_doc_ids(model: str, meow_root: str) -> list[int]:
    """Doc IDs whose meow source file mtime > extracted_at for this model."""
    from datetime import datetime
    stale: list[int] = []
    for r in db.get_kb_ttp_extracted_docs(model):
        resolved = _resolve_src(r.get("src_path", ""), meow_root)
        if resolved is None:
            continue
        try:
            src_mtime    = datetime.fromtimestamp(resolved.stat().st_mtime)
            extracted_at = datetime.fromisoformat(r["extracted_at"])
        except Exception:
            continue
        if src_mtime > extracted_at:
            stale.append(r["id"])
    return stale


def cmd_ttp(args: argparse.Namespace) -> None:
    """Extract MITRE ATT&CK TTPs from source code via LLM. Resumable."""
    model     = args.model
    base_url  = args.url
    max_lines = args.code_lines
    timeout   = args.timeout
    meow_root = args.meow_root or os.environ.get("MEOW_ROOT") or ""

    if meow_root:
        print(f"[ttp] meow_root: {meow_root}", flush=True)

    db.init()

    ok, installed = _ollama_has_model(model, base_url)
    if not ok:
        print(f"[ttp] model not available: {model}", flush=True)
        print(f"[ttp] installed: {', '.join(installed) or '(none)'}", flush=True)
        print(f"[ttp] fix: ollama pull {model}", flush=True)
        sys.exit(1)

    if getattr(args, "rebuild", False):
        n = db.delete_ttp_extracted(model)
        print(f"[ttp] --rebuild: wiped {n} ttp rows for model={model}", flush=True)
    elif getattr(args, "rebuild_changed", False):
        stale = _stale_ttp_doc_ids(model, meow_root)
        if stale:
            n = db.delete_ttp_extracted(model, doc_ids=stale)
            print(f"[ttp] --rebuild-changed: wiped {n} stale ttp rows", flush=True)
        else:
            print("[ttp] --rebuild-changed: nothing stale", flush=True)

    def _run_once() -> int:
        pending = db.get_kb_docs_without_ttps(model)
        if not pending:
            print(f"[ttp] nothing to do - all docs already processed with {model}", flush=True)
            return 0

        print(f"[ttp] {len(pending)} docs to extract TTPs from with {model} …", flush=True)
        done   = 0
        failed = 0

        for i, doc in enumerate(pending, 1):
            code   = _read_code(doc.get("src_path", ""), max_lines, meow_root)
            prompt = _build_ttp_prompt(doc, code)
            parsed, raw = _chat_json(prompt, model, base_url, timeout=timeout, label="ttp")

            if parsed is None:
                failed += 1
                attack_ids, tactics, confidence, rationale = [], [], "low", ""
            else:
                attack_ids, tactics, confidence, rationale = _normalize_ttps(parsed)

            db.upsert_ttp_extracted(doc["id"], model, attack_ids, tactics,
                                     confidence, rationale, raw)
            done += 1

            pct     = int(i / len(pending) * 100)
            ids_str = ",".join(attack_ids[:3]) or "(none)"
            label   = f"{i}/{len(pending)} - {doc['slug'][:28]:28s} -> {ids_str} [{confidence}]"
            _progress(pct, label, tag="ttp")

        print(f"\n[ttp] processed {done} docs ({failed} LLM failures)", flush=True)
        return done

    _run_once()

    if args.watch:
        interval = int(args.watch)
        print(f"[ttp] --watch {interval}s - polling for new docs …", flush=True)
        while True:
            time.sleep(interval)
            _run_once()


def cmd_tag(args: argparse.Namespace) -> None:
    """Classify each doc with constrained-JSON tags via local Ollama. Resumable."""
    model     = args.model
    base_url  = args.url
    max_lines = args.code_lines
    timeout   = args.timeout
    meow_root = args.meow_root or os.environ.get("MEOW_ROOT") or ""

    if meow_root:
        print(f"[tag] meow_root: {meow_root}", flush=True)

    db.init()

    ok, installed = _ollama_has_model(model, base_url)
    if not ok:
        print(f"[tag] model not available: {model}", flush=True)
        print(f"[tag] installed: {', '.join(installed) or '(none)'}", flush=True)
        print(f"[tag] fix: ollama pull {model}", flush=True)
        sys.exit(1)

    if getattr(args, "rebuild", False):
        n = db.delete_kb_tags(model)
        print(f"[tag] --rebuild: wiped {n} tag rows for model={model}", flush=True)
    elif getattr(args, "rebuild_changed", False):
        stale = _stale_doc_ids(model, meow_root)
        if stale:
            n = db.delete_kb_tags(model, doc_ids=stale)
            print(f"[tag] --rebuild-changed: wiped {n} stale tag rows", flush=True)
        else:
            print(f"[tag] --rebuild-changed: nothing stale", flush=True)

    def _run_once() -> int:
        pending = db.get_kb_docs_without_tags(model)
        if not pending:
            print(f"[tag] nothing to do - all docs already tagged with {model}", flush=True)
            return 0

        print(f"[tag] {len(pending)} docs to tag with {model} …", flush=True)
        done   = 0
        failed = 0

        for i, doc in enumerate(pending, 1):
            code   = _read_code(doc.get("src_path", ""), max_lines, meow_root)
            prompt = _build_tag_prompt(doc, code)
            parsed, raw = _chat_json(prompt, model, base_url, timeout=timeout, label="tag")

            if parsed is None:
                failed += 1
                tags = []
            else:
                tags = _normalize_tags(parsed)

            db.upsert_kb_tag(doc["id"], model, tags, raw)
            done += 1

            pct = int(i / len(pending) * 100)
            label = f"{i}/{len(pending)} - {doc['slug'][:30]:30s} -> {','.join(tags[:4]) or '(none)'}"
            _progress(pct, label, tag="tag")

        print(f"\n[tag] tagged {done} docs ({failed} failed)", flush=True)
        return done

    _run_once()

    if args.watch:
        interval = int(args.watch)
        print(f"[tag] --watch {interval}s - polling for new docs …", flush=True)
        while True:
            time.sleep(interval)
            _run_once()


def cmd_status(args: argparse.Namespace) -> None:
    db.init()
    s = db.kb_stats()
    meow_root = os.environ.get("MEOW_ROOT") or ""

    print(f"kb_docs        : {s['docs']}")

    import sqlite3
    with sqlite3.connect(db.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        emb_rows = conn.execute(
            "SELECT model, COUNT(*) n FROM kb_embeddings GROUP BY model"
        ).fetchall()
        tag_rows = conn.execute(
            "SELECT model, COUNT(*) n FROM kb_tags GROUP BY model"
        ).fetchall()
        ttp_rows = conn.execute(
            "SELECT model, COUNT(*) n FROM ttp_extracted GROUP BY model"
        ).fetchall()
        sum_rows = conn.execute(
            "SELECT model, COUNT(*) n FROM kb_summaries GROUP BY model"
        ).fetchall()

    # docs with src_path (eligible for ttp extraction)
    with sqlite3.connect(db.DB_PATH) as conn:
        src_docs = conn.execute(
            "SELECT COUNT(*) FROM kb_docs WHERE src_path != ''"
        ).fetchone()[0]

    if not emb_rows:
        print(f"kb_embeddings  : 0  (pending: {s['docs']})")
    for r in emb_rows:
        print(f"kb_embeddings  : {r['n']}  ({r['model']})  pending: {s['docs'] - r['n']}")

    if not tag_rows:
        print(f"kb_tags        : 0  (pending: {s['docs']})")
    for r in tag_rows:
        stale = 0
        if meow_root:
            try:
                stale = len(_stale_doc_ids(r["model"], meow_root))
            except Exception:
                pass
        print(f"kb_tags        : {r['n']}  ({r['model']})  pending: {s['docs'] - r['n']}, stale: {stale}")

    if not ttp_rows:
        print(f"ttp_extracted  : 0  (eligible: {src_docs} docs with src_path)")
    for r in ttp_rows:
        stale = 0
        if meow_root:
            try:
                stale = len(_stale_ttp_doc_ids(r["model"], meow_root))
            except Exception:
                pass
        print(f"ttp_extracted  : {r['n']}  ({r['model']})  pending: {src_docs - r['n']}, stale: {stale}")

    if not sum_rows:
        print(f"kb_summaries   : 0  (pending: {s['docs']})")
    for r in sum_rows:
        stale = 0
        if meow_root:
            try:
                stale = len(_stale_summary_doc_ids(r["model"], meow_root))
            except Exception:
                pass
        print(f"kb_summaries   : {r['n']}  ({r['model']})  pending: {s['docs'] - r['n']}, stale: {stale}")


def cmd_refresh(args: argparse.Namespace) -> None:
    """One-shot incremental update: [scan?] + init + embed pending + tag pending + [ttp?]."""
    if getattr(args, "scan", False):
        print("[refresh] ----- scan -----", flush=True)
        scan_args = argparse.Namespace(posts=None, meow_root=args.meow_root)
        cmd_scan(scan_args)

    print("\n[refresh] ----- init -----", flush=True)
    cmd_init(args)

    print("\n[refresh] ----- embed -----", flush=True)
    embed_args = argparse.Namespace(
        model=args.embed_model, url=args.url, batch=32,
        watch=0, rebuild=args.rebuild,
    )
    cmd_embed(embed_args)

    print("\n[refresh] ----- tag -----", flush=True)
    tag_args = argparse.Namespace(
        model=args.tag_model, url=args.url, code_lines=120,
        timeout=args.timeout, meow_root=args.meow_root,
        watch=0,
        rebuild=args.rebuild,
        rebuild_changed=(not args.rebuild),
    )
    cmd_tag(tag_args)

    if getattr(args, "ttp", False):
        print("\n[refresh] ----- ttp -----", flush=True)
        ttp_args = argparse.Namespace(
            model=args.ttp_model, url=args.url, code_lines=200,
            timeout=args.timeout, meow_root=args.meow_root,
            watch=0,
            rebuild=args.rebuild,
            rebuild_changed=(not args.rebuild),
        )
        cmd_ttp(ttp_args)

    if getattr(args, "summarize", False):
        print("\n[refresh] ----- summarize -----", flush=True)
        sum_args = argparse.Namespace(
            model=args.sum_model, url=args.url, code_lines=180,
            timeout=args.timeout, meow_root=args.meow_root,
            watch=0,
            rebuild=args.rebuild,
            rebuild_changed=(not args.rebuild),
        )
        cmd_summarize(sum_args)

    print("\n[refresh] ----- done -----", flush=True)
    cmd_status(args)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _post_text(doc: dict) -> str:
    """Build the text to embed for a kb_doc row (matches semantic.py logic)."""
    parts = [doc.get("title", ""), doc.get("category", "")]
    aids  = doc.get("attack_ids", [])
    if isinstance(aids, str):
        try:
            aids = json.loads(aids)
        except Exception:
            aids = []
    if aids:
        parts.append("ATT&CK: " + " ".join(aids))
    return " | ".join(p for p in parts if p)


def _progress(pct: int, label: str = "", tag: str = "worker") -> None:
    if sys.stdout.isatty():
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        print(f"\r[{bar}] {pct:3d}%  {label}  ", end="", flush=True)
    else:
        print(f"[{tag}] {pct}% {label}", flush=True)


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

class _StrictParser(argparse.ArgumentParser):
    """ArgumentParser with allow_abbrev=False forced on. Used for subparsers
    so e.g. `--mode` doesn't silently become `--model`."""
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)


def _build_parser() -> argparse.ArgumentParser:
    p = _StrictParser(
        prog="worker.py",
        description="peekaboo KB enrichment worker",
    )
    sub = p.add_subparsers(dest="cmd", required=True, parser_class=_StrictParser)

    sc = sub.add_parser("scan", help="scan local _posts/*.markdown -> library_cache.json")
    sc.add_argument("--posts",     default=None,
                    help="path to _posts/ (default: $BLOG_POSTS_ROOT)")
    sc.add_argument("--meow-root", default=None, dest="meow_root",
                    help="local meow repo path (default: $MEOW_ROOT)")

    sub.add_parser("init",   help="import library_cache.json -> kb_docs")
    sub.add_parser("status", help="show row counts")

    ep = sub.add_parser("embed", help="compute embedding vectors for new docs")
    ep.add_argument("--model",   default="nomic-embed-text",       help="Ollama model")
    ep.add_argument("--url",     default="http://localhost:11434", help="Ollama base URL")
    ep.add_argument("--batch",   type=int, default=32,             help="docs per call")
    ep.add_argument("--watch",   type=int, default=0, metavar="N",
                    help="loop every N seconds (0 = run once)")
    ep.add_argument("--rebuild", action="store_true",
                    help="wipe all embeddings for this model first, then embed all")

    tp = sub.add_parser("tag", help="classify docs with constrained-JSON tags (LLM)")
    tp.add_argument("--model",      default="qwen3:1.7b",              help="Ollama chat model")
    tp.add_argument("--url",        default="http://localhost:11434",  help="Ollama base URL")
    tp.add_argument("--code-lines", type=int, default=120, dest="code_lines",
                    help="max src lines fed to the LLM")
    tp.add_argument("--timeout",    type=int, default=300,             help="per-call timeout (s)")
    tp.add_argument("--meow-root",  default=None, dest="meow_root",
                    help="local meow repo path (default: $MEOW_ROOT, then stored absolute path)")
    tp.add_argument("--watch",      type=int, default=0, metavar="N",
                    help="loop every N seconds (0 = run once)")
    tp.add_argument("--rebuild",    action="store_true",
                    help="wipe all tags for this model first, then tag all")
    tp.add_argument("--rebuild-changed", action="store_true", dest="rebuild_changed",
                    help="re-tag docs whose meow source is newer than tagged_at")

    xp = sub.add_parser("ttp", help="extract MITRE ATT&CK TTPs from source code (LLM)")
    xp.add_argument("--model",           default="qwen3:14b",              help="Ollama chat model")
    xp.add_argument("--url",             default="http://localhost:11434", help="Ollama base URL")
    xp.add_argument("--code-lines",      type=int, default=200, dest="code_lines",
                    help="max src lines fed to the LLM")
    xp.add_argument("--timeout",         type=int, default=120,            help="per-call timeout (s)")
    xp.add_argument("--meow-root",       default=None, dest="meow_root",
                    help="local meow repo path (default: $MEOW_ROOT)")
    xp.add_argument("--watch",           type=int, default=0, metavar="N",
                    help="loop every N seconds (0 = run once)")
    xp.add_argument("--rebuild",         action="store_true",
                    help="wipe all ttp_extracted for this model first, then process all")
    xp.add_argument("--rebuild-changed", action="store_true", dest="rebuild_changed",
                    help="re-extract docs whose meow source is newer than extracted_at")

    sp = sub.add_parser("summarize", help="precompute one 3-sentence summary per doc (LLM)")
    sp.add_argument("--model",           default="qwen3:14b",              help="Ollama chat model")
    sp.add_argument("--url",             default="http://localhost:11434", help="Ollama base URL")
    sp.add_argument("--code-lines",      type=int, default=180, dest="code_lines",
                    help="max src lines fed to the LLM")
    sp.add_argument("--timeout",         type=int, default=120,            help="per-call timeout (s)")
    sp.add_argument("--meow-root",       default=None, dest="meow_root",
                    help="local meow repo path (default: $MEOW_ROOT)")
    sp.add_argument("--posts",           default=None, dest="posts",
                    help="path to _posts/ for blog body reads (default: $BLOG_POSTS_ROOT)")
    sp.add_argument("--watch",           type=int, default=0, metavar="N",
                    help="loop every N seconds (0 = run once)")
    sp.add_argument("--rebuild",         action="store_true",
                    help="wipe all summaries for this model first, then process all")
    sp.add_argument("--rebuild-changed", action="store_true", dest="rebuild_changed",
                    help="re-summarize docs whose meow source is newer than summarized_at")

    rp = sub.add_parser("refresh", help="one-shot incremental update (scan? + init + embed + tag + ttp? + summarize?)")
    rp.add_argument("--embed-model", default="nomic-embed-text", dest="embed_model")
    rp.add_argument("--tag-model",   default="qwen3:1.7b",       dest="tag_model")
    rp.add_argument("--ttp-model",   default="qwen3:14b",        dest="ttp_model")
    rp.add_argument("--sum-model",   default="qwen3:14b",        dest="sum_model")
    rp.add_argument("--url",         default="http://localhost:11434")
    rp.add_argument("--timeout",     type=int, default=300)
    rp.add_argument("--meow-root",   default=None, dest="meow_root")
    rp.add_argument("--scan",        action="store_true",
                    help="re-scan local _posts before init (catches new/edited blog files)")
    rp.add_argument("--rebuild",     action="store_true",
                    help="wipe embeddings + tags first, then full re-do")
    rp.add_argument("--ttp",         action="store_true",
                    help="also run TTP extraction after tagging (uses --ttp-model)")
    rp.add_argument("--summarize",   action="store_true",
                    help="also run summary precompute after tagging (uses --sum-model)")

    return p


if __name__ == "__main__":
    parser = _build_parser()
    args   = parser.parse_args()

    if args.cmd == "scan":
        cmd_scan(args)
    elif args.cmd == "init":
        cmd_init(args)
    elif args.cmd == "embed":
        cmd_embed(args)
    elif args.cmd == "tag":
        cmd_tag(args)
    elif args.cmd == "ttp":
        cmd_ttp(args)
    elif args.cmd == "summarize":
        cmd_summarize(args)
    elif args.cmd == "refresh":
        cmd_refresh(args)
    elif args.cmd == "status":
        cmd_status(args)
