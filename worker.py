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

    try:
        entries = mitre.build_library_cache()
    except KeyboardInterrupt:
        print("\n[scan] interrupted - no data written", flush=True)
        print("[scan] resume: python3 worker.py scan", flush=True)
        return
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
    try:
        for i, entry in enumerate(library, 1):
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
    except KeyboardInterrupt:
        remaining = len(library) - i
        print(f"\n[init] interrupted at {i}/{len(library)}  ({inserted} upserted, {remaining} remaining)", flush=True)
        print("[init] resume: python3 worker.py init", flush=True)
        return

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

        try:
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
        except KeyboardInterrupt:
            remaining = len(pending) - done
            print(f"\n[embed] interrupted after {done}/{len(pending)} docs  ({remaining} remaining)", flush=True)
            print(f"[embed] resume: python3 worker.py embed --model {model}", flush=True)
            return done

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

        try:
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
        except KeyboardInterrupt:
            remaining = len(pending) - i
            print(f"\n[sum] interrupted at {i}/{len(pending)}  ({done} saved, {remaining} remaining)", flush=True)
            print(f"[sum] resume: python3 worker.py summarize --model {model}", flush=True)
            return done

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

        try:
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
        except KeyboardInterrupt:
            remaining = len(pending) - i
            print(f"\n[ttp] interrupted at {i}/{len(pending)}  ({done} saved, {remaining} remaining)", flush=True)
            print(f"[ttp] resume: python3 worker.py ttp --model {model}", flush=True)
            return done

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

        try:
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
        except KeyboardInterrupt:
            remaining = len(pending) - i
            print(f"\n[tag] interrupted at {i}/{len(pending)}  ({done} saved, {remaining} remaining)", flush=True)
            print(f"[tag] resume: python3 worker.py tag --model {model}", flush=True)
            return done

        print(f"\n[tag] tagged {done} docs ({failed} failed)", flush=True)
        return done

    _run_once()

    if args.watch:
        interval = int(args.watch)
        print(f"[tag] --watch {interval}s - polling for new docs …", flush=True)
        while True:
            time.sleep(interval)
            _run_once()


def _build_sigma_prompt(entry: dict) -> str:
    tid       = entry.get("tid", "")
    name      = entry.get("name", tid)
    tactic    = entry.get("tactic", "")
    rules     = entry.get("rule_count", 0)
    event_ids = entry.get("event_ids", [])[:10]
    reg_keys  = entry.get("reg_keys",  [])[:6]
    processes = entry.get("processes", [])[:6]
    cmdlines  = entry.get("cmdlines",  [])[:4]

    parts = [
        f"ATT&CK Technique: {tid} - {name}",
        f"Tactic: {tactic}",
        f"Covered by {rules} Sigma detection rules.",
    ]
    if event_ids:
        parts.append("Key Windows event IDs: " + ", ".join(str(e) for e in event_ids))
    if processes:
        imgs = [p.split("\\")[-1] for p in processes]
        parts.append("Suspicious processes: " + ", ".join(imgs))
    if reg_keys:
        parts.append("Registry keys: " + "; ".join(reg_keys[:3]))
    if cmdlines:
        parts.append("Command-line patterns: " + "; ".join(cmdlines[:2]))

    context = "\n".join(parts)
    return (
        f"You are a threat detection expert.\n"
        f"Write exactly 3 plain sentences about this ATT&CK technique from a Blue Team / detection perspective.\n"
        f"Sentence 1: what the adversary does with this technique.\n"
        f"Sentence 2: the most reliable telemetry artifacts to detect it (event IDs, registry keys, or process names).\n"
        f"Sentence 3: one concise detection recommendation.\n"
        f"No markdown, no lists, no headers. Hard limit: 420 characters total.\n\n"
        f"{context}"
    )


def cmd_sigma(args: argparse.Namespace) -> None:
    """Parse Sigma rules and/or precompute detection briefs per ATT&CK technique."""
    model      = args.model
    base_url   = args.url
    timeout    = args.timeout
    sigma_path = getattr(args, "sigma_path", None)
    parse_only = getattr(args, "parse_only", False)

    db.init()

    # -- Step 1: parse sigma rules if --sigma-path given ---------------------
    if sigma_path:
        sigma_dir = Path(sigma_path).expanduser()
        if not sigma_dir.exists():
            print(f"[sigma] path not found: {sigma_dir}", flush=True)
            sys.exit(1)
        try:
            import sys as _sys
            _sys.path.insert(0, str(Path(__file__).parent / "dashboard"))
            from artifact_parser import build_artifact_map, HAS_YAML
        except ImportError:
            print("[sigma] artifact_parser not available (pyyaml installed?)", flush=True)
            sys.exit(1)
        if not HAS_YAML:
            print("[sigma] pyyaml not installed - run: pip install pyyaml", flush=True)
            sys.exit(1)

        print(f"[sigma] parsing {sigma_dir} …", flush=True)
        parsed = 0

        def _prog(current: int, total: int, filename: str) -> None:
            nonlocal parsed
            parsed = current
            if current % 500 == 0 and current:
                print(f"[sigma]   {current}/{total} rules parsed", flush=True)

        entries = build_artifact_map(sigma_dir, _prog)
        db.save_artifact_entries(entries)
        print(f"[sigma] stored {len(entries)} techniques from {parsed} rules", flush=True)

        if parse_only:
            return

    # -- Step 2: LLM summarization --------------------------------------------
    total = db.count_artifact_entries()
    if total == 0:
        print("[sigma] artifact map is empty - add --sigma-path to parse rules first", flush=True)
        print("[sigma]   example: python worker.py sigma --sigma-path ~/hacking/sigma", flush=True)
        return

    ok, installed = _ollama_has_model(model, base_url)
    if not ok:
        print(f"[sigma] model not available: {model}", flush=True)
        print(f"[sigma] installed: {', '.join(installed) or '(none)'}", flush=True)
        print(f"[sigma] fix: ollama pull {model}", flush=True)
        sys.exit(1)

    if getattr(args, "rebuild", False):
        import sqlite3
        with sqlite3.connect(db.DB_PATH) as conn:
            n = conn.execute(
                "DELETE FROM artifact_summaries WHERE model=?", (model,)
            ).rowcount
        print(f"[sigma] --rebuild: wiped {n} summary rows for model={model}", flush=True)

    pending_tids = db.get_artifact_tids_without_summary(model)
    if not pending_tids:
        print(f"[sigma] all {total} techniques already have briefs for {model}", flush=True)
        return

    print(f"[sigma] {len(pending_tids)}/{total} techniques to brief with {model} …", flush=True)
    done = failed = 0

    try:
        for i, tid in enumerate(pending_tids, 1):
            entry = db.get_artifact_entry(tid)
            if not entry:
                continue
            prompt = _build_sigma_prompt(entry)
            raw = _chat_text(prompt, model, base_url, timeout, label="sigma")
            if raw is None:
                failed += 1
                print(f"[sigma] {i}/{len(pending_tids)} FAIL  {tid}", flush=True)
                continue
            summary = _normalize_summary(raw)
            db.upsert_artifact_summary(tid, model, summary, raw)
            done += 1
            print(f"[sigma] {i}/{len(pending_tids)} ok    {tid}  ({entry.get('name','')})", flush=True)
    except KeyboardInterrupt:
        remaining = len(pending_tids) - i
        print(f"\n[sigma] interrupted at {i}/{len(pending_tids)}  ({done} saved, {remaining} remaining)", flush=True)
        print(f"[sigma] resume: python3 worker.py sigma --model {model}", flush=True)
        return

    print(f"[sigma] done: {done} ok, {failed} failed", flush=True)


def _build_apt_prompt(sess: dict) -> str:
    actor   = sess.get("actor_id", "unknown")
    ttps    = sess.get("ttps", [])
    params  = sess.get("params", {})
    started = (sess.get("started") or "")[:10]

    tids    = [t.get("id") or t if isinstance(t, str) else "" for t in ttps][:15]
    names   = [t.get("name", "") for t in ttps if isinstance(t, dict)][:10]
    tactics = list({t.get("tactic", "") for t in ttps if isinstance(t, dict) and t.get("tactic")})[:6]

    mods  = [m.get("title", m.get("module_id", "")) for m in params.get("selected_modules", []) if m][:8]
    enc   = params.get("encryption", "")
    inj   = params.get("injection", "")
    mal   = params.get("malware", "")

    parts = [f"APT Actor: {actor}", f"Campaign date: {started}"]
    if tids:
        parts.append("ATT&CK techniques: " + ", ".join(t for t in tids if t))
    if tactics:
        parts.append("Tactics covered: " + ", ".join(tactics))
    if names:
        parts.append("Key technique names: " + "; ".join(n for n in names if n)[:200])
    if mods:
        parts.append("Implant modules: " + ", ".join(mods))
    if enc:
        parts.append(f"Encryption: {enc}")
    if inj:
        parts.append(f"Injection: {inj}")
    if mal:
        parts.append(f"Malware family: {mal}")

    context = "\n".join(parts)
    return (
        "You are a threat intelligence analyst.\n"
        "Write exactly 3 plain sentences summarizing this APT simulation campaign.\n"
        "Sentence 1: who the actor is and what they targeted.\n"
        "Sentence 2: the key MITRE ATT&CK techniques and tactics used.\n"
        "Sentence 3: the highest-priority detection recommendation for defenders.\n"
        "No markdown, no lists, no headers. Hard limit: 420 characters total.\n\n"
        f"{context}"
    )


def cmd_apt(args: argparse.Namespace) -> None:
    """Precompute campaign briefs for finished APT pipeline sessions."""
    model    = args.model
    base_url = args.url
    timeout  = args.timeout

    db.init()

    if getattr(args, "rebuild", False):
        import sqlite3
        with sqlite3.connect(db.DB_PATH) as conn:
            n = conn.execute(
                "DELETE FROM session_summaries WHERE model=?", (model,)
            ).rowcount
        print(f"[apt] --rebuild: wiped {n} summary rows for model={model}", flush=True)

    pending = db.get_sessions_without_summary(model)
    if not pending:
        import sqlite3
        with sqlite3.connect(db.DB_PATH) as conn:
            n_finished = conn.execute(
                "SELECT COUNT(*) FROM pipeline_sessions WHERE status='success'"
            ).fetchone()[0]
        if n_finished == 0:
            print("[apt] no finished pipeline sessions found", flush=True)
            print("[apt] run the APT Campaign pipeline in the dashboard to create sessions", flush=True)
        else:
            briefs = db.count_session_summaries(model)
            print(f"[apt] all {n_finished} finished session(s) already have briefs for {model} ({briefs} total)", flush=True)
        return

    ok, installed = _ollama_has_model(model, base_url)
    if not ok:
        print(f"[apt] model not available: {model}", flush=True)
        print(f"[apt] installed: {', '.join(installed) or '(none)'}", flush=True)
        print(f"[apt] fix: ollama pull {model}", flush=True)
        sys.exit(1)

    print(f"[apt] {len(pending)} session(s) to brief with {model} …", flush=True)
    done = failed = 0

    try:
        for i, sess in enumerate(pending, 1):
            sid    = sess["session_id"]
            actor  = sess.get("actor_id", "?")
            prompt = _build_apt_prompt(sess)
            raw    = _chat_text(prompt, model, base_url, timeout, label="apt")
            if raw is None:
                failed += 1
                print(f"[apt] {i}/{len(pending)} FAIL  {sid} ({actor})", flush=True)
                continue
            summary = _normalize_summary(raw)
            db.upsert_session_summary(sid, model, summary, raw)
            done += 1
            print(f"[apt] {i}/{len(pending)} ok    {sid}  ({actor})", flush=True)
    except KeyboardInterrupt:
        remaining = len(pending) - i
        print(f"\n[apt] interrupted at {i}/{len(pending)}  ({done} saved, {remaining} remaining)", flush=True)
        print(f"[apt] resume: python3 worker.py apt --model {model}", flush=True)
        return

    print(f"[apt] done: {done} ok, {failed} failed", flush=True)


def _build_actor_prompt(actor: dict) -> str:
    name       = actor.get("name") or actor.get("id", "unknown")
    country    = actor.get("country", "")
    desc       = (actor.get("description") or "")[:600]
    targets    = actor.get("targets", [])[:5]
    victims    = actor.get("victims", [])[:5]
    synonyms   = actor.get("synonyms", [])[:4]
    families   = [f.get("id", "") if isinstance(f, dict) else str(f) for f in actor.get("families", [])][:6]
    inc_type   = actor.get("incident_type", "")

    parts = [f"Threat Actor: {name}"]
    if country:
        parts.append(f"Suspected origin: {country}")
    if synonyms:
        parts.append("Also known as: " + ", ".join(synonyms))
    if targets:
        parts.append("Target sectors: " + ", ".join(targets))
    if victims:
        parts.append("Known victims: " + ", ".join(victims))
    if inc_type:
        parts.append(f"Incident type: {inc_type}")
    if families:
        parts.append("Associated malware families: " + ", ".join(families))
    if desc:
        parts.append("Description: " + desc)

    context = "\n".join(parts)
    return (
        "You are a threat intelligence analyst.\n"
        "Write exactly 3 plain sentences profiling this threat actor.\n"
        "Sentence 1: who the actor is, suspected origin, and motivation.\n"
        "Sentence 2: typical targets and known malware families used.\n"
        "Sentence 3: one behavioral signature defenders should hunt for.\n"
        "No markdown, no lists, no headers. Hard limit: 420 characters total.\n\n"
        f"{context}"
    )


def cmd_actor(args: argparse.Namespace) -> None:
    """Precompute threat profile briefs for Malpedia actors."""
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent / "dashboard"))

    model    = args.model
    base_url = args.url
    timeout  = args.timeout

    db.init()

    try:
        import malpedia as _malp
    except ImportError:
        print("[actor] malpedia module not available", flush=True)
        sys.exit(1)

    if not _malp.available():
        print("[actor] malpediaclient not installed (pip install malpediaclient)", flush=True)
        sys.exit(1)

    if getattr(args, "rebuild", False):
        import sqlite3
        with sqlite3.connect(db.DB_PATH) as conn:
            n = conn.execute(
                "DELETE FROM actor_summaries WHERE model=?", (model,)
            ).rowcount
        print(f"[actor] --rebuild: wiped {n} summary rows for model={model}", flush=True)

    print("[actor] fetching actor list …", flush=True)
    actor_ids = _malp.list_actors()
    if not actor_ids:
        print("[actor] no actors found (check malpedia_config.api_token)", flush=True)
        return

    pending = db.get_actor_ids_without_summary(actor_ids, model)
    if not pending:
        print(f"[actor] all {len(actor_ids)} actors already have briefs for {model}", flush=True)
        return

    ok, installed = _ollama_has_model(model, base_url)
    if not ok:
        print(f"[actor] model not available: {model}", flush=True)
        print(f"[actor] fix: ollama pull {model}", flush=True)
        sys.exit(1)

    print(f"[actor] {len(pending)}/{len(actor_ids)} actors to brief with {model} …", flush=True)
    done = failed = 0

    try:
        for i, actor_id in enumerate(pending, 1):
            actor = _malp.get_actor(actor_id)
            if actor.get("error"):
                failed += 1
                print(f"[actor] {i}/{len(pending)} SKIP  {actor_id}  ({actor['error']})", flush=True)
                continue
            prompt = _build_actor_prompt(actor)
            raw    = _chat_text(prompt, model, base_url, timeout, label="actor")
            if raw is None:
                failed += 1
                print(f"[actor] {i}/{len(pending)} FAIL  {actor_id}", flush=True)
                continue
            summary = _normalize_summary(raw)
            db.upsert_actor_summary(actor_id, model, summary, raw)
            done += 1
            print(f"[actor] {i}/{len(pending)} ok    {actor_id}  ({actor.get('name','')})", flush=True)
    except KeyboardInterrupt:
        remaining = len(pending) - i
        print(f"\n[actor] interrupted at {i}/{len(pending)}  ({done} saved, {remaining} remaining)", flush=True)
        print(f"[actor] resume: python3 worker.py actor --model {model}", flush=True)
        return

    print(f"[actor] done: {done} ok, {failed} failed", flush=True)


def _build_family_prompt(family: dict) -> str:
    name       = family.get("name") or family.get("id", "unknown")
    desc       = (family.get("description") or "")[:600]
    alt_names  = family.get("alt_names", [])[:4]
    attribution = family.get("attribution", [])[:4]

    parts = [f"Malware Family: {name}"]
    if alt_names:
        parts.append("Also known as: " + ", ".join(alt_names))
    if attribution:
        parts.append("Attributed to: " + ", ".join(str(a) for a in attribution))
    if desc:
        parts.append("Description: " + desc)

    context = "\n".join(parts)
    return (
        "You are a malware analyst.\n"
        "Write exactly 3 plain sentences describing this malware family.\n"
        "Sentence 1: what the malware does and its primary capabilities.\n"
        "Sentence 2: how it persists, evades detection, or moves laterally.\n"
        "Sentence 3: the most actionable detection or hunting recommendation.\n"
        "No markdown, no lists, no headers. Hard limit: 420 characters total.\n\n"
        f"{context}"
    )


def cmd_family(args: argparse.Namespace) -> None:
    """Precompute behavioral briefs for Malpedia malware families."""
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent / "dashboard"))

    model    = args.model
    base_url = args.url
    timeout  = args.timeout

    db.init()

    try:
        import malpedia as _malp
    except ImportError:
        print("[family] malpedia module not available", flush=True)
        sys.exit(1)

    if not _malp.available():
        print("[family] malpediaclient not installed (pip install malpediaclient)", flush=True)
        sys.exit(1)

    if getattr(args, "rebuild", False):
        import sqlite3
        with sqlite3.connect(db.DB_PATH) as conn:
            n = conn.execute(
                "DELETE FROM family_summaries WHERE model=?", (model,)
            ).rowcount
        print(f"[family] --rebuild: wiped {n} summary rows for model={model}", flush=True)

    print("[family] fetching family list …", flush=True)
    family_ids = _malp.list_families()
    if not family_ids:
        print("[family] no families found (check malpedia_config.api_token)", flush=True)
        return

    pending = db.get_family_ids_without_summary(family_ids, model)
    if not pending:
        print(f"[family] all {len(family_ids)} families already have briefs for {model}", flush=True)
        return

    ok, installed = _ollama_has_model(model, base_url)
    if not ok:
        print(f"[family] model not available: {model}", flush=True)
        print(f"[family] fix: ollama pull {model}", flush=True)
        sys.exit(1)

    print(f"[family] {len(pending)}/{len(family_ids)} families to brief with {model} …", flush=True)
    done = failed = 0

    try:
        for i, family_id in enumerate(pending, 1):
            family = _malp.get_family(family_id)
            if family.get("error"):
                failed += 1
                print(f"[family] {i}/{len(pending)} SKIP  {family_id}  ({family['error']})", flush=True)
                continue
            prompt = _build_family_prompt(family)
            raw    = _chat_text(prompt, model, base_url, timeout, label="family")
            if raw is None:
                failed += 1
                print(f"[family] {i}/{len(pending)} FAIL  {family_id}", flush=True)
                continue
            summary = _normalize_summary(raw)
            db.upsert_family_summary(family_id, model, summary, raw)
            done += 1
            print(f"[family] {i}/{len(pending)} ok    {family_id}  ({family.get('name','')})", flush=True)
    except KeyboardInterrupt:
        remaining = len(pending) - i
        print(f"\n[family] interrupted at {i}/{len(pending)}  ({done} saved, {remaining} remaining)", flush=True)
        print(f"[family] resume: python3 worker.py family --model {model}", flush=True)
        return

    print(f"[family] done: {done} ok, {failed} failed", flush=True)


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

    import sqlite3
    with sqlite3.connect(db.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        art_total = conn.execute("SELECT COUNT(*) FROM artifact_map").fetchone()[0]
        art_sum_rows = conn.execute(
            "SELECT model, COUNT(*) n FROM artifact_summaries GROUP BY model"
        ).fetchall()
    if not art_sum_rows:
        print(f"artifact_summ  : 0  (techniques in map: {art_total})")
    for r in art_sum_rows:
        print(f"artifact_summ  : {r['n']}  ({r['model']})  pending: {art_total - r['n']}")

    with sqlite3.connect(db.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        sess_total  = conn.execute("SELECT COUNT(*) FROM pipeline_sessions WHERE status='success'").fetchone()[0]
        sess_rows   = conn.execute("SELECT model, COUNT(*) n FROM session_summaries GROUP BY model").fetchall()
        actor_rows  = conn.execute("SELECT model, COUNT(*) n FROM actor_summaries GROUP BY model").fetchall()
        family_rows = conn.execute("SELECT model, COUNT(*) n FROM family_summaries GROUP BY model").fetchall()

    if not sess_rows:
        print(f"session_summ   : 0  (finished sessions: {sess_total})")
    for r in sess_rows:
        print(f"session_summ   : {r['n']}  ({r['model']})  pending: {sess_total - r['n']}")

    if not actor_rows:
        print(f"actor_summ     : 0")
    for r in actor_rows:
        print(f"actor_summ     : {r['n']}  ({r['model']})")

    if not family_rows:
        print(f"family_summ    : 0")
    for r in family_rows:
        print(f"family_summ    : {r['n']}  ({r['model']})")


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

    aptp = sub.add_parser("apt", help="precompute campaign briefs for finished pipeline sessions (LLM)")
    aptp.add_argument("--model",   default="qwen3:14b",              help="Ollama chat model")
    aptp.add_argument("--url",     default="http://localhost:11434", help="Ollama base URL")
    aptp.add_argument("--timeout", type=int, default=120,            help="per-call timeout (s)")
    aptp.add_argument("--rebuild", action="store_true",
                      help="wipe existing session briefs and redo all")

    acp = sub.add_parser("actor", help="precompute threat profile briefs for Malpedia actors (LLM)")
    acp.add_argument("--model",   default="qwen3:14b",              help="Ollama chat model")
    acp.add_argument("--url",     default="http://localhost:11434", help="Ollama base URL")
    acp.add_argument("--timeout", type=int, default=120,            help="per-call timeout (s)")
    acp.add_argument("--rebuild", action="store_true",
                     help="wipe existing actor briefs and redo all")

    fap = sub.add_parser("family", help="precompute behavioral briefs for Malpedia malware families (LLM)")
    fap.add_argument("--model",   default="qwen3:14b",              help="Ollama chat model")
    fap.add_argument("--url",     default="http://localhost:11434", help="Ollama base URL")
    fap.add_argument("--timeout", type=int, default=120,            help="per-call timeout (s)")
    fap.add_argument("--rebuild", action="store_true",
                     help="wipe existing family briefs and redo all")

    sgp = sub.add_parser("sigma", help="parse Sigma rules + precompute detection briefs (LLM)")
    sgp.add_argument("--sigma-path", default=None, dest="sigma_path",
                     metavar="PATH",
                     help="parse Sigma rules from PATH into artifact_map before briefing")
    sgp.add_argument("--parse-only", action="store_true", dest="parse_only",
                     help="only parse Sigma rules, skip LLM briefing")
    sgp.add_argument("--model",      default="qwen3:14b")
    sgp.add_argument("--url",        default="http://localhost:11434")
    sgp.add_argument("--timeout",    type=int, default=120)
    sgp.add_argument("--rebuild",    action="store_true",
                     help="wipe existing LLM briefs and redo all")

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
    elif args.cmd == "apt":
        cmd_apt(args)
    elif args.cmd == "actor":
        cmd_actor(args)
    elif args.cmd == "family":
        cmd_family(args)
    elif args.cmd == "sigma":
        cmd_sigma(args)
    elif args.cmd == "refresh":
        cmd_refresh(args)
    elif args.cmd == "status":
        cmd_status(args)
