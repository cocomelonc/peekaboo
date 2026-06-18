#!/usr/bin/env python3
"""
peekaboo worker — GPU-side KB enrichment
standalone script; writes to dashboard/peekaboo.db

commands:
  init    import library_cache.json -> kb_docs           (idempotent)
  embed   compute embedding vectors for new docs         (resumable)
  tag     classify each doc with a constrained tag set   (resumable, LLM)
  status  show table row counts

options (embed):
  --watch N    loop every N seconds after first pass (default: off)
  --model M    embedding model (default: nomic-embed-text)
  --batch N    docs per Ollama call (default: 32)
  --url URL    Ollama base URL (default: http://localhost:11434)

options (tag):
  --watch N    loop every N seconds after first pass (default: off)
  --model M    chat model (default: qwen3:4b; try qwen3:14b on a GPU box)
  --url URL    Ollama base URL (default: http://localhost:11434)
  --code-lines N   max lines of src code to feed the LLM (default: 200)

examples:
  python3 worker.py init
  python3 worker.py embed
  python3 worker.py embed --watch 300
  python3 worker.py tag
  python3 worker.py tag --model qwen3:14b --watch 600
  python3 worker.py status
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

# -- path setup so we can import dashboard/db.py without installing the app
_ROOT = Path(__file__).parent
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


def _ollama_has_model(model: str, base_url: str) -> bool:
    try:
        req = urllib.request.Request(base_url.rstrip("/") + "/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            names = [m["name"] for m in json.loads(resp.read()).get("models", [])]
            return any(model.split(":")[0] in n for n in names)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Commands                                                                     #
# --------------------------------------------------------------------------- #

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
    print(f"[init] done — kb_docs: {stats['docs']} rows ({inserted} upserted)", flush=True)


def cmd_embed(args: argparse.Namespace) -> None:
    """Compute nomic-embed-text vectors for unembedded docs. Resumable."""
    model    = args.model
    base_url = args.url
    batch_sz = args.batch

    db.init()

    if not _ollama_has_model(model, base_url):
        print(f"[embed] model not available: {model}  (run: ollama pull {model})", flush=True)
        sys.exit(1)

    def _run_once() -> int:
        pending = db.get_kb_docs_without_embedding(model)
        if not pending:
            print(f"[embed] nothing to do — all docs already embedded with {model}", flush=True)
            return 0

        print(f"[embed] {len(pending)} docs to embed with {model} …", flush=True)
        done = 0

        for i in range(0, len(pending), batch_sz):
            batch = pending[i:i + batch_sz]
            texts = [_post_text(d) for d in batch]

            vecs = _embed_batch(texts, model, base_url)
            if vecs is None:
                print(f"[embed] batch {i//batch_sz + 1} failed — stopping", flush=True)
                break

            for doc, vec in zip(batch, vecs):
                db.upsert_kb_embedding(doc["id"], model, vec)
                done += 1

            pct = min(100, int((i + len(batch)) / len(pending) * 100))
            _progress(pct, f"{done}/{len(pending)}")

        print(f"\n[embed] embedded {done} docs", flush=True)
        return done

    _run_once()

    if args.watch:
        interval = int(args.watch)
        print(f"[embed] --watch {interval}s — polling for new docs …", flush=True)
        while True:
            time.sleep(interval)
            _run_once()


# --------------------------------------------------------------------------- #
# Tag taxonomy (constrained — keeps LLM output deterministic and queryable)    #
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


def _chat_json(prompt: str, model: str, base_url: str, timeout: int = 300) -> tuple[dict | None, str]:
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
        print(f"\n[tag] chat error: {e}", flush=True)
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


def _read_code(src_path: str, max_lines: int) -> str:
    if not src_path:
        return ""
    try:
        p = Path(src_path)
        if not p.is_absolute():
            p = _ROOT / src_path
        if not p.exists() or not p.is_file():
            return ""
        lines = p.read_text(errors="replace").splitlines()
        return "\n".join(lines[:max_lines])
    except Exception:
        return ""


def cmd_tag(args: argparse.Namespace) -> None:
    """Classify each doc with constrained-JSON tags via local Ollama. Resumable."""
    model     = args.model
    base_url  = args.url
    max_lines = args.code_lines
    timeout   = args.timeout

    db.init()

    if not _ollama_has_model(model, base_url):
        print(f"[tag] model not available: {model}  (run: ollama pull {model})", flush=True)
        sys.exit(1)

    def _run_once() -> int:
        pending = db.get_kb_docs_without_tags(model)
        if not pending:
            print(f"[tag] nothing to do — all docs already tagged with {model}", flush=True)
            return 0

        print(f"[tag] {len(pending)} docs to tag with {model} …", flush=True)
        done   = 0
        failed = 0

        for i, doc in enumerate(pending, 1):
            code   = _read_code(doc.get("src_path", ""), max_lines)
            prompt = _build_tag_prompt(doc, code)
            parsed, raw = _chat_json(prompt, model, base_url, timeout=timeout)

            if parsed is None:
                failed += 1
                tags = []
            else:
                tags = _normalize_tags(parsed)

            db.upsert_kb_tag(doc["id"], model, tags, raw)
            done += 1

            pct = int(i / len(pending) * 100)
            label = f"{i}/{len(pending)} — {doc['slug'][:30]:30s} -> {','.join(tags[:4]) or '(none)'}"
            _progress(pct, label)

        print(f"\n[tag] tagged {done} docs ({failed} failed)", flush=True)
        return done

    _run_once()

    if args.watch:
        interval = int(args.watch)
        print(f"[tag] --watch {interval}s — polling for new docs …", flush=True)
        while True:
            time.sleep(interval)
            _run_once()


def cmd_status(args: argparse.Namespace) -> None:
    db.init()
    s = db.kb_stats()
    total = s["docs"]
    embedded = s["embeddings"]
    tagged   = s["tags"]
    missing  = total - embedded
    print(f"kb_docs        : {total}")
    print(f"kb_embeddings  : {embedded}  (missing: {missing})")
    print(f"kb_tags        : {tagged}")


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


def _progress(pct: int, label: str = "") -> None:
    if sys.stdout.isatty():
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        print(f"\r[{bar}] {pct:3d}%  {label}  ", end="", flush=True)
    else:
        print(f"[embed] {pct}% {label}", flush=True)


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="worker.py",
        description="peekaboo KB enrichment worker",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init",   help="import library_cache.json -> kb_docs")
    sub.add_parser("status", help="show row counts")

    ep = sub.add_parser("embed", help="compute embedding vectors for new docs")
    ep.add_argument("--model",  default="nomic-embed-text",   help="Ollama model")
    ep.add_argument("--url",    default="http://localhost:11434", help="Ollama base URL")
    ep.add_argument("--batch",  type=int, default=32,          help="docs per call")
    ep.add_argument("--watch",  type=int, default=0, metavar="N",
                    help="loop every N seconds (0 = run once)")

    tp = sub.add_parser("tag", help="classify docs with constrained-JSON tags (LLM)")
    tp.add_argument("--model",      default="qwen3:1.7b",              help="Ollama chat model")
    tp.add_argument("--url",        default="http://localhost:11434",  help="Ollama base URL")
    tp.add_argument("--code-lines", type=int, default=120, dest="code_lines",
                    help="max src lines fed to the LLM")
    tp.add_argument("--timeout",    type=int, default=300,             help="per-call timeout (s)")
    tp.add_argument("--watch",      type=int, default=0, metavar="N",
                    help="loop every N seconds (0 = run once)")

    return p


if __name__ == "__main__":
    parser = _build_parser()
    args   = parser.parse_args()

    if args.cmd == "init":
        cmd_init(args)
    elif args.cmd == "embed":
        cmd_embed(args)
    elif args.cmd == "tag":
        cmd_tag(args)
    elif args.cmd == "status":
        cmd_status(args)
