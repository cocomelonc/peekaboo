"""
peekaboo semantic matching via local Ollama embeddings.
no hardcoded rules - pure cosine similarity on nomic-embed-text.

Data source priority:
  1. SQLite tables (kb_docs + kb_embeddings) - populated by worker.py
  2. Legacy JSON cache (data/post_embeddings.json) - fallback for old installs

The in-memory index is invalidated when peekaboo.db's mtime changes,
so `rsync peekaboo.db` from a GPU box picks up automatically.
"""
from __future__ import annotations
import json
import math
import sys
import time
from pathlib import Path

_BASE          = Path(__file__).parent.parent
_LIBRARY_CACHE = _BASE / "data" / "library_cache.json"
_EMB_CACHE     = _BASE / "data" / "post_embeddings.json"  # legacy fallback
_DB_PATH       = Path(__file__).parent / "peekaboo.db"

OLLAMA_URL  = "http://localhost:11434/api/embed"
EMBED_MODEL = "nomic-embed-text"


# --------------------------------------------------------------------------- #
# Ollama embed                                                                 #
# --------------------------------------------------------------------------- #

def _embed(texts: list[str]) -> list[list[float]] | None:
    try:
        import urllib.request
        payload = json.dumps({"model": EMBED_MODEL, "input": texts}).encode()
        req = urllib.request.Request(
            OLLAMA_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())["embeddings"]
    except Exception as e:
        print(f"[semantic] embed error: {e}")
        return None


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na  = math.sqrt(sum(x * x for x in a))
    nb  = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _post_text(post: dict) -> str:
    parts = [post.get("title", ""), post.get("category", "")]
    aids = post.get("attack_ids", [])
    if aids:
        parts.append("ATT&CK: " + " ".join(aids))
    return " | ".join(p for p in parts if p)


# --------------------------------------------------------------------------- #
# Index loading - DB first, JSON fallback, mtime-invalidated cache             #
# --------------------------------------------------------------------------- #

_cache: dict | None = None


def _load_from_db() -> tuple[list[dict], dict[str, list[float]], dict[str, list[str]]] | None:
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        import db
        rows = db.get_kb_embeddings_all(EMBED_MODEL)
        tags = db.get_kb_tags_all(None)  # union of all tagging models
    except Exception as e:
        print(f"[semantic] db load error: {e}")
        return None
    if not rows:
        return None
    posts: list[dict] = []
    embs:  dict[str, list[float]] = {}
    for r in rows:
        slug = r.get("slug") or ""
        if not slug:
            continue
        embs[slug] = r["vector"]
        posts.append({
            "slug":       slug,
            "title":      r.get("title", ""),
            "date":       r.get("date", ""),
            "blog_url":   r.get("blog_url", ""),
            "category":   r.get("category", ""),
            "attack_ids": r.get("attack_ids", []),
        })
    return posts, embs, tags


def _load_from_json() -> tuple[list[dict], dict[str, list[float]], dict[str, list[str]]] | None:
    try:
        if not _LIBRARY_CACHE.exists() or not _EMB_CACHE.exists():
            return None
        posts = json.loads(_LIBRARY_CACHE.read_text())
        raw   = json.loads(_EMB_CACHE.read_text())
        embs  = {item["slug"]: item["embedding"] for item in raw}
        return posts, embs, {}  # no tags in legacy json
    except Exception:
        return None


def _load_index() -> tuple[list[dict], dict[str, list[float]], dict[str, list[str]]]:
    """Cached load. Re-reads when peekaboo.db's mtime changes."""
    global _cache
    db_mtime = _DB_PATH.stat().st_mtime if _DB_PATH.exists() else 0.0
    if _cache and _cache["db_mtime"] == db_mtime:
        return _cache["posts"], _cache["embs"], _cache["tags"]

    data   = _load_from_db()
    source = "db"
    if data is None:
        data   = _load_from_json()
        source = "json"
    if data is None:
        _cache = {"posts": [], "embs": {}, "tags": {}, "db_mtime": db_mtime, "source": "none"}
        return [], {}, {}

    posts, embs, tags = data
    _cache = {"posts": posts, "embs": embs, "tags": tags,
              "db_mtime": db_mtime, "source": source}
    return posts, embs, tags


def data_source() -> str:
    """Where retrieval is currently reading from: 'db' | 'json' | 'none'."""
    _load_index()
    return _cache["source"] if _cache else "none"


def embedded_count() -> int:
    """Number of posts available for retrieval (from whichever source is active)."""
    _, embs, _ = _load_index()
    return len(embs)


def tagged_count() -> int:
    """Number of posts with tags attached (0 if --tag has not been run)."""
    _, _, tags = _load_index()
    return len(tags)


def invalidate_cache() -> None:
    global _cache
    _cache = None


# --------------------------------------------------------------------------- #
# Public retrieval API                                                         #
# --------------------------------------------------------------------------- #

def find_related_posts(query: str, max_results: int = 8) -> list[dict]:
    """Embed query, cosine-rank all posts, return top matches.

    If kb_tags has entries, results carry a `tags` field for downstream callers
    (e.g. the chatbot prompt builder)."""
    posts, embs, tags = _load_index()
    if not posts or not embs:
        return []

    q_embs = _embed([query])
    if not q_embs:
        return []
    q_vec = q_embs[0]

    scored: list[tuple[float, dict]] = []
    for post in posts:
        slug = post.get("slug", "")
        pvec = embs.get(slug)
        if pvec is None:
            continue
        sim = _cosine(q_vec, pvec)
        scored.append((sim, post))

    scored.sort(key=lambda x: x[0], reverse=True)

    results = []
    for sim, post in scored[:max_results]:
        if sim < 0.3:
            break
        slug = post.get("slug", "")
        results.append({
            "slug":       slug,
            "title":      post.get("title", ""),
            "date":       post.get("date", ""),
            "blog_url":   post.get("blog_url", ""),
            "category":   post.get("category", ""),
            "attack_ids": post.get("attack_ids", []),
            "tags":       tags.get(slug, []),
            "score":      round(sim, 3),
        })
    return results


# --------------------------------------------------------------------------- #
# Rebuild (writes to DB; used by the "Reindex" button)                         #
# --------------------------------------------------------------------------- #

def build_post_embeddings(force: bool = False) -> bool:
    """
    Embed posts into the DB. `force=True` re-embeds everything.

    The worker (worker.py) is the canonical producer; this function exists
    so the dashboard's "Reindex" button keeps working without shelling out.
    """
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        import db
        db.init()
    except Exception as e:
        print(f"[semantic] db init error: {e}")
        return False

    if not _LIBRARY_CACHE.exists():
        print(f"[semantic] {_LIBRARY_CACHE} not found")
        return False

    library = json.loads(_LIBRARY_CACHE.read_text())
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

    if force:
        import sqlite3
        try:
            with sqlite3.connect(db.DB_PATH) as conn:
                conn.execute("DELETE FROM kb_embeddings WHERE model = ?", (EMBED_MODEL,))
                conn.commit()
        except Exception as e:
            print(f"[semantic] wipe error: {e}")
            return False

    pending = db.get_kb_docs_without_embedding(EMBED_MODEL)
    if not pending:
        invalidate_cache()
        return True

    print(f"[semantic] embedding {len(pending)} posts via {EMBED_MODEL}…")
    t0 = time.time()
    chunk = 32
    for i in range(0, len(pending), chunk):
        batch = pending[i:i + chunk]
        texts = [_post_text(d) for d in batch]
        embs  = _embed(texts)
        if embs is None:
            print(f"[semantic] embedding failed at chunk {i}")
            return False
        for doc, vec in zip(batch, embs):
            db.upsert_kb_embedding(doc["id"], EMBED_MODEL, vec)

    invalidate_cache()
    print(f"[semantic] embedded {len(pending)} posts in {time.time()-t0:.1f}s")
    return True


# --------------------------------------------------------------------------- #
# Ollama availability                                                          #
# --------------------------------------------------------------------------- #

def available() -> bool:
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://localhost:11434/api/tags", method="GET"
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            names = [m["name"] for m in data.get("models", [])]
            return any(EMBED_MODEL in n for n in names)
    except Exception:
        return False
