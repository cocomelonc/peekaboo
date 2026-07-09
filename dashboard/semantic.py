"""
peekaboo semantic matching via local Ollama embeddings.
MMR (Maximal Marginal Relevance) retrieval: balances relevance and diversity.

Data source priority:
  1. SQLite tables (kb_docs + kb_embeddings) - populated by worker.py
  2. Legacy JSON cache (data/post_embeddings.json) - fallback for old installs

The in-memory index is invalidated when peekaboo.db's mtime changes,
so `rsync peekaboo.db` from a GPU box picks up automatically.
"""
from __future__ import annotations
import hashlib
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


def _embed_query(query: str) -> list[float] | None:
    """Embed a single search query, DB-cached to avoid repeat Ollama calls.

    This is the only live LLM call the dashboard makes. A warm cache means
    repeated Malpedia / semantic searches cost zero Ollama round-trips.
    """
    q = query.strip()
    if not q:
        return None
    h = hashlib.sha256(f"{EMBED_MODEL}\n{q}".encode()).hexdigest()
    try:
        import db
        cached = db.get_query_embedding(h, EMBED_MODEL)
    except Exception:
        cached = None
    if cached:
        return cached

    embs = _embed([q])
    if not embs:
        return None
    vec = embs[0]
    try:
        import db
        db.put_query_embedding(h, EMBED_MODEL, q, vec)
    except Exception:
        pass
    return vec


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


def _load_from_db() -> tuple[list[dict], dict[str, list[float]], dict[str, list[str]], dict[str, dict], dict[str, str]] | None:
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        import db
        rows      = db.get_kb_embeddings_all(EMBED_MODEL)
        tags      = db.get_kb_tags_all(None)
        ttp_rows  = db.get_ttp_extracted_all(None)
        summaries = db.get_kb_summaries_all(None)
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
            "slug":        slug,
            "title":       r.get("title", ""),
            "date":        r.get("date", ""),
            "blog_url":    r.get("blog_url", ""),
            "category":    r.get("category", ""),
            "attack_ids":  r.get("attack_ids", []),
            "source_type": r.get("source_type", "blog"),
        })
    # build ttps index: slug -> {attack_ids, tactics, confidence, rationale}
    # for multi-model rows, high-confidence entry wins over low
    _conf_rank = {"high": 0, "medium": 1, "low": 2}
    ttps: dict[str, dict] = {}
    for r in ttp_rows:
        slug = r.get("slug") or ""
        if not slug or not r.get("attack_ids"):
            continue
        entry = {
            "attack_ids": r["attack_ids"],
            "tactics":    r.get("tactics", []),
            "confidence": r.get("confidence", "low"),
            "rationale":  r.get("rationale", ""),
        }
        if slug not in ttps or (
            _conf_rank.get(entry["confidence"], 2) <
            _conf_rank.get(ttps[slug]["confidence"], 2)
        ):
            ttps[slug] = entry
    return posts, embs, tags, ttps, summaries


def _load_from_json() -> tuple[list[dict], dict[str, list[float]], dict[str, list[str]], dict[str, dict], dict[str, str]] | None:
    try:
        if not _LIBRARY_CACHE.exists() or not _EMB_CACHE.exists():
            return None
        posts = json.loads(_LIBRARY_CACHE.read_text())
        raw   = json.loads(_EMB_CACHE.read_text())
        embs  = {item["slug"]: item["embedding"] for item in raw}
        return posts, embs, {}, {}, {}  # no tags/ttps/summaries in legacy json
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
        _cache = {"posts": [], "embs": {}, "tags": {}, "ttps": {}, "summaries": {},
                  "db_mtime": db_mtime, "source": "none"}
        return [], {}, {}

    posts, embs, tags, ttps, summaries = data
    _cache = {"posts": posts, "embs": embs, "tags": tags, "ttps": ttps, "summaries": summaries,
              "db_mtime": db_mtime, "source": source}
    return posts, embs, tags


def _load_ttps() -> dict[str, dict]:
    _load_index()
    return _cache.get("ttps", {}) if _cache else {}


def _load_summaries() -> dict[str, str]:
    _load_index()
    return _cache.get("summaries", {}) if _cache else {}


def summary_count() -> int:
    return len(_load_summaries())


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


def ttp_count() -> int:
    """Number of posts with extracted TTPs (0 if worker ttp has not been run)."""
    return len(_load_ttps())


def invalidate_cache() -> None:
    global _cache
    _cache = None


# --------------------------------------------------------------------------- #
# Public retrieval API                                                         #
# --------------------------------------------------------------------------- #

def _mmr_select(
    query_vec: list[float],
    candidates: list[tuple[float, dict, list[float]]],
    max_results: int,
    lambda_: float = 0.6,
) -> list[tuple[float, dict]]:
    """Maximal Marginal Relevance: pick diverse-yet-relevant results.

    lambda_=1.0 is pure cosine ranking; lambda_=0.0 is pure diversity.
    0.6 balances both - avoids returning five process-injection variants
    for a broad "injection" query.
    """
    selected:      list[tuple[float, dict]] = []
    selected_vecs: list[list[float]]        = []
    remaining = list(candidates)

    while remaining and len(selected) < max_results:
        best_idx   = -1
        best_score = float("-inf")
        for idx, (sim_q, post, vec) in enumerate(remaining):
            redundancy = max(
                (_cosine(vec, sv) for sv in selected_vecs),
                default=0.0,
            )
            mmr = lambda_ * sim_q - (1.0 - lambda_) * redundancy
            if mmr > best_score:
                best_score = mmr
                best_idx   = idx
        if best_idx == -1:
            break
        sim_q, post, vec = remaining.pop(best_idx)
        selected.append((sim_q, post))
        selected_vecs.append(vec)

    return selected


def find_related_posts(query: str, max_results: int = 8,
                       filter_ttp: str | None = None) -> list[dict]:
    """Embed query, MMR-rank all posts, return diverse top matches.

    Uses Maximal Marginal Relevance (λ=0.6) over a candidate pool of
    min(40, 4×max_results) posts so broad queries like 'injection' or
    'evasion' return varied techniques instead of near-duplicate results.

    filter_ttp: if set (e.g. "T1055"), only return posts whose extracted ttps
    include that ATT&CK ID. Useful for TTP-scoped semantic search.

    Results carry `tags`, `ttps`, and `source_type` fields for downstream callers."""
    posts, embs, tags = _load_index()
    ttps      = _load_ttps()
    summaries = _load_summaries()
    if not posts or not embs:
        return []

    q_vec = _embed_query(query)
    if q_vec is None:
        return []

    # build candidate list: (sim_to_query, post, post_vec)
    candidates: list[tuple[float, dict, list[float]]] = []
    for post in posts:
        slug = post.get("slug", "")
        pvec = embs.get(slug)
        if pvec is None:
            continue
        if filter_ttp and filter_ttp not in (ttps.get(slug) or {}).get("attack_ids", []):
            continue
        sim = _cosine(q_vec, pvec)
        if sim >= 0.3:
            candidates.append((sim, post, pvec))

    if not candidates:
        return []

    # trim to a candidate pool, then apply MMR
    pool_size  = min(len(candidates), max(40, max_results * 4))
    candidates.sort(key=lambda x: x[0], reverse=True)
    pool       = candidates[:pool_size]
    selected   = _mmr_select(q_vec, pool, max_results, lambda_=0.6)

    results = []
    for sim, post in selected:
        slug = post.get("slug", "")
        results.append({
            "slug":        slug,
            "title":       post.get("title", ""),
            "date":        post.get("date", ""),
            "blog_url":    post.get("blog_url", ""),
            "category":    post.get("category", ""),
            "attack_ids":  post.get("attack_ids", []),
            "source_type": post.get("source_type", "blog"),
            "tags":        tags.get(slug, []),
            "ttps":        ttps.get(slug),
            "summary":     summaries.get(slug, ""),
            "score":       round(sim, 3),
        })
    return results


def find_posts_by_ttp(attack_id: str) -> list[dict]:
    """Return all posts whose extracted TTPs contain attack_id, sorted by confidence.

    Useful for the frontend: 'show me all posts implementing T1055'."""
    posts_idx, _, tags = _load_index()
    ttps = _load_ttps()
    posts_by_slug = {p["slug"]: p for p in posts_idx}

    _conf_rank = {"high": 0, "medium": 1, "low": 2}
    results = []
    for slug, t in ttps.items():
        if attack_id not in t.get("attack_ids", []):
            continue
        p = posts_by_slug.get(slug, {})
        results.append({
            "slug":       slug,
            "title":      p.get("title", ""),
            "date":       p.get("date", ""),
            "blog_url":   p.get("blog_url", ""),
            "category":   p.get("category", ""),
            "attack_ids": p.get("attack_ids", []),
            "tags":       tags.get(slug, []),
            "ttps":       t,
        })
    results.sort(key=lambda x: _conf_rank.get(x["ttps"]["confidence"], 2))
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
