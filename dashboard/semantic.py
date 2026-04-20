"""
peekaboo semantic matching via local Ollama embeddings
no hardcoded rules - pure cosine similarity on nomic-embed-text
"""
from __future__ import annotations
import json
import math
import time
from pathlib import Path

_BASE          = Path(__file__).parent.parent
_LIBRARY_CACHE = _BASE / "data" / "library_cache.json"
_EMB_CACHE     = _BASE / "data" / "post_embeddings.json"

OLLAMA_URL = "http://localhost:11434/api/embed"
EMBED_MODEL = "nomic-embed-text"


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


def _load_library() -> list[dict]:
    try:
        if _LIBRARY_CACHE.exists():
            return json.loads(_LIBRARY_CACHE.read_text())
    except Exception:
        pass
    return []


def build_post_embeddings(force: bool = False) -> bool:
    if not force and _EMB_CACHE.exists():
        return True
    posts = _load_library()
    if not posts:
        print("[semantic] no library posts found")
        return False

    texts = [_post_text(p) for p in posts]
    print(f"[semantic] embedding {len(texts)} posts via {EMBED_MODEL}...")
    t0 = time.time()

    # batch in chunks of 32 to avoid timeouts
    all_embs: list[list[float]] = []
    chunk = 32
    for i in range(0, len(texts), chunk):
        batch = texts[i:i + chunk]
        embs = _embed(batch)
        if embs is None:
            print(f"[semantic] embedding failed at chunk {i}")
            return False
        all_embs.extend(embs)

    cache = [
        {"slug": p["slug"], "embedding": e}
        for p, e in zip(posts, all_embs)
    ]
    _EMB_CACHE.write_text(json.dumps(cache, separators=(",", ":")))
    print(f"[semantic] cached {len(cache)} embeddings in {time.time()-t0:.1f}s -> {_EMB_CACHE}")
    return True


def _load_post_embeddings() -> dict[str, list[float]]:
    try:
        if _EMB_CACHE.exists():
            raw = json.loads(_EMB_CACHE.read_text())
            return {item["slug"]: item["embedding"] for item in raw}
    except Exception:
        pass
    return {}


def _build_post_index() -> tuple[list[dict], dict[str, list[float]]]:
    posts = _load_library()
    embs  = _load_post_embeddings()
    return posts, embs


def find_related_posts(query: str, max_results: int = 8) -> list[dict]:
    """Embed query, cosine-rank all posts, return top matches."""
    posts, embs = _build_post_index()
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
        results.append({
            "title":      post.get("title", ""),
            "date":       post.get("date", ""),
            "blog_url":   post.get("blog_url", ""),
            "category":   post.get("category", ""),
            "attack_ids": post.get("attack_ids", []),
            "score":      round(sim, 3),
        })
    return results


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
