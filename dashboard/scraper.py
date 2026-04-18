"""
peekaboo local knowledge base indexer
indexes ~/hacking/cocomelonc.github.io/_posts/ — full writeup markdown files
run once: python3 dashboard/scraper.py
"""
from __future__ import annotations
import json
import re
from datetime import datetime
from pathlib import Path

POSTS_DIR = Path.home() / "hacking" / "cocomelonc.github.io" / "_posts"
OUTPUT    = Path(__file__).parent / "knowledge_base.json"

# max chars of body content to keep per post (keeps KB within token budget)
CONTENT_LIMIT = 6000


def _parse_post(path: Path) -> dict | None:
    """Parse a Jekyll markdown post — extract frontmatter title + body text."""
    try:
        raw = path.read_text(errors="replace")
    except Exception as e:
        print(f"  [!] read error {path.name}: {e}")
        return None

    title = path.stem  # fallback
    body  = raw

    # strip YAML frontmatter (--- ... ---)
    fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n", raw, re.DOTALL)
    if fm_match:
        fm_text = fm_match.group(1)
        body    = raw[fm_match.end():]
        # extract title from frontmatter
        tm = re.search(r'^title:\s*["\']?(.+?)["\']?\s*$', fm_text, re.MULTILINE)
        if tm:
            title = tm.group(1).strip()

    # clean up body: remove image tags, liquid tags, html
    body = re.sub(r'\{%.*?%\}',   '',  body, flags=re.DOTALL)  # liquid tags
    body = re.sub(r'\{:.*?\}',    '',  body)                    # kramdown attrs
    body = re.sub(r'<[^>]+>',     '',  body)                    # html tags
    body = re.sub(r'!\[.*?\]\(.*?\)', '', body)                 # markdown images
    body = re.sub(r'\n{3,}',      '\n\n', body)                 # excessive blank lines
    body = body.strip()

    if len(body) < 100:
        return None

    return {
        "title":   title,
        "ref":     path.stem,
        "content": body[:CONTENT_LIMIT],
    }


def scrape() -> dict:
    if not POSTS_DIR.exists():
        raise FileNotFoundError(f"posts directory not found: {POSTS_DIR}")

    print(f"[*] indexing {POSTS_DIR}")
    posts: list[dict] = []

    files = sorted(POSTS_DIR.glob("*.markdown")) + sorted(POSTS_DIR.glob("*.md"))
    files = sorted(set(files))  # deduplicate, keep sorted by name (date-ordered)

    for i, f in enumerate(files, 1):
        post = _parse_post(f)
        if not post:
            print(f"  [{i}/{len(files)}] skip: {f.name}")
            continue
        posts.append(post)
        print(f"  [{i}/{len(files)}] {post['title'][:70]}")

    kb = {
        "source":     str(POSTS_DIR),
        "author":     "Zhassulan Zhussupov (@cocomelonc)",
        "indexed_at": datetime.utcnow().isoformat() + "Z",
        "post_count": len(posts),
        "posts":      posts,
    }
    OUTPUT.write_text(json.dumps(kb, indent=2, ensure_ascii=False))
    print(f"\n[+] indexed {len(posts)} posts → {OUTPUT}")
    return kb


if __name__ == "__main__":
    scrape()
