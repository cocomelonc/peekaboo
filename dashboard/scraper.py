"""
peekaboo blog scraper
scrapes cocomelonc.github.io and builds knowledge_base.json
run once: python3 dashboard/scraper.py
"""
from __future__ import annotations
import json
import re
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    raise SystemExit("pip install requests beautifulsoup4")

BLOG_URL   = "https://cocomelonc.github.io"
OUTPUT     = Path(__file__).parent / "knowledge_base.json"
MAX_POSTS  = 120
DELAY      = 0.8   # seconds between requests


def _get(url: str, timeout: int = 15) -> requests.Response | None:
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": "peekaboo-scraper/1.0"})
        r.raise_for_status()
        return r
    except Exception as e:
        print(f"  [!] {url} → {e}")
        return None


def _text(soup: BeautifulSoup) -> str:
    """Extract clean text from post body."""
    # remove nav/footer/script/style
    for tag in soup.find_all(["nav", "footer", "script", "style",
                               "header", ".site-nav", ".site-footer"]):
        tag.decompose()

    # try common post body selectors
    body = (soup.find("article") or
            soup.find(class_=re.compile(r"post[-_]content|post[-_]body|entry[-_]content")) or
            soup.find("main") or
            soup.find(id="main-content"))

    target = body if body else soup.find("body")
    if not target:
        return ""

    lines = []
    for elem in target.find_all(["p", "h1", "h2", "h3", "h4", "li", "pre", "code"]):
        t = elem.get_text(" ", strip=True)
        if t:
            lines.append(t)
    return "\n".join(lines)


def _post_urls(soup: BeautifulSoup, base: str) -> list[str]:
    """Collect post links from a page."""
    urls = []
    for a in soup.find_all("a", href=True):
        href = urljoin(base, a["href"])
        p = urlparse(href)
        # typical Jekyll post: /YYYY/MM/DD/slug/ or /YYYY/MM/slug/
        if (p.netloc == urlparse(base).netloc and
                re.search(r"/20\d\d/\d\d/", p.path)):
            clean = href.split("#")[0].rstrip("/")
            if clean not in urls:
                urls.append(clean)
    return urls


def scrape() -> dict:
    print(f"[*] scraping {BLOG_URL}")
    posts: list[dict] = []
    visited: set[str] = set()

    # ── collect post URLs ──────────────────────────────────────────────────
    page_url = BLOG_URL
    for page_num in range(1, 20):
        resp = _get(page_url)
        if not resp:
            break
        soup = BeautifulSoup(resp.text, "html.parser")
        found = _post_urls(soup, BLOG_URL)
        new = [u for u in found if u not in visited]
        visited.update(new)
        print(f"  page {page_num}: {len(new)} new posts ({len(visited)} total)")
        if not new:
            break

        # next page: look for pagination links
        next_link = None
        for a in soup.find_all("a", href=True):
            txt = a.get_text().lower().strip()
            if txt in ("next", "older", "next page", "›", "»", "older posts"):
                next_link = urljoin(BLOG_URL, a["href"])
                break
        if not next_link:
            break
        page_url = next_link
        time.sleep(DELAY)

    print(f"[*] found {len(visited)} post URLs, fetching content...")

    # ── fetch each post ────────────────────────────────────────────────────
    for i, url in enumerate(sorted(visited)[:MAX_POSTS], 1):
        resp = _get(url)
        if not resp:
            continue
        soup = BeautifulSoup(resp.text, "html.parser")

        title = ""
        if soup.find("h1"):
            title = soup.find("h1").get_text(strip=True)
        elif soup.find("title"):
            title = soup.find("title").get_text(strip=True).split("|")[0].strip()

        content = _text(soup)
        if len(content) < 200:
            print(f"  [{i}] skip (too short): {url}")
            continue

        # truncate very long posts to keep KB size manageable
        content = content[:8000]

        posts.append({
            "title":   title,
            "url":     url,
            "content": content,
        })
        print(f"  [{i}/{len(visited)}] {title[:70]}")
        time.sleep(DELAY)

    kb = {
        "blog":       BLOG_URL,
        "author":     "Zhassulan Zhussupov (@cocomelonc)",
        "scraped_at": datetime.utcnow().isoformat() + "Z",
        "post_count": len(posts),
        "posts":      posts,
    }
    OUTPUT.write_text(json.dumps(kb, indent=2, ensure_ascii=False))
    print(f"\n[+] saved {len(posts)} posts → {OUTPUT}")
    return kb


if __name__ == "__main__":
    scrape()
