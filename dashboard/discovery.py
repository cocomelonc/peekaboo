"""
peekaboo module discovery
read-only scan of ~/hacking/meow + blog posts
builds dynamic registry of all techniques
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Optional

_MEOW   = Path("/home/cocomelonc/hacking/meow")
_POSTS  = Path("/home/cocomelonc/hacking/cocomelonc.github.io/_posts")
_BASE   = Path(__file__).parent.parent
_CACHE  = _BASE / "data" / "module_registry.json"

ATTACK_RE = re.compile(r'\bT1\d{3}(?:\.\d{3})?\b')

_SLUG_RULES: list[tuple[str, str, Optional[str]]] = [
    (r"malware-injection|injection-\d",   "injection",     "T1055"),
    (r"dll.hijack|dllhijack",             "injection",     "T1574.001"),
    (r"malware-pers\b|pers-\d",           "persistence",   "T1547"),
    (r"mac.persist|mac-persist",          "persistence",   "T1547"),
    (r"av.evasion|evasion",               "evasion",       "T1027"),
    (r"malware.cryptography|cryptograph", "cryptography",  "T1027.013"),
    (r"hooking",                          "hooking",       "T1056"),
    (r"shellcod",                         "shellcoding",   "T1059"),
    (r"token.theft|token-theft",          "privesc",       "T1134"),
    (r"syscall",                          "syscalls",      "T1106"),
    (r"reverse.shell|rev.c\b",            "c2",            "T1059"),
    (r"pivoting",                         "network",       "T1090"),
    (r"linux.hack|linux.shell",           "linux",         None),
    (r"malware.mac\b|mac.malware",        "macos",         None),
    (r"android",                          "android",       None),
    (r"malware.trick|malware.tricks",     "tricks",        None),
    (r"malware.analysis|analysis",        "analysis",      None),
    (r"mem.forensic|forensic",            "analysis",      None),
    (r"overflow",                         "exploitation",  "T1203"),
    (r"inline.asm|inline-asm",            "evasion",       "T1027"),
    (r"hvck",                             "tricks",        None),
]

_PREFERRED_STEMS = {"hack", "evil", "main", "pers", "inject", "mal", "shellcode"}
_SRC_EXTS        = {".c", ".cpp", ".nim", ".asm", ".s"}

_CATEGORY_COLOR = {
    "injection":    "#0A84FF",
    "persistence":  "#30D158",
    "evasion":      "#FFD60A",
    "cryptography": "#BF5AF2",
    "tricks":       "#FF9F0A",
    "c2":           "#FF453A",
    "linux":        "#5AC8F5",
    "macos":        "#8E8E93",
    "analysis":     "#636366",
    "hooking":      "#FF375F",
    "syscalls":     "#5AC8FA",
    "exploitation": "#FF6B35",
    "shellcoding":  "#CF9FFF",
    "network":      "#34AADC",
    "privesc":      "#FF9500",
    "other":        "#636366",
}


def _category_from_slug(slug: str) -> tuple[str, Optional[str]]:
    s = slug.lower()
    for pattern, cat, aid in _SLUG_RULES:
        if re.search(pattern, s):
            return cat, aid
    return "other", None


def _detect_platform(src: str) -> str:
    if re.search(r'#include\s*[<"](windows\.h|winhttp\.h|winsock|wincrypt)[">]|WinMain\s*\(|WINAPI\b', src):
        return "windows"
    if re.search(r'#include\s*[<"](Foundation/|AppKit/|CoreFoundation)[">]', src):
        return "macos"
    if re.search(
        r'#include\s*[<"](linux/|unistd\.h|sys/types\.h|sys/socket|sys/ptrace'
        r'|sys/mman|dlfcn\.h|elf\.h|sys/ioctl|sys/stat\.h|dirent\.h)[">]',
        src
    ):
        return "linux"
    return "windows"


def _detect_compiler(path: Path, platform: str) -> str:
    ext = path.suffix.lower()
    if ext == ".nim":
        return "nim"
    if ext in (".asm", ".s"):
        return "nasm"
    if platform in ("linux", "macos"):
        return "gcc" if ext == ".c" else "gpp"
    return "mingw-gcc" if ext == ".c" else "mingw-gpp"


def _detect_extra_libs(src: str) -> list[str]:
    libs: list[str] = []
    if re.search(r'WinHttp|winhttp', src):
        libs.append("-lwinhttp")
    if re.search(r'GetAdaptersInfo|GetIpAddrTable|iphlpapi', src, re.I):
        libs.append("-liphlpapi")
    if re.search(r'CryptProtect|CryptUnprotect|crypt32', src, re.I):
        libs.append("-lcrypt32")
    if re.search(r'WSAStartup|WSACleanup|ws2_32', src, re.I):
        libs.append("-lws2_32")
    return libs


def _pick_primary(src_files: list[Path]) -> Optional[Path]:
    preferred = [f for f in src_files if f.stem in _PREFERRED_STEMS]
    if preferred:
        order = ["hack", "evil", "main", "pers", "inject", "mal", "shellcode"]
        for name in order:
            for p in preferred:
                if p.stem == name:
                    return p
        return preferred[0]
    c_files = [f for f in src_files if f.suffix == ".c"]
    if c_files:
        return sorted(c_files, key=lambda f: len(f.name))[0]
    return sorted(src_files, key=lambda f: len(f.name))[0] if src_files else None


def _read_snippet(path: Path, lines: int = 30) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[:lines])
    except Exception:
        return ""


def _find_blog_post(date_str: str, slug: str) -> Optional[Path]:
    # 1. exact match (meow date + slug)
    exact = _POSTS / f"{date_str}-{slug}.markdown"
    if exact.exists():
        return exact
    # 2. slug across all dates (post published on a different day than meow commit)
    by_slug = list(_POSTS.glob(f"*-{slug}.markdown"))
    if by_slug:
        return sorted(by_slug)[0]
    # 3. same date, any slug (last resort)
    by_date = list(_POSTS.glob(f"{date_str}-*.markdown"))
    return by_date[0] if by_date else None


def _parse_blog_post(post: Path) -> tuple[str, list[str], list[str]]:
    try:
        text = post.read_text(encoding="utf-8", errors="replace")
        fm_match = re.match(r'^---\s*\n(.*?)\n---', text, re.DOTALL)
        title, fm_cats = "", []
        if fm_match:
            fm = fm_match.group(1)
            tm = re.search(r'^title:\s*["\']?(.+?)["\']?\s*$', fm, re.MULTILINE)
            if tm:
                title = tm.group(1).strip('"\'')
            fm_cats = re.findall(r'^  - (\S+)', fm, re.MULTILINE)
        body = text[fm_match.end():] if fm_match else text
        attack_ids = sorted(set(ATTACK_RE.findall(body)))
        return title, attack_ids, fm_cats
    except Exception:
        return "", [], []


def build_registry() -> list[dict]:
    if not _MEOW.exists():
        return []

    entries: list[dict] = []

    for d in sorted(_MEOW.iterdir()):
        if not d.is_dir():
            continue
        name = d.name
        if not re.match(r'^\d{4}-\d{2}-\d{2}-', name):
            continue

        date_str = name[:10]
        slug     = name[11:]

        src_files = [
            f for f in d.iterdir()
            if f.suffix.lower() in _SRC_EXTS and not f.name.endswith(".exe")
        ]
        if not src_files:
            continue

        primary = _pick_primary(src_files)
        if not primary:
            continue

        try:
            src_text = primary.read_text(encoding="utf-8", errors="replace")
        except Exception:
            src_text = ""

        platform    = _detect_platform(src_text)
        compiler    = _detect_compiler(primary, platform)
        extra_libs  = _detect_extra_libs(src_text)
        category, slug_aid = _category_from_slug(slug)

        # category-based override: linux/macos categories are authoritative
        # regardless of what header-scanning returned (ASM files, dlfcn.h on
        # both platforms, kernel modules without standard headers, etc.)
        slug_lower = slug.lower()
        if category == "linux" or (platform == "windows" and re.search(r'linux|kernel.hack', slug_lower)):
            platform = "linux"
            compiler = _detect_compiler(primary, platform)
        elif category == "macos" or (platform == "windows" and re.search(r'mac(?!ro)', slug_lower)):
            platform = "macos"
            compiler = _detect_compiler(primary, platform)

        post = _find_blog_post(date_str, slug)
        title, attack_ids, fm_cats = ("", [], [])
        post_slug = slug
        post_date = date_str  # may differ from meow dir date
        if post:
            title, attack_ids, fm_cats = _parse_blog_post(post)
            post_date = post.stem[:10]           # actual publish date from filename
            post_slug = post.stem[11:]           # actual slug from filename

        if not title:
            title = slug.replace("-", " ").title()
        if not attack_ids and slug_aid:
            attack_ids = [slug_aid]

        has_post = post is not None
        y, m, day = post_date.split("-")
        fm_cat   = fm_cats[0] if fm_cats else ("malware" if platform == "windows" else "tutorial")
        blog_url = f"https://cocomelonc.github.io/{fm_cat}/{y}/{m}/{day}/{post_slug}.html" if has_post else ""

        entries.append({
            "id":          name,
            "date":        date_str,
            "slug":        slug,
            "title":       title,
            "category":    category,
            "color":       _CATEGORY_COLOR.get(category, _CATEGORY_COLOR["other"]),
            "attack_ids":  attack_ids,
            "platform":    platform,
            "compiler":    compiler,
            "extra_libs":  extra_libs,
            "src_path":    str(primary),
            "src_name":    primary.name,
            "all_sources": [{"name": f.name, "path": str(f)} for f in sorted(src_files)],
            "snippet":     _read_snippet(primary),
            "blog_url":    blog_url,
            "has_post":    has_post,
            "compilable":  compiler not in ("nasm", "nim"),
        })

    entries.sort(key=lambda x: x["date"], reverse=True)

    # deduplicate: same slug → keep the one with a post; if tied, keep newer date
    seen_slugs: dict[str, int] = {}
    deduped: list[dict] = []
    for e in entries:
        prev_idx = seen_slugs.get(e["slug"])
        if prev_idx is None:
            seen_slugs[e["slug"]] = len(deduped)
            deduped.append(e)
        else:
            prev = deduped[prev_idx]
            # prefer the entry with a post; otherwise keep the newer date (entries sorted desc)
            if e["has_post"] and not prev["has_post"]:
                deduped[prev_idx] = e
    entries = deduped

    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    _CACHE.write_text(json.dumps(entries, separators=(",", ":")))
    return entries


def scan_all(force: bool = False) -> list[dict]:
    if not force and _CACHE.exists():
        try:
            return json.loads(_CACHE.read_text())
        except Exception:
            pass
    return build_registry()


def get_module(module_id: str) -> Optional[dict]:
    for m in scan_all():
        if m["id"] == module_id:
            return m
    return None


def get_by_category(category: str) -> list[dict]:
    return [e for e in scan_all() if e["category"] == category]


def get_stats() -> dict:
    modules = scan_all()
    cats: dict[str, int]      = {}
    platforms: dict[str, int] = {}
    attack_ids: set[str]      = set()
    for m in modules:
        cats[m["category"]]    = cats.get(m["category"], 0) + 1
        platforms[m["platform"]] = platforms.get(m["platform"], 0) + 1
        attack_ids.update(m["attack_ids"])
    return {
        "total":      len(modules),
        "categories": sorted(cats.items(), key=lambda x: -x[1]),
        "platforms":  dict(platforms),
        "attack_ids": len(attack_ids),
        "colors":     _CATEGORY_COLOR,
    }


def coverage_map() -> dict:
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent))
        from mitre import PEEKABOO_MODULES
    except Exception:
        PEEKABOO_MODULES = {}

    registry = scan_all()

    library_map: dict[str, list[str]] = {}
    for entry in registry:
        for aid in entry["attack_ids"]:
            library_map.setdefault(aid, []).append(entry["id"])

    all_ids = set(PEEKABOO_MODULES.keys()) | set(library_map.keys())
    result: dict[str, dict] = {}
    for aid in sorted(all_ids):
        result[aid] = {
            "peekaboo": aid in PEEKABOO_MODULES,
            "library":  library_map.get(aid, []),
            "count":    len(library_map.get(aid, [])),
        }
    return result
