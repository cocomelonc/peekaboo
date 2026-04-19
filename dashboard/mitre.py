"""
peekaboo MITRE ATT&CK + R&D library
auto-scans ~/hacking/cocomelonc.github.io/_posts and ~/hacking/meow
mitreattack-python 5.x + local STIX bundle
"""
from __future__ import annotations
import json
import re
from pathlib import Path

_BASE          = Path(__file__).parent.parent
_MEOW          = Path("/home/cocomelonc/hacking/meow")
_POSTS         = Path("/home/cocomelonc/hacking/cocomelonc.github.io/_posts")
STIX_PATH      = str(_BASE / "data" / "enterprise-attack.json")
_GROUPS_CACHE  = _BASE / "data" / "mitre_groups_cache.json"
_LIBRARY_CACHE = _BASE / "data" / "library_cache.json"

# peekaboo repo implementations - these get a special "implemented" badge
PEEKABOO_MODULES: dict[str, dict] = {
    "T1055": {
        "category": "injection",
        "blog_url": "https://cocomelonc.github.io/tutorial/2021/09/18/malware-injection-1.html",
        "snippet":  _BASE / "malware/injection/virtualallocex/hack.c",
        "module":   "injection/virtualallocex",
    },
    "T1055.004": {
        "category": "injection",
        "blog_url": "https://cocomelonc.github.io/tutorial/2021/10/20/malware-injection-3.html",
        "snippet":  _MEOW / "2021-11-11-malware-injection-3/evil.cpp",
        "module":   "injection/enumdesktopsa",
    },
    "T1055.001": {
        "category": "injection",
        "blog_url": "https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html",
        "snippet":  _BASE / "malware/injection/enumdesktopsa/hack.c",
        "module":   "injection/enumdesktopsa",
    },
    "T1547.001": {
        "category": "persistence",
        "blog_url": "https://cocomelonc.github.io/tutorial/2022/04/20/malware-pers-1.html",
        "snippet":  _BASE / "malware/persistence/registry_run.c",
        "module":   "persistence/registry_run",
    },
    "T1547.004": {
        "category": "persistence",
        "blog_url": "https://cocomelonc.github.io/tutorial/2022/06/12/malware-pers-7.html",
        "snippet":  _BASE / "malware/persistence/winlogon.c",
        "module":   "persistence/winlogon",
    },
    "T1546.002": {
        "category": "persistence",
        "blog_url": "https://cocomelonc.github.io/tutorial/2022/04/26/malware-pers-2.html",
        "snippet":  _BASE / "malware/persistence/screensaver.c",
        "module":   "persistence/screensaver",
    },
    "T1053.005": {
        "category": "persistence",
        "blog_url": "https://cocomelonc.github.io/malware/2025/03/12/malware-pers-27.html",
        "snippet":  _MEOW / "2025-03-12-malware-pers-27/pers.c",
        "module":   None,
    },
    "T1102": {
        "category": "c2",
        "blog_url": "https://cocomelonc.github.io/malware/2024/06/16/malware-trick-40.html",
        "snippet":  _BASE / "malware/stealer/telegram.c",
        "module":   "stealer/telegram",
    },
    "T1041": {
        "category": "c2",
        "blog_url": "https://cocomelonc.github.io/malware/2025/01/19/malware-tricks-44.html",
        "snippet":  _BASE / "malware/stealer/github.c",
        "module":   "stealer/github",
    },
    "T1071": {
        "category": "c2",
        "blog_url": "https://cocomelonc.github.io/malware/2024/06/25/malware-trick-41.html",
        "snippet":  _BASE / "malware/stealer/virustotal.c",
        "module":   "stealer/virustotal",
    },
    "T1071.001": {
        "category": "c2",
        "blog_url": "https://cocomelonc.github.io/malware/2025/08/29/malware-tricks-51.html",
        "snippet":  _BASE / "malware/stealer/bitbucket.c",
        "module":   "stealer/bitbucket",
    },
}

# slug keyword → (category, fallback_attack_id)
_SLUG_RULES: list[tuple[str, str, str | None]] = [
    (r"injection|inject",           "injection",     "T1055"),
    (r"dll.hijack|dllhijack",       "injection",     "T1574.001"),
    (r"malware.pers|pers-\d",       "persistence",   "T1547"),
    (r"mac.+pers|pers.+mac",        "persistence",   None),
    (r"av.evasion|evasion",         "evasion",       "T1027"),
    (r"cryptography|crypto",        "cryptography",  "T1027"),
    (r"hooking",                    "hooking",       "T1056"),
    (r"shellcod",                   "shellcoding",   "T1059"),
    (r"token.theft|token",          "privesc",       "T1134"),
    (r"syscall",                    "syscalls",      "T1106"),
    (r"reverse.shell",              "c2",            "T1059"),
    (r"pivoting",                   "network",       "T1090"),
    (r"linux.hack|linux",           "linux",         None),
    (r"malware.mac|mac.malware|mac","macos",         None),
    (r"android",                    "android",       None),
    (r"malware.trick|trick",        "tricks",        None),
    (r"malware.analysis|analysis",  "analysis",      None),
    (r"mem.forensic|forensic",      "analysis",      None),
    (r"inline.asm|asm",             "evasion",       "T1027"),
    (r"overflow",                   "exploitation",  "T1203"),
    (r"shellcod",                   "shellcoding",   "T1059"),
    (r"hvck",                       "tricks",        None),
    (r"rev.c|simple.rev",           "c2",            "T1059"),
]

_ATTACK_RE = re.compile(r'\bT1\d{3}(?:\.\d{3})?\b')


def _category_from_slug(slug: str) -> tuple[str, str | None]:
    s = slug.lower()
    for pattern, cat, aid in _SLUG_RULES:
        if re.search(pattern, s):
            return cat, aid
    return "other", None


def _find_meow_source(date_str: str) -> str | None:
    if not _MEOW.exists():
        return None
    for d in _MEOW.iterdir():
        if d.is_dir() and d.name.startswith(date_str):
            preferred_stems = {"hack", "evil", "main", "pers", "inject", "mal", "shellcode"}
            for ext in ("*.c", "*.cpp"):
                files = sorted(d.glob(ext))
                preferred = [f for f in files if f.stem in preferred_stems]
                if preferred:
                    return str(preferred[0])
                if files:
                    return str(files[0])
    return None


def _read_snippet(path: str | Path | None, max_lines: int = 40) -> str:
    if not path:
        return ""
    try:
        p = Path(path)
        if not p.exists():
            return ""
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[:max_lines])
    except Exception:
        return ""


def _blog_url(date_str: str, slug: str, categories: list[str]) -> str:
    y, m, d = date_str.split("-")
    cat = categories[0] if categories else "malware"
    return f"https://cocomelonc.github.io/{cat}/{y}/{m}/{d}/{slug}.html"


def build_library_cache() -> list[dict]:
    if not _POSTS.exists():
        return []

    entries = []
    for f in sorted(_POSTS.glob("*.markdown")):
        stem     = f.stem
        date_str = stem[:10]
        slug     = stem[11:]
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # parse front matter
        fm_match = re.match(r'^---\s*\n(.*?)\n---', text, re.DOTALL)
        title, fm_cats = slug.replace("-", " ").title(), []
        if fm_match:
            fm = fm_match.group(1)
            tm = re.search(r'^title:\s*["\']?(.+?)["\']?\s*$', fm, re.MULTILINE)
            if tm:
                title = tm.group(1).strip('"\'')
            fm_cats = re.findall(r'^  - (\S+)', fm, re.MULTILINE)

        body      = text[fm_match.end():] if fm_match else text
        body_aids = sorted(set(_ATTACK_RE.findall(body)))

        category, slug_aid = _category_from_slug(slug)
        attack_ids = body_aids if body_aids else ([slug_aid] if slug_aid else [])

        src_path   = _find_meow_source(date_str)
        blog_url   = _blog_url(date_str, slug, fm_cats)
        peekaboo_m = next((m for aid in attack_ids for m in [PEEKABOO_MODULES.get(aid)] if m), None)

        entry: dict = {
            "date":       date_str,
            "slug":       slug,
            "title":      title,
            "category":   category,
            "attack_ids": attack_ids,
            "blog_url":   blog_url,
            "src_path":   src_path,
            "snippet":    _read_snippet(src_path),
            "module":     peekaboo_m.get("module") if peekaboo_m else None,
            "implemented": peekaboo_m is not None,
        }
        entries.append(entry)

    entries.sort(key=lambda x: x["date"], reverse=True)

    _LIBRARY_CACHE.write_text(json.dumps(entries, separators=(",", ":")))
    print(f"[mitre] library cache: {len(entries)} posts -> {_LIBRARY_CACHE}")
    return entries


def get_library(category: str = "all") -> list[dict]:
    if _LIBRARY_CACHE.exists():
        try:
            entries = json.loads(_LIBRARY_CACHE.read_text())
        except Exception:
            entries = build_library_cache()
    else:
        entries = build_library_cache()

    if category == "all":
        return entries
    return [e for e in entries if e["category"] == category]


# ── ATT&CK data ────────────────────────────────────────────────────────────────

_attack_data              = None
_tech_lookup: dict | None = None


def _load_attack():
    global _attack_data
    if _attack_data is not None:
        return _attack_data
    try:
        from mitreattack.stix20 import MitreAttackData
        _attack_data = MitreAttackData(STIX_PATH)
        return _attack_data
    except Exception as e:
        print(f"[mitre] failed to load STIX bundle: {e}")
        return None


def _build_tech_lookup() -> dict:
    global _tech_lookup
    if _tech_lookup is not None:
        return _tech_lookup
    ma = _load_attack()
    _tech_lookup = {}
    if not ma:
        return _tech_lookup
    try:
        for t in ma.get_techniques(include_subtechniques=True):
            ext_refs = t.get("external_references", [])
            aid = next(
                (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                None,
            )
            if aid:
                _tech_lookup[aid] = t
    except Exception as e:
        print(f"[mitre] tech lookup error: {e}")
    return _tech_lookup


def _extract_tech(item) -> object | None:
    if isinstance(item, dict) and "object" in item:
        return item["object"]
    if isinstance(item, (list, tuple)) and len(item) > 0:
        return item[0]
    return item


def get_groups() -> list[dict]:
    if _GROUPS_CACHE.exists():
        try:
            return json.loads(_GROUPS_CACHE.read_text())
        except Exception:
            pass
    ma = _load_attack()
    if not ma:
        return []
    try:
        result = []
        for g in ma.get_groups():
            result.append({
                "id":      g.get("id", ""),
                "name":    g.get("name", ""),
                "aliases": g.get("aliases", []),
            })
        return sorted(result, key=lambda x: x["name"])
    except Exception as e:
        print(f"[mitre] get_groups error: {e}")
        return []


def get_group_techniques(group_stix_id: str, category: str = "all") -> list[dict]:
    ma = _load_attack()
    if not ma:
        return []
    try:
        fn = getattr(ma, "get_techniques_used_by_group", None) \
          or getattr(ma, "get_techniques_by_group", None)
        if not fn:
            return []

        raw  = fn(group_stix_id)
        seen: set[str]   = set()
        results: list[dict] = []

        for item in raw:
            tech = _extract_tech(item)
            if tech is None:
                continue
            ext_refs  = tech.get("external_references", [])
            attack_id = next(
                (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                None,
            )
            if not attack_id or attack_id in seen:
                continue
            seen.add(attack_id)

            pm  = PEEKABOO_MODULES.get(attack_id)
            cat = pm["category"] if pm else "other"
            if category != "all" and cat != category:
                continue

            tactics = [p["phase_name"] for p in tech.get("kill_chain_phases", [])]
            desc    = (tech.get("description") or "").replace("\n", " ")[:280]

            entry: dict = {
                "attack_id":   attack_id,
                "name":        tech.get("name", ""),
                "description": desc,
                "tactics":     tactics,
                "category":    cat,
                "has_example": pm is not None,
            }
            if pm:
                entry["blog_url"] = pm["blog_url"]
                entry["module"]   = pm.get("module")
                entry["snippet"]  = _read_snippet(pm["snippet"])

            results.append(entry)

        return sorted(results, key=lambda x: x["attack_id"])

    except Exception as e:
        print(f"[mitre] get_group_techniques error: {e}")
        return []


def get_all_techniques() -> list[dict]:
    lookup = _build_tech_lookup()
    results = []
    for attack_id, pm in PEEKABOO_MODULES.items():
        stix = lookup.get(attack_id)
        desc, tactics = "", []
        if stix:
            desc    = (stix.get("description") or "").replace("\n", " ")[:320]
            tactics = [p["phase_name"] for p in stix.get("kill_chain_phases", [])]
        results.append({
            "attack_id":   attack_id,
            "name":        stix.get("name", attack_id) if stix else attack_id,
            "category":    pm["category"],
            "description": desc,
            "tactics":     tactics,
            "blog_url":    pm["blog_url"],
            "module":      pm.get("module"),
            "snippet":     _read_snippet(pm["snippet"]),
            "has_example": True,
        })
    return sorted(results, key=lambda x: (x["category"], x["attack_id"]))


def available() -> bool:
    return Path(STIX_PATH).exists() or _GROUPS_CACHE.exists()
