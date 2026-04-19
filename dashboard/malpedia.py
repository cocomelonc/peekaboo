"""
peekaboo Malpedia integration
reports, APT threat actors, malware families
https://malpedia.caad.fkie.fraunhofer.de
"""
from __future__ import annotations
import json
from pathlib import Path

_BASE          = Path(__file__).parent.parent
_CONFIG        = _BASE / "config" / "malpedia_config.json"
_ACTORS_CACHE  = _BASE / "data" / "malpedia_actors_cache.json"
_FAMILIES_CACHE = _BASE / "data" / "malpedia_families_cache.json"

_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    try:
        from malpediaclient import Client
        cfg = {}
        if _CONFIG.exists():
            cfg = json.loads(_CONFIG.read_text())
        token = cfg.get("api_token", "").strip()
        _client = Client(apitoken=token) if token else Client()
        return _client
    except Exception as e:
        print(f"[malpedia] client init error: {e}")
        return None


def available() -> bool:
    try:
        import malpediaclient  # noqa
        return True
    except ImportError:
        return False


def get_status() -> dict:
    c = _get_client()
    if not c:
        return {"ok": False, "error": "malpediaclient not available"}
    try:
        v = c.get_version()
        cfg = json.loads(_CONFIG.read_text()) if _CONFIG.exists() else {}
        token = cfg.get("api_token", "").strip()
        return {
            "ok":             True,
            "version":        v.get("version"),
            "date":           v.get("date"),
            "authenticated":  bool(token),
            "actors_cached":  _ACTORS_CACHE.exists(),
            "families_cached": _FAMILIES_CACHE.exists(),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def list_actors(force_refresh: bool = False) -> list[str]:
    if not force_refresh and _ACTORS_CACHE.exists():
        try:
            return json.loads(_ACTORS_CACHE.read_text())
        except Exception:
            pass
    c = _get_client()
    if not c:
        return []
    try:
        actors = c.list_actors()
        if isinstance(actors, list):
            actors = sorted(actors)
        _ACTORS_CACHE.write_text(json.dumps(actors, separators=(",", ":")))
        return actors
    except Exception as e:
        print(f"[malpedia] list_actors error: {e}")
        return []


def list_families(force_refresh: bool = False) -> list[str]:
    if not force_refresh and _FAMILIES_CACHE.exists():
        try:
            return json.loads(_FAMILIES_CACHE.read_text())
        except Exception:
            pass
    c = _get_client()
    if not c:
        return []
    try:
        fams = c.list_families()
        if isinstance(fams, list):
            fams = sorted(fams)
        elif isinstance(fams, dict):
            fams = sorted(fams.keys())
        _FAMILIES_CACHE.write_text(json.dumps(fams, separators=(",", ":")))
        return fams
    except Exception as e:
        print(f"[malpedia] list_families error: {e}")
        return []


def get_actor(actor_id: str) -> dict:
    c = _get_client()
    if not c:
        return {"error": "client unavailable"}
    try:
        raw  = c.get_actor(actor_id)
        meta = raw.get("meta", {})
        return {
            "id":           actor_id,
            "name":         raw.get("value", actor_id),
            "uuid":         raw.get("uuid", ""),
            "description":  raw.get("description", ""),
            "country":      meta.get("country", meta.get("cfr-suspected-state-sponsor", "")),
            "synonyms":     meta.get("synonyms", []),
            "targets":      meta.get("cfr-target-category", []),
            "victims":      meta.get("cfr-suspected-victims", []),
            "incident_type": meta.get("cfr-type-of-incident", ""),
            "refs":         meta.get("refs", []),
            "families":     _format_actor_families(raw.get("families", {})),
            "related":      [r.get("dest-uuid", "") for r in raw.get("related", [])],
        }
    except Exception as e:
        return {"error": str(e)}


def _format_actor_families(families: dict) -> list[dict]:
    result = []
    for fam_id, data in (families.items() if isinstance(families, dict) else []):
        result.append({
            "id":   fam_id,
            "urls": data.get("urls", [])[:3] if isinstance(data, dict) else [],
        })
    return sorted(result, key=lambda x: x["id"])


def get_family(family_id: str) -> dict:
    c = _get_client()
    if not c:
        return {"error": "client unavailable"}
    try:
        raw = c.get_family(family_id)
        return {
            "id":          family_id,
            "name":        raw.get("common_name", family_id),
            "uuid":        raw.get("uuid", ""),
            "description": raw.get("description", ""),
            "alt_names":   raw.get("alt_names", []),
            "attribution": raw.get("attribution", []),
            "updated":     raw.get("updated", ""),
            "urls":        raw.get("urls", [])[:10],
            "notes":       raw.get("notes", [])[:5],
        }
    except Exception as e:
        return {"error": str(e)}


def _extract_ids(result) -> list[str]:
    if not result:
        return []
    if isinstance(result, list):
        out = []
        for item in result:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                out.append(item.get("name") or item.get("id") or str(item))
        return out
    return []


def find_actor(needle: str) -> list[str]:
    c = _get_client()
    if not c:
        return []
    try:
        return _extract_ids(c.find_actor(needle))
    except Exception as e:
        print(f"[malpedia] find_actor error: {e}")
        needle_l = needle.lower()
        return [a for a in list_actors() if needle_l in a.lower()]


def find_family(needle: str) -> list[str]:
    c = _get_client()
    if not c:
        return []
    try:
        return _extract_ids(c.find_family(needle))
    except Exception as e:
        print(f"[malpedia] find_family error: {e}")
        needle_l = needle.lower()
        return [f for f in list_families() if needle_l in f.lower()]
