"""
VirusTotal v3 scanner - peekaboo dashboard module
Reads API key from config/virustotal_config.json
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

try:
    import requests as _req
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

_CFG = Path(__file__).parent.parent / "config" / "virustotal_config.json"
_VT_URL = "https://www.virustotal.com/api/v3"


def _api_key() -> str:
    try:
        cfg = json.loads(_CFG.read_text())
        return cfg.get("vt_api_key", "")
    except Exception:
        return ""


def _headers() -> dict:
    return {
        "x-apikey": _api_key(),
        "User-Agent": "peekaboo-vtscan/2.0",
        "Accept-Encoding": "gzip, deflate",
    }


def upload_file(filepath: Path) -> dict:
    """Upload a file to VT, returning analysis_id or cached results if already known."""
    if not HAS_REQUESTS:
        return {"ok": False, "error": "requests not installed"}
    key = _api_key()
    if not key or key in ("api_key", ""):
        return {"ok": False, "error": "VirusTotal API key not configured"}
    filepath = Path(filepath)
    if not filepath.exists():
        return {"ok": False, "error": f"file not found: {filepath.name}"}

    with filepath.open("rb") as fh:
        data = fh.read()
    sha256 = hashlib.sha256(data).hexdigest()

    # check if VT already has this file
    try:
        r = _req.get(f"{_VT_URL}/files/{sha256}", headers=_headers(), timeout=15)
        if r.status_code == 200:
            attrs = r.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            if stats:
                return {
                    "ok": True,
                    "cached": True,
                    "sha256": sha256,
                    "size": len(data),
                    "name": attrs.get("meaningful_name", filepath.name),
                    "file_type": attrs.get("type_description", ""),
                    "stats": stats,
                    "results": attrs.get("last_analysis_results", {}),
                }
    except Exception:
        pass

    # upload fresh
    try:
        with filepath.open("rb") as fh:
            r = _req.post(
                f"{_VT_URL}/files",
                headers=_headers(),
                files={"file": (filepath.name, fh)},
                timeout=60,
            )
        if r.status_code != 200:
            return {"ok": False, "error": f"upload failed: HTTP {r.status_code}"}
        analysis_id = r.json()["data"]["id"]
        return {
            "ok": True,
            "cached": False,
            "analysis_id": analysis_id,
            "sha256": sha256,
            "size": len(data),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def poll_analysis(analysis_id: str) -> dict:
    """Poll one analysis by ID. Returns status and results when completed."""
    if not HAS_REQUESTS:
        return {"ok": False, "error": "requests not installed"}
    try:
        r = _req.get(f"{_VT_URL}/analyses/{analysis_id}", headers=_headers(), timeout=15)
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        attrs = r.json()["data"]["attributes"]
        status = attrs.get("status", "queued")
        if status == "completed":
            return {
                "ok": True,
                "status": "completed",
                "stats": attrs.get("stats", {}),
                "results": attrs.get("results", {}),
            }
        return {"ok": True, "status": status}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def get_by_hash(sha256: str) -> dict:
    """Fetch existing file report by SHA256 hash."""
    if not HAS_REQUESTS:
        return {"ok": False, "error": "requests not installed"}
    try:
        r = _req.get(f"{_VT_URL}/files/{sha256}", headers=_headers(), timeout=15)
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        attrs = r.json()["data"]["attributes"]
        return {
            "ok": True,
            "sha256": sha256,
            "name": attrs.get("meaningful_name", ""),
            "file_type": attrs.get("type_description", ""),
            "stats": attrs.get("last_analysis_stats", {}),
            "results": attrs.get("last_analysis_results", {}),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}
