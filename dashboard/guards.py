"""
peekaboo security primitives - import from app.py and other modules.

Three tiny helpers, zero dependencies beyond stdlib + flask:

  safe_child(base, *parts) -> Path | None
      Returns the resolved path only if it stays inside base.
      Replaces string startswith() checks throughout the codebase.

  choice(params, key, allowed, default) -> str
      Validates a user-supplied string against an allowlist.
      Raises ValueError on unknown value.

  require_token() -> Response | None
      Optional per-request token guard for mutating routes.
      No-op when PEEKABOO_API_TOKEN is not set in the environment.
      Apply at the top of any route handler:
          err = require_token()
          if err: return err
"""
from __future__ import annotations
import os
import hmac
from pathlib import Path
from urllib.parse import urlsplit

from flask import jsonify, request


def safe_child(base: Path, *parts: str) -> Path | None:
    """Return base/parts resolved, or None if it escapes base."""
    base = base.resolve()
    p = base.joinpath(*parts).resolve()
    return p if p.is_relative_to(base) else None


def choice(params: dict, key: str, allowed: list, default: str) -> str:
    """Return params[key] if it is in allowed, else raise ValueError."""
    value = params.get(key, default)
    if value not in allowed:
        raise ValueError(f"invalid {key}: {value!r}")
    return value


def require_token():
    """
    Guard for mutating routes: check X-Peekaboo-Token header.
    No-op (returns None) when PEEKABOO_API_TOKEN is not set.
    Returns a 401 Response tuple when the token is wrong.
    """
    token = os.getenv("PEEKABOO_API_TOKEN", "")
    if not token:
        return None
    if request.headers.get("X-Peekaboo-Token") != token:
        return jsonify({"error": "unauthorized"}), 401
    return None


def protect_mutation():
    """Reject cross-site browser writes and require the optional token for API clients."""
    token = os.getenv("PEEKABOO_API_TOKEN", "")
    supplied = request.headers.get("X-Peekaboo-Token", "")
    if token and supplied and hmac.compare_digest(supplied, token):
        return None

    fetch_site = request.headers.get("Sec-Fetch-Site", "").lower()
    if fetch_site == "cross-site":
        return jsonify({"error": "cross-site request rejected"}), 403

    origin = request.headers.get("Origin", "")
    same_origin = fetch_site == "same-origin"
    if origin:
        actual = urlsplit(origin)
        expected = urlsplit(request.host_url)
        same_origin = (actual.scheme, actual.netloc) == (expected.scheme, expected.netloc)
        if not same_origin:
            return jsonify({"error": "origin rejected"}), 403

    # Same-origin dashboard requests are allowed without exposing the API token
    # to JavaScript. Non-browser API clients must send the token when configured.
    if token and not same_origin:
        return jsonify({"error": "unauthorized"}), 401
    return None
