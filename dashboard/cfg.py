"""
peekaboo central config loader.

Reads `.env` once at import time (python-dotenv). Returns dicts shaped exactly
like the old config/*.json files, so callers that did

    cfg = _load_config("telegram_config")
    token = cfg["bot_token"]

keep working without code changes - they just call `cfg.get("telegram_config")`.

`.env` is the single source of truth. The Settings panel is read-only.
"""
from __future__ import annotations
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

_ENV_PATH = Path(__file__).parent.parent / ".env"
load_dotenv(_ENV_PATH)

# config name -> {json_field: env_var}
_SCHEMA: dict[str, dict[str, str]] = {
    "ollama_config": {
        "base_url":                "OLLAMA_BASE_URL",
        "model":                   "OLLAMA_MODEL",
        "embedding_base_url":      "OLLAMA_EMBED_BASE_URL",
        "embedding_model":         "OLLAMA_EMBED_MODEL",
        "bearer_token":            "OLLAMA_BEARER_TOKEN",
        "temperature":             "OLLAMA_TEMPERATURE",
        "top_p":                   "OLLAMA_TOP_P",
        "num_thread":              "OLLAMA_NUM_THREAD",
        "context_posts":           "OLLAMA_CONTEXT_POSTS",
        "context_posts_technical": "OLLAMA_CONTEXT_POSTS_TECHNICAL",
        "num_ctx":                 "OLLAMA_NUM_CTX",
        "num_predict":             "OLLAMA_NUM_PREDICT",
        "max_snippet_lines":       "OLLAMA_MAX_SNIPPET_LINES",
        "fallback_snippets":       "OLLAMA_FALLBACK_SNIPPETS",
        "keep_alive":              "OLLAMA_KEEP_ALIVE",
    },
    "malpedia_config": {
        "api_token": "MALPEDIA_API_TOKEN",
    },
    "virustotal_config": {
        "vt_api_key": "VT_API_KEY",
        "file_id":    "VT_FILE_ID",
    },
    "telegram_config": {
        "bot_token": "TELEGRAM_BOT_TOKEN",
        "chat_id":   "TELEGRAM_CHAT_ID",
    },
    "github_config": {
        "github_token": "GITHUB_TOKEN",
        "repo_owner":   "GITHUB_REPO_OWNER",
        "repo_name":    "GITHUB_REPO_NAME",
        "issue_number": "GITHUB_ISSUE_NUMBER",
    },
    "bitbucket_config": {
        "bitbucket_token_base64": "BITBUCKET_TOKEN_BASE64",
        "bitbucket_workspace":    "BITBUCKET_WORKSPACE",
        "bitbucket_repo":         "BITBUCKET_REPO",
    },
    "slack_config": {
        "webhook_url": "SLACK_WEBHOOK_URL",
    },
    "azure_config": {
        "azure_org":     "AZURE_ORG",
        "azure_project": "AZURE_PROJECT",
        "azure_pat":     "AZURE_PAT",
    },
    "angelcam_config": {
        "api_key": "ANGELCAM_API_KEY",
    },
    "apt_pipeline_config": {
        "compile_each":     "APT_PIPELINE_COMPILE_EACH",
        "max_stages":       "APT_PIPELINE_MAX_STAGES",
        "ollama_narration": "APT_PIPELINE_OLLAMA_NARRATION",
        "ollama_base_url":  "APT_PIPELINE_OLLAMA_BASE_URL",
        "ollama_model":     "APT_PIPELINE_OLLAMA_MODEL",
    },
}


_SECRET_FIELDS = {
    "bot_token", "github_token", "api_key", "api_token",
    "bearer_token", "bitbucket_token_base64", "vt_api_key", "azure_pat",
}


def get(name: str) -> Optional[dict]:
    """Return the config dict for the given (legacy) name, or None if unknown."""
    schema = _SCHEMA.get(name)
    if schema is None:
        return None
    return {field: os.getenv(env_var, "") for field, env_var in schema.items()}


def names() -> list[str]:
    """List of all known config names - drives the Settings panel."""
    return sorted(_SCHEMA.keys())


def masked(name: str) -> Optional[dict]:
    """Like get(), but masks fields that look like secrets - for UI display."""
    cfg = get(name)
    if cfg is None:
        return None
    out = dict(cfg)
    for k in list(out.keys()):
        if k in _SECRET_FIELDS and out[k]:
            v = str(out[k])
            out[k] = v[:4] + "***" if len(v) > 4 else "***"
    return out
