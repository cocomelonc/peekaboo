"""
peekaboo AI chatbot - direct Ollama gateway (whiskers-style)
One canned response: "what is peekaboo?"
Everything else -> POST {OLLAMA_BASE_URL}/api/chat, streamed.
"""
from __future__ import annotations
import json
import re
import urllib.request
from pathlib import Path
from typing import Generator

KB_FILE              = Path(__file__).parent / "knowledge_base.json"
OLLAMA_MODEL_DEFAULT = "qwen25-coder-offensive:v1-q8"


# -- system prompt ---------------------------------------------------------------

_SYSTEM = """/no_think

You are peekaboo AI Assistant - a concise technical expert on malware development,
threat simulation, and the peekaboo framework (by @cocomelonc).

Answer fast and technically. Include code when relevant. Map to MITRE ATT&CK when obvious.
Do NOT output <think> blocks. Do NOT write long tutorials unless explicitly asked.
"""


# -- config ----------------------------------------------------------------------

import cfg as _cfg


def _coerce(d: dict, *, ints: tuple = (), floats: tuple = ()) -> dict:
    for k in ints:
        v = d.get(k)
        if isinstance(v, str) and v:
            try:
                d[k] = int(v)
            except ValueError:
                pass
    for k in floats:
        v = d.get(k)
        if isinstance(v, str) and v:
            try:
                d[k] = float(v)
            except ValueError:
                pass
    return d


def _get_ollama_config() -> dict:
    cfg = _cfg.get("ollama_config") or {}
    defaults = {
        "base_url":    "http://localhost:11434",
        "model":       OLLAMA_MODEL_DEFAULT,
        "temperature": 0.15,
        "top_p":       0.8,
        "num_thread":  8,
        "num_ctx":     8192,
        "num_predict": -1,
        "keep_alive":  "10m",
    }
    for k, v in defaults.items():
        if not cfg.get(k):
            cfg[k] = v
    _coerce(cfg,
            ints=("num_thread", "num_ctx", "num_predict"),
            floats=("temperature", "top_p"))
    return cfg


def _headers(cfg: dict) -> dict:
    h = {"Content-Type": "application/json"}
    token = str(cfg.get("bearer_token") or "").strip()
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


# -- canned: only "what is peekaboo?" -------------------------------------------

_PEEKABOO_RE = re.compile(
    r"what is peekaboo|what'?s peekaboo|explain peekaboo|"
    r"what('s| is) this (framework|tool|project)",
    re.I,
)

_PEEKABOO_ANSWER = """\
## peekaboo - APT Simulation Framework

**peekaboo** is an open-source threat simulation and malware development research \
framework by **@cocomelonc**, built for red team education and defensive \
implementation research.

### technique coverage

| Category | ATT&CK | Techniques |
|---|---|---|
| **C2 channels** | T1102, T1071 | Telegram, GitHub Issues, Bitbucket, VirusTotal abuse |
| **Process injection** | T1055 | VirtualAllocEx, EnumDesktopsA, APC, section mapping |
| **AV/EDR bypass** | T1027, T1562 | Direct syscalls, API hashing, AMSI patch, unhooking |
| **Payload crypto** | T1027, T1140 | Speck, FEAL-8, MARS, Treyfer, TEA, XTEA, Camellia… |
| **Persistence** | T1547, T1574 | Registry Run, Winlogon, DLL hijacking, screensaver |
| **Exfiltration** | T1041 | Stealer + C2 channel combos |

### dashboard panels

- **Builder** - compile technique modules (C/C++/Nim/ASM) with custom options
- **Shellcode** - extract, inspect, and process raw shellcode from builds
- **Module Library** - browse all ~300 techniques with MITRE mapping and blog links
- **Samples** - manage compiled binaries; generate YARA rules per sample
- **APT Campaign** - chain modules into a full kill-chain simulation pipeline
- **VirusTotal** - scan builds or samples, track AV detection rates
- **YARA** - generate and test YARA signatures from compiled samples
- **Artifact Map** - visual ATT&CK coverage map built from Sigma rules
- **MITRE ATT&CK** - browse techniques, groups, and implementation status
- **Malpedia** - threat intel pivot: families, actors, YARA, semantic search

ask me any technical question and I'll answer with code-level detail."""


def _stream_canned(text: str) -> Generator[str, None, None]:
    import time
    words = text.split(" ")
    buf: list[str] = []
    for i, w in enumerate(words):
        buf.append(w)
        if len(buf) >= 6 or i == len(words) - 1:
            yield " ".join(buf) + (" " if i < len(words) - 1 else "")
            buf = []
            time.sleep(0.012)


# -- Ollama gateway (whiskers-style) --------------------------------------------

def _stream_ollama(messages: list[dict]) -> Generator[str, None, None]:
    cfg      = _get_ollama_config()
    base_url = cfg["base_url"].rstrip("/")

    yield {"status": "generating", "msg": "thinking..."}

    payload = json.dumps({
        "model":      cfg["model"],
        "stream":     True,
        "think":      False,
        "keep_alive": cfg.get("keep_alive", "10m"),
        "options": {
            "temperature": cfg.get("temperature", 0.15),
            "num_predict": cfg.get("num_predict", -1),
            "num_thread":  cfg.get("num_thread", 8),
            "top_p":       cfg.get("top_p", 0.8),
        },
        "messages": [{"role": "system", "content": _SYSTEM}] + messages[-8:],
    }).encode()

    try:
        req = urllib.request.Request(
            f"{base_url}/api/chat", data=payload,
            headers=_headers(cfg), method="POST",
        )
        with urllib.request.urlopen(req, timeout=300) as resp:
            for raw in resp:
                line = raw.decode("utf-8").strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError:
                    continue
                token = chunk.get("message", {}).get("content", "")
                if token:
                    yield token
                if chunk.get("done"):
                    break
    except urllib.error.URLError as e:
        yield f"[=^..^=] Ollama offline: {e}. Is Ollama running?"
    except Exception as e:
        yield f"[=^..^=] error: {e}"


def _ollama_available() -> tuple[bool, str]:
    cfg      = _get_ollama_config()
    base_url = cfg["base_url"].rstrip("/")
    model    = cfg["model"]
    try:
        req = urllib.request.Request(
            f"{base_url}/api/tags", headers=_headers(cfg), method="GET"
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data  = json.loads(resp.read())
            names = [m["name"] for m in data.get("models", [])]
            if any(model.split(":")[0] in n for n in names):
                return True, model
            return False, f"{model} not pulled"
    except Exception:
        return False, "ollama offline"


# -- public interface -----------------------------------------------------------

def stream_chat(messages: list[dict], provider: str = "ollama") -> Generator[str, None, None]:
    last = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), "")
    if _PEEKABOO_RE.search(last.strip()):
        yield {"status": "canned", "msg": "instant answer"}
        yield from _stream_canned(_PEEKABOO_ANSWER)
        return
    yield from _stream_ollama(messages)


def has_knowledge_base() -> bool:
    return KB_FILE.exists() and KB_FILE.stat().st_size > 1000


def kb_info() -> dict:
    if not KB_FILE.exists():
        return {"status": "not_indexed", "posts": 0}
    try:
        kb = json.loads(KB_FILE.read_text())
        ts = kb.get("indexed_at", "")
        return {"status": "ready", "posts": kb.get("post_count", 0),
                "indexed_at": ts, "last_updated": ts, "source": kb.get("source", "")}
    except Exception:
        return {"status": "error", "posts": 0}


def providers_status() -> dict:
    ok, model = _ollama_available()
    cfg = _get_ollama_config()
    return {
        "ollama": {
            "available":  ok,
            "model":      model,
            "configured": bool(cfg.get("base_url") and cfg.get("model")),
            "auth":       "bearer" if cfg.get("bearer_token") else "none",
        },
    }
