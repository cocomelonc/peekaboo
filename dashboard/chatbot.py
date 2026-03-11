"""
peekaboo AI chatbot
supports: Claude (Anthropic) and Gemini (Google)
knowledge base: cocomelonc.github.io blog posts
focused on: C2 channels, binary delivery, malware dev, threat simulation
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Generator

KB_FILE    = Path(__file__).parent / "knowledge_base.json"
CONFIG_DIR = Path(__file__).parent.parent / "config"

CLAUDE_MODEL = "claude-opus-4-6"
GEMINI_MODEL_DEFAULT = "gemini-2.0-flash"

# ── system prompt ──────────────────────────────────────────────────────────────
_SYSTEM_BASE = """You are Peekaboo AI — an educational assistant for the Peekaboo Threat Simulation Framework, created by Zhassulan Zhussupov (@cocomelonc).

Your knowledge is grounded in cocomelonc.github.io — a deep-dive blog covering:
- **C2 (Command & Control) channels**: GitHub Issues/Comments, Telegram webhooks, Bitbucket, VirusTotal, Discord/Slack abuse
- **Binary delivery via C2**: how implants receive and execute dropped payloads from C2 servers
- **Process injection**: VirtualAllocEx, EnumDesktopsA callbacks, APC injection, and more
- **Payload encryption/obfuscation**: Speck, FEAL-8, Lucifer, MARS, Treyfer, custom XOR
- **Windows persistence**: Registry Run keys, Winlogon, DLL hijacking, scheduled tasks
- **AV/EDR bypass techniques**: syscalls, API hashing, string encryption, unhooking
- **Stealer/exfiltration**: collecting system info and exfiltrating via covert channels
- **Detection engineering**: how blue teams detect these techniques (telemetry, SIGMA rules)
- **MITRE ATT&CK mapping**: TTP mapping for each technique

The Peekaboo framework currently supports:
- Crypto: Speck, FEAL-8, Lucifer, MARS, Treyfer
- Injection: VirtualAllocEx, EnumDesktopsA
- Persistence: Registry Run, Winlogon
- C2/Stealer: Telegram, GitHub, Bitbucket, VirusTotal

## C2 binary delivery (key topic for demos):
C2 binary drop/delivery means the attacker infrastructure pushes a payload to the victim:
- **Telegram**: bot sends binary file via sendDocument API; victim checks for new docs
- **GitHub**: implant polls Issues/Releases/Gists for new payload; downloads via raw URL
- **Bitbucket**: implant polls repo for new commits containing encoded payloads
- **VirusTotal**: creative abuse — encode command/payload in file metadata or comments
- **Discord/Slack webhooks**: outbound-only but can host files for retrieval

Always frame content as **educational and defensive** — help researchers understand:
1. How the technique works mechanically
2. What telemetry it generates (what defenders can detect)
3. Which MITRE ATT&CK techniques apply
4. How to detect/prevent it in a blue team context

Be direct, technical, and practical. Reference specific blog posts when relevant.
Avoid vague explanations — give concrete details about APIs, memory layouts, WinAPI calls.
"""


# ── config loaders ─────────────────────────────────────────────────────────────

def _get_anthropic_key() -> str:
    cfg_path = CONFIG_DIR / "anthropic_config.json"
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text())
            key = data.get("api_key", "")
            if key and not key.startswith("sk-ant-xxx"):
                return key
        except Exception:
            pass
    return os.environ.get("ANTHROPIC_API_KEY", "")


def _get_gemini_config() -> tuple[str, str]:
    """Returns (api_key, model)."""
    cfg_path = CONFIG_DIR / "gemini_config.json"
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text())
            key   = data.get("api_key", "")
            model = data.get("model", GEMINI_MODEL_DEFAULT)
            if key and not key.startswith("AIzaxxx"):
                return key, model
        except Exception:
            pass
    return os.environ.get("GEMINI_API_KEY", ""), GEMINI_MODEL_DEFAULT


# ── knowledge base ─────────────────────────────────────────────────────────────

def _load_knowledge_base() -> str:
    if not KB_FILE.exists():
        return ""
    try:
        kb = json.loads(KB_FILE.read_text())
        posts = kb.get("posts", [])
        if not posts:
            return ""
        lines = [
            f"\n\n## Knowledge Base: {kb.get('author', '')} blog",
            f"Source: {kb.get('blog', '')}",
            f"Posts indexed: {len(posts)}",
            "---",
        ]
        budget, used = 80_000, 0
        for p in posts:
            chunk = f"\n### {p['title']}\nURL: {p['url']}\n{p['content']}\n"
            if used + len(chunk) > budget:
                break
            lines.append(chunk)
            used += len(chunk)
        return "\n".join(lines)
    except Exception:
        return ""


def _build_claude_system() -> list[dict] | str:
    """System prompt with optional prompt-cached KB block for Claude."""
    kb_text = _load_knowledge_base()
    if not kb_text:
        return _SYSTEM_BASE
    return [
        {"type": "text", "text": _SYSTEM_BASE},
        {"type": "text", "text": kb_text, "cache_control": {"type": "ephemeral"}},
    ]


def _build_gemini_system() -> str:
    """Single system string for Gemini (no block format)."""
    kb_text = _load_knowledge_base()
    if not kb_text:
        return _SYSTEM_BASE
    return _SYSTEM_BASE + kb_text


# ── Claude streaming ───────────────────────────────────────────────────────────

def _stream_claude(messages: list[dict]) -> Generator[str, None, None]:
    import anthropic

    api_key = _get_anthropic_key()
    if not api_key:
        yield "[!] Anthropic API key not set. Add it to config/anthropic_config.json"
        return

    client = anthropic.Anthropic(api_key=api_key)
    try:
        with client.messages.stream(
            model=CLAUDE_MODEL,
            max_tokens=2048,
            system=_build_claude_system(),
            messages=messages,
            thinking={"type": "adaptive"},
        ) as stream:
            for text in stream.text_stream:
                yield text
    except anthropic.AuthenticationError:
        yield "[!] Invalid Anthropic API key. Check config/anthropic_config.json"
    except anthropic.APIConnectionError:
        yield "[!] Anthropic connection error. Check your internet."
    except Exception as e:
        yield f"[!] Claude error: {e}"


# ── Gemini streaming ───────────────────────────────────────────────────────────

def _stream_gemini(messages: list[dict]) -> Generator[str, None, None]:
    from google import genai
    from google.genai import types

    api_key, model = _get_gemini_config()
    if not api_key:
        yield "[!] Gemini API key not set. Add it to config/gemini_config.json"
        return

    # convert messages to Gemini Content format
    contents = []
    for m in messages:
        role = "user" if m["role"] == "user" else "model"
        contents.append(types.Content(role=role, parts=[types.Part(text=m["content"])]))

    client = genai.Client(api_key=api_key)
    try:
        response = client.models.generate_content_stream(
            model=model,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=_build_gemini_system(),
                max_output_tokens=2048,
                temperature=0.7,
            ),
        )
        for chunk in response:
            if chunk.text:
                yield chunk.text
    except Exception as e:
        err = str(e)
        if "API_KEY_INVALID" in err or "API key" in err:
            yield f"[!] Invalid Gemini API key. Check config/gemini_config.json"
        else:
            yield f"[!] Gemini error: {e}"


# ── public interface ───────────────────────────────────────────────────────────

def stream_chat(messages: list[dict], provider: str = "claude") -> Generator[str, None, None]:
    """
    Stream a chat response.
    provider: "claude" | "gemini"
    messages: [{role, content}, ...]
    """
    if provider == "gemini":
        yield from _stream_gemini(messages)
    else:
        yield from _stream_claude(messages)


def has_knowledge_base() -> bool:
    return KB_FILE.exists() and KB_FILE.stat().st_size > 1000


def kb_info() -> dict:
    if not KB_FILE.exists():
        return {"status": "not_scraped", "posts": 0}
    try:
        kb = json.loads(KB_FILE.read_text())
        return {
            "status":     "ready",
            "posts":      kb.get("post_count", 0),
            "scraped_at": kb.get("scraped_at", ""),
            "blog":       kb.get("blog", ""),
        }
    except Exception:
        return {"status": "error", "posts": 0}


def providers_status() -> dict:
    """Check which providers are configured."""
    claude_key = _get_anthropic_key()
    gemini_key, gemini_model = _get_gemini_config()
    return {
        "claude": {
            "available": bool(claude_key),
            "model":     CLAUDE_MODEL,
        },
        "gemini": {
            "available": bool(gemini_key),
            "model":     gemini_model,
        },
    }
