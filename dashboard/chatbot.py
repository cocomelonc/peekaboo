"""
peekaboo AI chatbot
supports: Claude (Anthropic), Gemini (Google), local Ollama (RAG)
knowledge base: ~/hacking/meow local codebase + semantic post index
focused on: C2 channels, binary delivery, malware dev, threat simulation
"""
from __future__ import annotations
import json
import os
import urllib.request
from pathlib import Path
from typing import Generator

KB_FILE    = Path(__file__).parent / "knowledge_base.json"
CONFIG_DIR = Path(__file__).parent.parent / "config"

CLAUDE_MODEL = "claude-opus-4-6"
GEMINI_MODEL_DEFAULT = "gemini-2.0-flash"
OLLAMA_MODEL_DEFAULT = "qwen3:4b"

# ── system prompt ──────────────────────────────────────────────────────────────
_SYSTEM_BASE = """You are Peekaboo AI - an educational assistant for the Peekaboo Threat Simulation Framework, created by Zhassulan Zhussupov (@cocomelonc).

Your knowledge is grounded in the ~/hacking/meow codebase - real, working code covering:
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
- **VirusTotal**: creative abuse - encode command/payload in file metadata or comments
- **Discord/Slack webhooks**: outbound-only but can host files for retrieval

Always frame content as **educational and defensive** - help researchers understand:
1. How the technique works mechanically
2. What telemetry it generates (what defenders can detect)
3. Which MITRE ATT&CK techniques apply
4. How to detect/prevent it in a blue team context

Be direct, technical, and practical. Reference specific topic directories (e.g. 2021-09-19-injection-1) when relevant.
Avoid vague explanations - give concrete details about APIs, memory layouts, WinAPI calls, and actual code from the knowledge base.
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
        except Exception as e:
            print ("get gemini config: ", str(e))
    return os.environ.get("GEMINI_API_KEY", ""), GEMINI_MODEL_DEFAULT


def _get_ollama_config() -> dict:
    cfg_path = CONFIG_DIR / "ollama_config.json"
    defaults = {
        "base_url":      "http://localhost:11434",
        "model":         OLLAMA_MODEL_DEFAULT,
        "temperature":   0.6,
        "context_posts": 6,
    }
    if cfg_path.exists():
        try:
            defaults.update(json.loads(cfg_path.read_text()))
        except Exception:
            pass
    return defaults


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
            f"\n\n## Knowledge Base: {kb.get('author', '')}",
            f"Source: {kb.get('source', '')}",
            f"Topics indexed: {len(posts)}",
            "---",
        ]
        budget, used = 80_000, 0
        for p in posts:
            ref = p.get("ref") or p.get("url", "")
            chunk = f"\n### {p['title']}\nRef: {ref}\n{p['content']}\n"
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


# ── Ollama RAG streaming ───────────────────────────────────────────────────────

def _rag_context(question: str, n: int = 6) -> str:
    """Retrieve top-n relevant posts via semantic search, return formatted context block."""
    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(__file__))
        from semantic import find_related_posts
        posts = find_related_posts(question, max_results=n)
    except Exception as e:
        print(f"[ollama] rag retrieval error: {e}")
        return ""

    if not posts:
        return ""

    blocks = []
    for p in posts:
        title    = p.get("title", "")
        url      = p.get("blog_url", "")
        cat      = p.get("category", "")
        aids     = ", ".join(p.get("attack_ids", []))
        score    = p.get("score", 0)
        # try to get the code snippet from library cache
        snippet  = _get_snippet_for_post(p)
        block = f"### {title}\n- URL: {url}\n- Category: {cat}"
        if aids:
            block += f"\n- ATT&CK: {aids}"
        block += f"\n- Relevance: {score:.0%}"
        if snippet:
            block += f"\n\n```c\n{snippet}\n```"
        blocks.append(block)

    return "\n\n".join(blocks)


_library_cache: list[dict] | None = None

def _get_library() -> list[dict]:
    global _library_cache
    if _library_cache is not None:
        return _library_cache
    lc = Path(__file__).parent.parent / "data" / "library_cache.json"
    if lc.exists():
        try:
            _library_cache = json.loads(lc.read_text())
            return _library_cache
        except Exception:
            pass
    _library_cache = []
    return _library_cache


def _get_snippet_for_post(post: dict) -> str:
    """Look up a code snippet from library_cache by slug."""
    slug = post.get("slug") or post.get("title", "")
    if not slug:
        return ""
    for entry in _get_library():
        if entry.get("slug") == slug:
            snip = entry.get("snippet", "")
            if snip:
                lines = snip.splitlines()[:35]
                return "\n".join(lines)
    return ""


def _build_ollama_system(context: str) -> str:
    # /no_think disables qwen3 extended thinking mode
    base = "/no_think\n\n" + _SYSTEM_BASE
    if context:
        base += f"""

## Retrieved knowledge base context (most relevant to this question):

{context}

Use this context to give precise, code-grounded answers. Reference blog URLs when citing examples.
"""
    return base


def _stream_ollama(messages: list[dict]) -> Generator[str, None, None]:
    cfg = _get_ollama_config()
    base_url = cfg["base_url"].rstrip("/")
    model    = cfg["model"]
    temp     = cfg.get("temperature", 0.6)
    n_ctx    = cfg.get("context_posts", 6)

    # RAG: embed the latest user message to retrieve context
    last_user = next(
        (m["content"] for m in reversed(messages) if m.get("role") == "user"), ""
    )
    context = _rag_context(last_user, n=n_ctx) if last_user else ""

    system_prompt = _build_ollama_system(context)

    payload = json.dumps({
        "model":   model,
        "stream":  True,
        "think":   False,          # disable extended thinking for qwen3
        "options": {"temperature": temp, "num_predict": 2048},
        "messages": [{"role": "system", "content": system_prompt}] + messages,
    }).encode()

    url = f"{base_url}/api/chat"
    try:
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=300) as resp:
            # qwen3 emits thinking tokens ending with </think> before the real answer
            tokens: list[str] = []
            past_think = False
            emitted_thinking_event = False
            for raw_line in resp:
                line = raw_line.decode("utf-8").strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                    token = chunk.get("message", {}).get("content", "")
                    if token:
                        if past_think:
                            yield token
                        else:
                            if not emitted_thinking_event:
                                yield {"thinking": True}
                                emitted_thinking_event = True
                            tokens.append(token)
                            joined = "".join(tokens)
                            if "</think>" in joined:
                                past_think = True
                                yield {"thinking": False}
                                after = joined.split("</think>", 1)[1]
                                tokens = []
                                if after:
                                    yield after
                    if chunk.get("done"):
                        if not past_think:
                            if emitted_thinking_event:
                                yield {"thinking": False}
                            yield "".join(tokens)
                        break
                except json.JSONDecodeError:
                    continue
    except urllib.error.URLError as e:
        yield f"[!] Ollama connection error: {e}. Is Ollama running?"
    except Exception as e:
        yield f"[!] Ollama error: {e}"


def _ollama_available() -> tuple[bool, str]:
    cfg = _get_ollama_config()
    base_url = cfg["base_url"].rstrip("/")
    model    = cfg["model"]
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            names = [m["name"] for m in data.get("models", [])]
            if any(model.split(":")[0] in n for n in names):
                return True, model
            return False, f"{model} not pulled"
    except Exception:
        return False, "ollama offline"


# ── public interface ───────────────────────────────────────────────────────────

def stream_chat(messages: list[dict], provider: str = "claude") -> Generator[str, None, None]:
    """
    Stream a chat response.
    provider: "claude" | "gemini" | "ollama"
    messages: [{role, content}, ...]
    """
    if provider == "gemini":
        yield from _stream_gemini(messages)
    elif provider == "ollama":
        yield from _stream_ollama(messages)
    else:
        yield from _stream_claude(messages)


def has_knowledge_base() -> bool:
    return KB_FILE.exists() and KB_FILE.stat().st_size > 1000


def kb_info() -> dict:
    if not KB_FILE.exists():
        return {"status": "not_indexed", "posts": 0}
    try:
        kb = json.loads(KB_FILE.read_text())
        return {
            "status":     "ready",
            "posts":      kb.get("post_count", 0),
            "indexed_at": kb.get("indexed_at", ""),
            "source":     kb.get("source", ""),
        }
    except Exception:
        return {"status": "error", "posts": 0}


def providers_status() -> dict:
    """Check which providers are configured."""
    claude_key = _get_anthropic_key()
    gemini_key, gemini_model = _get_gemini_config()
    ollama_ok, ollama_model  = _ollama_available()
    return {
        "claude": {
            "available": bool(claude_key),
            "model":     CLAUDE_MODEL,
        },
        "gemini": {
            "available": bool(gemini_key),
            "model":     gemini_model,
        },
        "ollama": {
            "available": ollama_ok,
            "model":     ollama_model,
        },
    }
