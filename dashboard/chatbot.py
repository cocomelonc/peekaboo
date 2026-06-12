"""
peekaboo AI chatbot
supports: Claude (Anthropic), Gemini (Google), local Ollama (RAG)
knowledge base: ~/hacking/meow local codebase + semantic post index
focused on: C2 channels, binary delivery, malware dev, threat simulation
"""
from __future__ import annotations
import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Generator

KB_FILE    = Path(__file__).parent / "knowledge_base.json"
CONFIG_DIR = Path(__file__).parent.parent / "config"

CLAUDE_MODEL         = "claude-opus-4-6"
GEMINI_MODEL_DEFAULT = "gemini-2.0-flash"
OLLAMA_MODEL_DEFAULT = "qwen3:0.6b"


# -- system prompts ---------------------------------------------------------------

_SYSTEM_BASE = """You are Peekaboo AI - a high-end technical and educational assistant for the Peekaboo Threat Simulation Framework, created by Zhassulan Zhussupov (@cocomelonc).

Your primary goal is to bridge the gap between offensive research, practice and defensive implementation. You analyze the ~/hacking/meow codebase to explain how adversarial techniques operate at the binary and kernel levels.

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
- Crypto: Speck, FEAL-8, Lucifer, MARS, Treyfer, Camellia, A5/1, CAST128, DES, Madryga, Khufu, LOKI, RC5, RC6, SAFER, Skipjack, TEA (Tiny Encryption Algorithm), XTEA
- Injection: VirtualAllocEx, EnumDesktopsA
- Persistence: Registry Run, Winlogon, Screensaver Hijacking, File Type Hijacking
- C2/Stealer: Angelcam, Azure, Telegram, GitHub, Bitbucket, VirusTotal

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

## CRITICAL - mandatory response rules (follow these on EVERY response, no exceptions):

1. **Always include at least one code snippet.** Pull from the knowledge base context when available. If the KB has matching code, show it verbatim or adapted - never paraphrase code in words when you can show the actual implementation.
2. **Use fenced code blocks with a language tag** - ` ```c `, ` ```cpp `, ` ```python `, ` ```nim `, ` ```asm ` etc. Never put code inline without a fence.
3. **Structure every technical answer** in this order:
   - Brief explanation (1-3 sentences)
   - Code snippet from KB (or a representative example in the style of the codebase)
   - MITRE ATT&CK ID(s) if applicable
   - Detection / telemetry note (one line minimum)
4. **Cite the source slug** when using KB code (e.g. `maldev-1`, `injection-2`, `pers-1`).
5. If a question is completely non-technical (greetings, meta questions), skip the code section but still be concise and direct.
"""

_OLLAMA_SYSTEM_BASE = """/no_think

You are Peekaboo AI Assistant.

Answer fast, short, and technically.
Use the retrieved KB context as the primary source.

For technical questions:
1. Give 2-3 concise sentences.
2. If CODE SNIPPET FROM KB exists, include ONE short fenced code block.
3. Add MITRE ATT&CK only if present in context or obvious.
4. Add ONE detection / telemetry line.

Rules:
- Do not say "no specific code snippet is provided" if CODE SNIPPET FROM KB exists.
- Do not invent code if no snippet exists.
- Do not output <think> blocks.
- Do not write long tutorials unless the user asks for details.
"""


# -- config loaders ---------------------------------------------------------------

def _get_anthropic_key() -> str:
    cfg_path = CONFIG_DIR / "anthropic_config.json"
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text())
            key  = data.get("api_key", "")
            if key and not key.startswith("sk-ant-xxx"):
                return key
        except Exception:
            pass
    return os.environ.get("ANTHROPIC_API_KEY", "")


def _get_gemini_config() -> dict:
    cfg_path = CONFIG_DIR / "gemini_config.json"
    defaults: dict = {
        "api_key":           "",
        "model":             GEMINI_MODEL_DEFAULT,
        "temperature":       0.2,
        "max_output_tokens": 512,
        "thinking_budget":   0,
        "kb_budget":         12_000,
    }
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text())
            defaults.update(data)
        except Exception as e:
            print("get gemini config:", str(e))
    if not defaults["api_key"] or defaults["api_key"].startswith("AIzaxxx"):
        defaults["api_key"] = os.environ.get("GEMINI_API_KEY", "")
    return defaults


def _get_ollama_config() -> dict:
    cfg_path = CONFIG_DIR / "ollama_config.json"
    defaults: dict = {
        "base_url": "http://localhost:11434",
        "model": "qwen3:1.7b",

        "temperature": 0.15,
        "top_p": 0.75,
        "num_thread": 8,

        # Fast RAG defaults
        "context_posts": 2,
        "context_posts_technical": 3,

        # CPU-friendly
        "num_ctx": 4096,
        "num_predict": 384,

        # Keep answers compact
        "max_snippet_lines": 18,
        "fallback_snippets": 1,

        "keep_alive": "10m"
    }

    if cfg_path.exists():
        try:
            defaults.update(json.loads(cfg_path.read_text()))
        except Exception:
            pass

    return defaults


# -- knowledge base (Claude / Gemini full-context path) ---------------------------

def _load_knowledge_base(budget: int = 80_000) -> str:
    if not KB_FILE.exists():
        return ""
    try:
        kb    = json.loads(KB_FILE.read_text())
        posts = kb.get("posts", [])
        if not posts:
            return ""
        lines = [
            f"\n\n## Knowledge Base: {kb.get('author', '')}",
            f"Source: {kb.get('source', '')}",
            f"Topics indexed: {len(posts)}",
            "---",
        ]
        used = 0
        for p in posts:
            ref   = p.get("ref") or p.get("url", "")
            chunk = f"\n### {p['title']}\nRef: {ref}\n{p['content']}\n"
            if used + len(chunk) > budget:
                break
            lines.append(chunk)
            used += len(chunk)
        return "\n".join(lines)
    except Exception:
        return ""


def _build_claude_system() -> list[dict] | str:
    kb_text = _load_knowledge_base()
    if not kb_text:
        return _SYSTEM_BASE
    return [
        {"type": "text", "text": _SYSTEM_BASE},
        {"type": "text", "text": kb_text, "cache_control": {"type": "ephemeral"}},
    ]


_GEMINI_DEMO_SUFFIX = """

## Response format (DEMO MODE - follow strictly)
- Max 3 sentences of explanation.
- ONE fenced code block from the KB (mandatory for technical questions).
- ONE MITRE ATT&CK line if applicable.
- ONE detection/telemetry line.
- No long tutorials. No multi-section essays. Be fast and direct.
"""


def _build_gemini_system(kb_budget: int = 80_000) -> str:
    kb_text = _load_knowledge_base(budget=kb_budget)
    if not kb_text:
        return _SYSTEM_BASE + _GEMINI_DEMO_SUFFIX
    return _SYSTEM_BASE + kb_text + _GEMINI_DEMO_SUFFIX


# -- Claude streaming -------------------------------------------------------------

def _stream_claude(messages: list[dict]) -> Generator[str, None, None]:
    import anthropic

    api_key = _get_anthropic_key()
    if not api_key:
        yield "[=^..^=] Anthropic API key not set. Add it to config/anthropic_config.json"
        return

    yield {"status": "connecting", "msg": "connecting to Claude…"}
    client = anthropic.Anthropic(api_key=api_key)
    try:
        yield {"status": "generating", "msg": "generating response…"}
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
        yield "[=^..^=] Invalid Anthropic API key. Check config/anthropic_config.json"
    except anthropic.APIConnectionError:
        yield "[=^..^=] Anthropic connection error. Check your internet."
    except Exception as e:
        yield f"[=^..^=] Claude error: {e}"


# -- Gemini streaming -------------------------------------------------------------

def _stream_gemini(messages: list[dict]) -> Generator[str, None, None]:
    from google import genai
    from google.genai import types

    cfg     = _get_gemini_config()
    api_key = cfg["api_key"]
    model   = cfg["model"]

    if not api_key:
        yield "[=^..^=] Gemini API key not set. Add it to config/gemini_config.json"
        return

    contents = []
    for m in messages:
        role = "user" if m["role"] == "user" else "model"
        contents.append(types.Content(role=role, parts=[types.Part(text=m["content"])]))

    yield {"status": "connecting", "msg": "connecting to Gemini…"}
    client = genai.Client(api_key=api_key)
    try:
        yield {"status": "generating", "msg": f"generating response…"}

        gen_cfg = types.GenerateContentConfig(
            system_instruction=_build_gemini_system(kb_budget=cfg.get("kb_budget", 12_000)),
            max_output_tokens=cfg.get("max_output_tokens", 512),
            temperature=cfg.get("temperature", 0.2),
        )
        budget = cfg.get("thinking_budget", 0)
        try:
            gen_cfg.thinking_config = types.ThinkingConfig(thinking_budget=budget)
        except Exception:
            pass

        response = client.models.generate_content_stream(
            model=model,
            contents=contents,
            config=gen_cfg,
        )
        for chunk in response:
            if chunk.text:
                yield chunk.text
    except Exception as e:
        err = str(e)
        if "API_KEY_INVALID" in err or "API key" in err:
            yield "[=^..^=] Invalid Gemini API key. Check config/gemini_config.json"
        else:
            yield f"[=^..^=] Gemini error: {e}"


# -- technical-question detector (used by RAG and canned gate) --------------------

_TECHNICAL_MARKERS = [
    "code", "snippet", "source", "implementation", "api", "winapi",
    "virtualalloc", "virtualallocex", "virtualprotect", "createthread",
    "createremotethread", "writeprocessmemory", "queueuserapc",
    "enumdesktop", "ntcreate", "ntallocate", "syscall", "hell's gate",
    "halosgate", "tartarusgate", "shellcode", "loader", "payload",
    "injection", "process injection", "apc", "hollowing", "section",
    "c2", "telegram", "github", "bitbucket", "virustotal", "webhook",
    "persistence", "registry", "run key", "winlogon", "dll hijack",
    "amsi", "etw", "unhooking", "api hashing", "hashing",
    "encrypt", "encryption", "xor", "speck", "tea", "xtea", "mars",
    "feal", "treyfer", "lucifer", "camellia",
    "yara", "sigma", "sysmon", "telemetry", "detection",
    "mitre", "att&ck", "t1055", "t1106", "t1027", "t1547", "t1102",
]


def _is_technical_question(question: str) -> bool:
    q = question.lower()
    return any(marker in q for marker in _TECHNICAL_MARKERS)


_FULL_CODE_MARKERS = [
    "full code", "full snippet", "source code", "entire code", "whole code",
    "show full", "full source", "show the code", "show me the code",
    "code from meow", "code from kb", "source from kb", "all code",
    "complete code", "complete snippet", "full implementation",
    "entire implementation", "full file", "whole file", "entire file",
    "give me the code", "print the code", "show source",
]


def _is_full_code_request(question: str) -> bool:
    q = question.lower()
    return any(marker in q for marker in _FULL_CODE_MARKERS)


# -- RAG helpers ------------------------------------------------------------------

def _norm_text(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _extract_code_blocks(text: str, max_lines: int = 18) -> str:
    """Extract first fenced code block from markdown. Returns code without fences."""
    if not text:
        return ""
    m = re.search(
        r"```(?:c|cpp|c\+\+|python|py|nim|asm|nasm|powershell|bash)?\s*\n(.*?)```",
        text, re.S | re.I,
    )
    if not m:
        return ""
    lines = m.group(1).strip().splitlines()[:max_lines]
    return "\n".join(lines)


def _guess_lang(snippet: str) -> str:
    s = snippet.lower()
    if "#include" in s or "winapi" in s or "handle " in s or "dword" in s:
        return "c"
    if "import " in s or "def " in s:
        return "python"
    if "section ." in s or "global " in s or "syscall" in s:
        return "asm"
    if "proc " in s and "nim" in s:
        return "nim"
    return "c"


def _entry_matches_question(entry: dict, question: str) -> int:
    """Count how many 4+-char words from question appear in this library entry's metadata."""
    q   = _norm_text(question)
    hay = _norm_text(" ".join([
        str(entry.get("slug",        "")),
        str(entry.get("title",       "")),
        str(entry.get("url",         "")),
        str(entry.get("category",    "")),
        str(entry.get("description", "")),
        str(entry.get("attack_ids",  "")),
    ]))
    return sum(1 for word in q.split() if len(word) >= 4 and word in hay)


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


def _get_snippet_for_post(post: dict, question: str = "", max_lines: int = 18) -> tuple[str, str, str]:
    """
    Return (snippet, source_slug, language).

    Priority:
    1. Exact slug match in library_cache.json
    2. Exact normalized title / url match
    3. Fuzzy match on post-identity tokens (slug + title + url) vs library entries
    4. Question-keyword fallback if post identity yielded nothing
    5. Code block extracted from the post's own content field
    """
    slug  = post.get("slug")     or ""
    title = post.get("title")    or ""
    url   = post.get("blog_url") or post.get("url") or ""

    # tokens that describe *this specific post* (used for identity-based matching)
    post_tokens = {t for t in _norm_text(" ".join([slug, title, url])).split() if len(t) >= 4}
    post_ids    = {_norm_text(x) for x in [slug, title, url] if x}

    best_entry: dict | None = None
    best_score  = -1

    for entry in _get_library():
        # 1. exact slug match
        if slug and entry.get("slug") == slug:
            best_entry, best_score = entry, 999
            break

        # 2. exact normalized match on any identity field
        e_slug  = _norm_text(str(entry.get("slug",  "")))
        e_title = _norm_text(str(entry.get("title", "")))
        e_url   = _norm_text(str(entry.get("url",   "")))
        if any(x and x in {e_slug, e_title, e_url} for x in post_ids):
            best_entry, best_score = entry, 999
            break

        # 3. fuzzy: shared tokens between this post's identity and the entry's identity
        entry_hay = _norm_text(" ".join([
            str(entry.get("slug",     "")),
            str(entry.get("title",    "")),
            str(entry.get("url",      "")),
            str(entry.get("category", "")),
        ]))
        score = sum(1 for t in post_tokens if t in entry_hay)
        if score > best_score:
            best_entry, best_score = entry, score

    # 4. nothing matched post identity -> fall back to question keywords
    if best_score <= 0 and question:
        for entry in _get_library():
            score = _entry_matches_question(entry, question)
            if score > best_score:
                best_entry, best_score = entry, score

    if best_entry and best_score > 0:
        snip = best_entry.get("snippet", "") or best_entry.get("code", "")
        if snip:
            snippet = "\n".join(snip.splitlines()[:max_lines]).strip()
            return snippet, str(best_entry.get("slug") or slug or title), _guess_lang(snippet)
        content = best_entry.get("content", "") or best_entry.get("markdown", "")
        snippet = _extract_code_blocks(content, max_lines=max_lines)
        if snippet:
            return snippet, str(best_entry.get("slug") or slug or title), _guess_lang(snippet)

    # 5. try the post's own content field
    content = post.get("content", "") or post.get("text", "") or post.get("markdown", "")
    snippet = _extract_code_blocks(content, max_lines=max_lines)
    if snippet:
        return snippet, slug or title, _guess_lang(snippet)

    return "", slug or title or url, "c"


def _fallback_snippets_from_library(question: str, limit: int = 2, max_lines: int = 45) -> list[dict]:
    """
    Last-resort snippet search over library_cache.json.
    Called when semantic search found posts but none had attached snippets.
    Prevents Ollama from saying "no code snippet" when the technique exists.
    """
    scored: list[tuple[int, dict]] = []
    for entry in _get_library():
        score = _entry_matches_question(entry, question)
        snip  = entry.get("snippet", "") or entry.get("code", "")
        if not snip:
            content = entry.get("content", "") or entry.get("markdown", "")
            snip = _extract_code_blocks(content)
        if score > 0 and snip:
            scored.append((score, {**entry, "_snippet": snip}))

    scored.sort(key=lambda x: x[0], reverse=True)
    results = []
    for _, entry in scored[:limit]:
        snippet = entry["_snippet"]
        results.append({
            "title":    entry.get("title",    ""),
            "slug":     entry.get("slug",     ""),
            "url":      entry.get("url",      ""),
            "category": entry.get("category", ""),
            "snippet":  "\n".join(snippet.splitlines()[:max_lines]),
            "lang":     _guess_lang(snippet),
        })
    return results


def _rag_context(question: str, n: int = 6, max_lines: int = 18) -> str:
    """Retrieve top-n relevant posts, attach real code snippets, return context block."""
    try:
        import sys, os as _os
        sys.path.insert(0, _os.path.dirname(__file__))
        from semantic import find_related_posts
        posts = find_related_posts(question, max_results=n)
    except Exception as e:
        print(f"[rag] retrieval error: {e}")
        posts = []

    blocks:         list[str] = []
    snippets_found: int       = 0

    for p in posts:
        title = p.get("title",    "")
        url   = p.get("blog_url", "") or p.get("url", "")
        cat   = p.get("category", "")
        aids  = ", ".join(p.get("attack_ids", []))
        score = p.get("score",    0)

        snippet, source_slug, lang = _get_snippet_for_post(p, question=question, max_lines=max_lines)

        block = f"### {title}\n- Source slug: {source_slug}\n- URL: {url}\n- Category: {cat}"
        if aids:
            block += f"\n- ATT&CK: {aids}"
        try:
            block += f"\n- Relevance: {score:.0%}"
        except Exception:
            block += f"\n- Relevance: {score}"

        if snippet:
            snippets_found += 1
            block += f"\n\nCODE SNIPPET FROM KB - USE THIS IN THE ANSWER:\n```{lang}\n{snippet}\n```"
        else:
            block += "\n\nCODE SNIPPET: not attached for this post"

        blocks.append(block)

    # if semantic search found posts but none had snippets, scan library_cache directly
    if _is_technical_question(question) and snippets_found == 0:
        fallback = _fallback_snippets_from_library(question, limit=2, max_lines=max_lines)
        if fallback:
            blocks.append("## Fallback code snippets from library_cache.json")
            for item in fallback:
                snippets_found += 1
                blocks.append(
                    f"### {item.get('title') or item.get('slug')}\n"
                    f"- Source slug: {item.get('slug')}\n"
                    f"- URL: {item.get('url')}\n"
                    f"- Category: {item.get('category')}\n\n"
                    f"CODE SNIPPET FROM KB - USE THIS IN THE ANSWER:\n"
                    f"```{item.get('lang', 'c')}\n{item.get('snippet')}\n```"
                )

    if not blocks:
        return "No relevant KB posts found."

    if _is_technical_question(question) and snippets_found == 0:
        blocks.append(
            "## Retrieval warning\n"
            "KB snippet not found for this exact query. "
            "Explain using available metadata, but do not claim the technique does not exist."
        )

    return "\n\n".join(blocks)


# -- Ollama streaming -------------------------------------------------------------

def _build_ollama_system(context: str, full_code: bool = False) -> str:
    base = _OLLAMA_SYSTEM_BASE
    if full_code:
        base += "\n## Mode: FULL CODE - include the complete CODE SNIPPET FROM KB verbatim, no truncation.\n"
    else:
        base += "\n## Mode: FAST - be concise, include only the most relevant portion of the code snippet.\n"
    if context:
        base += f"""
## Retrieved knowledge base context

{context}

Use this context as the primary source. Prefer "CODE SNIPPET FROM KB" blocks.
Cite the source slug or title when including code.
"""
    else:
        base += """
## Retrieved knowledge base context

No context was retrieved. If the question is technical, say KB context was not found
and answer cautiously without fabricating code.
"""
    return base


def _stream_ollama(messages: list[dict]) -> Generator[str, None, None]:
    cfg      = _get_ollama_config()
    base_url = cfg["base_url"].rstrip("/")
    model    = cfg["model"]
    temp     = cfg.get("temperature", 0.2)

    last_user = next(
        (m["content"] for m in reversed(messages) if m.get("role") == "user"), ""
    )
    technical = _is_technical_question(last_user)
    full_code = _is_full_code_request(last_user)

    n_posts = cfg.get("context_posts_technical", 5) if technical else cfg.get("context_posts", 3)

    if full_code:
        max_lines   = 400
        num_predict = 2048
        num_ctx_val = 16384
    else:
        max_lines   = cfg.get("max_snippet_lines", 30)
        num_predict = cfg.get("num_predict", 384)
        num_ctx_val = cfg.get("num_ctx", 4096)

    yield {"status": "rag", "msg": "searching knowledge base…"}
    context = _rag_context(last_user, n=n_posts, max_lines=max_lines) if last_user else ""

    yield {"status": "generating", "msg": f"sending to {model}…"}
    system_prompt = _build_ollama_system(context, full_code=full_code)

    payload = json.dumps({
        "model":      model,
        "stream":     True,
        "think":      False,
        "keep_alive": cfg.get("keep_alive", "10m"),
        "options": {
            "temperature": temp,
            "num_ctx":     num_ctx_val,
            "num_predict": num_predict,
            "num_thread":  cfg.get("num_thread", 8),
            "top_p":       cfg.get("top_p",      0.8),
        },
        "messages": [{"role": "system", "content": system_prompt}] + messages[-4:],
    }).encode()

    url = f"{base_url}/api/chat"
    try:
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=300) as resp:
            in_think     = False
            think_buffer = ""

            for raw_line in resp:
                line = raw_line.decode("utf-8").strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError:
                    continue

                token = chunk.get("message", {}).get("content", "")

                if token:
                    if "<think>" in token:
                        in_think = True
                        yield {"thinking": True}
                        before, _, rest = token.partition("<think>")
                        if before:
                            yield before
                        think_buffer = rest
                        continue

                    if in_think:
                        think_buffer += token
                        if "</think>" in think_buffer:
                            in_think = False
                            yield {"thinking": False}
                            _, _, after = think_buffer.partition("</think>")
                            think_buffer = ""
                            if after:
                                yield after
                        continue

                    yield token

                if chunk.get("done"):
                    if in_think:
                        yield {"thinking": False}
                    break

    except urllib.error.URLError as e:
        yield f"[=^..^=] Ollama connection error: {e}. Is Ollama running?"
    except Exception as e:
        yield f"[=^..^=] Ollama error: {e}"


# -- direct KB code response (no LLM, instant, demo-grade) -----------------------

def _read_src_file(src_path: str, max_lines: int = 600) -> str:
    """Read a real source file from disk, capped at max_lines. Verbatim, no LLM."""
    if not src_path:
        return ""
    try:
        p = Path(src_path)
        if not p.exists() or not p.is_file():
            return ""
        text  = p.read_text(errors="replace")
        lines = text.splitlines()
        if len(lines) > max_lines:
            tail = f"\n// ... [{len(lines) - max_lines} more lines truncated]"
            return "\n".join(lines[:max_lines]) + tail
        return text
    except Exception:
        return ""


def _direct_kb_response(question: str, max_lines: int = 600) -> str:
    """
    Bypass the LLM entirely for full-code requests.
    Pulls verbatim source from src_path (or library snippet fallback).
    Demo-grade: instant on CPU, complete, never truncated by token limits.
    """
    try:
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.dirname(__file__))
        from semantic import find_related_posts
        posts = find_related_posts(question, max_results=3)
    except Exception as e:
        print(f"[direct_kb] retrieval error: {e}")
        posts = []

    blocks:     list[str] = []
    seen_slugs: set       = set()
    library              = _get_library()

    def _render(entry: dict, fallback_title: str = "") -> str | None:
        slug = entry.get("slug") or ""
        if slug in seen_slugs:
            return None
        code = _read_src_file(entry.get("src_path", ""), max_lines=max_lines)
        if not code:
            code = entry.get("snippet", "") or entry.get("code", "")
        if not code:
            return None
        seen_slugs.add(slug)

        title = entry.get("title") or fallback_title or slug
        url   = entry.get("blog_url") or entry.get("url", "")
        cat   = entry.get("category", "")
        aids  = entry.get("attack_ids", "")
        if isinstance(aids, list):
            aids = ", ".join(aids)
        lang  = _guess_lang(code)

        block = f"## {title}\n\n**Source:** `{slug}`  \n"
        if url:  block += f"**URL:** {url}  \n"
        if cat:  block += f"**Category:** {cat}  \n"
        if aids: block += f"**MITRE ATT&CK:** {aids}\n"
        block += f"\n```{lang}\n{code}\n```\n"
        return block

    # 1. match retrieved posts to library entries (slug -> title)
    for p in posts:
        slug  = p.get("slug")  or ""
        title = p.get("title") or ""
        entry = None
        for e in library:
            if (slug and e.get("slug") == slug) or (title and e.get("title") == title):
                entry = e
                break
        if entry:
            b = _render(entry, fallback_title=title)
            if b:
                blocks.append(b)

    # 2. keyword-fallback scan if semantic search yielded nothing usable
    if not blocks:
        scored: list[tuple[int, dict]] = []
        for entry in library:
            score = _entry_matches_question(entry, question)
            if score > 0:
                scored.append((score, entry))
        scored.sort(key=lambda x: x[0], reverse=True)
        for _, entry in scored[:2]:
            b = _render(entry)
            if b:
                blocks.append(b)

    if not blocks:
        return (
            "No matching KB code snippet found. Try a more specific keyword, "
            "for example: *show full code for VirtualAllocEx injection*, "
            "*source code for Speck encryption*, *full source for APC injection*."
        )

    return "Here is the verbatim code from the knowledge base:\n\n" + "\n\n---\n\n".join(blocks)


def _stream_kb_chunks(
    text: str,
    word_delay: float = 0.004,
    line_delay: float = 0.010,
    space_delay: float = 0.001,
) -> Generator[str, None, None]:
    """
    Word-by-word streaming for direct KB responses - mimics LLM token cadence
    so the frontend sees the same "typing" effect it gets from Ollama/Claude/Gemini.

    Tokenization keeps whitespace runs as their own tokens, which preserves
    indentation and blank lines in code blocks exactly as written on disk.

    Tuning: ~3000 word-tokens for a 14k-char response × 4ms ≈ 12s total
    (with a small extra pause at every newline so code renders line-by-line).
    """
    import re, time
    for tok in re.findall(r"\s+|\S+", text):
        yield tok
        if "\n" in tok:
            time.sleep(line_delay)
        elif tok.isspace():
            time.sleep(space_delay)
        else:
            time.sleep(word_delay)


def _ollama_available() -> tuple[bool, str]:
    cfg      = _get_ollama_config()
    base_url = cfg["base_url"].rstrip("/")
    model    = cfg["model"]
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data  = json.loads(resp.read())
            names = [m["name"] for m in data.get("models", [])]
            if any(model.split(":")[0] in n for n in names):
                return True, model
            return False, f"{model} not pulled"
    except Exception:
        return False, "ollama offline"


# -- canned answers: onboarding only (stable, no LLM needed) ---------------------
# Technical questions skip this entirely -> RAG -> LLM.

_CANNED: list[tuple[str, str]] = [

    # 1. what is Peekaboo? ---------------------------------------------------------
    (
        r"what is peekaboo|what('s| is) this (framework|tool|project)|explain peekaboo",
        """## Peekaboo - APT Simulation Framework

**Peekaboo** is an open-source threat simulation and malware development research framework by **@cocomelonc**, designed for red team education and defensive implementation research.

### Coverage at a glance

| Category | ATT&CK | Techniques |
|---|---|---|
| **C2 channels** | T1102, T1071 | Telegram, GitHub Issues, Bitbucket, VirusTotal abuse |
| **Process injection** | T1055 | VirtualAllocEx, EnumDesktopsA, APC, section mapping |
| **AV/EDR bypass** | T1027, T1562 | Direct syscalls, API hashing, AMSI patch, unhooking |
| **Payload crypto** | T1027, T1140 | Speck, FEAL-8, MARS, Treyfer, TEA, XTEA, Camellia… |
| **Persistence** | T1547, T1574 | Registry Run, Winlogon, DLL hijacking, screensaver |
| **Exfiltration** | T1041 | Stealer + C2 channel combos |

Every module ships with a blog post covering mechanics, WinAPI details, SIGMA detection rules, and MITRE mapping. Browse all techniques in the **Module Library** panel, or analyse compiled samples in **PE Inspector**.

Ask me any technical question - I'll pull context from the knowledge base and give a code-level answer."""
    ),

    # 2. What model / provider? ----------------------------------------------------
    (
        r"what model|which (llm|model|ai|provider)|what provider|ollama model|qwen",
        """## AI Assistant Providers

| Provider | Model | Mode | Strength |
|---|---|---|---|
| **Claude** | `claude-opus-4-6` | API + streaming | Best reasoning; extended thinking; full KB prompt-cached |
| **Gemini** | `gemini-2.0-flash` | API + streaming | Fast; full KB injected as system prompt |
| **Ollama** | `qwen3:0.6b` (default) | Local / offline | Air-gapped; RAG over top-3 KB posts |

Switch with the provider buttons below the chat input.

### Claude - prompt-cache detail
The full knowledge base (~80 k tokens) is sent as a `cache_control: ephemeral` block. Billed once per 5-minute TTL - multi-turn sessions cost ~90 % less.

### Ollama - RAG pipeline
```
question -> nomic-embed-text (768-dim) -> cosine similarity
         -> top-3 KB posts -> qwen3 system prompt -> streamed answer
```

**Setup:** add API keys to `config/anthropic_config.json` / `config/gemini_config.json`. For Ollama see *"How to set up Ollama?"*."""
    ),

    # 3. Help / capabilities -------------------------------------------------------
    (
        r"help|what can (you|this assistant) do|capabilities|commands|how (do i|to) use",
        """## Peekaboo AI - What You Can Ask

I answer technical questions grounded in the **~/hacking/meow** codebase. Every response includes code, MITRE IDs, and a detection note.

### Topics I cover well

- **Injection** - VirtualAllocEx, APC, EnumDesktopsA, section mapping, hollowing
- **Persistence** - Registry Run, Winlogon, screensaver, DLL hijacking, scheduled tasks
- **C2 channels** - Telegram, GitHub Issues, Bitbucket, VirusTotal, Discord/Slack abuse
- **AV/EDR bypass** - direct syscalls, API hashing, AMSI patching, ETW patching, unhooking
- **Payload crypto** - Speck, TEA, XTEA, FEAL-8, MARS, Treyfer, XOR, and 10+ more
- **Binary analysis** - PE anatomy, entropy, imports, ROP gadgets, shellcode emulation
- **Detection engineering** - SIGMA rules, Sysmon EIDs, ETW providers, telemetry

### Example questions

- *"How does EnumDesktopsA injection work?"*
- *"Show me Speck-64 encryption for a shellcode buffer"*
- *"What Sysmon events catch Registry Run key persistence?"*
- *"Explain the Hell's Gate SSN extraction approach"*

Switch provider with the buttons below. For Ollama (offline RAG) see *"How to set up Ollama?"*."""
    ),

    # 4. How to set up Ollama? -----------------------------------------------------
    (
        r"(how|setup|set up|install|configure).{0,30}ollama|ollama.{0,20}(setup|install|configure|run|start)",
        """## Setting Up Ollama (local / offline mode)

### 1. Install Ollama
```bash
# Linux / WSL
curl -fsSL https://ollama.com/install.sh | sh

# macOS
brew install ollama
```

### 2. Pull required models
```bash
ollama pull qwen3:0.6b          # chat model (~400 MB)
ollama pull nomic-embed-text    # embeddings for RAG (~270 MB)
```

### 3. Start the server
```bash
ollama serve   # listens on http://localhost:11434
```

### 4. Configure Peekaboo
Edit `config/ollama_config.json`:
```json
{
  "base_url":    "http://localhost:11434",
  "model":       "qwen3:0.6b",
  "temperature": 0.2,
  "num_ctx":     2048,
  "num_predict": 384
}
```

### 5. Select Ollama in the chat bar
Click the **Ollama** button. The RAG pipeline kicks in automatically - your question is embedded, top-3 relevant posts are retrieved from the knowledge base, and qwen3 generates a streamed answer with no internet connection required.

> **Tip:** build the knowledge base first (`peekaboo.py kb index`) so RAG has posts to retrieve from."""
    ),

    # 5. What can this assistant do? -----------------------------------------------
    (
        r"what (can|does|will) (this assistant|peekaboo ai|you) (do|know|answer|help)",
        """## Peekaboo AI Assistant - Capabilities

I'm a technical assistant specialised in malware research and threat simulation. I answer questions grounded in the **~/hacking/meow** codebase - real, working code with full MITRE ATT&CK and detection context.

**Ask me about:**
- Injection techniques and memory allocation patterns
- C2 channel implementations (Telegram, GitHub, Bitbucket, VirusTotal)
- AV/EDR bypass (syscalls, API hashing, AMSI/ETW patching, unhooking)
- Payload encryption (10+ ciphers from the crypto/ directory)
- Persistence primitives (Registry, Winlogon, DLL hijacking, screensaver)
- Binary analysis (PE anatomy, entropy, ROP chains, shellcode emulation)
- Detection engineering (SIGMA rules, Sysmon EIDs, ETW providers)

For every technical question I:
1. Give a brief explanation
2. Show a real code snippet from the knowledge base
3. Map to MITRE ATT&CK technique(s)
4. Add a detection / telemetry note

Type any technical question or say **help** for more detail."""
    ),

    # 6. Which repos for knowledge base? -------------------------------------------
    (
        r"(which|what) repo|knowledge base (repo|source|setup)|kb (setup|index|source)|index.*knowledge|how.*index",
        """## Knowledge Base - Setup & Sources

The knowledge base is built from **@cocomelonc's** malware research blog posts and the local codebase.

### Index it

```bash
# from the peekaboo root
python3 peekaboo.py kb index
```

Or in the dashboard: **Settings -> Knowledge Base -> Reindex**.

### What gets indexed

| Source | Content |
|---|---|
| `cocomelonc.github.io` blog | ~150 posts: technique write-ups, code walk-throughs |
| `~/hacking/meow` codebase | C/C++/Nim/Assembly source per technique |
| Per-post metadata | MITRE ATT&CK IDs, category tags, blog URL |
| Embeddings | `nomic-embed-text` 768-dim vectors (stored in `data/post_embeddings.json`) |

### Output files

```
dashboard/knowledge_base.json   <- full text + snippets (used by Claude/Gemini)
data/post_embeddings.json       <- vectors (used by Ollama RAG)
data/library_cache.json         <- code snippets per slug
```

### Repos referenced

- **`~/hacking/meow`** - main malware dev codebase (primary KB source)
- **Blog:** https://cocomelonc.github.io - scraped for post content

> **Ollama RAG** requires `nomic-embed-text` to be pulled first:
> `ollama pull nomic-embed-text`"""
    ),
]


def _canned_response(question: str) -> str:
    q = question.lower().strip()
    for pattern, answer in _CANNED:
        if re.search(pattern, q):
            return answer
    return ""


def _stream_canned(answer: str) -> Generator[str, None, None]:
    import time
    words  = answer.split(" ")
    chunk: list[str] = []
    for i, word in enumerate(words):
        chunk.append(word)
        if len(chunk) >= 6 or i == len(words) - 1:
            yield " ".join(chunk) + (" " if i < len(words) - 1 else "")
            chunk = []
            time.sleep(0.015)


# -- public interface -------------------------------------------------------------

def stream_chat(messages: list[dict], provider: str = "claude") -> Generator[str, None, None]:
    """
    Stream a chat response.
    provider: "claude" | "gemini" | "ollama"
    messages: [{role, content}, ...]

    Canned responses fire only for onboarding / help / product questions.
    Technical questions always go through RAG -> LLM.
    """
    last_user = next(
        (m["content"] for m in reversed(messages) if m.get("role") == "user"), ""
    )

    if not _is_technical_question(last_user):
        canned = _canned_response(last_user)
        if canned:
            yield {"status": "canned", "msg": "instant answer"}
            yield from _stream_canned(canned)
            return

    # Full-code requests bypass the LLM entirely - demo-fast, never truncated.
    # Works for every provider; the LLM is only used for explanations now.
    if _is_full_code_request(last_user):
        yield {"status": "kb_direct", "msg": "loading code from KB…"}
        response = _direct_kb_response(last_user)
        yield from _stream_kb_chunks(response)
        return

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
        ts = kb.get("indexed_at", "")
        return {
            "status":       "ready",
            "posts":        kb.get("post_count", 0),
            "indexed_at":   ts,
            "last_updated": ts,
            "source":       kb.get("source", ""),
        }
    except Exception:
        return {"status": "error", "posts": 0}


def providers_status() -> dict:
    claude_key  = _get_anthropic_key()
    gemini_cfg  = _get_gemini_config()
    ollama_ok, ollama_model = _ollama_available()
    return {
        "claude": {"available": bool(claude_key),               "model": CLAUDE_MODEL},
        "gemini": {"available": bool(gemini_cfg["api_key"]),    "model": gemini_cfg["model"]},
        "ollama": {"available": ollama_ok,                       "model": ollama_model},
    }
