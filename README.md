# Peekaboo

![img](./screenshots/2026-04-28_23-40.png)          


Peekaboo is a modular framework designed to safely emulate malware behavior. It allows security researchers, red teamers, and blue teamers to reproduce complex threat scenarios - including Command & Control (C2) communication, persistence mechanisms, and lateral movement - without using destructive payloads.     

**The goal of Peekaboo is to accelerate detection engineering and operator training by providing predictable, reproducible, and safe threat artifacts.**    

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=cocomelonc/peekaboo&type=date&theme=dark&legend=top-left" />
  <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=cocomelonc/peekaboo&type=date&legend=top-left" />
  <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=cocomelonc/peekaboo&type=date&legend=top-left" />
</picture>

## key features (how it works?)

- malware **source code template** - build a payload/stealer from templates (select C2 channel & data collection modules).
- **payload generator** - automated generation of C/C++ based payloads with built-in obfuscation (API hashing, string encryption).    
- **AV/EDR bypass** - encryption/encoding (syscalls)        
- **multi-channel C2** - support for various covert channels:
    - standard HTTP/S    
    - GitHub (abusing Issues/Commits)    
    - Telegram & Discord Webhooks    
    - TODO: adding all channels from one of [my recent research](https://www.youtube.com/watch?v=l2G2TZvzj0E)     
- **exfiltration** - staged exfil to controlled endpoints (Github/Discord/Slack/VirusTotal/Azure DevOps/Angelcam).      
- **evasive persistence** - modular implementation of Windows persistence (Registry Run Keys, Winlogon, Screensaver).    
- **lightweight dashboard** - a python-based C2 backend and dashboard for real-time monitoring of active "beacons".
- **MITRE ATT&CK R&D** - browse 200+ blog post techniques mapped to ATT&CK IDs with inline source code (C, C++, Nim, assembly).
- **Malpedia integration** - threat actor and malware family lookup with semantic blog post matching via local LLM embeddings.
- **AI assistant** - local RAG chatbot (Ollama/qwen3) trained on blog posts and codebase; fully offline, no cloud API keys required.
- **APT campaign pipeline** - end-to-end automated pipeline: Malpedia actor -> threat reports -> TTP extraction (offline regex) -> module selection -> binary compile. Full session history stored in SQLite with per-session report links, TTPs, and download access.
- **YARA rule generator** - auto-generate YARA rules from compiled binaries or uploaded samples; rules can be saved, copied, and downloaded.
- **VirusTotal scanner** - submit binaries for AV detection scoring; lookup by SHA256; poll analysis results; supports From Build and From Session sources.
- **Artifact Map** - 410 ATT&CK techniques cross-referenced with 4,799 Sigma rules; per-technique EventID coverage, registry keys, processes, command-line indicators - the defender-side companion to the meow knowledge base.
- **single-file config** - all API keys and per-service knobs live in one `.env` file at the project root; no JSON sprawl.
- **safe by design** - focuses on telemetry generation (process creation, network connections) rather than actual system damage.      

## architecture

Peekaboo consists of 5 main components:    
First **malware** module - highly portable C/C++ code designed to build specific "behaviors" (for final agent binary) on the target system.            
1. **crypto (malware, agent)** - build-in payload encryption/decryption logic constructor for agents.    
2. **injection (malware, agent)** - build-in injection logic constructor for agents.      
3. **persistence (malware, agent)** - build-in persistence logic constructor for agents (Registry Run Key, Winlogon, Screensaver).     
4. **stealer (malware, agent)** - stealer logic (Telegram, GitHub, VirusTotal, Bitbucket, Azure DevOps, Angelcam).      

Second, **payloads** module - build-in payloads.     
1. **payloads** - for simplicity, just messagebox and reverse shell.      

Final, `peekaboo.py` builder in Python.     

### demo

Run:    

```bash
python3 peekaboo.py
```

![img](./screenshots/2026-01-27_02-45.png)

## dashboard

The dashboard is a Flask-based web UI that combines C2 monitoring, malware building, threat intelligence, and AI assistance in a single interface.

```bash
cd dashboard && python3 app.py
```

![img](./screenshots/2026-06-11_09-51_1.png)    

![img](./screenshots/2026-06-11_09-49.png)    

![img](./screenshots/2026-06-11_09-51.png)    

### modules

| module | description |
|--------|-------------|
| **Builder** | Compile payloads and stealers from source templates with live build log streaming |
| **Shellcode** | Parse, transform, encode, analyse and reformat shellcode in 11 output formats |
| **Module Library** | Browse 190+ malware-research modules sourced from the meow knowledge base |
| **Samples** | Upload and manage compiled samples organized by session |
| **APT Campaign** | Fully automated pipeline: actor -> reports -> TTP extraction -> module selection -> binary compile |
| **VirusTotal** | Submit binaries to VirusTotal for AV detection scoring; lookup by SHA256; poll analysis; From Build and From Session sources |
| **YARA** | Auto-generate YARA rules from any binary (From Build, From Session, or Upload); save, copy, and download rules |
| **Artifact Map** | 410 ATT&CK techniques cross-referenced with 4,799 Sigma rules; per-technique EventID coverage and registry / process / cmdline artifacts |
| **MITRE ATT&CK** | Browse 200+ blog posts mapped to ATT&CK techniques with inline source code viewer |
| **Malpedia** | Threat actor and malware family lookup with semantic blog post matching |
| **AI Assistant** | Local RAG chatbot (Ollama/qwen3); answers questions about the codebase and blog posts; fully offline |
| **Settings** | Read-only viewer for `.env`-loaded API keys and service configs |

### Configuration (`.env`)

All API keys, credentials, and per-service knobs live in a single `.env` file at the project root. There are **no JSON config files** — the dashboard, CLI, builder, and APT pipeline all read from the same `.env` via `dashboard/cfg.py`.

```bash
cp .env.example .env
$EDITOR .env   # fill in real tokens
```

The Settings panel in the UI is a **read-only viewer** of what's currently loaded (secrets masked). To change a value, edit `.env` and restart the app.

**Variable groups:**

| group | example variables |
|-------|------|
| AI: Ollama | `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `OLLAMA_NUM_CTX`, … |
| Threat Intel | `MALPEDIA_API_TOKEN`, `VT_API_KEY` |
| Stealer / C2 (compile-time substitution) | `TELEGRAM_BOT_TOKEN`, `GITHUB_TOKEN`, `BITBUCKET_TOKEN_BASE64`, `SLACK_WEBHOOK_URL`, `AZURE_PAT`, `ANGELCAM_API_KEY` |
| APT Pipeline | `APT_PIPELINE_COMPILE_EACH`, `APT_PIPELINE_OLLAMA_NARRATION`, `APT_PIPELINE_OLLAMA_MODEL` |

The "Stealer / C2" group is only consumed by the **Builder** at compile time — the placeholders embedded in malware source templates (e.g. `TELEGRAM_BOT_TOKEN_PLACEHOLDER`) get substituted with real values before `gcc`/`mingw` runs. None of these tokens are stored in the compiled binary catalog.

`.env` is gitignored by default. `.env.example` is the redacted template — safe to commit.

### Builder

Select malware type (injection or stealer), injection technique, encryption algorithm, payload, stealer channel, and persistence method. Build output streams live to the UI. On success, the compiled binary and persistence binary (if enabled) are available for immediate download.

### Build History

Every build is persisted to SQLite. The history table shows build ID, status badge, module/stealer name, compiler options, timestamp, and download links for each compiled file (main binary + `persistence.exe` when present). Builds can be cleared individually or in bulk.

### Samples / Sessions

Upload binary samples captured during red team exercises. Each session groups files by actor/host, stores upload time, and provides direct download links. Sessions feed the "From Session" source selector in YARA and VirusTotal.

### YARA Rule Generator

Auto-generates YARA rules from a binary using string extraction, section name heuristics, import pattern matching, and entropy thresholds. Rules can be generated from:

- **From Build** - select any compiled build binary (or persistence binary)
- **From Session** - select a captured sample
- **Upload** - drag-and-drop any PE file

Generated rules can be copied to clipboard, downloaded as `.yar` files, and saved to the knowledge base.

### VirusTotal Scanner

Submit binaries directly to VirusTotal for AV engine detection scoring. Features:

- **Upload** tab - submit any binary by file upload
- **From Build** tab - select any compiled binary from build history
- **From Session** tab - select a captured sample
- SHA256 **Lookup** - query existing VT reports without re-uploading
- **Poll** - check pending analysis status

Results show detection ratio, engine-by-engine breakdown, and file metadata.

### MITRE ATT&CK R&D

The MITRE ATT&CK tab indexes all blog posts from the [meow](https://github.com/cocomelonc/meow) research repository and maps them to ATT&CK technique IDs found in the post body. Source code is extracted automatically from the post directory - supporting C, C++, Nim, and assembly (`.asm`/`.s`) files, including posts where source is nested inside subdirectories.

![img](./screenshots/2026-04-28_23-40.png)

- filter by category (injection, persistence, evasion, cryptography, linux, macos, etc.)
- click any technique to expand the inline source code snippet
- **Full Reindex** button re-runs library scan -> semantic embeddings -> knowledge base in one shot with live progress per step

### Malpedia integration

The Malpedia tab connects to the [Malpedia REST API](https://malpedia.caad.fkie.fraunhofer.de/) to browse threat actors and malware families. For each actor or family, related blog posts are matched using **semantic similarity** - the actor/family description is embedded via `nomic-embed-text` (Ollama), then cosine-ranked against all 200+ cached post embeddings. No hardcoded keyword rules.   

![img](./screenshots/2026-05-01_01-55_1.png)

- search actors by name, country, or malware family
- expand any actor/family to see techniques, aliases, and semantically matched blog posts with similarity score
- requires a Malpedia API key in `.env` (`MALPEDIA_API_TOKEN`)

### APT campaign pipeline

The APT Campaign tab runs a fully automated, five-stage pipeline that takes a Malpedia actor or family identifier and produces a ready-to-test compiled binary in one shot.

![img](./screenshots/2026-06-07_23-57.png)

**Pipeline stages:**

| # | Stage | What it does |
|---|-------|--------------|
| 1 | **Malpedia Fetch** | Resolves the actor or family ID against the Malpedia REST API and retrieves associated metadata (country, aliases, malware families, report URLs) |
| 2 | **Report Download** | Downloads up to 10 linked threat intelligence reports and stores raw content in SQLite for later inspection |
| 3 | **TTP Extraction** | Extracts MITRE ATT&CK technique IDs from report text via regex matching against `T1xxx` patterns - kill-chain ordered, deduped, mention-count sorted - all offline, no API calls |
| 4 | **Module Selection** | Maps extracted TTPs to available peekaboo modules (injection, crypto, stealer, persistence) and selects the best match per technique |
| 5 | **Binary Compile** | Runs the peekaboo builder with the selected parameters and produces a Windows PE ready for EDR testing |

![img](./screenshots/2026-06-08_00-01.png)

All pipeline progress streams live to the right panel as it runs - reports appear as clickable links the moment they are downloaded, TTPs and selected modules are appended on completion of each stage, and the final binary is immediately available for download. Every session is persisted to SQLite; click any row in **Past Sessions** to open a drawer showing:

- **Reports** tab - list of downloaded reports with a direct link to the original URL and character count
- **TTPs** tab - full list of extracted ATT&CK techniques with tactic and evidence quote
- **Binary** tab - build configuration badges, per-file download links, and selected modules

![img](./screenshots/2026-06-08_00-04.png)

**Configuration:** all pipeline knobs live in `.env` (`APT_PIPELINE_COMPILE_EACH`, `APT_PIPELINE_OLLAMA_*`). TTP extraction is fully offline. Optional Ollama narration can be enabled via `APT_PIPELINE_OLLAMA_NARRATION=true`.

### AI assistant

The AI assistant answers questions about malware techniques, the codebase, and blog posts using RAG (Retrieval-Augmented Generation). At query time the question is embedded and matched against all blog post embeddings; the top matching posts are injected as context into the LLM prompt. Runs fully offline — no cloud API keys required.

![img](./screenshots/2026-05-01_01-55.png)

**Provider:** local Ollama (`qwen3:1.7b` default, or any Ollama model). Configure via `OLLAMA_MODEL`, `OLLAMA_NUM_CTX`, etc. in `.env`. Thinking-mode tokens are filtered before streaming to the UI.

## CLI (`peekaboo_cli.py`)

The CLI is a rich interactive terminal application (`peekaboo_cli.py`) with a top-level REPL and dedicated sub-REPLs for each module. Uses `prompt_toolkit` for autocompletion and history, and `rich` for tables, panels, and syntax-highlighted output.

```bash
python3 peekaboo_cli.py
```

![img](./screenshots/2026-06-11_08-14.png)    

Top-level commands:    

![img](./screenshots/2026-06-11_08-17.png)        

| command | description |
|---------|-------------|
| `library` | Browse and search the MITRE ATT&CK blog post library |
| `artifacts` | View and rebuild the Artifact Map (embedding index) |
| `builder` | Compile payloads and stealers interactively |
| `shellcode` | Shellcode analysis and XOR encoding tools |
| `yara` | YARA rule generator sub-REPL |
| `malpedia` | Threat actor and malware family lookup |
| `ttp` | Browse MITRE ATT&CK techniques |
| `vtscan` | VirusTotal scanner sub-REPL |
| `help` | Top-level help; `help <module>` for module-specific docs |
| `exit` / `quit` | Exit the CLI |

### `library` sub-REPL

Browse and search 200+ blog post techniques with inline source code display.

![img](./screenshots/2026-06-11_08-18.png)    

| command | description |
|---------|-------------|
| `list [category]` | List all techniques, optionally filtered by category |
| `search <query>` | Full-text search across technique titles and body |
| `show <slug>` | Display metadata panel + syntax-highlighted source code |
| `categories` | List all available categories |
| `help` | Show all library commands |

Categories include: `analysis`, `android`, `c2`, `credential-access`, `cryptography`, `discovery`, `evasion`, `execution`, `exfiltration`, `injection`, `linux`, `macos`, `persistence`, `privilege-escalation`, `reconnaissance`.

### `builder` sub-REPL

Interactive payload builder with the same options as the dashboard builder.

![img](./screenshots/2026-06-11_08-19.png)    

| command | description |
|---------|-------------|
| `build <injection> [options]` | Build an injection binary |
| `build stealer <name>` | Build a stealer (telegram, github, slack, virustotal, bitbucket, azure, angelcam) |
| `list injection` | List all injection techniques |
| `list stealer` | List all stealer modules |
| `list payload` | List available payloads |
| `list encryption` | List encryption algorithms |
| `list persistence` | List persistence methods |
| `history` | Show build history |
| `show <build-id>` | Show build metadata and download path |
| `search <query>` | Search injection techniques by partial name |
| `help` | Full builder help |

Example:
```
peekaboo builder > build virtualallocex -e speck -p meow -r registry
peekaboo builder > build stealer telegram
```

### `shellcode` sub-REPL

Shellcode analysis and transformation tools.

![img](./screenshots/2026-06-11_08-20.png)    

| command | description |
|---------|-------------|
| `analyse <path>` | Analyse raw shellcode: size, entropy, known pattern detection, hex dump |
| `encode <path> [key]` | XOR-encode shellcode with a given key (default: random) |
| `decode <path> [key]` | XOR-decode shellcode |
| `help` | Show all shellcode commands |

### `yara` sub-REPL

Generate and manage YARA rules from binaries.

![img](./screenshots/2026-06-11_08-21.png)    

| command | description |
|---------|-------------|
| `gen <path>` | Generate YARA rule from a PE binary at the given path |
| `gen-build [id] [fname]` | Generate rule from a compiled build binary |
| `gen-session <sid> <file>` | Generate rule from a session sample |
| `builds` | List available compiled builds |
| `save <path>` | Save the last generated rule to a `.yar` file |
| `show` | Print the last generated rule |
| `help` | Show all YARA commands |

### `malpedia` sub-REPL

Threat actor and malware family lookup against the Malpedia REST API with semantic blog post matching.

![img](./screenshots/2026-06-11_08-22.png)    

| command | description |
|---------|-------------|
| `actors` | List all threat actors |
| `families` | List all malware families |
| `search <query>` | Search actors and families by name, country, or alias |
| `actor <id>` | Show actor detail + semantically matched blog posts |
| `family <id>` | Show family detail + semantically matched blog posts |
| `help` | Show all Malpedia commands |

### `ttp` sub-REPL

Browse MITRE ATT&CK techniques.

![img](./screenshots/2026-06-11_08-22_1.png)    

| command | description |
|---------|-------------|
| `list [tactic]` | List all techniques, optionally filtered by tactic |
| `search <query>` | Search by technique name or description |
| `show <T-ID>` | Show full technique detail: tactic, description, detection notes, mapped blog posts |
| `tactics` | List all ATT&CK tactics |
| `help` | Show all TTP commands |

### `vtscan` sub-REPL

Submit binaries to VirusTotal and query results.

![img](./screenshots/2026-06-11_08-34.png)    

| command | description |
|---------|-------------|
| `scan <path>` | Upload a binary and start analysis |
| `scan <id> [fname]` | Upload from a compiled build (optionally specify file) |
| `list` | List available compiled builds with per-file entries |
| `poll <analysis-id>` | Poll a pending analysis for results |
| `lookup <sha256>` | Fetch existing VT report by SHA256 |
| `help` | Show all vtscan commands |


## Attention
This tool is a Proof of Concept and is for Educational Purposes Only!!! Author takes no responsibility of any damage you cause

## License
[MIT](https://choosealicense.com/licenses/mit/)
