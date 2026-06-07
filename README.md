# Peekaboo

![img](./screenshots/2026-04-28_23-40.png)          

Peekaboo is a modular framework designed to safely emulate malware behavior. It allows security researchers, red teamers, and blue teamers to reproduce complex threat scenarios - including Command & Control (C2) communication, persistence mechanisms, and lateral movement - without using destructive payloads.     

**The goal of Peekaboo is to accelerate detection engineering and operator training by providing predictable, reproducible, and safe threat artifacts.**    

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
- **AI assistant** - local RAG chatbot (Ollama/qwen3) trained on blog posts and codebase; also supports Claude and Gemini.
- **APT campaign pipeline** - end-to-end automated pipeline: Malpedia actor → threat reports → TTP extraction (Claude API + regex) → module selection → binary compile. Full session history stored in SQLite with per-session report links, TTPs, and download access.
- **safe by design:** Focuses on telemetry generation (process creation, network connections) rather than actual system damage.      

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

![img](./screenshots/2026-04-28_23-40.png)

### modules

| module | description |
|--------|-------------|
| **Builder** | Compile payloads and stealers from source templates with live build log streaming |
| **Beacons** | Real-time monitoring of active agents - hostname, OS, IP, check-in time |
| **C2** | Deliver compiled binaries over Telegram, GitHub, VirusTotal, Bitbucket |
| **Config** | Inline editor for all API keys and service configs (Telegram, GitHub, Azure, Angelcam, Ollama, Gemini, etc.) |
| **AI Assistant** | RAG chatbot with support for Claude, Gemini, and local Ollama (qwen3); answers questions about the codebase and blog posts |
| **APT Campaign** | Fully automated pipeline: actor → reports → TTP extraction → module selection → binary compile |
| **MITRE ATT&CK** | Browse 200+ blog posts mapped to ATT&CK techniques with inline source code viewer |
| **Malpedia** | Threat actor and malware family lookup with semantic blog post matching |

### MITRE ATT&CK R&D

The MITRE ATT&CK tab indexes all blog posts from the [meow](https://github.com/cocomelonc/meow) research repository and maps them to ATT&CK technique IDs found in the post body. Source code is extracted automatically from the post directory - supporting C, C++, Nim, and assembly (`.asm`/`.s`) files, including posts where source is nested inside subdirectories.

![img](./screenshots/2026-04-28_23-40.png)

- filter by category (injection, persistence, evasion, cryptography, linux, macos, etc.)
- click any technique to expand the inline source code snippet
- **Full Reindex** button re-runs library scan → semantic embeddings → knowledge base in one shot with live progress per step

### Malpedia integration

The Malpedia tab connects to the [Malpedia REST API](https://malpedia.caad.fkie.fraunhofer.de/) to browse threat actors and malware families. For each actor or family, related blog posts are matched using **semantic similarity** - the actor/family description is embedded via `nomic-embed-text` (Ollama), then cosine-ranked against all 200+ cached post embeddings. No hardcoded keyword rules.   

![img](./screenshots/2026-05-01_01-55_1.png)

- search actors by name, country, or malware family
- expand any actor/family to see techniques, aliases, and semantically matched blog posts with similarity score
- requires a Malpedia API key in `config/malpedia_config.json`

### APT campaign pipeline

The APT Campaign tab runs a fully automated, five-stage pipeline that takes a Malpedia actor or family identifier and produces a ready-to-test compiled binary in one shot.

![img](./screenshots/2026-06-07_23-57.png)

**Pipeline stages:**

| # | Stage | What it does |
|---|-------|--------------|
| 1 | **Malpedia Fetch** | Resolves the actor or family ID against the Malpedia REST API and retrieves associated metadata (country, aliases, malware families, report URLs) |
| 2 | **Report Download** | Downloads up to 10 linked threat intelligence reports and stores raw content in SQLite for later inspection |
| 3 | **TTP Extraction** | Extracts MITRE ATT&CK technique IDs from report text - uses the Claude API for structured extraction with a regex fallback when no API key is configured |
| 4 | **Module Selection** | Maps extracted TTPs to available peekaboo modules (injection, crypto, stealer, persistence) and selects the best match per technique |
| 5 | **Binary Compile** | Runs the peekaboo builder with the selected parameters and produces a Windows PE ready for EDR testing |

![img](./screenshots/2026-06-08_00-01.png)

All pipeline progress streams live to the right panel as it runs - reports appear as clickable links the moment they are downloaded, TTPs and selected modules are appended on completion of each stage, and the final binary is immediately available for download. Every session is persisted to SQLite; click any row in **Past Sessions** to open a drawer showing:

- **Reports** tab - list of downloaded reports with a direct link to the original URL and character count
- **TTPs** tab - full list of extracted ATT&CK techniques with tactic and evidence quote
- **Binary** tab - build configuration badges, per-file download links, and selected modules

**Configuration:** set `api_key` in `config/anthropic_config.json` to enable Claude-powered TTP extraction. Without it the pipeline falls back to regex matching of `T1xxx` IDs in report text.

### AI assistant

The AI assistant answers questions about malware techniques, the codebase, and blog posts using RAG (Retrieval-Augmented Generation). At query time the question is embedded and matched against all blog post embeddings; the top matching posts are injected as context into the LLM prompt.   

![img](./screenshots/2026-05-01_01-55.png)

Supported providers:
- **Local (Ollama)** - `qwen3:4b` (or any Ollama model); runs fully offline; thinking mode tokens are filtered before streaming to the UI
- **Claude** (Anthropic API key required)
- **Gemini** (Google API key required)    

## virus total result:
02 september 2021

![virustotal](./screenshots/11.png?raw=true)

[https://www.virustotal.com/gui/file/c930b9aeab693d36c68e7bcf6353c7515b8fffc8f9a9233e49e90da49ab5d470/detection](https://www.virustotal.com/gui/file/c930b9aeab693d36c68e7bcf6353c7515b8fffc8f9a9233e49e90da49ab5d470/detection)

30 december 2021 (NT API injector)    

![virtustotal 2](./screenshots/16.png?raw=true)    

[https://www.virustotal.com/gui/file/743f50e92c6ef48d6514e0ce2a255165f83afb1ae66deefd68dac50d80748e55/detection](https://www.virustotal.com/gui/file/743f50e92c6ef48d6514e0ce2a255165f83afb1ae66deefd68dac50d80748e55/detection)    

## antiscan.me result:

11 january 2022 (NT API injector)    

![antiscan](./screenshots/antiscan.png?raw=true)    

[https://antiscan.me/scan/new/result?id=rQVfQhoFYgH9](https://antiscan.me/scan/new/result?id=rQVfQhoFYgH9)    

## websec.nl scanner result:

10 October 2024     

![websec](./screenshots/websec.png?raw=true)     

[https://websec.net/scanner/result/a3583316-cb72-4894-bd22-48241ca79db9](https://websec.net/scanner/result/a3583316-cb72-4894-bd22-48241ca79db9)     

## Attention
This tool is a Proof of Concept and is for Educational Purposes Only!!! Author takes no responsibility of any damage you cause

## License
[MIT](https://choosealicense.com/licenses/mit/)
