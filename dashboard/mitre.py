"""
peekaboo MITRE ATT&CK + R&D library
auto-scans ~/hacking/cocomelonc.github.io/_posts and ~/hacking/meow
mitreattack-python 5.x + local STIX bundle
"""
from __future__ import annotations
import json
import os
import re
from pathlib import Path

_BASE          = Path(__file__).parent.parent
# Both paths are env-overridable so the indexer runs anywhere (GPU server, CI, etc).
_MEOW          = Path(os.environ.get("MEOW_ROOT") or "/home/cocomelonc/hacking/meow").expanduser()
_POSTS         = Path(os.environ.get("BLOG_POSTS_ROOT") or
                      "/home/cocomelonc/hacking/cocomelonc.github.io/_posts").expanduser()
STIX_PATH      = str(_BASE / "data" / "enterprise-attack.json")
_GROUPS_CACHE  = _BASE / "data" / "mitre_groups_cache.json"
_LIBRARY_CACHE = _BASE / "data" / "library_cache.json"

# ---------------------------------------------------------------------------
# TTP_IMPLEMENTATIONS  -- canonical curated mapping, seeded into the DB.
# Each entry: (attack_id, blog_slug, meow_slug, platform, notes)
# meow_slug = compilable slug for compiler.compile_module(); empty = no binary
# tech_name and tactic are resolved from STIX at seed time
# ---------------------------------------------------------------------------
TTP_IMPLEMENTATIONS: list[tuple[str, str, str, str, str]] = [

    # -- Windows persistence series ------------------------------------------
    ("T1547.001", "malware-pers-1",  "malware-pers-1",  "windows",
     "HKCU Run registry key persistence"),
    ("T1546.002", "malware-pers-2",  "malware-pers-2",  "windows",
     "Screensaver hijack via SCRNSAVE.EXE registry value"),
    ("T1546.015", "malware-pers-3",  "malware-pers-3",  "windows",
     "COM DLL hijack via CLSID key"),
    ("T1543.003", "malware-pers-4",  "malware-pers-4",  "windows",
     "Windows service creation via OpenSCManager / CreateService"),
    ("T1546.010", "malware-pers-5",  "malware-pers-5",  "windows",
     "AppInit_DLLs registry key injection"),
    ("T1546.007", "malware-pers-6",  "malware-pers-6",  "windows",
     "Netsh helper DLL via HKLM\\...\\Netsh"),
    ("T1547.004", "malware-pers-7",  "malware-pers-7",  "windows",
     "Winlogon Userinit/Shell value hijack"),
    ("T1547.010", "malware-pers-8",  "malware-pers-8",  "windows",
     "Port monitor DLL via HKLM\\...\\Print\\Monitors"),
    ("T1546.001", "malware-pers-9",  "malware-pers-9",  "windows",
     "Default file extension association hijack"),
    ("T1546.012", "malware-pers-10", "malware-pers-10", "windows",
     "Image File Execution Options debugger key injection"),
    ("T1546.013", "malware-pers-11", "malware-pers-11", "windows",
     "PowerShell profile hijack ($PROFILE)"),
    ("T1546.008", "malware-pers-12", "malware-pers-12", "windows",
     "Accessibility feature binary replace (sethc.exe / utilman.exe)"),
    ("T1546.015", "malware-pers-13", "malware-pers-13", "windows",
     "Uninstall key execution hijack via UninstallString"),
    ("T1546.015", "malware-pers-14", "malware-pers-14", "windows",
     "Event Viewer help link COM object hijack"),
    ("T1547.001", "malware-pers-15", "malware-pers-15", "windows",
     "Internet Explorer persistence via registry run key"),
    ("T1547.001", "malware-pers-16", "malware-pers-16", "windows",
     "Cryptography provider registry key persistence"),
    ("T1546.015", "malware-pers-18", "malware-pers-18", "windows",
     "Windows Error Reporting COM handler hijack"),
    ("T1546.015", "malware-pers-19", "malware-pers-19", "windows",
     "Disk Cleanup Utility COM object hijack"),
    ("T1037.001", "malware-pers-20", "",                "windows",
     "UserInitMprLogonScript logon script via registry"),
    ("T1546.015", "malware-pers-21", "malware-pers-21", "windows",
     "Recycle Bin / My Documents COM extension handler hijack"),
    ("T1547.001", "malware-pers-22", "malware-pers-22", "windows",
     "Windows Setup CmdLine registry key persistence"),
    ("T1204.001", "malware-pers-23", "malware-pers-23", "windows",
     "LNK shortcut file persistence via Startup folder"),
    ("T1547.001", "malware-pers-24", "malware-pers-24", "windows",
     "StartupApproved registry key bypass"),
    ("T1574.010", "malware-pers-25", "malware-pers-25", "windows",
     "Symlink from legitimate binary path to evil payload"),
    ("T1176",     "malware-pers-26", "malware-pers-26", "windows",
     "Microsoft Edge extension/profile persistence"),
    ("T1053.005", "malware-pers-27", "malware-pers-27", "windows",
     "Scheduled task persistence via Windows Task Scheduler API"),
    ("T1547.001", "malware-pers-28", "malware-pers-28", "windows",
     "CertPropSvc registry key hijack for persistence"),
    ("T1547.015", "malware-pers-29", "malware-pers-29", "windows",
     "Windows Terminal profile hijack for persistence"),

    # -- macOS persistence series --------------------------------------------
    ("T1543.001", "malware-mac-persistence-1",  "malware-mac-persistence-1",  "macos",
     "LaunchAgent plist persistence in ~/Library/LaunchAgents/"),
    ("T1546.004", "malware-mac-persistence-2",  "malware-mac-persistence-2",  "macos",
     "Shell environment hijacking via ~/.bash_profile / ~/.zshrc"),
    ("T1574.006", "malware-mac-persistence-3",  "malware-mac-persistence-3",  "macos",
     "Dylib hijacking via VLC plugin path (macOS dynamic linker)"),
    ("T1547.015", "mac-malware-persistence-4",  "mac-malware-persistence-4",  "macos",
     "macOS Login Items / AutoLaunched Applications (Background Items)"),
    ("T1053.003", "mac-malware-persistence-5",  "mac-malware-persistence-5",  "macos",
     "Cron job persistence via crontab"),
    ("T1556.003", "mac-malware-persistence-6",  "mac-malware-persistence-6",  "macos",
     "PAM module injection for credential access and persistence"),
    ("T1547.007", "mac-malware-persistence-7",  "mac-malware-persistence-7",  "macos",
     "macOS Re-opened Applications persistence (resume state)"),
    ("T1053.003", "mac-malware-persistence-8",  "mac-malware-persistence-8",  "macos",
     "macOS periodic scripts (/etc/periodic/) persistence"),
    ("T1546.014", "mac-malware-persistence-9",  "mac-malware-persistence-9",  "macos",
     "emond (Event Monitor Daemon) persistence rule injection"),
    ("T1562.001", "mac-malware-persistence-10", "mac-malware-persistence-10", "macos",
     "caffeinate LOLBin persistence (prevent sleep, stay resident)"),
    ("T1059.002", "mac-malware-persistence-11", "mac-malware-persistence-11", "macos",
     "osascript (AppleScript) LOLBin persistence"),

    # -- Process injection series --------------------------------------------
    ("T1055",     "malware-injection-1",  "malware-injection-1",  "windows",
     "Classic shellcode injection: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread"),
    ("T1055.001", "malware-injection-2",  "malware-injection-2",  "windows",
     "Classic DLL injection via LoadLibrary + CreateRemoteThread"),
    ("T1055.004", "malware-injection-3",  "malware-injection-3",  "windows",
     "APC injection via QueueUserAPC + EnumDesktopsA alertable trick"),
    ("T1055.004", "malware-injection-4",  "malware-injection-4",  "windows",
     "APC injection via NtTestAlert to flush APC queue"),
    ("T1055.004", "malware-injection-5",  "malware-injection-5",  "windows",
     "APC injection via alertable thread wait (SleepEx / WaitForSingleObjectEx)"),
    ("T1055.003", "malware-injection-6",  "malware-injection-6",  "windows",
     "Thread execution hijacking via GetThreadContext / SetThreadContext"),
    ("T1055.001", "malware-injection-7",  "malware-injection-7",  "windows",
     "DLL injection via SetWindowsHookEx global hook"),
    ("T1055",     "malware-injection-8",  "malware-injection-8",  "windows",
     "Shellcode injection via Windows Fibers"),
    ("T1055.001", "malware-injection-9",  "malware-injection-9",  "windows",
     "DLL injection via undocumented NtCreateThreadEx"),
    ("T1055",     "malware-injection-10", "malware-injection-10", "windows",
     "Code injection via undocumented NtAllocateVirtualMemory"),
    ("T1055",     "malware-injection-11", "malware-injection-11", "windows",
     "Code injection via undocumented Native API (Nt/Zw functions)"),
    ("T1055",     "malware-injection-12", "malware-injection-12", "windows",
     "Code injection via shared memory sections (NtCreateSection)"),
    ("T1055",     "malware-injection-13", "malware-injection-13", "windows",
     "Code injection via ZwCreateSection + ZwMapViewOfSection"),
    ("T1055.004", "malware-injection-14", "malware-injection-14", "windows",
     "Code injection via ZwCreateSection + ZwQueueApcThread"),
    ("T1055",     "malware-injection-15", "malware-injection-15", "windows",
     "Process injection via KernelCallbackTable pointer overwrite"),
    ("T1055",     "malware-injection-16", "malware-injection-16", "windows",
     "Process injection via RWX-memory hunting in target process"),
    ("T1055",     "malware-injection-17", "malware-injection-17", "windows",
     "Process injection via FindWindow + WM_COPYDATA message"),
    ("T1027",     "malware-injection-18", "malware-injection-18", "windows",
     "Find kernel32.dll base address via inline assembly (PEB walk)"),
    ("T1055",     "malware-injection-19", "malware-injection-19", "windows",
     "Download and inject payload from remote URL"),
    ("T1055.004", "malware-injection-20", "malware-injection-20", "windows",
     "Shellcode execution via EnumDesktopsA callback APC trick"),
    ("T1055.004", "malware-injection-21", "malware-injection-21", "windows",
     "Shellcode execution via EnumChildWindows callback trick"),
    ("T1055.015", "malware-tricks-24",    "malware-tricks-24",    "windows",
     "ListPlanting injection via EM_SETTEXTEX into list view"),

    # -- DLL hijacking -------------------------------------------------------
    ("T1574.001", "dll-hijacking-1", "dll-hijacking-1", "windows",
     "DLL search order hijacking"),
    ("T1574.001", "dll-hijacking-2", "dll-hijacking-2", "windows",
     "DLL hijacking with exported function forwarding (Microsoft Teams example)"),

    # -- C2 / exfiltration via legitimate services ---------------------------
    ("T1102",     "malware-trick-40",  "",                "windows",
     "C2 via Telegram Bot API (legitimate web service)"),
    ("T1041",     "malware-tricks-44", "",                "windows",
     "Exfiltration via GitHub Issues API comment"),
    ("T1071",     "malware-trick-41",  "",                "windows",
     "Exfiltration via VirusTotal comment API"),
    ("T1071.001", "malware-tricks-51", "",                "windows",
     "Exfiltration via Bitbucket webhook registration API"),
    ("T1567",     "malware-tricks-49", "",                "windows",
     "Exfiltration via Azure DevOps work item creation API"),
    ("T1567.002", "malware-tricks-54", "",                "windows",
     "Exfiltration via Angelcam camera registration API"),

    # -- Evasion -------------------------------------------------------------
    ("T1027",     "malware-av-evasion-1",  "malware-av-evasion-1",  "windows",
     "AV evasion via payload encoding (XOR)"),
    ("T1027",     "malware-av-evasion-2",  "malware-av-evasion-2",  "windows",
     "AV evasion via custom base64 encoding"),
    ("T1027",     "malware-av-evasion-3",  "malware-av-evasion-3",  "windows",
     "AV evasion via payload splitting and reconstruction"),
    ("T1027",     "malware-av-evasion-4",  "malware-av-evasion-4",  "windows",
     "AV evasion via string obfuscation"),
    ("T1027",     "malware-av-evasion-5",  "malware-av-evasion-5",  "windows",
     "AV evasion via sleep-based sandbox evasion"),
    ("T1027",     "malware-av-evasion-6",  "malware-av-evasion-6",  "windows",
     "AV evasion via payload encryption (AES)"),
    ("T1562.001", "malware-av-evasion-7",  "malware-av-evasion-7",  "windows",
     "Disable Windows Defender via registry keys"),
    ("T1027",     "malware-av-evasion-8",  "malware-av-evasion-8",  "windows",
     "AV evasion via indirect API calls"),
    ("T1027",     "malware-av-evasion-9",  "malware-av-evasion-9",  "windows",
     "AV evasion via payload in PE resources"),
    ("T1622",     "malware-av-evasion-10", "malware-av-evasion-10", "windows",
     "Debugger evasion via IsDebuggerPresent / NtQueryInformationProcess"),
    ("T1027",     "malware-av-evasion-11", "malware-av-evasion-11", "windows",
     "AV evasion via syscall unhooking"),
    ("T1027",     "malware-av-evasion-12", "malware-av-evasion-12", "windows",
     "AV evasion via payload stomping"),
    ("T1027",     "malware-av-evasion-13", "malware-av-evasion-13", "windows",
     "AV evasion via AMSI bypass"),
    ("T1027",     "malware-av-evasion-14", "malware-av-evasion-14", "windows",
     "AV evasion via ETW patching"),
    ("T1027",     "malware-av-evasion-15", "malware-av-evasion-15", "windows",
     "AV evasion via Heaven's Gate (WOW64 transition)"),
    ("T1027",     "malware-av-evasion-16", "malware-av-evasion-16", "windows",
     "AV evasion via stack strings / compile-time obfuscation"),
    ("T1112",     "malware-av-evasion-17", "malware-av-evasion-17", "windows",
     "Modify registry to disable security tools"),
    ("T1564.004", "malware-tricks-35",     "malware-tricks-35",     "windows",
     "NTFS alternate data stream (ADS) hiding"),

    # -- Cryptography / obfuscation series -----------------------------------
    ("T1027.013", "malware-cryptography-1",  "malware-cryptography-1",  "windows",
     "Payload encryption: RC4"),
    ("T1027.013", "malware-cryptography-2",  "malware-cryptography-2",  "windows",
     "Payload encryption: AES-CBC (custom implementation)"),
    ("T1027.013", "malware-cryptography-3",  "malware-cryptography-3",  "windows",
     "Payload encryption: XOR with key rotation"),
    ("T1027.013", "malware-cryptography-4",  "malware-cryptography-4",  "windows",
     "Payload encryption: ChaCha20"),
    ("T1027.013", "malware-cryptography-5",  "malware-cryptography-5",  "windows",
     "Payload encryption: Blowfish"),
    ("T1027.013", "malware-cryptography-6",  "malware-cryptography-6",  "windows",
     "Payload encoding: Base58"),
    ("T1027.013", "malware-cryptography-7",  "malware-cryptography-7",  "windows",
     "Payload encoding: Base85"),
    ("T1027.013", "malware-cryptography-8",  "malware-cryptography-8",  "windows",
     "Payload obfuscation: UUID encoding"),
    ("T1027.013", "malware-cryptography-9",  "malware-cryptography-9",  "windows",
     "Payload obfuscation: IPv4/IPv6 fused encoding"),
    ("T1027.013", "malware-cryptography-10", "malware-cryptography-10", "windows",
     "Payload obfuscation: MAC address encoding"),
    ("T1027.013", "malware-cryptography-11", "malware-cryptography-11", "windows",
     "Payload obfuscation: morse code encoding"),
    ("T1027.013", "malware-cryptography-12", "malware-cryptography-12", "windows",
     "Payload obfuscation: XTEA encryption"),
    ("T1027.013", "malware-cryptography-13", "malware-cryptography-13", "windows",
     "Payload obfuscation: IDEA cipher"),
    ("T1027.013", "malware-cryptography-14", "malware-cryptography-14", "windows",
     "Payload obfuscation: ROT13 / Caesar cipher"),
    ("T1027.013", "malware-cryptography-15", "malware-cryptography-15", "windows",
     "Payload obfuscation: Vigenere cipher"),
    ("T1027.013", "malware-cryptography-16", "malware-cryptography-16", "windows",
     "Payload obfuscation: Twofish cipher"),
    ("T1027.013", "malware-cryptography-17", "malware-cryptography-17", "windows",
     "Payload obfuscation: Rabbit stream cipher"),
    ("T1027.013", "malware-cryptography-18", "malware-cryptography-18", "windows",
     "Payload obfuscation: HC-128 stream cipher"),
    ("T1027.013", "malware-cryptography-19", "malware-cryptography-19", "windows",
     "Payload obfuscation: SEED cipher"),
    ("T1027.013", "malware-cryptography-20", "malware-cryptography-20", "windows",
     "Payload obfuscation: DES cipher"),
    ("T1027.013", "malware-cryptography-21", "malware-cryptography-21", "windows",
     "Payload obfuscation: 3DES cipher"),
    ("T1027.013", "malware-cryptography-22", "malware-cryptography-22", "windows",
     "Payload obfuscation: Camellia cipher"),
    ("T1027.013", "malware-cryptography-23", "malware-cryptography-23", "windows",
     "Payload obfuscation: CAST-128 cipher"),
    ("T1027.013", "malware-cryptography-24", "malware-cryptography-24", "windows",
     "Payload obfuscation: MARS cipher"),
    ("T1012",     "malware-cryptography-35", "malware-cryptography-35", "windows",
     "Registry query for victim host enumeration"),
    ("T1027.013", "malware-cryptography-36", "malware-cryptography-36", "windows",
     "Payload obfuscation: Salsa20 cipher"),
    ("T1027.013", "malware-cryptography-37", "malware-cryptography-37", "windows",
     "Payload obfuscation: Serpent cipher"),
    ("T1027.013", "malware-cryptography-38", "malware-cryptography-38", "windows",
     "Payload obfuscation: PRESENT lightweight cipher"),
    ("T1027.013", "malware-cryptography-39", "malware-cryptography-39", "windows",
     "Payload obfuscation: PRINCE cipher"),
    ("T1027.013", "malware-cryptography-40", "malware-cryptography-40", "windows",
     "Payload obfuscation: SKINNY cipher"),
    ("T1027.013", "malware-cryptography-41", "malware-cryptography-41", "windows",
     "Payload obfuscation: SIMON cipher"),
    ("T1027.013", "malware-cryptography-42", "malware-cryptography-42", "windows",
     "Payload obfuscation: SPECK cipher"),
    ("T1027.013", "malware-cryptography-43", "malware-cryptography-43", "windows",
     "Payload obfuscation: ASCON-128 AEAD cipher"),
    ("T1027.013", "malware-cryptography-44", "malware-cryptography-44", "windows",
     "Payload obfuscation: GIFT-64 cipher"),

    # -- Hooking / keylogging ------------------------------------------------
    ("T1056.001", "basic-hooking-1", "basic-hooking-1", "windows",
     "Keylogging via SetWindowsHookEx WH_KEYBOARD_LL"),
    ("T1056.001", "basic-hooking-2", "basic-hooking-2", "windows",
     "Keylogging via GetAsyncKeyState polling"),

    # -- Syscalls / native API -----------------------------------------------
    ("T1106",     "syscalls-1", "syscalls-1", "windows",
     "Direct syscall invocation to bypass user-mode hooks (Hell's Gate)"),
    ("T1106",     "syscalls-2", "syscalls-2", "windows",
     "Indirect syscalls via SSN spoofing"),

    # -- Privilege escalation / token theft ----------------------------------
    ("T1134",     "token-theft-1", "token-theft-1", "windows",
     "Token duplication via OpenProcessToken + DuplicateTokenEx"),
    ("T1134",     "token-theft-2", "token-theft-2", "windows",
     "Token impersonation via ImpersonateLoggedOnUser"),
    ("T1134.001", "malware-tricks-28", "malware-tricks-28", "windows",
     "Token theft via SeDebugPrivilege + NtOpenProcessToken"),

    # -- Discovery -----------------------------------------------------------
    ("T1082",     "malware-cryptography-35", "malware-cryptography-35", "windows",
     "System information discovery (OS version, processor, drives)"),

    # -- Shellcoding ---------------------------------------------------------
    ("T1059.006", "windows-shellcoding-1", "windows-shellcoding-1", "windows",
     "Position-independent shellcode: MessageBox via PEB walk"),
    ("T1059.006", "windows-shellcoding-2", "windows-shellcoding-2", "windows",
     "Position-independent shellcode: reverse shell"),
    ("T1059.006", "windows-shellcoding-3", "windows-shellcoding-3", "windows",
     "Shellcode: custom EggHunter technique"),

    # -- Clipboard / collection ----------------------------------------------
    ("T1115",     "malware-tricks-47", "malware-tricks-47", "windows",
     "Clipboard data theft via OpenClipboard / GetClipboardData"),

    # -- Tricks / misc -------------------------------------------------------
    ("T1027",     "malware-tricks-18", "malware-tricks-18", "windows",
     "Payload obfuscation via PE section entropy manipulation"),
    ("T1027",     "malware-tricks-19", "malware-tricks-19", "windows",
     "Payload obfuscation via import table obfuscation"),
    ("T1027",     "malware-tricks-20", "malware-tricks-20", "windows",
     "Payload obfuscation via function pointer indirection"),
    ("T1055",     "malware-tricks-21", "malware-tricks-21", "windows",
     "Early Bird APC injection trick"),
    ("T1027",     "malware-tricks-22", "malware-tricks-22", "windows",
     "Anti-analysis: timing-based sandbox detection"),
    ("T1027",     "malware-tricks-23", "malware-tricks-23", "windows",
     "Anti-analysis: CPUID-based VM detection"),
    ("T1027",     "malware-tricks-25", "malware-tricks-25", "windows",
     "Heaven's Gate: 32-bit process calling 64-bit code"),
    ("T1027",     "malware-tricks-26", "malware-tricks-26", "windows",
     "Payload obfuscation via custom hash function for API resolution"),
    ("T1027",     "malware-tricks-27", "malware-tricks-27", "windows",
     "Anti-analysis: parent process check / PPID spoofing"),
    ("T1055",     "malware-tricks-29", "malware-tricks-29", "windows",
     "Process injection via NTFS transaction (Process Doppelganging)"),
    ("T1055",     "malware-tricks-30", "malware-tricks-30", "windows",
     "Process injection via module stomping"),
    ("T1027",     "malware-tricks-31", "malware-tricks-31", "windows",
     "Payload obfuscation via polymorphic XOR"),
    ("T1027",     "malware-tricks-32", "malware-tricks-32", "windows",
     "Anti-disassembly: junk byte insertion"),
    ("T1027",     "malware-tricks-33", "malware-tricks-33", "windows",
     "Payload obfuscation via control-flow flattening"),
    ("T1055",     "malware-tricks-34", "malware-tricks-34", "windows",
     "Ghost injection via NtCreateProcessEx"),
    ("T1027",     "malware-tricks-36", "malware-tricks-36", "windows",
     "Payload obfuscation: custom compression"),
    ("T1027",     "malware-tricks-37", "malware-tricks-37", "windows",
     "Payload obfuscation: LZNT1 compression"),
    ("T1027",     "malware-tricks-38", "malware-tricks-38", "windows",
     "Anti-analysis: hardware breakpoint detection via DR registers"),
    ("T1027",     "malware-tricks-39", "malware-tricks-39", "windows",
     "Anti-analysis: exception-based debugger detection"),
    ("T1059",     "malware-tricks-40", "malware-tricks-40", "windows",
     "Execute payload via WMI (WScript / COM)"),
    ("T1027",     "malware-tricks-41", "malware-tricks-41", "windows",
     "Payload obfuscation via binary watermarking"),
    ("T1027",     "malware-tricks-42", "malware-tricks-42", "windows",
     "Payload obfuscation: format string obfuscation"),
    ("T1027",     "malware-tricks-43", "malware-tricks-43", "windows",
     "API hashing for import obfuscation (djb2 / FNV)"),
    ("T1027",     "malware-tricks-45", "malware-tricks-45", "windows",
     "Anti-analysis: TLS callback anti-debug trick"),
    ("T1027",     "malware-tricks-46", "malware-tricks-46", "windows",
     "Payload obfuscation via code cave technique"),
    ("T1115",     "malware-tricks-47", "malware-tricks-47", "windows",
     "Clipboard hijacking for data theft / crypto address swap"),
    ("T1059",     "malware-tricks-48", "malware-tricks-48", "windows",
     "Execute payload via LOLBin (certutil / regsvr32)"),
    ("T1027",     "malware-tricks-50", "malware-tricks-50", "windows",
     "Payload obfuscation: stack-based string decryption"),
    ("T1027",     "malware-tricks-52", "malware-tricks-52", "windows",
     "Anti-analysis: NtQuerySystemInformation sandbox detection"),
    ("T1027",     "malware-tricks-53", "malware-tricks-53", "windows",
     "Payload obfuscation via call instruction encoding"),
    ("T1027",     "malware-tricks-55", "malware-tricks-55", "windows",
     "Anti-analysis: TEB-based debugger detection"),
    ("T1027",     "malware-tricks-56", "malware-tricks-56", "windows",
     "Payload obfuscation: binary padding / section bloating"),
    ("T1027",     "malware-tricks-57", "malware-tricks-57", "windows",
     "Anti-analysis: heap flags / ForceFlags check"),
    ("T1027",     "malware-tricks-58", "malware-tricks-58", "windows",
     "Anti-analysis: output debug string anti-debug"),
]


def _ttp_impl_as_peekaboo_module(entry: tuple) -> dict:
    attack_id, blog_slug, meow_slug, platform, notes = entry
    return {
        "category": blog_slug.split("-")[1] if "-" in blog_slug else "other",
        "blog_url":  "",
        "snippet":   None,
        "module":    meow_slug or None,
    }


# Backward-compat dict used by get_all_techniques() and get_group_techniques().
# Derived from TTP_IMPLEMENTATIONS: one entry per attack_id (first occurrence wins).
def _build_peekaboo_modules() -> dict:
    seen: dict[str, dict] = {}
    for entry in TTP_IMPLEMENTATIONS:
        attack_id, blog_slug, meow_slug, platform, notes = entry
        if attack_id in seen:
            continue
        seen[attack_id] = {
            "category": (
                "persistence" if "pers" in blog_slug
                else "injection" if "injection" in blog_slug or "hijack" in blog_slug
                else "evasion"   if "evasion" in blog_slug or "crypto" in blog_slug or "trick" in blog_slug
                else "c2"        if "trick-4" in blog_slug
                else "hooking"   if "hook" in blog_slug
                else "syscalls"  if "syscall" in blog_slug
                else "privesc"   if "token" in blog_slug
                else "other"
            ),
            "blog_url": "",
            "snippet":  None,
            "module":   meow_slug or None,
        }
    return seen


PEEKABOO_MODULES: dict[str, dict] = _build_peekaboo_modules()

# slug keyword -> (category, fallback_attack_id)
_SLUG_RULES: list[tuple[str, str, str | None]] = [
    (r"injection|inject",           "injection",       "T1055"),
    (r"dll.hijack|dllhijack",       "injection",       "T1574.001"),
    (r"malware.pers|pers-\d",       "persistence",     "T1547"),
    (r"mac.+pers|pers.+mac",        "persistence",     None),
    (r"av.evasion|evasion",         "evasion",         "T1027"),
    (r"cryptography|crypto",        "cryptography",    "T1027"),
    (r"hooking",                    "hooking",         "T1056"),
    (r"shellcod",                   "shellcoding",     "T1059"),
    (r"token.theft|token",          "privesc",         "T1134"),
    (r"syscall",                    "syscalls",        "T1106"),
    (r"reverse.shell",              "c2",              "T1059"),
    (r"pivoting",                   "network",         "T1090"),
    (r"linux.hack|linux",           "linux",           None),
    (r"malware.mac|mac.malware|mac","macos",           None),
    (r"android",                    "android",         None),
    (r"malware.trick|trick",        "tricks",          None),
    (r"malware.analysis|analysis",  "analysis",        None),
    (r"mem.forensic|forensic",      "analysis",        None),
    (r"inline.asm|asm",             "evasion",         "T1027"),
    (r"overflow",                   "exploitation",    "T1203"),
    (r"hvck",                       "tricks",          None),
    (r"rev.c|simple.rev",           "c2",              "T1059"),
]

# explicit ATT&CK ID -> canonical category (overrides slug-inferred category)
_AID_CATEGORY: dict[str, str] = {
    "T1003": "credential-access",
    "T1012": "discovery",
    "T1027": "evasion",
    "T1041": "c2",
    "T1053": "persistence",
    "T1055": "injection",
    "T1056": "hooking",
    "T1059": "execution",
    "T1071": "c2",
    "T1082": "discovery",
    "T1090": "network",
    "T1102": "c2",
    "T1106": "syscalls",
    "T1112": "evasion",
    "T1115": "tricks",
    "T1134": "privesc",
    "T1183": "persistence",
    "T1204": "execution",
    "T1543": "persistence",
    "T1546": "persistence",
    "T1547": "persistence",
    "T1562": "evasion",
    "T1564": "evasion",
    "T1567": "c2",
    "T1574": "injection",
    "T1622": "evasion",
}

_ATTACK_RE = re.compile(r'\bT1\d{3}(?:\.\d{3})?\b')


def _category_from_slug(slug: str) -> tuple[str, str | None]:
    s = slug.lower()
    for pattern, cat, aid in _SLUG_RULES:
        if re.search(pattern, s):
            return cat, aid
    return "other", None


def _find_meow_source(date_str: str) -> str | None:
    if not _MEOW.exists():
        return None
    for d in _MEOW.iterdir():
        if not (d.is_dir() and d.name.startswith(date_str)):
            continue
        preferred_stems = {"hack", "evil", "main", "pers", "inject", "mal", "shellcode"}
        # search order: C/C++ first, then assembly - root level before recursive
        for glob_fn, exts in [
            (d.glob,  ("*.c", "*.cpp", "*.nim", "*.asm", "*.s")),
            (d.rglob, ("*.c", "*.cpp", "*.nim", "*.asm", "*.s")),
        ]:
            for ext in exts:
                files = sorted(glob_fn(ext))
                preferred = [f for f in files if f.stem in preferred_stems]
                if preferred:
                    return str(preferred[0])
                if files:
                    return str(files[0])
    return None


def _read_snippet(path: str | Path | None, max_lines: int = 40) -> str:
    if not path:
        return ""
    try:
        p = Path(path)
        if not p.exists():
            return ""
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[:max_lines])
    except Exception:
        return ""


def _blog_url(date_str: str, slug: str, categories: list[str]) -> str:
    y, m, d = date_str.split("-")
    cat = categories[0] if categories else "malware"
    return f"https://cocomelonc.github.io/{cat}/{y}/{m}/{d}/{slug}.html"


def seed_ttp_implementations() -> int:
    """
    Populate ttp_implementations table from TTP_IMPLEMENTATIONS.
    Resolves tech_name + tactic from STIX bundle.
    Resolves blog_url from mitre_library DB.
    Returns number of rows inserted/updated.
    """
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    import db

    # build STIX lookup for tech_name / tactic
    lookup = _build_tech_lookup()

    # build blog_url lookup from mitre_library
    lib_rows = db.get_mitre_entries()
    slug_to_url: dict[str, str] = {e["slug"]: e.get("blog_url", "") for e in lib_rows}

    entries: list[dict] = []
    for (attack_id, blog_slug, meow_slug, platform, notes) in TTP_IMPLEMENTATIONS:
        stix     = lookup.get(attack_id)
        tactic   = ""
        tech_name = attack_id
        if stix:
            phases    = stix.get("kill_chain_phases", [])
            tactic    = phases[0]["phase_name"] if phases else ""
            tech_name = stix.get("name", attack_id)
        entries.append({
            "attack_id": attack_id,
            "tactic":    tactic,
            "tech_name": tech_name,
            "blog_slug": blog_slug,
            "blog_url":  slug_to_url.get(blog_slug, ""),
            "meow_slug": meow_slug,
            "platform":  platform,
            "notes":     notes,
        })

    return db.upsert_ttp_implementations(entries)


def build_library_cache() -> list[dict]:
    if not _POSTS.exists():
        return []

    entries = []
    for f in sorted(_POSTS.glob("*.markdown")):
        stem     = f.stem
        date_str = stem[:10]
        slug     = stem[11:]
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # parse front matter
        fm_match = re.match(r'^---\s*\n(.*?)\n---', text, re.DOTALL)
        title, fm_cats = slug.replace("-", " ").title(), []
        if fm_match:
            fm = fm_match.group(1)
            tm = re.search(r'^title:\s*["\']?(.+?)["\']?\s*$', fm, re.MULTILINE)
            if tm:
                title = tm.group(1).strip('"\'')
            fm_cats = re.findall(r'^  - (\S+)', fm, re.MULTILINE)

        body      = text[fm_match.end():] if fm_match else text
        body_aids = sorted(set(_ATTACK_RE.findall(body)))

        category, slug_aid = _category_from_slug(slug)
        attack_ids = body_aids if body_aids else ([slug_aid] if slug_aid else [])

        # explicit ATT&CK IDs in body override slug-inferred category
        if body_aids:
            base_id = body_aids[0].split(".")[0]
            category = _AID_CATEGORY.get(body_aids[0],
                       _AID_CATEGORY.get(base_id, category))

        src_path   = _find_meow_source(date_str)
        blog_url   = _blog_url(date_str, slug, fm_cats)
        peekaboo_m = next((m for aid in attack_ids for m in [PEEKABOO_MODULES.get(aid)] if m), None)

        entry: dict = {
            "date":       date_str,
            "slug":       slug,
            "title":      title,
            "category":   category,
            "attack_ids": attack_ids,
            "blog_url":   blog_url,
            "src_path":   src_path,
            "snippet":    _read_snippet(src_path),
            "module":     peekaboo_m.get("module") if peekaboo_m else None,
            "implemented": peekaboo_m is not None,
        }
        entries.append(entry)

    entries.sort(key=lambda x: x["date"], reverse=True)

    _LIBRARY_CACHE.write_text(json.dumps(entries, separators=(",", ":")))
    print(f"[mitre] library cache: {len(entries)} posts -> {_LIBRARY_CACHE}")
    return entries


def get_library(category: str = "all") -> list[dict]:
    if _LIBRARY_CACHE.exists():
        try:
            entries = json.loads(_LIBRARY_CACHE.read_text())
        except Exception:
            entries = build_library_cache()
    else:
        entries = build_library_cache()

    if category == "all":
        return entries
    return [e for e in entries if e["category"] == category]


# -- ATT&CK data ----------------------------------------------------------------

_attack_data              = None
_tech_lookup: dict | None = None


def _load_attack():
    global _attack_data
    if _attack_data is not None:
        return _attack_data
    try:
        from mitreattack.stix20 import MitreAttackData
        _attack_data = MitreAttackData(STIX_PATH)
        return _attack_data
    except Exception as e:
        print(f"[mitre] failed to load STIX bundle: {e}")
        return None


def _build_tech_lookup() -> dict:
    global _tech_lookup
    if _tech_lookup is not None:
        return _tech_lookup
    ma = _load_attack()
    _tech_lookup = {}
    if not ma:
        return _tech_lookup
    try:
        for t in ma.get_techniques(include_subtechniques=True):
            ext_refs = t.get("external_references", [])
            aid = next(
                (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                None,
            )
            if aid:
                _tech_lookup[aid] = t
    except Exception as e:
        print(f"[mitre] tech lookup error: {e}")
    return _tech_lookup


def _extract_tech(item) -> object | None:
    if isinstance(item, dict) and "object" in item:
        return item["object"]
    if isinstance(item, (list, tuple)) and len(item) > 0:
        return item[0]
    return item


def get_groups() -> list[dict]:
    if _GROUPS_CACHE.exists():
        try:
            return json.loads(_GROUPS_CACHE.read_text())
        except Exception:
            pass
    ma = _load_attack()
    if not ma:
        return []
    try:
        result = []
        for g in ma.get_groups():
            result.append({
                "id":      g.get("id", ""),
                "name":    g.get("name", ""),
                "aliases": g.get("aliases", []),
            })
        return sorted(result, key=lambda x: x["name"])
    except Exception as e:
        print(f"[mitre] get_groups error: {e}")
        return []


def get_group_techniques(group_stix_id: str, category: str = "all") -> list[dict]:
    ma = _load_attack()
    if not ma:
        return []
    try:
        fn = getattr(ma, "get_techniques_used_by_group", None) \
          or getattr(ma, "get_techniques_by_group", None)
        if not fn:
            return []

        raw  = fn(group_stix_id)
        seen: set[str]   = set()
        results: list[dict] = []

        for item in raw:
            tech = _extract_tech(item)
            if tech is None:
                continue
            ext_refs  = tech.get("external_references", [])
            attack_id = next(
                (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                None,
            )
            if not attack_id or attack_id in seen:
                continue
            seen.add(attack_id)

            pm  = PEEKABOO_MODULES.get(attack_id)
            cat = pm["category"] if pm else "other"
            if category != "all" and cat != category:
                continue

            tactics = [p["phase_name"] for p in tech.get("kill_chain_phases", [])]
            desc    = (tech.get("description") or "").replace("\n", " ")[:280]

            entry: dict = {
                "attack_id":   attack_id,
                "name":        tech.get("name", ""),
                "description": desc,
                "tactics":     tactics,
                "category":    cat,
                "has_example": pm is not None,
            }
            if pm:
                entry["blog_url"] = pm["blog_url"]
                entry["module"]   = pm.get("module")
                entry["snippet"]  = _read_snippet(pm["snippet"])

            results.append(entry)

        return sorted(results, key=lambda x: x["attack_id"])

    except Exception as e:
        print(f"[mitre] get_group_techniques error: {e}")
        return []


def get_all_techniques() -> list[dict]:
    lookup = _build_tech_lookup()
    results = []
    for attack_id, pm in PEEKABOO_MODULES.items():
        stix = lookup.get(attack_id)
        desc, tactics = "", []
        if stix:
            desc    = (stix.get("description") or "").replace("\n", " ")[:320]
            tactics = [p["phase_name"] for p in stix.get("kill_chain_phases", [])]
        results.append({
            "attack_id":   attack_id,
            "name":        stix.get("name", attack_id) if stix else attack_id,
            "category":    pm["category"],
            "description": desc,
            "tactics":     tactics,
            "blog_url":    pm["blog_url"],
            "module":      pm.get("module"),
            "snippet":     _read_snippet(pm["snippet"]),
            "has_example": True,
        })
    return sorted(results, key=lambda x: (x["category"], x["attack_id"]))


def available() -> bool:
    return Path(STIX_PATH).exists() or _GROUPS_CACHE.exists()
