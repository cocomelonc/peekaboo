"""
artifact_parser.py — Sigma → ATT&CK technique artifact map.

Walks ~/hacking/sigma recursively, parses each .yml rule, extracts the
technique IDs, event IDs, registry keys, process images, and command-line
patterns referenced in `detection:`, and aggregates everything per technique.

Design:
  * One pure parse phase  — Path → ParsedRule (or None)
  * One pure extract phase — Sigma detection block → 3 artifact lists,
                              driven by an _EXTRACTORS registry instead of
                              three nearly-identical functions
  * One aggregate phase   — observe(rule) into a _TechniqueAcc, finalize once

Public API preserved:
  - build_artifact_map(sigma_dir, progress_cb) -> list[dict]
  - HAS_YAML constant

The legacy _TNAME map (built-in human-readable technique names) sits at the
bottom so the top of the file is the working code, not 250 dict entries.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# =============================================================================
# 1. Patterns & lookups — pure data, easy to tune without touching code
# =============================================================================

_TID_RE  = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_TACT_RE = re.compile(r"^attack\.([a-z\-]+)$",          re.IGNORECASE)

_KNOWN_TACTICS = {
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
    "reconnaissance", "resource-development",
}

# Sysmon / Security category → representative event ID(s).
# Used as a fallback when the rule's `detection:` block has no explicit EventID.
_CAT_EVENTS: dict[str, list[int]] = {
    "process_creation":     [1, 4688],
    "image_load":           [7],
    "create_remote_thread": [8],
    "raw_access_read":      [9],
    "process_access":       [10],
    "file_event":           [11],
    "registry_add":         [12],
    "registry_set":         [13],
    "registry_delete":      [12, 13],
    "registry_rename":      [14],
    "pipe_created":         [17, 18],
    "dns_query":            [22],
    "file_delete":          [23, 26],
    "network_connection":   [3],
    "driver_load":          [6],
    "process_tampering":    [25],
    "file_access":          [11],
    "wmi_event":            [19, 20, 21],
    "ps_script":            [4104],
    "ps_module":            [4103],
    "ps_classic_script":    [400, 800],
    "security":             [],
}


# =============================================================================
# 2. Artifact extractors — three "find values in detection blocks that look
#    like X" passes, expressed as data instead of three hand-rolled functions.
# =============================================================================

@dataclass(frozen=True)
class Extractor:
    """A pattern-driven artifact extractor over Sigma `detection:` blocks."""
    name:        str
    fields:      tuple[str, ...]                # Sigma field names to scan
    predicate:   Callable[[str], bool]          # "this looks like one of these"
    clean:       Callable[[str], str]           # canonicalise
    cap:         int                            # max items kept per rule


def _looks_like_reg_key(s: str) -> bool:
    return any(x in s for x in (
        "\\SOFTWARE\\", "\\SYSTEM\\", "\\HKEY", "\\CurrentVersion\\",
        "HKLM", "HKCU", "HKCR", "\\Run", "\\Services\\", "\\Policies\\",
    ))


def _clean_reg_key(s: str) -> str:
    return re.sub(r"\|[a-z]+$", "", s).strip()


def _looks_like_process(s: str) -> bool:
    if re.search(r"\.exe$", s, re.IGNORECASE):
        return True
    return "\\" in s and bool(re.search(r"\\\w+\.exe", s, re.IGNORECASE))


def _clean_process(s: str) -> str:
    return s.strip().replace("\\\\", "\\")


_CMDLINE_HINTS = (" -", " /", "/c ", "/k ", "cmd", "powershell",
                  "Invoke", "bypass", "-enc", "-nop", "-w ")


def _looks_like_cmdline(s: str) -> bool:
    s = s.strip()
    if not (4 <= len(s) <= 120):
        return False
    if s.startswith("\\") or s.startswith("C:\\"):
        return False
    return any(h in s for h in _CMDLINE_HINTS)


_EXTRACTORS: tuple[Extractor, ...] = (
    Extractor(
        name="reg_keys",
        # TargetObject is the Sigma field for registry path; also scan
        # everywhere as a safety net for rules that put the key in detail strings.
        fields=("TargetObject",),
        predicate=_looks_like_reg_key, clean=_clean_reg_key, cap=20,
    ),
    Extractor(
        name="processes",
        fields=("Image", "ParentImage", "SourceImage"),
        predicate=_looks_like_process, clean=_clean_process, cap=20,
    ),
    Extractor(
        name="cmdlines",
        fields=("CommandLine",),
        predicate=_looks_like_cmdline, clean=str.strip, cap=15,
    ),
)


# =============================================================================
# 3. Detection-block walkers
# =============================================================================

def _flat_strings(obj, out: list[str]) -> None:
    """Collect every string value from a nested dict/list structure."""
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, list):
        for item in obj:
            _flat_strings(item, out)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flat_strings(v, out)


def _collect_field(detection: dict, field_name: str) -> list[str]:
    """Find string values associated with a specific Sigma field name."""
    if not isinstance(detection, dict):
        return []

    out: list[str] = []
    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            for sub_key, sub_val in val.items():
                if sub_key == field_name or sub_key.startswith(field_name + "|"):
                    _flat_strings(sub_val, out)
            out.extend(_collect_field(val, field_name))
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    out.extend(_collect_field(item, field_name))
    return out


def _collect_event_ids(detection: dict) -> list[int]:
    """Numeric EventID values declared anywhere in the detection block."""
    raw: set[int] = set()
    for v in _collect_field(detection, "EventID"):
        try:
            raw.add(int(v))
        except (ValueError, TypeError):
            pass
    return sorted(raw)


def _run_extractor(detection: dict, all_strings: list[str], ex: Extractor) -> list[str]:
    """Apply one Extractor to a detection block; dedup preserving order."""
    pool: list[str] = []
    for f in ex.fields:
        pool.extend(_collect_field(detection, f))
    pool.extend(all_strings)

    seen: set[str] = set()
    out:  list[str] = []
    for raw in pool:
        if not ex.predicate(raw):
            continue
        cleaned = ex.clean(raw)
        if not cleaned or len(cleaned) < 4 or cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
        if len(out) >= ex.cap:
            break
    return out


# =============================================================================
# 4. Parsed rule — one Sigma .yml's distilled facts
# =============================================================================

@dataclass
class ParsedRule:
    tids:       list[str]
    tactics:    list[str]
    event_ids:  list[int]
    artifacts:  dict[str, list[str]]    # extractor.name → values
    meta:       dict                     # rule_meta dict embedded under each technique


def _parse_rule_file(fpath: Path, sigma_root: Path) -> Optional[ParsedRule]:
    """Parse one .yml file into a ParsedRule, or None if it isn't a Sigma rule."""
    try:
        raw = fpath.read_text(encoding="utf-8", errors="replace")
        docs = list(yaml.safe_load_all(raw))
    except Exception:
        return None

    rule = next((d for d in docs if isinstance(d, dict) and "title" in d), None)
    if rule is None:
        return None

    tags = rule.get("tags") or []
    if not tags:
        return None

    tids:    list[str] = []
    tactics: list[str] = []
    for tag in tags:
        s = str(tag)
        if (m := _TID_RE.match(s)):
            tids.append(m.group(1).upper())
        elif (m2 := _TACT_RE.match(s)):
            t = m2.group(1).lower()
            if t in _KNOWN_TACTICS:
                tactics.append(t)
    if not tids:
        return None

    logsource = rule.get("logsource") or {}
    detection = rule.get("detection") or {}
    category  = logsource.get("category", "")

    event_ids = _collect_event_ids(detection)
    if not event_ids and category in _CAT_EVENTS:
        event_ids = list(_CAT_EVENTS[category])

    all_strings: list[str] = []
    _flat_strings(detection, all_strings)

    artifacts = {ex.name: _run_extractor(detection, all_strings, ex)
                 for ex in _EXTRACTORS}

    desc = rule.get("description", "") or ""
    if isinstance(desc, str):
        desc = desc[:200]

    meta = {
        "title":    rule.get("title", ""),
        "id":       rule.get("id", ""),
        "level":    rule.get("level", ""),
        "status":   rule.get("status", ""),
        "author":   (rule.get("author", "") or "")[:80],
        "file":     str(fpath.relative_to(sigma_root)),
        "desc":     desc,
        "category": category,
        "product":  logsource.get("product", ""),
    }

    return ParsedRule(
        tids=tids, tactics=tactics, event_ids=event_ids,
        artifacts=artifacts, meta=meta,
    )


# =============================================================================
# 5. Aggregator — observe(rule) per TID, then finalize() into the API shape
# =============================================================================

@dataclass
class _TechniqueAcc:
    tid:        str
    name:       str
    tactics:    set[str]                       = field(default_factory=set)
    rule_count: int                            = 0
    event_ids:  set[int]                       = field(default_factory=set)
    categories: set[str]                       = field(default_factory=set)
    # ordered-dedup buckets keyed by extractor.name
    artifacts:  dict[str, dict[str, None]]     = field(default_factory=dict)
    rules:      list[dict]                     = field(default_factory=list)

    def observe(self, r: ParsedRule, max_rules: int = 30) -> None:
        self.rule_count += 1
        self.tactics.update(r.tactics)
        self.event_ids.update(r.event_ids)
        if r.meta.get("category"):
            self.categories.add(r.meta["category"])
        for name, vals in r.artifacts.items():
            bucket = self.artifacts.setdefault(name, {})
            for v in vals:
                bucket.setdefault(v, None)
        if len(self.rules) < max_rules:
            self.rules.append(r.meta)

    def to_dict(self) -> dict:
        # Cap each artifact list to the matching extractor's cap so the
        # technique-level view doesn't balloon past what the per-rule view shows.
        caps = {ex.name: ex.cap for ex in _EXTRACTORS}
        artifacts_out: dict[str, list[str]] = {}
        for name, bucket in self.artifacts.items():
            artifacts_out[name] = list(bucket.keys())[:caps.get(name, 20)]
        return {
            "tid":        self.tid,
            "name":       self.name,
            "tactic":     ",".join(sorted(self.tactics)),
            "rule_count": self.rule_count,
            "event_ids":  sorted(self.event_ids),
            "categories": sorted(self.categories),
            "reg_keys":   artifacts_out.get("reg_keys",  []),
            "processes":  artifacts_out.get("processes", []),
            "cmdlines":   artifacts_out.get("cmdlines",  []),
            "rules":      self.rules,
        }


def _aggregate(rules: Iterable[ParsedRule]) -> list[dict]:
    by_tid: dict[str, _TechniqueAcc] = {}
    for r in rules:
        for tid in r.tids:
            acc = by_tid.get(tid)
            if acc is None:
                acc = _TechniqueAcc(tid=tid, name=_TNAME.get(tid, ""))
                by_tid[tid] = acc
            acc.observe(r)
    out = [acc.to_dict() for acc in by_tid.values()]
    out.sort(key=lambda e: -e["rule_count"])
    return out


# =============================================================================
# 6. Public entry point — same signature as before.
# =============================================================================

def build_artifact_map(
    sigma_dir:    str | Path,
    progress_cb:  Optional[Callable[[int, int, str], None]] = None,
) -> list[dict]:
    """
    Walk `sigma_dir` recursively, parse all .yml rules, aggregate by technique.
    `progress_cb(current, total, filename)` fires every 50 files plus a final
    `progress_cb(total, total, "done")`.
    """
    if not HAS_YAML:
        raise RuntimeError("pyyaml is required: pip install pyyaml")

    sigma_root = Path(sigma_dir)
    yml_files  = sorted(sigma_root.rglob("*.yml"))
    total      = len(yml_files)

    parsed: list[ParsedRule] = []
    for idx, fpath in enumerate(yml_files):
        if progress_cb and idx % 50 == 0:
            progress_cb(idx, total, fpath.name)
        rule = _parse_rule_file(fpath, sigma_root)
        if rule is not None:
            parsed.append(rule)

    if progress_cb:
        progress_cb(total, total, "done")

    return _aggregate(parsed)


# =============================================================================
# 7. T-ID → human name lookup (pure data, intentionally at the bottom).
# =============================================================================

_TNAME: dict[str, str] = {
    "T1001": "Data Obfuscation",
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.002": "Security Account Manager",
    "T1003.003": "NTDS",
    "T1003.004": "LSA Secrets",
    "T1003.006": "DCSync",
    "T1005": "Data from Local System",
    "T1007": "System Service Discovery",
    "T1010": "Application Window Discovery",
    "T1012": "Query Registry",
    "T1014": "Rootkit",
    "T1016": "System Network Configuration Discovery",
    "T1018": "Remote System Discovery",
    "T1020": "Automated Exfiltration",
    "T1021": "Remote Services",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.006": "Windows Remote Management",
    "T1027": "Obfuscated Files or Information",
    "T1027.001": "Binary Padding",
    "T1027.002": "Software Packing",
    "T1027.004": "Compile After Delivery",
    "T1033": "System Owner/User Discovery",
    "T1036": "Masquerading",
    "T1036.003": "Rename System Utilities",
    "T1036.005": "Match Legitimate Name or Location",
    "T1037": "Boot or Logon Initialization Scripts",
    "T1039": "Data from Network Shared Drive",
    "T1040": "Network Sniffing",
    "T1041": "Exfiltration Over C2 Channel",
    "T1046": "Network Service Discovery",
    "T1047": "Windows Management Instrumentation",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1049": "System Network Connections Discovery",
    "T1053": "Scheduled Task/Job",
    "T1053.002": "At",
    "T1053.005": "Scheduled Task",
    "T1055": "Process Injection",
    "T1055.001": "Dynamic-link Library Injection",
    "T1055.003": "Thread Execution Hijacking",
    "T1055.004": "Asynchronous Procedure Call",
    "T1055.011": "Extra Window Memory Injection",
    "T1055.012": "Process Hollowing",
    "T1056": "Input Capture",
    "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.005": "Visual Basic",
    "T1059.006": "Python",
    "T1059.007": "JavaScript",
    "T1068": "Exploitation for Privilege Escalation",
    "T1069": "Permission Groups Discovery",
    "T1070": "Indicator Removal",
    "T1070.001": "Clear Windows Event Logs",
    "T1070.004": "File Deletion",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1072": "Software Deployment Tools",
    "T1074": "Data Staged",
    "T1078": "Valid Accounts",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery",
    "T1087.001": "Local Account",
    "T1087.002": "Domain Account",
    "T1090": "Proxy",
    "T1091": "Replication Through Removable Media",
    "T1095": "Non-Application Layer Protocol",
    "T1098": "Account Manipulation",
    "T1102": "Web Service",
    "T1102.001": "Dead Drop Resolver",
    "T1105": "Ingress Tool Transfer",
    "T1106": "Native API",
    "T1110": "Brute Force",
    "T1112": "Modify Registry",
    "T1113": "Screen Capture",
    "T1114": "Email Collection",
    "T1115": "Clipboard Data",
    "T1119": "Automated Collection",
    "T1120": "Peripheral Device Discovery",
    "T1123": "Audio Capture",
    "T1124": "System Time Discovery",
    "T1125": "Video Capture",
    "T1127": "Trusted Developer Utilities Proxy Execution",
    "T1127.001": "MSBuild",
    "T1129": "Shared Modules",
    "T1132": "Data Encoding",
    "T1133": "External Remote Services",
    "T1134": "Access Token Manipulation",
    "T1134.001": "Token Impersonation/Theft",
    "T1134.002": "Create Process with Token",
    "T1135": "Network Share Discovery",
    "T1136": "Create Account",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1176": "Browser Extensions",
    "T1185": "Browser Session Hijacking",
    "T1189": "Drive-by Compromise",
    "T1190": "Exploit Public-Facing Application",
    "T1195": "Supply Chain Compromise",
    "T1197": "BITS Jobs",
    "T1199": "Trusted Relationship",
    "T1200": "Hardware Additions",
    "T1201": "Password Policy Discovery",
    "T1202": "Indirect Command Execution",
    "T1203": "Exploitation for Client Execution",
    "T1204": "User Execution",
    "T1204.001": "Malicious Link",
    "T1204.002": "Malicious File",
    "T1210": "Exploitation of Remote Services",
    "T1211": "Exploitation for Defense Evasion",
    "T1216": "System Script Proxy Execution",
    "T1218": "System Binary Proxy Execution",
    "T1218.001": "Compiled HTML File",
    "T1218.003": "CMSTP",
    "T1218.005": "Mshta",
    "T1218.007": "Msiexec",
    "T1218.010": "Regsvr32",
    "T1218.011": "Rundll32",
    "T1220": "XSL Script Processing",
    "T1222": "File and Directory Permissions Modification",
    "T1480": "Execution Guardrails",
    "T1482": "Domain Trust Discovery",
    "T1484": "Domain Policy Modification",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery",
    "T1491": "Defacement",
    "T1496": "Resource Hijacking",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1499": "Endpoint Denial of Service",
    "T1505": "Server Software Component",
    "T1505.003": "Web Shell",
    "T1518": "Software Discovery",
    "T1518.001": "Security Software Discovery",
    "T1528": "Steal Application Access Token",
    "T1529": "System Shutdown/Reboot",
    "T1530": "Data from Cloud Storage",
    "T1531": "Account Access Removal",
    "T1539": "Steal Web Session Cookie",
    "T1543": "Create or Modify System Process",
    "T1543.003": "Windows Service",
    "T1546": "Event Triggered Execution",
    "T1546.001": "Change Default File Association",
    "T1546.003": "Windows Management Instrumentation Event Subscription",
    "T1546.008": "Accessibility Features",
    "T1546.010": "AppInit DLLs",
    "T1546.011": "Application Shimming",
    "T1546.012": "Image File Execution Options Injection",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1547.004": "Winlogon Helper DLL",
    "T1547.005": "Security Support Provider",
    "T1547.008": "LSASS Driver",
    "T1547.009": "Shortcut Modification",
    "T1547.012": "Print Processors",
    "T1547.014": "Active Setup",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.002": "Bypass User Account Control",
    "T1550": "Use Alternate Authentication Material",
    "T1550.002": "Pass the Hash",
    "T1550.003": "Pass the Ticket",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Credentials In Files",
    "T1552.002": "Credentials in Registry",
    "T1552.004": "Private Keys",
    "T1553": "Subvert Trust Controls",
    "T1553.004": "Install Root Certificate",
    "T1555": "Credentials from Password Stores",
    "T1555.003": "Credentials from Web Browsers",
    "T1556": "Modify Authentication Process",
    "T1557": "Adversary-in-the-Middle",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.003": "Kerberoasting",
    "T1560": "Archive Collected Data",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1562.002": "Disable Windows Event Logging",
    "T1562.004": "Disable or Modify System Firewall",
    "T1562.010": "Downgrade Attack",
    "T1563": "Remote Service Session Hijacking",
    "T1564": "Hide Artifacts",
    "T1564.001": "Hidden Files and Directories",
    "T1564.003": "Hidden Window",
    "T1564.004": "NTFS File Attributes",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1569": "System Services",
    "T1569.002": "Service Execution",
    "T1570": "Lateral Tool Transfer",
    "T1571": "Non-Standard Port",
    "T1572": "Protocol Tunneling",
    "T1573": "Encrypted Channel",
    "T1574": "Hijack Execution Flow",
    "T1574.001": "DLL Search Order Hijacking",
    "T1574.002": "DLL Side-Loading",
    "T1574.007": "Path Interception by PATH Environment Variable",
    "T1574.011": "Services Registry Permissions Weakness",
    "T1578": "Modify Cloud Compute Infrastructure",
    "T1583": "Acquire Infrastructure",
    "T1588": "Obtain Capabilities",
    "T1590": "Gather Victim Network Information",
    "T1595": "Active Scanning",
    "T1596": "Search Open Technical Databases",
    "T1597": "Search Closed Sources",
    "T1600": "Weaken Encryption",
    "T1601": "Modify System Image",
    "T1606": "Forge Web Credentials",
    "T1608": "Stage Capabilities",
    "T1611": "Escape to Host",
    "T1614": "System Location Discovery",
    "T1615": "Group Policy Discovery",
    "T1620": "Reflective Code Loading",
    "T1622": "Debugger Evasion",
    "T1647": "Plist File Modification",
    "T1649": "Steal or Forge Authentication Certificates",
    "T1651": "Cloud Administration Command",
    "T1653": "Power Settings",
    "T1656": "Impersonation",
    "T1659": "Content Injection",
    "T1664": "Exploitation for Initial Access",
    "T1674": "Input Injection",
    "T1685": "Unknown",
}
