"""
artifact_parser.py - parse Sigma rules into a technique -> artifact map for peekaboo
walks ~/hacking/sigma recursively, extracts ATT&CK T-IDs, event IDs, registry keys,
process names, and command-line patterns, aggregated per technique ID.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Callable, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# -- static T-ID -> name map (most common techniques) -------------------------

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

# Sysmon/Security category -> representative event ID(s)
_CAT_EVENTS: dict[str, list[int]] = {
    "process_creation":       [1, 4688],
    "image_load":             [7],
    "create_remote_thread":   [8],
    "raw_access_read":        [9],
    "process_access":         [10],
    "file_event":             [11],
    "registry_add":           [12],
    "registry_set":           [13],
    "registry_delete":        [12, 13],
    "registry_rename":        [14],
    "pipe_created":           [17, 18],
    "dns_query":              [22],
    "file_delete":            [23, 26],
    "network_connection":     [3],
    "driver_load":            [6],
    "process_tampering":      [25],
    "file_access":            [11],
    "wmi_event":              [19, 20, 21],
    "ps_script":              [4104],
    "ps_module":              [4103],
    "ps_classic_script":      [400, 800],
    "security":               [],
}

_KNOWN_TACTICS = {
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
    "reconnaissance", "resource-development",
}

_TID_RE   = re.compile(r'^attack\.(t\d{4}(?:\.\d{3})?)', re.IGNORECASE)
_TACT_RE  = re.compile(r'^attack\.([a-z\-]+)$', re.IGNORECASE)


# -- helpers -------------------------------------------------------------------

def _flat_strings(obj, out: list[str]) -> None:
    """Recursively collect all string values from a nested structure."""
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, list):
        for item in obj:
            _flat_strings(item, out)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flat_strings(v, out)


def _collect_field(detection: dict, field: str) -> list[str]:
    """Find values associated with a specific field name anywhere in detection."""
    results: list[str] = []
    if not isinstance(detection, dict):
        return results

    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            for k2, v2 in val.items():
                # match 'Field', 'Field|contains', 'Field|endswith' etc.
                if k2 == field or k2.startswith(field + "|"):
                    _flat_strings(v2, results)
            # recurse
            deeper = _collect_field(val, field)
            results.extend(deeper)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    deeper = _collect_field(item, field)
                    results.extend(deeper)
    return results


def _collect_event_ids(detection: dict) -> list[int]:
    raw = _collect_field(detection, "EventID")
    ids: set[int] = set()
    for v in raw:
        try:
            ids.add(int(v))
        except (ValueError, TypeError):
            pass
    return sorted(ids)


def _extract_reg_keys(strings: list[str]) -> list[str]:
    """Keep strings that look like registry key paths."""
    out = []
    for s in strings:
        if any(x in s for x in ["\\SOFTWARE\\", "\\SYSTEM\\", "\\HKEY", "\\CurrentVersion\\",
                                  "HKLM", "HKCU", "HKCR", "\\Run", "\\Services\\",
                                  "\\Policies\\"]):
            # strip YARA-style modifiers and normalize
            clean = re.sub(r'\|[a-z]+$', '', s).strip()
            if len(clean) > 6:
                out.append(clean)
    return list(dict.fromkeys(out))[:15]   # dedup, cap 15


def _extract_processes(strings: list[str]) -> list[str]:
    """Keep strings that look like process image paths or names."""
    out = []
    for s in strings:
        if re.search(r'\.exe$', s, re.IGNORECASE) or (
            '\\' in s and re.search(r'\\\w+\.exe', s, re.IGNORECASE)
        ):
            name = s.strip().replace('\\\\', '\\')
            if 3 < len(name) < 100:
                out.append(name)
    return list(dict.fromkeys(out))[:12]


def _extract_cmdlines(strings: list[str]) -> list[str]:
    """Keep strings that look like command-line arguments or patterns."""
    out = []
    for s in strings:
        s = s.strip()
        if len(s) < 4 or len(s) > 120:
            continue
        # skip pure paths / registry keys
        if s.startswith('\\') or s.startswith('C:\\'):
            continue
        if any(c in s for c in [' -', ' /', '/c ', '/k ', 'cmd', 'powershell',
                                  'Invoke', 'bypass', '-enc', '-nop', '-w ']):
            out.append(s)
    return list(dict.fromkeys(out))[:10]


# -- main parser ---------------------------------------------------------------

def build_artifact_map(
    sigma_dir: str | Path,
    progress_cb: Optional[Callable[[int, int, str], None]] = None,
) -> list[dict]:
    """
    Walk sigma_dir recursively, parse all .yml rules, aggregate by technique ID.
    progress_cb(current, total, filename) called every 50 files.
    Returns list of entry dicts ready for db.save_artifact_entries().
    """
    if not HAS_YAML:
        raise RuntimeError("pyyaml is required: pip install pyyaml")

    sigma_dir = Path(sigma_dir)
    yml_files = sorted(sigma_dir.rglob("*.yml"))
    total = len(yml_files)

    # tid -> aggregated entry
    by_tid: dict[str, dict] = {}

    for idx, fpath in enumerate(yml_files):
        if progress_cb and idx % 50 == 0:
            progress_cb(idx, total, fpath.name)

        try:
            raw = fpath.read_text(encoding="utf-8", errors="replace")
            # some sigma files have multiple documents; take the first real rule
            docs = list(yaml.safe_load_all(raw))
            rule = next((d for d in docs if isinstance(d, dict) and "title" in d), None)
            if rule is None:
                continue
        except Exception:
            continue

        tags = rule.get("tags") or []
        if not tags:
            continue

        # extract technique IDs and tactics
        tids: list[str] = []
        tactics: list[str] = []
        for tag in tags:
            tag_s = str(tag)
            m = _TID_RE.match(tag_s)
            if m:
                tids.append(m.group(1).upper())
                continue
            m2 = _TACT_RE.match(tag_s)
            if m2 and m2.group(1).lower() in _KNOWN_TACTICS:
                tactics.append(m2.group(1).lower())

        if not tids:
            continue

        logsource  = rule.get("logsource") or {}
        detection  = rule.get("detection")  or {}
        category   = logsource.get("category", "")
        product    = logsource.get("product", "")
        service    = logsource.get("service", "")
        level      = rule.get("level", "")
        status_    = rule.get("status", "")
        title      = rule.get("title", "")
        rule_id    = rule.get("id", "")
        author     = rule.get("author", "")
        desc       = rule.get("description", "")
        if isinstance(desc, str):
            desc = desc[:200]

        # explicit event IDs from detection
        event_ids = _collect_event_ids(detection)

        # infer event IDs from logsource category
        if not event_ids and category in _CAT_EVENTS:
            event_ids = _CAT_EVENTS[category]

        # collect raw strings from detection for artifact extraction
        all_det_strings: list[str] = []
        _flat_strings(detection, all_det_strings)

        # collect TargetObject for registry keys
        target_objs = _collect_field(detection, "TargetObject")
        reg_keys    = _extract_reg_keys(target_objs + all_det_strings)

        # collect Image for processes
        images   = _collect_field(detection, "Image")
        images  += _collect_field(detection, "ParentImage")
        images  += _collect_field(detection, "SourceImage")
        processes = _extract_processes(images + all_det_strings)

        # collect CommandLine patterns
        cmdlines_raw = _collect_field(detection, "CommandLine")
        cmdlines     = _extract_cmdlines(cmdlines_raw)

        rule_meta = {
            "title":    title,
            "id":       rule_id,
            "level":    level,
            "status":   status_,
            "author":   author[:80],
            "file":     str(fpath.relative_to(sigma_dir)),
            "desc":     desc[:200] if isinstance(desc, str) else "",
            "category": category,
            "product":  product,
        }

        for tid in tids:
            if tid not in by_tid:
                by_tid[tid] = {
                    "tid":        tid,
                    "name":       _TNAME.get(tid, ""),
                    "tactics":    set(),
                    "rule_count": 0,
                    "event_ids":  set(),
                    "categories": set(),
                    "reg_keys":   [],
                    "processes":  [],
                    "cmdlines":   [],
                    "rules":      [],
                }
            e = by_tid[tid]
            e["tactics"].update(tactics)
            e["rule_count"] += 1
            e["event_ids"].update(event_ids)
            if category:
                e["categories"].add(category)
            # accumulate unique artifacts
            for rk in reg_keys:
                if rk not in e["reg_keys"]:
                    e["reg_keys"].append(rk)
            for pr in processes:
                if pr not in e["processes"]:
                    e["processes"].append(pr)
            for cl in cmdlines:
                if cl not in e["cmdlines"]:
                    e["cmdlines"].append(cl)
            # keep up to 30 rules per technique
            if len(e["rules"]) < 30:
                e["rules"].append(rule_meta)

    if progress_cb:
        progress_cb(total, total, "done")

    # convert sets to lists, cap lengths, sort by rule_count desc
    entries = []
    for e in by_tid.values():
        entries.append({
            "tid":        e["tid"],
            "name":       e["name"],
            "tactic":     ",".join(sorted(e["tactics"])),
            "rule_count": e["rule_count"],
            "event_ids":  sorted(e["event_ids"]),
            "categories": sorted(e["categories"]),
            "reg_keys":   e["reg_keys"][:20],
            "processes":  e["processes"][:20],
            "cmdlines":   e["cmdlines"][:15],
            "rules":      e["rules"],
        })

    entries.sort(key=lambda x: -x["rule_count"])
    return entries
