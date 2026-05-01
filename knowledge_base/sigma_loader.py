"""Sigma rule corpus. 20 hardcoded realistic rules covering the 5 demo techniques."""
from __future__ import annotations
from typing import Any, Dict, List


SIGMA_RULES: List[Dict[str, Any]] = [
    {
        "title": "Suspicious PowerShell Encoded Command",
        "id": "sigma_powershell_encoded",
        "attack_tags": ["T1059.001"],
        "description": "Detects PowerShell with -EncodedCommand or -enc which often indicates obfuscated execution.",
        "detection": "process.name: powershell.exe AND (process.command_line: '*-EncodedCommand*' OR process.command_line: '*-enc *')",
    },
    {
        "title": "PowerShell Execution Bypass and IEX Download Cradle",
        "id": "sigma_powershell_iex_cradle",
        "attack_tags": ["T1059.001"],
        "description": "Detects PowerShell using ExecutionPolicy Bypass alongside Invoke-Expression on a downloaded string.",
        "detection": "process.command_line contains '-exec bypass' AND process.command_line contains 'IEX(New-Object Net.WebClient).DownloadString'",
    },
    {
        "title": "PowerShell Suspicious Parent Process",
        "id": "sigma_powershell_office_parent",
        "attack_tags": ["T1059.001", "T1566.001"],
        "description": "Office application (winword/excel/outlook) spawning PowerShell.",
        "detection": "parent_process.name in ('winword.exe','excel.exe','outlook.exe') AND process.name: 'powershell.exe'",
    },
    {
        "title": "Mimikatz Process Creation",
        "id": "sigma_mimikatz_proc",
        "attack_tags": ["T1003.001"],
        "description": "Detects mimikatz binary execution via image name or known command line.",
        "detection": "process.name: 'mimikatz.exe' OR process.command_line contains 'sekurlsa::logonpasswords'",
    },
    {
        "title": "ProcDump LSASS Memory Dump",
        "id": "sigma_procdump_lsass",
        "attack_tags": ["T1003.001"],
        "description": "ProcDump used to dump lsass memory: classic credential extraction step.",
        "detection": "process.name: 'procdump.exe' AND process.command_line contains '-ma lsass'",
    },
    {
        "title": "LSASS Process Access by Untrusted Caller",
        "id": "sigma_lsass_handle",
        "attack_tags": ["T1003.001"],
        "description": "Process opened a handle to lsass.exe with PROCESS_VM_READ from an unsigned binary.",
        "detection": "target.process.name: 'lsass.exe' AND access_mask: '0x1010' AND signed: false",
    },
    {
        "title": "Reg Save of SAM/SYSTEM Hives",
        "id": "sigma_reg_save_sam",
        "attack_tags": ["T1003.002"],
        "description": "reg.exe save HKLM\\SAM or HKLM\\SYSTEM is a common credential extraction step.",
        "detection": "process.name: 'reg.exe' AND process.command_line contains 'save HKLM\\SAM'",
    },
    {
        "title": "Office Macro Spawns Command Shell",
        "id": "sigma_office_macro_cmd",
        "attack_tags": ["T1566.001", "T1059.001"],
        "description": "Office app spawns cmd.exe — strong macro-based execution indicator.",
        "detection": "parent_process.name in ('winword.exe','excel.exe','outlook.exe') AND process.name: 'cmd.exe'",
    },
    {
        "title": "External Email Link to Office Document Download",
        "id": "sigma_email_link_doc",
        "attack_tags": ["T1566.002"],
        "description": "Mail gateway logs a link click leading to an Office document download from external domain.",
        "detection": "event.category: 'email' AND url.path matches '\\.(doc|docm|xls|xlsm|ppt)$' AND email.from_external: true",
    },
    {
        "title": "Suspicious LNK Attachment Detected",
        "id": "sigma_lnk_attachment",
        "attack_tags": ["T1566.001"],
        "description": "Email arrived with .lnk attachment, increasingly used for malware delivery.",
        "detection": "event.category: 'email' AND attachment.extension: 'lnk'",
    },
    {
        "title": "Beacon-like Periodic HTTP GET Pattern",
        "id": "sigma_c2_beacon_http",
        "attack_tags": ["T1071.001"],
        "description": "HTTP GETs to the same destination at near-constant intervals (jitter <10%).",
        "detection": "network.protocol: 'http' AND interval_jitter < 0.10 AND destination.port in (80,443)",
    },
    {
        "title": "Cobalt Strike Default Profile URI",
        "id": "sigma_cobaltstrike_uri",
        "attack_tags": ["T1071.001"],
        "description": "Outbound HTTP GET to known default Cobalt Strike Malleable C2 URIs.",
        "detection": "url.path matches '/(ca|en_US/all|fwlink/p/?LinkID=).*'",
    },
    {
        "title": "DNS Query to High-Entropy DGA Domain",
        "id": "sigma_dga_dns",
        "attack_tags": ["T1071.001"],
        "description": "DNS query to a domain whose label has Shannon entropy > 4.0 — DGA-like.",
        "detection": "event.category: 'dns' AND label_entropy > 4.0",
    },
    {
        "title": "DNS TXT Record Exfiltration Pattern",
        "id": "sigma_dns_txt_exfil",
        "attack_tags": ["T1071.001"],
        "description": "Large volume of DNS TXT queries with base64-like payload labels.",
        "detection": "event.category: 'dns' AND query_type: 'TXT' AND payload_base64_chars > 80",
    },
    {
        "title": "Impossible Travel: Account Login from Two Geos in Short Window",
        "id": "sigma_impossible_travel",
        "attack_tags": ["T1078"],
        "description": "Account logged in from two different countries within < 1 hour.",
        "detection": "user.account: same AND location.country: differs AND interval_minutes < 60",
    },
    {
        "title": "After-Hours Admin Logon to Critical Server",
        "id": "sigma_afterhours_admin",
        "attack_tags": ["T1078"],
        "description": "Logon to a server tagged critical outside 06:00-22:00 local with admin role.",
        "detection": "user.role: 'admin' AND host.criticality: 'high' AND hour_of_day not in 6..22",
    },
    {
        "title": "Multiple Failed Logons Followed by Success From Same Source",
        "id": "sigma_brute_then_success",
        "attack_tags": ["T1078"],
        "description": "Brute-force success pattern: 5+ failed then one success from same IP within 5 min.",
        "detection": "event.outcome: 'failure' count >= 5 followed_by event.outcome: 'success' from same source.ip within 5m",
    },
    {
        "title": "VPN Login From Recently-Reported Abusive IP",
        "id": "sigma_vpn_abuseip",
        "attack_tags": ["T1078"],
        "description": "Successful VPN auth from an IP whose AbuseIPDB confidence > 75 in last 90d.",
        "detection": "event.action: 'vpn_login_success' AND threat.abuse_score > 75",
    },
    {
        "title": "Persistence via Run Key Modified by Suspicious Process",
        "id": "sigma_runkey_persist",
        "attack_tags": ["T1059.001", "T1566.001"],
        "description": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run modified by powershell or office child.",
        "detection": "registry.path contains '\\Run' AND process.name in ('powershell.exe','wscript.exe','cmd.exe')",
    },
    {
        "title": "Wmiexec Lateral Movement Pattern",
        "id": "sigma_wmiexec_lateral",
        "attack_tags": ["T1078"],
        "description": "WMI process call create on remote host using non-default credentials.",
        "detection": "wmi.method: 'Create' AND wmi.target_host != source.host",
    },
]


def load_rules() -> List[Dict[str, Any]]:
    return SIGMA_RULES


def rule_to_chunk(rule: Dict[str, Any]) -> str:
    return (
        f"{rule['title']}\n"
        f"ATT&CK: {', '.join(rule['attack_tags'])}\n"
        f"Description: {rule['description']}\n"
        f"Detection: {rule['detection']}"
    )
