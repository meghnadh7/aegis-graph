"""Load a curated subset of MITRE ATT&CK techniques.

Tries to fetch the official STIX bundle and filter to the techniques relevant
to the AegisGraph demo. If the bundle isn't on disk and network is
unavailable, falls back to a hardcoded set of complete technique entries.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

import httpx
import structlog

log = structlog.get_logger(__name__)

ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)
LOCAL_FILE = DATA_DIR / "enterprise-attack.json"

TARGET_TECHNIQUE_PREFIXES = ("T1059", "T1003", "T1566", "T1071", "T1078")


# Hardcoded fallback so the system works fully offline.
FALLBACK_TECHNIQUES: List[Dict[str, Any]] = [
    {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.",
        "platforms": ["Windows"],
        "data_sources": ["Process: Process Creation", "Command: Command Execution", "Module: Module Load"],
    },
    {
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Process: Process Access", "Process: OS API Execution", "File: File Access"],
    },
    {
        "technique_id": "T1003.001",
        "technique_name": "LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
        "platforms": ["Windows"],
        "data_sources": ["Process: Process Access", "Process: OS API Execution"],
    },
    {
        "technique_id": "T1003.002",
        "technique_name": "Security Account Manager",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry.",
        "platforms": ["Windows"],
        "data_sources": ["Command: Command Execution", "File: File Access"],
    },
    {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering.",
        "platforms": ["Linux", "macOS", "Windows", "Office 365", "SaaS"],
        "data_sources": ["Application Log: Application Log Content", "File: File Creation", "Network Traffic: Network Traffic Flow"],
    },
    {
        "technique_id": "T1566.001",
        "technique_name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.",
        "platforms": ["Linux", "macOS", "Windows"],
        "data_sources": ["File: File Creation", "Network Traffic: Network Traffic Content"],
    },
    {
        "technique_id": "T1566.002",
        "technique_name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.",
        "platforms": ["Linux", "macOS", "Windows", "Office 365"],
        "data_sources": ["Application Log: Application Log Content", "Network Traffic: Network Traffic Content"],
    },
    {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
        "platforms": ["Linux", "macOS", "Windows"],
        "data_sources": ["Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    },
    {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection by blending in with existing traffic.",
        "platforms": ["Linux", "macOS", "Windows"],
        "data_sources": ["Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "platforms": ["Windows", "Linux", "macOS", "SaaS", "Containers"],
        "data_sources": ["Logon Session: Logon Session Creation", "User Account: User Account Authentication"],
    },
]


def fetch_attack_bundle() -> Dict[str, Any]:
    """Fetch ATT&CK STIX bundle, caching to disk. Returns {} on failure."""
    if LOCAL_FILE.exists():
        try:
            with LOCAL_FILE.open() as fh:
                return json.load(fh)
        except Exception:
            pass
    try:
        log.info("fetching_attack_bundle", url=ENTERPRISE_ATTACK_URL)
        with httpx.Client(timeout=30.0) as c:
            r = c.get(ENTERPRISE_ATTACK_URL)
            r.raise_for_status()
            data = r.json()
        with LOCAL_FILE.open("w") as fh:
            json.dump(data, fh)
        return data
    except Exception as exc:
        log.warning("attack_bundle_fetch_failed", error=str(exc))
        return {}


def load_techniques() -> List[Dict[str, Any]]:
    """Return a list of technique dicts ready for embedding."""
    bundle = fetch_attack_bundle()
    if not bundle:
        log.info("using_fallback_techniques", count=len(FALLBACK_TECHNIQUES))
        return FALLBACK_TECHNIQUES

    techniques: List[Dict[str, Any]] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_refs = obj.get("external_references", [])
        ttp_id = next((r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"), None)
        if not ttp_id or not ttp_id.startswith(TARGET_TECHNIQUE_PREFIXES):
            continue
        kill_chain = obj.get("kill_chain_phases", [])
        tactic = kill_chain[0]["phase_name"].replace("-", " ").title() if kill_chain else "Unknown"
        techniques.append(
            {
                "technique_id": ttp_id,
                "technique_name": obj.get("name", ""),
                "tactic": tactic,
                "description": obj.get("description", ""),
                "platforms": obj.get("x_mitre_platforms", []),
                "data_sources": obj.get("x_mitre_data_sources", []),
            }
        )
    if not techniques:
        return FALLBACK_TECHNIQUES
    return techniques


def technique_to_chunk(t: Dict[str, Any]) -> str:
    """Format a technique dict into a single embeddable chunk."""
    return (
        f"{t['technique_id']} — {t['technique_name']}\n"
        f"Tactic: {t['tactic']}\n"
        f"Description: {t['description']}\n"
        f"Platforms: {', '.join(t.get('platforms', []))}\n"
        f"Data Sources: {', '.join(t.get('data_sources', []))}"
    )
