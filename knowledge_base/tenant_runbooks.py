"""Synthetic tenant runbooks (10 per tenant) used as RAG context."""
from __future__ import annotations
from typing import Dict, List


_BASE_RUNBOOKS: List[Dict[str, str]] = [
    {
        "title": "Ransomware Response SOP",
        "body": (
            "On ransomware detection, the analyst on call isolates affected hosts at the network layer "
            "via the EDR console within 5 minutes. Snapshot volumes on the storage tier are created "
            "immediately to preserve forensic state. The IR lead pages the CISO and legal counsel. "
            "Identify scope by querying SIEM for hosts that contacted the same C2 domain or shared the "
            "encrypted file extension. Restore from offline backups only after a confirmed-clean rebuild "
            "of the host. File a regulator notification per playbook within 72 hours."
        ),
    },
    {
        "title": "Credential Dumping Response SOP",
        "body": (
            "On detection of LSASS access, mimikatz, or procdump activity, immediately isolate the host "
            "and force a password reset for every account that interactively logged into that host in "
            "the last 30 days. Rotate Kerberos krbtgt twice if a domain controller is implicated. "
            "Hunt for golden-ticket activity (TGTs with anomalous lifetime). Pull a memory image for "
            "forensic analysis before reboot. Notify identity team to review all SSO sessions and "
            "force re-auth for high-risk users."
        ),
    },
    {
        "title": "Phishing Investigation SOP",
        "body": (
            "On user-reported phishing, the SOC pulls the message from quarantine and extracts attachments "
            "in a sandbox. URLs are detonated in URLhaus and an isolated browser. Identify all users who "
            "received the same message via email gateway search and proactively delete from inboxes. If a "
            "user clicked a link, check workstation telemetry for follow-on payload execution. Reset the "
            "user's credentials and any SSO tokens issued after the click time."
        ),
    },
    {
        "title": "C2 Communication Response SOP",
        "body": (
            "When egress traffic to a known-malicious domain is detected, sinkhole the destination at the "
            "perimeter immediately. Pivot from the source host to identify all processes that resolved or "
            "connected to that domain. Capture full PCAP for the host for the last 24 hours if available. "
            "Block the IOC across firewall, proxy, and DNS layers. Open a forensic case in DFIR-IRIS and "
            "begin host imaging for Tier-2 analysis."
        ),
    },
    {
        "title": "After-Hours Login Anomaly SOP",
        "body": (
            "When a privileged account logs in outside business hours, validate against approved change "
            "windows and on-call schedules. Contact the user via a known-good channel — never via the "
            "endpoint that logged in. If the user denies the activity, treat as compromised: revoke all "
            "sessions, rotate credentials, audit recent privileged actions. Pull authentication logs for "
            "the source IP across the last 30 days to identify lateral activity."
        ),
    },
    {
        "title": "Suspicious PowerShell Execution SOP",
        "body": (
            "For PowerShell with -EncodedCommand or download cradles, capture and decode the command line "
            "in the SIEM. Search for the parent process — if Office, treat as macro-driven malware. Block "
            "the host from outbound internet and pull EDR telemetry for the last 4 hours. Submit any "
            "dropped files to VirusTotal and the malware sandbox. Disable PowerShell v2 if still allowed "
            "in policy."
        ),
    },
    {
        "title": "Unauthorized Privilege Escalation SOP",
        "body": (
            "If an account suddenly receives a new high-privilege role, validate the change against "
            "ticketed approvals. Revert unapproved role assignments immediately and rotate any service "
            "account credentials granted in the same window. Investigate the assigning admin's session "
            "for compromise. Notify identity governance and audit."
        ),
    },
    {
        "title": "Data Exfiltration Indicator SOP",
        "body": (
            "On large outbound transfer to an uncategorized domain, throttle the source host's egress and "
            "pull DLP logs to inventory transferred file types. If sensitive data classifications are "
            "detected, trigger the regulatory notification workflow. Pull the user's mailbox and chat "
            "history for evidence of insider coordination. Engage legal."
        ),
    },
    {
        "title": "Generic Malware Containment SOP",
        "body": (
            "On EDR malware verdict, isolate host and gather: process tree, autoruns snapshot, recent "
            "scheduled tasks, network connections, browser history. Clean reimage is preferred over "
            "in-place removal for any verdict above 'medium' confidence. Maintain a 30-day quarantine "
            "of the original disk image."
        ),
    },
    {
        "title": "Insider Threat Investigation SOP",
        "body": (
            "When user behavior analytics flags a privileged employee (mass downloads, after-hours data "
            "movement, USB usage), engage HR and legal before acting. Preserve evidence quietly — do not "
            "tip off the subject. Capture endpoint state via covert imaging. Coordinate any access "
            "revocations with HR's offboarding workflow."
        ),
    },
]


def load_runbooks_for_tenant(tenant_id: str, tenant_name: str) -> List[Dict[str, str]]:
    """Return runbooks tagged with a tenant's name in the body for tenant-specific tone."""
    return [
        {
            "title": f"[{tenant_name}] {r['title']}",
            "body": r["body"] + f"\n\nThis runbook applies to {tenant_name} infrastructure and contacts.",
            "tenant_id": tenant_id,
        }
        for r in _BASE_RUNBOOKS
    ]


def runbook_to_chunk(rb: Dict[str, str]) -> str:
    return f"{rb['title']}\n{rb['body']}"
