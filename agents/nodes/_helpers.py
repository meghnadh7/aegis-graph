"""Shared helpers for agent nodes."""
from __future__ import annotations
import json
import re
from typing import Any, Dict, List

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)


def extract_iocs_from_alert(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Walk an arbitrary alert dict and pull plausible IOCs."""
    text = json.dumps(alert, default=str)
    iocs: List[Dict[str, Any]] = []
    seen = set()

    def add(t: str, v: str, src: str) -> None:
        if v in seen:
            return
        seen.add(v)
        iocs.append(
            {
                "type": t,
                "value": v,
                "source": src,
                "malicious": False,
                "confidence": 0.5,
                "details": {},
            }
        )

    for m in _URL_RE.finditer(text):
        add("url", m.group(0).rstrip(".,;)\""), "alert")
    for m in _IP_RE.finditer(text):
        ip = m.group(0)
        if ip.startswith(("0.", "127.", "255.255")):
            continue
        add("ip", ip, "alert")
    for m in _HASH_RE.finditer(text):
        v = m.group(0)
        ioc_type = "sha256" if len(v) == 64 else ("sha1" if len(v) == 40 else "md5")
        add(ioc_type, v, "alert")
    for m in _EMAIL_RE.finditer(text):
        add("email", m.group(0), "alert")
    for m in _DOMAIN_RE.finditer(text):
        v = m.group(0).lower()
        if v.endswith((".exe", ".dll", ".ps1", ".bat", ".dmp", ".log", ".com.exe")):
            continue
        if v.replace(".", "").isdigit():
            continue
        if v in {"localhost"}:
            continue
        add("domain", v, "alert")

    return iocs[:20]


def alert_summary(alert: Dict[str, Any]) -> str:
    """Compact, human-readable single-line-ish summary of the alert."""
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    agent = alert.get("agent", {})
    parts = [
        f"rule_id={rule.get('id', '?')}",
        f"desc={rule.get('description','')}",
        f"mitre={','.join(rule.get('mitre', {}).get('id', []) if isinstance(rule.get('mitre'), dict) else [])}",
        f"agent={agent.get('name','?')}/{agent.get('ip','?')}",
    ]
    win = data.get("win", {}) if isinstance(data, dict) else {}
    if win:
        evdata = win.get("eventdata", {})
        if isinstance(evdata, dict):
            cmd = evdata.get("commandLine") or evdata.get("CommandLine")
            if cmd:
                parts.append(f"cmd={cmd[:200]}")
            img = evdata.get("image") or evdata.get("Image")
            if img:
                parts.append(f"image={img}")
    return " | ".join(parts)
