"""Stub LLM + embedder used when MOCK_MODE is on or no API keys are configured.

The stub is keyword-driven — it picks a technique by scanning the prompt for
words like "powershell" or "lsass" — and seeds its randomness off a hash of
the prompt so the same alert produces the same answer twice in a row. Good
enough to demo the pipeline end-to-end without spending tokens.
"""
from __future__ import annotations
import hashlib
import json
import random
import re
from typing import Any, Dict, List, Optional, Type


class _MockResponse:
    def __init__(self, content: str) -> None:
        self.content = content
        self.usage_metadata = {"input_tokens": 100, "output_tokens": 100, "total_tokens": 200}


def _stable_seed(text: str) -> int:
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)


_TECHNIQUE_TABLE = {
    "powershell": ("T1059.001", "PowerShell", "Execution"),
    "encoded": ("T1059.001", "PowerShell", "Execution"),
    "lsass": ("T1003.001", "LSASS Memory", "Credential Access"),
    "mimikatz": ("T1003.001", "LSASS Memory", "Credential Access"),
    "procdump": ("T1003.001", "LSASS Memory", "Credential Access"),
    "credential": ("T1003", "OS Credential Dumping", "Credential Access"),
    "phish": ("T1566.001", "Spearphishing Attachment", "Initial Access"),
    "macro": ("T1566.001", "Spearphishing Attachment", "Initial Access"),
    "office": ("T1566.001", "Spearphishing Attachment", "Initial Access"),
    "beacon": ("T1071.001", "Web Protocols", "Command and Control"),
    "c2": ("T1071.001", "Web Protocols", "Command and Control"),
    "dga": ("T1071.001", "Web Protocols", "Command and Control"),
    "vpn": ("T1078", "Valid Accounts", "Initial Access"),
    "login": ("T1078", "Valid Accounts", "Initial Access"),
    "account": ("T1078", "Valid Accounts", "Initial Access"),
}


def _pick_technique(text: str) -> Dict[str, Any]:
    lower = text.lower()
    for key, (tid, name, tactic) in _TECHNIQUE_TABLE.items():
        if key in lower:
            return {"technique_id": tid, "technique_name": name, "tactic": tactic, "confidence": 0.82}
    return {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution", "confidence": 0.55}


class MockLLM:
    """Tiny keyword-driven LLM stub. Recognizes prompt intent by which schema is requested."""

    def __init__(self) -> None:
        self.calls = 0
        self._schema: Optional[Type] = None

    def with_structured_output(self, schema: Type):
        clone = MockLLM()
        clone._schema = schema
        return clone

    def invoke(self, prompt: Any) -> Any:
        return self._respond(self._prompt_text(prompt))

    async def ainvoke(self, prompt: Any) -> Any:
        return self._respond(self._prompt_text(prompt))

    def _prompt_text(self, prompt: Any) -> str:
        if isinstance(prompt, str):
            return prompt
        if isinstance(prompt, list):
            parts = []
            for m in prompt:
                if isinstance(m, dict):
                    parts.append(str(m.get("content", "")))
                else:
                    parts.append(str(getattr(m, "content", m)))
            return "\n".join(parts)
        return str(prompt)

    def _respond(self, text: str) -> Any:
        self.calls += 1
        rng = random.Random(_stable_seed(text))
        lower = text.lower()

        if self._schema is not None:
            payload = self._structured_payload(text, lower, rng)
            try:
                return self._schema(**payload)
            except Exception:
                return payload

        if "hyde" in lower or "hypothetical" in lower:
            return _MockResponse(
                "An attacker is leveraging a Windows-native scripting interpreter to execute "
                "obfuscated commands, typically logged via Sysmon Event ID 1 with parent process "
                "explorer.exe or office applications. Look for encoded command lines and unusual "
                "child processes."
            )
        if "summary" in lower or "analyst" in lower:
            return _MockResponse(self._analyst_summary(text, rng))
        if "verdict" in lower:
            choice = rng.choice(["true_positive", "false_positive", "escalate"])
            return _MockResponse(json.dumps({"verdict": choice}))
        return _MockResponse("OK")

    def _structured_payload(self, text: str, lower: str, rng: random.Random) -> Dict[str, Any]:
        schema_name = getattr(self._schema, "__name__", "")

        if "IOCExtraction" in schema_name:
            # The triage prompt has the raw alert and the enrichment payload glued
            # together. We only want IOCs from the alert side — otherwise the
            # mock ends up reporting noise from the enrichment URLs (e.g. the
            # GreyNoise viz link) as if it were an alert IOC.
            alert_section = text
            if "Enrichment results" in text:
                alert_section = text.split("Enrichment results", 1)[0]
            iocs = _extract_iocs_from_text(alert_section)
            return {"iocs": iocs}
        if "ATTACK" in schema_name or "Mapping" in schema_name:
            t = _pick_technique(text)
            return {
                "techniques": [
                    {
                        "technique_id": t["technique_id"],
                        "technique_name": t["technique_name"],
                        "tactic": t["tactic"],
                        "kill_chain_phase": t["tactic"].lower().replace(" ", "-"),
                        "confidence": t["confidence"],
                        "matched_sigma_rules": ["sigma_powershell_encoded", "sigma_suspicious_parent"],
                    }
                ],
                "kill_chain_stage": t["tactic"],
            }
        if "Investigation" in schema_name or "Timeline" in schema_name:
            return {
                "events": [
                    {
                        "timestamp": "2026-04-30T10:00:00Z",
                        "event_type": "alert",
                        "description": "Initial alert observed on host.",
                        "source": "wazuh",
                    },
                    {
                        "timestamp": "2026-04-30T10:02:00Z",
                        "event_type": "enrichment",
                        "description": "IOC enrichment completed against 5 threat-intel sources.",
                        "source": "aegisgraph",
                    },
                ],
                "asset_criticality": rng.choice(["low", "medium", "high"]),
                "related_cases": [],
            }
        if "Reflect" in schema_name or "Critic" in schema_name:
            base = 0.55 + rng.random() * 0.4
            return {
                "evidence_quality": min(1.0, base + 0.05),
                "reasoning_coherence": min(1.0, base),
                "hallucination_risk": min(1.0, base + 0.1),
                "investigation_depth": min(1.0, base - 0.05),
                "feedback": "Acceptable triage. Consider deepening investigation pivot on user account.",
            }
        if "Report" in schema_name or "Verdict" in schema_name:
            verdict = rng.choice(["true_positive", "false_positive", "escalate"])
            if "powershell" in lower and "encoded" in lower:
                verdict = "true_positive"
            return {
                "verdict": verdict,
                "analyst_summary": self._analyst_summary(text, rng),
                "recommended_action": _action_for(verdict),
            }
        return {}

    def _analyst_summary(self, text: str, rng: random.Random) -> str:
        return (
            "Alert reviewed and correlated against threat-intel sources. Multiple indicators were "
            "observed including the source host and observed command line. Enrichment data supports "
            "the assessment. Recommend the action below pending analyst confirmation."
        )


def _action_for(verdict: str) -> str:
    return {
        "true_positive": "Isolate affected host and rotate associated credentials.",
        "false_positive": "No action required — close case as benign.",
        "escalate": "Escalate to Tier-2 for forensic investigation.",
    }.get(verdict, "Review with Tier-2.")


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)


_IP_BAD = {"0.0.0.0", "255.255.255.255", "10.0.0.0", "192.168.0.0", "172.16.0.0"}


def _extract_iocs_from_text(text: str) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    seen = set()
    for m in _IP_RE.finditer(text):
        v = m.group(0)
        if v in seen or v.startswith(("0.", "127.")) or v in _IP_BAD:
            continue
        if v.endswith(".0.0") or v.endswith(".255"):
            continue
        seen.add(v)
        found.append({"type": "ip", "value": v, "source": "extractor", "malicious": False, "confidence": 0.5, "details": {}})
    for m in _URL_RE.finditer(text):
        v = m.group(0).rstrip(".,;)")
        if v in seen:
            continue
        seen.add(v)
        found.append({"type": "url", "value": v, "source": "extractor", "malicious": False, "confidence": 0.5, "details": {}})
    for m in _HASH_RE.finditer(text):
        v = m.group(0)
        if v in seen:
            continue
        seen.add(v)
        ioc_type = "sha256" if len(v) == 64 else ("sha1" if len(v) == 40 else "md5")
        found.append({"type": ioc_type, "value": v, "source": "extractor", "malicious": False, "confidence": 0.5, "details": {}})
    for m in _DOMAIN_RE.finditer(text):
        v = m.group(0)
        if v in seen or v.endswith((".exe", ".dll", ".ps1", ".bat")):
            continue
        if "." not in v or v.replace(".", "").isdigit():
            continue
        seen.add(v)
        found.append({"type": "domain", "value": v, "source": "extractor", "malicious": False, "confidence": 0.5, "details": {}})
    return found[:20]


class MockEmbedder:
    """Deterministic 384-dim embedding stub keyed on input text hash."""

    def embed_query(self, text: str) -> List[float]:
        rng = random.Random(_stable_seed(text))
        return [rng.uniform(-1, 1) for _ in range(384)]

    async def aembed_query(self, text: str) -> List[float]:
        return self.embed_query(text)

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return [self.embed_query(t) for t in texts]

    async def aembed_documents(self, texts: List[str]) -> List[List[float]]:
        return self.embed_documents(texts)
