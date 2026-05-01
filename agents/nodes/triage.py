"""Triage node — pulls IOCs out of the alert and fans them out to all 5 TI sources at once."""
from __future__ import annotations
import asyncio
import json
import time
from typing import Any, Dict, List

import structlog

from agents.config import get_llm
from agents.prompts.triage import TRIAGE_SYSTEM, TRIAGE_USER
from agents.schemas import IOCExtraction
from agents.state import TriageCase
from guardrails import PromptInjectionGuard
from mcp_servers import VirusTotalMCP, ShodanMCP, AbuseIPDBMCP, URLhausMCP, GreyNoiseMCP
from tenants.config import load_tenant
from ._helpers import extract_iocs_from_alert

log = structlog.get_logger(__name__)


_VT = VirusTotalMCP()
_SHODAN = ShodanMCP()
_ABUSE = AbuseIPDBMCP()
_URLHAUS = URLhausMCP()
_GREYNOISE = GreyNoiseMCP()


async def triage_node(state: TriageCase) -> Dict[str, Any]:
    t0 = time.time()
    log.info("triage_node_start", tenant=state["tenant_id"], alert=state["alert_id"])
    guard = PromptInjectionGuard()
    sanitized_alert = guard.sanitize_dict(state["raw_alert"])

    extracted = extract_iocs_from_alert(sanitized_alert)

    enrichments: List[Dict[str, Any]] = []
    enrichment_tasks = []
    for ioc in extracted:
        t, v = ioc["type"], ioc["value"]
        enrichment_tasks.append(_VT.lookup(v, t))
        if t == "ip":
            enrichment_tasks.append(_SHODAN.lookup_ip(v))
            enrichment_tasks.append(_ABUSE.check_ip(v))
            enrichment_tasks.append(_GREYNOISE.lookup_ip(v))
            enrichment_tasks.append(_URLHAUS.lookup_host(v))
        elif t in {"url"}:
            enrichment_tasks.append(_URLHAUS.lookup_url(v))
        elif t in {"domain"}:
            enrichment_tasks.append(_URLHAUS.lookup_host(v))

    if enrichment_tasks:
        results = await asyncio.gather(*enrichment_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                enrichments.append({"tool": "unknown", "success": False, "data": {}, "error": str(r), "cached": False})
            else:
                enrichments.append(r)

    _flag_iocs_from_enrichment(extracted, enrichments)

    tenant = load_tenant(state["tenant_id"])
    sanitized_enrichments = guard.sanitize_dict(enrichments, max_depth=4)

    llm = get_llm().with_structured_output(IOCExtraction)
    prompt = TRIAGE_SYSTEM.format(
        tenant_name=tenant["tenant_name"],
        tenant_description=tenant["description"],
        tenant_environment=tenant["environment"],
        tenant_critical_assets=", ".join(tenant["critical_assets"]),
        tenant_suppression_rules="; ".join(tenant.get("suppression_rules", [])),
    ) + "\n\n" + TRIAGE_USER.format(
        alert_json=json.dumps(sanitized_alert, default=str)[:4000],
        enrichment_json=json.dumps(sanitized_enrichments, default=str)[:4000],
    )
    cost = 0.0
    try:
        result = await llm.ainvoke(prompt)
        if hasattr(result, "iocs"):
            llm_iocs = [i.model_dump() if hasattr(i, "model_dump") else dict(i) for i in result.iocs]
        else:
            llm_iocs = result.get("iocs", []) if isinstance(result, dict) else []
        if llm_iocs:
            extracted = _merge_iocs(extracted, llm_iocs)
        cost = 0.002
    except Exception as exc:
        log.warning("triage_llm_failed", error=str(exc))

    dedup = "duplicate" if (state.get("revision_count", 0) > 0) else "new"
    elapsed_ms = int((time.time() - t0) * 1000)
    return {
        "extracted_iocs": extracted,
        "enrichment_results": enrichments,
        "dedup_status": dedup,
        "processing_time_ms": state.get("processing_time_ms", 0) + elapsed_ms,
        "total_cost_usd": state.get("total_cost_usd", 0.0) + cost,
    }


def _flag_iocs_from_enrichment(iocs: List[Dict[str, Any]], enrichments: List[Dict[str, Any]]) -> None:
    """Walk the enrichment results and mark IOCs malicious when any TI source flags them."""
    by_value = {i["value"]: i for i in iocs}
    for e in enrichments:
        if not e.get("success"):
            continue
        d = e.get("data", {})
        tool = e.get("tool")
        for ioc_value, ioc in by_value.items():
            if not _enrichment_relates(d, ioc_value):
                continue
            mal = False
            conf = ioc["confidence"]
            if tool == "virustotal" and d.get("malicious_count", 0) >= 3:
                mal = True
                conf = max(conf, 0.85)
            if tool == "abuseipdb" and d.get("abuseConfidenceScore", 0) >= 50:
                mal = True
                conf = max(conf, 0.8)
            if tool == "urlhaus" and d.get("query_status") == "ok":
                mal = True
                conf = max(conf, 0.9)
            if tool == "greynoise" and d.get("classification") == "malicious":
                mal = True
                conf = max(conf, 0.75)
            if tool == "shodan" and d.get("vulns"):
                conf = max(conf, 0.65)
            if mal:
                ioc["malicious"] = True
            ioc["confidence"] = conf
            ioc.setdefault("details", {}).setdefault(tool, d)


def _enrichment_relates(data: Dict[str, Any], ioc_value: str) -> bool:
    """Rough match: did this enrichment record actually mention this IOC?

    Not perfect — we don't track which task ran for which IOC at the call site
    yet, so we fall back to a substring check on the JSON dump. Small payloads
    are treated as "probably related" since most TI responses are short.
    """
    if not data:
        return True
    blob = json.dumps(data, default=str)
    return ioc_value in blob or len(blob) < 200


def _merge_iocs(base: List[Dict[str, Any]], llm_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_value = {i["value"]: i for i in base}
    for li in llm_iocs:
        v = li.get("value")
        if not v:
            continue
        if v in by_value:
            existing = by_value[v]
            existing["malicious"] = existing.get("malicious") or bool(li.get("malicious"))
            existing["confidence"] = max(existing.get("confidence", 0.5), float(li.get("confidence", 0.5)))
        else:
            by_value[v] = li
    return list(by_value.values())[:20]
