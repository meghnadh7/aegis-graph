"""Final verdict + summary, then files everything into DFIR-IRIS."""
from __future__ import annotations
import json
import time
from typing import Any, Dict

import structlog

from agents.config import get_llm
from agents.prompts.reporter import REPORTER_SYSTEM, REPORTER_USER
from agents.schemas import ReportOutput
from agents.state import TriageCase
from case_management import IRISClient
from knowledge_base.ingest import get_store
from knowledge_base.retriever import HyDERetriever
from tenants.config import load_tenant
from ._helpers import alert_summary

log = structlog.get_logger(__name__)


_IRIS = IRISClient()


async def reporter_node(state: TriageCase) -> Dict[str, Any]:
    t0 = time.time()
    tenant = load_tenant(state["tenant_id"])

    # Pull a runbook excerpt relevant to the alert.
    retriever = HyDERetriever(get_store(), tenant["pinecone_namespace_prefix"])
    runbooks = await retriever.retrieve_runbooks(alert_summary(state["raw_alert"]), top_k=1)
    runbook_excerpt = ""
    if runbooks:
        meta = runbooks[0].get("metadata", {})
        runbook_excerpt = (meta.get("title", "") + "\n" + meta.get("body", ""))[:1200]

    # Include the bits of the raw alert the reporter actually needs to decide
    # the verdict — the rule description and the command line. Without these
    # in the prompt the LLM is reasoning from IOCs and ATT&CK tags alone.
    raw = state.get("raw_alert") or {}
    rule = raw.get("rule") or {}
    evd = raw.get("data", {}).get("win", {}).get("eventdata", {}) if isinstance(raw.get("data"), dict) else {}
    case_summary = {
        "alert_id": state.get("alert_id"),
        "alert_description": rule.get("description"),
        "command_line": (evd.get("commandLine") or "")[:300],
        "severity": state.get("severity"),
        "extracted_iocs": state.get("extracted_iocs", [])[:10],
        "attack_techniques": state.get("attack_techniques", []),
        "investigation_timeline": state.get("investigation_timeline", [])[:6],
        "asset_criticality": state.get("asset_criticality"),
        "confidence_score": state.get("confidence_score"),
    }
    llm = get_llm().with_structured_output(ReportOutput)
    prompt = REPORTER_SYSTEM.format(tenant_name=tenant["tenant_name"]) + "\n\n" + REPORTER_USER.format(
        case_json=json.dumps(case_summary, default=str)[:5000],
        critic_feedback=state.get("critic_feedback") or "(none)",
        runbook_excerpt=runbook_excerpt or "(none)",
    )
    cost = 0.003
    verdict = "escalate"
    summary_text = "Triage complete. Review attached IOCs and timeline."
    action = "Escalate to Tier-2 for review."
    try:
        result = await llm.ainvoke(prompt)
        if hasattr(result, "verdict"):
            verdict = result.verdict
            summary_text = result.analyst_summary
            action = result.recommended_action
        elif isinstance(result, dict):
            verdict = result.get("verdict", verdict)
            summary_text = result.get("analyst_summary", summary_text)
            action = result.get("recommended_action", action)
    except Exception as exc:
        log.warning("reporter_llm_failed", error=str(exc))

    iris_case = await _IRIS.create_case(
        state["tenant_id"],
        {
            "case_id": state.get("case_id"),
            "alert_id": state.get("alert_id"),
            "alert_type": state.get("alert_type"),
            "verdict": verdict,
            "severity": state.get("severity"),
            "analyst_summary": summary_text,
        },
    )
    for ioc in state.get("extracted_iocs", [])[:10]:
        await _IRIS.add_ioc(iris_case, ioc)
    host = state["raw_alert"].get("agent", {}).get("name", "unknown-host")
    await _IRIS.add_asset(iris_case, host, state.get("asset_criticality", "low"))
    for evt in state.get("investigation_timeline", [])[:6]:
        await _IRIS.add_timeline_event(iris_case, evt)
    for tech in state.get("attack_techniques", [])[:3]:
        await _IRIS.add_attack_attribute(iris_case, tech.get("technique_id", ""), tech.get("technique_name", ""))
    await _IRIS.add_note(iris_case, summary_text + "\n\nRecommended: " + action)

    elapsed = int((time.time() - t0) * 1000)
    return {
        "verdict": verdict,
        "analyst_summary": summary_text,
        "recommended_action": action,
        "iris_case_id": iris_case,
        "processing_time_ms": state.get("processing_time_ms", 0) + elapsed,
        "total_cost_usd": state.get("total_cost_usd", 0.0) + cost,
    }
