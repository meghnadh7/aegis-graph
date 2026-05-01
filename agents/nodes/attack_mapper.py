"""ATT&CK mapper node: HyDE retrieval + LLM ranking."""
from __future__ import annotations
import json
import time
from typing import Any, Dict

import structlog

from agents.config import get_llm
from agents.prompts.attack_mapper import ATTACK_SYSTEM, ATTACK_USER
from agents.schemas import ATTACKMapping
from agents.state import TriageCase
from knowledge_base.ingest import get_store
from knowledge_base.retriever import HyDERetriever
from tenants.config import load_tenant
from ._helpers import alert_summary

log = structlog.get_logger(__name__)


async def attack_mapper_node(state: TriageCase) -> Dict[str, Any]:
    t0 = time.time()
    tenant = load_tenant(state["tenant_id"])
    summary = alert_summary(state["raw_alert"])
    retriever = HyDERetriever(get_store(), tenant["pinecone_namespace_prefix"])

    attack_hits = await retriever.retrieve_attack_techniques(summary, top_k=5)
    sigma_hits = await retriever.retrieve_sigma_rules(summary, top_k=3)

    llm = get_llm().with_structured_output(ATTACKMapping)
    prompt = ATTACK_SYSTEM.format(tenant_name=tenant["tenant_name"]) + "\n\n" + ATTACK_USER.format(
        alert_summary=summary,
        attack_candidates=json.dumps([h.get("metadata", {}) for h in attack_hits], default=str)[:3000],
        sigma_candidates=json.dumps([h.get("metadata", {}) for h in sigma_hits], default=str)[:2000],
    )
    cost = 0.002
    techniques = []
    kill_chain = "unknown"
    try:
        result = await llm.ainvoke(prompt)
        if hasattr(result, "techniques"):
            techniques = [t.model_dump() if hasattr(t, "model_dump") else dict(t) for t in result.techniques]
            kill_chain = result.kill_chain_stage or kill_chain
        elif isinstance(result, dict):
            techniques = result.get("techniques", [])
            kill_chain = result.get("kill_chain_stage", kill_chain)
    except Exception as exc:
        log.warning("attack_llm_failed", error=str(exc))

    if not techniques and attack_hits:
        meta = attack_hits[0].get("metadata", {})
        techniques = [
            {
                "technique_id": meta.get("technique_id", "T1059.001"),
                "technique_name": meta.get("technique_name", "PowerShell"),
                "tactic": meta.get("tactic", "Execution"),
                "kill_chain_phase": meta.get("tactic", "Execution").lower().replace(" ", "-"),
                "confidence": float(attack_hits[0].get("score", 0.5)),
                "matched_sigma_rules": [h.get("metadata", {}).get("id", "") for h in sigma_hits],
            }
        ]
        kill_chain = meta.get("tactic", "unknown")

    sigma_matches = [h.get("metadata", {}).get("id") for h in sigma_hits if h.get("metadata", {}).get("id")]
    elapsed = int((time.time() - t0) * 1000)
    return {
        "attack_techniques": techniques,
        "kill_chain_stage": kill_chain,
        "sigma_matches": sigma_matches,
        "processing_time_ms": state.get("processing_time_ms", 0) + elapsed,
        "total_cost_usd": state.get("total_cost_usd", 0.0) + cost,
    }
