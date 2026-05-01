"""Reflector / critic node — scores the case and may force a revision loop."""
from __future__ import annotations
import json
import time
from typing import Any, Dict

import structlog

from agents.config import get_llm
from agents.prompts.reflector import REFLECTOR_SYSTEM, REFLECTOR_USER
from agents.schemas import ReflectOutput
from agents.state import TriageCase

log = structlog.get_logger(__name__)


def _case_summary_for_critic(state: TriageCase) -> Dict[str, Any]:
    return {
        "alert_id": state.get("alert_id"),
        "tenant_id": state.get("tenant_id"),
        "severity": state.get("severity"),
        "extracted_iocs": state.get("extracted_iocs", []),
        "enrichment_results_summary": [
            {"tool": e.get("tool"), "success": e.get("success"), "keys": list((e.get("data") or {}).keys())}
            for e in state.get("enrichment_results", [])
        ],
        "attack_techniques": state.get("attack_techniques", []),
        "kill_chain_stage": state.get("kill_chain_stage"),
        "investigation_timeline": state.get("investigation_timeline", []),
        "asset_criticality": state.get("asset_criticality"),
        "revision_count": state.get("revision_count", 0),
    }


async def reflector_node(state: TriageCase) -> Dict[str, Any]:
    t0 = time.time()
    llm = get_llm().with_structured_output(ReflectOutput)
    prompt = REFLECTOR_SYSTEM + "\n\n" + REFLECTOR_USER.format(
        case_json=json.dumps(_case_summary_for_critic(state), default=str)[:5000],
    )
    cost = 0.001
    score = 0.6
    feedback = ""
    try:
        result = await llm.ainvoke(prompt)
        if hasattr(result, "composite"):
            score = result.composite()
            feedback = result.feedback
        elif isinstance(result, dict):
            ro = ReflectOutput(**result)
            score = ro.composite()
            feedback = ro.feedback
    except Exception as exc:
        log.warning("reflector_llm_failed", error=str(exc))
        score = 0.7

    elapsed = int((time.time() - t0) * 1000)
    return {
        "confidence_score": float(score),
        "critic_feedback": feedback or None,
        "processing_time_ms": state.get("processing_time_ms", 0) + elapsed,
        "total_cost_usd": state.get("total_cost_usd", 0.0) + cost,
    }
