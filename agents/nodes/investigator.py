"""Investigator — pivots on host/user/IP against recent history and tags asset criticality."""
from __future__ import annotations
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import structlog

from agents.config import get_llm
from agents.prompts.investigator import INVESTIGATOR_SYSTEM, INVESTIGATOR_USER
from agents.schemas import InvestigationOutput
from agents.state import TriageCase
from tenants.config import load_tenant
from ._helpers import alert_summary

log = structlog.get_logger(__name__)


# In a real deployment this would be Redis or a SIEM query; for the demo
# we just keep the last few hundred events per tenant in memory so the
# investigator has *something* to pivot on across alerts.
_EVENT_HISTORY: Dict[str, List[Dict[str, Any]]] = {}


def record_event(tenant_id: str, evt: Dict[str, Any]) -> None:
    _EVENT_HISTORY.setdefault(tenant_id, []).append(evt)
    if len(_EVENT_HISTORY[tenant_id]) > 1000:
        _EVENT_HISTORY[tenant_id] = _EVENT_HISTORY[tenant_id][-500:]


def _related(tenant_id: str, host: str, ip: str, user: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for evt in _EVENT_HISTORY.get(tenant_id, [])[-200:]:
        if evt.get("host") == host or evt.get("ip") == ip or evt.get("user") == user:
            out.append(evt)
    return out[-20:]


async def investigator_node(state: TriageCase) -> Dict[str, Any]:
    t0 = time.time()
    tenant = load_tenant(state["tenant_id"])
    raw = state["raw_alert"]
    agent = raw.get("agent", {})
    host = agent.get("name", "")
    ip = agent.get("ip", "")
    win = raw.get("data", {}).get("win", {}) if isinstance(raw.get("data"), dict) else {}
    user = ""
    if isinstance(win, dict):
        evd = win.get("eventdata", {})
        if isinstance(evd, dict):
            user = evd.get("user") or evd.get("targetUserName") or ""

    related = _related(state["tenant_id"], host, ip, user)
    record_event(state["tenant_id"], {"host": host, "ip": ip, "user": user, "alert_id": state["alert_id"], "ts": datetime.now(timezone.utc).isoformat()})

    criticality = "low"
    for asset in tenant.get("critical_assets", []):
        if asset and (asset == host or asset in str(raw)):
            criticality = "high"
            break

    summary = alert_summary(raw)
    llm = get_llm().with_structured_output(InvestigationOutput)
    prompt = INVESTIGATOR_SYSTEM.format(tenant_name=tenant["tenant_name"]) + "\n\n" + INVESTIGATOR_USER.format(
        alert_summary=summary,
        host_activity=json.dumps([e for e in related if e.get("host") == host], default=str)[:1500],
        user_activity=json.dumps([e for e in related if e.get("user") == user], default=str)[:1500],
        critical_assets=", ".join(tenant.get("critical_assets", [])),
        related_cases=json.dumps([e.get("alert_id") for e in related], default=str)[:1000],
    )
    cost = 0.002
    events: List[Dict[str, Any]] = []
    related_cases: List[str] = []
    try:
        result = await llm.ainvoke(prompt)
        if hasattr(result, "events"):
            events = [e.model_dump() if hasattr(e, "model_dump") else dict(e) for e in result.events]
            criticality = result.asset_criticality or criticality
            related_cases = list(result.related_cases or [])
    except Exception as exc:
        log.warning("investigator_llm_failed", error=str(exc))

    if not events:
        events = [
            {
                "timestamp": state["created_at"],
                "event_type": "alert_received",
                "description": f"Alert {state['alert_id']} received from {host}",
                "source": "wazuh",
            }
        ]

    elapsed = int((time.time() - t0) * 1000)
    return {
        "investigation_timeline": events,
        "asset_criticality": criticality,
        "related_cases": related_cases or [e["alert_id"] for e in related[-3:]],
        "processing_time_ms": state.get("processing_time_ms", 0) + elapsed,
        "total_cost_usd": state.get("total_cost_usd", 0.0) + cost,
    }
