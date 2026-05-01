"""The LangGraph supervisor graph.

Five nodes in sequence — triage, attack_mapper, investigator, reflector,
reporter. The reflector decides whether to loop back (capped at
MAX_REVISION_LOOPS) or hand off to the reporter. Every node call is wrapped
in a try/except so a single broken tool doesn't kill the whole run; errors
collect in `node_errors` and the case still gets a verdict.

If `langgraph` isn't installed we fall back to a hand-rolled async runner
that mirrors the same control flow — handy for CI environments where you
don't want the full LangGraph install.
"""
from __future__ import annotations
import asyncio
import time
from functools import wraps
from typing import Any, Dict

import structlog

from agents.config import CONFIDENCE_THRESHOLD, MAX_REVISION_LOOPS
from agents.state import TriageCase, empty_case
from agents.nodes.triage import triage_node
from agents.nodes.attack_mapper import attack_mapper_node
from agents.nodes.investigator import investigator_node
from agents.nodes.reflector import reflector_node
from agents.nodes.reporter import reporter_node

log = structlog.get_logger(__name__)


def _safe_node(fn):
    @wraps(fn)
    async def wrapper(state: TriageCase) -> Dict[str, Any]:
        try:
            return await fn(state)
        except Exception as exc:
            log.exception("node_failed", node=fn.__name__, error=str(exc))
            errs = list(state.get("node_errors", []))
            errs.append(f"{fn.__name__}: {exc}")
            return {"node_errors": errs}
    return wrapper


def _route_after_reflector(state: TriageCase) -> str:
    if (
        state.get("confidence_score", 0.0) < CONFIDENCE_THRESHOLD
        and state.get("revision_count", 0) < MAX_REVISION_LOOPS
    ):
        return "revise"
    return "report"


async def _bump_revision(state: TriageCase) -> Dict[str, Any]:
    return {"revision_count": state.get("revision_count", 0) + 1}


def build_graph():
    """Construct and compile the LangGraph supervisor graph.

    Returns a callable Runnable. Falls back to a hand-rolled async runner if
    langgraph is not importable.
    """
    try:
        from langgraph.graph import StateGraph, START, END
    except ImportError:
        return _build_fallback_runner()

    g = StateGraph(TriageCase)
    g.add_node("triage", _safe_node(triage_node))
    g.add_node("attack_mapper", _safe_node(attack_mapper_node))
    g.add_node("investigator", _safe_node(investigator_node))
    g.add_node("reflector", _safe_node(reflector_node))
    g.add_node("reporter", _safe_node(reporter_node))
    g.add_node("bump_revision", _bump_revision)

    g.add_edge(START, "triage")
    g.add_edge("triage", "attack_mapper")
    g.add_edge("attack_mapper", "investigator")
    g.add_edge("investigator", "reflector")
    g.add_conditional_edges("reflector", _route_after_reflector, {"revise": "bump_revision", "report": "reporter"})
    g.add_edge("bump_revision", "triage")
    g.add_edge("reporter", END)

    return g.compile()


class _FallbackRunner:
    """Asyncio runner that walks the same nodes when langgraph isn't installed."""

    async def ainvoke(self, state: TriageCase) -> TriageCase:
        for _ in range(MAX_REVISION_LOOPS + 1):
            for node in (triage_node, attack_mapper_node, investigator_node, reflector_node):
                update = await _safe_node(node)(state)
                state.update(update)
            if state.get("confidence_score", 0.0) >= CONFIDENCE_THRESHOLD:
                break
            if state.get("revision_count", 0) >= MAX_REVISION_LOOPS:
                break
            state["revision_count"] = state.get("revision_count", 0) + 1
        update = await _safe_node(reporter_node)(state)
        state.update(update)
        return state

    def invoke(self, state: TriageCase) -> TriageCase:
        return asyncio.run(self.ainvoke(state))


def _build_fallback_runner() -> _FallbackRunner:
    log.warning("langgraph_not_available_using_fallback")
    return _FallbackRunner()


async def run_alert(raw_alert: Dict[str, Any], tenant_id: str, alert_id: str | None = None) -> TriageCase:
    """Convenience: build state, run the graph, return final case."""
    from uuid import uuid4
    alert_id = alert_id or f"AL-{uuid4().hex[:10].upper()}"
    state = empty_case(tenant_id, alert_id, raw_alert)
    graph = build_graph()
    t0 = time.time()
    if hasattr(graph, "ainvoke"):
        final = await graph.ainvoke(state)
    else:
        final = graph.invoke(state)
    if isinstance(final, dict):
        final.setdefault("processing_time_ms", int((time.time() - t0) * 1000))
    return final  # type: ignore[return-value]
