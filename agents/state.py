"""TypedDict shape for the case object that flows through every node."""
from __future__ import annotations
from typing import TypedDict, Optional, Literal, List, Dict, Any


class IOC(TypedDict):
    type: str
    value: str
    source: str
    malicious: bool
    confidence: float
    details: Dict[str, Any]


class ATTACKTechnique(TypedDict):
    technique_id: str
    technique_name: str
    tactic: str
    kill_chain_phase: str
    confidence: float
    matched_sigma_rules: List[str]


class EnrichmentResult(TypedDict):
    tool: str
    success: bool
    data: Dict[str, Any]
    error: Optional[str]
    cached: bool


class InvestigationEvent(TypedDict):
    timestamp: str
    event_type: str
    description: str
    source: str


class TriageCase(TypedDict, total=False):
    # Identity
    case_id: str
    tenant_id: str
    alert_id: str
    created_at: str

    # Raw alert
    raw_alert: Dict[str, Any]
    alert_type: str
    severity: str

    # Triage
    extracted_iocs: List[IOC]
    enrichment_results: List[EnrichmentResult]
    dedup_status: str

    # ATT&CK
    attack_techniques: List[ATTACKTechnique]
    kill_chain_stage: str
    sigma_matches: List[str]

    # Investigator
    investigation_timeline: List[InvestigationEvent]
    related_cases: List[str]
    asset_criticality: str

    # Reflector
    confidence_score: float
    revision_count: int
    critic_feedback: Optional[str]

    # Reporter
    verdict: Optional[Literal["true_positive", "false_positive", "escalate"]]
    analyst_summary: Optional[str]
    recommended_action: Optional[str]
    iris_case_id: Optional[str]

    # HITL
    human_approved: bool
    human_feedback: Optional[str]

    # Meta
    node_errors: List[str]
    processing_time_ms: int
    total_cost_usd: float


def empty_case(tenant_id: str, alert_id: str, raw_alert: Dict[str, Any]) -> TriageCase:
    """New blank case object the graph mutates as it goes."""
    from uuid import uuid4
    from datetime import datetime, timezone
    return TriageCase(
        case_id=f"SG-{uuid4().hex[:10].upper()}",
        tenant_id=tenant_id,
        alert_id=alert_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        raw_alert=raw_alert,
        alert_type=raw_alert.get("rule", {}).get("description", "unknown"),
        severity=_severity_from_alert(raw_alert),
        extracted_iocs=[],
        enrichment_results=[],
        dedup_status="new",
        attack_techniques=[],
        kill_chain_stage="unknown",
        sigma_matches=[],
        investigation_timeline=[],
        related_cases=[],
        asset_criticality="low",
        confidence_score=0.0,
        revision_count=0,
        critic_feedback=None,
        verdict=None,
        analyst_summary=None,
        recommended_action=None,
        iris_case_id=None,
        human_approved=False,
        human_feedback=None,
        node_errors=[],
        processing_time_ms=0,
        total_cost_usd=0.0,
    )


def _severity_from_alert(raw_alert: Dict[str, Any]) -> str:
    level = raw_alert.get("rule", {}).get("level", 5)
    try:
        level = int(level)
    except (TypeError, ValueError):
        level = 5
    if level >= 12:
        return "critical"
    if level >= 9:
        return "high"
    if level >= 6:
        return "medium"
    return "low"
