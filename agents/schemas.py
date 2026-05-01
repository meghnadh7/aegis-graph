"""Pydantic models used as structured-output schemas for LLM calls."""
from __future__ import annotations
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field


class IOCModel(BaseModel):
    type: str
    value: str
    source: str = "extractor"
    malicious: bool = False
    confidence: float = 0.5
    details: Dict[str, Any] = Field(default_factory=dict)


class IOCExtraction(BaseModel):
    iocs: List[IOCModel] = Field(default_factory=list)


class ATTACKMatch(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    kill_chain_phase: str = ""
    confidence: float = 0.5
    matched_sigma_rules: List[str] = Field(default_factory=list)


class ATTACKMapping(BaseModel):
    techniques: List[ATTACKMatch] = Field(default_factory=list)
    kill_chain_stage: str = ""


class TimelineEventModel(BaseModel):
    timestamp: str
    event_type: str
    description: str
    source: str = "aegisgraph"


class InvestigationOutput(BaseModel):
    events: List[TimelineEventModel] = Field(default_factory=list)
    asset_criticality: str = "low"
    related_cases: List[str] = Field(default_factory=list)


class ReflectOutput(BaseModel):
    evidence_quality: float = 0.5
    reasoning_coherence: float = 0.5
    hallucination_risk: float = 0.5
    investigation_depth: float = 0.5
    feedback: str = ""

    def composite(self) -> float:
        return (
            self.evidence_quality * 0.35
            + self.reasoning_coherence * 0.25
            + self.hallucination_risk * 0.25
            + self.investigation_depth * 0.15
        )


class ReportOutput(BaseModel):
    verdict: Literal["true_positive", "false_positive", "escalate"]
    analyst_summary: str
    recommended_action: str
