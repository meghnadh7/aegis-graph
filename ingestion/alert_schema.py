"""Pydantic models describing the Wazuh alert envelope AegisGraph accepts."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class WazuhRule(BaseModel):
    id: str
    level: int = 5
    description: str = ""
    mitre: Dict[str, List[str]] = Field(default_factory=dict)


class WazuhAgent(BaseModel):
    name: str = "unknown-host"
    ip: str = "0.0.0.0"
    id: Optional[str] = None


class WazuhAlert(BaseModel):
    """Best-effort envelope. Extra fields (Windows eventdata, syslog) are kept."""
    id: str
    timestamp: str
    rule: WazuhRule
    agent: WazuhAgent
    data: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}
