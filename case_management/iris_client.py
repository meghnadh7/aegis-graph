"""DFIR-IRIS REST client. Mock-mode logs the would-be requests and returns a fake id."""
from __future__ import annotations
from typing import Any, Dict, Optional
from uuid import uuid4

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from agents.config import IRIS_URL, IRIS_API_KEY, MOCK_MODE, iris_keys_present

log = structlog.get_logger(__name__)


_VERDICT_MAP = {
    "true_positive": "True Positive",
    "false_positive": "False Positive",
    "escalate": "Open",
}

_SEVERITY_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class IRISClient:
    def __init__(self) -> None:
        self.mock = MOCK_MODE or not iris_keys_present()
        self.base = IRIS_URL.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {IRIS_API_KEY}" if IRIS_API_KEY else "",
            "Content-Type": "application/json",
        }

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=2, max=10), reraise=True)
    async def _post(self, path: str, json_body: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.post(f"{self.base}/api/v1{path}", headers=self.headers, json=json_body)
            r.raise_for_status()
            return r.json()

    async def create_case(self, tenant_id: str, case_data: Dict[str, Any]) -> str:
        payload = {
            "case_name": f"[{tenant_id.upper()}] {case_data.get('alert_type','alert')} — {case_data.get('case_id','')}",
            "case_description": case_data.get("analyst_summary") or "Triage in progress.",
            "case_soc_id": case_data.get("alert_id"),
            "case_customer": tenant_id,
            "case_classification": _VERDICT_MAP.get(case_data.get("verdict") or "", "Open"),
            "case_severity_id": _SEVERITY_MAP.get(case_data.get("severity", "medium"), 2),
        }
        if self.mock:
            case_id = f"MOCK-CASE-{uuid4().hex[:8].upper()}"
            log.info("iris_create_case_mock", case_id=case_id, payload=payload)
            return case_id
        try:
            resp = await self._post("/cases/add", payload)
            return str(resp.get("data", {}).get("case_id") or resp.get("case_id") or uuid4().hex)
        except Exception as exc:
            log.warning("iris_create_case_failed", error=str(exc))
            return f"FAILED-{uuid4().hex[:8]}"

    async def add_ioc(self, case_id: str, ioc: Dict[str, Any]) -> None:
        payload = {
            "case_id": case_id,
            "ioc_value": ioc.get("value"),
            "ioc_type": ioc.get("type"),
            "ioc_description": f"Source: {ioc.get('source')}, Confidence: {ioc.get('confidence')}",
            "ioc_tlp": "amber",
        }
        if self.mock:
            log.info("iris_add_ioc_mock", case_id=case_id, ioc_value=ioc.get("value"))
            return
        try:
            await self._post("/case/ioc/add", payload)
        except Exception as exc:
            log.warning("iris_add_ioc_failed", error=str(exc))

    async def add_asset(self, case_id: str, hostname: str, criticality: str) -> None:
        payload = {"case_id": case_id, "asset_name": hostname, "asset_description": f"criticality={criticality}"}
        if self.mock:
            log.info("iris_add_asset_mock", case_id=case_id, host=hostname)
            return
        try:
            await self._post("/case/asset/add", payload)
        except Exception as exc:
            log.warning("iris_add_asset_failed", error=str(exc))

    async def add_timeline_event(self, case_id: str, event: Dict[str, Any]) -> None:
        payload = {
            "case_id": case_id,
            "event_title": event.get("event_type", "event"),
            "event_content": event.get("description", ""),
            "event_date": event.get("timestamp"),
            "event_source": event.get("source", "aegisgraph"),
        }
        if self.mock:
            log.info("iris_add_timeline_mock", case_id=case_id, evt=event.get("event_type"))
            return
        try:
            await self._post("/case/timeline/event/add", payload)
        except Exception as exc:
            log.warning("iris_add_timeline_failed", error=str(exc))

    async def add_attack_attribute(self, case_id: str, technique_id: str, technique_name: str) -> None:
        payload = {
            "case_id": case_id,
            "attribute_name": "mitre_attack",
            "attribute_value": f"{technique_id} {technique_name}",
        }
        if self.mock:
            log.info("iris_add_attack_attr_mock", case_id=case_id, tid=technique_id)
            return
        try:
            await self._post("/case/attribute/add", payload)
        except Exception as exc:
            log.warning("iris_add_attack_attr_failed", error=str(exc))

    async def add_note(self, case_id: str, note_text: str) -> None:
        payload = {"case_id": case_id, "note_title": "AegisGraph", "note_content": note_text}
        if self.mock:
            log.info("iris_add_note_mock", case_id=case_id, len=len(note_text))
            return
        try:
            await self._post("/case/notes/add", payload)
        except Exception as exc:
            log.warning("iris_add_note_failed", error=str(exc))
