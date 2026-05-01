"""FastAPI webhook receiver for Wazuh-shaped alerts."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

import structlog
from fastapi import BackgroundTasks, FastAPI, HTTPException

from agents.config import MOCK_MODE
from agents.graph import run_alert
from ingestion.redis_stream import publish_alert, list_recent_alerts
from tenants.config import validate_tenant

log = structlog.get_logger(__name__)

app = FastAPI(title="AegisGraph Alert Ingestion", version="0.1.0")


_RECENT_CASES: Dict[str, list] = {}


async def _process(alert_id: str, tenant_id: str, alert: Dict[str, Any]) -> None:
    try:
        case = await run_alert(alert, tenant_id, alert_id=alert_id)
        _RECENT_CASES.setdefault(tenant_id, []).append(case)
        if len(_RECENT_CASES[tenant_id]) > 100:
            _RECENT_CASES[tenant_id] = _RECENT_CASES[tenant_id][-50:]
        log.info("alert_processed", alert_id=alert_id, verdict=case.get("verdict"), case=case.get("iris_case_id"))
    except Exception as exc:
        log.exception("alert_processing_failed", alert_id=alert_id, error=str(exc))


@app.post("/webhook/alert/{tenant_id}")
async def receive_alert(tenant_id: str, alert: Dict[str, Any], background_tasks: BackgroundTasks):
    try:
        validate_tenant(tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    alert_id = str(uuid4())
    alert.setdefault("_aegisgraph", {})
    alert["_aegisgraph"].update(
        {"alert_id": alert_id, "tenant_id": tenant_id, "received_at": datetime.now(timezone.utc).isoformat()}
    )
    await publish_alert(tenant_id, alert)
    background_tasks.add_task(_process, alert_id, tenant_id, alert)
    return {"status": "accepted", "alert_id": alert_id}


@app.get("/health")
async def health():
    return {"status": "ok", "mock_mode": MOCK_MODE}


@app.get("/cases/recent/{tenant_id}")
async def recent_cases(tenant_id: str, limit: int = 10):
    try:
        validate_tenant(tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"tenant_id": tenant_id, "cases": _RECENT_CASES.get(tenant_id, [])[-limit:]}


@app.get("/alerts/recent/{tenant_id}")
async def recent_alerts(tenant_id: str, limit: int = 10):
    try:
        validate_tenant(tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    alerts = await list_recent_alerts(tenant_id, count=limit)
    return {"tenant_id": tenant_id, "alerts": alerts}
