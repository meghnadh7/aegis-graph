"""Redis Stream publisher/consumer with an in-memory fallback for offline runs."""
from __future__ import annotations
import asyncio
import json
from typing import Any, Dict, List, Optional

import structlog

from agents.config import REDIS_URL

log = structlog.get_logger(__name__)


class _InMemStream:
    def __init__(self) -> None:
        self._streams: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def xadd(self, stream: str, fields: Dict[str, Any]) -> str:
        async with self._lock:
            self._streams.setdefault(stream, []).append(fields)
            return f"{stream}-{len(self._streams[stream])}"

    async def xrange(self, stream: str, count: int = 10) -> List[Dict[str, Any]]:
        async with self._lock:
            return list(self._streams.get(stream, []))[-count:]


_INMEM = _InMemStream()


async def _client():
    try:
        import redis.asyncio as aioredis  # type: ignore
        client = aioredis.from_url(REDIS_URL, decode_responses=True)
        await client.ping()
        return client
    except Exception:
        return None


async def publish_alert(tenant_id: str, alert: Dict[str, Any]) -> str:
    stream = f"alerts:{tenant_id}"
    payload = {"json": json.dumps(alert, default=str)}
    client = await _client()
    if client is None:
        return await _INMEM.xadd(stream, payload)
    try:
        msg_id = await client.xadd(stream, payload, maxlen=10000)
        return msg_id
    except Exception as exc:
        log.warning("redis_xadd_failed", error=str(exc))
        return await _INMEM.xadd(stream, payload)


async def list_recent_alerts(tenant_id: str, count: int = 10) -> List[Dict[str, Any]]:
    stream = f"alerts:{tenant_id}"
    client = await _client()
    if client is None:
        rows = await _INMEM.xrange(stream, count)
        return [json.loads(r["json"]) for r in rows if r.get("json")]
    try:
        entries = await client.xrevrange(stream, count=count)
        out: List[Dict[str, Any]] = []
        for _id, fields in entries:
            j = fields.get("json")
            if j:
                out.append(json.loads(j))
        return out
    except Exception as exc:
        log.warning("redis_xrevrange_failed", error=str(exc))
        return []
