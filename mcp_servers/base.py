"""Shared scaffolding for the threat-intel MCP servers — cache + retries + mock toggle."""
from __future__ import annotations
import hashlib
import json
import os
import time
from typing import Any, Dict, Optional

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

log = structlog.get_logger(__name__)


class RateLimitError(Exception):
    pass


class _InMemoryCache:
    """Tiny TTL cache. Keeps us from hammering external APIs with the same lookup."""

    def __init__(self) -> None:
        self._store: Dict[str, Any] = {}

    def get(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        if not entry:
            return None
        value, expiry = entry
        if expiry and expiry < time.time():
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any, ttl: int) -> None:
        self._store[key] = (value, time.time() + ttl if ttl else None)


_GLOBAL_CACHE = _InMemoryCache()


def _is_placeholder(v: Optional[str]) -> bool:
    if not v:
        return True
    s = v.strip().lower()
    return s.startswith("your_") or s in {"", "changeme"}


class BaseMCP:
    """Common MCP server scaffolding."""

    name: str = "base"
    base_url: str = ""
    api_key_env: Optional[str] = None
    cache_ttl: int = 3600

    def __init__(self, mock_mode: Optional[bool] = None, cache_ttl: Optional[int] = None) -> None:
        env_mock = os.getenv("MOCK_MODE", "true").strip().lower() in {"1", "true", "yes", "on"}
        self.mock_mode = env_mock if mock_mode is None else mock_mode
        if cache_ttl is not None:
            self.cache_ttl = cache_ttl
        self.api_key = os.getenv(self.api_key_env) if self.api_key_env else None
        if self.api_key_env and _is_placeholder(self.api_key):
            self.api_key = None
            self.mock_mode = True

    def _cache_key(self, method: str, *args: Any) -> str:
        payload = json.dumps([self.name, method, *args], sort_keys=True, default=str)
        return f"mcp:{self.name}:{hashlib.sha256(payload.encode()).hexdigest()[:24]}"

    def _cached(self, key: str) -> Optional[Dict[str, Any]]:
        return _GLOBAL_CACHE.get(key)

    def _store(self, key: str, value: Dict[str, Any]) -> None:
        _GLOBAL_CACHE.set(key, value, self.cache_ttl)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=2, max=10), reraise=True)
    async def _http_get(self, url: str, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, headers=headers, params=params)
            if r.status_code == 429:
                raise RateLimitError(f"{self.name} rate-limited")
            r.raise_for_status()
            return r.json()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=2, max=10), reraise=True)
    async def _http_post(self, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[Dict[str, Any]] = None, json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(url, headers=headers, data=data, json=json_body)
            if r.status_code == 429:
                raise RateLimitError(f"{self.name} rate-limited")
            r.raise_for_status()
            try:
                return r.json()
            except Exception:
                return {"raw": r.text}

    def _wrap(self, success: bool, data: Dict[str, Any], cached: bool = False, error: Optional[str] = None) -> Dict[str, Any]:
        return {"tool": self.name, "success": success, "data": data, "error": error, "cached": cached}
