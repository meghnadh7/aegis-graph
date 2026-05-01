"""URLhaus MCP server (no API key required)."""
from __future__ import annotations
import hashlib
from typing import Any, Dict

from .base import BaseMCP


class URLhausMCP(BaseMCP):
    name = "urlhaus"
    base_url = "https://urlhaus-api.abuse.ch/v1"
    api_key_env = None
    cache_ttl = 60 * 60 * 12  # 12h

    async def lookup(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if ioc_type == "url":
            return await self.lookup_url(ioc_value)
        if ioc_type in {"domain", "ip"}:
            return await self.lookup_host(ioc_value)
        return self._wrap(False, {}, error=f"unsupported IOC type: {ioc_type}")

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        key = self._cache_key("url", url)
        cached = self._cached(key)
        if cached:
            return self._wrap(True, cached, cached=True)
        if self.mock_mode:
            data = self._mock(url, kind="url")
        else:
            try:
                resp = await self._http_post(f"{self.base_url}/url/", data={"url": url})
                data = {
                    "query_status": resp.get("query_status"),
                    "urlhaus_reference": resp.get("urlhaus_reference"),
                    "threat": resp.get("threat"),
                    "tags": resp.get("tags", []),
                    "payloads": resp.get("payloads", []),
                }
            except Exception as exc:
                return self._wrap(False, {}, error=str(exc))
        self._store(key, data)
        return self._wrap(True, data)

    async def lookup_host(self, host: str) -> Dict[str, Any]:
        key = self._cache_key("host", host)
        cached = self._cached(key)
        if cached:
            return self._wrap(True, cached, cached=True)
        if self.mock_mode:
            data = self._mock(host, kind="host")
        else:
            try:
                resp = await self._http_post(f"{self.base_url}/host/", data={"host": host})
                data = {
                    "query_status": resp.get("query_status"),
                    "urls_count": resp.get("urls_count"),
                    "blacklists": resp.get("blacklists"),
                    "urls": resp.get("urls", []),
                }
            except Exception as exc:
                return self._wrap(False, {}, error=str(exc))
        self._store(key, data)
        return self._wrap(True, data)

    def _mock(self, value: str, kind: str) -> Dict[str, Any]:
        h = int(hashlib.sha256(value.encode()).hexdigest()[:8], 16)
        flagged = (h % 10) < 2
        if not flagged:
            return {"query_status": "no_results"} if kind == "url" else {"query_status": "no_results", "urls_count": 0}
        if kind == "url":
            return {
                "query_status": "ok",
                "urlhaus_reference": f"https://urlhaus.abuse.ch/url/{h}/",
                "threat": "malware_download",
                "tags": ["emotet", "exe"],
                "payloads": [{"filename": "invoice.exe", "file_type": "exe"}],
            }
        return {
            "query_status": "ok",
            "urls_count": (h % 20) + 1,
            "blacklists": {"surbl": "listed", "spamhaus_dbl": "listed"},
            "urls": [{"url": f"http://{value}/payload.exe", "threat": "malware_download"}],
        }
