"""GreyNoise community MCP server."""
from __future__ import annotations
import hashlib
from typing import Any, Dict

from .base import BaseMCP


class GreyNoiseMCP(BaseMCP):
    name = "greynoise"
    base_url = "https://api.greynoise.io/v3"
    api_key_env = "GREYNOISE_API_KEY"
    cache_ttl = 60 * 60 * 6  # 6h

    async def lookup(self, ioc_value: str, ioc_type: str = "ip") -> Dict[str, Any]:
        if ioc_type != "ip":
            return self._wrap(False, {}, error="greynoise only supports IP")
        return await self.lookup_ip(ioc_value)

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        key = self._cache_key("ip", ip)
        cached = self._cached(key)
        if cached:
            return self._wrap(True, cached, cached=True)
        if self.mock_mode:
            data = self._mock_ip(ip)
        else:
            try:
                resp = await self._http_get(
                    f"{self.base_url}/community/{ip}",
                    headers={"key": self.api_key or "", "Accept": "application/json"},
                )
                data = {
                    "noise": resp.get("noise"),
                    "riot": resp.get("riot"),
                    "classification": resp.get("classification"),
                    "name": resp.get("name"),
                    "link": resp.get("link"),
                    "last_seen": resp.get("last_seen"),
                }
            except Exception as exc:
                return self._wrap(False, {}, error=str(exc))
        self._store(key, data)
        return self._wrap(True, data)

    def _mock_ip(self, ip: str) -> Dict[str, Any]:
        h = int(hashlib.sha256(ip.encode()).hexdigest()[:8], 16)
        is_noise = (h % 10) < 6
        if not is_noise:
            return {"noise": False, "riot": False, "classification": "unknown", "name": None, "link": None, "last_seen": None}
        classifications = ["benign", "malicious", "unknown"]
        c = classifications[h % 3]
        names = ["Shodan Scanner", "Censys Scanner", "Tor Exit Node", "Mirai Scanner"]
        return {
            "noise": True,
            "riot": (h % 5) == 0,
            "classification": c,
            "name": names[h % len(names)],
            "link": f"https://viz.greynoise.io/ip/{ip}",
            "last_seen": "2026-04-29",
        }
