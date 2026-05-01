"""Shodan host lookup MCP server."""
from __future__ import annotations
import hashlib
from typing import Any, Dict

from .base import BaseMCP


class ShodanMCP(BaseMCP):
    name = "shodan"
    base_url = "https://api.shodan.io"
    api_key_env = "SHODAN_API_KEY"
    cache_ttl = 60 * 60 * 6  # 6h

    async def lookup(self, ioc_value: str, ioc_type: str = "ip") -> Dict[str, Any]:
        if ioc_type != "ip":
            return self._wrap(False, {}, error="shodan only supports IP")
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
                resp = await self._http_get(f"{self.base_url}/shodan/host/{ip}", params={"key": self.api_key or ""})
                data = {
                    "org": resp.get("org"),
                    "country_name": resp.get("country_name"),
                    "city": resp.get("city"),
                    "ports": resp.get("ports", []),
                    "vulns": list(resp.get("vulns", []) or []),
                    "tags": resp.get("tags", []),
                    "isp": resp.get("isp"),
                }
            except Exception as exc:
                return self._wrap(False, {}, error=str(exc))
        self._store(key, data)
        return self._wrap(True, data)

    def _mock_ip(self, ip: str) -> Dict[str, Any]:
        h = int(hashlib.sha256(ip.encode()).hexdigest()[:8], 16)
        port_pool = [22, 80, 443, 3306, 3389, 6379, 8080, 8443, 9200]
        ports = sorted({port_pool[(h >> i) % len(port_pool)] for i in range(0, 16, 4)})
        return {
            "org": ["DigitalOcean", "Hetzner", "AWS", "ChinaNet", "Cogent"][h % 5],
            "country_name": ["United States", "Russia", "China", "Germany", "Brazil"][h % 5],
            "city": ["Ashburn", "Moscow", "Beijing", "Frankfurt", "Sao Paulo"][h % 5],
            "ports": ports,
            "vulns": ["CVE-2021-44228"] if (h % 10) < 2 else [],
            "tags": ["c2"] if (h % 10) < 2 else [],
            "isp": ["DO LLC", "Hetzner", "Amazon", "CT", "Cogent"][h % 5],
        }
