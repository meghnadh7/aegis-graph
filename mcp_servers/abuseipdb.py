"""AbuseIPDB IP reputation MCP server."""
from __future__ import annotations
from typing import Any, Dict

from .base import BaseMCP


class AbuseIPDBMCP(BaseMCP):
    name = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2"
    api_key_env = "ABUSEIPDB_API_KEY"
    cache_ttl = 60 * 60 * 12  # 12h

    async def lookup(self, ioc_value: str, ioc_type: str = "ip") -> Dict[str, Any]:
        if ioc_type != "ip":
            return self._wrap(False, {}, error="abuseipdb only supports IP")
        return await self.check_ip(ioc_value)

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        key = self._cache_key("ip", ip)
        cached = self._cached(key)
        if cached:
            return self._wrap(True, cached, cached=True)
        if self.mock_mode:
            data = self._mock_ip(ip)
        else:
            try:
                resp = await self._http_get(
                    f"{self.base_url}/check",
                    headers={"Key": self.api_key or "", "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                )
                d = resp.get("data", {})
                data = {
                    "abuseConfidenceScore": d.get("abuseConfidenceScore", 0),
                    "totalReports": d.get("totalReports", 0),
                    "countryCode": d.get("countryCode"),
                    "isp": d.get("isp"),
                    "usageType": d.get("usageType"),
                    "lastReportedAt": d.get("lastReportedAt"),
                }
            except Exception as exc:
                return self._wrap(False, {}, error=str(exc))
        self._store(key, data)
        return self._wrap(True, data)

    def _mock_ip(self, ip: str) -> Dict[str, Any]:
        try:
            last_octet = int(ip.split(".")[-1])
        except (ValueError, IndexError):
            last_octet = 50
        if last_octet >= 100:
            score = min(100, 60 + last_octet // 4)
            reports = score * 3
        else:
            score = max(0, last_octet - 5)
            reports = score
        return {
            "abuseConfidenceScore": score,
            "totalReports": reports,
            "countryCode": "US" if last_octet % 3 == 0 else "RU",
            "isp": "Some ISP",
            "usageType": "Data Center/Web Hosting/Transit",
            "lastReportedAt": "2026-04-15T10:00:00Z" if score > 0 else None,
        }
