"""VirusTotal v3 MCP server. Mock-mode produces deterministic fake verdicts."""
from __future__ import annotations
import hashlib
from typing import Any, Dict, Optional

from .base import BaseMCP


class VirusTotalMCP(BaseMCP):
    name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"
    api_key_env = "VIRUSTOTAL_API_KEY"
    cache_ttl = 60 * 60 * 24  # 24h

    async def lookup(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        ioc_type = ioc_type.lower()
        if ioc_type in {"sha256", "sha1", "md5", "hash"}:
            return await self.lookup_hash(ioc_value)
        if ioc_type == "ip":
            return await self.lookup_ip(ioc_value)
        if ioc_type == "url":
            return await self.lookup_url(ioc_value)
        if ioc_type == "domain":
            return await self.lookup_domain(ioc_value)
        return self._wrap(False, {}, error=f"unsupported IOC type: {ioc_type}")

    async def lookup_hash(self, sha256: str) -> Dict[str, Any]:
        key = self._cache_key("hash", sha256)
        cached = self._cached(key)
        if cached:
            return self._wrap(True, cached, cached=True)
        if self.mock_mode:
            data = self._mock_hash(sha256)
        else:
            try:
                resp = await self._http_get(f"{self.base_url}/files/{sha256}", headers={"x-apikey": self.api_key or ""})
                attr = resp.get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                data = {
                    "malicious_count": stats.get("malicious", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "popular_threat_label": attr.get("popular_threat_classification", {}).get("suggested_threat_label"),
                    "first_submission_date": attr.get("first_submission_date"),
                }
            except Exception as exc:
                return self._wrap(False, {}, error=str(exc))
        self._store(key, data)
        return self._wrap(True, data)

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        key = self._cache_key("ip", ip)
        cached = self._cached(key)
        if cached:
            return self._wrap(True, cached, cached=True)
        if self.mock_mode:
            data = self._mock_ip(ip)
        else:
            try:
                resp = await self._http_get(f"{self.base_url}/ip_addresses/{ip}", headers={"x-apikey": self.api_key or ""})
                attr = resp.get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                data = {
                    "country": attr.get("country"),
                    "as_owner": attr.get("as_owner"),
                    "malicious_votes": stats.get("malicious", 0),
                    "reputation": attr.get("reputation", 0),
                }
            except Exception as exc:
                return self._wrap(False, {}, error=str(exc))
        self._store(key, data)
        return self._wrap(True, data)

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        key = self._cache_key("url", url)
        cached = self._cached(key)
        if cached:
            return self._wrap(True, cached, cached=True)
        if self.mock_mode:
            data = self._mock_url(url)
        else:
            data = {"malicious_count": 0, "threat_names": [], "categories": []}
        self._store(key, data)
        return self._wrap(True, data)

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        key = self._cache_key("domain", domain)
        cached = self._cached(key)
        if cached:
            return self._wrap(True, cached, cached=True)
        if self.mock_mode:
            data = self._mock_domain(domain)
        else:
            try:
                resp = await self._http_get(f"{self.base_url}/domains/{domain}", headers={"x-apikey": self.api_key or ""})
                attr = resp.get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                data = {
                    "reputation": attr.get("reputation", 0),
                    "categories": list(attr.get("categories", {}).values()),
                    "malicious_votes": stats.get("malicious", 0),
                }
            except Exception as exc:
                return self._wrap(False, {}, error=str(exc))
        self._store(key, data)
        return self._wrap(True, data)

    def _mock_hash(self, sha256: str) -> Dict[str, Any]:
        h = int(hashlib.sha256(sha256.encode()).hexdigest()[:8], 16)
        malicious = (h % 10) < 3
        return {
            "malicious_count": (h % 60) + 5 if malicious else 0,
            "total_engines": 72,
            "popular_threat_label": "trojan.mimikatz/credentialstealer" if malicious else None,
            "first_submission_date": 1690000000 + (h % 100000),
        }

    def _mock_ip(self, ip: str) -> Dict[str, Any]:
        h = int(hashlib.sha256(ip.encode()).hexdigest()[:8], 16)
        malicious = (h % 10) < 3
        return {
            "country": ["US", "RU", "CN", "DE", "BR"][h % 5],
            "as_owner": ["DigitalOcean", "Hetzner", "AWS", "ChinaNet", "Cogent"][h % 5],
            "malicious_votes": (h % 20) + 1 if malicious else 0,
            "reputation": -50 if malicious else 0,
        }

    def _mock_url(self, url: str) -> Dict[str, Any]:
        h = int(hashlib.sha256(url.encode()).hexdigest()[:8], 16)
        malicious = (h % 10) < 3
        return {
            "malicious_count": (h % 30) + 1 if malicious else 0,
            "threat_names": ["Phishing", "Malware"] if malicious else [],
            "categories": ["malicious"] if malicious else ["safe"],
        }

    def _mock_domain(self, domain: str) -> Dict[str, Any]:
        h = int(hashlib.sha256(domain.encode()).hexdigest()[:8], 16)
        malicious = (h % 10) < 3
        return {
            "reputation": -50 if malicious else 5,
            "categories": ["malware c2"] if malicious else ["business"],
            "malicious_votes": (h % 25) + 1 if malicious else 0,
        }
