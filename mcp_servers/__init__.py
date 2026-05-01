"""Threat-intel MCP servers (VirusTotal, Shodan, AbuseIPDB, URLhaus, GreyNoise).

Same interface for all five. In mock mode they return seeded fake responses;
with real keys + MOCK_MODE=false they make real HTTP calls behind retries
and a TTL cache.
"""
from .virustotal import VirusTotalMCP
from .shodan import ShodanMCP
from .abuseipdb import AbuseIPDBMCP
from .urlhaus import URLhausMCP
from .greynoise import GreyNoiseMCP

__all__ = ["VirusTotalMCP", "ShodanMCP", "AbuseIPDBMCP", "URLhausMCP", "GreyNoiseMCP"]
