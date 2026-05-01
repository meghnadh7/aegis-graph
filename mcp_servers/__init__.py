"""MCP-style threat-intel servers wrapping VirusTotal, Shodan, AbuseIPDB, URLhaus, GreyNoise.

In MOCK_MODE every server returns deterministic fake data so the entire pipeline
runs offline. When real keys are set and MOCK_MODE=false, the same interface
makes real HTTP calls with retry + caching.
"""
from .virustotal import VirusTotalMCP
from .shodan import ShodanMCP
from .abuseipdb import AbuseIPDBMCP
from .urlhaus import URLhausMCP
from .greynoise import GreyNoiseMCP

__all__ = ["VirusTotalMCP", "ShodanMCP", "AbuseIPDBMCP", "URLhausMCP", "GreyNoiseMCP"]
