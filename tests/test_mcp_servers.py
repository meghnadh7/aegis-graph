"""Smoke tests for MCP servers in mock mode."""
import pytest

from mcp_servers import VirusTotalMCP, ShodanMCP, AbuseIPDBMCP, URLhausMCP, GreyNoiseMCP


@pytest.mark.asyncio
async def test_virustotal_ip_mock():
    vt = VirusTotalMCP(mock_mode=True)
    r = await vt.lookup_ip("8.8.8.8")
    assert r["success"] is True
    assert "country" in r["data"]


@pytest.mark.asyncio
async def test_virustotal_hash_mock():
    vt = VirusTotalMCP(mock_mode=True)
    r = await vt.lookup_hash("a" * 64)
    assert r["success"] is True
    assert "total_engines" in r["data"]


@pytest.mark.asyncio
async def test_shodan_mock():
    s = ShodanMCP(mock_mode=True)
    r = await s.lookup_ip("198.51.100.42")
    assert r["success"]
    assert isinstance(r["data"]["ports"], list)


@pytest.mark.asyncio
async def test_abuseipdb_high_score():
    a = AbuseIPDBMCP(mock_mode=True)
    r = await a.check_ip("198.51.100.250")
    assert r["data"]["abuseConfidenceScore"] > 50


@pytest.mark.asyncio
async def test_urlhaus_lookup():
    u = URLhausMCP(mock_mode=True)
    r = await u.lookup_url("http://example.com/payload.exe")
    assert "query_status" in r["data"]


@pytest.mark.asyncio
async def test_greynoise_lookup():
    g = GreyNoiseMCP(mock_mode=True)
    r = await g.lookup_ip("198.51.100.10")
    assert "noise" in r["data"]


@pytest.mark.asyncio
async def test_cache_hit():
    vt = VirusTotalMCP(mock_mode=True)
    a = await vt.lookup_ip("1.2.3.4")
    b = await vt.lookup_ip("1.2.3.4")
    assert a["cached"] is False
    assert b["cached"] is True
