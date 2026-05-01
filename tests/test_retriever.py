"""Smoke tests for the HyDE retriever and KB ingest."""
import pytest

from knowledge_base.ingest import ingest_all, get_store
from knowledge_base.retriever import HyDERetriever


@pytest.mark.asyncio
async def test_ingest_creates_namespaces():
    counts = await ingest_all(["tenant_a"])
    assert counts.get("tenant_a_attack", 0) > 0
    assert counts.get("tenant_a_sigma", 0) > 0
    assert counts.get("tenant_a_runbooks", 0) > 0


@pytest.mark.asyncio
async def test_retrieve_attack():
    await ingest_all(["tenant_a"])
    r = HyDERetriever(get_store(), "tenant_a")
    hits = await r.retrieve_attack_techniques("powershell encoded command on host", top_k=3)
    assert len(hits) > 0


@pytest.mark.asyncio
async def test_retrieve_sigma():
    await ingest_all(["tenant_a"])
    r = HyDERetriever(get_store(), "tenant_a")
    hits = await r.retrieve_sigma_rules("powershell encoded command", top_k=2)
    assert len(hits) > 0
