"""Knowledge base ingestion.

If a Pinecone key is configured we upsert there; otherwise we keep an
in-process cosine-sim store with the same namespace layout, which is enough
for the demo and the offline evals.
"""
from __future__ import annotations
import math
from typing import Any, Dict, List, Optional, Tuple

import structlog

from agents.config import get_embedder, pinecone_keys_present, PINECONE_INDEX_NAME, MOCK_MODE
from tenants.config import list_tenants, load_tenant
from .mitre_loader import load_techniques, technique_to_chunk
from .sigma_loader import load_rules, rule_to_chunk
from .tenant_runbooks import load_runbooks_for_tenant, runbook_to_chunk

log = structlog.get_logger(__name__)


class InMemoryVectorStore:
    """Dumb cosine-similarity store, keyed by namespace. Fine for a few thousand vectors."""

    def __init__(self) -> None:
        self._ns: Dict[str, List[Tuple[str, List[float], Dict[str, Any]]]] = {}

    def upsert(self, namespace: str, vectors: List[Tuple[str, List[float], Dict[str, Any]]]) -> None:
        self._ns.setdefault(namespace, []).extend(vectors)

    def query(self, namespace: str, vector: List[float], top_k: int = 5) -> List[Dict[str, Any]]:
        items = self._ns.get(namespace, [])
        if not items:
            return []
        scored = []
        for vid, vec, meta in items:
            scored.append((_cosine(vector, vec), vid, meta))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{"id": vid, "score": score, "metadata": meta} for score, vid, meta in scored[:top_k]]

    def namespace_size(self, namespace: str) -> int:
        return len(self._ns.get(namespace, []))


_GLOBAL_STORE = InMemoryVectorStore()


def get_store():
    """Return the active vector store (Pinecone or in-memory)."""
    if MOCK_MODE or not pinecone_keys_present():
        return _GLOBAL_STORE
    try:
        from pinecone import Pinecone, ServerlessSpec  # type: ignore
        import os
        pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))
        existing = {i.name for i in pc.list_indexes()}
        if PINECONE_INDEX_NAME not in existing:
            pc.create_index(
                name=PINECONE_INDEX_NAME,
                dimension=384,
                metric="cosine",
                spec=ServerlessSpec(cloud="aws", region="us-east-1"),
            )
        return _PineconeAdapter(pc.Index(PINECONE_INDEX_NAME))
    except Exception as exc:
        log.warning("pinecone_init_failed_fallback_inmem", error=str(exc))
        return _GLOBAL_STORE


class _PineconeAdapter:
    def __init__(self, index: Any) -> None:
        self._idx = index

    def upsert(self, namespace: str, vectors: List[Tuple[str, List[float], Dict[str, Any]]]) -> None:
        items = [{"id": vid, "values": vec, "metadata": meta} for vid, vec, meta in vectors]
        self._idx.upsert(vectors=items, namespace=namespace)

    def query(self, namespace: str, vector: List[float], top_k: int = 5) -> List[Dict[str, Any]]:
        r = self._idx.query(vector=vector, top_k=top_k, namespace=namespace, include_metadata=True)
        return [
            {"id": m["id"], "score": m.get("score", 0.0), "metadata": m.get("metadata", {})}
            for m in r.get("matches", [])
        ]


def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


async def ingest_all(tenant_ids: Optional[List[str]] = None) -> Dict[str, int]:
    """Ingest ATT&CK + Sigma + tenant runbooks for the given tenants.

    Returns a mapping of namespace -> chunks ingested.
    """
    embedder = get_embedder()
    store = get_store()
    tenant_ids = tenant_ids or list_tenants()
    counts: Dict[str, int] = {}

    techniques = load_techniques()
    sigma_rules = load_rules()
    tech_chunks = [(f"attack:{t['technique_id']}", technique_to_chunk(t), {"kind": "attack", **t}) for t in techniques]
    sigma_chunks = [(f"sigma:{r['id']}", rule_to_chunk(r), {"kind": "sigma", **r}) for r in sigma_rules]

    tech_vectors = await embedder.aembed_documents([c[1] for c in tech_chunks])
    sigma_vectors = await embedder.aembed_documents([c[1] for c in sigma_chunks])

    for tenant_id in tenant_ids:
        tenant = load_tenant(tenant_id)

        attack_ns = f"{tenant_id}_attack"
        store.upsert(attack_ns, [(tech_chunks[i][0], tech_vectors[i], tech_chunks[i][2]) for i in range(len(tech_chunks))])
        counts[attack_ns] = len(tech_chunks)

        sigma_ns = f"{tenant_id}_sigma"
        store.upsert(sigma_ns, [(sigma_chunks[i][0], sigma_vectors[i], sigma_chunks[i][2]) for i in range(len(sigma_chunks))])
        counts[sigma_ns] = len(sigma_chunks)

        runbooks = load_runbooks_for_tenant(tenant_id, tenant["tenant_name"])
        rb_texts = [runbook_to_chunk(rb) for rb in runbooks]
        rb_vectors = await embedder.aembed_documents(rb_texts)
        rb_ns = f"{tenant_id}_runbooks"
        store.upsert(rb_ns, [(f"runbook:{tenant_id}:{i}", rb_vectors[i], {"kind": "runbook", **runbooks[i]}) for i in range(len(runbooks))])
        counts[rb_ns] = len(runbooks)

    log.info("kb_ingest_complete", counts=counts)
    return counts
