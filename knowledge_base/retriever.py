"""HyDE retriever.

The trick: instead of embedding the (terse) alert directly, we ask the LLM
to write the kind of paragraph an analyst would write about that alert, then
embed *that*. ATT&CK descriptions are written in similar prose, so cosine
similarity actually has something to bite on.
"""
from __future__ import annotations
from typing import Any, Dict, List

import structlog

from agents.config import get_embedder, get_llm

log = structlog.get_logger(__name__)


HYDE_PROMPT = (
    "A security analyst is investigating this alert: {alert_summary}. "
    "Write a 2-3 sentence technical description of the MITRE ATT&CK technique "
    "category this alert most likely belongs to, including typical indicators "
    "and log sources that would be present. (HyDE: hypothetical detection narrative)"
)


class HyDERetriever:
    def __init__(self, store: Any, namespace_prefix: str) -> None:
        self.store = store
        self.namespace_prefix = namespace_prefix
        self.llm = get_llm()
        self.embedder = get_embedder()

    async def _hyde_text(self, alert_summary: str) -> str:
        prompt = HYDE_PROMPT.format(alert_summary=alert_summary[:1500])
        try:
            resp = await self.llm.ainvoke(prompt)
            text = getattr(resp, "content", str(resp))
            return text or alert_summary
        except Exception as exc:
            log.warning("hyde_llm_failed", error=str(exc))
            return alert_summary

    async def retrieve_attack_techniques(self, alert_summary: str, top_k: int = 5) -> List[Dict[str, Any]]:
        hyp = await self._hyde_text(alert_summary)
        vec = await self.embedder.aembed_query(hyp)
        ns = f"{self.namespace_prefix}_attack"
        results = self.store.query(ns, vec, top_k=top_k)
        log.info("attack_retrieval", namespace=ns, hits=len(results))
        return results

    async def retrieve_sigma_rules(self, alert_summary: str, top_k: int = 3) -> List[Dict[str, Any]]:
        hyp = await self._hyde_text(alert_summary)
        vec = await self.embedder.aembed_query(hyp)
        ns = f"{self.namespace_prefix}_sigma"
        results = self.store.query(ns, vec, top_k=top_k)
        log.info("sigma_retrieval", namespace=ns, hits=len(results))
        return results

    async def retrieve_runbooks(self, alert_summary: str, top_k: int = 2) -> List[Dict[str, Any]]:
        vec = await self.embedder.aembed_query(alert_summary)
        ns = f"{self.namespace_prefix}_runbooks"
        return self.store.query(ns, vec, top_k=top_k)
