"""Reads .env, decides whether we're in mock mode, hands back the right LLM/embedder."""
from __future__ import annotations
import os
from functools import lru_cache
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


def _bool(v: Optional[str], default: bool = False) -> bool:
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _is_placeholder(v: Optional[str]) -> bool:
    if not v:
        return True
    s = v.strip().lower()
    return s.startswith("your_") or s in {"", "changeme", "none"}


MOCK_MODE: bool = _bool(os.getenv("MOCK_MODE"), True)
LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "anthropic").lower()
LLM_MODEL: str = os.getenv("LLM_MODEL", "claude-opus-4-5")
CONFIDENCE_THRESHOLD: float = float(os.getenv("CONFIDENCE_THRESHOLD", "0.75"))
MAX_REVISION_LOOPS: int = int(os.getenv("MAX_REVISION_LOOPS", "2"))
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
PINECONE_API_KEY: Optional[str] = os.getenv("PINECONE_API_KEY")
PINECONE_INDEX_NAME: str = os.getenv("PINECONE_INDEX_NAME", "aegisgraph")
IRIS_URL: str = os.getenv("IRIS_URL", "http://localhost:8000")
IRIS_API_KEY: Optional[str] = os.getenv("IRIS_API_KEY")


def llm_keys_present() -> bool:
    if LLM_PROVIDER == "anthropic":
        return not _is_placeholder(os.getenv("ANTHROPIC_API_KEY"))
    return not _is_placeholder(os.getenv("OPENAI_API_KEY"))


def pinecone_keys_present() -> bool:
    return not _is_placeholder(PINECONE_API_KEY)


def iris_keys_present() -> bool:
    return not _is_placeholder(IRIS_API_KEY)


@lru_cache(maxsize=1)
def get_llm():
    """Anthropic, OpenAI, or the mock — depending on MOCK_MODE and which keys are present."""
    if MOCK_MODE or not llm_keys_present():
        from agents.mock_llm import MockLLM
        return MockLLM()
    if LLM_PROVIDER == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model=LLM_MODEL, max_tokens=2048)
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(model=LLM_MODEL)


@lru_cache(maxsize=1)
def get_embedder():
    """Same idea as get_llm() but for embeddings."""
    if MOCK_MODE or not llm_keys_present():
        from agents.mock_llm import MockEmbedder
        return MockEmbedder()
    from langchain_openai import OpenAIEmbeddings
    return OpenAIEmbeddings(model="text-embedding-3-small")
