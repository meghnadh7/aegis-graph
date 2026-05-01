"""Validate that required packages and env vars are present (or that mock mode is on)."""
from __future__ import annotations
import importlib
import os
import sys
from typing import List, Tuple

REQUIRED_PACKAGES = ["fastapi", "httpx", "pydantic", "structlog", "tenacity", "dotenv"]
OPTIONAL_PACKAGES = [
    ("langgraph", "graph orchestration"),
    ("langchain", "LLM wrappers"),
    ("langchain_anthropic", "Anthropic LLM"),
    ("pinecone", "vector store"),
    ("redis", "stream/cache"),
    ("langsmith", "observability"),
]


def check_package(name: str) -> Tuple[bool, str]:
    try:
        importlib.import_module(name)
        return True, f"  [ok] {name}"
    except Exception as exc:
        return False, f"  [missing] {name}: {exc}"


def main() -> int:
    print("AegisGraph dependency check")
    failed: List[str] = []
    for pkg in REQUIRED_PACKAGES:
        ok, msg = check_package(pkg)
        print(msg)
        if not ok:
            failed.append(pkg)

    print("\nOptional packages:")
    for pkg, desc in OPTIONAL_PACKAGES:
        ok, msg = check_package(pkg)
        print(f"{msg}  ({desc})")

    print("\nEnvironment:")
    mock = os.getenv("MOCK_MODE", "true").strip().lower() in {"1", "true", "yes", "on"}
    print(f"  MOCK_MODE={mock}")
    if not mock:
        for var in ["ANTHROPIC_API_KEY", "PINECONE_API_KEY", "VIRUSTOTAL_API_KEY"]:
            v = os.getenv(var, "")
            if not v or v.startswith("your_"):
                print(f"  [warn] {var} not set — falling back to mock for that integration")

    if failed:
        print(f"\nMissing required packages: {', '.join(failed)}")
        return 1
    print("\nAll required dependencies are installed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
