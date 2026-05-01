"""One-time knowledge base ingestion: ATT&CK + Sigma + tenant runbooks into the vector store."""
from __future__ import annotations
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from knowledge_base.ingest import ingest_all  # noqa: E402


def main() -> int:
    counts = asyncio.run(ingest_all())
    print("Ingested:")
    for ns, n in counts.items():
        print(f"  {ns}: {n} chunks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
