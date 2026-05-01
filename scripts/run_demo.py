"""End-to-end demo: run a single PowerShell encoded-command alert through the graph."""
from __future__ import annotations
import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.graph import run_alert  # noqa: E402
from ingestion.synthetic.generator import generate_alert  # noqa: E402
from knowledge_base.ingest import ingest_all  # noqa: E402


def _section(title: str) -> None:
    print()
    print("=" * 72)
    print(f" {title}")
    print("=" * 72)


async def main() -> int:
    _section("AegisGraph demo — multi-tenant SOC triage")
    await ingest_all()

    alert = generate_alert("t1059_001", tenant_id="tenant_a", label="true_positive", seed=42)
    print("\n[1] Alert received:")
    print(json.dumps(alert, indent=2, default=str)[:1200])

    t0 = time.time()
    case = await run_alert(alert, "tenant_a", alert_id=alert["id"])
    elapsed = time.time() - t0

    _section("[2] Triage outputs")
    print(f"  IOCs extracted: {len(case.get('extracted_iocs', []))}")
    for ioc in case.get("extracted_iocs", [])[:5]:
        print(f"    - {ioc['type']}: {ioc['value']}  (mal={ioc['malicious']}, conf={ioc['confidence']:.2f})")
    print(f"  Enrichment calls: {len(case.get('enrichment_results', []))}")

    _section("[3] ATT&CK mapping")
    for t in case.get("attack_techniques", [])[:3]:
        print(f"  - {t['technique_id']} {t['technique_name']} ({t['tactic']})  conf={t.get('confidence',0):.2f}")
    print(f"  kill chain: {case.get('kill_chain_stage')}")
    print(f"  sigma matches: {case.get('sigma_matches')}")

    _section("[4] Investigation")
    print(f"  asset_criticality={case.get('asset_criticality')}")
    print(f"  related_cases={case.get('related_cases')}")
    for evt in case.get("investigation_timeline", [])[:5]:
        print(f"    {evt['timestamp']}  {evt['event_type']}  {evt['description'][:80]}")

    _section("[5] Reflection")
    print(f"  confidence_score={case.get('confidence_score'):.3f}")
    print(f"  revisions={case.get('revision_count')}")
    if case.get("critic_feedback"):
        print(f"  feedback: {case['critic_feedback'][:300]}")

    _section("[6] Final verdict")
    print(f"  verdict: {case.get('verdict')}")
    print(f"  recommended_action: {case.get('recommended_action')}")
    print(f"  iris_case_id: {case.get('iris_case_id')}")
    print(f"  analyst_summary:\n    {case.get('analyst_summary')}")

    _section("[7] Run metadata")
    print(f"  total processing_time_ms: {case.get('processing_time_ms')}")
    print(f"  total cost (USD): {case.get('total_cost_usd'):.4f}")
    print(f"  wall time: {elapsed:.2f}s")
    if case.get("node_errors"):
        print(f"  node errors: {case['node_errors']}")
    if os.getenv("LANGCHAIN_TRACING_V2", "").lower() == "true":
        proj = os.getenv("LANGCHAIN_PROJECT", "aegisgraph")
        print(f"  LangSmith project: {proj}  (trace URL appears in your LangSmith dashboard)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
