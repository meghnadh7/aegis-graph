"""End-to-end smoke test for the LangGraph pipeline."""
import pytest

from agents.graph import run_alert
from ingestion.synthetic.generator import generate_alert
from knowledge_base.ingest import ingest_all


@pytest.mark.asyncio
async def test_pipeline_end_to_end_powershell_tp():
    await ingest_all(["tenant_a"])
    alert = generate_alert("t1059_001", tenant_id="tenant_a", label="true_positive", seed=7)
    case = await run_alert(alert, "tenant_a", alert_id=alert["id"])
    assert case.get("verdict") in {"true_positive", "false_positive", "escalate"}
    assert case.get("iris_case_id")
    assert case.get("attack_techniques")
    assert isinstance(case.get("extracted_iocs"), list)


@pytest.mark.asyncio
async def test_pipeline_handles_phishing():
    await ingest_all(["tenant_b"])
    alert = generate_alert("t1566", tenant_id="tenant_b", label="escalate", seed=9)
    case = await run_alert(alert, "tenant_b", alert_id=alert["id"])
    assert case.get("verdict") in {"true_positive", "false_positive", "escalate"}
