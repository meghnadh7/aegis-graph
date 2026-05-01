"""Build the 200-alert labeled golden dataset and persist as JSON."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

from ingestion.synthetic.generator import generate_dataset

GOLDEN_PATH = Path(__file__).parent / "golden_dataset.json"


def _expected_iocs(alert: Dict[str, Any]) -> List[Dict[str, str]]:
    """Pull just the obvious IOCs for the ground-truth set."""
    iocs: List[Dict[str, str]] = []
    eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {})
    if eventdata.get("targetUrl"):
        iocs.append({"type": "url", "value": eventdata["targetUrl"]})
    if eventdata.get("targetDomain"):
        iocs.append({"type": "domain", "value": eventdata["targetDomain"]})
    if alert.get("agent", {}).get("ip"):
        iocs.append({"type": "ip", "value": alert["agent"]["ip"]})
    if eventdata.get("hashes", "").startswith("SHA256="):
        iocs.append({"type": "sha256", "value": eventdata["hashes"].split("=", 1)[1]})
    return iocs


def build_golden(per_technique: int = 40) -> List[Dict[str, Any]]:
    raw_alerts = generate_dataset(per_technique=per_technique)
    examples = []
    for a in raw_alerts:
        synth = a.get("_synthetic", {})
        examples.append(
            {
                "alert_id": a["id"],
                "tenant_id": synth.get("tenant_id"),
                "raw_alert": a,
                "ground_truth_label": synth.get("label"),
                "ground_truth_technique": synth.get("technique_id"),
                "ground_truth_iocs": _expected_iocs(a),
            }
        )
    return examples


def save_golden(examples: List[Dict[str, Any]], path: Path = GOLDEN_PATH) -> None:
    path.write_text(json.dumps(examples, indent=2, default=str))


def load_golden(path: Path = GOLDEN_PATH) -> List[Dict[str, Any]]:
    if not path.exists():
        examples = build_golden()
        save_golden(examples, path)
        return examples
    return json.loads(path.read_text())
