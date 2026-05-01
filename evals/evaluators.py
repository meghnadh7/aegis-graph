"""Custom evaluators. LangSmith-compatible signature: (run, example) -> dict."""
from __future__ import annotations
from typing import Any, Dict


def _outputs(run: Any) -> Dict[str, Any]:
    if isinstance(run, dict):
        return run.get("outputs", run)
    return getattr(run, "outputs", {}) or {}


def _example_outputs(example: Any) -> Dict[str, Any]:
    if isinstance(example, dict):
        return example.get("outputs", example)
    return getattr(example, "outputs", {}) or {}


def verdict_accuracy_evaluator(run: Any, example: Any) -> Dict[str, Any]:
    out = _outputs(run)
    exp = _example_outputs(example)
    predicted = out.get("verdict")
    expected = exp.get("ground_truth_label")
    return {"key": "verdict_accuracy", "score": 1.0 if predicted == expected else 0.0}


def attack_mapping_accuracy_evaluator(run: Any, example: Any) -> Dict[str, Any]:
    out = _outputs(run)
    exp = _example_outputs(example)
    techniques = out.get("attack_techniques", []) or []
    top1 = (techniques[0] or {}).get("technique_id") if techniques else None
    expected = exp.get("ground_truth_technique")
    if top1 and expected:
        if top1 == expected:
            score = 1.0
        elif top1.split(".")[0] == expected.split(".")[0]:
            score = 0.5
        else:
            score = 0.0
    else:
        score = 0.0
    return {"key": "attack_mapping_accuracy", "score": score}


def hallucination_evaluator(run: Any, example: Any) -> Dict[str, Any]:
    """Heuristic: penalize claims in summary that aren't grounded in IOCs/enrichment."""
    out = _outputs(run)
    summary = (out.get("analyst_summary") or "").lower()
    iocs = out.get("extracted_iocs", []) or []
    enrichment = out.get("enrichment_results", []) or []
    grounded_terms: set[str] = set()
    for ioc in iocs:
        v = (ioc.get("value") or "")[:60].lower()
        if v:
            grounded_terms.add(v)
    for e in enrichment:
        for k, v in (e.get("data") or {}).items():
            if isinstance(v, str) and len(v) < 60:
                grounded_terms.add(v.lower())
    suspicious = ["confirmed", "definitely", "certainly", "exfiltrated 100%"]
    risk = sum(1 for s in suspicious if s in summary) * 0.2
    score = max(0.0, 1.0 - risk)
    return {"key": "hallucination_resistance", "score": score}


def ioc_extraction_evaluator(run: Any, example: Any) -> Dict[str, Any]:
    out = _outputs(run)
    exp = _example_outputs(example)
    predicted = {(i.get("type"), i.get("value")) for i in out.get("extracted_iocs", []) or []}
    expected = {(i.get("type"), i.get("value")) for i in exp.get("ground_truth_iocs", []) or []}
    if not expected:
        return {"key": "ioc_f1", "score": 1.0 if not predicted else 0.5}
    tp = len(predicted & expected)
    precision = tp / len(predicted) if predicted else 0.0
    recall = tp / len(expected) if expected else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {"key": "ioc_f1", "score": f1, "precision": precision, "recall": recall}


def cost_efficiency_evaluator(run: Any, example: Any) -> Dict[str, Any]:
    out = _outputs(run)
    cost = float(out.get("total_cost_usd", 0.0))
    return {"key": "cost_per_alert_usd", "score": cost}


ALL_EVALUATORS = [
    verdict_accuracy_evaluator,
    attack_mapping_accuracy_evaluator,
    hallucination_evaluator,
    ioc_extraction_evaluator,
    cost_efficiency_evaluator,
]
