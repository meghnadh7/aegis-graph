"""Run the graph over the golden dataset and aggregate the metrics.

Always writes `evals/last_results.json`. If a real LangSmith key is in the
env it'll also create/sync the dataset there, but that's optional.
"""
from __future__ import annotations
import asyncio
import json
import os
import statistics
import time
from pathlib import Path
from typing import Any, Dict, List

import structlog

from agents.graph import run_alert
from .evaluators import ALL_EVALUATORS
from .golden_dataset import load_golden

log = structlog.get_logger(__name__)

RESULTS_PATH = Path(__file__).parent / "last_results.json"


async def _run_one(example: Dict[str, Any]) -> Dict[str, Any]:
    final = await run_alert(example["raw_alert"], example["tenant_id"], alert_id=example["alert_id"])
    return final


def _summarize(scores: Dict[str, List[float]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, vals in scores.items():
        if not vals:
            continue
        out[k] = {
            "mean": round(statistics.fmean(vals), 4),
            "median": round(statistics.median(vals), 4),
            "n": len(vals),
        }
    return out


async def run_full_evaluation(limit: int | None = None, concurrency: int = 8) -> Dict[str, Any]:
    examples = load_golden()
    if limit:
        examples = examples[:limit]
    log.info("eval_start", n=len(examples), concurrency=concurrency)

    sem = asyncio.Semaphore(concurrency)

    async def _bound(ex: Dict[str, Any]) -> Dict[str, Any]:
        async with sem:
            return await _run_one(ex)

    t0 = time.time()
    results = await asyncio.gather(*[_bound(ex) for ex in examples], return_exceptions=True)
    elapsed = time.time() - t0

    scores: Dict[str, List[float]] = {}
    rows: List[Dict[str, Any]] = []
    for ex, res in zip(examples, results):
        if isinstance(res, Exception):
            rows.append({"alert_id": ex["alert_id"], "error": str(res)})
            continue
        run_obj = {"outputs": res}
        example_obj = {"outputs": ex}
        per_eval: Dict[str, Any] = {}
        for evaluator in ALL_EVALUATORS:
            r = evaluator(run_obj, example_obj)
            per_eval[r["key"]] = r["score"]
            scores.setdefault(r["key"], []).append(float(r["score"]))
        rows.append(
            {
                "alert_id": ex["alert_id"],
                "tenant_id": ex["tenant_id"],
                "expected": ex["ground_truth_label"],
                "predicted": res.get("verdict"),
                "evals": per_eval,
            }
        )

    summary = _summarize(scores)
    summary["wall_time_seconds"] = round(elapsed, 2)
    summary["alerts"] = len(examples)
    print_summary(summary)

    RESULTS_PATH.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2, default=str))

    if os.getenv("LANGCHAIN_API_KEY") and not os.getenv("LANGCHAIN_API_KEY", "").startswith("your_"):
        try:
            from langsmith import Client  # type: ignore
            client = Client()
            ds_name = "aegisgraph-golden-v1"
            try:
                client.create_dataset(ds_name, description="AegisGraph 200-alert synthetic golden set")
            except Exception:
                pass
            for ex in examples:
                try:
                    client.create_example(
                        inputs={"raw_alert": ex["raw_alert"], "tenant_id": ex["tenant_id"]},
                        outputs={
                            "ground_truth_label": ex["ground_truth_label"],
                            "ground_truth_technique": ex["ground_truth_technique"],
                            "ground_truth_iocs": ex["ground_truth_iocs"],
                        },
                        dataset_name=ds_name,
                    )
                except Exception:
                    pass
            log.info("langsmith_dataset_synced", n=len(examples))
        except Exception as exc:
            log.warning("langsmith_sync_failed", error=str(exc))

    return summary


def print_summary(summary: Dict[str, Any]) -> None:
    print("\n=== AegisGraph Eval Summary ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print("=" * 36)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="Run on first N examples (default: all)")
    parser.add_argument("--concurrency", type=int, default=8)
    args = parser.parse_args()
    asyncio.run(run_full_evaluation(limit=args.limit, concurrency=args.concurrency))


if __name__ == "__main__":
    main()
