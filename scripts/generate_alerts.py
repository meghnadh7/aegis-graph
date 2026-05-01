"""Generate (or regenerate) the 200-alert golden dataset."""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evals.golden_dataset import build_golden, save_golden, GOLDEN_PATH  # noqa: E402


def main() -> int:
    examples = build_golden(per_technique=40)
    save_golden(examples)
    print(f"Wrote {len(examples)} examples to {GOLDEN_PATH}")
    counts: dict[str, int] = {}
    for ex in examples:
        counts[ex["ground_truth_label"]] = counts.get(ex["ground_truth_label"], 0) + 1
    print("Label distribution:")
    for k, v in counts.items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
