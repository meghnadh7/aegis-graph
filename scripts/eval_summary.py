"""Pretty-print the golden dataset stats + the most recent eval run.

Two things in one place: what's in the eval set, and how the agent did the
last time `make eval` was run. The output is meant to be screen-recorded
during the demo video.
"""
from __future__ import annotations
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console  # noqa: E402
from rich.panel import Panel  # noqa: E402
from rich.rule import Rule  # noqa: E402
from rich.table import Table  # noqa: E402

from evals.golden_dataset import load_golden, GOLDEN_PATH  # noqa: E402

console = Console()
RESULTS_PATH = Path(__file__).resolve().parent.parent / "evals" / "last_results.json"


def _technique_label_from_id(tid: str) -> str:
    return {
        "T1059.001": "PowerShell Execution",
        "T1003": "OS Credential Dumping",
        "T1003.001": "LSASS Memory",
        "T1003.002": "Security Account Manager",
        "T1566": "Phishing",
        "T1566.001": "Spearphishing Attachment",
        "T1566.002": "Spearphishing Link",
        "T1071": "Application Layer Protocol",
        "T1071.001": "Web Protocols",
        "T1078": "Valid Accounts",
    }.get(tid, tid)


def main() -> int:
    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]aegis-graph[/]  ·  evaluation summary\n"
            "[dim]Golden dataset breakdown + last `make eval` run.[/]",
            border_style="cyan",
        )
    )

    # ---- Golden dataset ------------------------------------------------
    examples = load_golden()
    console.print()
    console.print(Rule(f"[bold]Golden dataset[/]  ·  {len(examples)} alerts  ·  {GOLDEN_PATH.name}", style="cyan"))

    by_technique: Counter[str] = Counter()
    by_label: Counter[str] = Counter()
    by_tenant: Counter[str] = Counter()
    by_tech_label: dict[str, Counter[str]] = {}

    for ex in examples:
        tid = ex["ground_truth_technique"] or "unknown"
        lbl = ex["ground_truth_label"] or "unknown"
        tenant = ex["tenant_id"] or "unknown"
        by_technique[tid] += 1
        by_label[lbl] += 1
        by_tenant[tenant] += 1
        by_tech_label.setdefault(tid, Counter())[lbl] += 1

    tt = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
    tt.add_column("ATT&CK", style="cyan")
    tt.add_column("name")
    tt.add_column("total", justify="right")
    tt.add_column("TP", justify="right", style="red")
    tt.add_column("FP", justify="right", style="green")
    tt.add_column("Escalate", justify="right", style="yellow")
    for tid, total in sorted(by_technique.items()):
        labels = by_tech_label.get(tid, Counter())
        tt.add_row(
            tid,
            _technique_label_from_id(tid),
            str(total),
            str(labels.get("true_positive", 0)),
            str(labels.get("false_positive", 0)),
            str(labels.get("escalate", 0)),
        )
    console.print(tt)

    tenant_table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
    tenant_table.add_column("tenant", style="cyan")
    tenant_table.add_column("count", justify="right")
    for tenant, count in sorted(by_tenant.items()):
        tenant_table.add_row(tenant, str(count))
    console.print(Rule("[bold]Per-tenant split[/]", style="dim"))
    console.print(tenant_table)

    label_table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
    label_table.add_column("label", style="cyan")
    label_table.add_column("count", justify="right")
    label_table.add_column("share", justify="right")
    total = sum(by_label.values()) or 1
    for label, count in sorted(by_label.items(), key=lambda kv: -kv[1]):
        label_table.add_row(label, str(count), f"{count*100/total:.1f}%")
    console.print(Rule("[bold]Label distribution[/]", style="dim"))
    console.print(label_table)

    # ---- Sample alerts -------------------------------------------------
    console.print()
    console.print(Rule("[bold]Sample alerts (one per technique)[/]", style="dim"))
    samples_seen: set[str] = set()
    for ex in examples:
        tid = ex["ground_truth_technique"]
        if tid in samples_seen:
            continue
        samples_seen.add(tid)
        a = ex["raw_alert"]
        rule = a["rule"]
        evd = a.get("data", {}).get("win", {}).get("eventdata", {})
        cmd = (evd.get("commandLine") or "")[:100]
        console.print(
            f"  [cyan]{tid:10s}[/] [dim]{rule['description'][:60]:60s}[/] "
            f"[bold]{ex['ground_truth_label']:14s}[/] {cmd}"
        )
        if len(samples_seen) >= 6:
            break

    # ---- Last eval run -------------------------------------------------
    console.print()
    console.print(Rule("[bold]Last eval run[/]  ·  evals/last_results.json", style="cyan"))
    if not RESULTS_PATH.exists():
        console.print("[yellow]No prior eval run found. Run `make eval` to populate.[/]")
        return 0
    payload = json.loads(RESULTS_PATH.read_text())
    summary = payload.get("summary", {})
    rows = payload.get("rows", [])

    metrics = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
    metrics.add_column("metric", style="cyan")
    metrics.add_column("mean", justify="right")
    metrics.add_column("median", justify="right")
    metrics.add_column("n", justify="right")
    for k, v in summary.items():
        if isinstance(v, dict):
            metrics.add_row(k, f"{v.get('mean'):.4f}" if isinstance(v.get('mean'), (int, float)) else str(v.get('mean')),
                            f"{v.get('median'):.4f}" if isinstance(v.get('median'), (int, float)) else str(v.get('median')),
                            str(v.get('n')))
    console.print(metrics)

    extras = {k: v for k, v in summary.items() if not isinstance(v, dict)}
    if extras:
        et = Table(show_header=False, box=None, padding=(0, 1))
        et.add_column(style="bold")
        et.add_column()
        for k, v in extras.items():
            et.add_row(k, str(v))
        console.print(Rule("[bold]Run info[/]", style="dim"))
        console.print(et)

    # Per-label outcome on the last run
    if rows:
        agree = sum(1 for r in rows if r.get("predicted") == r.get("expected"))
        disagree = [r for r in rows if r.get("predicted") and r.get("predicted") != r.get("expected")]
        console.print()
        console.print(
            f"  agreement with ground truth: [bold]{agree}[/] / {len(rows)}  "
            f"([bold]{agree*100/len(rows):.1f}%[/])"
        )
        if disagree[:5]:
            console.print("  [dim]first few disagreements:[/]")
            for r in disagree[:5]:
                console.print(
                    f"    [dim]{r.get('alert_id','?')}[/] tenant={r.get('tenant_id','?')} "
                    f"expected=[bold]{r.get('expected')}[/] predicted=[red]{r.get('predicted')}[/]"
                )
    console.print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
