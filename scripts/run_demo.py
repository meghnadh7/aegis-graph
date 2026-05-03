"""Single-alert end-to-end demo, formatted for screen recording.

Runs one PowerShell encoded-command alert (T1059.001, true positive label)
against tenant_a and prints what each LangGraph node did, in order, with a
final verdict + DFIR-IRIS case id.

The output is designed to be read off a terminal in a Loom video: rich
panels per node, a compact IOC table, and the analyst summary at the end.
"""
from __future__ import annotations
import asyncio
import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Quiet structlog/INFO chatter during the demo — we want clean panels, not log noise.
logging.basicConfig(level=logging.WARNING)
import structlog  # noqa: E402

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
)

from rich.console import Console  # noqa: E402
from rich.panel import Panel  # noqa: E402
from rich.rule import Rule  # noqa: E402
from rich.table import Table  # noqa: E402
from rich.text import Text  # noqa: E402

from agents.graph import run_alert  # noqa: E402
from ingestion.synthetic.generator import generate_alert  # noqa: E402
from knowledge_base.ingest import ingest_all  # noqa: E402

console = Console()


def _verdict_color(v: str | None) -> str:
    return {
        "true_positive": "bold red",
        "false_positive": "bold green",
        "escalate": "bold yellow",
    }.get(v or "", "white")


async def main() -> int:
    console.print()
    console.print(
        Panel.fit(
            Text.from_markup(
                "[bold cyan]aegis-graph[/]  ·  multi-tenant SOC triage demo\n"
                "[dim]One synthetic PowerShell alert through the full LangGraph pipeline.\n"
                "Tenant: [bold]tenant_a (FinTech Corp)[/]  ·  Mode: [bold]MOCK[/][/]"
            ),
            border_style="cyan",
        )
    )

    with console.status("[cyan]Loading MITRE ATT&CK + Sigma + tenant runbooks into the vector store...", spinner="dots"):
        counts = await ingest_all(["tenant_a"])
    console.print(
        f"[green]✓[/] Knowledge base ready — "
        f"[bold]{counts.get('tenant_a_attack',0)}[/] ATT&CK chunks, "
        f"[bold]{counts.get('tenant_a_sigma',0)}[/] Sigma rules, "
        f"[bold]{counts.get('tenant_a_runbooks',0)}[/] runbooks."
    )

    alert = generate_alert("t1059_001", tenant_id="tenant_a", label="true_positive", seed=42)
    rule = alert["rule"]
    agent = alert["agent"]
    eventdata = alert["data"]["win"]["eventdata"]

    console.print()
    console.print(Rule("[bold]1. Alert received[/]", style="cyan"))
    alert_table = Table(show_header=False, box=None, padding=(0, 1))
    alert_table.add_column(style="bold cyan")
    alert_table.add_column()
    alert_table.add_row("alert id", alert["id"])
    alert_table.add_row("rule", f"{rule['id']}  ·  level {rule['level']}  ·  {rule['description']}")
    alert_table.add_row("ATT&CK tag", ", ".join(rule["mitre"]["id"]))
    alert_table.add_row("host / ip", f"{agent['name']}  ·  {agent['ip']}")
    alert_table.add_row("user", eventdata.get("user", ""))
    alert_table.add_row("image", eventdata.get("image", ""))
    cmd = eventdata.get("commandLine", "")
    alert_table.add_row("command line", cmd[:120] + ("…" if len(cmd) > 120 else ""))
    console.print(alert_table)

    t0 = time.time()
    with console.status("[cyan]Running graph: triage → attack_mapper → investigator → reflector → reporter...", spinner="dots"):
        case = await run_alert(alert, "tenant_a", alert_id=alert["id"])
    elapsed = time.time() - t0

    # ------------------------------------------------------------------
    # 2. Triage
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule("[bold]2. Triage  ·  IOC extraction + 5-way TI fan-out[/]", style="cyan"))
    iocs = case.get("extracted_iocs", []) or []
    enrichments = case.get("enrichment_results", []) or []
    console.print(
        f"  [bold]{len(iocs)}[/] IOCs extracted  ·  "
        f"[bold]{len(enrichments)}[/] enrichment calls  ·  "
        f"dedup status: [bold]{case.get('dedup_status')}[/]"
    )
    if iocs:
        ioc_table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
        ioc_table.add_column("type", style="cyan")
        ioc_table.add_column("value", overflow="fold", max_width=64)
        ioc_table.add_column("malicious", justify="center")
        ioc_table.add_column("confidence", justify="right")
        for ioc in iocs[:8]:
            mal = "[red]✗[/]" if ioc["malicious"] else "[green]·[/]"
            ioc_table.add_row(ioc["type"], ioc["value"], mal, f"{ioc['confidence']:.2f}")
        console.print(ioc_table)

    tools_hit = sorted({e.get("tool") for e in enrichments})
    console.print(f"  [dim]TI sources hit: {', '.join(t for t in tools_hit if t)}[/]")

    # ------------------------------------------------------------------
    # 3. ATT&CK mapping
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule("[bold]3. ATT&CK mapping  ·  HyDE → Pinecone[/]", style="cyan"))
    techs = case.get("attack_techniques", []) or []
    if techs:
        tt = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
        tt.add_column("technique", style="cyan")
        tt.add_column("name")
        tt.add_column("tactic")
        tt.add_column("confidence", justify="right")
        for t in techs[:3]:
            tt.add_row(
                t["technique_id"],
                t["technique_name"],
                t["tactic"],
                f"{t.get('confidence', 0):.2f}",
            )
        console.print(tt)
    console.print(f"  kill chain stage: [bold]{case.get('kill_chain_stage')}[/]")
    console.print(f"  matching Sigma rules: [dim]{', '.join(case.get('sigma_matches', []) or []) or 'none'}[/]")

    # ------------------------------------------------------------------
    # 4. Investigator
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule("[bold]4. Investigator  ·  pivots + timeline[/]", style="cyan"))
    crit = case.get("asset_criticality", "low")
    crit_color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(crit, "white")
    console.print(f"  asset criticality: [{crit_color}]{crit}[/]")
    related = case.get("related_cases", []) or []
    console.print(f"  related prior cases: [dim]{', '.join(related) if related else 'none'}[/]")
    for evt in (case.get("investigation_timeline") or [])[:5]:
        console.print(f"    [dim]{evt['timestamp']}[/]  [cyan]{evt['event_type']:12s}[/]  {evt['description'][:80]}")

    # ------------------------------------------------------------------
    # 5. Reflector
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule("[bold]5. Reflector  ·  LLM-as-judge[/]", style="cyan"))
    conf = case.get("confidence_score", 0.0)
    revisions = case.get("revision_count", 0)
    bar_len = 30
    filled = int(round(conf * bar_len))
    bar_color = "green" if conf >= 0.75 else ("yellow" if conf >= 0.5 else "red")
    bar = f"[{bar_color}]{'█' * filled}[/][dim]{'·' * (bar_len - filled)}[/]"
    console.print(f"  confidence: {bar}  [bold]{conf:.3f}[/]")
    console.print(f"  revisions:  [bold]{revisions}[/] / 2 max")
    if case.get("critic_feedback"):
        console.print(Panel(case["critic_feedback"][:400], title="critic feedback", border_style="dim"))

    # ------------------------------------------------------------------
    # 6. Reporter
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule("[bold]6. Reporter  ·  verdict + DFIR-IRIS write[/]", style="cyan"))
    verdict = case.get("verdict") or "unknown"
    console.print(f"  verdict:            [{_verdict_color(verdict)}]{verdict.upper()}[/]")
    console.print(f"  recommended action: {case.get('recommended_action')}")
    console.print(f"  iris case id:       [bold]{case.get('iris_case_id')}[/]")
    if case.get("analyst_summary"):
        console.print(Panel(case["analyst_summary"], title="analyst summary", border_style="cyan"))

    # ------------------------------------------------------------------
    # Run metadata
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule("[bold]Run metadata[/]", style="dim"))
    meta = Table(show_header=False, box=None, padding=(0, 1))
    meta.add_column(style="bold")
    meta.add_column()
    meta.add_row("processing_time_ms", str(case.get("processing_time_ms")))
    meta.add_row("wall time", f"{elapsed:.2f}s")
    meta.add_row("cost (USD, simulated)", f"${case.get('total_cost_usd', 0):.4f}")
    meta.add_row("node errors", str(case.get("node_errors") or "none"))
    if os.getenv("LANGCHAIN_TRACING_V2", "").lower() == "true":
        meta.add_row("langsmith project", os.getenv("LANGCHAIN_PROJECT", "aegisgraph"))
    console.print(meta)
    console.print()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
