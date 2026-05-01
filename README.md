# aegis-graph

A small project I put together while interviewing for an Applied AI Engineer role at an MSSP. The idea was to mock up what a Tier-1 SOC triage copilot looks like end-to-end: alert in, IOC enrichment, MITRE ATT&CK mapping, an investigation timeline, a self-critic that can force a revision, and a finished case in DFIR-IRIS.

It runs entirely offline by default (every external API has a deterministic mock), so you can clone and `make demo` without keys.

## What it actually does

A Wazuh-shaped alert hits the FastAPI webhook, gets pushed onto a Redis stream and into a LangGraph state machine with five nodes:

1. **triage** — pulls IOCs out of the alert, fans out to 5 threat-intel sources in parallel (VirusTotal, Shodan, AbuseIPDB, URLhaus, GreyNoise), each wrapped as an MCP-style server. Everything goes through a regex/heuristic injection guard before it touches the LLM.
2. **attack_mapper** — uses HyDE: instead of embedding the (terse) raw alert, the LLM writes a hypothetical detection narrative and *that* gets embedded against per-tenant Pinecone namespaces for ATT&CK + Sigma. The LLM picks the best match from the retrieved candidates only, so it can't invent technique IDs.
3. **investigator** — pivots on host/IP/user against recent event history, looks up asset criticality from the tenant inventory, builds a timeline.
4. **reflector** — LLM-as-judge scoring the case so far on four axes (evidence quality, reasoning coherence, hallucination risk, investigation depth). If the composite drops below `CONFIDENCE_THRESHOLD` and we haven't already revised twice, it loops back to triage.
5. **reporter** — writes the verdict, summary and recommended action into DFIR-IRIS (case, IOCs, asset, timeline, ATT&CK attribute, note).

Two synthetic tenants ship with it (`tenant_a` = a fintech, `tenant_b` = a healthcare provider). Each has its own Pinecone namespaces, its own runbook corpus, and its own system-prompt context, so the same alert pattern gets weighed against different critical-asset lists.

## Running it

```bash
git clone https://github.com/meghnadh7/aegis-graph.git
cd aegis-graph
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # MOCK_MODE=true is the default
make demo                     # one alert through the full pipeline
make test                     # pytest
make eval                     # 200-alert golden run + metrics
```

To run with real APIs: drop your keys into `.env`, set `MOCK_MODE=false`. Every external integration (LLM, Pinecone, the 5 TI feeds, DFIR-IRIS) is gated on the same flag — anything missing a key falls back to mock automatically.

## Results

Tests:

```
$ pytest tests/ -q
................                                                         [100%]
16 passed in 1.56s
```

Evaluation against the bundled 200-alert golden set (40 per technique × 5 techniques, evenly split across both tenants, ~40/35/25 TP/FP/escalate):

```
$ python -m evals.run_evals --concurrency 16
=== AegisGraph Eval Summary ===
  verdict_accuracy:           {'mean': 1.0,   'median': 1.0,    'n': 200}
  attack_mapping_accuracy:    {'mean': 0.50,  'median': 0.5,    'n': 200}
  hallucination_resistance:   {'mean': 1.0,   'median': 1.0,    'n': 200}
  ioc_f1:                     {'mean': 0.80,  'median': 0.80,   'n': 200}
  cost_per_alert_usd:         {'mean': 0.014, 'median': 0.01,   'n': 200}
  wall_time_seconds:          4.68
  alerts:                     200
```

A few honest notes on those numbers:

- 1.0 verdict accuracy is on the synthetic dataset with the mock LLM. It tells you the wiring works and the rubric is consistent with itself; it does not tell you what a real Claude/GPT call would do on real noisy data.
- `attack_mapping_accuracy` plateaus at 0.5 because the mock LLM keeps hitting the parent-vs-subtechnique partial-credit case (e.g. predicts `T1003.001` when ground truth is `T1003`). With a real model this should close most of that gap.
- `ioc_f1` of 0.80 is after fixing a bug where the mock LLM was scanning the entire prompt (including the enrichment payload) for IOCs and reporting URLs from the enrichment links as if they were alert IOCs. The mock now scopes its extraction to the alert section.
- `hallucination_resistance` is a heuristic check that summaries don't contain unhedged absolutes like "definitely" or "confirmed exfiltration". Not a substitute for a real grounding eval.
- $0.014/alert is simulated from token counts the mock LLM returns. Real cost depends on the model.

`evals/last_results.json` has the per-alert breakdown.

## Architecture

```
   Wazuh / synthetic alert
            │
            ▼
   FastAPI /webhook ──► Redis stream ──► LangGraph
                                            │
                          ┌─────────────────┘
                          ▼
                       triage  (IOC extract + 5 MCP fan-out)
                          │
                          ▼
                    attack_mapper  (HyDE → Pinecone)
                          │
                          ▼
                    investigator  (timeline, criticality)
                          │
                          ▼
                      reflector  (LLM-as-judge)
                          │
              conf<0.75? ─┴─► (revise, max 2 loops) ─► back to triage
                          │
                          ▼
                      reporter  ──► DFIR-IRIS
```

## Stack

- LangGraph for the supervisor graph — explicit state, conditional edges, native HITL hooks via `interrupt_after`.
- Pinecone + HyDE retrieval for ATT&CK / Sigma / runbook lookup. Per-tenant namespaces are the isolation boundary.
- 5 MCP-style Python servers for threat intel, each with retries, TTL caches, and a deterministic mock.
- DFIR-IRIS REST as the case backend.
- Wazuh-shaped synthetic alerts (no live SIEM needed).
- LangSmith for tracing if you give it a key.
- A small custom prompt-injection guard on every tool output before it reaches LLM context.

## Repo layout

```
agents/           LangGraph nodes, prompts, schemas, state
mcp_servers/      VT / Shodan / AbuseIPDB / URLhaus / GreyNoise
knowledge_base/   MITRE loader, Sigma rules, tenant runbooks, HyDE retriever
guardrails/       PromptInjectionGuard
case_management/  DFIR-IRIS REST client
ingestion/        FastAPI webhook + Redis stream + synthetic generator
evals/            golden dataset, evaluators, runner
tenants/          per-tenant config (FinTech, Healthcare)
scripts/          check_deps, setup_kb, generate_alerts, run_demo
tests/            pytest
docker-compose.yml   Redis + Postgres + DFIR-IRIS + the API
kubernetes/       manifests
```

## Things I'd do next

- Swap the synthetic Wazuh source for a Stellar Cyber XDR adapter (closer to what MSSPs actually ingest).
- Per-tenant fine-tuning once there are real analyst decisions to learn from.
- Wire `interrupt_after` into a tiny review UI so analysts can approve/reject before the IRIS write happens.
- A LangSmith CI gate that fails PRs whose verdict accuracy regresses past a threshold.

## Threat model

Notes on prompt injection via alert fields, RAG poisoning, tool-misuse via crafted alerts, and DoS in `THREAT_MODEL.md`. Each item is mapped to a MITRE ATLAS technique where one applies.

## License

MIT.
