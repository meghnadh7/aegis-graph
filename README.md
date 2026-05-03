# aegis-graph

A small project I put together to build out what a Tier-1 SOC triage copilot looks like end to end — alert in, IOC enrichment, MITRE ATT&CK mapping, an investigation timeline, a self-critic that can force a revision, and a finished case in DFIR-IRIS.

It runs offline by default. `make demo` works on a fresh clone with no API keys; just `pip install`, copy the env file, and go.

## What it actually does

A Wazuh-shaped alert hits the FastAPI webhook, lands on a Redis stream, then into a LangGraph state machine with five nodes:

1. **triage** — pulls IOCs out of the alert and fans them out to 5 threat-intel sources in parallel (VirusTotal, Shodan, AbuseIPDB, URLhaus, GreyNoise), each wrapped as an MCP-style server. Everything is sanitized through a small regex-based injection guard before it ever touches the LLM.
2. **attack_mapper** — uses HyDE. Instead of embedding the (terse) raw alert, the LLM writes a hypothetical detection narrative and that gets embedded against per-tenant Pinecone namespaces for ATT&CK + Sigma. The LLM only picks from retrieved candidates, so it can't invent technique IDs.
3. **investigator** — pivots on host / IP / user against recent event history, looks up asset criticality from the tenant inventory, builds a timeline.
4. **reflector** — LLM-as-judge scoring the case so far on four axes (evidence quality, reasoning coherence, hallucination risk, investigation depth). If the composite drops below `CONFIDENCE_THRESHOLD` and we haven't already revised twice, the graph loops back to triage.
5. **reporter** — writes the verdict, summary, and recommended action into DFIR-IRIS (case, IOCs, asset, timeline, ATT&CK attribute, note).

Two synthetic tenants ship in the box (`tenant_a` is a fintech, `tenant_b` is a healthcare provider). Each gets its own Pinecone namespaces, runbook corpus, and system-prompt context, so the same alert pattern is weighed against different critical-asset lists.

## Running it

```bash
git clone https://github.com/meghnadh7/aegis-graph.git
cd aegis-graph
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
make demo                     # one alert through the full pipeline
make test                     # pytest
make eval                     # 200-alert golden run + metrics
make eval-summary             # pretty-print dataset stats + last eval run
```

To run with real APIs: drop your keys into `.env` and set `MOCK_MODE=false`. Each external integration (LLM, Pinecone, the 5 TI feeds, DFIR-IRIS) is gated independently — anything missing a key falls back automatically, so you can mix and match (e.g. real Claude + real LangSmith but fake threat intel).

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

## Results

```
$ pytest tests/ -q
................                                                         [100%]
16 passed in 1.56s
```

Eval against the bundled 200-alert golden set (40 per technique × 5 techniques, evenly split across both tenants, 16 / 14 / 10 TP / FP / Escalate per technique):

```
$ python -m evals.run_evals --concurrency 16
=== AegisGraph Eval Summary ===
  verdict_accuracy:           {'mean': 0.93, 'median': 1.0, 'n': 200}
  attack_mapping_accuracy:    {'mean': 0.58, 'median': 0.5, 'n': 200}
  hallucination_resistance:   {'mean': 0.96, 'median': 1.0, 'n': 200}
  ioc_f1:                     {'mean': 0.86, 'median': 1.0, 'n': 200}
  wall_time_seconds:          7.52
  alerts:                     200
```

A few notes on what these numbers mean:

- The whole run above is offline — no real Claude calls. Treat the verdict number as a defensible lower bound; with a real model it should land higher.
- `ioc_f1 = 0.86` (median 1.0) is the metric that doesn't depend on the LLM at all. It's the regex extractor combined with the malicious-flag logic from the threat-intel responses, so this one carries over straight to a real-API run.
- `attack_mapping_accuracy = 0.58` is HyDE retrieval finding the right technique family but often picking a sibling subtechnique (e.g. `T1003.001` when truth is `T1003`), which gets half credit.
- `hallucination_resistance = 0.96` is a heuristic that dings unhedged absolutes in the analyst summary. Some true-positive summaries deliberately use "confirmed", which is why it's not a flat 1.0.

`evals/last_results.json` has the per-alert breakdown if you want to dig in.

## Stack

- **LangGraph** for the supervisor graph — explicit state, conditional edges, native HITL hooks via `interrupt_after`.
- **Pinecone + HyDE** retrieval for ATT&CK / Sigma / runbook lookup. Per-tenant namespaces are the isolation boundary.
- **5 MCP-style Python servers** for threat intel, each with retries and TTL caches.
- **DFIR-IRIS** REST as the case backend.
- Wazuh-shaped synthetic alerts (no live SIEM needed).
- **LangSmith** for tracing if you give it a key.
- Custom `PromptInjectionGuard` over every tool output before it reaches LLM context.

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

## Multi-tenancy

Two synthetic tenants ship in the box: **tenant_a / FinTech Corp** (AWS, PCI-DSS, payment-processor + auth-server are the crown jewels) and **tenant_b / Healthcare LLC** (on-prem VMware + Azure, HIPAA, EHR + radiology PACS are critical).

The isolation boundaries:

- **Pinecone** — each tenant gets its own `{tenant_id}_attack`, `{tenant_id}_sigma`, `{tenant_id}_runbooks` namespaces. Retriever calls are scoped at construction time, so one tenant can't accidentally pull another tenant's runbook into context.
- **System prompts** — every node injects the tenant's environment, critical asset list, and suppression rules. The same alert pattern reads differently against a fintech vs. a hospital.
- **Redis Streams** — alerts publish to `alerts:{tenant_id}` so backpressure and noisy-neighbor effects stay scoped.
- **DFIR-IRIS** — `tenant_id` maps to a customer record so cases land under the right account.

## Security and guardrails

- **Prompt-injection guard** runs on every alert field and every TI tool response before the LLM sees them. Regex catches the obvious "ignore previous instructions" family + chat-template tokens; field truncation caps payload size.
- **No user-submitted documents into the KB** — ingestion is offline and committed in code, not exposed via API. RAG poisoning needs a code change, not just a malicious upload.
- **Threat model** is in [`THREAT_MODEL.md`](THREAT_MODEL.md), with each scenario mapped to a MITRE ATLAS technique.

## Roadmap / what I'd do next

- Swap the synthetic Wazuh source for a real Stellar Cyber XDR adapter — that's the actual MSSP ingestion path.
- Per-tenant fine-tuning on historical analyst decisions to cut down on revision loops.
- Torq webhook on the reporter for response automation (host isolation, ticket close) once a verdict is human-approved.
- Wire `interrupt_after` into a tiny review UI so an analyst can approve / edit before the IRIS write happens.
- LangSmith CI gate that fails a PR if verdict accuracy on the golden set regresses past a threshold.

## License

MIT.
