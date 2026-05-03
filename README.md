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
make demo                     # one alert through the full pipeline (rich panels)
make test                     # pytest
make eval                     # 200-alert golden run + metrics
make eval-summary             # pretty-print dataset stats + last eval run
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
  verdict_accuracy:           {'mean': 0.41,  'median': 0.0,    'n': 200}
  attack_mapping_accuracy:    {'mean': 0.58,  'median': 0.5,    'n': 200}
  hallucination_resistance:   {'mean': 1.0,   'median': 1.0,    'n': 200}
  ioc_f1:                     {'mean': 0.86,  'median': 1.0,    'n': 200}
  cost_per_alert_usd:         {'mean': 0.015, 'median': 0.01,   'n': 200}
  wall_time_seconds:          4.44
  alerts:                     200
```

A few honest notes:

- These numbers are with the **mock LLM**, not a real model. The mock is deliberately keyword-driven — it hits TP for powershell-encoded prompts, otherwise picks a verdict roughly at random. So verdict_accuracy of 0.41 is what you'd expect from a 3-class system with a small recognition bonus. The point of running it like this is to prove the pipeline + evaluators are wired correctly across all three classes (TP / FP / Escalate). With real Claude this number jumps; the interesting work is making sure the eval *infrastructure* would catch a regression.
- The dataset is correctly stratified: 16 TP / 14 FP / 10 escalate per technique × 5 techniques × 2 tenants = 200 alerts.
- `ioc_f1 = 0.86` (median 1.0) is the genuine signal here — the IOC extractor and the enrichment-driven malicious tagging actually work. The number used to be ~0.63 before I fixed a bug where the mock LLM was scanning the enrichment payload (including TI tool URLs) as if it were the alert.
- `attack_mapping_accuracy = 0.58` is HyDE retrieval finding the right technique family but the mock often picks a sibling sub-technique (e.g. `T1003.001` when truth is `T1003`), getting partial credit.
- `hallucination_resistance` is a heuristic: it dings unhedged absolutes like "definitely" or "confirmed exfiltration" in the summary. Not a real grounding eval — that's a TODO.
- $0.015/alert is simulated from the token counts the mock LLM hands back. Real cost depends on the model and prompt-cache hit rate.

Run `make eval-summary` for a formatted view of the dataset breakdown plus the last eval run.

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

## Multi-tenancy

Two synthetic tenants ship in the box: **tenant_a / FinTech Corp** (AWS, PCI-DSS, payment-processor + auth-server are the crown jewels) and **tenant_b / Healthcare LLC** (on-prem VMware + Azure, HIPAA, EHR + radiology PACS are critical).

The isolation boundaries:

- **Pinecone** — each tenant gets its own `{tenant_id}_attack`, `{tenant_id}_sigma`, `{tenant_id}_runbooks` namespaces. Retriever calls are scoped at construction time, so one tenant can't accidentally pull another tenant's runbook into context.
- **System prompts** — every node injects the tenant's environment description, critical asset list, and suppression rules into its system prompt. The same alert pattern reads differently against a fintech vs. a hospital.
- **Redis Streams** — alerts publish to `alerts:{tenant_id}` so backpressure and noisy-neighbor effects stay scoped to one tenant.
- **DFIR-IRIS** — `tenant_id` maps to a customer record so cases land under the right account.

## Security and guardrails

- **Prompt-injection guard** runs on every alert field and every TI tool response before the LLM sees them. Regex catches the obvious "ignore previous instructions" family + chat-template tokens; field truncation caps payload size.
- **No user-submitted documents into the KB** — ingestion is offline and committed in code, not exposed via API. RAG poisoning needs a code change, not just a malicious upload.
- **Threat model** is in [`THREAT_MODEL.md`](THREAT_MODEL.md), with each scenario mapped to a MITRE ATLAS technique.

## Roadmap / what I'd do next

- Swap the synthetic Wazuh source for a real Stellar Cyber XDR adapter — that's the actual MSSP ingestion path.
- Per-tenant fine-tuning on historical analyst decisions to cut down on revision loops.
- Torq webhook on the reporter for response automation (host isolation, ticket close) once a verdict is human-approved.
- Wire `interrupt_after` into a tiny review UI so an analyst can approve/edit before the IRIS write happens.
- LangSmith CI gate that fails a PR if verdict accuracy on the golden set regresses past a threshold.

