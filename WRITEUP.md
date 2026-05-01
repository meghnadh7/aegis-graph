# AegisGraph — Engineering Writeup

## The problem

MSSPs sit at the wrong end of an asymmetry: every customer's noisy environment
is normalized and dumped into the same SOC queue. Industry surveys put the
average SOC analyst in front of ~2,992 alerts per day, and 25–30% of analyst
time is spent confirming false positives. CQ Blue (Compuquip's MSSP service)
publishes a roadmap targeting exactly this — a triage copilot that does the
mechanical pre-work for every alert so humans only review the cases that
actually warrant judgment. AegisGraph is my swing at that target.

The work the copilot has to do is well-known and tedious: pull threat-intel for
every IOC the alert touches, map the alert content to MITRE ATT&CK, check for
related activity on the same host/user/IP, decide whether the alert is a true
positive, false positive, or escalation, and write a coherent summary into the
case management system. Each step alone is a 30-second-to-2-minute task. The
problem is doing 2,992 of them per day per analyst.

## Why LangGraph (not CrewAI)

I picked LangGraph because triage is a *state-shaped* problem, not a
*conversation-shaped* one. Every node mutates a `TriageCase` typed dict in
predictable ways: triage adds IOCs and enrichment, attack_mapper adds
techniques, etc. LangGraph's `StateGraph` makes this explicit. It also gives me
deterministic conditional edges — the reflector decides "revise vs report"
based on a numeric threshold, not on the LLM choosing what to do next. With
CrewAI I would have to negotiate with a router agent for every decision, and
the path through the system would be model-dependent. LangGraph also has
first-class `interrupt_after` for human-in-the-loop, which I've stubbed in for
production HITL hand-offs.

## Why HyDE

Wazuh alerts are terse: a rule id, a level, a one-line description, and a few
fields out of `data.win.eventdata`. Embedding that directly against MITRE
ATT&CK prose ("Adversaries may abuse PowerShell commands and scripts for
execution...") works poorly — they don't share enough surface vocabulary.

HyDE inverts this: I ask the LLM to write the *kind* of detection narrative an
analyst would write for this alert ("An attacker is leveraging a Windows-native
scripting interpreter to execute obfuscated commands…") and embed *that*. Now
both sides of the cosine match speak the same language. In the demo, this
moves top-1 ATT&CK accuracy from coin-flip to consistently correct on
PowerShell/credential-dump/phishing variants.

## Why MCP

Each threat-intel source is wrapped as an MCP-style server with the same
async interface. Three reasons:

1. **Reuse across agents/models** — the next agent in the CQ Blue roadmap can
   call the same `VirusTotalMCP.lookup_ip()` without re-implementing the cache,
   retry, and rate-limit logic.
2. **Mock mode at the boundary** — every MCP server returns deterministic
   fake data when `MOCK_MODE=true` or when keys are absent. The graph runs
   end-to-end on a laptop with no network.
3. **Pluggable in the future** — replacing VirusTotal with Mandiant Advantage
   means swapping one class, not threading a new tool through every node.

## Multi-tenancy design

Per-tenant Pinecone namespaces (`tenant_a_attack`, `tenant_a_sigma`,
`tenant_a_runbooks`) — the same chunks are upserted under each namespace, and
the retriever only ever queries one. This is the cheapest enforceable
isolation; it avoids the metadata-filter trap where one missing filter call
leaks data across tenants.

Per-tenant prompt context is injected into every node's system prompt:
environment description, critical asset list, suppression rules. The Tier-1
triage call to a financial-services tenant will weigh "PCI vault" and "auth
server" differently from the same alert pattern at a hospital, where the EHR
server is the crown jewel.

Per-tenant Redis Streams (`alerts:tenant_a`) keep alert fan-in isolated and
make per-tenant rate-limiting and quota tracking straightforward.

## What I'd change with more time

- **Stellar Cyber XDR adapter** — Compuquip ingests via Stellar; my synthetic
  Wazuh source is a stand-in.
- **Per-tenant fine-tuning** — once historical analyst decisions are in the
  loop, a small LoRA on top of Haiku per tenant should tighten verdicts.
- **Torq response webhooks** — write back into Compuquip's automation: host
  isolation, ticket close, customer notification.
- **A real LangSmith eval gate in CI** — fail PRs whose verdict_accuracy
  regresses past a threshold.

## What I want to learn at Compuquip

- How real customer alert volumes shape architecture decisions you can't see
  from synthetic data — quota-bound external APIs, embedding cost at scale,
  cache eviction strategies.
- Where the LLM is *wrong* in production — the failure modes that show up only
  when 50 different customer environments are pushing alerts simultaneously.
- The actual tooling MSSP analysts use day-to-day, so the next iteration of an
  agent like this is built from inside the workflow, not bolted on.
