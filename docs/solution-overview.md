# Solution Overview

## What We Built

We built an AI-driven Threat Intelligence Correlation & Alert Prioritisation
Assistant — a system that takes in raw security alerts from multiple sources
(SIEM systems, cyber sensors, intelligence reports, and satellite feeds),
automatically figures out which alerts belong to the same attack, decides
how dangerous each resulting incident actually is, explains the attack in
plain language using the industry-standard MITRE ATT&CK framework, and
produces a structured, commander-ready BLUF (Bottom Line Up Front) report —
all without an analyst having to manually cross-reference alerts by hand.
On top of the core correlation and reporting pipeline, we added two
original capabilities: a behavioural "Threat DNA" fingerprint that can
recognize the same attacker even if they change IP address or malware, and
a Cyber-Physical Fusion feature that links cyber alerts to simulated
satellite/geospatial signals — directly using the "simulated satellite
feeds" detail called out in the original problem statement, which we felt
most solutions to this brief would otherwise overlook.

## How It Works

1. **Ingestion & Normalization** — Alerts arrive from four different simulated sources, each using its own field naming convention (e.g., a SIEM alert has `hostname` and `event_time`, a sensor alert has `asset` and `timestamp`). The system converts every alert into one common structure regardless of source.
2. **Correlation & Clustering** — Alerts that are likely part of the same attack (same asset, same IP, within a 15-minute window, or a chain of suspicious behaviours) are automatically grouped into a single incident, instead of appearing as dozens of disconnected alerts.
3. **Detection & Scoring** — Each incident is assessed for false-positive likelihood, given a 0–100 risk score, assigned a Critical/High/Medium/Low priority, and fingerprinted with a unique behavioural "Threat DNA" signature that can be compared against future incidents.
4. **Context Enrichment** — The incident's behaviour is mapped to specific MITRE ATT&CK technique IDs, laid out on a chronological attack timeline, enriched with available threat intelligence on any IPs/indicators involved, and checked for correlation against simulated satellite/geospatial signals near the affected asset.
5. **AI Reasoning & Reporting** — The system generates a plain-language explanation of why the incident matters, a structured BLUF report (Threat / Impact / Confidence / Evidence / Next Steps), a list of concrete recommended investigation actions, and a prediction of the attacker's likely next move based on the kill-chain technique(s) already observed.
6. **Command Center Dashboard** — All of the above is surfaced through an interactive dashboard: a Commander Overview with aggregate risk metrics, a filterable/searchable incident list, and a full investigation view per incident — including a live Q&A box where an analyst can type a question like "Why is this critical?" and get an answer generated directly from that incident's evidence.

## Architecture Diagram

> See [`architecture.md`](architecture.md) for the detailed diagram.

```
[Multi-Source Alerts] → [Ingestion & Correlation] → [Detection & Scoring]
↓
[Command Center Dashboard] ← [AI Reasoning & BLUF] ← [Context Enrichment]
```

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Built four independent pipeline modules sharing one `Incident` data contract, rather than one monolithic script | Let four team members build, test, and debug their features in parallel without editing each other's files or causing merge conflicts, while guaranteeing every module's output is compatible with the next stage. |
| Simulated all alert sources and threat intelligence locally rather than calling external APIs | Kept the prototype fully reproducible and runnable offline with zero setup friction (no API keys, no accounts, no rate limits) — while still demonstrating realistic multi-source correlation logic on a coherent, deliberately-designed attack scenario. |
| Added Threat DNA and Cyber-Physical Fusion as extensions beyond the base problem statement | The brief specifically mentions satellite feeds and the risk of both missing real threats and chasing false positives; these two features directly target those points — cross-incident behavioural matching for evasive attackers, and cyber-physical correlation for a fuller threat picture — rather than stopping at the minimum required correlation and scoring. |
| Chose Streamlit for the dashboard instead of a full React/FastAPI stack | Given the 2-day timeframe, Streamlit let us build a genuinely interactive, multi-panel dashboard (filtering, expandable incident views, live AI Q&A) directly on top of our existing Python pipeline with no separate frontend/backend split to maintain, maximizing time spent on the actual detection and reasoning logic rather than API plumbing. |

## IBM Technologies Used

- **IBM Bob:** Used as the primary implementation tool for writing the
  project's source code. After confirming the problem statement and
  scoping the 21 features (18 from the original brief plus 3 team-proposed
  additions), the team prepared detailed prompts specifying each feature's
  required input/output shape against a shared `Incident` data contract.
  These prompts were given directly to IBM Bob, which generated the working
  Python implementation for all four pipeline modules — Ingestion &
  Correlation, Detection & Scoring (including the Threat DNA behavioural
  fingerprinting feature), Context Enrichment (including MITRE ATT&CK
  mapping and the Cyber-Physical Threat Fusion feature), and AI Reasoning &
  Reporting (including the BLUF report generator and Kill-Chain
  Forecasting feature). Bob was also used iteratively throughout
  development to debug integration issues between modules, fix bugs
  identified during end-to-end pipeline testing, and build the Streamlit
  Command Center dashboard.
