# 🚀 [Your Project Title Here]

---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | ByteForge |
| **Track** | AI |
| **Team Lead** | Patel Khushi — 25cs065@charusat.edu.in.com |
| **Members** | Nandani Patel, Siddhi Panchal, yatri Dekivadiya |

---

## 🎯 Problem Statement

Defence analysts receive thousands of alerts daily from SIEM systems,
satellite feeds, cyber sensors, and intelligence reports — all in different
formats — and no human team can read them all in real time. Missing a
genuine threat because it was never correlated across sources is
catastrophic, while manually chasing false positives wastes critical
analyst hours that are already in short supply.

---

## 💡 Solution

We built a system that ingests multi-source threat feeds, automatically
correlates related alerts into single incidents instead of thousands of
disconnected events, scores and prioritises them using AI-driven risk and
behavioural analysis, maps attacker techniques to the MITRE ATT&CK
framework, and generates prioritised, commander-ready BLUF (Bottom Line Up
Front) investigation reports — all surfaced through an interactive Command
Center dashboard with a live AI analyst assistant.

---

## ✨ Key Features

- **AI Alert Correlation & Incident Clustering:** Groups related alerts from SIEM, sensors, intel reports, and satellite feeds into single, unified incidents instead of thousands of disconnected events.
- **Dynamic Risk Scoring, Prioritisation & Threat DNA:** Assigns each incident a 0–100 risk score and Critical/High/Medium/Low priority, and generates a unique behavioural fingerprint that can recognise the same attacker even after they change IP or malware.
- **MITRE ATT&CK Mapping & Cyber-Physical Threat Fusion:** Maps observed attacker behaviour to MITRE technique IDs and correlates cyber alerts against simulated satellite/geospatial signals for a fused threat picture.
- **AI Investigation Assistant & BLUF Report Generator:** Answers free-text analyst questions grounded in incident evidence and auto-generates structured Threat/Impact/Confidence/Evidence/Next-Steps reports for commanders.
- **Predictive Kill-Chain Forecasting:** Predicts the attacker's likely next MITRE technique based on the kill-chain progression already observed in the incident.

---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | Python |
| **Frameworks** | Streamlit |
| **IBM Technologies** | IBM Bob |
| **Databases** | None — pipeline runs in-memory on simulated data |
| **Other** | Git / GitHub Actions (submission validation) |

---

## 📁 Repository Structure

```
├── src/ # All source code
│ ├── shared/ # Shared Incident data contract
│ ├── ingestion/ # Multi-source ingestion, normalization, correlation, clustering
│ ├── detection/ # False-positive detection, risk scoring, prioritisation, Threat DNA
│ ├── context/ # MITRE mapping, attack timeline, intel enrichment, cyber-physical fusion
│ ├── reasoning/ # AI assistant, BLUF generator, recommended actions, kill-chain forecasting
│ ├── frontend/ # Streamlit Command Center dashboard
│ └── main.py # Pipeline orchestrator
├── docs/ # Written documentation
│ ├── problem-statement.md
│ ├── solution-overview.md
│ ├── architecture.md
│ └── setup-guide.md
├── demo/ # Demo artifacts
│ ├── screenshots/ # App screenshots
│ └── demo-video-link.txt # Link to demo video
├── presentation/ # Slide deck
└── submission.yaml # Structured submission metadata
```

---

## ⚡ How to Run

> **Copy these exact steps from your [`docs/setup-guide.md`](docs/setup-guide.md)**

```bash
# 1. Clone the repo
git clone https://github.com/25cs065-ux/bob-ai-hackathon-ByteForge.git
cd bob-ai-hackathon-ByteForge/src

# 2. Install dependencies
pip install streamlit --break-system-packages

# 3. Run the interactive dashboard
streamlit run frontend/dashboard.py

# — or run the pipeline directly from the command line —
python main.py
```

No environment variables, API keys, or database setup are required — all
alert sources and threat intelligence are simulated locally. See
[`docs/setup-guide.md`](docs/setup-guide.md) for full details, tests, and
troubleshooting.

---

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🌐 Live Demo | [See demo/live-demo-url.txt](demo/live-demo-url.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/slides.pdf](presentation/) |

---

## ⚠️ Known Limitations

- Threat DNA signature matching and incident history currently operate within a single pipeline run rather than persisting across sessions; a production version would store historical incidents in a database for cross-session pattern matching.
- All alert sources (SIEM, sensor, intel, satellite) and threat intelligence indicators are simulated locally rather than connected to live external feeds, to keep the prototype fully reproducible without API keys or accounts.
- Correlation uses a straightforward time-window and shared-attribute scoring approach suitable for prototype-scale data; production-scale alert volumes would need an indexed or streaming correlation approach.

---

## 🏅 What We're Most Proud Of

The Threat DNA behavioural fingerprinting and Cyber-Physical Threat Fusion
features go beyond the base problem statement's requirements — Threat DNA
detects attackers who evade traditional signature-based detection by
changing infrastructure, while Cyber-Physical Fusion directly uses the
"simulated satellite feeds" detail from the original brief to give
commanders a genuinely unified cyber + physical threat picture, something
we felt most solutions to this problem would otherwise treat as a checkbox
data source rather than a real correlation signal.

---
