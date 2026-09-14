# Setup Guide

> **This file is read by the automated evaluation pipeline. Be precise and complete.**

## Prerequisites

Before you begin, ensure you have the following installed:

- [ ] [e.g., Python 3.11+]
- [ ] [e.g., Node.js 18+]
- [ ] [e.g., Docker Desktop]
- [ ] [e.g., An IBM Cloud account with watsonx.ai access]

No database, external API keys, or paid services are required — the
pipeline runs entirely on simulated, locally-generated alert data.

## Environment Variables

No environment variables or `.env` file are required for this project.
All alert sources (SIEM, cyber sensor, intelligence report, satellite
feed) are simulated locally within the ingestion module, and no external
APIs are called.

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/25cs065-ux/bob-ai-hackathon-ByteForge.git
cd bob-ai-hackathon-ByteForge

# 2. Move into the source directory
cd src

# 3. Install dependencies
pip install streamlit --break-system-packages
```

No frontend build step, no database migration, and no additional
installation steps are required — the project is pure Python.

## Running the Application

**Option 1 — Run the interactive dashboard (recommended for demo):**

```bash
cd src
streamlit run frontend/dashboard.py
```

This opens automatically in your default browser. If it doesn't open
automatically, copy the URL shown in the terminal (typically
`http://localhost:8501`) into your browser manually.

**Option 2 — Run the pipeline from the command line (no UI):**

```bash
cd src
python main.py
```

This prints each processed incident — including risk score, priority,
MITRE ATT&CK techniques, BLUF report, and recommended actions — directly
to the terminal.

The application will be available at: `http://localhost:8501`

## Running Tests

```bash
cd src

# Test the full pipeline end-to-end with a single sample incident
python -m test_full_pipeline

# Test the ingestion module specifically (multi-source correlation)
python -m ingestion.test_ingestion

# Test the detection module specifically
python -m detection.test_detection
```

Each test prints real, populated field values for its module (risk
scores, MITRE technique IDs, BLUF reports, etc.) — if any field prints as
empty, `None`, or a placeholder value, that indicates the corresponding
module did not run correctly.

## Quick Demo (Optional)

To see the full system working end-to-end with a realistic multi-source
attack scenario (login failure → PowerShell execution → privilege
escalation → data exfiltration, correlated across SIEM, sensor, intel,
and satellite sources):

```bash
cd src
streamlit run frontend/dashboard.py
```

Open the **Overview** tab to see the Commander Dashboard summary, then
click into either incident under **Active Incidents** to see the full
Detection, Context, and AI Reasoning panels, including a live Analyst
Q&A box under the AI Reasoning tab.

## Troubleshooting

| Issue | Solution |
|---|---|
| `python` is not recognized / opens Microsoft Store | On Windows, this means the App Execution Alias is intercepting the command. Try `py` instead of `python`, or disable it under Settings → Apps → Advanced app settings → App execution aliases. |
| `ModuleNotFoundError: No module named 'shared'` (or `context`, `detection`, `reasoning`) | You are running a file directly from inside its own folder. Always run commands as a module from inside `src/` (e.g. `python -m context.mitre_mapping`), not by `cd`-ing into the module's subfolder. |
| `streamlit: command not found` | Run `pip install streamlit --break-system-packages` again, and ensure you are using the same Python environment where it was installed. |
| Dashboard loads but shows "0 incidents" | Check `main.py` — the `sample_sources` list must contain source names (e.g. `["siem", "sensor", "intel", "satellite"]`), not raw alert dictionaries. |
| Dashboard filter chips or sidebar text hard to read | Ensure `src/.streamlit/config.toml` exists with the dark theme settings — this file is required for the intended styling and is not optional. |
