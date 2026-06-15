# Agentic SOC Analyst

An LLM-driven threat hunting pipeline for Microsoft Sentinel / Azure Log
Analytics. It takes a plain-language hunting request, decides which table and
fields to query, pulls the matching logs from a Log Analytics workspace via KQL,
and runs them through Google Gemini to produce structured threat findings mapped
to MITRE ATT&CK.

The project also ships scripts to generate synthetic Azure/Sentinel datasets and
ingest them into a workspace, so the full pipeline can be exercised without real
production logs.

## What it does

1. Takes a natural-language request (e.g. "something is off with user arisa in
   Entra ID over the last two weeks").
2. Uses Gemini to pick the right Log Analytics table, fields, entity filters
   (device / user / caller), and time range.
3. Validates the chosen table and fields against an allow-list, dropping
   anything the model hallucinated.
4. Builds and runs a scoped KQL query against the workspace.
5. Estimates token count and cost, lets you pick the model, then sends the logs
   to Gemini for analysis.
6. Returns structured JSON findings: title, description, MITRE mapping,
   confidence, IOCs, log evidence, tags, and recommended actions.

## Components

### Agent

The agent lives in `baseline_agent/` and is built from these modules:

| Module | Responsibility |
|---|---|
| `_main.py` | Orchestrates the full hunt flow end to end. |
| `EXECUTOR.py` | Calls Gemini for tool selection and analysis; runs the KQL query. |
| `PROMPT_MANAGEMENT.py` | System prompts, per-table hunting instructions, output schema, tool definition. |
| `GUARDRAILS.py` | Table/field allow-list and model validation. |
| `MODEL_MANAGEMENT.py` | Token counting, cost estimation, model selection, rate-limit display. |
| `UTILITIES.py` | Query-context sanitization and result display. |
| `_keys.py` | Reads `GEMINI_API_KEY` and the workspace ID from the environment. |

### Standalone scripts

| Script | Purpose |
|---|---|
| `soc_analyst.py` | Single-shot threat hunt over a fixed `DeviceLogonEvents_CL` KQL query. |
| `generate_datasets.py` | Generates synthetic SigninLogs, AzureActivity, and AzureNetworkAnalytics CSVs. |
| `generate_logons.py` | Generates a synthetic DeviceLogonEvents dataset. |
| `ingest_to_loganalytics.py` | Posts a synthetic CSV into a custom `*_CL` table via the Log Analytics HTTP Data Collector API. |

### Synthetic data

The repository includes pre-generated synthetic CSVs (`*_synthetic.csv`) for
SigninLogs, AzureActivity, AzureNetworkAnalytics, and DeviceLogonEvents. All
values are made up and safe to ingest into a test workspace.

## Requirements

- Python 3.13
- A Google Gemini API key
- An Azure Log Analytics / Sentinel workspace
- Azure CLI, authenticated with `az login` (the agents use
  `DefaultAzureCredential`)

Python packages:

```
google-genai
azure-identity
azure-monitor-query
pandas
colorama
numpy
requests
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install google-genai azure-identity azure-monitor-query pandas colorama numpy requests
```

Set the required environment variables:

```bash
export GEMINI_API_KEY="your-gemini-key"
az login
```

Set your workspace ID where the code expects it (`_keys.py` for the agents, or
the `WORKSPACE_ID` constant in the standalone scripts).

## Usage

Run an agent:

```bash
cd baseline_agent
python _main.py
```

You will be prompted for a hunting request. The agent shows the table and
fields it chose, the constructed KQL, a token/cost estimate, and finally the
structured findings.

Run the single-shot analyst:

```bash
python soc_analyst.py
```

Generate and ingest synthetic data:

```bash
python generate_datasets.py
export LA_WORKSPACE_ID="your-workspace-guid"
export LA_SHARED_KEY="your-primary-key"
python ingest_to_loganalytics.py devicelogonevents_synthetic.csv DeviceLogonEvents
```

A new custom table can take 5–10 minutes to appear in the workspace after first
ingest.

## Supported tables

The allow-list in `GUARDRAILS.py` controls what can be queried:

- DeviceProcessEvents
- DeviceNetworkEvents
- DeviceLogonEvents
- DeviceFileEvents
- DeviceRegistryEvents
- AlertInfo / AlertEvidence
- AzureActivity
- SigninLogs
- AzureNetworkAnalytics_CL

## Models

Defined in `GUARDRAILS.py` (context limits and approximate per-million-token
pricing):

- gemini-2.5-flash
- gemini-2.5-pro
- gemini-2.5-flash-lite (default)
- gemini-2.0-flash

Confirm current pricing at https://ai.google.dev/gemini-api/docs/pricing.

## Security notes

- API keys are read from the environment and are not committed.
- `ingest_to_loganalytics.py` is gitignored. If you use it, supply the workspace
  ID and shared key from environment variables rather than hardcoding them, and
  rotate any key that has been written into a local file.
- All bundled datasets are synthetic.
