# Cyber Threat Dashboard

A polished, end-to-end cyber threat intelligence prototype for collecting, normalizing, scoring, and visualizing security events.

The project is intentionally small enough to understand, but structured like a real platform:

- data collection from CSV feeds or synthetic demo data
- parsing and preprocessing into a clean event schema
- configurable detection rules with MITRE ATT&CK mapping
- offline enrichment for asset criticality and source reputation
- explainable risk scoring and anomaly triage
- an interactive Streamlit dashboard for threat operations
- tests for the core analysis pipeline

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run src/visualization/app.py


importante

play

cd "C:\Users\LENOVO\OneDrive\Desktop\Cyber Threat Dashboard"
python -m src.pipeline
```

If you only want to verify the logic:

```powershell
pytest
```

## Project Layout

```text
data/
  raw/                 Source feeds and exported logs
  processed/           Normalized events and scored outputs
config/
  rules.yaml           Detection rules, MITRE mappings, and recommendations
  assets.yaml          Asset owners, criticality, exposure, and business context
src/
  data_collection/     Feed loading and demo data generation
  enrichment/          Asset and reputation context
  processing/          Parsing, cleaning, enrichment, analysis
  detection/           Risk models and detector orchestration
  visualization/       Streamlit dashboard
  utils/               Shared helpers
reports/               Generated summaries and exports
tests/                 Unit tests
```

## Event Schema

The platform normalizes every event to these fields:

| Field | Meaning |
| --- | --- |
| `timestamp` | Event time in UTC-compatible ISO format |
| `source_ip` | Origin IP address |
| `destination_ip` | Target IP address |
| `event_type` | Category such as `login_failure`, `malware`, `scan`, or `exfiltration` |
| `severity` | `low`, `medium`, `high`, or `critical` |
| `asset` | Host, workload, or business system involved |
| `country` | Source country or geo label |
| `description` | Human-readable context |

## Intelligence Layer

Detection logic lives in `config/rules.yaml`, so you can add or tune detections without rewriting the engine.

Each rule can define:

```yaml
id: credential_pressure
name: Credential Pressure
event_type: login_failure
base_score: 35
mitre_tactic: Credential Access
mitre_technique: T1110 Brute Force
recommendation: Review VPN logs, lock affected accounts, enforce MFA.
description: Repeated authentication failures may indicate brute force activity.
```

Asset context lives in `config/assets.yaml`. Criticality, owner, exposure, and business unit now influence scoring and appear in the dashboard.

## Pipeline

Run the full intelligence pipeline:

```powershell
python -m src.pipeline
```

It writes:

- `data/processed/events_scored.csv`
- `reports/threat_summary.md`

## Notes

This is a defensive analytics project. The sample detections are designed for triage and learning, not offensive activity.
