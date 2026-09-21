# Universal Log Pre-processing Framework (ULPF)

Smart India Hackathon 2026 | Problem Statement 26156 | NTRO | Software | Blockchain & Cybersecurity

> **Status: working UI prototype with sample data. The parsing engine is under development.**

## Team

| | |
|---|---|
| Team name | [EthicalOne] |
| Team ID | [Your Team ID] |
| Members | [Adarsh], [Member 2], [Member 3] |
| GitHub | [adarshasus1620-collab](https://github.com/adarshasus1620-collab) |

## The problem

Perimeter devices (firewalls, VPN gateways, IDS/IPS) write logs in very different formats: key=value, syslog text, CSV, JSON, CEF, LEEF and vendor-specific layouts. Security teams spend a lot of effort writing a separate parser for every source before a SIEM, data lake or ML pipeline can use the data.

## Our approach

ULPF converts logs from any perimeter device into one standard, lossless, analytics-ready event, and keeps the original line untouched.

```
Perimeter logs  ->  Detect format  ->  Parse  ->  Normalize  ->  Enrich  ->  SIEM / Data Lake / ML
                          |
                          +--> Raw Vault (original line + SHA-256, linked to every normalized event)
```

Design goals:

- Preserve the complete raw event, with no information loss
- Normalize fields into one common schema (OCSF-aligned), with an `extensions` bucket so no field is dropped
- Keep a trace link from every normalized event back to its raw event
- Add a new log source with a small YAML parser pack instead of new code
- Run in an air-gapped network, packaged in a container

## What the prototype shows

A Streamlit app with five screens:

| Screen | What it shows |
|---|---|
| Overview | Event counts, charts, and one attacker IP seen by three different vendors |
| Before and after | The same SSH probe as Fortinet, Cisco ASA and Suricata wrote it, then as one unified table |
| Events | Filterable table of normalized events |
| Trace and integrity | Raw event next to its normalized record, with a live SHA-256 tamper check |
| Parser packs | Example of the planned YAML parser-pack format |

## What is real and what is sample

| Item | Status |
|---|---|
| UI, filters, charts | Working |
| SHA-256 hashing, hash chain and tamper detection | Working (computed live) |
| 8 sample events (Fortinet, Cisco ASA, Suricata) | Sample data |
| Normalized fields for those events | Filled in by hand for the demo |
| Parsers, format auto-detection, YAML parser packs, raw vault, SIEM and data lake connectors | Planned |

The sample logs are simplified and illustrative. They were not captured from real devices. Timestamps without a timezone are assumed to be UTC.

## Run it locally

Requirements: Python 3.11 or newer, and Git.

```
git clone https://github.com/adarshasus1620-collab/universal-log-preprocessing-framework.git
cd universal-log-preprocessing-framework
python -m venv venv
venv\Scripts\Activate.ps1
pip install streamlit
streamlit run app.py
```

On macOS or Linux, use `source venv/bin/activate` instead of `venv\Scripts\Activate.ps1`.

Then open http://localhost:8501 in a browser.

## Repository layout

```
app.py                   Streamlit demo UI
sample_logs/             Sample Fortinet, Cisco ASA and Suricata logs (pfsense.log is a placeholder)
parsers/                 Reserved for YAML parser packs (planned)
ulpf/                    Reserved for the processing engine (planned)
output/                  Reserved for pipeline output (planned)
.streamlit/config.toml   Theme settings
```

## Roadmap

- [x] Demo UI with tamper-evident raw-to-normalized tracing
- [x] Sample logs for three sources
- [ ] Unified schema (Pydantic)
- [ ] Parsers for Fortinet, Cisco ASA, Suricata and pfSense
- [ ] Format auto-detection
- [ ] YAML parser packs for plug-and-play onboarding
- [ ] Raw vault with SHA-256 trace IDs and hash chain
- [ ] Docker packaging and offline install bundle
- [ ] Streaming ingestion and SIEM / data lake outputs

## Planned technology

Python, Pydantic, PyYAML, Streamlit (prototype UI), Kafka, ClickHouse or OpenSearch, MinIO, Docker.