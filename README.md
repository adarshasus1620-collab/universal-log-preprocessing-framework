# Universal Log Pre-processing Framework (ULPF)

Smart India Hackathon 2026 | Problem Statement 26156 | NTRO | Software | Blockchain & Cybersecurity

> **Status: working end-to-end pipeline.** Raw logs are auto-detected, parsed by four vendor
> parsers (or a YAML parser pack), normalized to one schema, stored in a tamper-evident raw
> vault, and shown live in the demo UI. Streaming ingestion and production-scale storage
> remain future work (see Roadmap).

## Team

| | |
|---|---|
| EthicalOne | [Adarsh] |
| Team ID | [Your Team ID] |
| Members | [Member 1], [Member 2], [Member 3] |
| GitHub | [adarshasus1620-collab](https://github.com/adarshasus1620-collab) |

## The problem

Perimeter devices (firewalls, VPN gateways, IDS/IPS) write logs in very different formats: key=value, syslog text, CSV, JSON, CEF, LEEF and vendor-specific layouts. Security teams spend a lot of effort writing a separate parser for every source before a SIEM, data lake or ML pipeline can use the data.

## Our approach

ULPF converts logs from any perimeter device into one standard, lossless, analytics-ready event, and keeps the original line untouched.

```
Perimeter logs -> Detect format -> Parse -> Normalize -> Raw Vault -> Output / UI
                                       |
                          (Python parser OR YAML parser pack)
```

Design goals:

- Preserve the complete raw event, with no information loss
- Normalize fields into one common schema (OCSF-aligned), with an `extensions` bucket so no field is dropped
- Keep a trace link from every normalized event back to its raw event, secured by a SHA-256 hash chain
- Add a new log source with a small YAML parser pack instead of new code
- Run in an air-gapped network, packaged in a container

## What the pipeline does

1. **Detect** - `detect.py` identifies which vendor wrote a raw log line.
2. **Parse** - either a dedicated Python parser (`parse.py`, `parse_cisco.py`, `parse_suricata.py`, `parse_pfsense.py`) or a declarative YAML parser pack (`yaml_parser.py` + `parsers/*.yaml`) extracts fields.
3. **Normalize** - `schema.py` (Pydantic) enforces one unified event shape for every source.
4. **Vault** - `vault.py` stores every raw line with its SHA-256 hash, chained to the previous entry, so tampering with any past entry is detectable.
5. **Run** - `cli.py` runs the whole pipeline over one or more log files and writes `output/events.jsonl` and `output/vault.jsonl`.
6. **View** - `app.py` (Streamlit) reads that output and shows it live, with a tamper-detection demo.

## Demo UI

A Streamlit app with five screens:

| Screen | What it shows |
|---|---|
| Overview | Event counts, charts, and one attacker IP seen by multiple vendors |
| Before and after | The same SSH probe as Fortinet, Cisco ASA and Suricata wrote it, then as one unified table |
| Events | Filterable table of normalized events |
| Trace and integrity | Raw event next to its normalized record, with a live SHA-256 tamper check |
| Parser packs | Every YAML parser pack in `parsers/`, with a box to test any raw log line against it live |

## What is real and what is illustrative

| Item | Status |
|---|---|
| Detection, parsing, normalization for 4 vendors (Fortinet, Cisco ASA, Suricata, pfSense) | Real |
| YAML-driven parser engine, with 2 working packs (Fortinet, and "Acme Firewall" as a proof that a brand-new vendor can be onboarded with zero Python code) | Real |
| Raw vault: SHA-256 hashing and hash chain, tamper detection | Real (computed live) |
| CLI pipeline (`cli.py`) | Real |
| Demo UI, filters, charts, live parser-pack testing | Real, reads the CLI's actual output |
| Docker image (build + run tested locally) | Real |
| YAML packs for Suricata and pfSense | Not yet written (those two still use Python-only parsers) |
| Streaming ingestion, Kafka, production storage (ClickHouse/OpenSearch/MinIO/Parquet), SIEM/data-lake connectors | Planned, not implemented |

The sample logs in `sample_logs/` are simplified and illustrative. They were not captured from real devices. Timestamps without a timezone are assumed to be UTC.

## Run it locally

Requirements: Python 3.11+ and Git (Docker optional, see below).

```
git clone https://github.com/adarshasus1620-collab/universal-log-preprocessing-framework.git
cd universal-log-preprocessing-framework
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

On macOS or Linux, use `source venv/bin/activate` instead.

**Run the pipeline** (parses all sample logs, writes normalized output and the raw vault):

```
cd ulpf
python cli.py ..\sample_logs\fortinet.log ..\sample_logs\cisco_asa.log ..\sample_logs\suricata_eve.json ..\sample_logs\pfsense.log --out ..\output\events.jsonl
cd ..
```

**Run the demo UI:**

```
streamlit run app.py
```

Then open http://localhost:8501 in a browser.

## Run with Docker

```
docker build -t ulpf-demo .
docker run -p 8501:8501 ulpf-demo
```

Then open http://localhost:8501. This runs fully self-contained, with no host Python installation required, and needs no internet access at runtime, matching the air-gapped deployment requirement.

## Repository layout

```
app.py                   Streamlit demo UI
Dockerfile                Container build definition
requirements.txt          Python dependencies
sample_logs/              Sample logs: Fortinet, Cisco ASA, Suricata, pfSense
parsers/                  YAML parser packs (fortinet.yaml, acme_firewall.yaml)
ulpf/
  schema.py                Unified event schema (Pydantic)
  detect.py                 Format auto-detection
  parse.py                   Fortinet parser
  parse_cisco.py              Cisco ASA parser
  parse_suricata.py            Suricata parser
  parse_pfsense.py              pfSense parser
  yaml_parser.py                 YAML-driven parser engine
  vault.py                        Raw vault: SHA-256 + hash chain
  cli.py                           Pipeline runner
output/                   events.jsonl and vault.jsonl (generated by cli.py)
.streamlit/config.toml    Theme settings
```

## Roadmap

- [x] Unified schema (Pydantic)
- [x] Parsers for Fortinet, Cisco ASA, Suricata and pfSense
- [x] Format auto-detection
- [x] Raw vault with SHA-256 trace IDs and hash chain
- [x] YAML-driven parser engine, with plug-and-play onboarding demonstrated
- [x] Demo UI connected to real pipeline output
- [x] Docker packaging
- [ ] YAML parser packs for Suricata and pfSense
- [ ] Streaming ingestion (Kafka) and horizontal scaling
- [ ] Production storage: data lake (Parquet), OpenSearch/ClickHouse, object storage (MinIO)
- [ ] SIEM / data lake output connectors
- [ ] Offline / air-gapped install bundle refinement

## Planned technology

Python, Pydantic, PyYAML, Streamlit (prototype UI), Docker (implemented). Planned for production: Kafka, ClickHouse or OpenSearch, MinIO.