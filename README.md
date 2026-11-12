# Sentinel Triage
### Explainable authentication-event triage

`Prototype` · `Python 3.10+` · `Synthetic demo data` · `November 2026`

## The problem
A security analyst needs to prioritise suspicious sign-ins without treating every failed password as an incident.

## Try it in 60 seconds
From this project directory, run:

```sh
python3 main.py events.jsonl
```

No dependencies are required for the deterministic path. Run the standalone regression suite with `python3 -m unittest -v test_main.py`.

## Architecture
JSONL → schema checks → time sorting → rolling window → evidence-rich alert

## What exists
Read [main.py](main.py) for the complete working core. Its small size makes decisions and assumptions auditable. See [design notes](DESIGN.md) for threat boundaries and validation.

## Honest limitations
Detection works on synthetic fixtures. No SIEM ingestion, IP enrichment, distributed attack detection or production false-positive measurements.

## Next release
Add labelled benign and malicious samples; measure precision and recall; add a read-only SIEM adapter.

## Evidence over claims
This repository starts with a reproducible demo. Hardware recordings, deployment measurements and customer outcomes will be added only when they exist. Initial code was developed with AI assistance and requires owner review before being represented in interviews.

## Example output

The fixture produces one `AUTH-001` alert: three failures followed by a successful login for the same user and source IP. This is an investigation lead, not proof of compromise.

## Input contract

One JSON object per line with `timestamp` (ISO 8601 with timezone), `user`, `source_ip`, and `outcome` (`failure` or `success`). Events are sorted before evaluation. The default threshold is three failures within 300 seconds. A success clears that user/IP failure history. The CLI loads the full file into memory; use bounded fixtures.
