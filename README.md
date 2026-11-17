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


## Input validation milestone

The CLI rejects malformed JSON, missing/invalid fields, invalid IP addresses and timestamps without timezones. It returns exit code `2`, a short diagnostic on stderr, and no partial JSON output. JSON/schema errors include the physical input line number without echoing event values. Successful runs return code `0` and a JSON alert array (possibly empty).

IPv6 spellings are canonicalized before grouping. User identifiers remain case-sensitive and are not trimmed. Extra fields are ignored. Input ties preserve input order. A failure exactly 300 seconds before success is included; one older than the configured window is excluded.

```sh
python3 main.py events.jsonl --threshold 3 --window-seconds 300
```

Threshold must be a positive integer; window must be finite and nonnegative. The API applies the same event validation as the CLI. All records are validated before detection; it does not silently skip bad records. Reading and sorting still happen in memory, so this is a bounded-file prototype, not a streaming ingestion service.

## Checks

`python3 -m unittest -v test_main.py` covers 12 tests, including subprocess CLI checks, invalid records/configuration, window boundaries, source isolation and IPv6 normalization. A GitHub Actions workflow is prepared for Python 3.10, 3.12 and 3.14; local results do not imply that hosted CI has run. Actions are pinned to verified commit SHAs.
