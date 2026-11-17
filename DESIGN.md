# Design and operations

## Data flow
UTF-8 JSONL → per-line JSON/schema validation → canonical IP addresses → timestamp sort → user/IP failure queues → JSON alerts.

## Failure boundary
All records must pass validation before any result is emitted. Invalid JSON and schema errors report the physical line number. Raw input values are omitted from diagnostics; missing files and invalid encoding produce generic errors. The library raises ValueError with the event index. The CLI returns 2 and leaves stdout empty on input failure.

## Detection semantics
A success after at least the configured failure threshold inside the inclusive time window emits AUTH-001 and clears that user/IP bucket. Equivalent IPv6 representations share a bucket. User identifiers are case-sensitive; no other identity normalization occurs. Sorting is stable for equal timestamps. Detection cannot distinguish a legitimate password retry from a takeover.

## Trust and resource boundaries
This is a local, standard-library CLI. It makes no network calls and has no model integration. Records and alerts may contain personal identifiers; use only synthetic fixtures in the public repository. The entire input is loaded and sorted in memory. There are no input size caps, streaming support, distributed correlation, production precision/recall measurements or SIEM adapters.

## Validation
Run `python3 -m unittest -v test_main.py` and `python3 main.py events.jsonl`. The 12 local tests validate deterministic behavior and CLI errors, not operational effectiveness. Hosted CI is configured separately; do not claim hosted success until a workflow run completes.

## Next milestone
Evaluate against a labelled synthetic corpus, include benign retry cases and document detection gaps before adding an ingestion adapter.
