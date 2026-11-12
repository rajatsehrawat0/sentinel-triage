# Design and operations

## Data flow
JSONL → schema checks → time sorting → rolling window → evidence-rich alert

## Trust boundaries
Treat incoming records and model output as untrusted. Demos use synthetic data. Do not expose a local inference endpoint to the internet. Restrict any future service to authenticated users and bounded request sizes.

## Validation
Run the root test suite. Inspect the demo output against the input fixture. These tests validate core behavior only, not deployment or adversarial robustness.

## Failure handling
CLI input errors fail visibly with a nonzero exit. This prototype does not silently retry or mutate external services. Validate data before using it in a deployed workflow. Optional model-service errors propagate; check that a local model is installed and the service is available.

## Operational boundary
Detection works on synthetic fixtures. No SIEM ingestion, IP enrichment, distributed attack detection or production false-positive measurements.

## Planned implementation
Add labelled benign and malicious samples; measure precision and recall; add a read-only SIEM adapter.

## Release criteria
Add a reproducible change, a relevant test, updated setup instructions and a dated changelog entry. Record measured results with dataset and methodology; do not invent benchmarks.
