# Changelog

## 0.2.0 — 2026-11-17
- Validate JSONL schemas, timezones, IPv4/IPv6 and detector configuration.
- Add line-numbered CLI diagnostics with no raw values or partial output.
- Canonicalize IPv6 and expose threshold/window options.
- Expand to 12 tests; add SHA-pinned Python 3.10/3.12/3.14 CI.
- Published implementation: `68e065235db632bd678ae80fc1c19cc844249c63`. All three Python jobs passed in [GitHub Actions](https://github.com/rajatsehrawat0/sentinel-triage/actions/runs/44045371784).

## 0.1.0 — 2026-11-11
- Initial rolling-window authentication detector.
- Synthetic fixture and five passing standalone tests.
- Documented limitations; no production deployment claimed.

