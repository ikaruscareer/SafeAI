# SafeAI Benchmarks

Reproducible, offline evidence for what the scanner detects — and where it
is expected to be uncertain. See `BENCHMARKS.md` (repo root) for the
published corpus table, versioned results, and non-claims.

## Layout

- `catalog.yml` — the pinned corpus (v1.0, 20 fixtures). Each entry states
  intent, kind, target, and expectations. Update expectations only
  intentionally, with the reason in `notes`.
- `results/` — machine-readable run payloads (one per SafeAI version).
  Regenerated on every run; committed so regressions are diffable.
- `scripts/run_benchmarks.py` (repo `scripts/`) — the deterministic runner.

## Fixture intents

- `positive` — the listed rules must fire at the listed severities.
- `negative` — no finding at medium or above may fire.
- `regression` — like positive, plus it guards a previously fixed behavior.
- `escalation` — the listed `ESC_*` ids must appear in a before/after diff.
- `limitation` — recorded and reported, never fails (known ambiguity).

Most scan fixtures reference `tests/fixtures/` (single maintenance source).
Small synthetic fixtures (MCP tool JSON, escalation pairs) are inline in
the catalog with provenance notes. Inline fixtures contain no real
secrets, private code, or live credentials.

## Run

```bash
python scripts/run_benchmarks.py --subset smoke   # PRs: fast subset
python scripts/run_benchmarks.py --subset full    # releases: full corpus, blocking
```

Exit codes: 0 pass · 1 expected outcome regressed · 2 usage/catalog error.
Durations are environmental measurements, never asserted.

## Contributing a fixture

Prefer converting reports into fixtures over one-off scan issues:

- Missed capability → new `positive` entry (or extend an existing one).
- False positive → new `negative` entry reproducing it.
- Escalation gap → new `escalation` entry (before/after pair).
- Ambiguity → new `limitation` entry documenting it.

Add the catalog entry, run the full corpus, and record results in
`BENCHMARKS.md`.
