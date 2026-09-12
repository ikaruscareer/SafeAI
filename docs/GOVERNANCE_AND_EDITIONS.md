# Governance and Editions

SafeAI is Apache-2.0, offline, and local-first. This document states what
the Community Edition permanently includes, what a Corporate Edition may
add as separate components, and the non-negotiables that protect
contributors and users. Linked from `README.md`, `CONTRIBUTING.md`, and
`ROADMAP.md`.

## Community Edition permanently includes

- Scanner engine and all analyzers, with detection depth and accuracy
  improvements over time.
- Framework and MCP adapters.
- JSON, SARIF, HTML, terminal, PR comment, scorecard, and canonical
  manifest (`safeai-manifest.json`, Contract v1) outputs.
- Local KYA registry, baselines, portable import/export, and CI gating
  (quality gates, `--fail-on-*`, `--pr-comment-post`).
- Policy-as-code, named profiles, and local governed suppressions.
- Plugin SDK and community rule/policy authoring when shipped (CE 2.3).

## Corporate Edition may include (separately installed, separately licensed)

- Cross-repository aggregation and organization ownership/review workflow.
- SSO/RBAC/audit retention; central exceptions and policy distribution.
- Signed, tamper-evident organizational evidence retention.
- Credentialed, read-only live IAM/RBAC/network-policy reconciliation.
- SIEM/GRC/ITSM integrations and optional opt-in intelligence services.

## Explicit non-negotiables

- Community scans do not phone home: no network calls, no telemetry
  unless explicitly opted in, no accounts. Network activity occurs only
  through explicitly enabled integration commands (currently only
  `--pr-comment-post`, which announces itself; see
  `docs/guides/REPORTING_GUIDE.md`).
- Corporate is never required to use Community Edition.
- Corporate never receives deliberately superior detection verdicts —
  detection gating by edition is forbidden.
- Runtime interception, sandboxing, identity issuance, and production
  monitoring do not enter the Community scanner core.
- Static analysis evidence does not certify compliance, runtime safety,
  or deployed authorization (see every report's assurance boundary).

## MCP and machine-configuration scope

Repository-local configuration scanning is the default. Reading
user/global/out-of-repository MCP and IDE configuration
(`--mcp-ide-scopes`, user machine scopes) is **opt-in only**. Such scans
must mark provenance on every out-of-repository entry, and
out-of-repository evidence is **excluded from portable exports and
manifests by default** unless an explicit opt-in export flag is supplied.
SafeAI never silently ingests personal configuration into CI artifacts.
(Decision record: `docs/adr/0003-mcp-scope-and-export-privacy.md`.)
