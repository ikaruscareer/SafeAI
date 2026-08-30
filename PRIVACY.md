# SafeAI — Privacy & Telemetry

**SafeAI collects no data by default. Usage telemetry is opt-in, anonymous, and documented in full below.**

---

## What triggers telemetry to be sent

Nothing. If you do nothing, nothing is ever sent.

Telemetry is disabled by default. It is only activated when a user explicitly enables it via one of:

- `safeai telemetry on` (CLI command)
- Setting the environment variable `SAFEAI_TELEMETRY=1`

If you have never typed either of these, SafeAI has never sent any data.

---

## What is collected (when telemetry is enabled)

When telemetry is explicitly enabled, SafeAI sends a single anonymous usage event at the start of a scan. The event contains **only** the following fields:

| Field | Description | Example |
|-------|-------------|---------|
| `schema_version` | Event schema version (integer) | `1` |
| `safeai_version` | SafeAI version (semver) | `2.0.0` |
| `python_version` | Python major.minor only | `3.12` |
| `os_family` | OS family: `linux`, `darwin`, or `windows` | `linux` |
| `invocation_context` | How SafeAI was invoked: `cli`, `github-action`, `ci-other`, or `unknown` | `cli` |
| `command` | Command invoked: `scan`, `init`, `registry`, `welcome`, or `other` | `scan` |
| `install_id` | Random, locally-generated, non-reversible UUID (not tied to email, username, or machine identifiers) | `a1b2c3d4-...` |
| `date` | Date only (ISO 8601), not full timestamp | `2026-08-30` |

---

## What is never collected

- File paths, repository names, or repository URLs
- Source code, file contents, or code snippets
- Finding content, finding messages, or finding details
- Secret values, API keys, tokens, or credentials
- Environment variable values (only the presence/absence of specific CI-indicator variables is checked)
- IP address (the HTTP transport layer may incidentally see the sending IP the way any HTTP request does; the server-side process must not persist it)
- Hostname, username, or machine identifiers
- Command-line arguments or flags (only the constrained command name is sent)
- Any data from the scanned repository

---

## How to disable telemetry

Telemetry can be disabled at any time using any of these methods:

1. **CLI command:**
   ```bash
   safeai telemetry off
   ```

2. **Environment variable:**
   ```bash
   export SAFEAI_TELEMETRY=0
   ```

3. **`DO_NOT_TRACK` convention:**
   ```bash
   export DO_NOT_TRACK=1
   ```
   If `DO_NOT_TRACK` is set to `1` (any casing), telemetry is off regardless of any other setting, with no override possible.

4. **CI auto-detection:** Telemetry is automatically disabled in CI environments even if `SAFEAI_TELEMETRY=1` is set, unless `SAFEAI_TELEMETRY_IN_CI=1` is also explicitly set. This is a deliberate two-key-turn safety design.

---

## How to verify the claims yourself

SafeAI is open source (Apache 2.0). You can verify the telemetry implementation by reading:

- `safeai/telemetry/config.py` — reads env vars and the local on/off state file; implements the precedence rules
- `safeai/telemetry/schema.py` — builds the event dict; the field set is tested against this document
- `safeai/telemetry/client.py` — sends the event; uses `urllib.request` (stdlib) with a 2-second timeout; any failure is silent and non-fatal
- `tests/test_telemetry.py` — comprehensive test suite verifying the privacy contract

No network call is made unless telemetry is explicitly enabled and the endpoint is configured.

---

## Retention and deletion

- **Raw events:** No longer than 30 days. Individual event records are deleted after 30 days.
- **Aggregated statistics:** Up to 90 days. Aggregated data (e.g., "X scans used v2.0.0") may be retained for up to 90 days to track adoption trends.
- No raw event is retained past the 30-day period.
- Users can request deletion of their installation's data by opening an issue with their `install_id` (visible via `safeai telemetry status`).

---

## Who to contact

For privacy questions or concerns, open an issue at:

https://github.com/ikaruscareer/SafeAI/issues

---

## Data contract version

This document is the authoritative specification for SafeAI's telemetry data contract. Any implementation must match this document field-for-field. If a future version of SafeAI changes the telemetry schema, this document will be updated in the same release.

**Version:** 1.0 (2026-08-30)
