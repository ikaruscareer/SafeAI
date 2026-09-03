# SafeAI — Upgrade Guide: v1.x → v2.0.0

This guide covers all changes in SafeAI v2.0.0 that may affect your
existing integrations, policies, CI pipelines, or reporting scripts.

## Breaking Changes

**None.** SafeAI v2.0.0 is fully backward compatible. All v1.x scans
continue to work. No existing rule IDs are removed or renamed. Exit codes,
JSON schema, and SARIF output are additive-only.

## New Rule IDs

Two new governance rules are now detected. Custom policies referencing
`GOV_*` rules may need updating to account for these:

| Rule ID | Severity | Detection |
|---------|----------|-----------|
| `GOV_MAX_ITERATIONS_MISSING` | `high` | Agent loops with no `max_iterations` bound: `while True`, `for` with huge range, recursive calls without depth limit |
| `GOV_RECURSION_GUARD_MISSING` | `medium` | Recursive tool calls without a recursion depth guard |

**Impact**: If your `--fail-on` threshold is `high` or `critical`, repos
with unbounded loops will now fail. If your policy references a count of
`GOV_*` rules, the expected count increases from 8 to 10.

## New JSON Field: `failure_class_matrix`

The JSON report now includes a `failure_class_matrix` top-level field.
This is an additive change — existing fields are unchanged.

```json
{
  "failure_class_matrix": [
    {
      "failure_class": "unbounded_recursion",
      "covered": false,
      "rules_missing": ["GOV_MAX_ITERATIONS_MISSING", "GOV_RECURSION_GUARD_MISSING"],
      "rules_found": [],
      "findings": []
    }
  ]
}
```

**Impact**: Consumers should handle the field's absence gracefully (older
reports do not include it).

## New Scannable File: `.windsurfrules`

The orchestrator now scans `.windsurfrules` files (Windsurf IDE config).
Repos containing this file will produce new findings from the Windsurf
framework adapter.

**Impact**: CI pipelines using `--fail-on high` may see new findings if
the repo has a `.windsurfrules` with unrestricted tool grants.

## KYA Manifest Schema v1.3

The KYA manifest bumps from v1.2 to v1.3. The only change is the
`evidence_type` field on every finding. This is additive — v1.2 manifests
are still accepted by `--baseline`.

**Impact**: None for most consumers. If your manifest consumer validates
against a strict schema, update to v1.3.

## Upgrade Steps

### 1. Install v2.0.0

```bash
pip install --upgrade SafeAI-Static-Analyzer==2.0.0
```

### 2. Re-run your baseline scan

```bash
safeai scan . --json report.json --baseline old-report.json
```

Review any new `GOV_MAX_ITERATIONS_MISSING` or `GOV_RECURSION_GUARD_MISSING`
findings. These are real governance gaps — fix them, or suppress them in
your policy if they are false positives.

### 3. Check the failure-class coverage matrix

Open the HTML report or inspect `report.json["failure_class_matrix"]`.
Look for `covered: false` entries — these are failure modes your agent is
not prepared for (per static analysis).

### 4. Update CI pipelines (if applicable)

- If you count `GOV_*` findings in a threshold check, update from 8 to 10
  controls.
- If you reference `GOV_MAX_ITERATIONS_MISSING` or `GOV_RECURSION_GUARD_MISSING`
  in a policy, add it to your allowlist or fix the code.

### 5. No action needed for

- **Rule IDs**: all existing IDs unchanged.
- **Exit codes**: 0, 1, 2 unchanged.
- **SARIF output**: additive fields only.
- **Action inputs/outputs**: all existing inputs/outputs unchanged.
- **`.cursorrules`**: already scanned in v1.9.1; no change.

## Rollback

If v2.0.0 causes issues, revert to the last stable release:

```bash
pip install SafeAI-Static-Analyzer==1.9.1
```

No data migration is required — the KYA registry and manifests are
forward-compatible.
