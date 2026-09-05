# SafeAI Developer Guide

This guide covers three common uses of SafeAI:

1. Regular local scans.
2. GitHub Actions scans.
3. Finding and interpreting results.

SafeAI is local-first static analysis. It does not prove exploitability, runtime safety, or the absence of vulnerabilities.

## 1. Regular scan

Create an isolated environment outside the repository being scanned:

```bash
python3 -m venv .safeai-venv
source .safeai-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "git+https://github.com/ikaruscareer/SafeAI.git@v1.6"
safeai --version
```

Run without installing or executing the target project's dependencies:

```bash
mkdir -p reports
set +e
safeai scan . \
  --no-registry \
  --fail-on critical \
  --json reports/safeai.json \
  --html reports/safeai.html \
  --sarif reports/safeai.sarif \
  --scorecard reports/safeai-scorecard.md \
  --scorecard-json reports/safeai-scorecard.json
SAFEAI_EXIT=$?
set -e
echo "SafeAI exit code: ${SAFEAI_EXIT}"
```

Preserve reports even when the exit code is 1. A non-zero result may be an intentional policy failure caused by a critical finding, rather than a scanner crash.

Record reproducibility data:

```bash
git rev-parse HEAD
safeai --version
python --version
```

Useful options include `--baseline`, `--fail-on-new`, `--fail-on-escalation`, and `--scorecard-fail-under SCORE`.

## 2. Scan with GitHub Actions

A minimal workflow is:

```yaml
name: SafeAI scan

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  safeai:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run SafeAI
        uses: ikaruscareer/SafeAI@v1.6
        with:
          path: .
          fail-on: critical
          no-registry: true
          sarif: reports/safeai.sarif
          scorecard: reports/safeai-scorecard.md
          scorecard-json: reports/safeai-scorecard.json
          scorecard-summary: true
          extra-args: '["--json", "reports/safeai.json", "--html", "reports/safeai.html"]'

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: safeai-reports-${{ github.run_id }}
          path: reports/
          if-no-files-found: warn
```

For production, pin third-party Actions to reviewed full commit SHAs, use `persist-credentials: false`, keep permissions least-privilege, avoid target dependency installation and code execution, and use `if: always()` when uploading reports.

## 3. Find and interpret results

| Output | Use |
|---|---|
| JSON | Detailed machine-readable report. |
| HTML | Human-readable findings and assurance context. |
| SARIF | GitHub code-scanning and other static-analysis integrations. |
| Markdown scorecard | Quick score, status, category, severity, and coverage summary. |
| JSON scorecard | Automated score and policy consumption. |
| Job summary | Scorecard shown in the Actions run summary. |

Start with:

```bash
less reports/safeai-scorecard.md
python -m json.tool reports/safeai-scorecard.json | less
```

Review critical and high findings first, then new/regressed findings, capability escalations, and coverage limitations. Check the rule ID, location, evidence, confidence, inferred-versus-confirmed status, and remediation guidance.

`pass`, `warn`, and `fail` describe the configured policy outcome. They do not directly describe exploitability. A scan may return exit code 1 because a policy threshold was crossed while still producing valid reports.

Use these disclosure classifications:

- `informational`: general observation.
- `review_recommended`: needs maintainer or runtime validation.
- `high_confidence_security_concern`: strong static evidence requiring prompt review.
- `potentially_sensitive`: secrets, personal data, private endpoints, or sensitive configuration may be involved.
- `not_publishable`: retain privately until independently reviewed.

Safe public language is:

> SafeAI identified a finding requiring maintainer review.

Do not call a project vulnerable without independent validation and an appropriate responsible-disclosure decision.

Before sharing results, remove secrets, personal data, private URLs, raw source blocks, and weaponisable evidence. Send sensitive findings privately through the repository's security policy.

## Baselines and assurance

For repeat scans, compare the same commit first to check deterministic output, then use a reviewed SafeAI manifest as `--baseline`. Review new, existing, regressed, resolved, suppressed, and unknown findings, plus tool-level capability escalations.

SafeAI can inspect source and repository-local configuration evidence. It cannot verify deployed IAM, runtime identity, network policy, actual runtime behavior, or dynamically constructed bindings.
