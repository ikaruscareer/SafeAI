# SafeAI P0 Fuzzing

These coverage-guided fuzz targets exercise untrusted scan-report and manifest inputs without running scanned repositories, installing target dependencies, making network calls, or using secrets.

## Targets

- `fuzz_sanitise_report.py`: hostile JSON-derived findings through the public sanitisation pipeline. It asserts that recognised secret-like prefixes are not emitted in the public summary.
- `fuzz_report_schema.py`: hostile JSON through `community-scans/report-schema.json` validation.
- `fuzz_targets_manifest.py`: hostile YAML through community target-manifest parsing and structural validation.

## Local smoke run

```bash
python -m venv .venv-fuzz
source .venv-fuzz/bin/activate
python -m pip install -r fuzz/requirements.txt

timeout 60s python fuzz/fuzz_sanitise_report.py
timeout 60s python fuzz/fuzz_report_schema.py
timeout 60s python fuzz/fuzz_targets_manifest.py
```

A timeout exit code is expected for a healthy continuous fuzz loop. A non-timeout non-zero exit indicates a crash or assertion requiring investigation.

## Scope

This is in-repository fuzz coverage. It does not claim that SafeAI has been accepted into Google OSS-Fuzz. OSS-Fuzz enrolment requires a separately maintained upstream integration and acceptance by the OSS-Fuzz project.
