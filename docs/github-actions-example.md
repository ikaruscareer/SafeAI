# Minimal GitHub Actions Example

A small CI integration should scan the agent manifest that is actually being reviewed and publish the machine-readable report as an artifact. Keep the policy decision explicit: teams may fail on new findings, capability escalations, or only on selected severities.

The example below is intentionally schematic so it does not prescribe a repository-specific command or hide a version pin:

```yaml
name: SafeAI scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install SafeAI
        run: pip install safeai==<reviewed-version>
      - name: Scan manifest
        run: safeai scan path/to/manifest --format sarif --output safeai.sarif
      - uses: actions/upload-artifact@v4
        with:
          name: safeai-report
          path: safeai.sarif
```

Do not place credentials in the manifest or echo private prompts into CI logs. Review the generated report as evidence, and keep baseline changes separate from unrelated implementation changes.
