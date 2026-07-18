# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them via [GitHub Private Vulnerability Reporting](https://github.com/ikaruscareer/SafeAI/security/advisories/new).

You should receive a response within 72 hours. If the issue is confirmed, we will:

1. Acknowledge the report
2. Develop and test a fix
3. Release a patched version
4. Credit the reporter (unless anonymity is requested)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.0-beta | Yes |

## Security Model

SafeAI is a static analyzer. Key security properties:

- **No code execution** — scanned code is never imported, executed, or evaluated
- **No network access** — analysis is fully offline; no telemetry or external calls
- **Secret masking** — credential values in findings are masked in all report formats
- **Deterministic** — identical input always produces identical output

See [SECURITY_MODEL.md](SECURITY_MODEL.md) for the full threat model and trust score documentation.

## Scope

The following are considered security issues in SafeAI itself:

- Arbitrary code execution triggered by scanning a malicious repository
- Path traversal when reading or writing files
- Unmasked secret values in generated reports
- Malicious YAML causing unsafe deserialization
- Regular expression denial of service (ReDoS) against crafted input

The following are **not** SafeAI vulnerabilities (they are the findings the tool is designed to report):

- Vulnerabilities discovered in scanned codebases
- False positive or false negative detections (report as regular bugs)
