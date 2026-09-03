# SafeAI — Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SafeAI, please report it
responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

Email **security@ikaruscareer.com** with:

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact assessment
- Suggested fix (if any)

### Response Targets

| Phase | Target |
|-------|--------|
| Acknowledgment | 48 hours |
| Triage & severity assessment | 5 business days |
| Fix development (critical) | 10 business days |
| Fix development (high) | 30 business days |
| Fix development (medium/low) | Next scheduled release |
| Public disclosure | After fix is released |

### What We Consider a Vulnerability

- **Rule bypass**: a pattern that should trigger a finding but doesn't
- **False-negative injection**: code that evades detection due to a parser bug
- **Supply chain**: dependency confusion or typosquatting in `pyproject.toml`
- **CI/CD**: GitHub Action inputs that allow code execution
- **Data exfiltration**: telemetry or reporting that leaks sensitive data

### What We Don't Consider Vulnerabilities

- Heuristic false positives (by design — see LIMITATIONS.md)
- Framework adapter coverage gaps (use GitHub Issues)
- Feature requests (use GitHub Issues)

## Ownership

| Area | Owner | Response Target |
|------|-------|-----------------|
| Core scanner | @ikaruscareer | 5 business days |
| Framework adapters | @ikaruscareer | 10 business days |
| GitHub Action | @ikaruscareer | 5 business days |
| Rule content | Community | Best effort |
| Documentation | Community | Best effort |

## False Positive Reports

Open a GitHub Issue with the `false-positive` label. Include:

- Rule ID that fired
- Source file and line number
- Why you believe it's a false positive
- SafeAI version and scan command used

Target response: 10 business days for triage, fix in next patch release.

## Breaking Regression Reports

Open a GitHub Issue with the `regression` label. Include:

- What changed (worked in vX.Y, broken in vX.Z)
- Reproduction steps
- Expected vs actual behavior

Target response: 5 business days for triage, fix in next patch release.
