# SafeAI — Security Model

This document describes the security model and threat coverage of the SafeAI Static AI Capability & Risk Analyzer.

---

## Threat Model

SafeAI is designed to detect sources of risk in AI agent codebases *before* runtime. It operates as a **static analysis** tool — it examines source code, configuration files, and dependency manifests without executing the code.

### What SafeAI Detects

| Threat Category | OWASP LLM | Description |
|-----------------|-----------|-------------|
| Prompt Injection | LLM01 | Untrusted input interpolated into prompts; missing delimiters; system prompt leakage; role override attempts |
| Data Leakage | LLM02 | Hardcoded API keys, tokens, passwords, and environment variable references to secrets |
| Excessive Agency | LLM06 | Shell execution, filesystem access, HTTP access, database access, code execution, autonomous loops |
| Supply Chain | — | AI framework dependency detection (name/version extraction from manifests) |
| MCP Misconfiguration | — | Missing auth, weak auth, missing permissions, exposed endpoints, hardcoded secrets in MCP configs |

### What SafeAI Does NOT Detect

- Runtime prompt injection (dynamic, context-dependent)
- Model-level vulnerabilities (e.g., adversarial examples, model inversion)
- Infrastructure-level threats (e.g., network segmentation, IAM policies)
- Insider threats or compromised supply chain packages
- Business logic flaws

---

## Trust Score Model

SafeAI computes a **deterministic trust score** (0–100) from scan findings. The
score is **always reproducible** — given the same codebase and rules, the score
is identical regardless of environment or execution order.

```
Category Score = clamp(100 - sum(weighted_contributions), 0, 100)
Overall Score  = average of all Category Scores
```

Severity point values (`critical=25, high=15, medium=8, low=4, info=1`) are
defined in `safeai/severity.py`; each finding's contribution is multiplied by
its category weight (default `1.0`). The 7 risk categories are Capability,
Governance, Safety, Identity, Integration, Autonomy, and Enterprise Readiness.

Each finding also carries a confidence label (`high|medium|low`) reflecting how
it was detected (AST/import vs config vs regex). Confidence is reported for
review; scoring weights are driven by severity and category.

> **Full scoring reference:** see [RISK_MODEL.md](RISK_MODEL.md) for the
> complete Trust Score model and the separate 0–10 Security Scorecard, including
> how to read the numbers safely.

---

## Detection Coverage by Threat Area

These are detection groupings (not the 7 scoring categories — see
[RISK_MODEL.md](RISK_MODEL.md)).

### Safety (Prompt Injection Prevention)
- **PROMPT_INJECTION**: Direct user input interpolation into prompt strings
- **PROMPT_DELIMITER**: Missing separation between system and user content
- **PROMPT_SYSTEM_LEAK**: Potential exposure of system prompts
- **PROMPT_ROLE_OVERRIDE**: Attempts to bypass system instructions

### Identity (Data Leakage Prevention)
- **DATA_LEAKAGE**: Hardcoded API keys, tokens, passwords
- Environment variable references to secrets (indirect leakage)

### Autonomy (Agent Control)
- **CAP_AUTONOMY**: Unbounded autonomous agent loops
- Missing iteration limits or human-in-the-loop controls

### Capability (Excessive Agency)
- **CAP_shell**: Shell command execution
- **CAP_filesystem**: Filesystem read/write operations
- **CAP_http**: External HTTP requests
- **CAP_db**: Database access
- **CAP_code_exec**: Dynamic code execution

### MCP (Model Context Protocol)
- Missing or weak authentication
- Missing permissions configuration
- Exposed endpoints
- Hardcoded secrets in configuration
- Dangerous tool definitions

---

## Output Formats

SafeAI supports these output formats:

| Format | Use Case |
|--------|----------|
| Terminal (default) | CI/CD pipelines, quick developer feedback |
| JSON | Machine parsing, integration with other tools |
| SARIF 2.1.0 | Integration with GitHub Advanced Security and other SARIF-compatible tools |
| HTML | Detailed interactive reports for team review |
| KYA manifest | Canonical `safeai-manifest.json` evidence contract |
| PR comment | Reviewer-facing capability-escalation summary (Markdown) |
| Security Scorecard | 0–10 reviewer score (Markdown / JSON) |

### Output Security

- **Secret masking** — credential values detected by the data leakage analyzer are masked in finding evidence (first four characters retained for identification, remainder replaced with `***MASKED***`) across all output formats.
- **Relative paths** — file paths in findings are relativized to the scanned root, so reports do not expose the scanner host's filesystem layout and SARIF consumers (e.g. GitHub code scanning) can map results to repository files.
- **HTML output** uses a self-contained file with no external dependencies.
- **Scorecard injection safety** — untrusted finding text is Markdown-escaped and secret-redacted before it reaches the Scorecard or the GitHub Actions step summary.

---

## Security of SafeAI Itself

SafeAI follows these security practices:

1. **No code execution** — Scans source code without importing or executing it
2. **No network access** — All analysis is local; no telemetry, no API calls
3. **Deterministic** — Identical output for identical input
4. **Minimal dependencies** — Python standard library + `PyYAML` for the core scanner (the community-scan pipeline pins its own additional dependencies separately)
