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

SafeAI computes a **deterministic trust score** (0–100) from scan findings.

The score is **always reproducible** — given the same codebase and rules, the score is identical regardless of environment or execution order.

### Score Formula

```
Category Score = clamp(100 - sum(weighted_contributions), 0, 100)
Overall Score = average of all Category Scores
```

### Weighted Contribution per Finding

| Severity | Base Points | Notes |
|----------|-------------|-------|
| critical | 25 | Multiplied by rule weight (0.5-1.5) |
| high | 15 | Multiplied by category weight |
| medium | 8 | Multiplied by category weight |
| low | 4 | Multiplied by category weight |
| info | 1 | Minimal impact |

### Risk Categories (7)

| Category | Default Weight | Example Threats |
|----------|---------------|-----------------|
| Safety | 1.0 | Prompt injection, delimiter issues, system leak |
| Identity | 0.8 | Hardcoded secrets, credential exposure |
| Autonomy | 1.0 | Autonomous agent capabilities |
| Antipattern | 0.5 | Coding anti-patterns |
| MCP | 1.0 | MCP misconfiguration |
| Dependency | 0.7 | AI framework dependency risk indicators |
| Capability | 0.6 | Dangerous capabilities |

### Confidence System

Each finding has a confidence level:

| Confidence | Description | Weight |
|------------|-------------|--------|
| high | Verified via AST/import analysis | 1.0 |
| medium | Detected via config or dependency analysis | 0.75 |
| low | Detected via regex or heuristic | 0.5 |

Findings below a configurable confidence threshold (default: `low`) are excluded from scoring but included in reports.

---

## Category Coverage

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

SafeAI supports four output formats:

| Format | Use Case |
|--------|----------|
| Terminal (default) | CI/CD pipelines, quick developer feedback |
| JSON | Machine parsing, integration with other tools |
| SARIF 2.1.0 | Integration with GitHub Advanced Security and other SARIF-compatible tools |
| HTML | Detailed interactive reports for team review |

### Output Security

- **Secret masking** — credential values detected by the data leakage analyzer are masked in finding evidence (first four characters retained for identification, remainder replaced with `***MASKED***`) across all output formats: terminal, JSON, SARIF, and HTML.
- **Relative paths** — file paths in findings are relativized to the scanned root, so reports do not expose the scanner host's filesystem layout and SARIF consumers (e.g. GitHub code scanning) can map results to repository files.
- **HTML output** uses a self-contained file with no external dependencies.

---

## Security of SafeAI Itself

SafeAI follows these security practices:

1. **No code execution** — Scans source code without importing or executing it
2. **No network access** — All analysis is local; no telemetry, no API calls
3. **Deterministic** — Identical output for identical input
4. **Minimal dependencies** — Only Python standard library + `yaml` + `packaging`
