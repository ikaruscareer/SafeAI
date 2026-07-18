# SafeAI User Guide — Early Preview

> 🌐 [safeai-analyzer.ikaruscareer.com](https://safeai-analyzer.ikaruscareer.com) — project landing page

## Table of Contents

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Running Scans](#running-scans)
4. [CLI Commands](#cli-commands)
5. [Input Formats](#input-formats)
6. [Supported Project Types](#supported-project-types)
7. [Understanding Results](#understanding-results)
8. [Reports](#reports)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

---

## Installation

### System Requirements

- Python 3.11 or 3.12
- Operating system: Linux, macOS, Windows
- No external service dependencies
- No GPU required

### Install from Source

```bash
git clone https://github.com/ikaruscareer/SafeAI.git
cd SafeAI
pip install -e .
```

Dependencies installed:

- `PyYAML` — YAML configuration file parsing

The SafeAI package itself is installed in editable mode, providing both the
`safeai` command and `python -m safeai`.

### Verify Installation

```bash
safeai scan --help
# or equivalently:
python -m safeai scan --help
```

Expected output:

```
usage: safeai scan [-h] [--sarif SARIF] [--json JSON_PATH] [--html HTML_PATH]
                   [--rules RULES] [--fail-on {critical,high,medium}]
                   [--verbose]
                   directory
```

---

## Configuration

SafeAI requires no configuration file. By default it uses built-in rules from `rules/base_rules.yaml`.

### Custom Rules Directory

You can supply custom rule YAML files:

```bash
python -m safeai scan . --rules ./my-rules/
```

Custom rules merge with built-in rules. Duplicate rule IDs overwrite severity and description.

### Rule File Format

```yaml
- id: CUSTOM_RULE
  description: Description of the rule
  severity: high
  owasp_llm: LLM06
```

### Exit Threshold

```bash
python -m safeai scan . --fail-on high   # exit 1 if any high+ finding
```

Valid values: `critical` (default), `high`, `medium`.

---

## Running Scans

### Basic Scan

```bash
python -m safeai scan /path/to/project
```

### Generate All Reports

```bash
python -m safeai scan /path/to/project \
    --sarif results.sarif \
    --json results.json \
    --html report.html
```

### Skip SARIF Output

```bash
python -m safeai scan /path/to/project --sarif ""
```

---

## CLI Commands

### `scan` — Run a static AI risk scan

```
usage: safeai scan [-h] [--sarif SARIF] [--json JSON_PATH]
                   [--html HTML_PATH] [--rules RULES]
                   [--fail-on {critical,high,medium}] [--verbose]
                   directory
```

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `directory` | positional | required | Target project directory |
| `--sarif` | string | `report.sarif` | SARIF output file path |
| `--json` | string | — | JSON output file path |
| `--html` | string | — | HTML report output path |
| `--rules` | string | built-in | Path to custom rules directory |
| `--fail-on` | choice | `critical` | Minimum severity for non-zero exit |
| `--verbose` | flag | off | Enable verbose scanner output |

---

## Input Formats

SafeAI scans files with the following extensions:

- `.py` — Python source files (primary target for framework detection)
- `.json` — JSON configuration files (MCP configs, Bedrock agents)
- `.yaml`, `.yml` — YAML configuration files (Azure Foundry, MCP configs)

### Dependency Files

SafeAI also scans these files for framework detection:

- `requirements.txt` — Python pip dependencies
- `Pipfile` — Pipenv dependencies
- `pyproject.toml` — Python project metadata
- `package.json` — Node.js project metadata

---

## Supported Project Types

SafeAI is designed for projects that build or use AI agents, including:

- **LangGraph applications** — graph-based agent workflows
- **CrewAI projects** — multi-agent task orchestrators
- **LangChain applications** — chain-based LLM applications
- **Semantic Kernel projects** — plugin-based AI orchestrators
- **OpenAI Agents SDK projects** — agent-based assistants
- **Microsoft Agent Framework projects** — Azure AI Agent Service
- **Azure AI Foundry projects** — Azure AI configuration
- **Bedrock Agent projects** — AWS Bedrock agent definitions

---

## Understanding Results

### Findings

Each finding contains:

| Field | Description |
|-------|-------------|
| `rule_id` | Unique rule identifier |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `message` | Human-readable description |
| `file` | Source file path |
| `line` | Line number |
| `owasp_llm` | OWASP LLM category reference |
| `evidence` | Matching source code excerpt |
| `reason` | Explanation of the risk |
| `risk_category` | `Capability`, `Governance`, `Safety`, `Identity`, `Integration`, `Autonomy`, `Enterprise Readiness` |
| `affected_framework` | Detected framework name |
| `affected_capability` | Capability category affected |
| `score_contribution` | Points contributed to overall risk score |
| `remediation` | Recommended fix |
| `confidence` | Detection confidence (0.0–1.0) |
| `source` | Detection method (`ast`, `configuration`, `regex`, etc.) |
| `resolved_definition` | Resolved symbol origin (if import graph resolved) |
| `provenance_frameworks` | All frameworks that identified this finding |
| `schema_version` | (MCP only) Schema version used for validation |
| `validation_rule` | (MCP only) Validation rule that triggered |
| `affected_object` | (MCP only) MCP configuration section affected |

### Severity Levels

| Level | Meaning |
|-------|---------|
| Critical | Immediate risk of compromise (e.g., prompt injection, hardcoded secrets) |
| High | Significant capability exposure (e.g., shell execution, missing auth) |
| Medium | Moderate risk (e.g., filesystem access, database access) |
| Low | Informational (e.g., MCP reference without config) |
| Info | Scanner metadata |

---

## Risk Scores

### Trust Score (0–100)

SafeAI computes a deterministic risk score across 7 categories:

| Category | Description |
|----------|-------------|
| Capability | Risk from detected agent capabilities |
| Governance | Risk from missing governance controls |
| Safety | Risk from prompt safety issues |
| Identity | Risk from credential exposure |
| Integration | Risk from MCP and external integrations |
| Autonomy | Risk from autonomous agent behavior |
| Enterprise Readiness | Risk from missing enterprise controls |

### Score Interpretation

| Score Range | Meaning |
|-------------|---------|
| 0–20 | Excellent governance, low risk |
| 21–40 | Good, minor risks |
| 41–60 | Moderate risk, review findings |
| 61–80 | Significant risk, remediate before deployment |
| 81–100 | Critical risk, stop deployment |

---

## Reports

### Terminal Summary

Printed to stdout. Includes:

- Files scanned
- Detected frameworks
- MCP asset count
- Overall AI Risk Score
- Finding count by severity
- Finding list with severity, location, message

### JSON Report

Full scanner output as JSON. Compatible with custom tooling.

### SARIF 2.1.0

SARIF format for integration with GitHub Advanced Security, Azure DevOps, and other SARIF-compliant tools. Each finding includes:

- `ruleId` — rule identifier
- `message.text` — finding description
- `locations[].physicalLocation` — file and line number
- `properties` — extended data (OWASP category, risk category, evidence, remediation)

### HTML Report

Self-contained HTML report with:

- Executive Summary
- Detected Frameworks
- Capability Matrix
- Risk Summary
- Trust Scores
- Governance Summary
- Findings table with evidence and recommendations

Responsive design, print-friendly.

---

## Troubleshooting

### No frameworks detected

- Ensure the project contains Python files with recognized framework imports
- Check that dependency files are present (`requirements.txt`, etc.)
- Run with `--verbose` to see scan details

### No findings reported

- The project may not use AI agent frameworks
- The project may use frameworks not yet supported
- Run `--json` to inspect raw output

### Scan fails with ModuleNotFoundError

- Install the package: `pip install -e .`
- Ensure you are running from the correct directory

### False positive capabilities

- Capability detection uses AST + regex fallback. Some regex patterns may trigger on unrelated code
- Check `confidence` and `source` fields: `ast` detections are more reliable than `regex`
- Submit false positive reports to the project issue tracker

---

## FAQ

**Q: Does SafeAI execute my code?**  
A: No. SafeAI is a static analyzer. It never imports, executes, or evaluates any code in the scanned project.

**Q: Does SafeAI call LLMs or external APIs?**  
A: No. SafeAI runs entirely offline with no external dependencies.

**Q: Can SafeAI detect prompt injection at runtime?**  
A: No. SafeAI detects static patterns that may lead to prompt injection. Runtime testing requires separate dynamic analysis tools.

**Q: Is SafeAI specific to any programming language?**  
A: The current Early Preview focuses on Python projects. Framework detection uses Python imports and dependency manifests.

**Q: Does SafeAI support JavaScript/TypeScript projects?**  
A: Limited support via `package.json` dependency detection and JSON/YAML configuration scanning.

**Q: How are trust scores calculated?**  
A: Each finding contributes weighted penalty points to one of 7 categories. Scores start at 100 and decrease as penalties accumulate. The formula is: `category_score = clamp(100 - sum(weighted_contributions), 0, 100)`. The overall score is the average of all category scores.

**Q: Can I trust the confidence values?**  
A: Confidence values indicate detection reliability. AST-based detections typically score 0.8–0.9. Regex fallback detections score 0.45–0.5. Cross-framework arbitration uses max confidence.

**Q: How do I add support for a new framework?**  
A: See CONTRIBUTING.md for the framework adapter pattern and registration process.
