# SafeAI — Static AI Capability & Risk Analyzer

[![CI](https://github.com/ikaruscareer/SafeAI/actions/workflows/ci.yml/badge.svg)](https://github.com/ikaruscareer/SafeAI/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ikaruscareer/SafeAI/badge)](https://scorecard.dev/viewer/?uri=github.com/ikaruscareer/SafeAI)
[![Website](https://img.shields.io/badge/web-safeai--analyzer.ikaruscareer.com-0f766e)](https://safeai-analyzer.ikaruscareer.com)
[![Latest Release](https://img.shields.io/badge/latest-v2.0.1-0f766e)](https://github.com/ikaruscareer/SafeAI/releases/tag/v2.0.1)
[![Best Practices](https://bestpractices.dev/projects/14126/badge)](https://www.bestpractices.dev/en/projects/14126)

Enjoying SafeAI? A ⭐ on [GitHub](https://github.com/ikaruscareer/SafeAI) helps more security teams find it.

**SafeAI** is a static analysis tool that scans AI application source code for security risks, capability exposure, and governance gaps. It runs entirely offline, never executes agents or calls LLMs, and integrates into CI/CD pipelines.

> 🌐 [safeai-analyzer.ikaruscareer.com](https://safeai-analyzer.ikaruscareer.com) — project landing page

<img width="1024" height="1024" alt="SafeAI_Agent_Software_Static_Analyzer" src="https://github.com/user-attachments/assets/de40f40b-14b9-4cd6-bc2c-27e81e8253fe" />

---

Know Your Agent (KYA)

SafeAI now turns static scan results into a private, historical inventory of AI agents and their findings.

<img width="1024" height="1024" alt="SafeAI_Know_Your_Agent" src="https://github.com/user-attachments/assets/47923b8d-f7c3-44c7-8890-ddb82d04838d" />

---

## Why SafeAI?

Traditional application security tools (SAST, SCA, IaC scanning) are not designed for AI agent systems. AI applications introduce new risk surfaces:

- **Prompt injection** — untrusted input flows into model prompts
- **Agent tool misuse** — agents with filesystem, shell, or database access
- **Capability sprawl** — frameworks expose capabilities without visibility
- **MCP exposure** — Model Context Protocol endpoints and tools
- **Governance gaps** — missing authentication, permissions, audit trails

SafeAI fills this gap by analyzing frameworks, agents, tools, capabilities, and MCP integrations at rest—before deployment.

SafeAI analyzes AI applications without executing them, helping developers discover capabilities, identify potential risks, and improve governance early in the software lifecycle.

Designed to be lightweight, explainable, and community-driven, SafeAI aims to become an open foundation for AI capability and risk analysis.

SafeAI sits before runtime guardrails and red-teaming tools in the security lifecycle. It scans agent source code at commit time — detecting framework-specific capabilities, MCP misconfigurations, and prompt injection patterns — before you ever deploy an agent to staging. It does not replace runtime tools (Microsoft AGT), evaluation frameworks (LangSmith, DeepEval), or red-teaming scanners (Promptfoo, Garak). It complements them: find the risk in code first, then validate at runtime.

<img width="1024" height="1024" alt="SafeAI_Concept" src="https://github.com/user-attachments/assets/c07999b2-79d5-4200-9eec-ce1ab4e63cc8" />


---

## Key Features

| Feature | Description |
|---------|-------------|
| **Framework Detection** | Detects and parses 17 AI agent frameworks (AST + config + regex, no mutual exclusion) |
| **Tool Identity & Access Modes** | Capabilities attributed to named tools (agent / MCP server / skill / tool / workflow node) on an access scale `none < read < write < mutate < execute`; inferred modes are flagged, never overstated |
| **Capability Discovery** | Maps 19 capability categories (shell, filesystem, network, database, memory, MCP, ...) with evidence, confidence, and provenance |
| **Capability Escalation Detection** | Per-tool authority diffs between scans (new shell, read→write widening, new MCP server, removed approval gate, ...) — 14 rules, including gating-aware subsumption |
| **AI Risk Analysis** | Categorizes findings into 7 risk categories with weighted trust scoring (0–100) |
| **Prompt Risk Analysis** | Detects injection patterns, delimiter issues, system leak, role override |
| **Governance Signal Detection** | Detects missing operational controls: timeout, retry, approval, audit, rate limiting, circuit breaker, backpressure, health check (8 `GOV_*` rules) |
| **Component-Level Analysis** | Skills, prompt files, tool definitions, model configurations, workflow templates |
| **Data-Flow Analysis** | Tracks untrusted input propagation into sensitive sinks (prompts, tool calls, shell, file writes, HTTP, database); placeholder-aware confidence |
| **Control Mappings** | OWASP LLM / Agentic + NIST AI RMF mapping layer for framework-based filtering and grouping |
| **Deep Claude Code Analysis** | Structural analysis of `.claude/settings.json`, permissions, slash commands, subagents, hooks, `.mcp.json` |
| **MCP Analysis** | Discovers MCP servers, clients, tools, resources, and validates configuration |
| **Data Leakage Detection** | Flags hardcoded secrets, tokens, and API keys (redacted in all outputs) |
| **KYA Shared Registry** | Append-only SQLite registry of scan-derived agent records, shared org-wide; `list`/`show`/`history`/`diff`/`export`/`components` |
| **Baseline & Escalation Gating** | `--fail-on-new` for new/regressed findings, `--fail-on-escalation` for authority changes, `--pr-comment` PR summaries |
| **Policy-as-Code & Suppressions** | `allow`/`warn`/`require_review`/`deny` policy with selectors; required-reason suppressions |
| **Assurance Boundary** | Every scan states exactly what it did and could not verify — never a fixed disclaimer |
| **Security Scorecard** | Deterministic 0–10 score with per-category breakdown and `pass`/`warn`/`fail` outcome; `--scorecard`, `--scorecard-json`, `--scorecard-summary`, and `--scorecard-fail-under` to gate CI on a minimum score |
| **CI/CD Integration** | SARIF 2.1.0 output, exit codes, GitHub Actions **Marketplace action** and workflow included |
| **Community Scan** | Governed private-pilot workflow for scanning public third-party agent frameworks with responsible disclosure (`community-scans/`) — private by default, human-reviewed before any publication |
| **Multi-Format Reports** | Terminal, JSON, SARIF 2.1.0, HTML, canonical KYA manifest, PR comment, Security Scorecard |
| **Cross-File Analysis** | Import graph, symbol resolution, and project graph |
| **Confidence-Arbitrated Parsing** | Multiple parsers per file, merged with provenance |

---

## How It Works

```
Source Code
    │
    ▼
File Collection — Python, YAML, JSON, .prompt, and .claude configs;
                 prunes VCS, caches, oversized files, and SafeAI's own artifacts
    │
    ▼
Framework Detection — 16 parsers (AST + config + regex), all run on all files;
                     import graph and dependency manifests
    │
    ▼
Static Analysis — semantic docs, component extraction, capability / prompt /
                 data-leakage / MCP / Claude Code analyzers
    │
    ▼
Capability Mapping — per-tool identity (agent, MCP server, skill, tool,
                    workflow node) + access modes (read < write < mutate < execute)
    │
    ▼
Risk Rules — rule engine with severity, confidence, provenance, stable fingerprints
    │
    ▼
Trust Score — deterministic 0–100 score across 7 weighted risk categories
    │
    ▼
KYA Pipeline — finding normalization, suppressions, baseline (new/regressed),
              policy-as-code, capability escalation diff
    │
    ▼
Registry & Reports — shared SQLite registry; terminal, JSON, SARIF 2.1.0, HTML,
                     canonical manifest, PR comment
```
<img width="1024" height="1024" alt="SafeAI_AI_Capability_Risk_Analyzer" src="https://github.com/user-attachments/assets/618f9ebc-030b-40c9-a98e-b0a5c41e07cc" />

---

## Supported Frameworks

| Framework | Detection | Discovery | Capability Analysis | Risk Analysis | Status |
|-----------|-----------|-----------|-------------------|---------------|--------|
| LangGraph | ✔ | Partial | Partial | Partial | Partial |
| CrewAI | ✔ | Partial | Partial | Partial | Partial |
| LangChain | ✔ | Partial | Partial | Partial | Partial |
| Semantic Kernel | ✔ | Partial | Partial | Partial | Partial |
| OpenAI Agents SDK | ✔ | Partial | Partial | Partial | Partial |
| Microsoft Agent Framework | ✔ | Partial | Minimal | Minimal | Experimental |
| Azure AI Foundry | ✔ | Minimal | Minimal | Minimal | Experimental |
| Bedrock Agent | ✔ | Minimal | Minimal | Minimal | Experimental |
| Claude Code | ✔ (deep) | Deep | Partial | Partial | Partial |
| Google ADK | ✔ | Partial | Minimal | Minimal | Experimental |
| Mastra | ✔ | Partial | Minimal | Minimal | Experimental |
| Haystack | ✔ | Partial | Minimal | Minimal | Experimental |
| LlamaIndex | ✔ | Partial | Minimal | Minimal | Experimental |
| Dify | ✔ | Minimal | Minimal | Minimal | Experimental |
| n8n | ✔ | Partial | Minimal | Minimal | Experimental |
| Cursor (.cursorrules) | ✔ | Minimal | Minimal | Minimal | Experimental |
| Windsurf (.windsurfrules) | ✔ | Minimal | Minimal | Minimal | Experimental |


### Framework Support Details

- **LangGraph** — detects `StateGraph`, `add_edge`, `bind_tools`, nodes, models
- **CrewAI** — detects `Agent`, `Task`, tools, models
- **AutoGen** — detects `AssistantAgent`, `UserProxyAgent`, `register_for_llm`, `register_function`, models
- **LangChain** — detects `AgentExecutor`, `Chain`, `Tool`, `PromptTemplate`, models
- **Semantic Kernel** — detects `Kernel.invoke`, plugins, functions, skills, memory
- **OpenAI Agents SDK** — detects `Agent`, tools, handoffs, MCP references
- **Microsoft Agent Framework** — detects `AgentClient`, tools, workflows, Azure models
- **Azure AI Foundry** — detects YAML configurations with Azure resources
- **Bedrock Agent** — detects JSON configurations with Bedrock resources
- **Claude Code** — structural analysis of `.claude/settings.json`, permission
  grants, `.mcp.json`, slash commands, subagent definitions, and lifecycle hooks
- **Google ADK** — detects ADK agent, workflow, tool, and model patterns
- **Mastra** — detects Mastra agents, workflows, tools, and model references
- **Haystack** — detects Haystack pipelines, agents, tools, and retrievers
- **LlamaIndex** — detects agents, tools, indexes, and model references
- **Dify** — detects Dify workflow and agent configuration files
- **n8n** — detects n8n workflow exports, nodes, and connections
- **Cursor (.cursorrules)** — detects declared tools/permissions and
  capability-relevant keywords (shell, filesystem, HTTP, database) in the
  IDE's rules config, JSON, YAML, or free text

Maturity is on the scale defined in [`FRAMEWORK_SUPPORT.md`](FRAMEWORK_SUPPORT.md):
**Partial** = reliable detection and discovery with capability/risk analysis over
common patterns; **Experimental** = detection and basic artifact discovery with
limited framework-specific analysis. No framework is rated fully **Supported**
yet — SafeAI is in early preview and deliberately does not overclaim coverage.

### Framework Test Coverage (v1.8.0)

Representative test fixtures and validation tests for framework detection:

| Framework | Test | Fixture | Contributor |
|-----------|------|---------|-------------|
| LangGraph | `test_langgraph_framework.py` | `fixtures/langgraph/representative/graph.py` | @adnqcr7-code [#63] |
| LlamaIndex | `test_llamaindex_framework.py` | `fixtures/llamaindex/representative/agent.py` | @adnqcr7-code [#61] |
| CrewAI | `test_crewai_framework.py` | `fixtures/crewai/representative/crew.py` | @adnqcr7-code [#62] |
| Claude Code | `test_claude_code_deep.py` | `fixtures/claude_code/compatibility/` | @adnqcr7-code [#59] |

---

## Supported Capabilities

SafeAI fingerprints capabilities at the framework object level and via fallback regex patterns. Each capability includes evidence, confidence score, resolved definition, and provenance.

<img width="1024" height="1024" alt="SafeAI_Capability_Risk_Report" src="https://github.com/user-attachments/assets/ae924e9d-650f-4480-b5b2-2984e5c57087" />

| Capability | Category | Risk Impact |
|------------|----------|-------------|
| Shell Execution | Shell | Command injection, host compromise |
| Filesystem Access | Filesystem | Data exfiltration, file tampering |
| Browser Automation | Browser | UI-based attacks, credential theft |
| Planning / Orchestration | Planner | Autonomous decision chain risk |
| Agent Delegation | Delegation | Unchecked sub-agent authority |
| Memory / Checkpoint | Memory | Data retention across sessions |
| RAG / Retrieval | RAG | Document exfiltration, prompt injection via documents |
| GitHub Integration | GitHub | Repository access, secret leakage |
| Slack Integration | Slack | Channel monitoring, message injection |
| Email Integration | Email | Phishing, data exfiltration |
| Database Access | Databases | SQL injection, data breach |
| Cloud Services | Cloud | Cloud resource abuse, cost escalation |
| External APIs | External APIs | Third-party data exfiltration |
| MCP Services | MCP | Exposed endpoints, unauthorized tool access |
| Human Approval | Human Approval | Approval bypass risk |
| Multi-Agent | Multi-Agent | Delegation-based privilege escalation |
| Container | Container | Container orchestration abuse (Docker, Kubernetes) |
| Collaboration | Collaboration | Cross-system coordination risk |
| Untrusted Input | Untrusted Input | Injection surface into agent pipelines |

> **Note:** A capability is detected wherever the evidence lives — through a
> framework adapter, a direct pattern detector (for example Docker,
> Kubernetes, S3, Slack, Jira, browser automation, GCP), or MCP
> configuration analysis. Capabilities that only MCP configuration exposes
> today (e.g. email, human approval gates) are still flagged — the tool is
> reported with an unattributed identity rather than a guessed owner.

---

## Know Your Agent (KYA) — Shared Registry

Every scan automatically builds a **private "Know Your Agent" registry** of
scan-derived agent records — no server, no account, no network call, no
source upload. Scans from every project accumulate in **one shared SQLite
database** (`SAFEAI_REGISTRY` env var or `~/.safeai/registry.db`), so
`safeai registry list` shows the whole organization's agents from any folder.

```bash
safeai scan .                              # scan + accumulate into the shared registry
safeai scan . --manifest safeai-manifest.json   # also write the canonical KYA manifest
safeai scan . --html report.html                # interactive HTML report (risk gauge, escalations)
safeai registry list                       # agents/workflows from every scanned project
safeai registry list --format html > registry.html   # shareable HTML inventory
safeai registry show <agent-id>            # latest KYA record
safeai registry history <agent-id>         # all scans for an agent
safeai registry diff <agent-id> --from previous --to latest
safeai registry export --format json --output inventory.json
safeai registry export --format html --output inventory.html
```

What you get on the first run:

- A static scan ran successfully.
- The shared registry was initialized (`SAFEAI_REGISTRY` or
  `~/.safeai/registry.db`).
- One or more KYA agent records were created with stable identities.
- Findings carry confidence, provenance, remediation, and stable fingerprints.
- No source code or secrets are uploaded or stored in output artifacts.

**KYA records static evidence, not runtime truth.** It answers "what does the
source/configuration say this agent can do?" — never "what is this agent doing
in production?" See [REGISTRY.md](REGISTRY.md), [KYA_MANIFEST.md](KYA_MANIFEST.md),
and [LIMITATIONS.md](LIMITATIONS.md).

CI note: registry persistence is auto-disabled for bare CI jobs (the `CI`
env var). Use `--registry "$RUNNER_TEMP/registry.db"`, set `SAFEAI_REGISTRY`
to a shared path, or use `--no-registry` for ephemeral scans.

---

## Installation

### Requirements

- Python 3.11, 3.12, or 3.13
- PyYAML (for YAML configuration parsing)

### Install from source

```bash
git clone https://github.com/ikaruscareer/SafeAI.git
cd SafeAI
pip install -e .
```

### Install development dependencies

```bash
pip install -e ".[dev]"
```

---

## Privacy & Telemetry

SafeAI collects no data by default. Usage telemetry is opt-in, anonymous, and fully documented in [`PRIVACY.md`](PRIVACY.md). If you do nothing, nothing is ever sent. See `PRIVACY.md` for the complete data contract, what is never collected, and how to disable telemetry.

---

## CLI Usage

```bash
python -m safeai scan <directory> [options]
```

```bash
python -m safeai registry <subcommand> [options]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `directory` | required | Path to scan |
| `--sarif` | `report.sarif` | SARIF output path (empty string to skip) |
| `--json` | — | JSON output path |
| `--html` | — | HTML report output path |
| `--manifest` | — | Canonical KYA manifest output path (`safeai-manifest.json`) |
| `--baseline` | — | Prior manifest/report for new/existing comparison |
| `--fail-on-new` | off | With `--baseline`: fail only on new/regressed findings |
| `--policy` | `.safeai/policy.yml` | Policy-as-code YAML file |
| `--suppressions` | `.safeai/suppressions.yml` | Suppressions YAML file |
| `--registry` | shared (`SAFEAI_REGISTRY`/`~/.safeai/registry.db`) | Registry database path |
| `--no-registry` | off | Skip registry persistence |
| `--strict-registry` | off | Fail the scan if registry persistence fails |
| `--pr-comment` | — | Write a reviewer-facing Markdown summary of capability escalations to this path (never posted anywhere) |
| `--pr-comment-stdout` | off | Print the PR comment Markdown to stdout |
| `--fail-on-escalation` | — | Fail if a capability escalation at or above `critical`, `high`, or `medium` is detected (requires `--baseline`) |
| `--scorecard` / `--scorecard-md` | — | Write the SafeAI Security Scorecard as Markdown to this path |
| `--scorecard-json` | — | Write the SafeAI Security Scorecard as JSON (conforms to `safeai/scorecard-schema.json`) |
| `--scorecard-summary` | — | Append the Security Scorecard to the GitHub Actions step summary (`$GITHUB_STEP_SUMMARY`) |
| `--scorecard-fail-under` | — | Fail the scan if the Security Scorecard score is below this value (`0`–`10`) |
| `--rules` | built-in | Custom rules directory |
| `--fail-on` | `critical` | Exit code threshold: `critical`, `high`, `medium` |
| `--verbose` | — | Enable verbose output |

### Exit Codes

| Code | Condition |
|------|-----------|
| 0 | No findings at or above threshold; policy outcome not `deny` |
| 1 | Finding at or above threshold, or policy outcome `deny` |
| 2 | Operational error (e.g. `--strict-registry` persistence failure) |

Suppressed findings never trigger exit code 1. With `--fail-on-new`, only
findings classified `new` or `regressed` against the baseline are gated.

### Common 1.4 Workflows

```bash
# canonical manifest + baseline seed
python -m safeai scan . --manifest safeai-manifest.json

# CI/PR scan: fail only for new or regressed findings
python -m safeai scan . --baseline safeai-manifest.json --fail-on-new --fail-on high

# CI/PR scan: fail on capability escalations and render a PR comment
python -m safeai scan . --baseline safeai-manifest.json \
  --fail-on-escalation high --pr-comment comment.md

# inspect the shared KYA registry
python -m safeai registry list
python -m safeai registry show <agent-id>
python -m safeai registry history <agent-id>
python -m safeai registry diff <agent-id> --from previous --to latest
python -m safeai registry export --format json --output safeai-kya-inventory.json
```

---

## Example Output

> See [REPORTING_GUIDE.md](./REPORTING_GUIDE.md) for a complete guide to
> interpreting each output format (HTML, JSON, SARIF, PR comments, scorecard,
> registry) and triaging findings.

### Terminal

```
SafeAI Scan Summary
Files: 12
Frameworks: langgraph, crewai
MCP assets: 2
Overall AI Risk Score: 73
critical: 1
high: 3
medium: 5
Findings:
[critical] app.py:10 - Untrusted input interpolated into prompt
[high] app.py:22 - Capability detected: shell_execution
[high] mcp.json:1 - MCP configuration does not define authentication
```

### Example: LangGraph agent with MCP

```json
{
  "Framework": "LangGraph",
  "Capabilities": ["Planner", "Memory", "Filesystem", "MCP"],
  "Risk Score": 73,
  "Findings": 9,
  "Critical": 1,
  "High": 3
}
```

---

## CI/CD Integration

### GitHub Actions — SafeAI Static Analysis

[![SafeAI Static Analysis](https://img.shields.io/badge/Available%20on-GitHub%20Marketplace-2088FF?logo=github)](https://github.com/marketplace/actions/safeai-static-analysis)

SafeAI ships a ready-to-use composite action for GitHub-hosted runners. The
action is a thin, pure-Python driver: it installs the `SafeAI-Static-Analyzer`
PyPI distribution into the runner's Python, runs `python -m safeai scan` on
your repository, preserves the tool's native exit codes, and always writes a
SARIF 2.1.0 artifact (even when the scan fails). It never evaluates any input
through a shell, never executes your agent code, and makes no network calls
beyond installing the PyPI package.

Use it with `uses: ikaruscareer/SafeAI@<ref>` (see [Version pinning](#version-pinning)).

```yaml
name: safeai-scan
on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  safeai-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Scan with SafeAI
        id: safeai
        uses: ikaruscareer/SafeAI@v1.0.0
        with:
          path: .
          fail-on: critical

      - name: Upload SARIF to GitHub Advanced Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.safeai.outputs.sarif-path }}
```

The `if: always()` on the upload step matters: SafeAI fails the job when a
finding meets the `fail-on` threshold, but the SARIF file is still written so
code-scanning alerts are still created. `permissions: contents: read` is the
least privilege the action needs — it only reads your repository and writes
reports inside the workspace.

#### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory or file to scan. Relative paths are resolved against `GITHUB_WORKSPACE`. |
| `version` | *(latest stable)* | Exact SafeAI PyPI version to install (e.g. `1.5.0`). Empty installs the latest release of `SafeAI-Static-Analyzer`. |
| `fail-on` | `critical` | Minimum severity that fails the job: `critical`, `high`, or `medium`. |
| `sarif` | `safeai-results.sarif` | SARIF 2.1.0 output path, relative to the repo root. Empty string disables SARIF. |
| `rules` | *(none)* | Path to a custom rules directory (`--rules`). |
| `baseline` | *(none)* | Prior `safeai-manifest.json`/JSON report for new/regressed and escalation comparison (`--baseline`). |
| `fail-on-new` | `false` | With `baseline`: fail only on NEW or REGRESSED findings at or above `fail-on` (`--fail-on-new`). |
| `fail-on-escalation` | *(none)* | Minimum capability-escalation severity that fails the job: `critical`, `high`, or `medium`. Requires `baseline`. |
| `no-registry` | `true` | Skip local KYA registry persistence (`--no-registry`), keeping scans ephemeral. |
| `extra-args` | `[]` | Extra scan arguments as a JSON array of strings (e.g. `["--verbose"]`). Never shell-evaluated. |

#### Outputs

| Output | Description |
|--------|-------------|
| `sarif-path` | Absolute path to the written SARIF file (empty if SARIF was disabled or the scan did not produce one). |

#### Exit behavior

The action passes SafeAI's exit code through unchanged:

| Code | Condition |
|------|-----------|
| 0 | No findings at or above `fail-on`; policy outcome not `deny`. |
| 1 | Finding at or above threshold, new/regressed finding with `fail-on-new`, escalation with `fail-on-escalation`, or policy `deny`. |
| 2 | Operational error — missing scan path, invalid input, or missing Python 3.11+. |

Even on exit 1, the SARIF file (and any HTML/JSON reports you request via
`extra-args`) are written so downstream steps can keep working. The action
prints a GitHub `::warning::` if a scan failed without producing SARIF.

#### More examples

PR gating on new findings + escalation review:

```yaml
- name: Scan with SafeAI
  uses: ikaruscareer/SafeAI@v1.0.0
  with:
    path: .
    baseline: safeai-manifest.json
    fail-on-new: 'true'
    fail-on-escalation: high
    sarif: safeai-results.sarif
```

Custom rules, verbose logs, and an HTML report (all argv-passed, no shell):

```yaml
- name: Scan with SafeAI
  uses: ikaruscareer/SafeAI@v1.0.0
  with:
    path: ./agents
    rules: .safeai/rules
    extra-args: '["--verbose", "--html", "report.html"]'
```

#### Version pinning

Exact versioning is required for Marketplace-verified actions. Pin to a
release tag:

```yaml
uses: ikaruscareer/SafeAI@v1.0.0
```

and optionally relax to the major tag `@v1` for bugfix updates. For the
strictest supply-chain posture, pin to a full commit SHA:

```yaml
uses: ikaruscareer/SafeAI@<40-char-commit-sha>
```

The `version` input is independent: it controls the SafeAI **PyPI** package
installed into the runner, while the `uses:` ref controls which **action**
release you run.

**Recommended posture — pin both.** The `version` input defaults to the
*latest stable* SafeAI release on PyPI (per the Marketplace design), but
pinning it makes every scan reproducible and avoids surprising tool/action
pairings. Set the `version` input to the exact release the action was
validated against:

```yaml
- uses: ikaruscareer/SafeAI@v1.0.0
  with:
    version: "1.5.0"
```

If you rely on the default, know that SafeAI may upgrade underneath you on a
future run; combined with `uses: @v1`, that is two moving parts. For
maximum supply-chain control, pin the action to a commit SHA *and* set an
explicit `version`.

#### Troubleshooting

- **`SafeAI requires Python 3.11+`** — the runner's default Python is too old
  or missing. Add `actions/setup-python@v5` with `python-version: '3.12'`
  before this action.
- **Scan fails but you expected it to pass** — lower the threshold or switch
  to baseline-gated `fail-on-new`, which only fails on regressions.
- **No SARIF uploaded despite `if: always()`** — confirm the `sarif` input is
  non-empty and that `${{ steps.safeai.outputs.sarif-path }}` is referenced
  with the same `id:` you set on the action step.
- **Security scanners flag `${{ inputs.* }}` interpolation** — this is safe:
  action inputs are passed to the driver as environment variables with
  `env:`, and the driver hands them to the tool as an argv list. No input is
  ever interpolated into `run:`.
- **Registry warnings** — `no-registry: true` is the default precisely so
  scans on shared runners stay ephemeral and never touch a shared
  `~/.safeai/registry.db`.

The action's own test workflow (`.github/workflows/action-test.yml`) runs the
action against fixture repositories, builds and inspects the wheel, and
validates SARIF output on every commit.

### GitHub Actions (manual workflow)

A self-scan workflow is also included at `.github/workflows/ci.yml`. To use
SafeAI directly in your project:

```yaml
jobs:
  safeai-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install SafeAI
        run: |
          pip install -e .
      - name: Run scan
        run: |
          python -m safeai scan . \
            --sarif results.sarif \
            --html report.html \
            --manifest safeai-manifest.json \
            --no-registry
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
safeai-scan:
  image: python:3.12
  script:
    - pip install -e .
    - python -m safeai scan . --sarif results.sarif --html report.html --no-registry
  artifacts:
    paths:
      - results.sarif
      - report.html
```

### Azure DevOps

```yaml
- task: PythonScript@0
  inputs:
    scriptSource: 'inline'
    script: |
      import subprocess
      subprocess.run(["pip", "install", "-e", "."])
      subprocess.run(["python", "-m", "safeai", "scan", ".", "--sarif", "$(Build.ArtifactStagingDirectory)/results.sarif", "--no-registry"])
```

### Capability escalation in CI

A capability *escalation* is a change between two scans where a tool gains
more authority than it had before — a new shell capability, a filesystem
access widening from read to write, a new MCP server, an approval gate
being removed, and so on (see `RULES_REFERENCE.md` and `KYA_MANIFEST.md`
for the full rule list). Reviewing these on every pull request is more
targeted than reviewing every finding, because most findings on a mature
codebase are pre-existing and already accepted; an escalation is new by
definition.

`--fail-on-escalation` gates the scan on escalation severity, and
`--pr-comment` writes a short Markdown summary you can post as a PR
comment. SafeAI itself never posts anything anywhere and makes no network
calls of any kind — generating the comment and publishing it are two
separate steps, and the second one is entirely up to your CI workflow.

```yaml
name: safeai-escalation-check
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  safeai-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install SafeAI
        run: pip install -e .

      - name: Fetch baseline manifest from the base branch
        run: |
          git fetch origin "${{ github.event.pull_request.base.ref }}" --depth=1
          git show "origin/${{ github.event.pull_request.base.ref }}:safeai-manifest.json" \
            > safeai-manifest.json || echo '{}' > safeai-manifest.json

      - name: Run scan
        run: |
          safeai scan . \
            --baseline safeai-manifest.json \
            --pr-comment comment.md \
            --fail-on-escalation high

      - name: Post or update PR comment
        if: always()
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh pr comment "${{ github.event.pull_request.number }}" \
            --edit-last --body-file comment.md \
            || gh pr comment "${{ github.event.pull_request.number }}" \
            --body-file comment.md
```

The `gh pr comment --edit-last` call updates SafeAI's own previous comment
in place on repeat pushes, rather than adding a new one each time; it fails
when there is no previous comment to edit (for example, on the first push),
so the fallback plain `gh pr comment` handles that case. The `--fail-on-escalation`
step runs before the comment step so the workflow's exit code still reflects
the scan outcome; `if: always()` on the comment step makes sure the comment
is posted even when the scan step fails the job.

### SARIF Integration

SafeAI outputs SARIF 2.1.0 format, compatible with GitHub Advanced Security, Azure DevOps, and other SARIF-compliant tools.

---

## Roadmap

See [ROADMAP.md](./ROADMAP.md) for the detailed roadmap.

- **Completed in 1.3**: KYA manifest, baseline/new-regressed gating,
  suppressions, policy-as-code, local SQLite registry, registry CLI.
- **Completed in 1.4** (beta): tool-centric capability model (tool identity
  + access modes), 14 capability escalation rules, capability diff v2,
  deep Claude Code analysis, PR comment + CI context, assurance boundary,
  registry schema v2, shared org-wide registry default.
- **Completed in 1.5**: environment/credential dependency inventory and
  dependency-to-capability correlation, first **stable** release
  (`1.5.0`, classifier `5 - Production/Stable`), and a GitHub Actions
  **Marketplace action** (`action.yml` composite action plus a validated
  `scripts/safeai-action.py` driver and `action-test.yml` CI workflow).
- **Completed in 1.9.0**: component version/hash in registry, `safeai init`,
  governance signal detection (8 `GOV_*` rules including circuit breaker,
  backpressure, health check), control mappings (OWASP LLM/Agentic + NIST
  AI RMF), AutoGen + LangGraph adapter completion, heuristic data-flow
  analysis with placeholder-aware confidence, browser automation rule split.
- **Next focus**: adapter depth improvements, richer dataflow/context
  precision, and optional enterprise-scale workflows.

<img width="1024" height="1024" alt="SafeAI_Roadmap" src="https://github.com/user-attachments/assets/de21b305-9e17-4390-a745-e00f9427f8e4" />


---

## Community Contributors

SafeAI is built by and for the AI security community. Thank you to all
contributors who have helped make AI safer:

| Contributor | Key Contributions |
|-------------|-------------------|
| [@i-safonoff](https://github.com/i-safonoff) | `.cursorrules` framework adapter, `rule_coverage_summary()`, RULES_REFERENCE.md, dataflow casing fix |
| [@ARAVIND281](https://github.com/ARAVIND281) | Claude Code permission evaluation order, interprocedural data-flow tracking |
| [@Solarthis](https://github.com/Solarthis) | MCP tool description injection detection |
| [@Aming9303](https://github.com/Aming9303) | `safeai registry components` CLI, `safeai init` command, GitHub Actions example |
| [@adnqcr7-code](https://github.com/adnqcr7-code) | Framework detection tests (LangGraph, CrewAI, LlamaIndex, n8n, Claude Code), CI/SARIF docs |
| [@hadbiaghiles](https://github.com/hadbiaghiles) | AutoGen framework documentation |
| [@D05TL3](https://github.com/D05TL3) | GitHub Actions scanning example |
| [@mikemikimike](https://github.com/mikemikimike) | Adapter negative detection tests |
| [@mah](https://github.com/mahirhir) | Claude Code deep analysis documentation |
| [@asarakhatun17-lgtm](https://github.com/asarakhatun17-lgtm) | Supported frameworks consistency fix |
| [@yugaaank](https://github.com/yugaaank) | Capability detectors (Docker, Kubernetes, Redis, S3, GCP, Slack, Jira, browser) |

See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to get involved.

---

## Documentation

- [Release Notes](./RELEASE_NOTES.md) — changelog for all versions
- [Upgrade Guide](./UPGRADE.md) — v1.x → v2.0.0 migration
- [Support Matrix](./SUPPORT_MATRIX.md) — Python versions, platforms, adapters, CI
- [Release Channels](./RELEASE_CHANNELS.md) — main, stable, prerelease, maintenance
- [Security Policy](./SECURITY.md) — vulnerability reporting and response targets
- [Known Limitations](./LIMITATIONS.md) — what SafeAI does and does not do
- [Roadmap](./ROADMAP.md) — future plans and feature requests

---

## License

SafeAI is released under the Apache 2.0 License.
