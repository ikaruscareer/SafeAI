# SafeAI — GitHub Release

## v2.0.1

Release hardening. Consolidated 6-job release pipeline with mandatory
verification gates, GPG-signed artifacts, cross-platform verification
instructions, and pre-release checklist.

### What's New

- Consolidated release pipeline with mandatory gates
- Pre-release checklist blocks publication on inconsistencies
- GPG-signed artifacts (wheel, sdist, checksums, provenance, SBOM)
- Cross-platform verification instructions (Linux, macOS, Windows)
- Regression fixtures for 6 high-risk areas
- File discovery extraction and scanner metadata

### Verification

See [VERIFICATION.md](./VERIFICATION.md) for GPG, checksum, and
provenance verification instructions.

---

## v2.0.0

Governance Depth & Ecosystem Expansion. Deepens governance detection with
runaway-loop and recursion-guard rules, adds Windsurf config-file adapter,
and presents governance gaps as a failure-class coverage matrix.

### What's New

- **Runaway-loop / recursion-guard detection** — `GOV_MAX_ITERATIONS_MISSING`
  (high) detects agent loops with no max-iteration bound. `GOV_RECURSION_GUARD_MISSING`
  (medium) detects recursive tool calls without depth guard.
- **Failure-class coverage matrix** — groups GOV_* findings by failure class
  (dependency timeout, unavailable, resource exhaustion, cascading failure,
  unbounded recursion, missing accountability). HTML + JSON output.
- **Windsurf adapter** — `.windsurfrules` config-file scanning. JSON/YAML/
  free-text parsing, capability detection, tool/model extraction.
- **Evidence type schema v1.3** — `evidence_type` on every finding:
  `static-config`, `static-pattern`, or `runtime-observed` (reserved).

### Schema Stability (v2.0.0)

The following are frozen and will not change without a major version bump:

- **Rule IDs**: 79 rules across `CAP_*`, `CC_*`, `DATA_*`, `DATAFLOW_*`,
  `DEP_*`, `ENV_*`, `GOV_*`, `MCP_*`, `MODEL_*`, `PROMPT_*`,
  `PROMPT_FILE_*`, `SKILL_*`, `TOOL_*`, `WORKFLOW_*`.
- **SARIF 2.1.0**: `properties.*` fields (risk_category, affected_framework,
  affected_capability, score_contribution, confidence, confidence_label,
  evidence_type, resolved_definition, schema_version, validation_rule,
  affected_object).
- **JSON report**: findings[], summary, assurance_boundary,
  failure_class_matrix, tool_surface, capability_diff, components,
  kya_agents, policy_decision, suppressions, baseline.
- **Exit codes**: 0 (clean), 1 (findings at/above threshold), 2 (scan error).
- **Action inputs**: path, version, fail-on, sarif, rules, baseline,
  fail-on-new, fail-on-escalation, no-registry, extra-args, scorecard,
  scorecard-json, scorecard-summary, scorecard-fail-under.
- **Action outputs**: sarif-path, scorecard-path, safeai-version.
- **KYA manifest**: schema v1.3 (additive — evidence_type field).

### Supported Environments

- **Python**: 3.11, 3.12, 3.13 (requires-python >= 3.11)
- **Platforms**: Linux (Ubuntu 24.04), macOS, Windows
- **CI**: GitHub Actions (primary), GitLab CI, Azure Pipelines
- **Framework adapters**: azure_foundry, bedrock_agent, claude_code,
  crewai, cursorrules, dify, google_adk, haystack, langchain, langgraph,
  llamaindex, mastra, microsoft_agent, n8n, openai_agents,
  semantic_kernel, windsurf

### Known Limitations

- Static analysis only — does not execute agents or verify runtime behavior.
- No compliance certification — control mappings are taxonomy references.
- Heuristic detection — false positives possible; confidence labels reflect this.
- Single-file data-flow — cross-file taint not yet supported.
- MCP content-level inspection deferred to v2.1.
- Not a runtime security platform, observability product, or red-teaming tool.

### Upgrade Guide

See [UPGRADE.md](./UPGRADE.md) for the full migration guide.

### Installation

```bash
pip install SafeAI-Static-Analyzer==2.0.0
```

### Links

- [Source Code](https://github.com/ikaruscareer/SafeAI/tree/v2.0.0)
- [Upgrade Guide](./UPGRADE.md)
- [Release Notes](./RELEASE_NOTES.md)
- [Issue Tracker](https://github.com/ikaruscareer/SafeAI/issues)

---

## v1.9.1 (2026-08-30)

Static AI Capability & Risk Analyzer for AI agents and workflows. Post-release
fixes for v1.9.0: mojibake correction, scoped governance suppression, hardened
LangGraph detection, and browser rule enrichment mappings.

### Installation

```bash
pip install SafeAI-Static-Analyzer
```

### What's Fixed in 1.9.1

- **AGENTIC04 mojibake** — removed CJK fragment from English description in `safeai/controls/catalogs.py`.
- **Scoped governance source suppression** — suppression now scoped to tool line ±10 window, avoiding masking missing controls in poly-tool modules.
- **Removed unused regex patterns** — `_TOOL_TIMEOUT_RE`, `_TOOL_RETRY_RE`, `FUNCTION_PARAM_RE` cleaned up.
- **Hardened LangGraph detection** — `detect()` now requires an import or `StateGraph(` call, not a bare substring match.
- **Browser rule enrichment** — added `CAP_browser_playwright`, `CAP_browser_selenium`, `CAP_browser_use` to `RULE_MAPPINGS` in `safeai/controls/mappings.py`.

### Links

- [Source Code](https://github.com/ikaruscareer/SafeAI/tree/v1.9.1)
- [Issue Tracker](https://github.com/ikaruscareer/SafeAI/issues)

---

## v1.9.0

Static AI Capability & Risk Analyzer for AI agents and workflows. Detects
prompt injection, data leakage, excessive agency, MCP misconfigurations, and
credential/capability mismatches — entirely offline and static. This release
adds component-record depth, governance signal detection, heuristic data-flow
analysis, control mappings, and ecosystem foundations (`safeai init`, registry
components CLI).

### Installation

```bash
pip install SafeAI-Static-Analyzer
```

### Quick Start

```bash
safeai scan /path/to/project
safeai init  # scaffold .safeai/ with config, policy, suppressions
safeai registry components  # list tracked components
```

### GitHub Action

```yaml
- uses: ikaruscareer/SafeAI@v1
  with:
    path: .
    fail-on: critical
```

### What's New in 1.9.0

**Component Depth (WS1)**
- Component `content_hash` (SHA-256) stored in `component_snapshots` table (schema v5).
- `safeai registry components` CLI with dedup, type filtering, and agent resolution.

**Ecosystem Foundations (WS2)**
- `safeai init [--profile NAME] [--force]` scaffolds `.safeai/` with config, policy, suppressions.
- Identity-preserving init: existing `local_project_uuid` never overwritten.

**Governance Signal Detection (WS3)**
- `GovernanceAnalyzer` with 8 rules: timeout, retry, approval, audit, rate limiting, circuit breaker, backpressure, health check.
- Per-tool deduplication; source-level confirmation scoped to ±10 lines.

**Control Mappings (WS4)**
- Structured mapping layer: OWASP LLM, OWASP Agentic, NIST AI RMF.
- `map_rule_to_controls()` and `map_findings_to_controls()` API.

**Adapter Completion (WS5)**
- AutoGen tightened (requires import, class usage, or registration).
- LangGraph detects `add_conditional_edges()`.
- Browser automation rules split: Playwright / Selenium / browser_use.

**Heuristic Data-Flow Depth (WS6)**
- `DataFlowAnalyzer` tracks untrusted input propagation into sensitive sinks.
- 6 rules: prompt, tool_call, shell, file_write, http_request, database.
- Placeholder-aware confidence; `.py`-only file filter.

### Supported Frameworks (16)

LangGraph, CrewAI, AutoGen, LangChain, Semantic Kernel, OpenAI Agents,
Microsoft Agent, Azure AI Foundry, Bedrock Agent, Claude Code, Google ADK,
Mastra, Haystack, LlamaIndex, Dify, n8n.

### Output Formats

- Terminal (human-readable)
- JSON (machine-readable)
- SARIF 2.1.0 (GitHub Advanced Security)
- HTML (self-contained interactive report)
- KYA manifest (`safeai-manifest.json`)
- PR comment (reviewer-facing escalation summary)
- Security Scorecard (Markdown / JSON)

### Links

- [Landing Page](https://safeai-analyzer.ikaruscareer.com)
- [Source Code](https://github.com/ikaruscareer/SafeAI)
- [Issue Tracker](https://github.com/ikaruscareer/SafeAI/issues)
- [Changelog](RELEASE_NOTES.md)

### Assets

- `safeai_static_analyzer-1.9.0-py3-none-any.whl`
- `safeai_static_analyzer-1.9.0.tar.gz`

---

## v1.8.0

Static AI Capability & Risk Analyzer for AI agents and workflows. Detects
prompt injection, data leakage, excessive agency, MCP misconfigurations, and
credential/capability mismatches — entirely offline and static. This curated
release bundles the remaining CE 1.4, CE 1.5, and CE 1.8 gaps into four
cohesive workstreams — the gate for starting CE 2.0.

### Installation

```bash
pip install SafeAI-Static-Analyzer
```

### Quick Start

```bash
safeai scan /path/to/project
safeai scan /path/to/project --json results.json --html report.html
safeai scan /path/to/project --scorecard scorecard.md --scorecard-fail-under 7.0
```

### GitHub Action

```yaml
- uses: ikaruscareer/SafeAI@v1
  with:
    path: .
    fail-on: critical
```

### What's New in 1.8.0

**Workstream 1 — Lifecycle & Ownership (CE 1.4)**
- **Finding Lifecycle Event Engine** — `finding_lifecycle` table (schema v4)
  tracking state transitions: `introduced → persisting → resolved → reopened`.
  `ESC_RECURRING_RISK` escalation rule fires when a previously resolved finding
  is reintroduced.
- **Stale Suppression Guard** — `detect_stale_suppressions()` binds waivers to
  exact code fingerprints; `--strict-suppressions` fails on expired or moved
  suppressions.
- **Agent Enrichment Schema** — `safeai registry metadata set` for
  owner/environment stored in a decoupled `agent_metadata` table and shown in
  HTML reports.

**Workstream 2 — Code-Level Authority (CE 1.5)**
- **Tool ↔ Implementation Mapping** — correlates declared tools with their
  implementations; surfaces orphan states (`TOOL_ORPHAN_DECLARED`,
  `TOOL_ORPHAN_IMPLEMENTED`) with full file/line provenance.
- **Command-Aware MCP Resolution** — statically resolves local MCP server
  commands; labels output `assurance: resolved` vs `unresolved-command` vs
  `external-package`.
- **Target Taxonomy Engine** — aggregates external-network capabilities into
  destination buckets (Database, Object Storage, SaaS APIs, Cloud Services,
  Messaging).

**Workstream 3 — Detection Depth**
- **Prompt risk depth** — multi-line concatenation, cross-file interpolation,
  indirect injection via tool calls, XML/HTML tag injection, template variable
  injection in `.md` files.
- **Data leakage depth** — RSA/JWT/AWS keys, connection strings,
  base64/hex-encoded secrets with per-pattern severity differentiation.
- **Cross-component analysis** — directed skill→tool→workflow→MCP→model
  relationship graph with orphan detection and coupling analysis.

**Workstream 4 — Community & Onboarding**
- Expanded community scan targets from 5 to 25 AI tools.
- `safeai welcome` guided first-run experience.

### Exit Criterion

A reviewer can see, for any tool or MCP server, where it is declared and where
it is implemented, and SafeAI flags mismatches. Suppressions are provably valid
against the current code, and every finding carries its longitudinal history.

---

### What It Detects

| Category | Examples |
|----------|----------|
| Prompt Injection | User input in prompts, missing delimiters, system prompt leaks |
| Data Leakage | Hardcoded API keys, tokens, passwords (masked in all outputs) |
| Excessive Agency | Shell exec, filesystem access, HTTP, database, code exec, autonomous loops |
| MCP Misconfig | Missing auth, weak permissions, exposed endpoints, hardcoded secrets |
| Capability Escalation | Per-tool authority diffs between scans (14 `ESC_*` rules) |
| Dependency Correlation | Undeclared capabilities, orphaned tools (`DEP_*`) |
| Supply Chain | AI framework dependency detection |

### Supported Frameworks

LangGraph, CrewAI, LangChain, Semantic Kernel, OpenAI Agents, Microsoft Agent,
Azure AI Foundry, Bedrock Agent, Claude Code, Google ADK, Mastra, Haystack,
LlamaIndex, Dify, n8n (15 adapters).

### Output Formats

- Terminal (human-readable)
- JSON (machine-readable)
- SARIF 2.1.0 (GitHub Advanced Security)
- HTML (self-contained interactive report)
- KYA manifest (`safeai-manifest.json`)
- PR comment (reviewer-facing escalation summary)
- Security Scorecard (Markdown / JSON)

### Links

- [Landing Page](https://safeai-analyzer.ikaruscareer.com)
- [Source Code](https://github.com/ikaruscareer/SafeAI)
- [Issue Tracker](https://github.com/ikaruscareer/SafeAI/issues)
- [Changelog](RELEASE_NOTES.md)

### Assets

- `safeai_static_analyzer-1.8.0-py3-none-any.whl`
- `safeai_static_analyzer-1.8.0.tar.gz`
