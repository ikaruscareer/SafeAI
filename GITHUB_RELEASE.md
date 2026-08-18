# SafeAI — GitHub Release

## v1.7.0

Static AI Capability & Risk Analyzer for AI agents and workflows. Detects
prompt injection, data leakage, excessive agency, MCP misconfigurations, and
credential/capability mismatches — entirely offline and static. This release
completes CE 1.4 and CE 1.6 with **IDE-scoped MCP discovery**, **named
policy profiles**, **registry freshness indicators**, **suppression CI
failure**, **component registry persistence**, and **component-change diffs**.

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

### What's New in 1.7.0

- **IDE-scoped MCP discovery** — Cursor / Windsurf / VS Code MCP configs via
  `--mcp-ide-scopes` (repo-local only, excluded from exports by default).
- **Named policy profiles** — `developer`, `strict-ci`, `mcp`, `rag`,
  `production-agent` via `--policy-profile NAME`.
- **Registry freshness indicators** — `last_scan_timestamp` + `scan_count`;
  `safeai registry list` shows freshness status.
- **Suppression CI failure** — `--strict-suppressions` fails the scan on expired
  or moved suppressions.
- **Component registry persistence** — schema-v3 `component_snapshots` with
  first/last-seen provenance; consuming agents resolved internally.
- **Component-change diffs** — changed/added/removed components flag consuming
  agents in the `component_diff` report section.

---

## v1.8.0 (Curated scope — Unreleased: "True Authority & Complete Lifecycle")

A curated release bundling the remaining CE 1.4 and CE 1.5 gaps into four
cohesive workstreams — the gate for starting CE 2.0. Confirmed
not-yet-implemented in the v1.7.0 architectural review.

- **Workstream 1 — Lifecycle & Ownership (CE 1.4)**: `finding_lifecycle` table
  (schema v4) with `introduced → persisting → resolved → reopened` and an
  `ESC_RECURRING_RISK` rule; Stale Suppression Guard binding waivers to exact
  code fingerprints; `safeai registry metadata set` for owner/environment stored
  in a decoupled `agent_metadata` table and shown in HTML.
- **Workstream 2 — Code-Level Authority (CE 1.5)**: Tool ↔ Implementation
  Mapping (orphan detection); Command-Aware MCP Resolution (`assurance: resolved`
  vs `unresolved-command`); Target Taxonomy Engine aggregating external-network
  capabilities into Database / Object Storage / SaaS API buckets.
- **Workstream 3 — Detection Depth**: Prompt risk depth (multi-line, cross-file,
  indirect injection, XML/HTML injection); Data leakage depth (private keys, JWT,
  AWS keys, connection strings, base64/hex); Cross-component analysis
  (`component_graph.py` — skill→tool→workflow→MCP→model relationships).
- **Workstream 4 — Community & Onboarding**: Community scans expansion (new
  framework targets); first-time user experience (Getting Started guide,
  improved terminal output, scorecard interpretation tips).

**Exit criterion:** a reviewer can see, for any tool or MCP server, where it is
declared and where it is implemented, and SafeAI flags mismatches. Suppressions
are provably valid against the current code, and every finding carries its
longitudinal history.

## v1.9.0 (Curated scope — Unreleased: "Component Depth & Ecosystem Foundations")

- **CE 1.6 depth** — component version/hash columns; `safeai registry components`
  impact-query CLI; component-level unpinned-reference and unsafe-composition
  detection; component manifests / lockfile-style integrity.
- **CE 1.4 / CE 1.5 leftovers** — governance signal detection; heuristic
  data-flow depth.
- **CE 2.0 foundations** — `safeai init`; custom rule authoring scaffold; OWASP
  Agentic / OWASP LLM / NIST AI RMF control mappings (taxonomy only); portable
  registry import; per-scan plugin / rule-pack versions.
- **Remote repository scanning** — scan GitHub, Bitbucket, and other remote
  repositories directly without local checkout.

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

- `safeai_static_analyzer-1.6.0-py3-none-any.whl`
- `safeai_static_analyzer-1.6.0.tar.gz`
