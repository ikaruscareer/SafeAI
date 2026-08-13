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

### What's New in 1.6.0

- **Security Scorecard** — deterministic 0–10 score with per-category
  breakdown and `pass`/`warn`/`fail` outcome. Flags: `--scorecard`,
  `--scorecard-json`, `--scorecard-summary`, `--scorecard-fail-under`.
- **Community Scan (private pilot)** — governed workflow for scanning public
  third-party agent frameworks with responsible disclosure; private by default.
- **CLI version support** — `safeai --version` / `-V`.
- **Action hardening** — dynamic version source of truth, hermetic installs,
  output-injection protection.

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
