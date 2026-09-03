# Good First Issues

Welcome, and thank you for considering contributing to SafeAI!

This document indexes **32 beginner-friendly issues** designed for first-time contributors (15 currently open). Each issue includes the files you'll need to modify, the tests you should write, and the acceptance criteria.

> **For maintainers:** These issues are defined in `.github/good-first-issues/` as YAML templates. Run the [create-good-first-issues workflow](../../actions/workflows/create-good-first-issues.yml) to create them in the GitHub issue tracker with the `good first issue` label. Once created, this file serves as a curated index.

> **25 issues have already been completed** by community and internal contributors. See the [Completed Issues](#-completed-issues) section at the bottom.

---

## Framework Adapters

### 1. Add AutoGen detector
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/frameworks/autogen/parser.py`
- **Suggested tests:** `tests/test_autogen.py`
- **Description:** Detect Microsoft AutoGen framework by scanning Python imports (`from autogen import`). Follow the pattern used by existing parsers (Google ADK, Mastra, etc.) — AST import detection, agent/tool/model extraction, and registration via `@register_parser`.

### 2. Improve LangGraph parser — detect conditional edges
- **Difficulty:** Medium | **Effort:** 3–4 hours
- **Suggested files:** `safeai/frameworks/langgraph/parser.py`
- **Status:** Partially done — regular `add_edge` calls are detected; `add_conditional_edges` is not yet handled
- **Description:** Extend the LangGraph parser to detect `add_conditional_edges()` calls. Currently the `endswith("add_edge")` check misses the conditional variant (`add_conditional_edges`). Update both the AST detection and regex fallback to capture conditional routing edges.

---

## Capability Detection

### 3. Detect Microsoft Teams integration
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/analyzers/capability/analyzer.py`, `safeai/analysis/capabilities.py`
- **Description:** Add a regex pattern to detect Microsoft Teams SDK usage (`import teams`, `from teams import`, `TeamsClient`, etc.). Follow the same pattern as the existing Docker, Slack, and Jira detectors.

### 4. Detect SharePoint access
- **Difficulty:** Easy | **Effort:** 2 hours
- **Description:** Add a regex pattern for SharePoint Python SDK (`office365`, `sharepoint`, `ClientContext`). This is deferred from the initial capability detection batch and requires MCP-based detection consideration.

### 5. Detect OneDrive access
- **Difficulty:** Easy | **Effort:** 2 hours
- **Description:** Similar to SharePoint — detect OneDrive SDK references (`onedrive`, `OneDriveClient`). May share detection logic with the SharePoint detector.

### 6. Split browser automation into separate rules
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `safeai/analyzers/capability/analyzer.py`, `safeai/rules/base_rules.yaml`
- **Description:** The current `CAP_browser` pattern groups Playwright, Selenium, Puppeteer, and `browser_use` under one rule. Split into separate rules (`CAP_browser_playwright`, `CAP_browser_selenium`, etc.) for finer granularity. Community feedback suggests this would improve rule specificity.

---

## Prompt Rules

### 7. Detect unsafe prompt instruction patterns
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/analyzers/prompt/analyzer.py`, `safeai/rules/base_rules.yaml`

### 8. Detect unrestricted instruction overrides
- **Difficulty:** Easy | **Effort:** 2 hours

### 9. Detect hidden system prompt injection
- **Difficulty:** Medium | **Effort:** 3–4 hours

### 10. Detect prompt extraction attempts
- **Difficulty:** Medium | **Effort:** 3–4 hours

---

## Governance Signals

### 11. Detect timeout configuration
- **Difficulty:** Easy | **Effort:** 2 hours
- **Description:** Scan agent configs and code for timeout settings that are missing, too long, or set to infinite. Flag as a governance gap.

### 12. Detect retry policy configuration
- **Difficulty:** Easy | **Effort:** 2 hours

### 13. Detect approval workflow requirement
- **Difficulty:** Medium | **Effort:** 3–4 hours

### 14. Detect audit logging configuration
- **Difficulty:** Medium | **Effort:** 3–4 hours

### 15. Detect rate limiting configuration
- **Difficulty:** Easy | **Effort:** 2 hours

---

## Reports & Output

### 16. Improve terminal output readability
- **Status:** ✅ Complete (v1.4) — severity-grouped summary, explicit counts, `Highest escalation` line, coverage/assurance notes
- **Difficulty:** Easy | **Effort:** 3–4 hours
- **Suggested files:** `safeai/report/terminal.py`
- **Description:** Original task restructured the terminal scan summary for readability. Now delivered: grouping by severity, clearer section headers, and a better signal-to-noise ratio (informed by the HTML report design).

### 17. Improve HTML report — add filtering and search
- **Status:** ✅ Complete (v1.4-b) — client-side filter + searchable tables via `safeai/report/html_kit.py` (`data_table`, `data-filter`)
- **Difficulty:** Medium | **Effort:** 4–6 hours
- **Suggested files:** `safeai/report/html.py`, `safeai/report/html_kit.py`

### 18. Improve SARIF output — add code flow
- **Difficulty:** Medium | **Effort:** 3–4 hours
- **Suggested files:** `safeai/report/sarif.py`

### 19. Add Markdown report generator
- **Status:** 🔄 Partial — a Markdown reviewer summary ships via `--pr-comment` (`safeai/report/pr_comment.py`); a standalone `--format markdown` report generator is still open
- **Difficulty:** Easy | **Effort:** 3–4 hours
- **Suggested files:** `safeai/report/markdown.py`

### 20. Improve JSON schema — add versioning
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `safeai/report/json_report.py`

### 21. Add dependency graph visualization in HTML
- **Difficulty:** Medium | **Effort:** 4–6 hours
- **Suggested files:** `safeai/report/html.py`

### 22. Add CSV report generator
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `safeai/report/csv_report.py`

---

## Scoring & Trust Score

### 23. Tune trust score weighting for critical and high findings
- **Status:** ✅ Complete (v1.4) — severity weighting shipped via `SEVERITY_POINTS` in `safeai/severity.py` (critical 25 / high 15 / medium 8 / low 4 / info 1), consumed by `safeai/scoring/engine.py`; category weights remain configurable (`config_weights`)
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/scoring/engine.py`, `safeai/severity.py`
- **Description:** Weighted severity now drives the trust score; the original equal-weight-per-category note is superseded.

---

## Documentation

### 24. Improve architecture diagram
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `ARCHITECTURE_FOR_CONTRIBUTORS.md`

### 25. Add framework-specific documentation page
- **Difficulty:** Easy | **Effort:** 3–4 hours

### 26. Improve installation guide for Windows users
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `USER_GUIDE.md`

### 27. Add FAQ with common troubleshooting scenarios
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `USER_GUIDE.md`

### 28. Add glossary of terms
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `GLOSSARY.md`

### 29. Create video or animated GIF guide for scan workflow
- **Difficulty:** Medium | **Effort:** 4–6 hours

---

## Config-File Adapters

### 30. Add Windsurf config-file adapter
- **Difficulty:** Easy-Medium | **Effort:** 3–4 hours
- **Suggested files:** `safeai/frameworks/windsurf/__init__.py` (new), `safeai/frameworks/windsurf/parser.py` (new), `safeai/frameworks/__init__.py` (register), `safeai/engine/orchestrator.py` (add `.windsurfrules` to `_is_scannable_file`), `tests/test_windsurf_framework.py` (new), `tests/fixtures/windsurf/representative/.windsurfrules` (new)
- **Description:** Add a framework adapter for the Windsurf IDE config file (`.windsurfrules`). Follow the exact pattern of the `.cursorrules` adapter (PR [#113](https://github.com/ikaruscareer/SafeAI/pull/113)): filename-based detection, JSON/YAML/free-text structured-first parsing, capability keyword scanning (`shell`, `filesystem`, `external_apis`, `databases`), tool/model extraction, unrestricted grant detection, MCP reference detection. Register via `@register_parser`. Write tests covering JSON parsing, YAML parsing, free-text fallback, detection by filename, and integration with `run_scan()`. Maps to v2.0.0 config-file coverage in `ROADMAP.md`.

---

## Governance Depth

### 31. Detect runaway-loop / recursion-guard governance signals
- **Difficulty:** Medium | **Effort:** 4–5 hours
- **Suggested files:** `safeai/analyzers/governance/analyzer.py`, `safeai/rules/base_rules.yaml`, `tests/test_governance_analyzer.py`
- **Description:** Add two new `GOV_*` rules to the `GovernanceAnalyzer`: `GOV_MAX_ITERATIONS_MISSING` (detects agent loops with no max-iteration bound — e.g. `while True`, recursive agent-to-agent calls without depth limit) and `GOV_RECURSION_GUARD_MISSING` (detects recursive tool calls without a recursion depth guard). Follow the existing pattern in `GovernanceAnalyzer`: regex detection over Python source, per-tool dedup, ±10-line source confirmation. Add rules to `base_rules.yaml` with appropriate severity (`high` for unbounded loops, `medium` for missing recursion guards). Map both to OWASP LLM06 and OWASP Agentic in `RULE_MAPPINGS`. Write tests covering detection, dedup, and rule mapping. Maps to v2.0.0 governance depth in `ROADMAP.md`.

---

## Registry

### 32. Add `safeai registry import` command
- **Difficulty:** Medium | **Effort:** 4–5 hours
- **Suggested files:** `safeai/cmd/cli.py`, `safeai/kya/exporter.py`, `tests/test_registry_cli.py`
- **Description:** Implement `safeai registry import <file>` to complete the portable registry export/import cycle. `registry export` already produces a portable, source-safe JSON inventory (`safeai/kya/exporter.py`); `import` should read that JSON and merge agent records into the local SQLite registry (`SAFEAI_REGISTRY` or `~/.safeai/registry.db`). Import must: skip duplicate agents (match on `agent_id`), merge `agent_metadata` fields (business owner, technical owner, environment), merge `component_snapshots` (dedup by component identity), merge `finding_lifecycle` events (dedup by finding fingerprint), merge `agent_tool_snapshots` (dedup by tool identity), and record the import in the scan history. Add `--dry-run` flag to preview what would be imported without writing. Add `--force` flag to overwrite existing metadata. Write tests covering: import of a valid export, idempotent re-import (no duplicates), metadata merge, dry-run output, and error handling for corrupt/invalid JSON. Maps to CE 2.0 portable registry in `ROADMAP.md`.

---

## ✅ Completed Issues

These issues have been implemented by community contributors and are now part of the main codebase.

### Framework Adapters

| # | Issue | Contributor |
|---|-------|-------------|
| 1 | Add Google ADK detector | ikaruscareer |
| 2 | Add Mastra detector | ikaruscareer |
| 3 | Add Haystack detector | ikaruscareer |
| 5 | Add n8n workflow detector | ikaruscareer |
| 6 | Improve CrewAI parser — extract tool definitions | ikaruscareer |
| 8 | Add Dify detector | ikaruscareer |
| — | Add `.cursorrules` config-file adapter | @i-safonoff (PR #113) |

### Capability Detection

| # | Issue | Contributor |
|---|-------|-------------|
| 12 | Detect Docker capability | @yugaaank (PR #2) |
| 13 | Detect Kubernetes capability | @yugaaank (PR #2) |
| 14 | Detect Redis capability | @yugaaank (PR #2) |
| 15 | Detect S3 / cloud storage access | @yugaaank (PR #2) |
| 16 | Detect GCP / Google Cloud services | @yugaaank (PR #2) |
| 17 | Detect Slack integration | @yugaaank (PR #2) |
| 18 | Detect Jira integration | @yugaaank (PR #2) |
| 19 | Detect browser automation capability | @yugaaank (PR #2) |
| — | Detect hidden instructions in MCP tool descriptions | @Solarthis (PR #107) |

### Reports, Output & Scoring

| # | Issue | Contributor |
|---|-------|-------------|
| 16 | Improve terminal output readability | SafeAI (v1.4) |
| 17 | Improve HTML report — add filtering and search | SafeAI (v1.4-b) |
| 23 | Tune trust score weighting for critical/high findings | SafeAI (v1.4) |
| — | Add `rule_coverage_summary()` for control-mapping gaps | @i-safonoff (PR #112) |

### Data-Flow & Governance

| # | Issue | Contributor |
|---|-------|-------------|
| — | Interprocedural data-flow tracking (follow taint one call deep) | @ARAVIND281 (PR #110) |
| — | Resolve Claude Code permission evaluation order | @ARAVIND281 (PR #111) |

---

## Test Fixtures & Compatibility

### 32. Expand golden fixtures to all framework adapters
- **Difficulty:** Easy | **Effort:** 1–2 hours per framework
- **Suggested files:** `tests/fixtures/<framework>/representative/`, `tests/test_compatibility.py`
- **Description:** The compatibility test suite has golden fixtures for 10 of 17 framework adapters (Claude Code, CrewAI, LangGraph, Cursor Rules, Windsurf, n8n, LlamaIndex, Google ADK, OpenAI Agents, Semantic Kernel). Add representative fixtures and golden tests for the remaining 7: Azure Foundry, Bedrock Agent, Dify, Haystack, LangChain, Mastra, Microsoft Agent.
- **Acceptance criteria:**
  1. Create `tests/fixtures/<framework>/representative/` with a minimal source file
  2. Add a `Test<Framework>Golden` class in `tests/test_compatibility.py` following the existing pattern
  3. All 36+ tests pass (`pytest tests/test_compatibility.py`)

### 33. Add MCP tool-pattern golden fixtures
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `tests/fixtures/mcp/`, `tests/test_compatibility.py`
- **Description:** Add golden fixtures for representative MCP patterns: clean server, poisoned tool description, missing auth, exposed endpoint. Test that the MCP analyzer produces expected findings for each.
- **Acceptance criteria:**
  1. Create `tests/fixtures/mcp/golden/` with 4 representative `.json` files
  2. Add `TestMCPToolPatterns` class in `tests/test_compatibility.py`
  3. All tests pass

---

## Detailed Templates

Each issue above has a corresponding YAML template in `.github/good-first-issues/` with the full description, acceptance criteria, and labels. Run the GitHub Actions workflow to create them all in the issue tracker at once.

## How to Claim an Issue

1. Find an issue in the [GitHub issue tracker](https://github.com/ikaruscareer/SafeAI/issues) labeled `good first issue`
2. Comment to let others know you're working on it
3. Ask questions if anything is unclear
4. Submit a draft PR early for feedback
5. Reference the issue in your PR description

**All first-time contributors are welcome.** If you're unsure where to start, pick the smallest issue that interests you and start there.
