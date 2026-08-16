# SafeAI — Release Notes

## v1.7.0 (Unreleased)

**SafeAI 1.7.0 completes the CE 1.4 and CE 1.6 roadmap milestones.** Adds
IDE-scoped MCP discovery, named policy profiles, registry freshness
indicators, suppression CI failure, component registry persistence, and
component-change diffs. The scanner stays fully offline, static, and
local-first.

### Headline: Multi-source MCP discovery

MCP server configs are now discovered across Cursor, Windsurf, and VS Code
scopes in addition to the scanned repo. Out-of-repo scopes are behind an
explicit `--mcp-ide-scopes` flag and excluded from exports by default.

### Headline: Named policy profiles

Five built-in profiles (`developer`, `strict-ci`, `mcp`, `rag`,
`production-agent`) provide composable policy rule sets. Load with
`--policy-profile NAME`; user overrides in `.safeai/policy.yml` extend the
preset.

### Headline: Registry freshness + suppression enforcement

- Agent records track `last_scan_timestamp` and `scan_count`; `safeai registry
  list` surfaces freshness status.
- `--strict-suppressions` fails the scan on expired or moved suppressions,
  enabling CI enforcement.

### Headline: Component registry + change diffs

- Component snapshots (type, name, path, source, full data JSON) are persisted in
  the KYA registry's `component_snapshots` table (schema v3) with first/last-seen
  provenance; consuming agents are resolved via `get_component_agents`.
- Changed, added, or removed components flag all consuming agents in a new
  `component_diff` section (computed against the baseline scan).

### Upgrade notes

- No breaking changes. All new flags are opt-in.
- Registry schema auto-migrates from v1.6.0 to v3 (adds `component_snapshots`).

---

## v1.8.0 (Unreleased — curated scope: "True Authority & Complete Lifecycle")

**SafeAI 1.8.0 bundles the remaining CE 1.4 and CE 1.5 gaps into two cohesive
workstreams and is the gate for starting CE 2.0.** Every item below was confirmed
as not-yet-implemented (or only partially implemented) in the v1.7.0
architectural review.

### Workstream 1 — Lifecycle & Ownership (CE 1.4 completion)

- **Finding Lifecycle Event Engine** — `finding_lifecycle` table (schema v4)
  tracking `introduced → persisting → resolved → reopened` on existing
  fingerprints; new `ESC_RECURRING_RISK` rule for reintroduced findings.
- **Stale Suppression Guard** — compare a suppression's fingerprint against the
  current AST/location; `--strict-suppressions` fails when a waiver exists but
  the underlying code has materially shifted.
- **Agent Enrichment Schema** — `safeai registry metadata set <agent_id>
  --owner … --env …` stored in a decoupled `agent_metadata` table and shown in
  the HTML report.

### Workstream 2 — Code-Level Authority (CE 1.5 completion)

- **Tool ↔ Implementation Mapping** — correlator bridging `tool_def` findings
  with skill/capabilities; surfaces orphan states ("declared but no
  implementation found").
- **Command-Aware MCP Resolution** — statically resolve a local MCP server
  `command`, attempt static extraction, label `assurance: resolved` vs
  `assurance: unresolved-command`.
- **Target Taxonomy Engine** — aggregate external-network capabilities into
  explicit buckets (Database, Object Storage, SaaS APIs) in HTML/JSON reports.

### Workstream 3 — Detection Depth (analysis hardening)

- **Prompt risk depth** — multi-line concatenation, cross-file interpolation,
  indirect injection via tool calls, XML/HTML tag injection, template variable
  injection in `.md` files.
- **Data leakage depth** — private keys, JWT tokens, AWS access keys,
  connection strings, base64/hex-encoded secrets; per-pattern severity.
- **Cross-component analysis** — `component_graph.py` analyzes skill→tool→
  workflow→MCP→model relationships and flags dangerous combinations.

**Definition of done:** all CE 1.4 and CE 1.5 roadmap items marked ✅ shipped;
a reviewer can see, for any tool or MCP server, where it is declared and where
it is implemented, and SafeAI flags mismatches. Suppressions are provably valid
against the current code, and every finding carries its longitudinal history —
unblocking CE 2.0.

---

## v1.9.0 (Unreleased — curated scope: "Component Depth & Ecosystem Foundations")

Carries the remaining depth items not in v1.8.0.

- **CE 1.6 depth** — component version/hash columns; `safeai registry components`
  impact-query CLI; component-level unpinned-reference and unsafe-composition
  detection; component manifests / lockfile-style integrity.
- **CE 1.4 / CE 1.5 leftovers** — governance signal detection (timeout/retry/
  approval/audit/rate-limit); heuristic data-flow depth (untrusted input into
  prompts / tool args).
- **CE 2.0 foundations** — `safeai init`; custom rule authoring scaffold; OWASP
  Agentic / OWASP LLM / NIST AI RMF control mappings (taxonomy only); portable
  registry import; per-scan plugin / rule-pack versions.

---

## v1.6.0 (2026-08-13)

**SafeAI 1.6.0 adds a Security Scorecard, a Community Scan programme, and a
hardened GitHub Action.** The scanner stays fully offline, static, and
local-first — nothing in this release executes agent code or calls an LLM.

### Headline: the SafeAI Security Scorecard

Every scan can now produce a **Security Scorecard** — a single deterministic
0–10 score with per-category breakdowns and a `pass`/`warn`/`fail` outcome,
designed to be the first thing a reviewer reads on a PR.

- **Transparent scoring**: severity weights (`critical=4.0 … info=0.0`),
  diminishing returns for repeated findings, and fingerprint deduplication are
  all documented in `safeai/scorecard.py`. Identical findings always produce an
  identical score.
- **Suppressed findings never move the score** — waivers are respected without
  silently hiding findings.
- **Five new flags**: `--scorecard` / `--scorecard-md`, `--scorecard-json`,
  `--scorecard-summary` (GitHub Actions step summary), and
  `--scorecard-fail-under N` to gate CI on a minimum score.
- **Machine-readable**: `safeai-scorecard.json` conforms to
  `safeai/scorecard-schema.json` (`schema_version: 1`), and every rendering
  Markdown-escapes and secret-redacts untrusted finding text.

```bash
safeai scan . --scorecard scorecard.md --scorecard-json scorecard.json \
  --scorecard-fail-under 7.0
```

### Community Scan programme (private pilot)

SafeAI can now be pointed at **public third-party agent frameworks** under a
governed, responsible-disclosure process (`community-scans/`): a target
manifest, a documented methodology and disclosure policy, provenance manifests,
and a sanitiser that turns a private report into a public-safe summary.
Everything is **private by default**; nothing is published without human
review. CI runs with `contents: read`, SHA-pinned actions, a concurrency group,
and a 30-minute timeout.

### GitHub Action & packaging hardening

- The package version is now read dynamically from `safeai.__version__`, so
  source and metadata cannot drift.
- `scripts/safeai-action.py` supports a hermetic install via
  `SAFEAI_ACTION_FIND_LINKS`, rejects control characters in path inputs, and
  strips newlines from `$GITHUB_OUTPUT` values to block output injection.
- `safeai --version` / `-V` prints a stable machine-readable version line
  (`safeai/version.py`), and a new `DEVELOPER_GUIDE.md` covers local and
  Actions usage.

### Verification Snapshot

- 459 tests collected; scorecard, community-scan, and action suites green.
- Lint passing (`ruff check safeai/ tests/ scripts/ community-scans/`).
- Scorecard output validated against `safeai/scorecard-schema.json`.

### Upgrade Notes

- No breaking changes to existing CLI flags, exit codes, or report shapes; all
  scorecard flags are opt-in.
- The informational scorecard is additive — existing SARIF/JSON/HTML outputs
  are unchanged unless a `--scorecard*` flag is supplied.

## v1.5.0 (2026-08-11)

First **stable** release (`5 - Production/Stable`). In addition to the CE 1.5
environment dependency inventory work, this release makes SafeAI consumable
as a GitHub Actions **Marketplace action**.

### Major Additions

- **GitHub Actions Marketplace action** (`action.yml` composite action):
  - Inputs: `path`, `version`, `fail-on`, `sarif`, `rules`, `baseline`,
    `fail-on-new`, `fail-on-escalation`, `no-registry`, `extra-args`.
  - Output: `sarif-path`.
  - Installs `SafeAI-Static-Analyzer` from PyPI and runs `python -m safeai
    scan` on the repository; native exit codes are preserved.
  - Inputs are passed as environment variables to a pure-Python driver
    (`scripts/safeai-action.py`) and forwarded as an argv list — nothing is
    ever evaluated by a shell. Least-privilege (`contents: read` only).
  - SARIF is written even when a scan fails, so `if: always()` upload steps
    still produce code-scanning alerts. `no-registry: true` is the default to
    keep scans ephemeral.
- **Self-validating CI** (`.github/workflows/action-test.yml`): exercises the
  action itself against fixture repositories, builds/installs the wheel, and
  validates SARIF on every commit. 24 new tests in `tests/test_github_action.py`.
- **Environment and credential dependency inventory** with
  dependency-to-capability correlation (`DEP_UNDECLARED_CAPABILITY`,
  `DEP_ORPHANED_TOOL`).

### Fixed

- Packaging: version → `1.5.0`, classifier → `5 - Production/Stable`;
  `_safeai_version()` resolves through `SafeAI-Static-Analyzer` metadata;
  wheel package-data verified (`safeai/rules/base_rules.yaml`).

### Usage

```yaml
- uses: ikaruscareer/SafeAI@v1.0.0
  with:
    path: .
    fail-on: critical
```

### Verification Snapshot

- Full test suite passing (373 tests, 1 skip).
- Lint passing (`ruff check safeai/ tests/ scripts/`).
- Wheel and source distribution build successfully.
- End-to-end published-style install validated (build → venv install → scan →
  SARIF + exit-code checks) for both a clean fixture (exit 0) and a risky
  fixture (exit 1, SARIF preserved).

## v1.3.0-beta (2026-07-31)

Release 1.3 introduces **KYA (Know Your Agent)** baseline and local registry
capabilities while preserving SafeAI's offline-first static-analysis model.

### Major Additions

- **Canonical manifest**: `safeai-manifest.json` (`schema_version: "1.0"`,
  `manifest_type: "safeai.kya"`) as the portable contract.
- **Deterministic finding identity**: stable `finding_id`/`fingerprint`
  generation, confidence labels (`high|medium|low`), provenance, and
  remediation normalization.
- **Baseline diffing**: `--baseline` and `--fail-on-new` for PR-focused
  gating (new/regressed findings only).
- **Suppressions**: `.safeai/suppressions.yml` with required reason/owner/
  created date, optional expiry and path scope.
- **Policy-as-code**: `.safeai/policy.yml` with actions `allow`, `warn`,
  `require_review`, `deny` and deterministic evaluation.
- **Local SQLite registry**: `.safeai/registry.db` with append-only scan
  history and agent snapshots.
- **Registry CLI**:
  - `safeai registry list`
  - `safeai registry show <agent-id>`
  - `safeai registry history <agent-id>`
  - `safeai registry diff <agent-id> --from previous --to latest`
  - `safeai registry export --format json --output <path>`

### New Scan Flags

- `--manifest`
- `--baseline`
- `--fail-on-new`
- `--registry`
- `--no-registry`
- `--strict-registry`
- `--policy`
- `--suppressions`

### Behavior and Compatibility Notes

- Existing `--fail-on` behavior is preserved unless `--fail-on-new` is
  explicitly used.
- Registry persistence is local-only and enabled by default for interactive
  scans; it is auto-disabled when `CI` is detected unless `--registry` is
  explicitly provided.
- Report schema changes are additive.

### Verification Snapshot

- Full test suite passing (141 tests)
- Lint checks passing (`ruff check safeai/ tests/`)
- End-to-end CLI flows validated for scan, manifest, baseline, suppressions,
  policy, registry, and export.

## v1.1.0-beta (2026-07-24)

Phase 1.5 AI Component Security and stabilization release for SafeAI, the Static AI Capability & Risk Analyzer. This release remains entirely offline and static: SafeAI does not execute agents, invoke tools, call LLMs, or contact reputation services.

### New Features

- **AI Component Security**
  - Discovers skills, prompt files, tool definitions, model configurations, and workflow templates.
  - Reports component inventories in JSON, project graphs, terminal summaries, and HTML reports.

- **Skill Analysis**
  - Detects embedded prompts, hardcoded secrets, excessive permissions, insecure defaults, and risky capabilities.

- **Prompt File Analysis**
  - Scans prompt and system-instruction files for injection-prone placeholders, system prompt exposure, role overrides, and untrusted input interpolation.
  - Supports `CLAUDE.md`, `prompt.md`, `system_prompt.md`, `.prompt`, `.prompt.md`, and `.prompt.txt` artifacts.

- **Tool Definition Analysis**
  - Detects missing input validation, dangerous parameters, shell execution, and excessive tool permissions.

- **Model Configuration Analysis**
  - Detects unsafe temperature settings and explicitly disabled safety controls.
  - Applies provider-aware checks for Google, Bedrock, and Azure model safety settings.

- **Workflow Template Analysis**
  - Detects missing approval gates, insecure defaults, capability sprawl, and missing validation.

- **Deep MCP Analysis**
  - Adds per-tool broad-permission analysis.
  - Detects resources that may expose sensitive data.
  - Detects insecure MCP transports.

- **Framework Coverage**
  - Adds early-preview adapters for Claude Code, Google ADK, Mastra, Haystack, LlamaIndex, Dify, and n8n.
  - SafeAI now includes 15 built-in framework parsers.

- **Capability Diff**
  - Compares the current normalized capability inventory with a previous JSON report.
  - Use `safeai scan <directory> --baseline previous-report.json`.

### Stabilization Improvements

- Parser registry now supports installed third-party parsers through the `safeai.parsers` entry-point group.
- Duplicate parser names and invalid parser interfaces are rejected safely.
- Component paths are normalized to scan-relative paths for portable reports.
- Component extraction diagnostics are exposed in scan reports.
- Dify and n8n detection was tightened to reduce generic configuration false positives.
- Framework dependency extraction includes the new early-preview frameworks.
- README, framework support documentation, roadmap, and release metadata now distinguish established and early-preview adapters.

### Verification

- 51 automated tests passing.
- Ruff checks passing.
- Wheel and source distribution build successfully.

### Known Limitations

- The seven new framework adapters are early-preview integrations with limited framework-specific depth.
- Capability diff compares serialized static inventories; it does not infer runtime behavior.
- JavaScript/TypeScript source analysis remains limited.
- Runtime prompt injection, jailbreak, hallucination, and tool execution testing remain outside the scope of SafeAI.

## v1.0.0-beta (2026-07-14)

Initial beta release of SafeAI — the Static AI Capability & Risk Analyzer for AI agent codebases.

### Features

- **Multi-Framework Scanning**
  - LangGraph, CrewAI, LangChain, Semantic Kernel, OpenAI Agents
  - Microsoft Agent, Azure AI Foundry, Bedrock Agent
  - Automatic framework detection (AST + config + dependency analysis)

- **Prompt Injection Detection**
  - Direct user input interpolation into prompts (LLM01)
  - Missing delimiters between system and user content
  - System prompt leakage detection
  - Role override / instruction override attempts

- **Capability Analysis**
  - Shell execution, filesystem, HTTP, database, code execution
  - Autonomous agent loop detection
  - OWASP LLM06 (Excessive Agency) coverage

- **Data Leakage Detection**
  - Hardcoded API keys, tokens, passwords
  - Environment variable references to secrets

- **MCP (Model Context Protocol) Analysis**
  - Configuration discovery across project files
  - Schema validation (v1.0, v1.1)
  - Authentication and permissions gap detection
  - Endpoint exposure and secret detection

- **Trust Score**
  - Deterministic, reproducible risk scoring (0–100)
  - 7 risk categories with configurable weights
  - Confidence-weighted findings

- **Report Output**
  - Terminal (human-readable summary)
  - JSON (machine-readable)
  - SARIF 2.1.0 (GitHub Advanced Security compatible)
  - HTML (self-contained interactive report)

- **Custom Rules**
  - User-defined YAML rule overrides via `--rules`
  - Merge with built-in rules

- **Exit Code Integration**
  - Configurable `--fail-on` threshold for CI/CD pipelines

### Known Limitations (Beta)

- Dynamic prompt injection at runtime is not detectable via static analysis
- Framework detection is heuristic-based; some complex configurations may not be detected
- Python-only source analysis (JavaScript/TypeScript agent code not yet supported)
- MCP analysis supports v1.0 and v1.1 schemas only
- Dependency scanning is framework-agnostic (name/version extraction only; no CVE matching)

### Installation

```bash
pip install git+https://github.com/ikaruscareer/SafeAI.git
```

### Quick Start

```bash
safeai scan /path/to/project
safeai scan /path/to/project --json report.json
safeai scan /path/to/project --html report.html --fail-on medium
```
