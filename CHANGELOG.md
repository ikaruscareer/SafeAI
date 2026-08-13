# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] - Unreleased

### Added — Multi-source MCP discovery

- IDE-scoped MCP config discovery for Cursor (`.cursor/mcp.json`), Windsurf
  (`.windsurf/mcp.json`), and VS Code (`.vscode/mcp.json`). Out-of-repo scopes
  are behind an explicit `--mcp-ide-scopes` flag and excluded from exports by
  default, preserving the source-private guarantee.

### Added — Named policy profiles

- Five built-in profiles: `developer`, `strict-ci`, `mcp`, `rag`,
  `production-agent`. Each profile is a composable set of policy rules that
  extends (not replaces) the user's `.safeai/policy.yml`.
- `--policy-profile NAME` loads the preset profile plus user overrides.
- Profiles documented in `POLICY.md`.

### Added — Registry freshness indicators

- Agent records now track `last_scan_timestamp` and `scan_count` in the local
  SQLite registry.
- `safeai registry list` surfaces freshness status (fresh / stale / never
  scanned).
- HTML report includes freshness indicators per agent.

### Added — Suppression CI failure

- `--strict-suppressions` fails the scan (exit 1) when expired or moved
  suppressions are detected, enabling CI enforcement of suppression hygiene.
- Expired suppressions already produce warnings; this flag promotes them to
  failures.

### Added — Component registry persistence

- Component identity (name, version/hash, source, findings, usage relationships)
  is now stored in the KYA registry alongside agent and tool records.
- New query: "which agents reference this component?" via
  `safeai registry components`.

### Added — Component-change diffs

- When a scan detects a changed MCP configuration, skill, prompt, tool
  definition, or model config, all consuming agents are flagged.
- New `component_diff` section in JSON report and HTML output.

### Changed

- Version bumped to `1.7.0`.

## [1.6.0] - 2026-08-13

### Added — SafeAI Security Scorecard

- **Security Scorecard** (`safeai/scorecard.py`): a deterministic, auditable
  0–10 report that summarises a scan into an overall score, per-category
  scores, and a `pass`/`warn`/`fail` outcome. It is a Scorecard-style report,
  **not** an OpenSSF Scorecard report, and says so in every rendering.
- **Scoring model** (documented in-module): severity weights
  `critical=4.0, high=2.0, medium=0.75, low=0.25, info=0.0`, diminishing
  returns for repeated findings at the same `(rule_id, file, line)`, and
  fingerprint deduplication. Suppressed findings are excluded from the score
  and from gating.
- **Five new scan flags**: `--scorecard`/`--scorecard-md` (Markdown),
  `--scorecard-json` (JSON), `--scorecard-summary` (append to the GitHub
  Actions step summary via `$GITHUB_STEP_SUMMARY`), and
  `--scorecard-fail-under N` (fail the scan when the score is below `N`,
  validated to `[0, 10]`).
- **Machine-readable contract** (`safeai/scorecard-schema.json`,
  `schema_version: 1`) with `additionalProperties: false` on the `policy`,
  `coverage`, and finding objects so producer/consumer drift fails validation.
- **Injection-safe rendering**: all untrusted finding text is Markdown-escaped
  and secret-redacted before it reaches the report or the job summary.
- Robustness: malformed finding input (non-numeric `line`, unknown severity,
  unrecognised `--fail-on`) never crashes the scorecard; an unknown fail-on
  threshold fails closed. ~55 scorecard tests in `tests/test_scorecard.py`.

### Added — Community Scan programme (private pilot)

- **`community-scans/`**: a governed workflow for scanning public third-party
  agent frameworks and disclosing results responsibly. Includes the target
  manifest (`targets.yml` + `targets-schema.json`), `methodology.md`,
  `disclosure-policy.md`, `private-pilot.md`, and a pinned-dependency
  `requirements.txt`.
- **Pipeline scripts** (`community-scans/scripts/`): `validate_targets.py`
  (read-only GitHub API validation, path-traversal-safe refs), `resolve_meta.py`
  (pin a target to a 40-char commit SHA), `build_scan_manifest.py` (provenance
  manifest), `sanitise_report.py` (redact a private report into a public-safe
  summary), and `render_reddit_draft.py` (human-review disclosure drafts).
- **Workflows**: `.github/workflows/community-scan.yml` (SHA-pinned actions,
  `contents: read` only, concurrency group, 30-minute timeout, private/public
  artifact split) and `.github/workflows/validate-community-scan.yml`.
- Nothing is published automatically; every report is private by default and
  requires human review before any external disclosure.

### Added — CLI version support & developer guide

- **`safeai/version.py`**: single source of truth for the version string
  (`SAFEAI_VERSION`) plus `version_requested()`/`print_version()` helpers.
  `safeai --version` / `-V` prints a stable machine-readable line.
- **`DEVELOPER_GUIDE.md`**: local development and GitHub Actions usage guide,
  including the Security Scorecard flags.

### Changed — GitHub Action hardening

- **Version source of truth**: `pyproject.toml` reads the version dynamically
  from `safeai.__version__` (`setuptools` `attr:`), so the package metadata and
  the source can no longer drift.
- **Hermetic install path**: `scripts/safeai-action.py` honours
  `SAFEAI_ACTION_FIND_LINKS` so CI can install a freshly built wheel instead of
  a published PyPI version; dependencies still resolve from PyPI.
- **Output hardening**: `set_output()` strips `\n`/`\r` to prevent
  `$GITHUB_OUTPUT` key injection; path inputs are rejected when they contain
  control characters; `get_safeai_version()` failures surface as `::warning::`.

### Notes

- Version bumped to `1.6.0` (tag `v1.6`). Full suite: 459 tests collected.

## [1.5.0] - 2026-08-11

### Added — GitHub Actions Marketplace action

- **Composite action** (`action.yml` at the repository root): a ready-to-use
  GitHub Actions action with inputs `path`, `version`, `fail-on`, `sarif`,
  `rules`, `baseline`, `fail-on-new`, `fail-on-escalation`, `no-registry`,
  and `extra-args`; a `sarif-path` output; and `shield`/`purple` branding.
- **Pure-Python driver** (`scripts/safeai-action.py`): installs the
  `SafeAI-Static-Analyzer` PyPI distribution into the runner's Python and
  runs `python -m safeai scan`. All inputs arrive as `INPUT_*` environment
  variables and are forwarded to the tool as an argv list — no shell
  evaluation, no `eval`, no interpolation of user input into `run:`.
- **Native exit-code passthrough** (0 = pass, 1 = policy/finding threshold hit,
  2 = operational error), with the SARIF artifact written even on a failing
  scan so downstream uploads keep working. The action prints `::warning::`
  if a failed scan produced no SARIF.
- **Least-privilege design**: the action only needs `contents: read` and runs
  with the runner's default Python 3.11+ (`setup-python@v5` recommended);
  `no-registry: true` is the default so scans stay ephemeral.
- **Self-validating CI** (`.github/workflows/action-test.yml`): runs the
  action itself (`uses: ./`) against clean and risky fixture repositories,
  builds the wheel, installs it into a throwaway venv, and validates SARIF
  2.1.0 output and failure behavior on every commit.
- Local validation helpers: `scripts/run_local_integration.py` (build →
  venv-install → scan → SARIF/exit-code check, with `PYTHONPATH` cleared so
  only the installed package is used) and `scripts/check_wheel.py` (wheel
  entry points, rules data, METADATA name). 24 new tests in
  `tests/test_github_action.py` plus fixtures in `tests/fixtures/action/`.

### Added — Environment Dependency Inventory & Correlation (CE 1.5)

- **Environment and credential dependency inventory**
  (`safeai/analyzers/env_dependency/`): a new analyzer records *references* to
  external configuration and credentials — `os.getenv`/`os.environ`,
  `process.env`, dotenv keys, shell/template interpolation, AWS Secrets
  Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, and Kubernetes
  `secretKeyRef`. **Names and source locations only; values are never read,
  masked, or stored**, preserving the source-private guarantee. Entries are
  flagged `secret: true` when backed by a secret manager or a secret-ish name.
- **Dependency-to-capability correlation**
  (`safeai/analysis/dependency_correlation.py`): the inventory is matched
  against the per-tool capability surface via a reviewable name-family keyword
  model, producing two new findings:
  - `DEP_UNDECLARED_CAPABILITY` (medium) — a referenced credential/config
    family has no declared capability to consume it: a candidate undeclared
    capability.
  - `DEP_ORPHANED_TOOL` (low) — a credential-demanding capability is declared
    with no matching credential/config reference anywhere: a probable dead or
    misconfigured tool.
- Correlation findings feed the severity counts, trust score, SARIF, terminal
  and HTML outputs, and are written to the KYA manifest (`dependency_inventory`
  and `dependency_correlation`, plus a `summary.dependency_count`).
- New rules in `safeai/rules/base_rules.yaml`: `ENV_DEP_INVENTORY`,
  `DEP_UNDECLARED_CAPABILITY`, `DEP_ORPHANED_TOOL`.

### Fixed — CE 1.5 architecture review hardening

- **Family matching is now word-segment based**
  (`safeai/analysis/dependency_correlation.py`): names are split on
  non-alphanumeric boundaries instead of raw substring matching, so short
  tokens no longer false-positive inside unrelated words (e.g. `jdbc` no longer
  maps to the database family via `db`). Provider-specific families
  (`cloud`/`database`/`messaging`) take precedence over the generic `api`
  fallback, keeping `SLACK_TOKEN` aligned with a declared `slack` capability and
  eliminating simultaneous false `DEP_UNDECLARED_CAPABILITY` +
  `DEP_ORPHANED_TOOL` pairs.
- **Single scoring pass** (`safeai/engine/orchestrator.py`): correlation now
  runs before the single count/score/relativize pass so its findings are
  included exactly once; the second `_relativize_report()` call was removed.
- **Payload-carrying findings are never suppressed**
  (`safeai/kya/suppressions.py`): `ENV_DEP_INVENTORY` (and
  `MCP_ASSETS_DISCOVERED`) are exempt from `apply_suppressions`, so a broad
  `rule_id`/`path` suppression cannot blank the dependency-inventory section.

### Notes

- The informational `ENV_DEP_INVENTORY` finding is counted in the severity
  breakdown and baseline; scans of repositories with a declared dependency
  inventory will report one more finding than v1.4 for the same input.

### Changed — first stable release & packaging fixes

- Version bumped to `1.5.0` and the `Development Status :: 4 - Beta`
  classifier replaced with `5 - Production/Stable` (`pyproject.toml`).
- `safeai.cmd.postprocess._safeai_version()` now resolves the installed
  version through `importlib.metadata` using the `SafeAI-Static-Analyzer`
  distribution name (with the previous `safeai` name as fallback).
- `data_files`-free pure-Python wheel confirmed to package
  `safeai/rules/base_rules.yaml` as package data; a wheel check script now
  guards this in CI.

## [1.4.0-beta] - 2026-08-02

### Added — Tool-Centric Capability Model & Escalation Detection

- **Tool identity** (`safeai/analysis/tool_identity.py`): capabilities are now
  attributed to a named tool rather than only to an agent. A tool identity
  carries a `kind` (`agent`, `mcp_server`, `skill`, `tool`, `workflow_node`,
  or `unknown`), a `name`, and a `framework`, and reduces to a deterministic
  `tool_key` (for example `mcp_server:invoice-lookup`, `tool:send_email`).
  The key is stable across scans when a name is available, and falls back to
  a path-derived hash only when a tool is genuinely unnamed. Capabilities
  that cannot be attributed to any tool are grouped under a fixed
  `unknown:unattributed` identity rather than dropped or guessed at.
- **Access modes**: every capability now carries an `access_mode` on an
  ascending scale of `none < read < write < mutate < execute`. Where a
  framework or configuration does not explicitly declare the mode, SafeAI
  infers it conservatively (defaulting to `read`) and marks the capability
  `access_mode_inferred: true`. Inferred access can trigger a rule, but its
  severity is capped below critical, and never on its own claims the same
  certainty as a declared, evidenced access mode. See `LIMITATIONS.md`.
- **Capability diff, schema version 2** (`safeai/analysis/capability_diff.py`):
  the baseline comparison now keys on `(tool_key, capability_name,
  access_mode)` instead of capability name alone, so the diff can tell you
  which tool gained or lost which authority, not just that "shell" appeared
  somewhere in the project. The output adds a `tools` breakdown, `counts`
  (new/escalated/reduced/removed/unchanged tools, plus escalations by
  severity), and a `highest_escalation` summary. The pre-2.0 flat
  added/removed/changed diff is preserved verbatim under a `legacy` key and
  at the top level for existing consumers.
- **Thirteen capability escalation rules** (`safeai/analysis/escalation.py`):
  `ESC_SHELL_ADDED`, `ESC_FILESYSTEM_WRITE_ADDED`,
  `ESC_EXTERNAL_ACCESS_ADDED`, `ESC_MCP_SERVER_ADDED`,
  `ESC_MCP_READ_TO_MUTATE`, `ESC_APPROVAL_GATE_REMOVED`,
  `ESC_MEMORY_SCOPE_EXPANDED`, `ESC_WRITE_TOOL_ADDED`,
  `ESC_NEW_EXTERNAL_DESTINATION`, `ESC_AUTONOMY_INCREASED`, plus three
  combination rules that only fire when two conditions are true of the same
  tool at once — `ESC_COMBO_UNTRUSTED_INPUT_SHELL`,
  `ESC_COMBO_AUTONOMY_BROAD_DATA`, and
  `ESC_COMBO_DELEGATION_EXTERNAL_SIDE_EFFECT`. These exist because a single
  capability rarely tells you whether a change matters: an agent gaining
  shell access is a different story than one that already had it, and an
  agent that gains both autonomy and broad data access at once is riskier
  than the sum of the two changes taken separately.
- **Tool surface** (`safeai/analysis/tool_surface.py`): a per-tool capability
  index, built from data the scan already collected (agent models and MCP
  assets), with no additional file access. It is written into the JSON
  report, the KYA manifest (`tool_surface`, added at manifest schema 1.1),
  and the registry. An MCP configuration that does not name its server is
  recorded under the unattributed tool identity rather than assigned an
  invented name.

### Added — Deep Claude Code Analysis

- The Claude Code adapter moves from presence detection to structural
  analysis of `.claude/settings.json` and `.claude/settings.local.json` (in
  that precedence order), `.mcp.json`, `.claude/commands/*.md` slash
  commands, `.claude/agents/*.md` subagent definitions, and lifecycle hooks.
  See `FRAMEWORK_SUPPORT.md` for the full scope boundary.
- **Ten new rules**, documented with exact severities and OWASP LLM mappings
  in `RULES_REFERENCE.md`: `CC_WILDCARD_PERMISSION`,
  `CC_BYPASS_PERMISSIONS`, `CC_DENY_SHADOWED`, `CC_FS_WRITE_OUTSIDE_ROOT`,
  `CC_SLASH_COMMAND_SHELL`, `CC_SLASH_COMMAND_ARG_INJECTION`,
  `CC_SUBAGENT_PRIVILEGE_ESCALATION`, `CC_HOOK_SHELL_EXEC`,
  `CC_MCP_UNCONSTRAINED`, and `CC_SETTINGS_UNPARSEABLE`. Configuration that
  cannot be parsed is reported as a low-severity finding rather than
  silently skipped or treated as a crash.

### Added — PR Comment, CI Context, and the Assurance Boundary

- **PR comment renderer** (`safeai/report/pr_comment.py`): produces a short,
  reviewer-facing Markdown summary of capability escalations, grouped by
  tool with the worst severity first, capped at 60 lines. With no baseline
  it summarizes the first scan rather than fabricating a diff; with no
  changes it prints a single line. SafeAI only ever writes this file to
  disk or stdout — it never posts it anywhere and makes no network call of
  any kind. Publishing the comment is left entirely to the CI workflow. See
  the "Capability escalation in CI" section in `README.md`.
- **CI context detection** (`safeai/kya/ci_context.py`): reads environment
  variables (and, on GitHub Actions, the pull request event payload) to
  identify the provider, branch, base ref, commit, PR number, and
  repository. It never raises — outside CI it returns an
  all-`unknown`/`None` result — and supports GitHub Actions, GitLab CI, and
  Azure Pipelines.
- **Three new `safeai scan` flags**: `--pr-comment PATH` writes the Markdown
  summary to a file; `--pr-comment-stdout` prints it to stdout; and
  `--fail-on-escalation {critical,high,medium}` fails the scan when a
  capability escalation at or above that severity is found. This is a
  separate gate from `--fail-on`/`--fail-on-new`, which act on findings, not
  capability escalations; the two gates only add to the failing set, never
  subtract from it, and `--fail-on-escalation` requires `--baseline` because
  an escalation is by definition a change relative to something.
- **Assurance boundary** (`safeai/kya/assurance.py`): a short, factual
  statement of what a scan verified statically (declared tools, prompt and
  instruction files, MCP server configuration, workflow structure,
  permission configuration) and what it structurally cannot verify (IAM and
  cloud permissions, runtime identity, deployed network policy, actual
  runtime behaviour, dynamically constructed tool bindings). It is computed
  from real scan data — files actually skipped, configuration that actually
  failed to parse, and the count of access modes that were actually
  inferred rather than declared — never from a fixed template. Written into
  the manifest as `assurance_boundary` (manifest schema 1.2). See
  `KYA_MANIFEST.md` and `LIMITATIONS.md`.

### Added — Registry Schema v2

- **`agent_tool_snapshots` table**: one row per tool per scan, storing the
  tool's identity, kind, framework, its capability list, and a summarized
  access level. `agent_id` is nullable by design — a tool is attributed to
  an agent only when the tool's evidence paths overlap the agent's source
  locations, and a tool with no such overlap is stored unattributed rather
  than assigned a guessed owner or dropped. Uniqueness is enforced by an
  expression index (`IFNULL(agent_id, ''), scan_id, tool_key`) because
  SQLite treats `NULL` as distinct for ordinary `UNIQUE` constraints. See
  `REGISTRY.md`.
- **Automatic migration from schema v1**: existing registries gain the new
  table and indexes in place on the next scan. Migrations are additive and
  forward-only; no existing row in any table is dropped, rewritten, or
  renumbered.

### Changed

- `MANIFEST_SCHEMA_VERSION` is now `1.2`. The `tool_surface` array
  (introduced at 1.1, alongside this release) and the `assurance_boundary`
  object (new at 1.2) are both present in every manifest written by this
  version. `KYA_MANIFEST.md` has been brought up to date to document both.
- Baseline loading accepts a legacy JSON report or a KYA manifest of schema
  1.1 or later as the `--baseline` input, matching the existing baseline
  contract.
- Version bumped to `1.4.0b0` (`pyproject.toml`).

### Compatibility

- **Registries** created under schema v1 migrate automatically on the next
  scan and retain every existing row; nothing is deleted or renumbered by
  the migration.
- **Baselines** captured before v1.4 (no `tool_surface` in the manifest, or
  a legacy JSON report) still work with `--baseline` and
  `--fail-on-escalation`, but because they predate per-tool attribution,
  the diff cannot trust their structural tool status. In that case,
  individual per-tool escalation rules are suppressed and only the three
  combination rules are evaluated, since those depend on conditions within
  a single scan rather than on trusting the baseline's tool structure.
- No new runtime dependency was introduced. PyYAML remains the only
  third-party dependency.

## [1.3.0-beta] - 2026-07-31

### Added — KYA Baseline & Local Registry

- **Canonical KYA manifest** (`safeai-manifest.json`, schema v1.0): the
  portable public contract for scan-derived agent evidence, written via
  `--manifest`. See `KYA_MANIFEST.md`.
- **Local SQLite KYA registry** at `.safeai/registry.db`, created/updated
  automatically on interactive scans (auto-disabled when `CI` is set).
  Historical snapshots are append-only. See `REGISTRY.md`.
- **`safeai registry` command group**: `list`, `show`, `history`, `diff`,
  `export` with `--registry PATH` and `--format table|json`.
- **Deterministic finding fingerprints** (documented SHA-256 algorithm),
  stable `finding_id`s, confidence labels (`high|medium|low`), provenance
  records, and remediation defaults for high-value rules.
- **Baseline comparison** (`--baseline`): classifies findings as
  new/existing/resolved; accepts manifests or legacy JSON reports.
- **`--fail-on-new`**: opt-in gating on new/regressed findings only.
  Existing `--fail-on` semantics are unchanged without it.
- **Suppression workflow** (`.safeai/suppressions.yml`): required
  reason/owner/created, optional expiry and path scope; expired entries
  warn; suppressed findings stay visible and are excluded from gating.
- **Minimal policy-as-code** (`.safeai/policy.yml`): `allow|warn|
  require_review|deny` with rule/severity/capability/framework/agent/path/
  MCP-posture selectors; deterministic evaluation; outcome in terminal,
  manifest, HTML, and JSON. `deny` fails the scan.
- New scan flags: `--manifest`, `--registry`, `--no-registry`,
  `--strict-registry`, `--policy`, `--suppressions`, `--fail-on-new`.
- Terminal/HTML/SARIF output: KYA section, registry status, policy
  outcome, baseline counters, SARIF `partialFingerprints` and rule help
  text.
- Docs: `KYA_MANIFEST.md`, `REGISTRY.md`, `LIMITATIONS.md`; maturity
  categories in `FRAMEWORK_SUPPORT.md`; README/USER_GUIDE KYA sections.
- 66 new tests covering manifest determinism, fingerprints, baseline,
  suppressions, policy, registry persistence/queries/CLI, redaction, and
  CI behavior.

### Changed

- Scan engine skips `.safeai/` and SafeAI-generated artifacts (manifests,
  JSON reports) to prevent findings feedback loops. The JSON report now
  carries a `report_type: safeai.scan` marker (additive).
- JSON report findings gain additive keys (`fingerprint`, `finding_id`,
  `status`, `confidence_label`, `provenance`); no keys removed or retyped.
- `--baseline` still feeds legacy capability diff when given a legacy JSON
  report, and now also drives fingerprint comparison.
- Version bumped to `1.3.0b0` (`safeai/__init__.py` now matches
  `pyproject.toml`).

### Backward compatibility

- Existing CLI usage, exit codes, and JSON/HTML/SARIF shapes are preserved;
  all schema changes are additive. The manifest is a new artifact, versioned
  independently (`schema_version: 1.0`).
- Registry write failures never fail a scan unless `--strict-registry` is
  passed (exit code 2).

## [1.2.0] - 2026-07-26

### Added
- Eight new capability detectors (contributed by @yugaaank):
  - Docker (`CAP_docker`): `import docker`, `DockerClient`, `containers.run`
  - Kubernetes (`CAP_kubernetes`): `import kubernetes`, `kubectl`, `kube_config`, `k8s`
  - Redis (`CAP_redis`): `import redis`, `Redis()`, `StrictRedis`
  - S3 / Cloud Storage (`CAP_s3`): `import boto3`, `boto3.client('s3')`
  - Slack (`CAP_slack`): `import slack`, `slack_sdk`, `SlackClient`
  - Jira (`CAP_jira`): `import jira`, `JIRA()`, `jira.Client`
  - Browser Automation (`CAP_browser`): `playwright`, `selenium`, `webdriver`, `browser_use`
  - Google Cloud (`CAP_gcp`): `google.cloud`, `BigQuery`, `gcsfs`
- New capability categories: `Container` and `Collaboration`
- 20 tests in `tests/test_capability_detection.py` covering detection, false positives, multi-capability, and deduplication

### Changed
- `safeai/analysis/capabilities.py`: added `container` and `collaboration` categories
- `safeai/analyzers/capability/analyzer.py`: 8 new `CAP_PATTERNS`, `RULE_BY_CAP`, and `CATEGORY_BY_CAP` entries
- `safeai/rules/base_rules.yaml`: 8 new capability rules

## [1.1.0-beta] - 2026-07-24

### Added
- AI Component Security: skill, prompt file, tool definition, model config, and workflow template analysis
- Deep MCP analysis: per-tool broad permissions, sensitive resource detection, insecure transport detection
- Seven early-preview framework adapters: Claude Code, Google ADK, Mastra, Haystack, LlamaIndex, Dify, n8n (15 total)
- Capability diff (`--baseline` flag) comparing current scan against a previous JSON report
- Parser registry with `@register_parser` decorator and `safeai.parsers` entry-point group for third-party plugins
- Diagnostics reporting in scan output

### Changed
- Component and integration paths are relativized to scan root in all report formats
- Provider-aware model safety checks (`MODEL_MISSING_CONTENT_FILTER` scoped to Google/Bedrock/Azure)
- Dify and n8n detection tightened to reduce false positives
- Guard against `IndexError` in parser arg extraction

### Security
- Masked credential values in findings evidence across all report formats

## [1.0.0-beta] - 2026-07-18

### Added
- Multi-framework scanning: LangGraph, CrewAI, LangChain, Semantic Kernel,
  OpenAI Agents SDK, Microsoft Agent Framework, Azure AI Foundry, Bedrock Agent
- Prompt injection detection (LLM01): input interpolation, missing delimiters,
  system prompt leakage, role override attempts
- Capability analysis (LLM06): shell, filesystem, HTTP, database, code
  execution, autonomous loops, `subprocess` with `shell=True`, file writes
- Data leakage detection (LLM02): hardcoded API keys, tokens, passwords,
  environment secret references
- MCP analysis: config discovery, schema validation (v1.0/v1.1), missing auth,
  weak auth, missing permissions, exposed endpoints, hardcoded secrets
- Deterministic trust scoring across 7 risk categories (0–100)
- Reports: terminal, JSON, SARIF 2.1.0, HTML
- Custom YAML rules via `--rules`
- CI/CD exit codes via `--fail-on`
- GitHub Actions workflow with self-scan SARIF dogfooding
- Installable package with `safeai` console script and `python -m safeai`

### Security
- Credential values in findings evidence are masked in all report formats
- Scans exclude VCS directories, dependency caches, and oversized files
