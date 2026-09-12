# SafeAI v2.2 — Implementation Assessment (verified against repository state)

Date: 2026-09-12. Package version in source: `2.1.2` (`safeai/version.py:6`).
Latest Git tag: `v2.1.2` (tags present: v2.1.2, v2.1.1, v2.0.1, v2.0.0, …).
This assessment was written **before** any v2.2 code change, per the prime directive.
Every claim cites a repository-relative path. No network calls were made.

## 1. Package version, tags, releases

- `safeai/version.py:6`: `SAFEAI_VERSION = "2.1.2"`.
- `scripts/check_release.py:8`: pins `tag_version = "2.1.2"`.
- `CHANGELOG.md:8`: top entry `[2.1.2]` (Cosign signing); then `[2.1.1]`, `[2.1.0]`.
- Git tags (descending): `v2.1.2`, `v2.1.1`, `v2.0.1`, `v2.0.0`, `v1.9.1`, … — so the
  prompt's "release line is at least v2.1.2" is correct, and `ROADMAP.md:7`
  ("Current state: v2.0.1 is shipped", "v2.1 … in development") is **stale**.

## 2. Manifest contract — actual state

- Manifest schema version: `"1.2"` (`safeai/kya/__init__.py:12`
  `MANIFEST_SCHEMA_VERSION = "1.2"`; asserted in
  `tests/test_assurance.py:175` and `tests/test_kya_manifest.py:24`).
- **Discrepancy found:** `docs/reference/KYA_MANIFEST.md:28` documents a `1.3`
  row ("`evidence_type` on every finding"), but `safeai/kya/manifest.py:36-53`
  `_finding_entry()` emits **no** `evidence_type` key. `evidence_type` exists
  only in finding-enrichment/report metadata (`safeai/engine/metadata.py:77`
  `"schema_version": "1.3"` is the *evidence* schema, plus
  `tests/test_evidence_type.py`). The manifest document itself is 1.2.
  v2.2 must resolve this (schema v1.0.0 contract restarts versioning cleanly;
  see WS1 plan — manifest contract gets its own `contract.version`,
  independent of the legacy `schema_version` string).
- Generation: `safeai/kya/manifest.py:73-177` `build_manifest()`; deterministic
  serialization `serialize_manifest()` (`:180-182`, `sort_keys=True`, 2-space
  indent + trailing newline); writer `write_manifest()` (`:185-187`).
- Emitted top-level keys (`:102-176`): `schema_version`, `manifest_type`,
  `generated_at`, `safeai{version,ruleset_version,config_hash,custom_rules_dir,
  custom_rules_count,builtin_rules_count,rule_pack_ids}`, `project{project_id,
  name,source_root,repository}`, `scan{scan_id,started_at,completed_at,
  files_scanned,analysis_coverage}`, `agents`, `tool_surface` (v1.1),
  `components`, `dependency_inventory`, `findings[]` (with `finding_id,
  rule_id, severity, title, message, remediation, confidence, provenance,
  location, fingerprint, status`), `summary`, `assurance_boundary` (v1.2),
  `limitations`.
- Wiring: `safeai/cmd/postprocess.py` (`_build_manifest`, `manifest_path`
  handling; ruleset hash `sha256:…[:16]` at `:34-35`); CLI flag
  `safeai scan --manifest PATH` (`safeai/cmd/cli.py:56-57`).
- Baseline accepts a manifest: `safeai/kya/baseline.py:4` (canonical manifest
  preferred, legacy JSON accepted).
- Portable registry inventory is a **separate** contract:
  `safeai/kya/exporter.py:24` `EXPORT_SCHEMA_VERSION = "1.1"`,
  `export_type: "safeai.kya.inventory"`; validated by
  `safeai/kya/importer.py:15,29-78` (`SUPPORTED_SCHEMA_VERSIONS = {"1.0",
  "1.1"}`, field-level errors, deterministic import scan IDs at `:81-88`).
- **No manifest validation entry point exists**: grep for
  `manifest validate|manifest verify|manifest sign|require-integrity|
  payload_sha256` finds nothing in `safeai/`. `registry import` validates
  *inventory* documents only, not manifests.
- **No published JSON Schema**: `schemas/` directory does not exist.
- **No integrity block**: no `integrity`, `payload_sha256`, canonical-digest,
  signature, attestation, or provenance fields in `build_manifest()`.
  Release-level signing exists (Cosign `.sig`/`.pem` per artifact since v2.1.2,
  `actions/attest-build-provenance`, SBOM, `SHA256SUMS` — see
  `.github/workflows/release.yml` Gate 4) but nothing signs or hashes the
  *manifest content itself*. `config_hash()` (`manifest.py:30-33`) hashes only
  the effective config, not the manifest payload.

## 3. ChangeGuard / escalations — actual state

- 14 `ESC_*` rules shipped in `safeai/analysis/escalation.py:248-364`
  (`ESCALATION_RULES`): `ESC_SHELL_ADDED`, `ESC_ACCESS_MODE_INCREASED`,
  `ESC_FILESYSTEM_WRITE_ADDED`, `ESC_EXTERNAL_ACCESS_ADDED`,
  `ESC_MCP_SERVER_ADDED`, `ESC_MCP_READ_TO_MUTATE`, `ESC_APPROVAL_GATE_REMOVED`,
  `ESC_MEMORY_SCOPE_EXPANDED`, `ESC_WRITE_TOOL_ADDED`,
  `ESC_NEW_EXTERNAL_DESTINATION`, `ESC_AUTONOMY_INCREASED`, plus 3 combos
  (`ESC_COMBO_UNTRUSTED_INPUT_SHELL`, `ESC_COMBO_AUTONOMY_BROAD_DATA`,
  `ESC_COMBO_DELEGATION_EXTERNAL_SIDE_EFFECT`). Covered by
  `tests/test_escalation.py` (subsumption, combos) and
  `tests/test_capability_diff_v2.py:49`.
- Rule table entries carry only `id/severity/trigger/names/summary` — **no**
  `why_it_matters`, `review_questions`, `recommended_actions`,
  `safe_configuration_patterns`, or `limitations` fields anywhere in
  `escalation.py` (verified: grep for those keys returns nothing).
- Finding-level `remediation` (for `CAP_*/GOV_*/MCP_*/PROMPT_*/DATA_*` etc.)
  **does** exist: analyzer-emitted strings plus
  `safeai/kya/enrich.py:16-26` `DEFAULT_REMEDIATION` fallback; persisted to
  registry (`kya/registry/schema.py:74`, `persist.py:300-310`,
  `importer.py:381-389`); present in JSON/manifest (`manifest.py:43`),
  SARIF rule help + result props (`report/sarif.py:16-23,81-82`), HTML
  (`report/html.py:325,353`), scorecard JSON + Markdown
  (`scorecard.py:387,545-550`, `scorecard-schema.json:122`).
- **Gaps (WS3 scope, real):**
  - Terminal (`report/terminal.py:102-106`) prints only
    `[severity] file:line - message`; no remediation, no next action.
  - PR comment (`report/pr_comment.py`, 397 lines) has **zero** remediation
    references (grep: no hits); hard cap `MAX_LINES = 60`, target 20
    (`:30-35`), deterministic, marker-first (`:28`) — constraints to preserve.
  - Escalation diffs (`capability_diff.escalations`) carry `id/severity/
    summary` only; no structured remediation object flows to any output.

## 4. Fixtures, golden tests, regression, benchmarks

- `tests/fixtures/` has 20 top-level dirs: 17 framework adapters
  (`azure_foundry, bedrock_agent, claude_code, crewai, cursorrules, dify,
  google_adk, haystack, langchain, langgraph, llamaindex, mastra,
  microsoft_agent, n8n, openai_agents, semantic_kernel, windsurf`)
  + `mcp/` (golden dir + `clean_tool.json`/`poisoned_tool.json`) +
  `action/` (clean/risky) + `regression/` (6 dirs: `claude_code_deny_allow,
  config_discovery, dataflow_casing, governance_suppression, mcp_injection,
  runaway_loop`).
- Golden-test infra: `tests/test_compatibility.py` (per-adapter golden
  classes + `TestFixtureCoverageCompleteness`); 79 rules in
  `safeai/rules/base_rules.yaml` (families CAP/CC_/DATA*/DEP/ENV/GOV/MCP/
  MODEL/PRO*/SKI*/TOO*/WOR*).
- Failure-class matrix: `safeai/report/failure_matrix.py` (GOV_* → failure
  classes), asserted non-empty in release checklist (`release.yml`).
- **No benchmark system**: `benchmarks/` dir, `BENCHMARKS.md`, and
  `scripts/run_benchmarks.py` all absent (`Test-Path` → False). No pinned
  15–25 corpus, no catalog, no runner, no published accuracy table.
- **No performance measurement collection**: no timing/benchmark scripts in
  `scripts/` (`build_standalone.py, check_release.py, check_wheel.py,
  create_good_first_issues.py, generate_release_artifacts.py,
  run_local_integration.py, safeai-action.py` only); scan duration is not
  recorded in manifests.
- Community scans exist (`community-scans/`, validation workflow) but are
  not wired into a regression corpus.

## 5. Governance, DCO/CLA, editions, MCP scope

- **No DCO/CLA**: no `DCO.md`/`CLA*` file; grep for `Signed-off-by|Developer
  Certificate` finds only `CLAUDE.md` fixture noise and roadmap prose
  (`ROADMAP.md:302` lists DCO/CLA as *planned* EE0 work). `CONTRIBUTING.md`
  exists but contains no sign-off requirement (verified by grep).
- **Edition boundary**: only in `ROADMAP.md:5,24,284,288-303` prose.
  No standalone `docs/GOVERNANCE_AND_EDITIONS.md`; README/CONTRIBUTING/ROADMAP
  do not link to one (it doesn't exist). "No detection gating by edition" is
  stated (`ROADMAP.md:284`) but not published as a commitment doc.
- **MCP scope**: repo-local default + opt-in IDE scopes
  (`--mcp-ide-scopes`, `cli.py:111-113`) is implemented; export exclusion of
  out-of-repo evidence is implemented per roadmap. But no ADR or dedicated
  policy doc records the decision; no `docs/adr/` directory exists.
- **Trademark**: no policy file; nothing claims registration (good) — needs
  the neutral decision record the prompt requests.
- `PRIVACY.md` exists (telemetry transparency, Phase 1).

## 6. ROADMAP.md accuracy

Stale in at least these places (all verified above):
- `:7` "Current state: v2.0.1" — actual: v2.1.2 shipped (PyPI + GitHub
  Release + Cosign signatures).
- `:184-206` "v2.1 … in development / Target Q4 2026 / 5-of-6 shipped" —
  actual: all v2.1 items shipped and released (v2.1.0→v2.1.2).
- `:209-239` "v2.2 — Visibility & Intelligence (trend tracking, architecture
  maps, AI-BOM, toxic-flow, exploitability pilot…)" — this is **not** the
  v2.2 the prompt defines ("Contract & Proof"). Must be re-sequenced per
  §10 of the prompt (CE 2.2/2.3/2.4/CE-V/EE0/EE1–4).
- Inventory `:374-413` says "15 framework adapters… 76 built-in rules" —
  actual: 17 adapters, 79 rules.

## 7. What v2.2 must (and must not) do

**Necessary (gaps verified above, none already complete):**
1. WS1: publish `schemas/safeai-manifest/v1.0.0.json`; add `contract{}`
   metadata; add `manifest validate` path reusing stdlib (+documented
   limits); write `docs/manifest/{README,COMPATIBILITY,EXAMPLES}.md`;
   resolve the 1.2-vs-1.3-doc discrepancy explicitly. Reuse
   `serialize_manifest`, `build_manifest`, `validate_inventory` patterns.
2. WS2: canonical SHA-256 digest over a documented canonical payload
   (exclude `integrity` itself + volatile `generated_at/scan_id/timestamps`);
   `manifest verify`; optional `--require-integrity` on `registry import`
   (default off); detached-signature *spec + GPG external* docs only —
   no new crypto code (stdlib `hashlib` suffices for hashing).
3. WS3: remediation catalog for all 14 `ESC_*` rules (new module, e.g.
   `safeai/analysis/escalation_remediation.py`); wire into JSON/manifest/
   SARIF/HTML/terminal(next-action line)/PR-comment(1 line per crit/high,
   within 60-line cap)/scorecard(themes). No auto-fix, no diffs.
4. WS4: `benchmarks/` corpus (15–25, synthetic, from existing fixtures),
   `scripts/run_benchmarks.py`, `BENCHMARKS.md`, CI wiring (release-blocking,
   PR subset). Reuse `run_scan`, golden fixtures, failure matrix.
5. WS5: `DCO.md`, `docs/GOVERNANCE_AND_EDITIONS.md` (+3 README/
   CONTRIBUTING/ROADMAP links), MCP-scope policy doc, `docs/adr/0001-0004`.
6. WS6: rewrite `ROADMAP.md` per prompt §10 with shipped/remaining/
   not-in-core table.

**Must NOT duplicate (already shipped):** quality gates (`--fail-on-rule`,
`--fail-on-category`), `--pr-comment-post`, MCP poisoning detection,
standalone binaries, VS Code MVP, golden fixtures for all 17 adapters,
fixture-coverage + support-matrix release checks, Cosign release signing,
PyPI trusted publishing, finding-level remediation in JSON/manifest/SARIF/
HTML/scorecard, assurance boundary, registry export/import, policy profiles,
suppressions, lifecycle, failure matrix.

## 8. Constraints pre-check (for implementation)

- Deps: PyYAML + stdlib only — WS1 validator must be stdlib-only with
  documented limits; WS2 hashing via `hashlib.sha256` (already used via
  `kya/util.py:sha256_text`); no new runtime deps planned.
- Determinism: reuse `serialize_manifest` conventions (sorted keys);
  integrity payload must exclude volatile fields; benchmark timing is
  measurement-only, never hashed.
- Privacy: reuse `redact_secrets`; remediation/benchmark docs must carry
  no source values; no network/execution in benchmark runner.
- Compat: manifest 1.2 documents must still import; `--require-integrity`
  default off; unknown-field policy = ignore (matches `KYA_MANIFEST.md:19`
  and inventory practice).
