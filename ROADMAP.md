# SafeAI — Roadmap

SafeAI is a **Static AI Capability & Risk Analyzer** — think SonarQube for AI agents and workflows.

This document describes the roadmap across **two editions**: the open-source **Community Edition (Apache 2.0, offline, local-first)** and the commercial **Corporate Edition (evidence and governance plane)**. Milestones are not strictly sequential; work may proceed in parallel where dependencies allow.

> **Current state:** v1.9.0 is shipped. Community Edition **CE 1.4 (Reviewable Change)** is complete; **CE 1.5 (True Capability Surface)** env inventory + correlation shipped; **CE 1.6 (AI Component Records)** — component version/hash, impact-query CLI shipped in v1.9.0; unpinned-reference detection and lockfile-style integrity remain planned; **CE 1.8 (Code-Level Authority & Provenance)** is complete (tool↔implementation mapping, command-aware MCP resolution, target taxonomy, finding lifecycle, stale suppression guard, agent metadata, prompt/data-leakage depth, cross-component graph); **v1.9.0** is shipped (component depth, ecosystem foundations, `safeai init`, governance signal detection, data-flow analysis, control mappings); **CE 2.0** (plugin ecosystem, static IaC authority correlation) — `safeai init` and control mappings shipped; plugin SDK, portable registry import, per-scan plugin versions remain planned; **CE-V** (pre-deployment validation packs) are planned; the entire Corporate Edition remains planned.

---

## Community Phases at a Glance

| Phase | Question | Status |
|---|---|---|
| **Phase 1** — What can this AI application do? | Capability, tool, MCP, prompt discovery | ✅ Shipped |
| **Phase 2** — What changed since the last approved version? | Tool-centric escalation diffs, PR review, governed waivers, lifecycle | ✅ Shipped |
| **Phase 3** — Does declared capability match deployed authority? | Static IaC correlation (CE); live IAM reconciliation (Corporate) | 🔄 CE 2.0 / EE3 |
| **Phase 4** — Does the agent resist manipulation at its risk surfaces? | Capability-informed validation packs, adversarial regression | ⏳ CE-V (planned) |

---

# Roadmap 1 — Community Edition (Apache 2.0, offline, local-first)

**Mission:** know your agent before you deploy it, with zero setup, no account, and no network.

**Constraint:** if a feature does not improve a developer's ability to understand, remediate or prevent a risky agent change *before deployment*, it is not in the Community core.

Status legend: ✅ **Shipped** · 🔄 **In progress / partial** · ⏳ **Planned**

---

## CE 1.4 — Reviewable Change (the PR release)

*Goal: make SafeAI the thing a reviewer reads first on any PR that touches an agent.*

**Status: ✅ shipped (v1.3 → v1.4 → v1.4-b → v1.5 → v1.6 → v1.7.0). CE 1.4 is complete; remaining governance items (lifecycle timeline, enrichable metadata, governance signals) are curated into v1.8.0.**

### Tool-centric diff model *(do this first — it is a schema change)*
- ✅ Re-key capability snapshots on `(tool_identity, capability, access_mode)` instead of flat capability sets — `safeai/analysis/tool_identity.py` (path-independent keys), `tool_surface.py`, `capability_diff.py` (schema v2, per-tool).
- ✅ Track access-mode transitions explicitly — `read-only → mutating` is a first-class escalation (ranked `none < read < write < mutate < execute`, with inference and severity caps).
- ✅ Persist per-agent snapshots of capability, authority, autonomy, data reach and governance evidence per scan (`agent_snapshots`, `agent_tool_snapshots` v2).
- ✅ Migration path for existing v1.3 registries — additive, forward-only `_MIGRATIONS` (1 → 2).

### PR escalation review
- ✅ Detect and rank: new shell capability, filesystem write added, external HTTP/API access added, new MCP server bound, MCP read-only → mutation, human approval gate removed, memory scope expanded, new write-capable tool, new external destination — 14 `ESC_*` escalation rules in a data table with subsumption, `--fail-on-escalation`.
- ✅ `--pr-comment` / `--pr-comment-stdout`: a short, grouped, reviewer-facing summary (never posted by SafeAI) — grouped by tool/server, leads with escalations, suppresses unchanged surface.
- ✅ Branch/base auto-detection — GitHub Actions, GitLab CI, and Azure Pipelines (`safeai/kya/ci_context.py`, `PROVIDERS`).
- ✅ Risky-combination detection — untrusted input + shell, autonomous planning + broad access, delegation + external side effects (`ESC_COMBO_*`).
- ✅ **GitHub Actions Marketplace action** — composite action (`action.yml`) with SARIF upload, scorecard outputs, and native exit-code passthrough. Hermetic install path (`SAFEAI_ACTION_FIND_LINKS`), least-privilege design (`contents: read`), `set_output` sanitisation, and self-validating CI (`scripts/safeai-action.py`, `.github/workflows/action-test.yml`, 24 tests).

### Surface depth *(the two that matter)*
- ✅ **Multi-source MCP discovery** — MCP servers discovered across the scanned repo and Claude Code configuration, normalised into one capability model with provenance on every entry. Repo-local IDE scopes (`.cursor/`, `.windsurf/`, `.vscode/` via `--mcp-ide-scopes`) are now read; out-of-repo user/global scopes remain behind an explicit gate and excluded from exports by default.
- ✅ **Deep Claude Code analysis** — `.claude/settings.json`, instruction files, permissions, `allowedTools`, custom slash commands (treated as an injection surface), subagents, hooks, dangerous/auto-approve flags, project structure (10 `CC_*` rules; repo-local scope only, never user/machine config).
- ✅ **MCP posture** — transport, authentication evidence, exposed tools and resources, wildcard permissions, local vs remote endpoint risk, configuration provenance.

### Governance and lifecycle
- ✅ **Governed suppressions** — suppressions carry rule_id, file, location, reason, owner, expiry and are never silent. Stale-suppression *detection* (warning) shipped earlier; **CI failure on expired or moved suppressions shipped in v1.7.0** via `--strict-suppressions`.
- ✅ **Per-finding lifecycle timeline** — introduced → resolved → reopened, with repeated reopening flagged as a governance signal. **Shipped in v1.8.0** (Finding Lifecycle Event Engine, `finding_lifecycle` table / schema v4, `ESC_RECURRING_RISK`).
- ✅ **Policy profiles** — policy-as-code (`allow / warn / require_review / deny`) plus five named profiles (`developer`, `strict-ci`, `mcp`, `rag`, `production-agent`) via `--policy-profile NAME`; bundled in `safeai/policy_profiles/`.
- ✅ **Policy decision recorded on every scan** (pass / warn / review-required / block / accepted-exception, with rationale).
- ✅ **Registry freshness indicators** — never scanned, stale, changed since last approval, policy drift. `last_scan_timestamp` and `scan_count` tracked in registry; `safeai registry list` and the HTML report surface freshness status.
- ✅ **Locally enrichable agent metadata** — business owner, technical owner, intended purpose, environment, lifecycle status, review date. **Shipped in v1.8.0** (`safeai registry metadata set`, decoupled `agent_metadata` table, rendered in HTML).
- ✅ **CLI version support** — `safeai --version` / `-V` prints a stable machine-readable line; single source of truth in `safeai/version.py` (`SAFEAI_VERSION`), with `pyproject.toml` reading the version dynamically from `safeai.__version__`.
- ✅ **Developer guide** — local development and GitHub Actions usage guide (`DEVELOPER_GUIDE.md`), including the Security Scorecard flags.

### Trust and honesty
- ✅ **Mandatory machine-readable assurance boundary block** in every report and manifest — what was verified (declared tools, prompt files, MCP servers, workflow structure, configuration) versus what cannot be verified statically (IAM permissions, runtime identity, deployed network policy, actual behaviour) — `assurance_boundary`.
- 📋 **Telemetry transparency** — the assurance boundary block will include a `telemetry_active` boolean field reflecting whether opt-in telemetry was enabled for that scan (Phase 2 of telemetry implementation).
- ✅ **Governance signal detection** — timeout, retry policy, approval workflow, audit logging, rate limiting, circuit breaker, backpressure, health check. **Shipped in v1.9.0** (8 `GOV_*` rules, `GovernanceAnalyzer`, per-tool dedup, scoped source confirmation).
- ✅ **Better terminal output** — severity-grouped summary, clear layout, improved signal-to-noise (v1.4-b).
- ✅ **Severity-weighted trust score** — 7-category weighted scoring keyed on `safeai/severity.py`.
- ✅ **Security Scorecard** — a deterministic, auditable 0–10 report summarising a scan into an overall score, per-category scores, and a `pass`/`warn`/`fail` outcome. Markdown, JSON (`scorecard-schema.json`), and GitHub Actions step summary outputs. `--scorecard-fail-under N` gating. ~55 tests (`safeai/scorecard.py`).

### Exit criterion
> ✅ **Achieved.** A reviewer sees, in a PR comment, that a specific **named tool** gained a specific **new authority** — and SafeAI records that change, the policy decision and the assurance boundary in local KYA history. Ordinary SAST does not produce that.

---

## CE 1.5 — True Capability Surface

*Goal: close the gap between what an agent declares and what it actually needs to run.*

**Status: ✅ shipped (v1.5.0); remaining surface items planned below.**

- ✅ **Secret and configuration dependency inventory** — names and sources only, never values: `os.getenv`, `os.environ`, `process.env`, dotenv keys, shell/template interpolation, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Kubernetes `secretKeyRef` (`safeai/analyzers/env_dependency`).
- ✅ **Dependency-to-capability correlation** — referenced credential/config with no matching declared capability = undeclared-capability candidate; declared credential-demanding capability with no referenced config = orphaned tool (`safeai/analysis/dependency_correlation.py`, rules `DEP_*`). Correlation findings feed severity, trust score, SARIF, HTML and the manifest. Matching uses whole-word-segment family keywords (no substring false positives on `jdbc`/`rabbit_mq`), with provider families taking precedence over the generic `api` fallback; the payload-carrying `ENV_DEP_INVENTORY` finding is exempt from suppression so the inventory section can never be blanked.
- ✅ **Tool → implementation mapping** — declaration site, implementation site, unresolved/orphan cases in both directions. **Shipped in v1.8.0** (Tool ↔ Implementation Mapping correlator; orphan states in reports).
- ✅ **Command-aware MCP analysis** — resolve in-repo and vendored server entrypoints statically, depth-capped, never executed, with explicit resolved / unresolved-command labelling. **Shipped in v1.8.0** (Command-Aware MCP Resolution; `assurance: resolved` vs `unresolved-command`).
- ✅ **External write target taxonomy** — filesystem, databases, S3, blob storage, GitHub, Slack, external APIs — promoted to a first-class report view. **Shipped in v1.8.0** (Target Taxonomy Engine; Database / Object Storage / SaaS API buckets in HTML/JSON).
- ✅ **Heuristic data-flow depth** — untrusted input propagation into prompts and tool arguments. **Shipped in v1.9.0** (`DataFlowAnalyzer`, 6 `DATAFLOW_*` rules, placeholder-aware confidence, `.py`-only filter).
- ✅ **Prompt risk depth** — move beyond single-line regex: multi-line prompt concatenation detection, cross-file prompt interpolation (prompt file → code), indirect injection via tool calls embedded in prompts, XML/HTML tag injection in prompts, template variable injection in `.md` files. **Shipped in v1.8.0** (deepens `PROMPT_*` / `PROMPT_FILE_*` rules).
- ✅ **Data leakage depth** — expand beyond the 4 basic patterns: private keys (`-----BEGIN RSA PRIVATE KEY-----`), JWT tokens (`eyJ...`), AWS access keys (`AKIA...`), connection strings (`mongodb://`, `postgres://`), base64-encoded secrets, hex-encoded secrets. Per-pattern severity differentiation (private keys = critical, connection strings = high). **Shipped in v1.8.0** (deepens `DATA_LEAKAGE` rule).
- ✅ **Adapter completion** — AutoGen, LangGraph `add_conditional_edges`, browser-automation rule split (Playwright / Selenium / browser_use). **Shipped in v1.9.0**.

### Exit criterion
> SafeAI reports the credentials and destinations an agent actually depends on, and flags mismatches between declared and required capability — with no cloud access and no execution.

---

## CE 1.6 — AI Component Records

*Goal: extend evidence from agents to the reusable components they share. Deliberately after 1.5.*

**Status: ✅ shipped. Component-level analysis ships (skills, prompts, MCP configs, tool definitions, workflows, model configs); registry persistence (schema v3) and component-change diffs shipped in v1.7.0. Remaining depth items (version/hash, impact-query CLI, unpinned/unsafe-composition detection, manifests) are curated into v1.8.0.**

- ✅ Treat prompts, skills, MCP configurations, tool definitions, workflows and model configs as versioned components (component analysis → findings).
- ✅ Scan only local and vendored artifacts — no external feeds.
- ✅ Detect embedded prompts, hard-coded secrets, over-broad permissions, insecure defaults. (Unpinned references and unsafe *composition* across component analyzers are **not yet** detected at the component level — only proxy heuristics exist in the unrelated Claude Code analyzer.)
- ✅ Record component identity, source, and usage relationships in the local registry — schema-v3 `component_snapshots` (type, name, path, source, line, data JSON, first/last-seen) shipped in v1.7.0. **Component version/hash and explicit findings linkage are deferred** (the bug where the diff compared a scan to itself was fixed in v1.7.0).
- ✅ **Impact queries** — `safeai registry components` lists tracked components with deduplication, type filtering, and consuming-agent resolution (`list_components_deduped`, `get_component_agents`). **Shipped in v1.9.0**.
- ✅ **Component-change diffs** — a changed/added/removed MCP configuration (or skill/prompt/tool/model) flags consuming agents via the `component_diff` report section (computed against the baseline scan).
- ✅ **Cross-component analysis** — analyze relationships between components: skill X references tool Y with shell access, workflow step calls dangerous tool, MCP server exposes tool used by workflow, model config sets unsafe temperature AND workflow has no approval gate, subagent has shell access AND parent has no approval. **Shipped in v1.8.0** (new `analysis/component_graph.py`; bridges `skill`→`tool_def`→`workflow`→`mcp`→`model_config` findings).
- ⏳ Component manifests where feasible; lockfile-style integrity metadata deferred to 2.x. **Targeted for v1.9.0**.

### Exit criterion
> A team can trace a risky reusable component to every consuming agent and repository, and produce static evidence for remediation.

---

## CE 1.8 — Code-Level Authority & Provenance ✅ shipped (v1.8.0)
The Remaining "Deep Dive" Features (Currently marked as ⏳ in CE 1.5 and CE 1.6)
These are the items that go deeper on your existing capabilities, but are not yet implemented:

- Tool → Implementation Mapping: SafeAI extracts tool definitions but needs to map the declaration site to the actual implementation site.
- Command-Aware MCP Analysis: The scanner needs to resolve command: python server.py by inspecting the actual local script to extract its true capability surface (labeled resolved or unresolved-command).
- External Write-Target Taxonomy: Needs explicit taxonomy grouping for external write destinations (S3, Databases, Slack).
- Per-Finding Lifecycle Timeline: Needs to track findings longitudinally (introduced → resolved → reopened) and flag recurring risks.
- Stale Suppression Guard: Needs to track if a suppression is invalid because the underlying code or fingerprint changed.
- Agent Metadata: Needs a schema to store Business Owner, Technical Owner, and Environment.

---

## CE 2.0 — Ecosystem and Static Authority Correlation

*Goal: grow coverage through contribution, and answer the authority question without leaving the repository.*

**Status: 🔄 plugin architecture; the rest ⏳ planned.**

### Ecosystem
- 🔄 **Stable plugin SDK** — framework adapters are pluggable via the `@register_parser` decorator and the `safeai.parsers` entry-point group. **Analyzers and rules are not yet entry-point discoverable**: analyzers are hard-coded in the orchestrator and rules are directory-loaded YAML (the `safeai.parsers` group is declared but currently empty). Report enrichers and policy packs planned.
- ⏳ **Curated (and signed where practical) community registry** for versioned rule and policy packages.
- ✅ **`safeai init`** — scaffold config, local registry, recommended policy profile. **Shipped in v1.9.0**.
- 🔄 **Custom rule authoring** — the `--rules <dir>` directory loader (custom YAML overriding built-in rules by ID) shipped; authoring *scaffold* with fixtures, tests, and expected-findings tooling is planned.
- ✅ **Control mappings** — OWASP Top 10 for Agentic Applications, OWASP Top 10 for LLM Applications, NIST AI RMF 1.0 (NIST AI 100-1) — presented as taxonomy, policy selection and prioritisation aid, explicitly **not** as coverage or compliance claims. **Shipped in v1.9.0**.
- 🔄 Plugin and rule-pack versions recorded in every scan — the **ruleset version** is recorded on every scan (manifest + registry); per-parser/plugin versions are not yet recorded.
- 🔄 **Portable registry export/import** — `registry export` (portable KYA inventory JSON, source- and secret-safe, `--include-history`/`--include-suppressed`) **shipped**; `import` is not yet implemented.
- ⏳ **Opt-in usage telemetry** — anonymous, opt-in, local-first usage signal (SafeAI version, Python version, OS family, invocation context). Disabled by default; CI auto-disable; `DO_NOT_TRACK` respected; never transmits scan content. Two-phase: Phase 1 (documentation + PRIVACY.md) → Phase 2 (client implementation). **Phase 1 planned for v2.0.0.**

### Static authority correlation *(the community's Phase 3, offline)*
- ⏳ Parse in-repo IaC — Terraform, CloudFormation, Helm, Kubernetes manifests, serverless configs.
- ⏳ Compare declared capability against granted authority and report both directions: capability without grant (probable breakage), and grant without capability (excess authority).
- ⏳ Report confidence honestly — IaC in the repo is not proof of what is deployed, and the assurance boundary block must say so.

### Exit criterion
> A contributor can add an adapter or rule pack with tests, and a reviewer can see declared-versus-granted authority mismatches using only files already in the repository.

---

## v2.0.0 — Governance Depth & Ecosystem Expansion *(planned)*

*Goal: deepen governance detection, harden MCP against content-level attacks, expand config-file coverage, and present governance gaps as failure-class coverage.*

**Status: ⏳ planned. Target: after v1.9.1.**

### Governance depth
- ⏳ **Runaway-loop / token-bombing / recursion-guard detection** — missing loop bounds, missing max-iteration guards, recursive agent-to-agent call chains without depth limits, unbounded recursive tool calls. Extends the `GOV_*` rule family (e.g. `GOV_MAX_ITERATIONS_MISSING`, `GOV_RECURSION_GUARD_MISSING`). Slots naturally next to the existing timeout/retry/circuit-breaker rules in the `GovernanceAnalyzer`. Addresses cost-exhaustion attacks and unbounded agent recursion — a top-marketed AI agent risk.
- ⏳ **Failure-class coverage matrix** — group existing `GOV_*` findings by the class of failure they leave the agent unprepared for (dependency timeout, dependency unavailable, resource exhaustion, cascading failure, malformed config). Present as a coverage matrix: "this agent has no statically detectable circuit breaker, retry, or backpressure control, so cascading failure behavior is unverified." Not new detection logic — it is a view layer over `GOV_TIMEOUT_MISSING`, `GOV_RETRY_MISSING`, `GOV_CIRCUIT_BREAKER_MISSING`, `GOV_BACKPRESSURE_MISSING`, `GOV_HEALTH_CHECK_MISSING`, `GOV_RATE_LIMIT_MISSING`, `GOV_AUDIT_MISSING`, `GOV_APPROVAL_MISSING`. Shifts the operator question from "which rules fired?" to "which failure modes can this agent survive?" Source: Reddit community feedback (2026-09).

### MCP hardening
- ⏳ **MCP tool-description/schema poisoning detection** — detect hidden instructions embedded in MCP tool description or schema fields that get silently injected into the agent's context ("tool poisoning"). Extends the existing MCP analyzer (currently structural: resolved vs unresolved-command) with content-level inspection of tool metadata. Aligns with the existing `PROMPT_*` depth work (multi-line, cross-file, indirect injection).

### Config-file coverage
- ⏳ **Config-file-level agent scanning** — native support for `.cursorrules`, Windsurf/OpenClaw configs, Copilot configs as first-class scan targets alongside Claude Code permission analysis (`safeai/frameworks/claude_code/permissions.py`). Each config format gets its own adapter; capability and governance analysis over agent configuration files that declare permissions, tools, and behavioral constraints.

### Exit criterion
> SafeAI detects token-bombing risks in governance signals, catches tool-poisoning in MCP metadata, scans agent config files across all major IDE frameworks, and presents governance gaps as a failure-class coverage matrix — all offline, all static, all in the Community Edition.

---

## CE-V — Pre-Deployment Validation Packs *(planned)*

*Goal: turn SafeAI's static capability map into a CI-runnable adversarial test suite for agents.*

**Rationale:** Static analysis tells you what an agent *can do* and what *changed*; adversarial validation tests whether the agent *resists* manipulation at those exact risk surfaces. NIST AI 600-1 describes structured pre-deployment testing as a mandatory activity for GenAI systems. This feature is *not* a runtime sandbox, hallucination benchmark, or general jailbreak lab — it is a tightly scoped pre-deployment harness generated directly from the KYA manifest.

**Status: ⏳ planned.** CE-V 1-2 are Community Edition; the external handoff (CE-V 3) belongs in Corporate (EE3).

### CE-V 1 — Validation Pack Generator

- Read the KYA manifest and produce a version-controlled test plan (`safeai-validation-plan.json`)
- Generate adversarial queries only for detected risk surfaces — no blind brute-force prompts
- Pack types: prompt injection, indirect retrieval injection, tool-invocation abuse, approval-gate bypass, sensitive-data exfiltration
- **Fault-injection test plans derived from the failure-class coverage matrix** — "this agent declares a dependency on service X with no retry evidence; inject a timeout on X and assert graceful degradation." Each uncovered failure class maps to a concrete fault-injection scenario with setup, trigger, and assertion. Source: Reddit community feedback (2026-09).
- Each test carries: surface type, severity, test input, expected safe behavior assertion, linked finding ID
- Deterministic local harness: offline, no model calls, no external network, no runtime observation
- Deterministic pass/fail assertions: "must refuse," "must not call tool X," "must request approval"
- `safeai validate` command with exit-code gating and SARIF output
- Validation results labelled as "adversarial test evidence" — never conflated with static-scan evidence
- Assurance boundary block distinguishes what was tested from what was not

### CE-V 2 — Regression & Pack Versioning

- Persist validation results in the local SQLite registry alongside scan evidence
- Regression mode: previously failed tests become mandatory passing checks
- Pack versioning: record pack version, query set, and assertion schema in the manifest
- `safeai validate diff` to show validation status changes between commits
- Community-contributed validation packs (consistent with CE 2.0 community registry)

### Exit criterion
> A developer can run `safeai validate` in CI, see which capability-informed attacks the agent resisted or failed, and link each failure to the source finding.

---

## CE permanent guarantees

- ✅ **Local by default** — no account, server, daemon, telemetry or external network calls.
- **Amended 2026-08-30:** SafeAI remains local-by-default and offline-by-default. An **opt-in only** usage-telemetry mechanism was added in v2.0.0; it is disabled unless a user explicitly enables it, is auto-disabled in CI, never transmits scan content, and can be permanently disabled with one command or one environment variable. See `PRIVACY.md` for the full data contract.
- ✅ **Source-private by default** — references and evidence, not raw source.
- ✅ **Static truth only** — detected evidence always distinguished from unknown runtime state.
- ✅ **No compliance certification claims** — mappings and evidence, never a declaration that an agent is safe or compliant.
- ✅ **No runtime-platform creep in core** — no interception, sandboxing, identity issuance or production monitoring.
- ✅ **No detection gating by edition** — Community Edition must never receive deliberately weakened detection depth; Corporate adds governance and aggregation on top of the same scanner, not a better scanner.

---

# Roadmap 2 — Corporate Edition (commercial evidence and governance plane)

**Mission:** turn per-repository KYA evidence into organisational assurance — who owns which agent, what authority it holds, who approved it, and what changed since.

**Status: ⏳ all milestones planned; architecture and sequencing defined below.**

**Non-goals:** a second scanner, a runtime security platform, an observability product, a compliance certificate.

**Architecture:** built entirely on `safeai-manifest.json` and portable registry exports produced by the free scanner. No privileged data path. Self-hosted first.

## EE0 — Commercial foundation *(do before writing any Corporate feature)*
Mindset: sequencing matters more than features — get it wrong and CE becomes unmonetisable or the contributor base walks.

- Keep the core Apache 2.0 — do not relicense shipped code. Corporate lives in a separate repository or module under a proprietary or BSL licence (open-core, cleanly separated).
- Contribution terms: a DCO or CLA in place **before** CE 2.0's plugin ecosystem attracts external contributions.
- Publish the edition boundary and the never-gated list in the repository; say it once, publicly.
- **Freeze the manifest contract** — version, document and schema-test `safeai-manifest.json` and the registry export format; it is the entire integration surface.
- Protect the **SafeAI** name and the **KYA** positioning; keep "Know Your Agent" an operating principle, not a claimed standard.
- Price on **agents or repositories under governance**, not seats; keep the free tier genuinely useful at small scale.

## EE1 — Organisational Evidence Registry
*The first thing to sell. Aggregation and ownership, not analytics.*
- Self-hosted central registry of an org-wide KYA inventory from CI-submitted manifests and local exports.
- Portfolio view across repositories, teams and environments; portfolio-level diffs.
- Ownership model: business owner, technical owner, environment, lifecycle status, review date, approval state.
- Central exception management: verified approver identity, approval workflow, expiry enforcement and notification, org-wide stale-waiver reporting (the identity-backed half of the Community CE 1.4 suppressions item).
- PR risk ownership and security-review assignment routing.
- SSO, RBAC, audit logs.
- Registry coverage reporting: unscanned / stale / drifted repositories and agents.

## EE2 — Policy Governance and Evidence Integrity
- Private rule and policy registries, org-wide distribution and version pinning.
- Central baseline management and approved-exception inheritance across repositories.
- Signed attestations and tamper-evident, immutable scan evidence with retention controls.
- Reproducibility guarantee per decision: exact scanner version, ruleset, policy and configuration hash.
- Assurance-boundary declarations (from CE 1.4) carried into every attestation.
- DevSecOps integrations: GitHub, GitLab, Azure DevOps, Jenkins, Jira, ServiceNow, SIEM, GRC, artifact stores.
- Trend analysis and executive reporting — only once ownership, schemas and workflow are stable.

## EE3 — Live Authority Reconciliation
*The highest-value corporate capability, and the reason the edition boundary exists.*
- Read-only reconciliation of declared capability against live granted authority: AWS IAM, Azure Managed Identity, GCP IAM, Kubernetes RBAC, service accounts, network policies.
- Continuous drift detection between approved baseline authority and current deployed authority.
- Cross-environment comparison (dev / staging / prod divergence).
- Optional runtime-evidence correlation: link static finding IDs to observed behaviour from existing runtime/observability tools, presented as correlated evidence, never as static-scan evidence.
- Capability-informed test-plan export to third-party evaluation, red-team and runtime-governance tools, with results linked to the exact scan and policy decision.
- Delivered as a separate explicitly installed component with scoped read-only credentials — never inside the core scanner, so the offline guarantee holds.

## EE4 — Regulated-Industry Content and Federation
- Maintained compliance-oriented policy and rule packs: HIPAA/patient data, PCI/transaction security, GDPR/data protection, EU AI Act mappings, org-specific packs.
- Control-mapped evidence exports for GRC and audit workflows, with explicit non-certification language.
- Optional federated registry — safe KYA evidence across business groups without centralising source code.
- Optional opt-in intelligence services (component reputation, known-malicious component data) — network-dependent by nature, therefore Corporate-only and always opt-in.

---

## Community & Quality Initiatives

*Cross-cutting work that supports the roadmap but is not tied to a specific milestone.*

- ✅ **Community Scan programme** — governed workflow for scanning public third-party agent frameworks and disclosing results responsibly. Target manifest, methodology, disclosure policy, private pilot documentation, and pinned-dependency requirements (`community-scans/`).
- ✅ **Validate Community Scan CI** — validation workflow for the community scan programme: target manifest validation, report schema validation, and pytest for pipeline scripts (`.github/workflows/validate-community-scan.yml`).
- ✅ **Fuzz testing** — P0 parser and sanitiser fuzzing for the scorecard, report schema, and targets manifest (`fuzz/`, `.github/workflows/fuzz.yml`).
- ✅ **OSSF Scorecard analysis** — OpenSSF Scorecard analysis workflow for supply-chain security posture (`.github/workflows/scorecard-analysis.yml`).

---

## Registry of latest shipped work (this branch, see CHANGELOG/releases)

- **v1.7.0** — IDE-scoped MCP discovery (Cursor, Windsurf, VS Code), named policy profiles (`developer`, `strict-ci`, `mcp`, `rag`, `production-agent`), registry freshness indicators, `--strict-suppressions` CI failure, component registry persistence (schema v3 `component_snapshots`), component-change diffs (self-comparison bug fixed).
- **v1.8.0 (curated: "True Authority & Complete Lifecycle")** — ✅ **Shipped.** CE 1.4 + CE 1.5 + CE 1.8 closure: Finding Lifecycle Event Engine (`finding_lifecycle` / schema v4, `ESC_RECURRING_RISK`), Stale Suppression Guard (fingerprint-bound waivers), Agent Enrichment Schema (`safeai registry metadata set` / `agent_metadata` table), Tool ↔ Implementation Mapping, Command-Aware MCP Resolution (`assurance: resolved` vs `unresolved-command`), Target Taxonomy Engine (Database / Object Storage / SaaS API buckets). **Plus depth:** prompt risk depth (multi-line, cross-file, indirect injection, XML/HTML injection), data leakage depth (private keys, JWT, AWS keys, connection strings, base64/hex, per-pattern severity), cross-component analysis (`component_graph.py` — skill→tool→workflow→MCP→model relationships). **Community:** expanded from 5 to 25 community scan targets; `safeai welcome` guided first-run experience. **Gate for CE 2.0.**
- **v1.9.0 (curated: "Component Depth & Ecosystem Foundations")** — ✅ **Shipped.** CE 1.6 depth (component version/hash in `component_snapshots` schema v5, `safeai registry components` impact-query CLI with dedup/type-filter/agent-resolution). CE 1.4/1.5 leftovers: **Governance signal detection** (`GovernanceAnalyzer`, 8 `GOV_*` rules — timeout, retry, approval, audit, rate limiting, circuit breaker, backpressure, health check; per-tool dedup, ±10-line source confirmation). **Heuristic data-flow depth** (`DataFlowAnalyzer`, 6 `DATAFLOW_*` rules — prompt, tool_call, shell, file_write, http_request, database; placeholder-aware confidence, `.py`-only filter). **Adapter completion** (AutoGen tightened, LangGraph `add_conditional_edges`, browser rule split). CE 2.0 foundations (`safeai init`, control mappings — OWASP LLM/Agentic + NIST AI RMF). **Post-review fixes:** governance dedup granularity, AutoGen/LangGraph detection hardened, orchestrator null guard, mojibake fixed. **564 tests passing, 76 built-in rules.**
- **v1.9.1** — ✅ **Shipped.** Post-release fixes: AGENTIC04 mojibake (CJK fragment in English description), scoped governance source suppression to tool line ±10 window (avoids masking missing controls in poly-tool modules), removed unused regex patterns (`_TOOL_TIMEOUT_RE`, `_TOOL_RETRY_RE`, `FUNCTION_PARAM_RE`), hardened LangGraph detection (require import or `StateGraph(`, not bare substring), added `CAP_browser_playwright/selenium/use` to `RULE_MAPPINGS` for enrichment.
- **v1.6.0** — **Security Scorecard** (0–10 deterministic score, Markdown/JSON outputs, `--scorecard-fail-under` gating, `scorecard-schema.json`), **Community Scan programme** (private pilot, target manifest, sanitisation pipeline, disclosure workflow), **CLI version support** (`safeai --version`), **Developer guide** (`DEVELOPER_GUIDE.md`), GitHub Action hardening (hermetic install path, `set_output` sanitisation, version source of truth).
- **v1.5.0** — **GitHub Actions Marketplace action** (composite action with SARIF upload, scorecard outputs, native exit-code passthrough; `action.yml`, `scripts/safeai-action.py`, 24 tests). **Environment & credential dependency inventory** (`os.getenv`/`os.environ`/`process.env`/dotenv/shell/template, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Kubernetes `secretKey`) and **dependency-to-capability correlation** (`DEP_UNDECLARED_CAPABILITY`, `DEP_ORPHANED_TOOL`), surfaced in terminal, HTML, SARIF, and the KYA manifest. First stable release (`Development Status :: 5 - Production/Stable`).
- **v1.4-b** — unified **org-wide shared registry** (`SAFEAI_REGISTRY` env var or `~/.safeai/registry.db`), self-contained **HTML reports** for scan and registry output, docs aligned to the v1.4 capability model.
- **v1.4** — tool-centric capability model + access modes, 14 declarative escalation rules with subsumption, per-tool capability diff, deep **Claude Code** analysis, **PR comment** review output, **assurance boundary**, governed suppressions policy-as-code, severity centralization (`safeai/severity.py`), KYA registry schema v2 migration.
- **Architecture refactor (P1)** — `safeai/kya/registry` split into `schema/connection/persist/queries`, `ScanOrchestrator` extracted from `run_scan`, `ScanPostProcessor` extracted from the scan CLI command. No public API break.

---

## Implementation inventory (as of v1.8.0)

The v1.8.0 architectural review found substantial shipped surface that the
roadmap never enumerated. Captured here so future curation does not re-discover
it:

- **15 framework adapters** (`safeai/frameworks/`): azure_foundry, bedrock_agent,
  claude_code, crewai, dify, google_adk, haystack, langchain, langgraph,
  llamaindex, mastra, microsoft_agent, n8n, openai_agents, semantic_kernel. All
  load via `@register_parser`; the `safeai.parsers` entry-point group is declared
  but currently empty (third-party plugins not yet wired).
- **13 analyzers** (`safeai/analyzers/`): capability, claude_code, data_leakage,
  dataflow, env_dependency, governance, mcp, model_config, prompt, prompt_file,
  skill, tool_def, workflow — emitting the `CAP_*`, `CC_*`, `DATA_*`,
  `DATAFLOW_*`, `DEP_*`, `ENV_*`, `GOV_*`, `MCP_*`, `MODEL_*`, `PROMPT_*`,
  `PROMPT_FILE_*`, `SKILL_*`, `TOOL_*`, `WORKFLOW_*`
  rule families (76 built-in rules in `safeai/rules/base_rules.yaml`).
- **Analysis core** (`safeai/analysis/`): `semantic` (AST document + symbol
  resolution), `import_graph` (project-wide import/symbol graph), `project_graph`
  (cross-file entity aggregation), `aggregation` (multi-parser merge +
  capability dedup), `capabilities` (23 capability categories + ranked access
  modes `none<read<write<mutate<execute`), `escalation`, `tool_identity`,
  `tool_surface`, `capability_diff`, `components`, `component_diff`,
  `dependency_correlation`.
- **KYA internals** (`safeai/kya/`): `enrich` (fingerprint/confidence/provenance
  normalisation + default remediation), `identity` (deterministic project/agent
  IDs via git-remote fingerprint + `.safeai/config.yml`), `fingerprints`
  (SHA-256 contract), `exporter` (portable registry inventory export),
  `util` (secret redaction + confidence labels), plus `baseline`, `ci_context`,
  `manifest`, `policy`, `suppressions`, `assurance`.
- **Report formats** (`safeai/report/`): terminal, json_report, html, sarif,
  pr_comment, and `registry_html` (self-contained HTML for `registry --format
  html`). Scoring (7 categories: Capability, Governance, Safety, Identity,
  Integration, Autonomy, Enterprise Readiness; equal weight by default) lives in
  `safeai/scoring/engine.py` with severity weights in `safeai/severity.py`
  (`critical 25 / high 15 / medium 8 / low 4 / info 1`).
- **Shipped-ahead-of-doc items** (previously marked ⏳, now ✅): `registry
  export` (portable inventory, `--include-history`/`--include-suppressed`);
  `--rules <dir>` custom-rule directory loader; GitLab CI + Azure Pipelines
  detection (already in `ci_context.PROVIDERS`).

---

## Philosophy

SafeAI is intentionally:

- **Lightweight** — no external services, no runtime, no LLM calls
- **Environment agnostic** — works in any CI/CD pipeline, on any OS
- **CI/CD friendly** — SARIF output, exit codes, GitHub Actions ready
- **Plugin based** — frameworks, analyzers, and rules are all pluggable
- **Community driven** — built by and for the AI security community

The product is consistently described as a **Static AI Capability & Risk Analyzer** — emphasizing that it analyzes *capabilities* (what an agent *can do*) and *risk* (what could go wrong) entirely through static analysis, without executing code or calling external services.
