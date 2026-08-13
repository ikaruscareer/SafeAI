# SafeAI — Roadmap

SafeAI is a **Static AI Capability & Risk Analyzer** — think SonarQube for AI agents and workflows.

This document describes the roadmap across **two editions**: the open-source **Community Edition (Apache 2.0, offline, local-first)** and the commercial **Corporate Edition (evidence and governance plane)**. Milestones are not strictly sequential; work may proceed in parallel where dependencies allow.

> **Current state:** v1.4-b shipped; CE 1.5 environment-inventory and dependency-correlation work is in progress on this branch. Community Edition **CE 1.4 (Reviewable Change)** is substantially complete; CE 1.5/1.6/2.0 and the entire Corporate Edition are planned.

---

# Roadmap 1 — Community Edition (Apache 2.0, offline, local-first)

**Mission:** know your agent before you deploy it, with zero setup, no account, and no network.

**Constraint:** if a feature does not improve a developer's ability to understand, remediate or prevent a risky agent change *before deployment*, it is not in the Community core.

Status legend: ✅ **Shipped** · 🔄 **In progress / partial** · ⏳ **Planned**

---

## CE 1.4 — Reviewable Change (the PR release)

*Goal: make SafeAI the thing a reviewer reads first on any PR that touches an agent.*

**Status: ✅ shipped (v1.3 → v1.4 → v1.4-b); a few items remain.**

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

### Surface depth *(the two that matter)*
- 🔄 **Multi-source MCP discovery** — MCP servers discovered across the scanned repo and Claude Code configuration, normalised into one capability model with provenance on every entry. Cursor / Windsurf source scopes and user/global scopes are **not yet read** (out-of-repo scopes are intentionally behind an explicit gate and excluded from exports by default).
- ✅ **Deep Claude Code analysis** — `.claude/settings.json`, instruction files, permissions, `allowedTools`, custom slash commands (treated as an injection surface), subagents, hooks, dangerous/auto-approve flags, project structure (10 `CC_*` rules; repo-local scope only, never user/machine config).
- ✅ **MCP posture** — transport, authentication evidence, exposed tools and resources, wildcard permissions, local vs remote endpoint risk, configuration provenance.

### Governance and lifecycle
- 🔄 **Governed suppressions** — current suppressions already carry rule_id, file, location, reason, owner, expiry and are never silent. **Stale-suppression detection and CI failure when a waiver expires or code moves are planned.**
- ⏳ **Per-finding lifecycle timeline** — introduced → resolved → reopened, with repeated reopening flagged as a governance signal.
- 🔄 **Policy profiles** — policy-as-code shipped (`allow / warn / require_review / deny`); named profiles (`developer`, `strict-ci`, `mcp`, `rag`, `production-agent`) planned.
- ✅ **Policy decision recorded on every scan** (pass / warn / review-required / block / accepted-exception, with rationale).
- ⏳ **Registry freshness indicators** — never scanned, stale, changed since last approval, policy drift.
- ⏳ **Locally enrichable agent metadata** — business owner, technical owner, intended purpose, environment, lifecycle status, review date.

### Trust and honesty
- ✅ **Mandatory machine-readable assurance boundary block** in every report and manifest — what was verified (declared tools, prompt files, MCP servers, workflow structure, configuration) versus what cannot be verified statically (IAM permissions, runtime identity, deployed network policy, actual behaviour) — `assurance_boundary`.
- ⏳ **Governance signal detection** — timeout, retry policy, approval workflow, audit logging, rate limiting.
- ✅ **Better terminal output** — severity-grouped summary, clear layout, improved signal-to-noise (v1.4-b).
- ✅ **Severity-weighted trust score** — 7-category weighted scoring keyed on `safeai/severity.py`.

### Exit criterion
> ✅ **Achieved.** A reviewer sees, in a PR comment, that a specific **named tool** gained a specific **new authority** — and SafeAI records that change, the policy decision and the assurance boundary in local KYA history. Ordinary SAST does not produce that.

---

## CE 1.5 — True Capability Surface

*Goal: close the gap between what an agent declares and what it actually needs to run.*

**Status: 🔄 partial — CE 1.5 environment inventory and correlation shipped; remaining surface items planned below.**

- ✅ **Secret and configuration dependency inventory** — names and sources only, never values: `os.getenv`, `os.environ`, `process.env`, dotenv keys, shell/template interpolation, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Kubernetes `secretKeyRef` (`safeai/analyzers/env_dependency`).
- ✅ **Dependency-to-capability correlation** — referenced credential/config with no matching declared capability = undeclared-capability candidate; declared credential-demanding capability with no referenced config = orphaned tool (`safeai/analysis/dependency_correlation.py`, rules `DEP_*`). Correlation findings feed severity, trust score, SARIF, HTML and the manifest. Matching uses whole-word-segment family keywords (no substring false positives on `jdbc`/`rabbit_mq`), with provider families taking precedence over the generic `api` fallback; the payload-carrying `ENV_DEP_INVENTORY` finding is exempt from suppression so the inventory section can never be blanked.
- ⏳ **Tool → implementation mapping** — declaration site, implementation site, unresolved/orphan cases in both directions.
- ⏳ **Command-aware MCP analysis** — resolve in-repo and vendored server entrypoints statically, depth-capped, never executed, with explicit resolved / unresolved-command labelling.
- ⏳ **External write target taxonomy** — filesystem, databases, S3, blob storage, GitHub, Slack, external APIs — promoted to a first-class report view.
- ⏳ **Heuristic data-flow depth** — untrusted input propagation into prompts and tool arguments.
- ⏳ **Adapter completion** — AutoGen, LangGraph `add_conditional_edges`, browser-automation rule split (Playwright / Selenium / browser_use).

### Exit criterion
> SafeAI reports the credentials and destinations an agent actually depends on, and flags mismatches between declared and required capability — with no cloud access and no execution.

---

## CE 1.6 — AI Component Records

*Goal: extend evidence from agents to the reusable components they share. Deliberately after 1.5.*

**Status: 🔄 partial. Component-level analysis ships today (skills, prompts, MCP configs, tool definitions, workflows, model configs); registry impact queries and component-change diffs are planned.**

- ✅ Treat prompts, skills, MCP configurations, tool definitions, workflows and model configs as versioned components (component analysis → findings).
- ✅ Scan only local and vendored artifacts — no external feeds.
- ✅ Detect embedded prompts, hard-coded secrets, over-broad permissions, insecure defaults, unpinned references, unsafe composition.
- ⏳ Record component identity, version/hash, source, findings and usage relationships in the local registry.
- ⏳ **Impact queries** — which agents reference this MCP server, prompt template, tool definition or model config?
- ⏳ **Component-change diffs** — a changed MCP configuration affects seven scanned agents.
- ⏳ Component manifests where feasible; lockfile-style integrity metadata deferred to 2.x.

### Exit criterion
> A team can trace a risky reusable component to every consuming agent and repository, and produce static evidence for remediation.

---

## CE 2.0 — Ecosystem and Static Authority Correlation

*Goal: grow coverage through contribution, and answer the authority question without leaving the repository.*

**Status: 🔄 plugin architecture; the rest ⏳ planned.**

### Ecosystem
- 🔄 **Stable plugin SDK** — framework adapters, analyzers, and rules are already pluggable (entry-point + decorator discovery); report enrichers and policy packs planned.
- ⏳ **Curated (and signed where practical) community registry** for versioned rule and policy packages.
- ⏳ **`safeai init`** — config, local registry, recommended policy profile.
- ⏳ **Custom rule authoring** with fixtures, tests, expected findings.
- ⏳ **Control mappings** — OWASP Top 10 for Agentic Applications, OWASP Top 10 for LLM Applications, NIST AI RMF 1.0 (NIST AI 100-1) — presented as taxonomy, policy selection and prioritisation aid, explicitly **not** as coverage or compliance claims.
- ⏳ Plugin and rule-pack versions recorded in every scan for reproducibility.
- ⏳ **Portable registry export/import** so organisations can exchange KYA evidence without a central service.

### Static authority correlation *(the community's Phase 3, offline)*
- ⏳ Parse in-repo IaC — Terraform, CloudFormation, Helm, Kubernetes manifests, serverless configs.
- ⏳ Compare declared capability against granted authority and report both directions: capability without grant (probable breakage), and grant without capability (excess authority).
- ⏳ Report confidence honestly — IaC in the repo is not proof of what is deployed, and the assurance boundary block must say so.

### Exit criterion
> A contributor can add an adapter or rule pack with tests, and a reviewer can see declared-versus-granted authority mismatches using only files already in the repository.

---

## CE permanent guarantees

- ✅ **Local by default** — no account, server, daemon, telemetry or external network calls.
- ✅ **Source-private by default** — references and evidence, not raw source.
- ✅ **Static truth only** — detected evidence always distinguished from unknown runtime state.
- ✅ **No compliance certification claims** — mappings and evidence, never a declaration that an agent is safe or compliant.
- ✅ **No runtime-platform creep in core** — no interception, sandboxing, identity issuance or production monitoring.

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

## Registry of latest shipped work (this branch, see CHANGELOG/releases)

- **CE 1.5 (in progress)** — environment & credential dependency inventory (`os.getenv`/`os.environ`/`process.env`/dotenv/shell/template, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Kubernetes `secretKey` — names and sources only, never values) and dependency-to-capability correlation (`DEP_UNDECLARED_CAPABILITY`, `DEP_ORPHANED_TOOL`), surfaced in terminal, HTML, SARIF, and the KYA manifest (`dependency_inventory`, `dependency_correlation`) with a reviewable name-family heuristic.
- **v1.4-b** — unified **org-wide shared registry** (`SAFEAI_REGISTRY` env var or `~/.safeai/registry.db`), self-contained **HTML reports** for scan and registry output, docs aligned to the v1.4 capability model.
- **v1.4** — tool-centric capability model + access modes, 14 declarative escalation rules with subsumption, per-tool capability diff, deep **Claude Code** analysis, **PR comment** review output, **assurance boundary**, governed suppressions policy-as-code, severity centralization (`safeai/severity.py`), KYA registry schema v2 migration.
- **Architecture refactor (P1)** — `safeai/kya/registry` split into `schema/connection/persist/queries`, `ScanOrchestrator` extracted from `run_scan`, `ScanPostProcessor` extracted from the scan CLI command. No public API break.

---

## Philosophy

SafeAI is intentionally:

- **Lightweight** — no external services, no runtime, no LLM calls
- **Environment agnostic** — works in any CI/CD pipeline, on any OS
- **CI/CD friendly** — SARIF output, exit codes, GitHub Actions ready
- **Plugin based** — frameworks, analyzers, and rules are all pluggable
- **Community driven** — built by and for the AI security community

The product is consistently described as a **Static AI Capability & Risk Analyzer** — emphasizing that it analyzes *capabilities* (what an agent *can do*) and *risk* (what could go wrong) entirely through static analysis, without executing code or calling external services.