# ADR 0002 — Community/Corporate boundary

- Status: accepted
- Date: 2026-09-12
- Context: a commercial evidence plane is planned (EE1–EE4). Without a
  published boundary, contributors cannot tell what stays free and
  enterprise users cannot tell what they buy.
- Decision: Community Edition permanently owns repository-local
  discovery, analysis, policy, reports, manifest, registry, and CI
  gating; Corporate (separate repo/module/license) adds aggregation,
  identity-backed workflows, retention, and credentialed live
  reconciliation. Detection gating by edition is forbidden; runtime
  enforcement never enters the Community core. Published in
  `docs/GOVERNANCE_AND_EDITIONS.md`.
- Alternatives: single-codebase feature flags (rejected: invites gating,
  complicates offline guarantee); relicensing core (rejected: breaks
  contributor trust, EE0 forbids it).
- Consequences: Corporate must integrate through the frozen manifest
  contract only; Community roadmap stays independently useful.
