# ADR 0001 — Manifest contract v1

- Status: accepted
- Date: 2026-09-12
- Context: `safeai-manifest.json` is consumed by the registry, baselines,
  CI artifacts, and portable exports, but had no published schema,
  no validator, and no compatibility policy. Corporate planning (EE0)
  requires a frozen integration surface.
- Decision: publish Contract v1 (`schemas/safeai-manifest/v1.0.0.json`,
  `docs/manifest/`), stamp a `contract{}` block distinct from package
  version, validate locally with stdlib-only checks
  (`safeai/kya/contract.py`, `safeai manifest validate`), keep the legacy
  `schema_version` 1.x line additive, and ignore unknown fields.
- Alternatives: adopt JSON-Schema draft engine as a runtime dependency
  (rejected: dependency discipline, offline installer weight); freeze
  without a validator (rejected: unenforceable contracts drift).
- Consequences: third parties can build on the manifest; schema changes
  now require intentional fixture updates and CHANGELOG entries.
