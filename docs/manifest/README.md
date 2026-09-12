# SafeAI Manifest Contract v1

`safeai-manifest.json` is the canonical portable artifact for SafeAI KYA
evidence — the interface between local scans, the local registry, CI
artifacts, portable import/export, and future evidence aggregation. The
SQLite registry is an implementation detail; integrations consume the
manifest.

- Normative schema: `schemas/safeai-manifest/v1.0.0.json`
  (JSON Schema draft 2020-12).
- Compatibility policy: `docs/manifest/COMPATIBILITY.md`.
- Worked examples: `docs/manifest/EXAMPLES.md`.
- Legacy field reference: `docs/reference/KYA_MANIFEST.md`.

## Identity fields

Every manifest carries three independent versions — do not conflate them:

| Field | Example | Meaning |
|---|---|---|
| `safeai.version` | `"2.2.0"` | Scanner package that produced the scan |
| `schema_version` | `"1.2"` | Legacy document shape (`1.0`/`1.1`/`1.2`, additive) |
| `contract.version` | `"1.0.0"` | Public contract version (semver; this document) |

## Validate locally (offline, no dependencies beyond PyYAML/stdlib)

```bash
safeai manifest validate safeai-manifest.json
safeai manifest verify safeai-manifest.json
```

`validate` checks structure, value domains, and compatibility semantics and
prints field-level errors. `verify` additionally recomputes the canonical
`integrity.payload_sha256` digest (see `docs/manifest/EXAMPLES.md`).

The stdlib validator (`safeai/kya/contract.py`) deliberately does not
implement the full JSON-Schema draft engine (no `$ref` resolution, no
`pattern` evaluation beyond pinned constants). Third-party consumers
should validate against the published schema file with their own tooling;
verdicts agree on every required-field and enum rule.

## Data classification

- **Source evidence** — `agents`, `tool_surface`, `components`,
  `dependency_inventory` (names only, never values), finding `location`
  (`path` + line numbers) and `fingerprint`.
- **Inferred evidence** — findings with `confidence: low`, heuristic
  provenance (`provenance.heuristic: true`), capability diffs.
- **Unverified runtime assumptions** — everything in `assurance_boundary`
  under "not statically verifiable" (IAM, runtime identity, network
  policy, deployed behavior).
- **Redacted secrets** — `message`/`evidence` pass through
  `safeai/kya/util.py:redact_secrets`; raw source blocks and secret values
  are never emitted.

## Not a guarantee

A valid manifest proves **structure**, not truth: import validates declared
schema compatibility but cannot prove the original scan was truthful or
complete. Static analysis evidence is never a security guarantee,
compliance certificate, or proof of deployed authorization. See
`assurance_boundary` in every manifest.
