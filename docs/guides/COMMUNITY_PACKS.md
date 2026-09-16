# Community Rule Packs (CE 2.3)

How to author, test, version, and share a SafeAI rule pack. A pack is a
directory of `*.yaml` rule files plus `fixtures/` — no hosted
marketplace, no account, no network.

## Layout

```
my-pack/
  my_rules.yaml          # rules with id/description/severity (+ optional owasp_llm)
  fixtures/
    risky_example.py     # MUST fire a pack rule ID at pack severity
    safe_example.py      # MUST NOT fire any pack rule ID
  tests/
    test_pack.py         # calls safeai.rules.pack_test.check_pack (scaffolded by safeai init)
```

`safeai init` scaffolds this layout under `.safeai/rules/` including a
working override example (`pack_example.yaml`).

## Rules

Each rule needs `id`, `description`, `severity`
(`critical|high|medium|low|info`). Optional: `owasp_llm`.

**Pack rules take effect as overrides of built-in rule IDs.** A brand-new
ID documents intent and validates cleanly, but no analyzer emits it —
`safeai rules check` warns about such IDs. To change what a scan
reports, override an ID an analyzer already emits (e.g.
`CAP_subprocess_shell`) and prove it with fixtures.

## Fixtures (required)

- `fixtures/risky_*.py` — at least one file required. Every risky
  fixture must produce ≥1 finding whose rule ID is in the pack, at the
  pack's severity.
- `fixtures/safe_*.py` — must produce zero findings with pack rule IDs
  (other rules may still fire; only pack IDs are asserted).

Check any pack offline, fixture code never executed:

```bash
safeai rules check ./my-pack
```

## Compatibility policy

- Packs declare the SafeAI versions they were tested against in their
  README (e.g. "tested with SafeAI 2.3.x"). The scanner does not gate
  on this; it is a human contract.
- Record what each scan used: every manifest stamps
  `analyzer_versions`, `parser_versions`, `rule_pack_ids`, and
  `policy_profile` (`safeai` block); the registry persists the same pins
  per scan (`plugin_versions_json`); `registry export` carries them and
  `registry import --dry-run` warns on drift.
- Built-in rule IDs are stable within a major version. If a future
  SafeAI renames an overridden ID, `safeai rules check` reports your
  rule as documentation-only — update the ID, re-run fixtures.
- Pinning for teams: commit a `components.lock.json`
  (`registry components --lockfile`) and gate CI with
  `registry components --check-lockfile` alongside the pack check.

## Sharing

Distribute packs as versioned archives or git checkouts with a
`README` (tested SafeAI versions, rule list, fixture notes). Curated
packs are signed where practical. Never execute scanned code, never
transmit scan content — packs are static YAML plus fixtures.
