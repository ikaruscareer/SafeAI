# SafeAI Limitations

SafeAI is a **static** analyzer. Understanding what static analysis can and
cannot tell you is essential to using its results responsibly.

## What static analysis cannot prove

- **Runtime permissions** — code that *can* call a shell is not proof a
  deployed agent *did* or *will be allowed to*.
- **Live identity** — SafeAI does not verify which identity an agent assumes
  in production, nor effective IAM/RBAC permissions.
- **Executed behavior** — no tool calls are executed, no models are invoked,
  no MCP servers are probed.
- **Data classification** — detected flows are pattern-based; SafeAI does not
  inspect actual data at rest or in transit.
- **Model behavior** — hallucination, jailbreak resistance, and output safety
  are out of scope (use evaluation/red-teaming tools).
- **Deployment configuration** — containers, gateways, and environment
  overrides are only visible where expressed in scanned source/config.
- **Policy enforcement** — a SafeAI policy outcome describes whether static
  evidence matched local policy rules. It is **not** a compliance claim and
  never means "this application is safe".

## Coverage caveats

- **Dynamic language patterns** — agents constructed via factories, dynamic
  imports, decorators, metaprogramming, or custom wrappers may reduce
  discovery coverage.
- **Framework maturity varies** — see `FRAMEWORK_SUPPORT.md`. Early-preview
  adapters have lower detection confidence than LangGraph/CrewAI/LangChain.
- **Regex fallback** — capability findings produced by regex fallback are
  heuristic and may include false positives; they carry lower confidence and
  are marked as heuristic in finding provenance.

## The assurance boundary

Every manifest carries an `assurance_boundary` object (see
`KYA_MANIFEST.md`) that states, in one place, what a given scan verified
and what it structurally cannot verify. It exists because the rest of this
document is necessarily general — the boundary is the scan-specific version
of the same idea.

- **What is verified statically**: declared tools, prompt and instruction
  files, MCP server configuration, workflow structure, and permission
  configuration — anything expressed directly in the source or
  configuration that was scanned.
- **What is not verifiable statically**: IAM and cloud permissions, runtime
  identity, deployed network policy, actual runtime behaviour, and
  dynamically constructed tool bindings. These require observing a running
  system, which SafeAI deliberately does not do.
- **Access modes may be inferred, not declared.** Not every framework or
  configuration format states a capability's access mode explicitly. When
  SafeAI cannot find a definite signal, it infers a conservative access
  mode (defaulting to `read`) and marks that capability
  `access_mode_inferred: true`. Inferred access modes can still trigger an
  escalation rule, but the rule's severity is capped at `medium` when it
  fired on an inferred value — a guess must never be presented as a
  certainty — and the manifest's
  `assurance_boundary.inferred_value_count` reports exactly how many
  capabilities in that scan were inferred rather than declared — counted
  fresh per scan, not accumulated across scans.
- **A baseline predating v1.4 yields combination-only escalations.** The
  v1.4 capability diff attributes capabilities to named tools; a baseline
  captured before this release (a legacy JSON report, or a manifest without
  `tool_surface`) has no such attribution, so its tool-level status cannot
  be trusted. In that case, the diff still runs, but only the escalation
  rules that depend on conditions within the current scan alone (the three
  `ESC_COMBO_*` combination rules) are evaluated; the rules that depend on
  comparing a tool's structural status against the baseline are suppressed
  rather than risk reporting an escalation that the baseline could not
  actually support.

## Confidence levels

| Level | Meaning |
|---|---|
| `high` | AST/semantic resolution with strong evidence |
| `medium` | Structured config or partial semantic evidence |
| `low` | Regex/heuristic fallback only |

Confidence reflects *evidence quality for the detection*, not the
probability that a risk is real.

## False positives / false negatives

- Prefer suppression with a documented reason over deleting findings (see
  `.safeai/suppressions.yml` in `USER_GUIDE.md`).
- Report suspected false negatives with a minimal reproducing fixture —
  they directly improve parser maturity.

## The right mental model

SafeAI answers: **"What does the source and configuration say this agent
system can do, and where are the risky patterns?"**

It does not answer: "What is this agent doing in production right now?"
For that, pair SafeAI with runtime governance tools such as the Microsoft
Agent Governance Toolkit.
