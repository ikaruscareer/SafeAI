# SafeAI KYA Manifest — `safeai-manifest.json` (Schema v1.2)

The KYA manifest is SafeAI's **canonical portable artifact** for scan-derived
"Know Your Agent" evidence. It is the public contract consumed by the local
registry, JSON output, capability/agent comparison, and future integrations.

> The SQLite registry schema is an implementation detail. Integrations should
> consume this manifest, not the database.

## Guarantees

- **Offline** — generated without any network, API, or LLM call.
- **Source-private** — contains no raw source code and no unredacted secrets.
- **Deterministic** — same repository, configuration, ruleset, and commit
  produce an equivalent manifest (except `generated_at`, `scan.scan_id`, and
  scan timestamps, which identify the event, not the artifact).
- **Versioned** — `schema_version` follows semver semantics for the document
  contract. `1.x` consumers can read any `1.y` manifest; unknown optional
  fields must be ignored.

## Schema history

| Version | Added |
|---|---|
| 1.0 | Initial manifest: `agents`, `components`, `findings`, `summary`, `limitations` |
| 1.1 | `tool_surface` — the per-tool capability index described below |
| 1.2 | `assurance_boundary` — the verified/not-verifiable statement described below |

Both 1.1 and 1.2 are purely additive: a 1.0 consumer that ignores unknown
fields reads a 1.2 manifest without error.

## Top-Level Structure

```json
{
  "schema_version": "1.2",
  "manifest_type": "safeai.kya",
  "generated_at": "2026-08-02T12:00:00Z",
  "safeai": {
    "version": "1.4.0b0",
    "ruleset_version": "sha256:abc123...",
    "config_hash": "sha256-of-normalized-effective-config"
  },
  "project": {
    "project_id": "git-0123abcd...-ef45",
    "name": "my-agent-app",
    "source_root": ".",
    "repository": {
      "remote_fingerprint": "sha256-of-normalized-remote-or-null",
      "commit_sha": "optional",
      "branch": "optional",
      "tag": "optional"
    }
  },
  "scan": {
    "scan_id": "uuid-per-run",
    "started_at": "ISO-8601 UTC",
    "completed_at": "ISO-8601 UTC",
    "files_scanned": 12,
    "analysis_coverage": {
      "languages": ["python"],
      "frameworks_detected": ["langgraph"],
      "limitations": ["..."]
    }
  },
  "agents": [],
  "tool_surface": [],
  "components": [],
  "findings": [],
  "summary": {
    "risk_score": 92,
    "severity_counts": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 1},
    "capability_counts": {"Shell": 1},
    "agent_count": 1,
    "component_count": 0,
    "policy_decision": {"outcome": "warn", "reasons": ["..."], "matches": []}
  },
  "assurance_boundary": {
    "schema_version": 1,
    "verified_statically": ["declared tools", "prompt and instruction files", "MCP server configuration", "workflow structure", "permission configuration"],
    "not_verifiable_statically": ["IAM and cloud permissions", "runtime identity", "deployed network policy", "actual runtime behaviour", "dynamically constructed tool bindings"],
    "coverage_notes": ["..."],
    "inferred_value_count": 0,
    "summary": "Static analysis of repository configuration and source. SafeAI cannot verify deployed IAM permissions, runtime identity, or network policy."
  },
  "limitations": [
    "SafeAI results are static analysis evidence and do not verify deployed runtime permissions, identities, or behavior."
  ]
}
```

Field order in `build_manifest()` places `tool_surface` after `agents` and
`assurance_boundary` after `summary`, immediately before `limitations`.
Both are described in detail below.

## Agent Records

Each agent/workflow discovered in source or configuration:

| Field | Description |
|---|---|
| `agent_id` | Deterministic ID: `sha256(project_id, framework, name, primary path, type)` |
| `name` | Discovered or derived human-readable name |
| `agent_type` | `agent` \| `workflow` \| `application` \| `unknown` |
| `framework` | e.g. `langgraph`, `crewai` |
| `source_locations` | Project-relative `{path, line_start, line_end}` list |
| `first_seen` | Managed by the registry (scan time when new) |
| `capabilities` | `[{name, category}]` detected in source/configuration |
| `tools` | Discovered tool names |
| `resources`, `mcp_assets`, `autonomy_signals`, `governance_evidence`, `authority_evidence` | Evidence lists (may be empty) |
| `confidence` | `high` \| `medium` \| `low` |
| `provenance` | Which parser/discovery method produced the record |

Renaming or moving the primary source file creates a **new** agent identity.
Aliasing/migration is deferred to a future release.

## Tool Surface (added in schema 1.1)

`tool_surface` is a flat, sorted list of every named tool the scan
identified, with its capabilities and access modes attached directly to the
tool rather than only to the agent that happens to hold it. It is built
from data the scan already collected — agent models and MCP assets — so it
costs no additional file access. This is the granularity the v1.4
capability diff and PR comment operate on: "which tool gained what" rather
than "did any tool anywhere gain something."

| Field | Description |
|---|---|
| `tool_key` | Deterministic identity string, e.g. `mcp_server:invoice-lookup`, `tool:send_email`, or `unknown:<hash>` for an unnamed tool |
| `kind` | `agent` \| `mcp_server` \| `skill` \| `tool` \| `workflow_node` \| `unknown` |
| `name` | Discovered tool name, or `"unattributed"` if none could be determined |
| `framework` | Framework that produced this tool, if known |
| `capabilities` | `[{name, category, access_mode, access_mode_inferred, confidence, ...}]` |
| `access_summary` | The highest access mode across the tool's capabilities |

Access modes follow an ascending scale: `none < read < write < mutate <
execute`. When a framework or configuration file does not explicitly
declare a capability's access mode, SafeAI infers one conservatively
(defaulting to `read`) and sets `access_mode_inferred: true` on that
capability; inferred access modes are counted in the manifest's
`assurance_boundary.inferred_value_count` below, precisely because an
inferred value carries less certainty than a declared one.

A tool identity is deterministic and path-independent whenever a name is
available, so the same MCP server or tool keeps the same `tool_key` across
scans even if its defining file moves. Only genuinely unnamed tools fall
back to a path-derived hash. An MCP configuration that does not name its
server is recorded under a fixed `unknown:unattributed` identity rather
than given an invented name.

## Assurance Boundary (added in schema 1.2)

`assurance_boundary` is a short, factual statement of what a specific scan
verified and what it structurally cannot verify, computed from the scan's
own data rather than a fixed template.

| Field | Description |
|---|---|
| `schema_version` | Integer, currently `1` |
| `verified_statically` | Fixed list: declared tools, prompt and instruction files, MCP server configuration, workflow structure, permission configuration |
| `not_verifiable_statically` | Fixed list: IAM and cloud permissions, runtime identity, deployed network policy, actual runtime behaviour, dynamically constructed tool bindings |
| `coverage_notes` | Scan-specific notes: files actually skipped, configuration that actually failed to parse (e.g. `CC_SETTINGS_UNPARSEABLE`), the count of access modes actually inferred, and baseline attribution status when a baseline was supplied. If none of these applied, a note says so explicitly rather than omitting the field. |
| `inferred_value_count` | Number of capabilities in this scan whose `access_mode` was inferred rather than declared |
| `summary` | One fixed sentence: "Static analysis of repository configuration and source. SafeAI cannot verify deployed IAM permissions, runtime identity, or network policy." |

The two fixed lists (`verified_statically` and `not_verifiable_statically`)
are deliberately not scan-specific — they describe what static analysis of
this kind can and cannot ever establish, independent of what any one
repository happens to contain. `coverage_notes` and `inferred_value_count`
are the scan-specific parts, and are what make the boundary an honest
reflection of this run rather than boilerplate. Read this alongside
`LIMITATIONS.md`, which explains the same boundary in narrative form.

## Finding Records

| Field | Description |
|---|---|
| `finding_id` / `fingerprint` | Deterministic SHA-256 (see below) |
| `rule_id` | Stable rule identifier (e.g. `CAP_shell`, `DATA_LEAKAGE`) |
| `severity` | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `title`, `message`, `remediation` | Human-readable, actionable text |
| `confidence` | `high` \| `medium` \| `low` |
| `provenance` | `{analyzer, heuristic, evidence[]}` — evidence is redacted |
| `location` | `{path, line_start, line_end}` — project-relative |
| `status` | `new` \| `existing` \| `regressed` \| `resolved` \| `suppressed` \| `unknown` |

## Fingerprint Algorithm

```
fingerprint = SHA-256(
    UPPER(rule_id)      + "\n" +
    relative_path       + "\n" +   # forward slashes
    line_number         + "\n" +
    normalized_evidence            # whitespace-collapsed, secret-redacted (full mask)
).hexdigest()
```

Fingerprints never depend on timestamps, absolute paths, scan IDs, or
ordering. Whitespace-only formatting changes and secret rotation do not
change a fingerprint; a material change to rule, location, or matched
evidence does.

## Redaction & Privacy

- Secret values are masked (`sk-1***MASKED***`) before any evidence is
  written to the manifest, SARIF, exports, or the registry.
- `repository.remote_fingerprint` is a one-way hash — the raw remote URL
  (which may embed credentials or private hostnames) is never stored.
- No raw file contents, environment values, or credentials are included.

## Example (fictional, safe values)

```json
{
  "schema_version": "1.2",
  "manifest_type": "safeai.kya",
  "generated_at": "2026-08-02T12:00:00Z",
  "safeai": {"version": "1.4.0b0", "ruleset_version": "sha256:1111", "config_hash": "2222"},
  "project": {"project_id": "local-00000000-0000-4000-8000-000000000000", "name": "demo", "source_root": ".", "repository": {}},
  "scan": {"scan_id": "33333333-3333-4333-8333-333333333333", "started_at": "2026-08-02T11:59:59Z", "completed_at": "2026-08-02T12:00:00Z", "files_scanned": 1, "analysis_coverage": {"languages": ["python"], "frameworks_detected": ["langgraph"], "limitations": []}},
  "agents": [{
    "agent_id": "researcher-0123456789ab",
    "name": "researcher",
    "agent_type": "agent",
    "framework": "langgraph",
    "source_locations": [{"path": "agent.py", "line_start": 1, "line_end": 1}],
    "first_seen": "2026-08-02T12:00:00Z",
    "capabilities": [{"name": "shell_execution", "category": "Shell"}],
    "tools": [],
    "resources": [],
    "mcp_assets": [],
    "autonomy_signals": [],
    "governance_evidence": [],
    "authority_evidence": [],
    "confidence": "high",
    "provenance": [{"framework": "langgraph", "discovery_method": "ast", "note": "detected in source/configuration (static evidence)"}]
  }],
  "tool_surface": [{
    "tool_key": "agent:researcher",
    "kind": "agent",
    "name": "researcher",
    "framework": "langgraph",
    "capabilities": [{"name": "shell_execution", "category": "Shell", "access_mode": "execute", "access_mode_inferred": false, "confidence": 0.85}],
    "access_summary": "execute"
  }],
  "components": [],
  "findings": [{
    "finding_id": "aaaa...",
    "rule_id": "CAP_subprocess_shell",
    "severity": "critical",
    "title": "subprocess invoked with shell=True",
    "message": "subprocess invoked with shell=True",
    "remediation": "Avoid shell=True; pass argument arrays and validate every interpolated value.",
    "confidence": "medium",
    "provenance": {"analyzer": "capability", "heuristic": true, "evidence": ["subprocess.run(user_input, shell=True)"]},
    "location": {"path": "agent.py", "line_start": 8, "line_end": 8},
    "fingerprint": "aaaa...",
    "status": "new"
  }],
  "summary": {
    "risk_score": 90,
    "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
    "capability_counts": {"Shell": 1},
    "agent_count": 1,
    "component_count": 0,
    "policy_decision": {"outcome": "warn", "reasons": ["No policy file supplied; default posture 'warn'."], "matches": []}
  },
  "assurance_boundary": {
    "schema_version": 1,
    "verified_statically": ["declared tools", "prompt and instruction files", "MCP server configuration", "workflow structure", "permission configuration"],
    "not_verifiable_statically": ["IAM and cloud permissions", "runtime identity", "deployed network policy", "actual runtime behaviour", "dynamically constructed tool bindings"],
    "coverage_notes": ["No files were skipped, no configuration failed to parse, and no access mode was inferred in this scan."],
    "inferred_value_count": 0,
    "summary": "Static analysis of repository configuration and source. SafeAI cannot verify deployed IAM permissions, runtime identity, or network policy."
  },
  "limitations": ["SafeAI results are static analysis evidence and do not verify deployed runtime permissions, identities, or behavior."]
}
```
