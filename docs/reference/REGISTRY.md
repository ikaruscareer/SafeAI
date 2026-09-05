# SafeAI Local KYA Registry

The KYA registry is a **private, local, SQLite** store of scan-derived agent
records and evidence. It is created and updated automatically by
`safeai scan` — no server, no account, no network call, no source upload.

> Everything in the registry is **static analysis evidence**: things detected
> in source/configuration. It never reflects deployed runtime state,
> effective IAM permissions, live identities, or runtime behavior.

## Location & Lifecycle

The registry is a **single shared database** by default, so agents from
every scanned project accumulate in one place:

1. **`SAFEAI_REGISTRY` environment variable** — point it at a team-shared
   or network location (e.g. `$ORG_DATA/safeai/registry.db`). Overrides the
   default and also enables persistence in CI (see below).
2. Otherwise **`~/.safeai/registry.db`** (per user, shared across projects).

Resolution order for every registry path: `--registry PATH` >
`--project-dir DIR` (the per-project `DIR/.safeai/registry.db`) > the
shared registry above. `safeai scan` uses the same default, so scans from
any folder land in the shared registry and `safeai registry list` shows
the organization's agents regardless of the current directory.

- First scan creates the database (a one-line message is printed, plus a
  tip about `SAFEAI_REGISTRY`). Existing databases are never destroyed.
- Every subsequent scan **appends** a new snapshot — history is never
  overwritten.
- The per-project fallback (`<scan-root>/.safeai/registry.db`) is still
  used when you pass `--project-dir`/`--registry` explicitly, keeping
  existing per-project databases readable and backward compatible.
- If you use the default location, add it to your `.gitignore`
  (`~/.safeai/registry.db`); a per-project `registry.db` should also be
  ignored.

### CI behavior

When the `CI` environment variable is set, registry persistence is
**auto-disabled** for bare jobs so they don't write local state into
checkouts. An explicitly configured registry always wins:

```bash
safeai scan . --no-registry                          # explicit ephemeral scan
safeai scan . --registry "$RUNNER_TEMP/registry.db"  # persist to workspace/artifact storage
SAFEAI_REGISTRY=/org/data/safeai/registry.db safeai scan .   # persist to the org-shared registry
```

`--registry PATH` and a set `SAFEAI_REGISTRY` both override CI
auto-disable (they are deliberate configurations). A scan still succeeds
and produces reports if persistence fails (a warning is printed); use
`--strict-registry` to fail instead (exit code 2).

## Commands

```bash
safeai registry list                          # known agents/workflows
safeai registry show <agent-id>               # latest KYA record
safeai registry show <agent-id> --scan <id>   # historical record
safeai registry history <agent-id>            # all scans for an agent
safeai registry diff <agent-id> --from previous --to latest
safeai registry export --format json --output inventory.json
```

All commands accept `--registry PATH`, `--project-dir DIR`, and
`--format table|json|html`. `--format html` renders a self-contained,
dark-mode aware, searchable report page (redirect stdout to a file for
`list`/`show`/`history`/`diff`); `export --format html --output <path>`
writes the full inventory as one portable HTML document.

The default registry is resolved with this precedence:

```text
--registry PATH  >  --project-dir DIR/.safeai/registry.db  >  shared registry
```

where the shared registry is `SAFEAI_REGISTRY` if set, else
`~/.safeai/registry.db`. Because scans write to the same shared default,
you can scan several projects and then list the whole organization's
agents from anywhere:

```bash
safeai scan ../agents/crewai-examples                 # accumulates into the shared registry
safeai scan ../agents/agt-examples
safeai scan ../agents/langgraph-examples
safeai registry list                                  # shows agents from all of them
```

To inspect one project's own database (backward compatible with existing
per-project registries):

```bash
safeai scan ../other/project --registry ../other/project/.safeai/registry.db
safeai registry list --project-dir ../other/project   # reads it back
```

`diff` exit codes: `0` = no risk-relevant change, `1` = capability/finding
changes exist, `2` = usage/registry error.

### `registry diff` reports

- Added/removed capabilities and tools
- New / resolved / regressed findings
- Confidence changes

### `registry export`

Produces a versioned (`schema_version: 1.0`) inventory document containing
project metadata, current agent records, current posture, latest scan
references, and optionally history (`--include-history`) and suppressed
findings (`--include-suppressed`, excluded by default).

## What is stored

- Project metadata (ID, name, sanitized source root, remote fingerprint)
- Scan metadata (IDs, timestamps, tool/ruleset/config versions, commit)
- Full canonical manifest + its SHA-256 hash
- Agent snapshots, capabilities, tools
- Per-tool capability snapshots (`agent_tool_snapshots`, schema v2), including
  unattributed tools that could not be linked to a specific agent
- Findings with fingerprints, statuses, redacted evidence
- Policy decisions and matched policies

## What is never stored

- Raw source file contents
- Credentials, API keys, tokens, or unredacted secret values
- Telemetry of any kind
- Runtime activity data

## Schema & migrations

The schema is versioned via the `schema_migrations` table. Migrations are
additive, forward-only, and applied automatically on open — no existing
table or row is ever dropped or rewritten by a migration. Current
version: **2**.

Tables through schema v1: `schema_migrations`, `projects`, `scans`,
`agents`, `agent_snapshots`, `findings`, `scan_findings`,
`policy_decisions`, `policy_matches`, `metadata`. Indexes cover project,
agent ID, scan ID, finding fingerprint, and scan timestamp. WAL journal
mode is enabled for safe local CLI concurrency.

### Schema v2: `agent_tool_snapshots`

Migration 2 adds one table, capturing the per-tool capability surface
(`tool_surface` in the KYA manifest, see `KYA_MANIFEST.md`) for every scan:

```sql
CREATE TABLE IF NOT EXISTS agent_tool_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT REFERENCES agents(agent_id),
    scan_id  TEXT NOT NULL REFERENCES scans(scan_id),
    tool_key TEXT NOT NULL,
    tool_kind TEXT,
    tool_name TEXT,
    framework TEXT,
    capabilities_json TEXT NOT NULL,
    access_summary TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tool_snapshots_unique
    ON agent_tool_snapshots(IFNULL(agent_id, ''), scan_id, tool_key);
CREATE INDEX IF NOT EXISTS idx_tool_snapshots_agent ON agent_tool_snapshots(agent_id);
CREATE INDEX IF NOT EXISTS idx_tool_snapshots_key   ON agent_tool_snapshots(tool_key);
```

One row is inserted per tool per scan (`INSERT OR REPLACE`), with the
tool's capabilities stored as sorted JSON and `access_summary` set to the
highest access mode across the tool's capabilities.

**`agent_id` is nullable, and this is deliberate.** A tool surface is
attributed to an agent only when the tool's capability evidence paths
overlap the agent's declared `source_locations` — if a scan finds an MCP
server or tool whose evidence doesn't point back to any known agent's
source files, inventing an owner for it would be a fabricated attribution,
which this release explicitly avoids making. Such tools are retained in
`agent_tool_snapshots` with `agent_id = NULL` rather than dropped, so the
tool surface still shows up in registry queries; it is simply not claimed
to belong to anyone. When more than one agent's source locations overlap
a tool's evidence, the lowest agent ID (alphabetically) is used, to keep
attribution deterministic.

Because SQLite's ordinary `UNIQUE` constraint treats every `NULL` as
distinct from every other `NULL` (so two unattributed rows for the same
tool in the same scan would not violate a naive constraint), uniqueness
is enforced instead by an expression index over
`IFNULL(agent_id, ''), scan_id, tool_key`, which normalizes `NULL` to an
empty string before comparing.

### Migrating from schema v1

An existing v1 registry gains the `agent_tool_snapshots` table and its
indexes automatically the next time `safeai scan` opens it — no manual
migration step, flag, or separate command is required. All pre-existing
tables and rows (`agents`, `agent_snapshots`, `findings`, and so on) are
left exactly as they were; the migration is additive only. The registry's
`metadata` table records the applied `registry_version` so re-opening an
already-migrated database is a no-op.

## Backup

The registry is a single SQLite file (plus `-wal`/`-shm` sidecars while
open). To back up, close any running scans and copy the file, or use
`safeai registry export` for a portable JSON inventory.

## Limitations

Agent identity derives from project, framework, discovered name, primary
source path, and type. Renaming or moving the primary source file creates
a new agent identity; aliasing/migration is future work.
