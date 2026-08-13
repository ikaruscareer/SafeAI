"""Registry schema definitions and forward-only migrations.

Schema v1 (``_SCHEMA``): projects, scans, agents, agent_snapshots,
findings, scan_findings, policy_decisions, policy_matches, metadata plus
supporting indexes.

Schema v2 (``_SCHEMA_V2``, added in v1.4): per-tool capability snapshots
(``agent_tool_snapshots``) with evidence-based agent attribution.

Migrations are additive: no migration drops, rewrites, or reorders an
existing row. They are applied in ascending order by
:func:`safeai.kya.registry.connection.migrate`.
"""

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    name TEXT,
    source_root TEXT,
    remote_fingerprint TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    started_at TEXT,
    completed_at TEXT,
    files_scanned INTEGER,
    safeai_version TEXT,
    ruleset_version TEXT,
    config_hash TEXT,
    commit_sha TEXT,
    branch TEXT,
    tag TEXT,
    manifest_json TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    policy_outcome TEXT,
    risk_score INTEGER,
    agent_count INTEGER,
    finding_count INTEGER,
    severity_counts_json TEXT
);
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    name TEXT,
    agent_type TEXT,
    framework TEXT,
    primary_path TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    snapshot_json TEXT NOT NULL,
    capability_count INTEGER,
    finding_count INTEGER,
    confidence TEXT,
    UNIQUE(agent_id, scan_id)
);
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    rule_id TEXT,
    severity TEXT,
    title TEXT,
    message TEXT,
    remediation TEXT,
    confidence TEXT,
    first_seen_scan TEXT,
    last_seen_scan TEXT,
    status TEXT DEFAULT 'new'
);
CREATE TABLE IF NOT EXISTS scan_findings (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    fingerprint TEXT NOT NULL REFERENCES findings(fingerprint),
    status TEXT,
    severity TEXT,
    rule_id TEXT,
    path TEXT,
    line INTEGER,
    finding_json TEXT,
    PRIMARY KEY (scan_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS policy_decisions (
    scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id),
    outcome TEXT,
    reasons_json TEXT
);
CREATE TABLE IF NOT EXISTS policy_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    policy_id TEXT,
    action TEXT,
    message TEXT,
    matched_json TEXT
);
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_scans_completed ON scans(completed_at);
CREATE INDEX IF NOT EXISTS idx_agents_project ON agents(project_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_agent ON agent_snapshots(agent_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_fp ON scan_findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
"""

# --- Migration 2 (v1.4): per-tool capability snapshots ------------------
#
# Deviation from the release note's draft DDL, made deliberately:
# ``agent_id`` is nullable. A tool surface is attributed to an agent only
# when static evidence supports it; inventing an owner for an
# unattributed MCP server would fabricate attribution, which the release
# explicitly forbids. Because SQLite treats NULLs as distinct in UNIQUE
# constraints, uniqueness is enforced by an expression index instead.
_SCHEMA_V2 = """
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
"""

# --- Migration 3 (v1.7): component registry persistence -----------------
#
# Stores component identity, version/hash, source, findings and usage
# relationships in the local registry so teams can query "which agents
# reference this component?" and track component-change diffs.
_SCHEMA_V3 = """
CREATE TABLE IF NOT EXISTS component_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    component_type TEXT NOT NULL,
    component_subtype TEXT,
    name TEXT,
    file_path TEXT NOT NULL,
    source TEXT,
    line INTEGER,
    data_json TEXT,
    first_seen_scan TEXT NOT NULL,
    last_seen_scan TEXT NOT NULL,
    UNIQUE(scan_id, component_type, file_path)
);
CREATE INDEX IF NOT EXISTS idx_component_snapshots_type ON component_snapshots(component_type);
CREATE INDEX IF NOT EXISTS idx_component_snapshots_name ON component_snapshots(name);
CREATE INDEX IF NOT EXISTS idx_component_snapshots_file ON component_snapshots(file_path);
"""

#: Forward-only migrations, applied in ascending order. Migrations are
#: additive: no migration drops, rewrites, or reorders an existing row.
_MIGRATIONS = {
    1: _SCHEMA,
    2: _SCHEMA_V2,
    3: _SCHEMA_V3,
}
