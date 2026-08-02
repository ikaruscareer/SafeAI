"""Local SQLite KYA registry.

Stores scan-derived, static-analysis agent records and evidence at
``.safeai/registry.db`` by default. Everything stays on the local
filesystem: no server, account, network call, or source upload.

Design notes:
  * Standard-library ``sqlite3`` only — no ORM, no new dependencies.
  * WAL journal mode for safe local CLI concurrency.
  * Versioned schema via ``schema_migrations``; migrations are additive.
  * Historical scans are append-only: a prior scan snapshot is never
    overwritten.
  * Raw source code and unredacted secrets are never stored.
"""

import json
import os
import sqlite3

from safeai.kya import REGISTRY_SCHEMA_VERSION
from safeai.kya.util import sha256_text, utc_now_iso

DEFAULT_REGISTRY_DIRNAME = ".safeai"
DEFAULT_REGISTRY_FILENAME = "registry.db"

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

#: Forward-only migrations, applied in ascending order. Migrations are
#: additive: no migration drops, rewrites, or reorders an existing row.
_MIGRATIONS = {
    1: _SCHEMA,
    2: _SCHEMA_V2,
}


class RegistryError(Exception):
    """Raised for registry open, migration, or persistence failures."""


def default_registry_path(root):
    """Return the default registry path for a scan root."""
    return os.path.join(root, DEFAULT_REGISTRY_DIRNAME, DEFAULT_REGISTRY_FILENAME)


def registry_exists(path):
    return bool(path) and os.path.exists(path)


def connect(path):
    """Open a registry connection with safe local CLI pragmas."""
    try:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=3000")
        return conn
    except sqlite3.Error as exc:
        raise RegistryError(f"Unable to open registry at {path}: {exc}") from exc


def _current_version(conn):
    try:
        row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
    except sqlite3.Error:
        return 0
    return row["v"] if row and row["v"] is not None else 0


def migrate(conn):
    """Apply pending schema migrations in ascending order.

    Migrations are additive and forward-only: an existing v1.3 database
    opens, gains the new tables, and keeps every prior row untouched.
    """
    version = _current_version(conn)
    if version >= REGISTRY_SCHEMA_VERSION:
        return version
    with conn:
        for target in sorted(_MIGRATIONS):
            if target <= version:
                continue
            conn.executescript(_MIGRATIONS[target])
            conn.execute(
                "INSERT OR REPLACE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (target, utc_now_iso()),
            )
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES ('registry_version', ?)",
            (str(REGISTRY_SCHEMA_VERSION),),
        )
    return REGISTRY_SCHEMA_VERSION


def init_registry(path):
    """Create (if needed) and migrate the registry at ``path``.

    Returns ``(conn, created)``. Never destroys an existing database;
    parent directories are created safely.
    """
    created = not os.path.exists(path)
    parent = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        raise RegistryError(f"Unable to create registry directory {parent}: {exc}") from exc
    conn = connect(path)
    try:
        migrate(conn)
    except sqlite3.Error as exc:
        conn.close()
        raise RegistryError(f"Unable to migrate registry at {path}: {exc}") from exc
    return conn, created


def _previous_scan_fingerprints(conn, project_id, exclude_scan_id):
    # rowid breaks completed_at ties so same-second scans order by insertion.
    row = conn.execute(
        "SELECT scan_id FROM scans WHERE project_id = ? AND scan_id != ? "
        "ORDER BY completed_at DESC, rowid DESC LIMIT 1",
        (project_id, exclude_scan_id),
    ).fetchone()
    if not row:
        return None, set()
    scan_id = row["scan_id"]
    rows = conn.execute(
        "SELECT fingerprint FROM scan_findings WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    return scan_id, {r["fingerprint"] for r in rows}


def _agent_id_for_tool(manifest, tool_entry):
    """Attribute a tool to an agent by shared evidence path, or return None.

    Attribution is evidence-based only. When no agent declares a source
    location matching the tool's evidence the tool is stored unattributed
    rather than assigned to an arbitrary owner.
    """
    paths = set()
    for capability in tool_entry.get("capabilities") or []:
        for item in capability.get("evidence") or []:
            path = item.get("path")
            if path:
                paths.add(str(path).replace("\\", "/"))
    if not paths:
        return None
    candidates = []
    for agent in manifest.get("agents") or []:
        agent_paths = {
            str(loc.get("path")).replace("\\", "/")
            for loc in (agent.get("source_locations") or [])
            if loc.get("path")
        }
        if agent_paths & paths:
            candidates.append(agent["agent_id"])
    return min(candidates) if candidates else None


def _persist_tool_surface(conn, manifest, scan_id, stats):
    """Store the per-tool capability surface for this scan (schema v2)."""
    surface = manifest.get("tool_surface") or []
    stored = 0
    for tool_entry in sorted(surface, key=lambda t: str(t.get("tool_key"))):
        tool = tool_entry.get("tool") or {}
        capabilities = sorted(
            (
                {
                    "name": c.get("name"),
                    "access_mode": c.get("access_mode"),
                    "confidence": c.get("confidence"),
                    "inferred": bool(c.get("inferred")),
                }
                for c in tool_entry.get("capabilities") or []
            ),
            key=lambda c: (str(c["name"]), str(c["access_mode"])),
        )
        conn.execute(
            "INSERT OR REPLACE INTO agent_tool_snapshots("
            "agent_id, scan_id, tool_key, tool_kind, tool_name, framework, "
            "capabilities_json, access_summary"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _agent_id_for_tool(manifest, tool_entry),
                scan_id,
                tool_entry.get("tool_key"),
                tool.get("kind"),
                tool.get("name"),
                tool.get("framework"),
                json.dumps(capabilities, sort_keys=True, separators=(",", ":"), default=str),
                tool_entry.get("access_summary"),
            ),
        )
        stored += 1
    stats["tool_snapshots"] = stored
    return stored


def get_tool_snapshots(conn, scan_id):
    """Return the stored per-tool surface for a scan, sorted by tool key."""
    rows = conn.execute(
        "SELECT tool_key, tool_kind, tool_name, framework, capabilities_json, access_summary "
        "FROM agent_tool_snapshots WHERE scan_id = ? ORDER BY tool_key",
        (scan_id,),
    ).fetchall()
    surface = []
    for row in rows:
        try:
            capabilities = json.loads(row["capabilities_json"])
        except (TypeError, ValueError):
            capabilities = []
        surface.append({
            "tool_key": row["tool_key"],
            "tool": {
                "kind": row["tool_kind"],
                "name": row["tool_name"],
                "framework": row["framework"],
            },
            "capabilities": capabilities,
            "access_summary": row["access_summary"],
        })
    return surface


def persist_scan(conn, manifest):
    """Persist a scan snapshot (project, scan, agents, findings, policy).

    Append-only: existing scans and snapshots are never overwritten.
    Finding statuses are refined using registry history — a fingerprint
    seen before, absent in the immediately previous scan, and present
    again is classified ``regressed``.

    Returns a stats dict for terminal output.
    """
    project = manifest["project"]
    scan = manifest["scan"]
    safeai = manifest["safeai"]
    summary = manifest["summary"]
    repo = project.get("repository") or {}
    now = utc_now_iso()

    project_id = project["project_id"]
    scan_id = scan["scan_id"]

    manifest_json = json.dumps(manifest, sort_keys=True, default=str)
    manifest_hash = sha256_text(manifest_json)

    stats = {
        "project_id": project_id,
        "scan_id": scan_id,
        "new_agents": 0,
        "updated_agents": 0,
        "new_findings": 0,
        "regressed_findings": 0,
        "agent_count": len(manifest.get("agents") or []),
    }

    try:
        with conn:
            conn.execute(
                "INSERT INTO projects(project_id, name, source_root, remote_fingerprint, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(project_id) DO UPDATE SET name=excluded.name, "
                "source_root=excluded.source_root, updated_at=excluded.updated_at",
                (
                    project_id,
                    project.get("name"),
                    project.get("source_root"),
                    repo.get("remote_fingerprint"),
                    now,
                    now,
                ),
            )

            _, previous_fps = _previous_scan_fingerprints(conn, project_id, scan_id)

            # Refine statuses using history before storing the snapshot.
            known_rows = conn.execute(
                "SELECT fingerprint FROM findings"
            ).fetchall()
            known_fps = {r["fingerprint"] for r in known_rows}

            for finding in manifest.get("findings") or []:
                fp = finding.get("fingerprint")
                if not fp:
                    continue
                if fp in known_fps:
                    if previous_fps is not None and fp not in previous_fps:
                        finding["status"] = "regressed"
                        stats["regressed_findings"] += 1
                    elif finding.get("status") == "new":
                        finding["status"] = "existing"
                else:
                    stats["new_findings"] += 1

            # Re-serialize after status refinement so stored + exported
            # manifests carry final statuses.
            manifest_json = json.dumps(manifest, sort_keys=True, default=str)
            manifest_hash = sha256_text(manifest_json)

            policy = summary.get("policy_decision") or {}
            conn.execute(
                "INSERT OR REPLACE INTO scans("
                "scan_id, project_id, started_at, completed_at, files_scanned, "
                "safeai_version, ruleset_version, config_hash, commit_sha, branch, tag, "
                "manifest_json, manifest_hash, policy_outcome, risk_score, "
                "agent_count, finding_count, severity_counts_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    project_id,
                    scan.get("started_at"),
                    scan.get("completed_at"),
                    scan.get("files_scanned"),
                    safeai.get("version"),
                    safeai.get("ruleset_version"),
                    safeai.get("config_hash"),
                    repo.get("commit_sha"),
                    repo.get("branch"),
                    repo.get("tag"),
                    manifest_json,
                    manifest_hash,
                    policy.get("outcome"),
                    summary.get("risk_score"),
                    summary.get("agent_count"),
                    len(manifest.get("findings") or []),
                    json.dumps(summary.get("severity_counts") or {}, sort_keys=True),
                ),
            )

            for agent in manifest.get("agents") or []:
                agent_id = agent["agent_id"]
                primary_path = (agent.get("source_locations") or [{}])[0].get("path")
                source_paths = {
                    str(loc.get("path")).replace("\\", "/")
                    for loc in (agent.get("source_locations") or [])
                    if loc.get("path")
                }
                scoped_findings = [
                    finding
                    for finding in (manifest.get("findings") or [])
                    if ((finding.get("location") or {}).get("path") or "").replace("\\", "/") in source_paths
                ]
                existing = conn.execute(
                    "SELECT agent_id, first_seen FROM agents WHERE agent_id = ?", (agent_id,)
                ).fetchone()
                if existing:
                    agent["first_seen"] = existing["first_seen"]
                    conn.execute(
                        "UPDATE agents SET name=?, agent_type=?, framework=?, primary_path=?, last_seen=? "
                        "WHERE agent_id=?",
                        (
                            agent.get("name"),
                            agent.get("agent_type"),
                            agent.get("framework"),
                            primary_path,
                            now,
                            agent_id,
                        ),
                    )
                    stats["updated_agents"] += 1
                else:
                    agent["first_seen"] = now
                    conn.execute(
                        "INSERT INTO agents(agent_id, project_id, name, agent_type, framework, "
                        "primary_path, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            agent_id,
                            project_id,
                            agent.get("name"),
                            agent.get("agent_type"),
                            agent.get("framework"),
                            primary_path,
                            now,
                            now,
                        ),
                    )
                    stats["new_agents"] += 1

                conn.execute(
                    "INSERT OR REPLACE INTO agent_snapshots("
                    "agent_id, scan_id, snapshot_json, capability_count, finding_count, confidence"
                    ") VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        agent_id,
                        scan_id,
                        json.dumps(agent, sort_keys=True, default=str),
                        len(agent.get("capabilities") or []),
                        len(scoped_findings),
                        agent.get("confidence"),
                    ),
                )

            for finding in manifest.get("findings") or []:
                fp = finding.get("fingerprint")
                if not fp:
                    continue
                conn.execute(
                    "INSERT INTO findings(fingerprint, rule_id, severity, title, message, "
                    "remediation, confidence, first_seen_scan, last_seen_scan, status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(fingerprint) DO UPDATE SET last_seen_scan=excluded.last_seen_scan, "
                    "status=excluded.status, severity=excluded.severity",
                    (
                        fp,
                        finding.get("rule_id"),
                        finding.get("severity"),
                        finding.get("title"),
                        finding.get("message"),
                        finding.get("remediation"),
                        finding.get("confidence"),
                        scan_id,
                        scan_id,
                        finding.get("status", "new"),
                    ),
                )
                location = finding.get("location") or {}
                conn.execute(
                    "INSERT OR REPLACE INTO scan_findings("
                    "scan_id, fingerprint, status, severity, rule_id, path, line, finding_json"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        scan_id,
                        fp,
                        finding.get("status", "new"),
                        finding.get("severity"),
                        finding.get("rule_id"),
                        location.get("path"),
                        location.get("line_start"),
                        json.dumps(finding, sort_keys=True, default=str),
                    ),
                )

            _persist_tool_surface(conn, manifest, scan_id, stats)

            conn.execute(
                "INSERT OR REPLACE INTO policy_decisions(scan_id, outcome, reasons_json) VALUES (?, ?, ?)",
                (scan_id, policy.get("outcome"), json.dumps(policy.get("reasons") or [])),
            )
            for match in policy.get("matches") or []:
                conn.execute(
                    "INSERT INTO policy_matches(scan_id, policy_id, action, message, matched_json) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        scan_id,
                        match.get("policy_id"),
                        match.get("action"),
                        match.get("message"),
                        json.dumps(match.get("matched") or [], default=str),
                    ),
                )
    except sqlite3.Error as exc:
        raise RegistryError(f"Failed to persist scan {scan_id}: {exc}") from exc

    return stats


# ---------------------------------------------------------------------------
# Query helpers used by the registry CLI
# ---------------------------------------------------------------------------

def list_projects(conn):
    rows = conn.execute(
        "SELECT project_id, name, source_root, created_at, updated_at FROM projects ORDER BY updated_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def _latest_scan_for_agent(conn, agent_id):
    return conn.execute(
        "SELECT s.* FROM scans s JOIN agent_snapshots a ON a.scan_id = s.scan_id "
        "WHERE a.agent_id = ? ORDER BY s.completed_at DESC, s.rowid DESC LIMIT 1",
        (agent_id,),
    ).fetchone()


def list_agents(conn, project_id=None):
    """List known agents with their latest snapshot metadata."""
    if project_id:
        rows = conn.execute(
            "SELECT * FROM agents WHERE project_id = ? ORDER BY agent_id", (project_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM agents ORDER BY agent_id").fetchall()

    agents = []
    for row in rows:
        agent = dict(row)
        latest = _latest_scan_for_agent(conn, row["agent_id"])
        if latest:
            agent["last_scan_id"] = latest["scan_id"]
            scoped_findings = get_agent_scan_findings(conn, row["agent_id"], latest["scan_id"])
            agent["policy_outcome"] = _agent_policy_outcome(
                conn,
                latest["scan_id"],
                {f.get("fingerprint") for f in scoped_findings if f.get("fingerprint")},
                default="warn",
            )
            agent["risk_score"] = _agent_risk_score(scoped_findings)
            agent["severity_counts"] = _severity_counts(scoped_findings)
        snap = conn.execute(
            "SELECT capability_count, confidence FROM agent_snapshots WHERE agent_id = ? "
            "ORDER BY id DESC LIMIT 1",
            (row["agent_id"],),
        ).fetchone()
        if snap:
            agent["capability_count"] = snap["capability_count"]
            agent["confidence"] = snap["confidence"]
        agents.append(agent)
    return agents


def get_agent(conn, agent_id, scan_id=None):
    """Fetch one agent record plus (optionally a specific) snapshot."""
    row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if not row:
        return None
    agent = dict(row)
    if scan_id:
        snap = conn.execute(
            "SELECT * FROM agent_snapshots WHERE agent_id = ? AND scan_id = ?",
            (agent_id, scan_id),
        ).fetchone()
    else:
        snap = conn.execute(
            "SELECT * FROM agent_snapshots WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
            (agent_id,),
        ).fetchone()
    if snap:
        agent["snapshot"] = json.loads(snap["snapshot_json"])
        agent["snapshot_scan_id"] = snap["scan_id"]
        scan = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (snap["scan_id"],)).fetchone()
        if scan:
            agent["scan"] = {
                "scan_id": scan["scan_id"],
                "completed_at": scan["completed_at"],
                "commit_sha": scan["commit_sha"],
                "policy_outcome": scan["policy_outcome"],
                "risk_score": scan["risk_score"],
            }
        scoped = get_agent_scan_findings(conn, agent_id, snap["scan_id"])
        agent["findings"] = [
            {
                "fingerprint": f.get("fingerprint"),
                "rule_id": f.get("rule_id"),
                "severity": f.get("severity"),
                "status": f.get("status"),
                "path": (f.get("location") or {}).get("path"),
                "line": (f.get("location") or {}).get("line_start"),
            }
            for f in scoped
        ]
    return agent


def agent_history(conn, agent_id):
    """List all scans that observed this agent, newest first."""
    rows = conn.execute(
        "SELECT s.scan_id, s.completed_at, s.commit_sha, s.policy_outcome, s.risk_score, "
        "s.severity_counts_json, a.capability_count FROM scans s "
        "JOIN agent_snapshots a ON a.scan_id = s.scan_id "
        "WHERE a.agent_id = ? ORDER BY s.completed_at DESC, s.rowid DESC",
        (agent_id,),
    ).fetchall()
    history = []
    for row in rows:
        entry = dict(row)
        entry["severity_counts"] = json.loads(entry.pop("severity_counts_json") or "{}")
        history.append(entry)
    return history


def resolve_scan_ref(conn, agent_id, ref):
    """Resolve ``latest``/``previous``/explicit scan ID for an agent."""
    rows = conn.execute(
        "SELECT scan_id FROM agent_snapshots WHERE agent_id = ? ORDER BY id DESC",
        (agent_id,),
    ).fetchall()
    scan_ids = [r["scan_id"] for r in rows]
    if not scan_ids:
        return None
    if ref in (None, "latest"):
        return scan_ids[0]
    if ref == "previous":
        return scan_ids[1] if len(scan_ids) > 1 else None
    return ref


def get_snapshot(conn, agent_id, scan_id):
    row = conn.execute(
        "SELECT snapshot_json FROM agent_snapshots WHERE agent_id = ? AND scan_id = ?",
        (agent_id, scan_id),
    ).fetchone()
    return json.loads(row["snapshot_json"]) if row else None


def get_scan_findings(conn, scan_id):
    rows = conn.execute(
        "SELECT finding_json FROM scan_findings WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    return [json.loads(r["finding_json"]) for r in rows]


def _severity_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "medium").lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _agent_risk_score(findings):
    if not findings:
        return 0
    from safeai.scoring.engine import score_report

    return score_report(findings).get("overall_ai_risk_score")


def _agent_policy_outcome(conn, scan_id, agent_fingerprints, default="warn"):
    """Derive agent-specific policy outcome from policy match records.

    Falls back to ``default`` when no policy matches are scoped to findings
    belonging to the selected agent.
    """
    if not agent_fingerprints:
        return default

    action_rank = {"allow": 0, "warn": 1, "require_review": 2, "deny": 3}
    highest = action_rank.get(default or "warn", 1)

    rows = conn.execute(
        "SELECT action, matched_json FROM policy_matches WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()

    for row in rows:
        action = str(row["action"] or "warn").lower()
        try:
            matched = json.loads(row["matched_json"] or "[]")
        except json.JSONDecodeError:
            matched = []
        for item in matched:
            fingerprint = item.get("fingerprint")
            status = item.get("status")
            if fingerprint in agent_fingerprints and status != "suppressed":
                highest = max(highest, action_rank.get(action, 1))
                break

    reverse = {value: key for key, value in action_rank.items()}
    return reverse.get(highest, default or "warn")


def _source_paths_from_snapshot(snapshot):
    paths = set()
    for location in snapshot.get("source_locations") or []:
        path = location.get("path")
        if path:
            paths.add(str(path).replace("\\", "/"))
    return paths


def get_agent_scan_findings(conn, agent_id, scan_id):
    """Return findings in ``scan_id`` scoped to ``agent_id`` source paths.

    This avoids presenting project-wide findings as if they belonged to a
    specific agent in ``registry show`` and ``registry diff``.
    """
    snapshot = get_snapshot(conn, agent_id, scan_id)
    if not snapshot:
        return []
    source_paths = _source_paths_from_snapshot(snapshot)
    if not source_paths:
        return []

    scoped = []
    for finding in get_scan_findings(conn, scan_id):
        location = finding.get("location") or {}
        path = location.get("path")
        if not path:
            continue
        normalized = str(path).replace("\\", "/")
        if normalized in source_paths:
            scoped.append(finding)
    return scoped


def latest_scan_id(conn, project_id=None):
    if project_id:
        row = conn.execute(
            "SELECT scan_id FROM scans WHERE project_id = ? "
            "ORDER BY completed_at DESC, rowid DESC LIMIT 1",
            (project_id,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT scan_id FROM scans ORDER BY completed_at DESC, rowid DESC LIMIT 1"
        ).fetchone()
    return row["scan_id"] if row else None
