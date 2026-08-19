"""Read-only query helpers used by the registry CLI and exporter.

All queries operate on an already-open connection (see
:func:`safeai.kya.registry.connection.connect`). None of them write.
"""

import json
from datetime import UTC, datetime

from safeai.kya.util import utc_now_iso


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
            agent["last_scan_completed"] = latest["completed_at"]
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
        scan_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM agent_snapshots WHERE agent_id = ?",
            (row["agent_id"],),
        ).fetchone()
        agent["scan_count"] = scan_count["cnt"] if scan_count else 0
        agent["freshness"] = compute_freshness(agent.get("last_seen"))
        agents.append(agent)
    return agents


def compute_freshness(last_seen):
    """Compute a freshness label from the last_seen timestamp.

    Returns a dict with ``label`` (fresh/aging/stale/never), ``age_days``,
    and ``color`` (CSS color for display).
    """
    if not last_seen:
        return {"label": "never", "age_days": None, "color": "#6b7280"}
    try:
        last = datetime.fromisoformat(last_seen)
    except (ValueError, AttributeError):
        return {"label": "unknown", "age_days": None, "color": "#6b7280"}
    now = datetime.now(UTC)
    delta = now - last
    age_days = delta.days
    if age_days <= 7:
        return {"label": "fresh", "age_days": age_days, "color": "#059669"}
    if age_days <= 30:
        return {"label": "aging", "age_days": age_days, "color": "#d97706"}
    return {"label": "stale", "age_days": age_days, "color": "#dc2626"}


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
    from safeai.severity import SEVERITIES

    counts = {severity: 0 for severity in reversed(SEVERITIES)}
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


def list_components(conn, scan_id=None, component_type=None):
    """List component snapshots, optionally filtered by scan_id or type.

    Returns a list of dicts with component metadata including freshness
    indicators (first_seen_scan, last_seen_scan).
    """
    conditions = []
    params = []
    if scan_id:
        conditions.append("scan_id = ?")
        params.append(scan_id)
    if component_type:
        conditions.append("component_type = ?")
        params.append(component_type)
    where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    rows = conn.execute(
        f"SELECT * FROM component_snapshots{where} ORDER BY component_type, name, file_path",
        params,
    ).fetchall()
    components = []
    for row in rows:
        comp = dict(row)
        if comp.get("data_json"):
            try:
                comp["data"] = json.loads(comp["data_json"])
            except json.JSONDecodeError:
                comp["data"] = {}
        components.append(comp)
    return components


def component_history(conn, component_type, file_path):
    """List all scans that observed a specific component."""
    rows = conn.execute(
        "SELECT scan_id, first_seen_scan, last_seen_scan, data_json "
        "FROM component_snapshots WHERE component_type = ? AND file_path = ? "
        "ORDER BY scan_id DESC",
        (component_type, file_path),
    ).fetchall()
    return [dict(r) for r in rows]


def get_component_agents(conn, component_type, file_path):
    """Find all agents that reference a component (via scan co-occurrence)."""
    rows = conn.execute(
        "SELECT DISTINCT a.agent_id, a.name, a.framework, a.project_id "
        "FROM agents a "
        "JOIN agent_snapshots asnap ON asnap.agent_id = a.agent_id "
        "JOIN component_snapshots cs ON cs.scan_id = asnap.scan_id "
        "WHERE cs.component_type = ? AND cs.file_path = ? "
        "ORDER BY a.agent_id",
        (component_type, file_path),
    ).fetchall()
    return [dict(r) for r in rows]


# --- Finding lifecycle queries (schema v4) ---------------------------------


def finding_lifecycle(conn, fingerprint):
    """Return the full lifecycle history for a finding, newest first."""
    rows = conn.execute(
        "SELECT id, fingerprint, scan_id, event, previous_event, rule_id, "
        "severity, file_path, line, message, created_at "
        "FROM finding_lifecycle WHERE fingerprint = ? ORDER BY id DESC",
        (fingerprint,),
    ).fetchall()
    return [dict(r) for r in rows]


def finding_lifecycle_summary(conn):
    """Return lifecycle event counts across all findings."""
    rows = conn.execute(
        "SELECT event, COUNT(*) as count FROM finding_lifecycle "
        "GROUP BY event ORDER BY count DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def recurring_risks(conn):
    """Return all findings that were reopened after being resolved."""
    rows = conn.execute(
        "SELECT fl.fingerprint, fl.rule_id, fl.severity, fl.message, "
        "fl.file_path, fl.line, fl.created_at "
        "FROM finding_lifecycle fl "
        "WHERE fl.event = 'reopened' "
        "AND fl.previous_event = 'resolved' "
        "ORDER BY fl.created_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


# --- Agent enrichment queries (schema v4) -----------------------------------


def get_agent_metadata(conn, agent_id):
    """Return metadata for an agent, or None if not set."""
    row = conn.execute(
        "SELECT agent_id, owner, environment, purpose, lifecycle_status, updated_at "
        "FROM agent_metadata WHERE agent_id = ?",
        (agent_id,),
    ).fetchone()
    return dict(row) if row else None


def set_agent_metadata(conn, agent_id, owner=None, environment=None, purpose=None,
                       lifecycle_status=None):
    """Create or update agent metadata. Only provided fields are changed."""
    existing = get_agent_metadata(conn, agent_id)
    now = utc_now_iso()
    if existing:
        owner = owner if owner is not None else existing.get("owner")
        environment = environment if environment is not None else existing.get("environment")
        purpose = purpose if purpose is not None else existing.get("purpose")
        lifecycle_status = lifecycle_status if lifecycle_status is not None else existing.get("lifecycle_status")
        conn.execute(
            "UPDATE agent_metadata SET owner=?, environment=?, purpose=?, "
            "lifecycle_status=?, updated_at=? WHERE agent_id=?",
            (owner, environment, purpose, lifecycle_status, now, agent_id),
        )
    else:
        conn.execute(
            "INSERT INTO agent_metadata(agent_id, owner, environment, purpose, "
            "lifecycle_status, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (agent_id, owner, environment, purpose, lifecycle_status or "active", now),
        )
    return get_agent_metadata(conn, agent_id)
