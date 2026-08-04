"""Read-only query helpers used by the registry CLI and exporter.

All queries operate on an already-open connection (see
:func:`safeai.kya.registry.connection.connect`). None of them write.
"""

import json


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
