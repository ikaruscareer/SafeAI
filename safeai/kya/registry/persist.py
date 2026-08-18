"""Append-only persistence of scan snapshots.

A prior scan snapshot is never overwritten. Finding statuses are refined
using registry history — a fingerprint seen before, absent in the
immediately previous scan, and present again is classified ``regressed``.
Raw source code and unredacted secret values are never stored.
"""

import json
import sqlite3

from safeai.kya.registry.connection import RegistryError
from safeai.kya.util import sha256_text, utc_now_iso


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
            _persist_components(conn, manifest, scan_id)

            recurring_risks = _persist_finding_lifecycle(
                conn, manifest.get("findings") or [], scan_id,
                known_fps, previous_fps,
            )
            stats["recurring_risks"] = recurring_risks

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


def _persist_components(conn, manifest, scan_id):
    """Persist component snapshots from the manifest into the registry.

    Components are stored in the ``component_snapshots`` table (schema v3)
    with first_seen/last_seen tracking for freshness queries.
    """
    components = manifest.get("components") or []
    if not components:
        return

    existing = {}
    for row in conn.execute(
        "SELECT component_type, file_path, last_seen_scan FROM component_snapshots"
    ).fetchall():
        key = (row["component_type"], row["file_path"])
        existing[key] = row["last_seen_scan"]

    for comp in components:
        comp_type = comp.get("type") or "unknown"
        comp_path = comp.get("path") or comp.get("file") or ""
        comp_name = comp.get("name") or ""
        comp_subtype = comp.get("subtype") or ""
        comp_source = comp.get("source") or ""
        comp_line = comp.get("line")
        data_json = json.dumps(comp, sort_keys=True, default=str)
        key = (comp_type, comp_path)
        first_seen = existing.get(key) or scan_id
        conn.execute(
            "INSERT OR REPLACE INTO component_snapshots("
            "scan_id, component_type, component_subtype, name, file_path, "
            "source, line, data_json, first_seen_scan, last_seen_scan"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                comp_type,
                comp_subtype,
                comp_name,
                comp_path,
                comp_source,
                comp_line,
                data_json,
                first_seen,
                scan_id,
            ),
        )


def _persist_finding_lifecycle(conn, findings, scan_id, known_fps, previous_fps):
    """Track finding lifecycle events and return recurring-risk escalations.

    For each finding, emits a lifecycle event into the ``finding_lifecycle``
    table and returns a list of ``ESC_RECURRING_RISK`` escalation dicts for
    findings that were previously resolved and have reappeared.

    Lifecycle events:
    - ``introduced`` — fingerprint seen for the first time
    - ``persisting`` — fingerprint seen in the previous scan and still present
    - ``reopened`` — fingerprint was absent in the previous scan but seen earlier
    """
    recurring_risks = []
    for finding in findings or []:
        fp = finding.get("fingerprint")
        if not fp:
            continue
        status = finding.get("status", "new")
        location = finding.get("location") or {}
        if status == "regressed":
            # Was absent in previous scan but seen earlier — reopened
            event = "reopened"
            # Check if the finding was previously resolved
            prev = conn.execute(
                "SELECT event FROM finding_lifecycle WHERE fingerprint = ? "
                "ORDER BY id DESC LIMIT 1",
                (fp,),
            ).fetchone()
            previous_event = prev["event"] if prev else None
            if previous_event == "resolved":
                recurring_risks.append({
                    "fingerprint": fp,
                    "rule_id": finding.get("rule_id"),
                    "severity": finding.get("severity"),
                    "message": finding.get("message"),
                    "file": location.get("path"),
                    "line": location.get("line_start"),
                })
        elif status == "existing":
            event = "persisting"
            previous_event = None
        elif fp not in known_fps:
            event = "introduced"
            previous_event = None
        else:
            event = "persisting"
            previous_event = None

        conn.execute(
            "INSERT INTO finding_lifecycle("
            "fingerprint, scan_id, event, previous_event, rule_id, "
            "severity, file_path, line, message, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fp,
                scan_id,
                event,
                previous_event,
                finding.get("rule_id"),
                finding.get("severity"),
                location.get("path"),
                location.get("line_start"),
                finding.get("message"),
                utc_now_iso(),
            ),
        )

        # Update findings table status for lifecycle tracking
        if event == "reopened":
            conn.execute(
                "UPDATE findings SET status = 'reopened' WHERE fingerprint = ?",
                (fp,),
            )

    return recurring_risks
