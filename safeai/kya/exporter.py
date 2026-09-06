"""Registry export: produce a portable project inventory document.

The export contains project metadata, current agent records, current
posture, latest scan references, and optionally scan history. It never
contains raw source code or unredacted secret values.
"""

import json

from safeai.kya import STATIC_ANALYSIS_DISCLAIMER
from safeai.kya.registry import (
    agent_history,
    get_agent,
    get_agent_metadata,
    get_scan_findings,
    get_tool_snapshots,
    latest_scan_id,
    list_agents,
    list_components,
    list_projects,
)
from safeai.kya.util import utc_now_iso

EXPORT_SCHEMA_VERSION = "1.1"


def _portable_components(conn, scan_id):
    components = []
    for row in list_components(conn, scan_id=scan_id):
        data = row.get("data")
        if isinstance(data, dict):
            components.append(data)
            continue
        components.append({
            "type": row.get("component_type"),
            "subtype": row.get("component_subtype"),
            "name": row.get("name"),
            "path": row.get("file_path"),
            "source": row.get("source"),
            "line": row.get("line"),
            "content_hash": row.get("content_hash"),
        })
    return components


def _portable_lifecycle(conn, project_id, fingerprints):
    if not fingerprints:
        return []
    rows = conn.execute(
        "SELECT fl.*, fl.scan_id AS source_scan_id FROM finding_lifecycle fl "
        "JOIN scans s ON s.scan_id = fl.scan_id WHERE s.project_id = ? ORDER BY fl.id",
        (project_id,),
    ).fetchall()
    return [
        {key: value for key, value in dict(row).items() if key not in {"id", "scan_id"}}
        for row in rows if row["fingerprint"] in fingerprints
    ]


def export_inventory(conn, *, project_id=None, include_history=False, include_suppressed=False):
    """Build the export document from an open registry connection."""
    projects = list_projects(conn)
    if project_id:
        projects = [p for p in projects if p["project_id"] == project_id]

    export_projects = []
    for project in projects:
        pid = project["project_id"]
        agents = []
        for agent_row in list_agents(conn, pid):
            record = get_agent(conn, agent_row["agent_id"])
            if not record:
                continue
            snapshot = record.get("snapshot") or {}
            entry = {
                "agent_id": record["agent_id"],
                "name": record.get("name"),
                "agent_type": record.get("agent_type"),
                "framework": record.get("framework"),
                "first_seen": record.get("first_seen"),
                "last_seen": record.get("last_seen"),
                "source_locations": snapshot.get("source_locations") or [],
                "capabilities": snapshot.get("capabilities") or [],
                "tools": snapshot.get("tools") or [],
                "confidence": snapshot.get("confidence"),
                "latest_scan": record.get("scan"),
                "findings": [
                    f for f in (record.get("findings") or [])
                    if include_suppressed or f.get("status") != "suppressed"
                ],
                "metadata": get_agent_metadata(conn, record["agent_id"]),
            }
            if include_history:
                entry["history"] = agent_history(conn, record["agent_id"])
            agents.append(entry)

        latest = latest_scan_id(conn, pid)
        latest_findings = get_scan_findings(conn, latest) if latest else []
        if not include_suppressed:
            latest_findings = [f for f in latest_findings if f.get("status") != "suppressed"]
        exported_fingerprints = {
            finding.get("fingerprint") for finding in latest_findings
            if finding.get("fingerprint")
        }

        export_projects.append({
            "project_id": pid,
            "name": project.get("name"),
            "source_root": project.get("source_root"),
            "agents": agents,
            "latest_scan_id": latest,
            "latest_findings": latest_findings,
            "component_snapshots": _portable_components(conn, latest) if latest else [],
            "tool_snapshots": get_tool_snapshots(conn, latest) if latest else [],
            "finding_lifecycle": _portable_lifecycle(conn, pid, exported_fingerprints),
        })

    return {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "export_type": "safeai.kya.inventory",
        "generated_at": utc_now_iso(),
        "projects": export_projects,
        "limitations": [STATIC_ANALYSIS_DISCLAIMER],
    }


def write_export(document, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True, default=str)
        fh.write("\n")
