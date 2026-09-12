"""Portable KYA inventory import.

The importer validates the complete document before writing, then merges the
source inventory in one transaction.  Re-importing the same document is
idempotent because every imported snapshot is attached to a deterministic
import scan ID and table-native identities are preserved.
"""

import json

from safeai.kya.exporter import EXPORT_SCHEMA_VERSION
from safeai.kya.registry import RegistryError
from safeai.kya.util import sha256_text, utc_now_iso

SUPPORTED_SCHEMA_VERSIONS = {"1.0", EXPORT_SCHEMA_VERSION}


def load_inventory(path, *, require_integrity=False):
    """Load and validate a portable inventory JSON document.

    ``require_integrity`` rejects documents whose integrity digest is
    missing or invalid. Default ``False`` preserves backward
    compatibility with pre-2.2 exports.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            document = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"Unable to read inventory {path}: {exc}") from exc
    validate_inventory(document)
    if require_integrity:
        from safeai.kya.integrity import OK, verify_document
        status, detail = verify_document(document)
        if status != OK:
            raise RegistryError(
                f"Integrity check failed ({status}): {detail}")
    return document


def validate_inventory(document):
    """Reject malformed or unsupported inventories before any registry write."""
    if not isinstance(document, dict):
        raise RegistryError("Invalid inventory: root must be a JSON object")
    if document.get("export_type") != "safeai.kya.inventory":
        raise RegistryError("Invalid inventory: export_type must be 'safeai.kya.inventory'")
    version = str(document.get("schema_version") or "")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(sorted(SUPPORTED_SCHEMA_VERSIONS))
        raise RegistryError(
            f"Unsupported inventory schema_version '{version}' (supported: {supported})"
        )
    projects = document.get("projects")
    if not isinstance(projects, list):
        raise RegistryError("Invalid inventory: projects must be a list")

    project_ids = set()
    agent_projects = {}
    for project in projects:
        if not isinstance(project, dict):
            raise RegistryError("Invalid inventory: each project must be an object")
        project_id = project.get("project_id")
        if not isinstance(project_id, str) or not project_id.strip():
            raise RegistryError("Invalid inventory: every project needs a project_id")
        if project_id in project_ids:
            raise RegistryError(f"Invalid inventory: duplicate project_id '{project_id}'")
        project_ids.add(project_id)
        agents = project.get("agents", [])
        if not isinstance(agents, list):
            raise RegistryError(f"Invalid inventory: agents for '{project_id}' must be a list")
        for agent in agents:
            if not isinstance(agent, dict):
                raise RegistryError("Invalid inventory: each agent must be an object")
            agent_id = agent.get("agent_id")
            if not isinstance(agent_id, str) or not agent_id.strip():
                raise RegistryError("Invalid inventory: every agent needs an agent_id")
            previous_project = agent_projects.setdefault(agent_id, project_id)
            if previous_project != project_id:
                raise RegistryError(
                    f"Invalid inventory: agent_id '{agent_id}' belongs to multiple projects"
                )
        for key in (
            "latest_findings",
            "component_snapshots",
            "finding_lifecycle",
            "tool_snapshots",
        ):
            value = project.get(key, [])
            if not isinstance(value, list):
                raise RegistryError(f"Invalid inventory: {key} for '{project_id}' must be a list")


def _import_scan_id(document, project):
    payload = {
        "schema_version": document["schema_version"],
        "generated_at": document.get("generated_at"),
        "project": project,
    }
    digest = sha256_text(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str))
    return f"import-{digest[:32]}"


def _exists(conn, sql, params):
    return conn.execute(sql, params).fetchone() is not None


def plan_import(conn, document, *, force=False):
    """Return the rows an import would add or update without mutating the registry."""
    validate_inventory(document)
    counts = {
        "projects": 0,
        "scans": 0,
        "agents": 0,
        "agent_snapshots": 0,
        "metadata": 0,
        "findings": 0,
        "component_snapshots": 0,
        "finding_lifecycle": 0,
        "tool_snapshots": 0,
    }
    for project in document["projects"]:
        project_id = project["project_id"]
        scan_id = _import_scan_id(document, project)
        if not _exists(conn, "SELECT 1 FROM projects WHERE project_id = ?", (project_id,)):
            counts["projects"] += 1
        new_scan = not _exists(conn, "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,))
        if new_scan:
            counts["scans"] += 1
        for agent in project.get("agents", []):
            agent_id = agent["agent_id"]
            existing_agent = conn.execute(
                "SELECT project_id FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if existing_agent and existing_agent["project_id"] != project_id:
                raise RegistryError(
                    f"Cannot import agent_id '{agent_id}': it belongs to project "
                    f"'{existing_agent['project_id']}', not '{project_id}'"
                )
            if not existing_agent:
                counts["agents"] += 1
            if not _exists(
                conn,
                "SELECT 1 FROM agent_snapshots WHERE agent_id = ? AND scan_id = ?",
                (agent_id, scan_id),
            ):
                counts["agent_snapshots"] += 1
            metadata = agent.get("metadata")
            if metadata:
                existing_metadata = conn.execute(
                    "SELECT owner, environment, purpose, lifecycle_status FROM agent_metadata "
                    "WHERE agent_id = ?",
                    (agent_id,),
                ).fetchone()
                if force or not existing_metadata or any(
                    existing_metadata[key] is None and metadata.get(key) is not None
                    for key in ("owner", "environment", "purpose", "lifecycle_status")
                ):
                    counts["metadata"] += 1
        for finding in project.get("latest_findings", []):
            fingerprint = finding.get("fingerprint") if isinstance(finding, dict) else None
            if fingerprint and not _exists(
                conn, "SELECT 1 FROM findings WHERE fingerprint = ?", (fingerprint,)
            ):
                counts["findings"] += 1
        if new_scan:
            counts["component_snapshots"] += len(_unique_components(project))
            importable_fingerprints = {
                finding.get("fingerprint")
                for finding in project.get("latest_findings", [])
                if isinstance(finding, dict) and finding.get("fingerprint")
            }
            importable_fingerprints.update(
                row["fingerprint"]
                for row in conn.execute("SELECT fingerprint FROM findings").fetchall()
            )
            counts["finding_lifecycle"] += sum(
                event["fingerprint"] in importable_fingerprints
                for event in _unique_lifecycle(project)
            )
            counts["tool_snapshots"] += len(_unique_tools(project))
    return counts


def _unique_components(project):
    unique = {}
    for component in project.get("component_snapshots", []):
        if not isinstance(component, dict):
            continue
        identity = (component.get("type"), component.get("path") or component.get("file"))
        if all(identity):
            unique.setdefault(identity, component)
    return list(unique.values())


def _unique_lifecycle(project):
    unique = {}
    for event in project.get("finding_lifecycle", []):
        if not isinstance(event, dict) or not event.get("fingerprint"):
            continue
        identity = (
            event.get("fingerprint"),
            event.get("event"),
            event.get("created_at"),
            event.get("source_scan_id") or event.get("scan_id"),
        )
        unique.setdefault(identity, event)
    return list(unique.values())


def _unique_tools(project):
    unique = {}
    for tool in project.get("tool_snapshots", []):
        if not isinstance(tool, dict) or not tool.get("tool_key"):
            continue
        identity = (tool.get("agent_id"), tool["tool_key"])
        unique.setdefault(identity, tool)
    return list(unique.values())


def import_inventory(conn, document, *, force=False):
    """Merge a validated inventory into ``conn`` as one atomic transaction."""
    validate_inventory(document)
    planned = plan_import(conn, document, force=force)
    now = utc_now_iso()
    try:
        with conn:
            for project in document["projects"]:
                _import_project(conn, document, project, now=now, force=force)
    except Exception as exc:
        if isinstance(exc, RegistryError):
            raise
        raise RegistryError(f"Failed to import inventory: {exc}") from exc
    return planned


def _import_project(conn, document, project, *, now, force):
    project_id = project["project_id"]
    scan_id = _import_scan_id(document, project)
    conn.execute(
        "INSERT OR IGNORE INTO projects(project_id, name, source_root, remote_fingerprint, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            project_id,
            project.get("name"),
            project.get("source_root"),
            None,
            now,
            now,
        ),
    )

    findings = [
        finding for finding in project.get("latest_findings", [])
        if isinstance(finding, dict) and finding.get("fingerprint")
    ]
    agents = project.get("agents", [])
    manifest = {
        "import": {
            "export_schema_version": document["schema_version"],
            "generated_at": document.get("generated_at"),
        },
        "project": {"project_id": project_id, "name": project.get("name")},
        "agents": agents,
        "findings": findings,
        "components": _unique_components(project),
        "tool_surface": _unique_tools(project),
    }
    manifest_json = json.dumps(manifest, sort_keys=True, default=str)
    manifest_hash = sha256_text(manifest_json)
    completed_at = document.get("generated_at") or now
    conn.execute(
        "INSERT OR IGNORE INTO scans(scan_id, project_id, started_at, completed_at, "
        "files_scanned, safeai_version, ruleset_version, config_hash, commit_sha, branch, tag, "
        "manifest_json, manifest_hash, policy_outcome, risk_score, agent_count, finding_count, "
        "severity_counts_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            scan_id,
            project_id,
            completed_at,
            completed_at,
            None,
            "portable-import",
            None,
            None,
            None,
            None,
            None,
            manifest_json,
            manifest_hash,
            "imported",
            None,
            len(agents),
            len(findings),
            "{}",
        ),
    )

    for agent in agents:
        _import_agent(conn, project_id, scan_id, agent, now=now, force=force)
    for finding in findings:
        _import_finding(conn, scan_id, finding)
    for component in _unique_components(project):
        _import_component(conn, scan_id, component)
    for tool in _unique_tools(project):
        _import_tool(conn, scan_id, tool)
    for event in _unique_lifecycle(project):
        _import_lifecycle(conn, scan_id, event, fallback_created_at=completed_at)


def _import_agent(conn, project_id, scan_id, agent, *, now, force):
    agent_id = agent["agent_id"]
    source_locations = agent.get("source_locations") or []
    primary_path = source_locations[0].get("path") if source_locations else None
    conn.execute(
        "INSERT OR IGNORE INTO agents(agent_id, project_id, name, agent_type, framework, "
        "primary_path, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            agent_id,
            project_id,
            agent.get("name"),
            agent.get("agent_type"),
            agent.get("framework"),
            primary_path,
            agent.get("first_seen") or now,
            agent.get("last_seen") or now,
        ),
    )
    snapshot = {
        "agent_id": agent_id,
        "name": agent.get("name"),
        "agent_type": agent.get("agent_type"),
        "framework": agent.get("framework"),
        "source_locations": source_locations,
        "capabilities": agent.get("capabilities") or [],
        "tools": agent.get("tools") or [],
        "confidence": agent.get("confidence"),
        "first_seen": agent.get("first_seen"),
        "last_seen": agent.get("last_seen"),
    }
    conn.execute(
        "INSERT OR IGNORE INTO agent_snapshots(agent_id, scan_id, snapshot_json, "
        "capability_count, finding_count, confidence) VALUES (?, ?, ?, ?, ?, ?)",
        (
            agent_id,
            scan_id,
            json.dumps(snapshot, sort_keys=True, default=str),
            len(snapshot["capabilities"]),
            len(agent.get("findings") or []),
            agent.get("confidence"),
        ),
    )
    metadata = agent.get("metadata")
    if not isinstance(metadata, dict):
        return
    existing = conn.execute(
        "SELECT owner, environment, purpose, lifecycle_status FROM agent_metadata "
        "WHERE agent_id = ?",
        (agent_id,),
    ).fetchone()
    if existing and not force:
        values = {
            key: existing[key] if existing[key] is not None else metadata.get(key)
            for key in ("owner", "environment", "purpose", "lifecycle_status")
        }
    else:
        values = {
            key: metadata.get(key)
            for key in ("owner", "environment", "purpose", "lifecycle_status")
        }
    conn.execute(
        "INSERT INTO agent_metadata(agent_id, owner, environment, purpose, lifecycle_status, "
        "updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(agent_id) DO UPDATE SET "
        "owner=excluded.owner, environment=excluded.environment, purpose=excluded.purpose, "
        "lifecycle_status=excluded.lifecycle_status, updated_at=excluded.updated_at",
        (
            agent_id,
            values["owner"],
            values["environment"],
            values["purpose"],
            values["lifecycle_status"] or "active",
            now,
        ),
    )


def _import_finding(conn, scan_id, finding):
    fingerprint = finding["fingerprint"]
    location = finding.get("location") or {}
    path = location.get("path") or finding.get("path")
    line = location.get("line_start") or finding.get("line")
    conn.execute(
        "INSERT OR IGNORE INTO findings(fingerprint, rule_id, severity, title, message, "
        "remediation, confidence, first_seen_scan, last_seen_scan, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            fingerprint,
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
    conn.execute(
        "INSERT OR IGNORE INTO scan_findings(scan_id, fingerprint, status, severity, rule_id, "
        "path, line, finding_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            scan_id,
            fingerprint,
            finding.get("status", "new"),
            finding.get("severity"),
            finding.get("rule_id"),
            path,
            line,
            json.dumps(finding, sort_keys=True, default=str),
        ),
    )


def _import_component(conn, scan_id, component):
    component_type = component.get("type")
    file_path = component.get("path") or component.get("file")
    conn.execute(
        "INSERT OR IGNORE INTO component_snapshots(scan_id, component_type, component_subtype, "
        "name, file_path, source, line, data_json, first_seen_scan, last_seen_scan, content_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            scan_id,
            component_type,
            component.get("subtype"),
            component.get("name"),
            file_path,
            component.get("source"),
            component.get("line"),
            json.dumps(component, sort_keys=True, default=str),
            scan_id,
            scan_id,
            component.get("content_hash"),
        ),
    )


def _import_tool(conn, scan_id, tool):
    details = tool.get("tool") or {}
    conn.execute(
        "INSERT OR IGNORE INTO agent_tool_snapshots(agent_id, scan_id, tool_key, tool_kind, "
        "tool_name, framework, capabilities_json, access_summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            tool.get("agent_id"),
            scan_id,
            tool["tool_key"],
            details.get("kind"),
            details.get("name"),
            details.get("framework"),
            json.dumps(tool.get("capabilities") or [], sort_keys=True, default=str),
            tool.get("access_summary"),
        ),
    )


def _import_lifecycle(conn, scan_id, event, *, fallback_created_at):
    fingerprint = event["fingerprint"]
    if not _exists(conn, "SELECT 1 FROM findings WHERE fingerprint = ?", (fingerprint,)):
        return
    lifecycle_event = event.get("event") or "introduced"
    created_at = event.get("created_at") or fallback_created_at
    if _exists(
        conn,
        "SELECT 1 FROM finding_lifecycle WHERE fingerprint = ? AND scan_id = ? "
        "AND event = ? AND created_at = ?",
        (fingerprint, scan_id, lifecycle_event, created_at),
    ):
        return
    conn.execute(
        "INSERT INTO finding_lifecycle(fingerprint, scan_id, event, previous_event, rule_id, "
        "severity, file_path, line, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            fingerprint,
            scan_id,
            lifecycle_event,
            event.get("previous_event"),
            event.get("rule_id"),
            event.get("severity"),
            event.get("file_path"),
            event.get("line"),
            event.get("message"),
            created_at,
        ),
    )
