"""Lockfile-style component integrity (CE 2.3, WS5).

A lockfile pins the exact component set a team approved: type, name,
path, and content hash. ``--lockfile`` writes one from the registry;
``--check-lockfile`` fails a scan gate when components were added,
removed, or changed since the pin. Deterministic, offline, JSON.
"""

from safeai.kya.util import utc_now_iso
from safeai.version import SAFEAI_VERSION

LOCKFILE_SCHEMA_VERSION = 1


def _latest_components(conn, component_type=None, project_id=None):
    """Return one row per component with its latest-scan content hash.

    ``list_components_deduped`` groups rows but SQLite picks an
    indeterminate row's ``content_hash`` within a group, which would
    compare stale hashes after a change. Latest ``rowid`` is the newest
    write (persist uses INSERT OR REPLACE per scan).

    ``project_id`` scopes the query to one project: shared registries
    accumulate many projects, and identical relative paths across
    projects would otherwise merge into ambiguous pins.
    """
    conditions = [
        (
            "outer_cs.rowid = (SELECT MAX(inner_cs.rowid) "
            "FROM component_snapshots AS inner_cs "
            "JOIN scans AS inner_s ON inner_s.scan_id = inner_cs.scan_id "
            "WHERE inner_cs.component_type = outer_cs.component_type "
            "AND inner_cs.file_path = outer_cs.file_path"
            + (" AND inner_s.project_id = ?" if project_id else "")
            + ")"
        )
    ]
    params = []
    if project_id:
        params.append(project_id)
    if component_type:
        conditions.append("outer_cs.component_type = ?")
        params.append(component_type)
    if project_id:
        conditions.append(
            "EXISTS (SELECT 1 FROM scans AS outer_s "
            "WHERE outer_s.scan_id = outer_cs.scan_id "
            "AND outer_s.project_id = ?)"
        )
        params.append(project_id)
    rows = conn.execute(
        "SELECT outer_cs.component_type, outer_cs.name, outer_cs.file_path, "
        "outer_cs.source, outer_cs.content_hash "
        "FROM component_snapshots AS outer_cs "
        f"WHERE {' AND '.join(conditions)} "
        "ORDER BY outer_cs.component_type, outer_cs.name, outer_cs.file_path",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


def _pin_key(component):
    return (
        str(component.get("component_type") or component.get("type") or ""),
        str(component.get("file_path") or component.get("path") or ""),
    )


def build_lockfile(conn, component_type=None, project_id=None):
    """Return a pinned lockfile dict for the registry's components."""
    pins = []
    for comp in _latest_components(conn, component_type=component_type, project_id=project_id):
        pins.append({
            "type": comp.get("component_type"),
            "name": comp.get("name"),
            "path": comp.get("file_path"),
            "content_hash": comp.get("content_hash"),
        })
    pins.sort(key=lambda p: ((p["type"] or ""), (p["path"] or "")))
    lockfile = {
        "schema_version": LOCKFILE_SCHEMA_VERSION,
        "lockfile_type": "safeai.component-lockfile",
        "generated_at": utc_now_iso(),
        "safeai_version": SAFEAI_VERSION,
        "components": pins,
    }
    if project_id:
        lockfile["project_id"] = project_id
    return lockfile


def check_lockfile(conn, lockfile, component_type=None, project_id=None):
    """Compare the registry against a lockfile.

    Returns ``{"added": [...], "removed": [...], "changed": [...]}``
    where each entry is a pin dict. Empty lists mean the pin holds.
    Unknown lockfile shapes raise ``TypeError``. When the lockfile
    carries ``project_id`` and no explicit ``project_id`` is passed,
    the check scopes itself to that project.
    """
    if not isinstance(lockfile, dict) or not isinstance(lockfile.get("components"), list):
        raise TypeError("lockfile must be an object with a components list")
    if project_id is None:
        project_id = lockfile.get("project_id")
    current = {
        _pin_key(c): c for c in (
            {"type": c.get("component_type"), "name": c.get("name"),
             "path": c.get("file_path"), "content_hash": c.get("content_hash")}
            for c in _latest_components(conn, component_type=component_type, project_id=project_id)
        )
    }
    pinned = {}
    for entry in lockfile["components"]:
        if not isinstance(entry, dict):
            continue
        key = (str(entry.get("type") or ""), str(entry.get("path") or ""))
        pinned.setdefault(key, {
            "type": entry.get("type"), "name": entry.get("name"),
            "path": entry.get("path"), "content_hash": entry.get("content_hash"),
        })
    added = [current[k] for k in sorted(set(current) - set(pinned))]
    removed = [pinned[k] for k in sorted(set(pinned) - set(current))]
    changed = [
        {"expected": pinned[k], "actual": current[k]}
        for k in sorted(set(current) & set(pinned))
        if (current[k].get("content_hash") or "") != (pinned[k].get("content_hash") or "")
    ]
    return {"added": added, "removed": removed, "changed": changed}
