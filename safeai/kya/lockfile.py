"""Lockfile-style component integrity (CE 2.3, WS5).

A lockfile pins the exact component set a team approved: type, name,
path, and content hash. ``--lockfile`` writes one from the registry;
``--check-lockfile`` fails a scan gate when components were added,
removed, or changed since the pin. Deterministic, offline, JSON.
"""

from safeai.kya.util import utc_now_iso
from safeai.version import SAFEAI_VERSION

LOCKFILE_SCHEMA_VERSION = 1


def _latest_components(conn, component_type=None):
    """Return one row per component with its latest-scan content hash.

    ``list_components_deduped`` groups rows but SQLite picks an
    indeterminate row's ``content_hash`` within a group, which would
    compare stale hashes after a change. Latest ``rowid`` is the newest
    write (persist uses INSERT OR REPLACE per scan).
    """
    conditions = [
        (
            "rowid = (SELECT MAX(rowid) FROM component_snapshots AS inner_cs "
            "WHERE inner_cs.component_type = outer_cs.component_type "
            "AND inner_cs.file_path = outer_cs.file_path)"
        )
    ]
    params = []
    if component_type:
        conditions.append("component_type = ?")
        params.append(component_type)
    rows = conn.execute(
        "SELECT component_type, name, file_path, source, content_hash "
        "FROM component_snapshots AS outer_cs "
        f"WHERE {' AND '.join(conditions)} "
        "ORDER BY component_type, name, file_path",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


def _pin_key(component):
    return (
        str(component.get("component_type") or component.get("type") or ""),
        str(component.get("file_path") or component.get("path") or ""),
    )


def build_lockfile(conn, component_type=None):
    """Return a pinned lockfile dict for the registry's components."""
    pins = []
    for comp in _latest_components(conn, component_type=component_type):
        pins.append({
            "type": comp.get("component_type"),
            "name": comp.get("name"),
            "path": comp.get("file_path"),
            "content_hash": comp.get("content_hash"),
        })
    pins.sort(key=lambda p: ((p["type"] or ""), (p["path"] or "")))
    return {
        "schema_version": LOCKFILE_SCHEMA_VERSION,
        "lockfile_type": "safeai.component-lockfile",
        "generated_at": utc_now_iso(),
        "safeai_version": SAFEAI_VERSION,
        "components": pins,
    }


def check_lockfile(conn, lockfile, component_type=None):
    """Compare the registry against a lockfile.

    Returns ``{"added": [...], "removed": [...], "changed": [...]}``
    where each entry is a pin dict. Empty lists mean the pin holds.
    Unknown lockfile shapes raise ``ValueError``.
    """
    if not isinstance(lockfile, dict) or not isinstance(lockfile.get("components"), list):
        raise TypeError("lockfile must be an object with a components list")
    current = {
        _pin_key(c): c for c in (
            {"type": c.get("component_type"), "name": c.get("name"),
             "path": c.get("file_path"), "content_hash": c.get("content_hash")}
            for c in _latest_components(conn, component_type=component_type)
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
