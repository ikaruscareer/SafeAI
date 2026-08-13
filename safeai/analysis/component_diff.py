"""Component-change diff detection.

When a scan detects a changed MCP configuration, skill, prompt, tool
definition, or model config, all consuming agents should be flagged.
This module compares the current scan's components against a baseline
(registry or previous scan) and produces a ``component_diff`` section
in the report.
"""

import json
import logging

logger = logging.getLogger("safeai")


def compute_component_diff(current_components, previous_components, registry_conn=None):
    """Compare current and previous component lists.

    Args:
        current_components: List of component dicts from the current scan.
        previous_components: List of component dicts from the previous scan
            (or an empty list for first scans).
        registry_conn: Optional database connection for querying consuming
            agents via the component_snapshots table.

    Returns:
        A dict with ``changed``, ``added``, ``removed`` lists, and
        ``affected_agents`` mapping changed components to their consumers.
    """
    if not previous_components:
        return {
            "changed": [],
            "added": [_summarize(c) for c in current_components],
            "removed": [],
            "affected_agents": {},
        }

    prev_index = {_component_key(c): c for c in previous_components}
    curr_index = {_component_key(c): c for c in current_components}

    added = []
    removed = []
    changed = []

    for key, comp in curr_index.items():
        if key not in prev_index:
            added.append(_summarize(comp))
        else:
            prev = prev_index[key]
            if _has_changed(prev, comp):
                changed.append({
                    **_summarize(comp),
                    "previous": _summarize(prev),
                })

    for key, comp in prev_index.items():
        if key not in curr_index:
            removed.append(_summarize(comp))

    affected_agents = {}
    if registry_conn and (changed or added or removed):
        affected_agents = _find_affected_agents(
            registry_conn, changed, added, removed
        )

    return {
        "changed": changed,
        "added": added,
        "removed": removed,
        "affected_agents": affected_agents,
    }


def _component_key(comp):
    """Generate a stable key for a component."""
    comp_type = comp.get("type") or "unknown"
    comp_path = comp.get("path") or comp.get("file") or ""
    return (comp_type, comp_path)


def _summarize(comp):
    """Create a summary dict for a component."""
    return {
        "type": comp.get("type"),
        "name": comp.get("name"),
        "path": comp.get("path") or comp.get("file"),
        "subtype": comp.get("subtype"),
    }


def _has_changed(prev, curr):
    """Check if a component has changed between scans."""
    prev_name = prev.get("name") or ""
    curr_name = curr.get("name") or ""
    if prev_name != curr_name:
        return True

    prev_type = prev.get("type") or ""
    curr_type = curr.get("type") or ""
    if prev_type != curr_type:
        return True

    prev_data = json.dumps(prev.get("data") or {}, sort_keys=True, default=str)
    curr_data = json.dumps(curr.get("data") or {}, sort_keys=True, default=str)
    return prev_data != curr_data


def _find_affected_agents(registry_conn, changed, added, removed):
    """Find agents that consume changed/added/removed components."""
    affected = {}
    all_affected = changed + added + removed
    for comp in all_affected:
        comp_type = comp.get("type") or "unknown"
        comp_path = comp.get("path") or ""
        try:
            from safeai.kya.registry.queries import get_component_agents
            agents = get_component_agents(registry_conn, comp_type, comp_path)
            if agents:
                key = f"{comp_type}:{comp.get('name') or comp_path}"
                affected[key] = [
                    {
                        "agent_id": a.get("agent_id"),
                        "name": a.get("name"),
                        "framework": a.get("framework"),
                        "project_id": a.get("project_id"),
                    }
                    for a in agents
                ]
        except Exception as exc:
            logger.debug("Failed to query affected agents for %s: %s", comp_type, exc)
    return affected
