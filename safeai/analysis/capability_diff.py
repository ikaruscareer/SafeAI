"""Tool-centric comparison of capability inventories between scan reports.

v1.3 keyed capabilities on ``(name, category)``. A repository whose
``invoice-lookup`` MCP server flipped from read-only to mutating showed
**no diff at all**, because the capability ``mcp`` was present before and
after. That is precisely the change a reviewer needs to see.

v1.4 keys on the triple ``(tool_key, capability_name, access_mode)`` and
reports per tool: what it gained, what it lost, how its access modes
moved, and which escalation rules fired.

Backward compatibility: the returned document still carries the v1 flat
``added``/``removed``/``changed``/``counts`` fields (also mirrored under
``legacy``) so v1.3 consumers, reports and tests keep working.
"""

from safeai.analysis.capabilities import access_mode_rank
from safeai.analysis.escalation import (
    classify_escalations,
    highest_severity,
)
from safeai.analysis.tool_identity import UNATTRIBUTED_KEY
from safeai.analysis.tool_surface import build_tool_surface, surface_index

CAPABILITY_DIFF_SCHEMA_VERSION = 2

_SEVERITIES = ("critical", "high", "medium", "low")


def _key(capability):
    return (
        str(capability.get("name", "capability")).lower(),
        str(capability.get("category", "Capability")).lower(),
    )


def compute_legacy_capability_diff(current_report, baseline_report):
    """The exact v1.3 flat diff, preserved for existing consumers.

    A baseline that carries no capability inventory (e.g. a KYA manifest,
    which stores the tool surface instead) yields an explicitly
    unavailable legacy block rather than a diff in which every existing
    capability looks new.
    """
    if "normalized_capabilities" not in (baseline_report or {}):
        return {
            "baseline_available": False,
            "reason": "baseline document carries no capability inventory",
            "added": [],
            "removed": [],
            "changed": [],
            "counts": {"added": 0, "removed": 0, "changed": 0},
        }
    current = {_key(cap): cap for cap in current_report.get("normalized_capabilities", [])}
    baseline = {_key(cap): cap for cap in baseline_report.get("normalized_capabilities", [])}

    added = [current[key] for key in sorted(current.keys() - baseline.keys())]
    removed = [baseline[key] for key in sorted(baseline.keys() - current.keys())]
    changed = []
    for key in sorted(current.keys() & baseline.keys()):
        before = baseline[key]
        after = current[key]
        fields = {}
        for field in ("confidence", "risk_weight", "source_frameworks", "sources", "evidence"):
            if before.get(field) != after.get(field):
                fields[field] = {"before": before.get(field), "after": after.get(field)}
        if fields:
            changed.append({"key": {"name": after.get("name"), "category": after.get("category")}, "changes": fields})

    return {
        "baseline_available": True,
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
    }


def _resolve_surface(report):
    """Return ``(surface, attributed)`` for a report.

    A pre-1.4 baseline has no ``tool_surface``; we say so rather than
    fabricating attribution from capability names.
    """
    surface = report.get("tool_surface")
    if isinstance(surface, list):
        return surface, True
    return [], False


def _capability_view(capability):
    return {
        "name": capability.get("name"),
        "category": capability.get("category"),
        "access_mode": capability.get("access_mode"),
        "evidence": capability.get("evidence") or [],
        "confidence": capability.get("confidence"),
        "inferred": bool(capability.get("inferred")),
    }


def _status_for(before_state, after_state):
    """Structural status of a tool, independent of the escalation ruleset."""
    if before_state is None:
        return "new"
    if after_state is None:
        return "removed"
    before_caps = {c["name"]: c for c in before_state.get("capabilities") or []}
    after_caps = {c["name"]: c for c in after_state.get("capabilities") or []}
    gained = set(after_caps) - set(before_caps)
    lost = set(before_caps) - set(after_caps)
    raised = any(
        access_mode_rank(after_caps[n].get("access_mode")) > access_mode_rank(before_caps[n].get("access_mode"))
        for n in set(after_caps) & set(before_caps)
    )
    lowered = any(
        access_mode_rank(after_caps[n].get("access_mode")) < access_mode_rank(before_caps[n].get("access_mode"))
        for n in set(after_caps) & set(before_caps)
    )
    if gained or raised:
        return "escalated"
    if lost or lowered:
        return "reduced"
    return "unchanged"


def _tool_entry(tool_key_value, before_state, after_state, evaluate_combinations):
    status = _status_for(before_state, after_state)
    before_caps = {c["name"]: c for c in (before_state or {}).get("capabilities") or []}
    after_caps = {c["name"]: c for c in (after_state or {}).get("capabilities") or []}

    added = [_capability_view(after_caps[n]) for n in sorted(set(after_caps) - set(before_caps))]
    removed = [_capability_view(before_caps[n]) for n in sorted(set(before_caps) - set(after_caps))]
    access_mode_changes = []
    for name in sorted(set(after_caps) & set(before_caps)):
        before, after = before_caps[name], after_caps[name]
        if before.get("access_mode") != after.get("access_mode"):
            access_mode_changes.append({
                "capability": name,
                "before": before.get("access_mode"),
                "after": after.get("access_mode"),
                "inferred": bool(before.get("inferred") or after.get("inferred")),
            })

    escalations = classify_escalations(
        before_state, after_state, status, evaluate_combinations=evaluate_combinations
    )
    reference = after_state or before_state or {}
    return {
        "tool_key": tool_key_value,
        "tool": reference.get("tool") or {"kind": "unknown", "name": None, "framework": None},
        "status": status,
        "access_summary": {
            "before": (before_state or {}).get("access_summary"),
            "after": (after_state or {}).get("access_summary"),
        },
        "capabilities_added": added,
        "capabilities_removed": removed,
        "access_mode_changes": access_mode_changes,
        "escalations": escalations,
    }


def compute_capability_diff(current_report, baseline_report):
    """Compare two reports, tool by tool.

    The comparison is deterministic and uses only serialized report data:
    no file access, no execution, no network.
    """
    legacy = compute_legacy_capability_diff(current_report, baseline_report)

    current_surface, current_attributed = _resolve_surface(current_report)
    baseline_surface, baseline_attributed = _resolve_surface(baseline_report)

    if not current_attributed:
        current_surface = build_tool_surface(current_report)
        current_attributed = True

    current_index = surface_index(current_surface)
    baseline_index = surface_index(baseline_surface)

    # Without baseline attribution every tool would look "new". Say so and
    # fall back to the capability-level view instead of misleading the
    # reviewer with a fabricated tool diff.
    tool_keys = sorted(set(current_index) | set(baseline_index))

    tools = []
    unattributed = None
    counts = {
        "tools_new": 0,
        "tools_escalated": 0,
        "tools_reduced": 0,
        "tools_removed": 0,
        "tools_unchanged": 0,
        "escalations_by_severity": {sev: 0 for sev in _SEVERITIES},
    }
    all_escalations = []

    for key in tool_keys:
        before_state = baseline_index.get(key) if baseline_attributed else None
        after_state = current_index.get(key)
        if before_state is None and after_state is None:
            continue
        evaluate_combinations = True
        entry = _tool_entry(key, before_state, after_state, evaluate_combinations)

        if not baseline_attributed:
            # Structural status is unknowable; report the surface without
            # asserting that the tool is new.
            entry["status"] = "unknown"
            entry["capabilities_added"] = []
            entry["escalations"] = [
                e for e in entry["escalations"]
                if e["id"].startswith("ESC_COMBO_")
            ]

        if entry["status"] != "unchanged" or entry["escalations"]:
            all_escalations.extend(entry["escalations"])
            for escalation in entry["escalations"]:
                severity = escalation["severity"]
                counts["escalations_by_severity"][severity] = (
                    counts["escalations_by_severity"].get(severity, 0) + 1
                )

        status_counter = {
            "new": "tools_new",
            "escalated": "tools_escalated",
            "reduced": "tools_reduced",
            "removed": "tools_removed",
            "unchanged": "tools_unchanged",
        }.get(entry["status"])
        if status_counter:
            counts[status_counter] += 1

        if key == UNATTRIBUTED_KEY:
            unattributed = entry
        else:
            tools.append(entry)

    tools.sort(key=lambda t: t["tool_key"])

    result = {
        "schema_version": CAPABILITY_DIFF_SCHEMA_VERSION,
        "baseline_available": True,
        "baseline_tool_attribution": bool(baseline_attributed),
        "tools": tools,
        "unattributed": unattributed,
        "counts": {**counts, **legacy["counts"]},
        "highest_escalation": highest_severity(all_escalations),
        "legacy": legacy,
        # v1 fields kept at the top level for backward compatibility.
        "added": legacy["added"],
        "removed": legacy["removed"],
        "changed": legacy["changed"],
    }
    return result
