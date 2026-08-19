"""Unit tests for the tool <-> implementation mapping (CE 1.5).

These exercise the orphan-detection logic directly with minimal report
dicts so the matching/provenance behaviour is locked down independent of
the full scan pipeline.
"""

from safeai.analysis.tool_implementation import map_tool_implementations


def _report(tool_surface=None, components=None):
    return {"tool_surface": tool_surface or [], "components": components or []}


def test_matched_tool_produces_no_finding():
    surface = [{
        "tool_key": "tool:slack",
        "tool": {"kind": "tool", "name": "slack"},
        "capabilities": [
            {"name": "post", "evidence": [{"path": "impl/slack.py", "line": 12}]}
        ],
    }]
    components = [{
        "type": "skill",
        "name": "s1",
        "data": {"tools": ["slack"]},
        "path": "skills/s1.py",
        "line": 5,
    }]
    findings, summary = map_tool_implementations(_report(surface, components))

    assert findings == []
    assert summary["declared_tools"] == 1
    assert summary["implemented_tools"] == 1
    assert summary["orphaned_declared"] == 0
    assert summary["orphaned_implemented"] == 0
    assert len(summary["mappings"]) == 1
    assert summary["mappings"][0]["status"] == "matched"


def test_orphan_declared_carries_provenance():
    components = [{
        "type": "skill",
        "name": "s1",
        "data": {"tools": ["ghost"]},
        "path": "skills/s1.py",
        "line": 5,
    }]
    findings, summary = map_tool_implementations(_report([], components))

    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "TOOL_ORPHAN_DECLARED"
    assert finding["file"] == "skills/s1.py"
    assert finding["line"] == 5
    assert summary["orphaned_declared"] == 1
    assert summary["orphaned_implemented"] == 0


def test_orphan_implemented_carries_provenance():
    surface = [{
        "tool_key": "tool:bar",
        "tool": {"kind": "tool", "name": "bar"},
        "capabilities": [
            {"name": "x", "evidence": [{"path": "impl/bar.py", "line": 3}]}
        ],
    }]
    findings, summary = map_tool_implementations(_report(surface, []))

    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "TOOL_ORPHAN_IMPLEMENTED"
    assert finding["file"] == "impl/bar.py"
    assert finding["line"] == 3
    assert summary["orphaned_implemented"] == 1


def test_mcp_keys_are_skipped():
    surface = [{
        "tool_key": "mcp_server:x",
        "tool": {"kind": "mcp_server", "name": "x"},
        "capabilities": [],
    }]
    findings, summary = map_tool_implementations(_report(surface, []))

    assert findings == []
    assert summary["mcp_tools"] == 1


def test_output_is_deterministic():
    surface = [
        {
            "tool_key": "tool:slack",
            "tool": {"kind": "tool", "name": "slack"},
            "capabilities": [],
        },
        {
            "tool_key": "tool:bar",
            "tool": {"kind": "tool", "name": "bar"},
            "capabilities": [],
        },
    ]
    components = [{
        "type": "skill",
        "name": "s1",
        "data": {"tools": ["slack", "bar"]},
        "path": "skills/s1.py",
        "line": 1,
    }]
    _, first = map_tool_implementations(_report(surface, components))
    _, second = map_tool_implementations(_report(surface, components))

    assert first["mappings"] == second["mappings"]
    assert first == second
