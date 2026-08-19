"""Unit tests for the cross-component relationship graph (CE 1.8)."""

from safeai.analysis.component_graph import (
    analyze_component_health,
    build_component_graph,
)


def test_orphaned_ref_is_actionable_with_provenance():
    components = [{
        "type": "skill",
        "name": "s1",
        "data": {"tools": ["ghost"]},
        "path": "skills/s1.py",
        "line": 7,
    }]
    findings, graph = analyze_component_health(components)

    assert "tool:ghost" in graph["orphaned_refs"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "COMPONENT_ORPHANED_REF"
    assert finding["file"] == "skills/s1.py"
    assert finding["line"] == 7
    assert "s1" in finding["evidence"]


def test_no_orphan_when_target_exists():
    components = [
        {
            "type": "skill",
            "name": "s1",
            "data": {"tools": ["t1"]},
            "path": "a.py",
            "line": 1,
        },
        {"type": "tool", "name": "t1", "path": "c.py", "line": 1},
    ]
    findings, graph = analyze_component_health(components)

    assert graph["orphaned_refs"] == []
    assert findings == []


def test_edge_kinds_and_determinism():
    components = [
        {"type": "skill", "name": "s1", "data": {"tools": ["t1"]}, "path": "a.py", "line": 1},
        {"type": "workflow", "name": "w1", "data": {"steps": [{"tool": "t1"}]}, "path": "b.py", "line": 1},
        {"type": "tool", "name": "t1", "path": "c.py", "line": 1},
    ]
    g1 = build_component_graph(components)
    g2 = build_component_graph(components)

    edges1 = sorted((e["from"], e["to"], e["kind"]) for e in g1["edges"])
    edges2 = sorted((e["from"], e["to"], e["kind"]) for e in g2["edges"])
    assert edges1 == edges2

    kinds = {e["kind"] for e in g1["edges"]}
    assert "skill_uses_tool" in kinds
    assert "workflow_uses_tool" in kinds


def test_orphan_points_at_referencing_source():
    components = [
        {"type": "workflow", "name": "w1", "data": {"steps": [{"tool": "missing"}]}, "path": "wf.py", "line": 3},
        {"type": "skill", "name": "s1", "data": {"tools": ["missing"]}, "path": "sk.py", "line": 9},
    ]
    findings, graph = analyze_component_health(components)

    assert graph["orphaned_refs"] == ["tool:missing"]
    assert len(findings) == 1
    # Either referencing component is acceptable; the finding must point at a
    # real location, not an empty file/line.
    assert findings[0]["file"] in ("wf.py", "sk.py")
    assert findings[0]["line"] in (3, 9)
