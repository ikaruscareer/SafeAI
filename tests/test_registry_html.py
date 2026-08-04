"""Tests for the self-contained registry HTML renderers."""

from safeai.report import registry_html


def _agent():
    return {
        "agent_id": "agent-abc",
        "name": "researcher",
        "agent_type": "agent",
        "framework": "crewai",
        "project_id": "proj-1",
        "first_seen": "2026-08-01T10:00:00Z",
        "last_seen": "2026-08-02T10:00:00Z",
        "risk_score": 42,
        "policy_outcome": "warn",
        "snapshot": {
            "confidence": 0.9,
            "capabilities": [{"name": "filesystem", "access_mode": "write",
                              "access_mode_inferred": True}],
            "tools": ["send_email"],
            "source_locations": [{"path": "agent.py", "line_start": 3}],
        },
        "scan": {
            "scan_id": "scan-1",
            "completed_at": "2026-08-02T10:00:00Z",
            "commit_sha": "abc1234",
            "policy_outcome": "warn",
            "risk_score": 42,
        },
        "findings": [{
            "fingerprint": "fp-1",
            "rule_id": "CAP_shell",
            "severity": "high",
            "status": "new",
            "path": "agent.py",
            "line": 10,
        }],
    }


def test_render_agents_list():
    html = registry_html.render_agents_list([_agent()], registry_path="x.db")
    assert "Registry Inventory" in html
    assert "researcher" in html
    assert "crewai" in html
    assert "proj-1" in html
    assert "data-theme=" in html
    assert "x.db" in html


def test_render_agent_show():
    html = registry_html.render_agent_show(_agent(), registry_path="x.db")
    assert "researcher" in html
    assert "agent-abc" in html
    assert "filesystem" in html
    assert "write" in html
    assert "CAP_shell" in html
    assert "send_email" in html


def test_render_history():
    history = [{
        "scan_id": "scan-2",
        "completed_at": "2026-08-02T10:00:00Z",
        "commit_sha": "abc1234",
        "policy_outcome": "warn",
        "risk_score": 42,
        "capability_count": 3,
        "severity_counts": {"critical": 1, "high": 2},
    }]
    html = registry_html.render_history("agent-abc", history, registry_path="x.db")
    assert "Agent History" in html
    assert "scan-2" in html
    assert "3" in html


def test_render_diff():
    diff = {
        "agent_id": "agent-abc",
        "from_scan": "scan-1",
        "to_scan": "scan-2",
        "capabilities": {"added": ["shell"], "removed": []},
        "tools": {"added": [], "removed": []},
        "findings": {
            "new": [{"severity": "high", "rule_id": "CAP_shell", "fingerprint": "fp-1"}],
            "resolved": [],
            "regressed": [],
        },
        "tool_diff": {
            "highest_escalation": "high",
            "baseline_tool_attribution": True,
            "tools": [{
                "tool_key": "tool:run",
                "status": "escalated",
                "access_summary": {"before": "read", "after": "write"},
                "escalations": [{"id": "ESC_WRITE_TOOL_ADDED", "severity": "high",
                                 "summary": "write added"}],
            }],
        },
    }
    html = registry_html.render_diff("agent-abc", diff, registry_path="x.db")
    assert "Agent Diff" in html
    assert "ESC_WRITE_TOOL_ADDED" in html
    assert "high" in html
    assert "shell" in html


def test_render_inventory():
    document = {
        "schema_version": "1.0",
        "generated_at": "2026-08-02T10:00:00Z",
        "projects": [{
            "project_id": "proj-1",
            "name": "example",
            "source_root": ".",
            "latest_scan_id": "scan-1",
            "latest_findings": [{"severity": "high"}],
            "agents": [_agent()],
        }],
    }
    html = registry_html.render_inventory(document, registry_path="x.db")
    assert "Inventory Export" in html
    assert "example" in html
    assert "researcher" in html


def test_renderers_escape_user_data():
    agent = _agent()
    agent["name"] = "<script>alert(1)</script>"
    html = registry_html.render_agent_show(agent)
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html
