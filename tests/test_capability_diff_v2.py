"""Tool-centric capability diff (schema v2) and v1 backward compatibility."""

import json
import pathlib
import sqlite3

from safeai.analysis.capability_diff import (
    compute_capability_diff,
    compute_legacy_capability_diff,
)
from safeai.engine.scan import run_scan
from safeai.kya import REGISTRY_SCHEMA_VERSION
from safeai.kya.registry import connect, migrate


def _write_project(root, server_tools):
    root.mkdir(parents=True, exist_ok=True)
    (root / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"github": {"command": "npx", "tools": server_tools}}}, indent=2)
    )
    (root / "agent.py").write_text(
        "from langchain.agents import initialize_agent\n"
        "agent = initialize_agent(tools=[], llm=None)\n"
    )
    return root


READ_ONLY = ["get_issue", "list_repos", "read_file"]
MUTATING = ["get_issue", "list_repos", "read_file", "delete_repo", "merge_pull_request"]


def _before_after(tmp_path):
    before = run_scan(str(_write_project(tmp_path / "before", READ_ONLY)))
    after = run_scan(str(_write_project(tmp_path / "after", MUTATING)))
    return before, after


def test_read_only_to_mutating_mcp_server_is_caught_only_by_v2(tmp_path):
    """The headline v1.4 case: v1 sees nothing, v2 names the server."""
    before, after = _before_after(tmp_path)

    legacy = compute_legacy_capability_diff(after, before)
    assert legacy["counts"] == {"added": 0, "removed": 0, "changed": 0}

    diff = compute_capability_diff(after, before)
    escalated = [t for t in diff["tools"] if t["status"] == "escalated"]
    assert [t["tool_key"] for t in escalated] == ["mcp_server:github"]
    rule_ids = {e["id"] for e in escalated[0]["escalations"]}
    assert "ESC_MCP_READ_TO_MUTATE" in rule_ids
    assert diff["highest_escalation"] == "critical"


def test_diff_is_deterministic_across_runs(tmp_path):
    before, after = _before_after(tmp_path)
    first = json.dumps(compute_capability_diff(after, before), sort_keys=True)
    second = json.dumps(compute_capability_diff(after, before), sort_keys=True)
    assert first == second


def test_v2_diff_preserves_v1_top_level_shape(tmp_path):
    before, after = _before_after(tmp_path)
    diff = compute_capability_diff(after, before)
    legacy = compute_legacy_capability_diff(after, before)

    assert diff["schema_version"] == 2
    for field in ("added", "removed", "changed"):
        assert diff[field] == legacy[field]
        assert diff["counts"][field] == legacy["counts"][field]
    assert diff["legacy"]["counts"] == legacy["counts"]


def test_unchanged_tool_reports_no_escalation(tmp_path):
    before = run_scan(str(_write_project(tmp_path / "a", READ_ONLY)))
    after = run_scan(str(_write_project(tmp_path / "b", READ_ONLY)))
    diff = compute_capability_diff(after, before)
    assert all(t["status"] == "unchanged" for t in diff["tools"])
    assert diff["highest_escalation"] is None


def test_removed_tool_is_reported_not_dropped(tmp_path):
    before = run_scan(str(_write_project(tmp_path / "before", READ_ONLY)))
    after_dir = tmp_path / "after"
    after_dir.mkdir()
    (after_dir / "agent.py").write_text(
        "from langchain.agents import initialize_agent\n"
        "agent = initialize_agent(tools=[], llm=None)\n"
    )
    diff = compute_capability_diff(run_scan(str(after_dir)), before)
    removed = [t for t in diff["tools"] if t["status"] == "removed"]
    assert "mcp_server:github" in {t["tool_key"] for t in removed}


def test_pre_14_baseline_disables_tool_attribution(tmp_path):
    """A v1.3 baseline has no tool surface; say so, do not invent one."""
    after = run_scan(str(_write_project(tmp_path / "after", MUTATING)))
    legacy_baseline = {"normalized_capabilities": []}
    diff = compute_capability_diff(after, legacy_baseline)

    assert diff["baseline_tool_attribution"] is False
    assert all(t["status"] == "unknown" for t in diff["tools"])
    for tool in diff["tools"]:
        assert tool["capabilities_added"] == []


def test_v13_registry_migrates_and_retains_rows(tmp_path):
    """Opening a v1.3 registry upgrades it in place without losing data."""
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    schema = pathlib.Path("safeai/kya/registry.py")
    assert schema.exists()

    # Build a v1 registry using the shipped v1 baseline schema, then stamp it.
    from safeai.kya.registry import _MIGRATIONS

    conn.executescript(_MIGRATIONS[1])
    conn.execute(
        "INSERT INTO projects(project_id, name, source_root, created_at, updated_at) "
        "VALUES (?,?,?,?,?)",
        ("p1", "legacy", "/tmp/x", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
    )
    conn.execute(
        "INSERT OR REPLACE INTO schema_migrations(version, applied_at) VALUES (1, ?)",
        ("2024-01-01T00:00:00Z",),
    )
    conn.commit()
    conn.close()

    conn = connect(str(db_path))
    try:
        assert migrate(conn) == REGISTRY_SCHEMA_VERSION
        rows = conn.execute("SELECT project_id FROM projects").fetchall()
        assert [r["project_id"] for r in rows] == ["p1"]
        # New table exists and is queryable.
        assert conn.execute("SELECT COUNT(*) c FROM agent_tool_snapshots").fetchone()["c"] == 0
        versions = [
            r["version"] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")
        ]
        assert versions == [1, 2]
    finally:
        conn.close()
