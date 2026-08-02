"""Tool identity: stable, path-independent keys for named tools."""

import json

from safeai.analysis.tool_identity import (
    UNATTRIBUTED,
    UNATTRIBUTED_KEY,
    display_name,
    identity_summary,
    make_tool_identity,
    tool_key,
    unknown_identity,
)
from safeai.analysis.tool_surface import build_tool_surface, surface_index


def test_tool_key_is_stable_across_file_moves():
    """Renaming or moving the defining file must not change the tool key."""
    before = make_tool_identity("mcp_server", "github", "mcp", source_path="a/.mcp.json")
    after = make_tool_identity("mcp_server", "github", "mcp", source_path="deeply/nested/b/.mcp.json")
    assert tool_key(before) == tool_key(after) == "mcp_server:github"


def test_tool_key_distinguishes_kind_and_server():
    agent = make_tool_identity("agent", "planner", "langchain")
    tool = make_tool_identity("tool", "planner", "langchain")
    assert tool_key(agent) != tool_key(tool)

    scoped = make_tool_identity("tool", "search", "mcp", server="brave")
    unscoped = make_tool_identity("tool", "search", "mcp")
    assert tool_key(scoped) != tool_key(unscoped)


def test_unnamed_tool_falls_back_to_path_hash_deterministically():
    first = unknown_identity("some evidence", framework="crewai", source_path="src/app.py")
    second = unknown_identity("some evidence", framework="crewai", source_path="src/app.py")
    assert tool_key(first) == tool_key(second)
    assert tool_key(first).startswith("unknown:")


def test_unattributed_sentinel_is_well_formed():
    assert UNATTRIBUTED_KEY == tool_key(UNATTRIBUTED)
    assert display_name(UNATTRIBUTED)
    assert identity_summary(UNATTRIBUTED)["kind"] == "unknown"


def _report_with_server(tools, path=".mcp.json"):
    return {
        "agent_models": [],
        "mcp_assets": [
            {
                "path": path,
                "servers": [{"name": "github", "command": "npx", "tools": tools}],
            }
        ],
    }


def test_tool_surface_groups_capabilities_under_named_server():
    surface = build_tool_surface(_report_with_server(["get_issue", "list_repos"]))
    index = surface_index(surface)
    assert "mcp_server:github" in index
    entry = index["mcp_server:github"]
    assert entry["tool"]["name"] == "github"
    assert entry["capabilities"], "named server should own at least one capability"


def test_tool_surface_is_path_independent_and_deterministic():
    a = build_tool_surface(_report_with_server(["get_issue"], path=".mcp.json"))
    b = build_tool_surface(_report_with_server(["get_issue"], path="config/sub/.mcp.json"))
    keys_a = [t["tool_key"] for t in a]
    keys_b = [t["tool_key"] for t in b]
    assert keys_a == keys_b

    # Byte-identical serialization on repeated builds of the same input.
    again = build_tool_surface(_report_with_server(["get_issue"], path=".mcp.json"))
    assert json.dumps(a, sort_keys=True) == json.dumps(again, sort_keys=True)


def test_tool_surface_evidence_carries_no_raw_source():
    surface = build_tool_surface(_report_with_server(["get_issue"]))
    for entry in surface:
        for capability in entry["capabilities"]:
            for evidence in capability["evidence"]:
                assert set(evidence) <= {"path", "line"}
