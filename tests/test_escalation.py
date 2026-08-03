"""Escalation rules: one positive and one negative fixture per rule.

Every rule in ``ESCALATION_RULES`` must be exercised in both directions,
so a rule can neither silently stop firing nor start firing on a
non-escalating change.
"""

import pytest

from safeai.analysis.escalation import (
    COMBINATION_RULE_IDS,
    ESCALATION_RULES,
    classify_escalations,
    highest_severity,
)


def cap(name, access_mode="read", category=None, confidence=0.9, inferred=False):
    return {
        "name": name,
        "category": category or name.title(),
        "access_mode": access_mode,
        "confidence": confidence,
        "inferred": inferred,
        "evidence": [{"path": "a.py", "line": 1}],
    }


def state(capabilities, kind="tool", name="deploy", framework="langchain"):
    return {
        "tool": {"kind": kind, "name": name, "framework": framework},
        "capabilities": list(capabilities),
    }


def fired(before, after, status="escalated", combos=True):
    return {
        e["id"] for e in classify_escalations(before, after, status, evaluate_combinations=combos)
    }


# --- Per-rule fixtures ---------------------------------------------------
#
# Each entry: rule id -> (before, after, status) for a POSITIVE case and a
# NEGATIVE case that is deliberately close to the positive one.

BASE_CASES = {
    "ESC_ACCESS_MODE_INCREASED": (
        (state([cap("databases", "read")]), state([cap("databases", "write")]), "escalated"),
        (state([cap("databases", "read")]), state([cap("databases", "read")]), "unchanged"),
    ),
    "ESC_SHELL_ADDED": (
        (state([cap("network")]), state([cap("network"), cap("shell", "execute")]), "escalated"),
        (state([cap("network")]), state([cap("network"), cap("logging")]), "escalated"),
    ),
    "ESC_FILESYSTEM_WRITE_ADDED": (
        (state([cap("filesystem", "read")]), state([cap("filesystem", "write")]), "escalated"),
        (state([cap("filesystem", "read")]), state([cap("filesystem", "read")]), "unchanged"),
    ),
    "ESC_EXTERNAL_ACCESS_ADDED": (
        (state([cap("logging")]), state([cap("logging"), cap("network")]), "escalated"),
        (state([cap("logging"), cap("network")]), state([cap("logging"), cap("network")]), "unchanged"),
    ),
    "ESC_MCP_SERVER_ADDED": (
        (None, state([cap("mcp")], kind="mcp_server", name="github"), "new"),
        (None, state([cap("logging")], kind="tool", name="logger"), "new"),
    ),
    "ESC_MCP_READ_TO_MUTATE": (
        (
            state([cap("mcp", "read")], kind="mcp_server", name="github"),
            state([cap("mcp", "mutate")], kind="mcp_server", name="github"),
            "escalated",
        ),
        (
            state([cap("mcp", "read")], kind="mcp_server", name="github"),
            state([cap("mcp", "read")], kind="mcp_server", name="github"),
            "unchanged",
        ),
    ),
    "ESC_APPROVAL_GATE_REMOVED": (
        (state([cap("human_approval"), cap("network")]), state([cap("network")]), "escalated"),
        (state([cap("human_approval"), cap("network")]), state([cap("human_approval")]), "reduced"),
    ),
    "ESC_MEMORY_SCOPE_EXPANDED": (
        (state([cap("memory", "read")]), state([cap("memory", "write")]), "escalated"),
        (state([cap("memory", "write")]), state([cap("memory", "read")]), "reduced"),
    ),
    "ESC_WRITE_TOOL_ADDED": (
        (None, state([cap("databases", "write")], name="writer"), "new"),
        (None, state([cap("databases", "read")], name="reader"), "new"),
    ),
    "ESC_NEW_EXTERNAL_DESTINATION": (
        (state([cap("logging")]), state([cap("logging"), cap("email", "write")]), "escalated"),
        (state([cap("logging")]), state([cap("logging"), cap("email", "read")]), "escalated"),
    ),
    "ESC_AUTONOMY_INCREASED": (
        (
            state([cap("databases", "write")]),
            state([cap("databases", "write"), cap("planner")]),
            "escalated",
        ),
        (
            state([cap("databases", "read")]),
            state([cap("databases", "read"), cap("planner")]),
            "escalated",
        ),
    ),
}

COMBO_CASES = {
    "ESC_COMBO_UNTRUSTED_INPUT_SHELL": (
        (
            state([cap("shell", "execute")]),
            state([cap("shell", "execute"), cap("untrusted_input")]),
            "escalated",
        ),
        (
            state([cap("shell", "execute")]),
            state([cap("shell", "execute"), cap("logging")]),
            "escalated",
        ),
    ),
    "ESC_COMBO_AUTONOMY_BROAD_DATA": (
        (
            state([cap("databases", "read")]),
            state([cap("databases", "read"), cap("planner")]),
            "escalated",
        ),
        (
            state([cap("logging")]),
            state([cap("logging"), cap("planner")]),
            "escalated",
        ),
    ),
    "ESC_COMBO_DELEGATION_EXTERNAL_SIDE_EFFECT": (
        (
            state([cap("email", "write")]),
            state([cap("email", "write"), cap("delegation")]),
            "escalated",
        ),
        (
            state([cap("email", "read")]),
            state([cap("email", "read"), cap("delegation")]),
            "escalated",
        ),
    ),
}

ALL_CASES = {**BASE_CASES, **COMBO_CASES}


def test_every_rule_has_fixtures():
    """No rule may ship without both a positive and a negative fixture."""
    assert {rule["id"] for rule in ESCALATION_RULES} == set(ALL_CASES)


@pytest.mark.parametrize("rule_id", sorted(ALL_CASES))
def test_rule_fires_on_positive_fixture(rule_id):
    before, after, status = ALL_CASES[rule_id][0]
    assert rule_id in fired(before, after, status)


@pytest.mark.parametrize("rule_id", sorted(ALL_CASES))
def test_rule_silent_on_negative_fixture(rule_id):
    before, after, status = ALL_CASES[rule_id][1]
    assert rule_id not in fired(before, after, status)


def test_combination_rules_can_be_disabled():
    before, after, status = COMBO_CASES["ESC_COMBO_UNTRUSTED_INPUT_SHELL"][0]
    assert not (fired(before, after, status, combos=False) & set(COMBINATION_RULE_IDS))


def test_inferred_access_mode_caps_severity_at_medium():
    """Inference must never be reported at critical/high confidence."""
    before = state([cap("filesystem", "read", inferred=True)])
    after = state([cap("filesystem", "write", inferred=True)])
    escalations = classify_escalations(before, after, "escalated")
    fs = [e for e in escalations if e["id"] == "ESC_FILESYSTEM_WRITE_ADDED"]
    assert fs and fs[0]["severity"] == "medium"
    assert fs[0]["inferred"] is True


@pytest.mark.parametrize(
    "capability",
    [
        "shell",
        "databases",
        "github",
        "slack",
        "cloud",
        "external_apis",
        "email",
        "tool_grant",
        "mcp",
        "filesystem",
        "memory",
    ],
)
def test_access_mode_escalation_covers_all_capability_names(capability):
    before = state([cap(capability, "read")])
    after = state([cap(capability, "write")])
    ids = fired(before, after, "escalated")
    assert "ESC_ACCESS_MODE_INCREASED" in ids


def test_removed_tool_raises_no_escalation():
    before = state([cap("shell", "execute")])
    assert classify_escalations(before, None, "removed") == []


def test_highest_severity_picks_most_severe():
    escalations = [{"severity": "medium"}, {"severity": "critical"}, {"severity": "low"}]
    assert highest_severity(escalations) == "critical"
    assert highest_severity([]) is None


def test_escalations_are_deterministically_ordered():
    before = state([cap("filesystem", "read")])
    after = state([cap("filesystem", "write"), cap("shell", "execute"), cap("network")])
    first = classify_escalations(before, after, "escalated")
    second = classify_escalations(before, after, "escalated")
    assert [e["id"] for e in first] == [e["id"] for e in second]
    severities = [e["severity"] for e in first]
    assert severities == sorted(severities, key=["critical", "high", "medium", "low"].index)
