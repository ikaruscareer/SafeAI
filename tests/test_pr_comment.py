"""PR comment renderer.

The renderer's job is to make one fact obvious to a reviewer in seconds:
a named tool gained named authority. These tests defend that contract —
line budget, ordering, grouping, determinism, and the absence of source
text.
"""

import os

from safeai.report.pr_comment import MARKER, MAX_LINES, TARGET_LINES, render_pr_comment

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "claude_code")


def escalation(rule_id, severity, summary="Gained authority", path="src/tool.py", line=10):
    return {
        "id": rule_id,
        "severity": severity,
        "summary": summary,
        "before": "absent",
        "after": "present",
        "evidence": [{"path": path, "line": line}],
        "confidence": "medium",
        "inferred": False,
    }


def tool_entry(tool_key, kind, name, severity, status="escalated", before="read", after="mutate",
               escalations=None):
    return {
        "tool_key": tool_key,
        "tool": {"kind": kind, "name": name, "framework": "mcp"},
        "status": status,
        "access_summary": {"before": before, "after": after},
        "capabilities_added": [],
        "capabilities_removed": [],
        "access_mode_changes": [],
        "escalations": escalations or [escalation("ESC_MCP_READ_TO_MUTATE", severity)],
    }


def report_with(tools, **diff_overrides):
    diff = {
        "schema_version": 2,
        "baseline_available": True,
        "baseline_tool_attribution": True,
        "tools": tools,
        "unattributed": None,
        "counts": {
            "tools_new": 0,
            "tools_escalated": len(tools),
            "tools_reduced": 0,
            "tools_removed": 0,
            "tools_unchanged": 3,
            "escalations_by_severity": {},
            "added": 0,
            "removed": 0,
            "changed": len(tools),
        },
        "highest_escalation": "critical" if tools else None,
        "legacy": {},
    }
    diff.update(diff_overrides)
    return {"capability_diff": diff, "tool_surface": [], "kya_agents": []}


def typical_report():
    return report_with([
        tool_entry(
            "mcp_server:invoice-lookup", "mcp_server", "invoice-lookup", "critical",
            escalations=[escalation(
                "ESC_MCP_READ_TO_MUTATE", "critical",
                "MCP server gained mutating tools: create_invoice, delete_invoice",
                ".mcp.json", 12,
            )],
        ),
        tool_entry(
            "tool:report_builder", "tool", "report_builder", "high",
            status="new", before=None, after="write",
            escalations=[escalation(
                "ESC_FILESYSTEM_WRITE_ADDED", "high",
                "Filesystem access widened to write/mutate (filesystem)",
                "src/tools/report.py", 44,
            )],
        ),
    ])


# --- structure -----------------------------------------------------------


def test_marker_is_always_the_first_line():
    for report in (typical_report(), report_with([]), {"capability_diff": {}}):
        assert render_pr_comment(report).splitlines()[0] == MARKER


def test_typical_change_fits_the_target_budget():
    lines = render_pr_comment(typical_report()).splitlines()
    assert len(lines) <= TARGET_LINES, "\n".join(lines)


def test_body_names_the_tool_not_the_rule():
    text = render_pr_comment(typical_report())
    assert "`mcp_server:invoice-lookup`" in text
    assert "`tool:report_builder`" in text
    # Rule identifiers are detail; the summary carries the meaning.
    assert "ESC_MCP_READ_TO_MUTATE" not in text


def test_access_mode_transition_is_shown():
    text = render_pr_comment(typical_report())
    assert "read → mutate" in text


def test_highest_severity_is_rendered_first():
    text = render_pr_comment(typical_report())
    assert text.index("invoice-lookup") < text.index("report_builder")


def test_evidence_is_a_path_and_line_only():
    text = render_pr_comment(typical_report())
    assert "`.mcp.json:12`" in text
    assert "`src/tools/report.py:44`" in text


def test_footer_states_the_static_analysis_boundary():
    text = render_pr_comment(typical_report())
    assert "cannot verify deployed IAM permissions" in text


def test_no_unchanged_surface_inventory():
    text = render_pr_comment(typical_report())
    assert "unchanged" in text  # only as a one-line count
    assert text.count("unchanged") == 1


# --- edge paths ----------------------------------------------------------


def test_no_baseline_emits_a_first_scan_summary():
    report = {
        "capability_diff": {"schema_version": 2, "baseline_available": False, "tools": []},
        "tool_surface": [{
            "tool_key": "tool:bash",
            "capabilities": [{"name": "shell", "access_mode": "execute"}],
        }],
        "kya_agents": [{"agent_id": "a"}],
    }
    text = render_pr_comment(report)
    assert "first scan" in text
    assert "baseline" in text
    assert "→" not in text, "a first scan must not render a fake diff"
    assert "`tool:bash` — shell (execute)" in text


def test_missing_capability_diff_is_treated_as_a_first_scan():
    text = render_pr_comment({})
    assert text.splitlines()[0] == MARKER
    assert "first scan" in text


def test_no_changes_emits_a_single_line():
    text = render_pr_comment(report_with([]))
    body = [line for line in text.splitlines() if line.strip() and line != MARKER]
    assert len(body) == 2  # heading + footer
    assert "no capability escalations" in body[0]


def test_low_severity_escalations_are_not_promoted_to_the_summary():
    report = report_with([tool_entry("tool:x", "tool", "x", "low")])
    assert "no capability escalations" in render_pr_comment(report)


def test_unattributed_escalations_are_still_reported():
    report = report_with([])
    report["capability_diff"]["unattributed"] = {
        "tool_key": "unknown:unattributed",
        "tool": {"kind": "unknown", "name": "unattributed", "framework": None},
        "status": "new",
        "access_summary": {"before": None, "after": "execute"},
        "escalations": [escalation("ESC_SHELL_ADDED", "critical")],
    }
    assert "unknown:unattributed" in render_pr_comment(report)


# --- limits --------------------------------------------------------------


def test_fifty_escalations_respect_the_hard_cap():
    tools = [
        tool_entry(f"tool:t{index:02d}", "tool", f"t{index:02d}", "critical")
        for index in range(50)
    ]
    lines = render_pr_comment(report_with(tools)).splitlines()
    assert len(lines) <= MAX_LINES, len(lines)
    assert any("more — see full report" in line for line in lines)


def test_truncation_notice_counts_the_hidden_tools():
    tools = [
        tool_entry(f"tool:t{index:02d}", "tool", f"t{index:02d}", "critical")
        for index in range(50)
    ]
    text = render_pr_comment(report_with(tools))
    shown = text.count("**`tool:t")
    notice = next(line for line in text.splitlines() if "see full report" in line)
    assert notice == f"_{50 - shown} more — see full report_"


def test_capped_output_still_ends_with_the_footer():
    tools = [
        tool_entry(f"tool:t{index:02d}", "tool", f"t{index:02d}", "critical")
        for index in range(50)
    ]
    assert render_pr_comment(report_with(tools)).rstrip().endswith("network policy._")


# --- determinism ---------------------------------------------------------


def test_rendering_is_byte_identical_across_runs():
    report = typical_report()
    assert render_pr_comment(report) == render_pr_comment(report)


def test_no_timestamps_or_run_ids_in_the_body():
    report = typical_report()
    report["scan"] = {"scan_id": "scan-123", "completed_at": "2026-01-01T00:00:00Z"}
    text = render_pr_comment(report)
    assert "scan-123" not in text
    assert "2026" not in text


def test_ci_context_does_not_change_the_body():
    report = typical_report()
    context = {"provider": "github_actions", "branch": "feature", "base_ref": "main",
               "commit_sha": "abc", "pr_number": 3, "repository": "acme/agents"}
    assert render_pr_comment(report, ci_context=context) == render_pr_comment(report)


# --- snapshot ------------------------------------------------------------


EXPECTED = """<!-- safeai:pr-comment:v1 -->

### SafeAI — 2 capability escalations across 2 tools

**`mcp_server:invoice-lookup`** — read → mutate  ⚠️ critical
  MCP server gained mutating tools: create_invoice, delete_invoice · `.mcp.json:12`

**`tool:report_builder`** — new · write  ⚠️ high
  Filesystem access widened to write/mutate (filesystem) · `src/tools/report.py:44`

<sub>3 unchanged tools · 2 shown</sub>

_Static analysis of repository configuration and source. SafeAI cannot verify \
deployed IAM permissions, runtime identity, or network policy._
"""


def test_exact_markdown_snapshot():
    assert render_pr_comment(typical_report()) == EXPECTED


# --- end to end ----------------------------------------------------------


def test_real_scan_renders_named_tools():
    from safeai.engine.scan import run_scan

    baseline = run_scan(os.path.join(FIXTURES, "minimal"))
    current = run_scan(os.path.join(FIXTURES, "permissive"), baseline_report=baseline)
    text = render_pr_comment(current)

    assert text.splitlines()[0] == MARKER
    assert "`mcp_server:github`" in text
    assert len(text.splitlines()) <= MAX_LINES
    # Never echo configuration source into a PR comment.
    assert "bypassPermissions" not in text
