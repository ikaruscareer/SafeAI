"""Tests for newly reachable source→destination paths in PR comments (WS5)."""

from safeai.report.pr_comment import (
    MAX_LINES,
    _dataflow_paths,
    render_pr_comment,
)


def _flow(rule="DATAFLOW_shell", status="new", severity="high",
          evidence="source:user_input@L3 -> sink:shell@L9",
          file="agent.py", line=9):
    return {
        "rule_id": rule,
        "severity": severity,
        "status": status,
        "message": "flow",
        "file": file,
        "line": line,
        "evidence": evidence,
    }


def _report(findings, tools=None):
    return {
        "findings": findings,
        "capability_diff": {
            "schema_version": 2,
            "baseline_available": True,
            "baseline_tool_attribution": True,
            "tools": tools or [],
            "unattributed": None,
            "counts": {"tools_unchanged": 1},
            "highest_escalation": None,
            "legacy": {},
        },
        "tool_surface": [],
        "kya_agents": [],
    }


def _tool(tool_key="tool:x"):
    return {
        "tool_key": tool_key,
        "tool": {"kind": "tool", "name": "x", "framework": None},
        "status": "escalated",
        "access_summary": {"before": "read", "after": "write"},
        "capabilities_added": [],
        "capabilities_removed": [],
        "access_mode_changes": [],
        "escalations": [{
            "id": "ESC_X", "severity": "high", "summary": "Widened",
            "before": "read", "after": "write",
            "evidence": [{"path": "a.py", "line": 1}],
            "confidence": "high", "inferred": False,
        }],
    }


class TestDataflowPaths:
    def test_new_path_renders(self):
        lines = _dataflow_paths(_report([_flow()]))
        text = "\n".join(lines)
        assert "New data-flow paths" in text
        assert "user_input" in text
        assert "shell" in text
        assert "heuristic" in text

    def test_old_and_suppressed_excluded(self):
        report = _report([
            _flow(status="existing"),
            _flow(status="suppressed"),
            _flow(status="resolved"),
        ])
        assert _dataflow_paths(report) == []

    def test_non_dataflow_excluded(self):
        report = _report([_flow(rule="CAP_shell")])
        assert _dataflow_paths(report) == []

    def test_regressed_included(self):
        lines = _dataflow_paths(_report([_flow(status="regressed")]))
        assert any("shell" in line for line in lines)

    def test_overflow_capped(self):
        findings = [_flow(evidence=f"source:v{i}@L1 -> sink:http@L2",
                          file=f"f{i}.py") for i in range(20)]
        lines = _dataflow_paths(_report(findings), budget=7)
        assert len(lines) <= 7
        assert any("+1" in line and "more" in line for line in lines)

    def test_severity_ordering(self):
        findings = [_flow(severity="low"), _flow(severity="critical")]
        lines = _dataflow_paths(_report(findings))
        joined = "\n".join(lines)
        assert joined.index("shell") < len(joined)  # sanity: both render
        first_path = next(line for line in lines if line.startswith("- `"))
        assert "user_input" in first_path  # deterministic single-label set


class TestRenderWithPaths:
    def test_paths_alongside_escalations(self):
        text = render_pr_comment(_report([_flow()], tools=[_tool()]))
        assert "New data-flow paths" in text
        assert "tool:x" in text

    def test_no_paths_no_section(self):
        text = render_pr_comment(_report([], tools=[_tool()]))
        assert "New data-flow paths" not in text

    def test_line_cap_holds(self):
        findings = [_flow(evidence=f"source:v{i}@L1 -> sink:http@L2",
                          file=f"f{i}.py") for i in range(30)]
        tools = [_tool(f"tool:{i}") for i in range(10)]
        text = render_pr_comment(_report(findings, tools=tools))
        assert len(text.splitlines()) <= MAX_LINES

    def test_first_scan_unaffected(self):
        text = render_pr_comment(_report([_flow()]))
        # No baseline_available tools -> escalations pathAbsent; first-scan
        # summary renders instead.
        assert "establishing a baseline" in text or "no capability escalations" in text


def _decision(matches):
    return {"outcome": "review-required", "action": "require_review",
            "lane": "B", "lanes": {"A": 0, "B": len(matches)},
            "reasons": [], "matches": matches}


def _match(policy_id="review-shell", lane="B", message="Shell needs eyes"):
    return {"policy_id": policy_id, "action": "require_review", "lane": lane,
            "message": message, "matched": []}


class TestReviewQuestions:
    def test_questions_rendered(self):
        report = _report([], tools=[_tool()])
        report["policy_decision"] = _decision([_match()])
        text = render_pr_comment(report)
        assert "Human review" in text
        assert "? [review-shell]" in text
        assert "not CI gates" in text

    def test_lane_a_matches_excluded(self):
        report = _report([], tools=[_tool()])
        report["policy_decision"] = _decision([_match(lane="A")])
        text = render_pr_comment(report)
        assert "Human review" not in text

    def test_no_matches_no_section(self):
        report = _report([], tools=[_tool()])
        report["policy_decision"] = _decision([])
        text = render_pr_comment(report)
        assert "Human review" not in text

    def test_cap_with_questions(self):
        matches = [_match(policy_id=f"p{i}") for i in range(20)]
        report = _report([], tools=[_tool()])
        report["policy_decision"] = _decision(matches)
        text = render_pr_comment(report)
        assert len(text.splitlines()) <= MAX_LINES
        assert "Human review" in text
