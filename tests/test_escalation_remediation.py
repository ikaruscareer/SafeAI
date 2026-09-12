"""Escalation remediation (WS3): catalog completeness + output wiring."""

import json

from safeai.analysis.escalation import ESCALATION_RULES, classify_escalations
from safeai.analysis.escalation_remediation import (
    COVERED_RULE_IDS,
    REMEDIATION,
    remediation_for,
)
from safeai.kya.contract import validate_manifest
from safeai.kya.manifest import _escalation_entries, build_manifest
from safeai.report.pr_comment import MAX_LINES, render_pr_comment


def _cap(name, access_mode="read", confidence=0.9):
    return {
        "name": name,
        "category": name.title(),
        "access_mode": access_mode,
        "confidence": confidence,
        "inferred": False,
        "evidence": [{"path": "a.py", "line": 1}],
    }


def _state(capabilities, kind="tool", name="deploy"):
    return {
        "tool": {"kind": kind, "name": name, "framework": "langchain"},
        "capabilities": list(capabilities),
    }


def test_catalog_covers_every_rule():
    table_ids = {rule["id"] for rule in ESCALATION_RULES}
    assert COVERED_RULE_IDS == table_ids
    assert len(table_ids) == 14


def test_every_rule_has_structured_remediation():
    required = ("summary", "why_it_matters", "review_questions",
                "recommended_actions", "safe_configuration_patterns",
                "limitations")
    for rule in ESCALATION_RULES:
        entry = remediation_for(rule["id"])
        for key in required:
            assert entry.get(key), f"{rule['id']} missing {key}"
        assert all(isinstance(q, str) and q for q in entry["review_questions"])
        assert all(isinstance(a, str) and a for a in entry["recommended_actions"])


def test_unknown_rule_id_never_none():
    entry = remediation_for("ESC_DOES_NOT_EXIST")
    assert entry["summary"]
    assert entry["recommended_actions"]


def test_catalog_contains_no_values_or_patches():
    import re
    blob = json.dumps(REMEDIATION)
    assert "AKIA" not in blob
    assert re.search(r"sk-[A-Za-z0-9]{8,}", blob) is None
    assert "```diff" not in blob
    assert "auto-fix" not in blob.lower()


def test_classifier_attaches_remediation():
    before = _state([_cap("network")])
    after = _state([_cap("network"), _cap("shell", "execute")])
    escalations = classify_escalations(before, after, "escalated")
    ids = {e["id"] for e in escalations}
    assert "ESC_SHELL_ADDED" in ids
    for escalation in escalations:
        remediation = escalation.get("remediation")
        assert isinstance(remediation, dict)
        assert remediation["recommended_actions"]


def test_json_capability_diff_carries_remediation():
    before = _state([_cap("network")])
    after = _state([_cap("network"), _cap("shell", "execute")])
    escalations = classify_escalations(before, after, "escalated")
    report = {"capability_diff": {"tools": [{
        "tool_key": "deploy",
        "escalations": escalations,
    }]}}
    blob = json.dumps(report)
    assert "recommended_actions" in blob


def test_manifest_escalations_validate():
    before = _state([_cap("network")])
    after = _state([_cap("network"), _cap("shell", "execute")])
    escalations = classify_escalations(before, after, "escalated")
    report = {
        "findings": [],
        "files_scanned": 1,
        "detected_frameworks": [],
        "capability_diff": {"tools": [{
            "tool_key": "deploy", "escalations": escalations}]},
    }
    manifest = build_manifest(
        report,
        project={"project_id": "p1", "name": "d", "source_root": ".", "repository": {}},
        scan_meta={"scan_id": "s", "started_at": "t0", "completed_at": "t1"},
        safeai_meta={"version": "x", "ruleset_version": "y", "config_hash": "z"},
        agents=[],
    )
    assert len(manifest["escalations"]) == len(escalations)
    assert manifest["escalations"][0]["remediation"]["recommended_actions"]
    errors, _ = validate_manifest(manifest)
    assert errors == []
    # No baseline → empty array, still valid.
    assert _escalation_entries({}) == []


def _pr_report(escalations):
    return {
        "capability_diff": {
            "baseline_available": True,
            "counts": {},
            "tools": [{
                "tool_key": "deploy",
                "tool": {"name": "deploy"},
                "status": "escalated",
                "access_summary": {"before": "read", "after": "execute"},
                "escalations": escalations,
            }],
        },
        "policy_decision": {"outcome": "block"},
    }


def test_pr_comment_renders_one_action_per_critical():
    escalations = classify_escalations(
        _state([_cap("network")]),
        _state([_cap("network"), _cap("shell", "execute")]),
        "escalated",
    )
    text = render_pr_comment(_pr_report(escalations))
    assert "Remove shell execution if the tool can work without it." in text
    assert len(text.splitlines()) <= MAX_LINES


def test_pr_comment_unchanged_without_remediation():
    text = render_pr_comment(_pr_report([{
        "id": "ESC_SHELL_ADDED",
        "severity": "critical",
        "summary": "Gained shell",
        "evidence": [{"path": "a.py", "line": 1}],
    }]))
    assert "Remove shell execution" not in text


def test_pr_comment_cap_preserved_with_remediation():
    tools = []
    for i in range(30):
        tools.append({
            "tool_key": f"tool-{i:02d}",
            "tool": {"name": f"tool-{i:02d}"},
            "status": "escalated",
            "access_summary": {"before": "read", "after": "execute"},
            "escalations": [{
                "id": "ESC_SHELL_ADDED",
                "severity": "critical",
                "summary": "Gained shell",
                "evidence": [{"path": "a.py", "line": 1}],
                "remediation": remediation_for("ESC_SHELL_ADDED"),
            }],
        })
    text = render_pr_comment({
        "capability_diff": {"baseline_available": True, "counts": {}, "tools": tools},
        "policy_decision": {"outcome": "block"},
    })
    assert len(text.splitlines()) <= MAX_LINES


def _terminal_report():
    return {
        "files_scanned": 1,
        "counts": {"critical": 1, "high": 1, "medium": 1},
        "findings": [
            {"severity": "critical", "file": "a.py", "line": 1,
             "message": "shell", "status": "new",
             "remediation": "Remove shell execution or gate it behind approval."},
            {"severity": "high", "file": "b.py", "line": 2,
             "message": "http", "status": "new",
             "remediation": "Allowlist the required endpoints."},
            {"severity": "medium", "file": "c.py", "line": 3,
             "message": "note", "status": "new",
             "remediation": "Review at leisure."},
        ],
    }


def test_terminal_next_action_only_for_high_critical(capsys):
    from safeai.report.terminal import print_summary
    print_summary(_terminal_report())
    out = capsys.readouterr().out
    assert "Next: Remove shell execution or gate it behind approval" in out
    assert "Next: Allowlist the required endpoints" in out
    assert "Review at leisure" not in out


def test_scorecard_remediation_themes(capsys):
    from safeai.scorecard import _remediation_theme_lines
    findings = [
        {"remediation": "Allowlist the required endpoints."},
        {"remediation": "Allowlist the required endpoints."},
        {"remediation": "Remove shell execution."},
        {"remediation": ""},
        {},
    ]
    lines = _remediation_theme_lines(findings)
    assert lines[0].startswith("- 2x")
    assert "Allowlist" in lines[0]
    assert len(lines) == 2


def test_html_escalation_remediation_collapsible():
    from safeai.report.html import _escalation_section
    escalations = classify_escalations(
        _state([_cap("network")]),
        _state([_cap("network"), _cap("shell", "execute")]),
        "escalated",
    )
    html = _escalation_section({"capability_diff": {
        "counts": {"added": 1, "removed": 0, "changed": 0, "escalations": 1},
        "highest_escalation": "critical",
        "tools": [{"tool_key": "deploy", "status": "escalated",
                   "access_summary": {}, "escalations": escalations}],
    }})
    assert "<details><summary>Remediation</summary>" in html
    assert "Recommended actions" in html
    assert "Limitations" in html


def test_html_escalation_without_remediation_renders(tmp_path):
    from safeai.report.html import _escalation_section
    html = _escalation_section({"capability_diff": {
        "counts": {}, "tools": [{"tool_key": "t", "status": "escalated",
                                 "access_summary": {},
                                 "escalations": [{"id": "ESC_X", "severity": "high",
                                                  "summary": "s"}]}],
    }})
    assert "ESC_X" in html
    assert "<details>" not in html


def test_sarif_does_not_duplicate_escalations(tmp_path):
    """Escalations are baseline diffs without file locations, so SARIF
    intentionally carries finding-level remediation only (documented in
    docs/guides/REPORTING_GUIDE.md)."""
    from safeai.report.sarif import write_sarif
    report = {
        "findings": [{
            "rule_id": "CAP_shell", "severity": "critical",
            "message": "shell", "file": "a.py", "line": 1,
            "remediation": "Remove shell execution.",
        }],
        "capability_diff": {"tools": [{"tool_key": "deploy", "escalations": [{
            "id": "ESC_SHELL_ADDED", "severity": "critical",
            "remediation": remediation_for("ESC_SHELL_ADDED"),
        }]}]},
    }
    path = str(tmp_path / "r.sarif")
    write_sarif(report, path)
    import json as _json
    sarif = _json.loads(open(path, encoding="utf-8").read())
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "CAP_shell" in rule_ids
    assert "ESC_SHELL_ADDED" not in rule_ids
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["help"]["text"] == \
        "Remove shell execution."
