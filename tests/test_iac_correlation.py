"""Tests for IaC authority correlation verdicts (v2.5, Lane B)."""

from safeai.analysis.iac_correlation import (
    RULE_EXCESS,
    RULE_MISMATCH,
    RULE_UNVERIFIED,
    correlate_iac_authority,
)


def _grant(family="cloud", principal="agent-s3-access",
           action="s3:GetObject", resource="*",
           source_file="main.tf", line=10,
           provenance="repo-iac-observed"):
    return {
        "principal": principal, "action": action, "resource": resource,
        "source": "terraform", "source_file": source_file, "line": line,
        "provenance": provenance, "fidelity_notes": [], "family": family,
    }


def _report(tool_caps=(), inventory=()):
    surface = [
        {"tool_key": f"tool:{name}", "capabilities": [{"name": cap}]}
        for name, cap in tool_caps
    ]
    findings = []
    if inventory:
        findings.append({
            "rule_id": "ENV_DEP_INVENTORY",
            "dep_inventory": [{"name": name} for name in inventory],
        })
    return {"tool_surface": surface, "findings": findings}


def _meta(*tf_files, rbac=()):
    return {"tf_files": list(tf_files), "rbac_files": list(rbac),
            "unparsed_files": []}


def test_no_iac_is_silent():
    findings, summary = correlate_iac_authority(_report(), [], [], [])
    assert findings == []
    assert summary["verdicts"] == []
    assert summary["lane"] == "B"


def test_excess_authority_grant_without_capability():
    report = _report()
    findings, summary = correlate_iac_authority(
        report, [_grant()], [], [], _meta("main.tf"))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == RULE_EXCESS
    assert finding["severity"] == "medium"
    assert finding["provenance_class"] == "repo-iac-observed"
    assert finding["gateability"] == "review-only"
    assert finding["iac_verdict"] == "EXCESS_AUTHORITY"
    assert finding["file"] == "main.tf"
    assert summary["counts"]["excess_authority"] == 1


def test_mismatch_capability_without_grant():
    report = _report(tool_caps=[("x", "s3")])
    findings, summary = correlate_iac_authority(
        report, [], [], [], _meta("main.tf"))
    assert len(findings) == 1
    assert findings[0]["rule_id"] == RULE_MISMATCH
    assert findings[0]["gateability"] == "review-only"
    assert summary["counts"]["authority_mismatch"] == 1


def test_declared_without_any_iac_is_silent():
    report = _report(tool_caps=[("x", "s3")])
    findings, summary = correlate_iac_authority(report, [], [], [], _meta())
    assert findings == []
    assert summary["verdicts"] == []


def test_unverified_link_is_the_default():
    report = _report(tool_caps=[("x", "s3")])
    findings, summary = correlate_iac_authority(
        report, [_grant()], [], [], _meta("main.tf"))
    assert len(findings) == 1
    assert findings[0]["rule_id"] == RULE_UNVERIFIED
    assert findings[0]["gateability"] == "review-only"
    verdict = summary["verdicts"][0]
    assert verdict["verdict"] == "UNVERIFIED_LINK"
    assert verdict["linked"] is False


def test_match_requires_static_identity_link():
    report = _report(tool_caps=[("x", "s3")],
                     inventory=["agent-s3-access"])
    findings, summary = correlate_iac_authority(
        report, [_grant(principal="agent-s3-access")], [], [],
        _meta("main.tf"))
    assert findings == []  # MATCH is recorded, never a finding
    verdict = summary["verdicts"][0]
    assert verdict["verdict"] == "MATCH"
    assert verdict["linked"] is True
    assert "dependency inventory" in (verdict["link_evidence"] or "")


def test_partial_name_match_does_not_link():
    report = _report(tool_caps=[("x", "s3")], inventory=["agent-s3"])
    _, summary = correlate_iac_authority(
        report, [_grant(principal="agent-s3-access")], [], [],
        _meta("main.tf"))
    assert summary["verdicts"][0]["verdict"] == "UNVERIFIED_LINK"


def test_kubernetes_family_uses_k8s_grants():
    report = _report(tool_caps=[("x", "kubernetes")])
    grant = _grant(family="kubernetes", principal="Role/agent-reader",
                   action="get,list", resource="pods",
                   source_file="rbac.yaml")
    findings, summary = correlate_iac_authority(
        report, [grant], [], [], _meta(rbac=["rbac.yaml"]))
    assert summary["verdicts"][0]["family"] == "kubernetes"
    assert summary["verdicts"][0]["verdict"] == "UNVERIFIED_LINK"
    assert findings[0]["file"] == "rbac.yaml"


def test_all_findings_are_review_only():
    report = _report(tool_caps=[("x", "s3")])
    findings, _ = correlate_iac_authority(
        report, [_grant()], [], [], _meta("main.tf"))
    assert findings
    for finding in findings:
        assert finding["gateability"] == "review-only"
        assert finding["provenance_class"] == "repo-iac-observed"


def test_end_to_end_scan_with_terraform(tmp_path):
    from safeai.engine.orchestrator import ScanOrchestrator

    (tmp_path / "main.tf").write_text(
        'resource "aws_iam_policy" "p" {\n'
        '  statement {\n'
        '    actions = ["s3:GetObject"]\n'
        '    resources = ["*"]\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    report = ScanOrchestrator(str(tmp_path)).run()
    iac = report.get("iac_correlations") or {}
    assert iac.get("lane") == "B"
    assert iac["counts"]["grants"] == 1
    assert iac["counts"]["excess_authority"] == 1
    rule_ids = [f.get("rule_id") for f in report.get("findings") or []]
    assert RULE_EXCESS in rule_ids
    for finding in report["findings"]:
        if str(finding.get("rule_id") or "").startswith("IAC_"):
            assert finding["gateability"] == "review-only"


def test_end_to_end_mismatch_with_declared_cloud(tmp_path):
    from safeai.engine.orchestrator import ScanOrchestrator

    (tmp_path / "mcp.json").write_text(
        '{"mcp": {"version": "1.1", '
        '"servers": [{"name": "storage"}], '
        '"tools": [{"name": "s3_list_buckets", '
        '"description": "List S3 buckets."}]}}',
        encoding="utf-8",
    )
    (tmp_path / "main.tf").write_text(
        'resource "aws_iam_role" "r" {\n  name = "r"\n}\n',
        encoding="utf-8",
    )
    report = ScanOrchestrator(str(tmp_path)).run()
    rule_ids = [f.get("rule_id") for f in report.get("findings") or []]
    assert RULE_MISMATCH in rule_ids
