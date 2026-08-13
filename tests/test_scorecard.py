"""Tests for the SafeAI Security Scorecard feature.

Covers the scoring logic, category aggregation, JSON/Markdown generation,
GitHub summary output, and the scorecard-fail-under gate.
"""

import json
import os
import subprocess
import sys

import pytest

from safeai.scorecard import (
    SCORECARD_SCHEMA_VERSION,
    SEVERITY_WEIGHTS,
    build_scorecard,
    compute_category_scores,
    compute_score,
    render_scorecard_md,
    write_scorecard_json,
    write_scorecard_md,
    write_scorecard_summary,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "action")


def _base_finding(**overrides):
    """Return a minimal finding dict for testing."""
    finding = {
        "rule_id": "DATA_LEAKAGE",
        "severity": "high",
        "message": "Potential secret exposure: API_KEY",
        "file": "agent.py",
        "line": 4,
        "fingerprint": "abc123",
        "status": "new",
        "remediation": "Remove the hardcoded secret.",
        "provenance": {"analyzer": "data_leakage"},
    }
    finding.update(overrides)
    return finding


def _base_report(findings, **overrides):
    """Return a minimal scan report dict for testing."""
    report = {
        "report_type": "safeai.scan",
        "findings": findings,
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "files_scanned": 1,
        "detected_frameworks": ["langgraph"],
        "safeai_meta": {"version": "1.5.0"},
    }
    report.update(overrides)
    return report


def _base_scan_meta():
    return {
        "scan_id": "test-scan-1",
        "started_at": "2026-01-01T00:00:00",
        "completed_at": "2026-01-01T00:00:01",
    }


def _base_policy(outcome="warn"):
    return {
        "outcome": outcome,
        "reasons": ["No policy file supplied; default posture."],
    }


def _base_args(**overrides):
    args = {
        "directory": ".",
        "fail_on": "critical",
        "fail_on_new": False,
        "fail_on_escalation": None,
        "scorecard_fail_under": None,
    }
    args.update(overrides)
    return args


# --- Scoring logic tests ---


def test_compute_score_no_findings():
    """No findings yields a perfect score of 10."""
    assert compute_score([]) == 10.0


def test_compute_score_critical_finding():
    """One critical finding reduces the score by its weight."""
    findings = [_base_finding(severity="critical")]
    # critical = 4.0, so score = 10 - 4.0 = 6.0
    assert compute_score(findings) == 6.0


def test_compute_score_high_finding():
    """One high finding reduces the score by its weight."""
    findings = [_base_finding(severity="high")]
    # high = 2.0, so score = 10 - 2.0 = 8.0
    assert compute_score(findings) == 8.0


def test_compute_score_medium_finding():
    """One medium finding reduces the score by its weight."""
    findings = [_base_finding(severity="medium")]
    # medium = 0.75, so score = 10 - 0.75 = 9.25
    assert compute_score(findings) == 9.25


def test_compute_score_low_finding():
    """One low finding reduces the score by its weight."""
    findings = [_base_finding(severity="low")]
    # low = 0.25, so score = 10 - 0.25 = 9.75
    assert compute_score(findings) == 9.75


def test_compute_score_info_finding():
    """Info findings do not reduce the score."""
    findings = [_base_finding(severity="info")]
    assert compute_score(findings) == 10.0


def test_compute_score_multiple_findings():
    """Multiple findings accumulate penalties."""
    findings = [
        _base_finding(severity="critical", fingerprint="f1", file="a.py", line=1),
        _base_finding(severity="high", fingerprint="f2", file="b.py", line=2),
        _base_finding(severity="medium", fingerprint="f3", file="c.py", line=3),
    ]
    # 4.0 + 2.0 + 0.75 = 6.75, so score = 10 - 6.75 = 3.25
    assert compute_score(findings) == 3.25


def test_compute_score_duplicate_fingerprints():
    """Duplicate fingerprints are deduplicated (counted once)."""
    findings = [
        _base_finding(severity="high", fingerprint="same"),
        _base_finding(severity="high", fingerprint="same"),
        _base_finding(severity="high", fingerprint="same"),
    ]
    # Only one unique finding, so score = 10 - 2.0 = 8.0
    assert compute_score(findings) == 8.0


def test_compute_score_diminishing_returns():
    """Repeated findings from the same rule and location have diminishing returns."""
    findings = [
        _base_finding(rule_id="CAP_shell", severity="high", file="a.py", line=1, fingerprint="f1"),
        _base_finding(rule_id="CAP_shell", severity="high", file="a.py", line=1, fingerprint="f2"),
        _base_finding(rule_id="CAP_shell", severity="high", file="a.py", line=1, fingerprint="f3"),
        _base_finding(rule_id="CAP_shell", severity="high", file="a.py", line=1, fingerprint="f4"),
    ]
    # 2.0 + 1.0 + 0.5 + 0.25 = 3.75, so score = 10 - 3.75 = 6.25
    assert compute_score(findings) == 6.25


def test_compute_score_clamped_to_zero():
    """A very large penalty clamps the score to 0."""
    findings = [
        _base_finding(severity="critical", fingerprint=f"f{i}", file=f"file{i}.py", line=i)
        for i in range(10)
    ]
    # 10 * 4.0 = 40.0, so score = 10 - 40 = -30, clamped to 0
    assert compute_score(findings) == 0.0


def test_compute_score_deterministic():
    """Identical findings always produce the same score."""
    findings = [
        _base_finding(severity="high", fingerprint="f1"),
        _base_finding(severity="medium", fingerprint="f2"),
    ]
    assert compute_score(findings) == compute_score(list(findings))


# --- Category aggregation tests ---


def test_compute_category_scores_no_findings():
    """No findings yields no categories."""
    assert compute_category_scores([]) == []


def test_compute_category_scores_single_category():
    """Findings in one category produce one category entry."""
    findings = [
        _base_finding(rule_id="DATA_LEAKAGE", severity="high"),
        _base_finding(rule_id="SKILL_HARDCODED_SECRET", severity="critical"),
    ]
    categories = compute_category_scores(findings)
    assert len(categories) == 1
    assert categories[0]["name"] == "Secrets and credentials"
    assert categories[0]["findings"] == 2
    assert categories[0]["severity_counts"]["high"] == 1
    assert categories[0]["severity_counts"]["critical"] == 1


def test_compute_category_scores_multiple_categories():
    """Findings in multiple categories produce multiple entries."""
    findings = [
        _base_finding(rule_id="DATA_LEAKAGE", severity="high"),
        _base_finding(rule_id="CAP_shell", severity="critical"),
        _base_finding(rule_id="PROMPT_INJECTION", severity="critical"),
    ]
    categories = compute_category_scores(findings)
    names = {c["name"] for c in categories}
    assert names == {
        "Secrets and credentials",
        "Command or code execution",
        "Prompt injection",
    }


def test_compute_category_scores_status():
    """Category status reflects the worst finding severity."""
    # Only info findings -> warn (not pass, because findings exist)
    findings = [_base_finding(rule_id="ENV_DEP_INVENTORY", severity="info")]
    categories = compute_category_scores(findings)
    assert categories[0]["status"] == "warn"

    # Critical finding -> fail
    findings = [_base_finding(rule_id="DATA_LEAKAGE", severity="critical")]
    categories = compute_category_scores(findings)
    assert categories[0]["status"] == "fail"

    # High finding -> fail (high is at or above the default blocking threshold)
    findings = [_base_finding(rule_id="DATA_LEAKAGE", severity="high")]
    categories = compute_category_scores(findings)
    assert categories[0]["status"] == "fail"


def test_compute_category_scores_suppressed():
    """Suppressed findings do not affect category status."""
    findings = [
        _base_finding(rule_id="DATA_LEAKAGE", severity="high", status="suppressed"),
    ]
    categories = compute_category_scores(findings)
    # All findings suppressed -> pass
    assert categories[0]["status"] == "pass"


def test_compute_category_scores_top_findings():
    """Top findings are limited and ordered by severity."""
    findings = [
        _base_finding(rule_id="DATA_LEAKAGE", severity="low", fingerprint="f1"),
        _base_finding(rule_id="DATA_LEAKAGE", severity="critical", fingerprint="f2"),
        _base_finding(rule_id="DATA_LEAKAGE", severity="medium", fingerprint="f3"),
        _base_finding(rule_id="DATA_LEAKAGE", severity="high", fingerprint="f4"),
    ]
    categories = compute_category_scores(findings)
    top = categories[0]["top_findings"]
    assert len(top) == 3
    assert top[0]["severity"] == "critical"
    assert top[1]["severity"] == "high"
    assert top[2]["severity"] == "medium"


# --- Scorecard build tests ---


def test_build_scorecard_schema():
    """The scorecard has the expected top-level structure."""
    findings = [_base_finding()]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()

    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)
    assert "safeai_security_scorecard" in scorecard
    data = scorecard["safeai_security_scorecard"]
    assert data["schema_version"] == SCORECARD_SCHEMA_VERSION
    assert data["tool"]["name"] == "SafeAI"
    assert data["tool"]["report_type"] == "safeai-security-scorecard"
    assert "summary" in data
    assert "severity_counts" in data
    assert "categories" in data
    assert "top_findings" in data
    assert "coverage" in data
    assert "policy" in data


def test_build_scorecard_summary():
    """The summary section has the expected fields."""
    findings = [
        _base_finding(severity="high", fingerprint="f1"),
        _base_finding(severity="medium", fingerprint="f2"),
        _base_finding(severity="info", fingerprint="f3", status="suppressed"),
    ]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()

    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)
    summary = scorecard["safeai_security_scorecard"]["summary"]
    assert summary["findings_total"] == 3
    assert summary["blocking_findings"] == 0  # high < critical threshold
    assert summary["suppressed_findings"] == 1
    assert summary["new_findings"] == 0  # no baseline
    assert summary["resolved_findings"] == 0


def test_build_scorecard_status_pass():
    """A scan with no active findings yields status pass."""
    report = _base_report([])
    scan_meta = _base_scan_meta()
    policy = _base_policy(outcome="allow")
    args = _base_args()

    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)
    assert scorecard["safeai_security_scorecard"]["summary"]["status"] == "pass"


def test_build_scorecard_status_warn():
    """A scan with findings below the blocking threshold yields status warn."""
    findings = [_base_finding(severity="medium")]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()

    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)
    assert scorecard["safeai_security_scorecard"]["summary"]["status"] == "warn"


def test_build_scorecard_status_fail_policy():
    """A policy deny outcome yields status fail."""
    findings = [_base_finding(severity="low")]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy(outcome="deny")
    args = _base_args()

    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)
    assert scorecard["safeai_security_scorecard"]["summary"]["status"] == "fail"


def test_build_scorecard_status_fail_blocking():
    """Blocking findings at or above the threshold yield status fail."""
    findings = [_base_finding(severity="critical")]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()  # warn, not deny
    args = _base_args(fail_on="high")  # critical >= high threshold

    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)
    assert scorecard["safeai_security_scorecard"]["summary"]["status"] == "fail"


def test_build_scorecard_baseline():
    """Baseline new/resolved counts are included."""
    findings = [_base_finding()]
    report = _base_report(findings, baseline={"new": 2, "resolved": 1})
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()

    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)
    summary = scorecard["safeai_security_scorecard"]["summary"]
    assert summary["new_findings"] == 2
    assert summary["resolved_findings"] == 1
    assert scorecard["safeai_security_scorecard"]["scan"]["baseline_used"] is True


def test_build_scorecard_policy_section():
    """The policy section reflects the scan arguments."""
    report = _base_report([])
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args(
        fail_on="high",
        fail_on_new=True,
        fail_on_escalation="medium",
        scorecard_fail_under=7.5,
    )

    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)
    policy_section = scorecard["safeai_security_scorecard"]["policy"]
    assert policy_section["fail_on"] == "high"
    assert policy_section["fail_on_new"] is True
    assert policy_section["fail_on_escalation"] == "medium"
    assert policy_section["scorecard_fail_under"] == 7.5


def test_build_scorecard_deterministic():
    """Identical inputs produce identical scorecards."""
    findings = [_base_finding()]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()

    sc1 = build_scorecard(report, scan_meta, policy, scan_args=args)
    sc2 = build_scorecard(report, scan_meta, policy, scan_args=args)
    assert sc1 == sc2


# --- JSON output tests ---


def test_write_scorecard_json(tmp_path):
    """JSON output is valid and has the expected structure."""
    findings = [_base_finding()]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()
    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)

    path = str(tmp_path / "scorecard.json")
    write_scorecard_json(scorecard, path)

    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    assert "safeai_security_scorecard" in data
    assert data["safeai_security_scorecard"]["schema_version"] == 1


def test_write_scorecard_json_stdout(capsys):
    """JSON output to stdout works with ``-``."""
    findings = [_base_finding()]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()
    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)

    write_scorecard_json(scorecard, "-")
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "safeai_security_scorecard" in data


def test_write_scorecard_json_parent_dir(tmp_path):
    """Parent directories are created when needed."""
    findings = [_base_finding()]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()
    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)

    path = str(tmp_path / "nested" / "deep" / "scorecard.json")
    write_scorecard_json(scorecard, path)
    assert os.path.exists(path)


# --- Markdown output tests ---


def test_render_scorecard_md():
    """Markdown output has the expected structure."""
    findings = [_base_finding()]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()
    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)

    md = render_scorecard_md(scorecard)
    assert "# SafeAI Security Scorecard" in md
    assert "| Overall score |" in md
    assert "| Status |" in md
    assert "## Category scores" in md
    assert "## Severity distribution" in md
    assert "## Highest-priority findings" in md
    assert "## Coverage and limitations" in md
    assert "not an official OpenSSF Scorecard report" in md


def test_render_scorecard_md_escapes_markdown():
    """Untrusted content is escaped for safe Markdown rendering."""
    findings = [
        _base_finding(message="Test with | pipe and `code`"),
    ]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()
    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)

    md = render_scorecard_md(scorecard)
    # The pipe should be escaped so it does not break the table.
    assert "\\|" in md or "&#124;" in md


def test_render_scorecard_md_no_secrets():
    """Secret values are redacted from the Markdown output."""
    findings = [
        _base_finding(message="Secret sk-abcdef0123456789 exposed"),
    ]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()
    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)

    md = render_scorecard_md(scorecard)
    assert "sk-abcdef0123456789" not in md


def test_write_scorecard_md(tmp_path):
    """Markdown output is written to a file."""
    findings = [_base_finding()]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()
    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)

    path = str(tmp_path / "scorecard.md")
    write_scorecard_md(scorecard, path)

    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    assert "# SafeAI Security Scorecard" in content


def test_write_scorecard_md_stdout(capsys):
    """Markdown output to stdout works with ``-``."""
    findings = [_base_finding()]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()
    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)

    write_scorecard_md(scorecard, "-")
    captured = capsys.readouterr()
    assert "# SafeAI Security Scorecard" in captured.out


# --- GitHub summary tests ---


def test_write_scorecard_summary(tmp_path):
    """The scorecard is appended to the GitHub step summary."""
    findings = [_base_finding()]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()
    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)

    summary_path = str(tmp_path / "summary.md")
    write_scorecard_summary(scorecard, path=summary_path)

    with open(summary_path, encoding="utf-8") as fh:
        content = fh.read()
    assert "# SafeAI Security Scorecard" in content


def test_write_scorecard_summary_no_env(tmp_path, monkeypatch):
    """Without $GITHUB_STEP_SUMMARY the summary write is a no-op."""
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    findings = [_base_finding()]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()
    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)

    # Should not raise.
    write_scorecard_summary(scorecard)


def test_write_scorecard_summary_uses_env(tmp_path, monkeypatch):
    """The summary path defaults to $GITHUB_STEP_SUMMARY."""
    summary_path = str(tmp_path / "gh_summary.md")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", summary_path)
    findings = [_base_finding()]
    report = _base_report(findings)
    scan_meta = _base_scan_meta()
    policy = _base_policy()
    args = _base_args()
    scorecard = build_scorecard(report, scan_meta, policy, scan_args=args)

    write_scorecard_summary(scorecard)
    assert os.path.exists(summary_path)


# --- Integration tests (through the CLI) ---


def _run_safeai(args, cwd=None):
    """Run the SafeAI CLI as a subprocess."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "..")
    return subprocess.run(
        [sys.executable, "-m", "safeai", "scan"] + args,
        cwd=cwd or os.path.join(os.path.dirname(__file__), ".."),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_scorecard_json(tmp_path):
    """--scorecard-json produces a valid JSON scorecard."""
    json_path = str(tmp_path / "scorecard.json")
    proc = _run_safeai([
        os.path.join(FIXTURES, "clean"),
        "--scorecard-json", json_path,
        "--no-registry",
    ])
    assert proc.returncode == 0
    with open(json_path, encoding="utf-8") as fh:
        data = json.load(fh)
    assert "safeai_security_scorecard" in data
    assert data["safeai_security_scorecard"]["summary"]["status"] == "warn"


def test_cli_scorecard_md(tmp_path):
    """--scorecard-md produces a valid Markdown scorecard."""
    md_path = str(tmp_path / "scorecard.md")
    proc = _run_safeai([
        os.path.join(FIXTURES, "clean"),
        "--scorecard-md", md_path,
        "--no-registry",
    ])
    assert proc.returncode == 0
    with open(md_path, encoding="utf-8") as fh:
        content = fh.read()
    assert "# SafeAI Security Scorecard" in content


def test_cli_scorecard_alias(tmp_path):
    """--scorecard is an alias for --scorecard-md."""
    md_path = str(tmp_path / "scorecard.md")
    proc = _run_safeai([
        os.path.join(FIXTURES, "clean"),
        "--scorecard", md_path,
        "--no-registry",
    ])
    assert proc.returncode == 0
    with open(md_path, encoding="utf-8") as fh:
        content = fh.read()
    assert "# SafeAI Security Scorecard" in content


def test_cli_scorecard_on_policy_failure(tmp_path):
    """The scorecard is still written when the scan fails with exit 1."""
    json_path = str(tmp_path / "scorecard.json")
    proc = _run_safeai([
        os.path.join(FIXTURES, "risky"),
        "--scorecard-json", json_path,
        "--no-registry",
    ])
    assert proc.returncode == 1
    assert os.path.exists(json_path)
    with open(json_path, encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["safeai_security_scorecard"]["summary"]["status"] == "fail"


def test_cli_scorecard_fail_under(tmp_path):
    """--scorecard-fail-under fails the scan when the score is below the threshold."""
    json_path = str(tmp_path / "scorecard.json")
    proc = _run_safeai([
        os.path.join(FIXTURES, "clean"),
        "--scorecard-json", json_path,
        "--scorecard-fail-under", "9.5",
        "--no-registry",
    ])
    # The clean fixture has 2 info findings, so the score is 10.0.
    # 10.0 >= 9.5, so the scan should pass.
    assert proc.returncode == 0


def test_cli_scorecard_fail_under_fails(tmp_path):
    """--scorecard-fail-under fails the scan when the score is below the threshold."""
    json_path = str(tmp_path / "scorecard.json")
    proc = _run_safeai([
        os.path.join(FIXTURES, "medium"),
        "--scorecard-json", json_path,
        "--scorecard-fail-under", "9.5",
        "--no-registry",
    ])
    # The medium fixture has 1 medium finding, so the score is 9.25.
    # 9.25 < 9.5, so the scan should fail.
    assert proc.returncode == 1


def test_cli_scorecard_fail_under_without_output_paths():
    """The fail-under gate works even when no scorecard files are requested."""
    proc = _run_safeai([
        os.path.join(FIXTURES, "medium"),
        "--scorecard-fail-under", "9.5",
        "--no-registry",
    ])
    # medium fixture score ~= 9.25, so this should fail via score gate.
    assert proc.returncode == 1


def test_cli_scorecard_fail_under_invalid():
    """--scorecard-fail-under rejects non-numeric values."""
    proc = _run_safeai([
        os.path.join(FIXTURES, "clean"),
        "--scorecard-fail-under", "not-a-number",
        "--no-registry",
    ])
    assert proc.returncode == 2
    assert "invalid float value" in proc.stderr


def test_cli_scorecard_fail_under_out_of_range(tmp_path):
    """--scorecard-fail-under rejects values outside [0, 10]."""
    json_path = str(tmp_path / "scorecard.json")
    proc = _run_safeai([
        os.path.join(FIXTURES, "clean"),
        "--scorecard-json", json_path,
        "--scorecard-fail-under", "15",
        "--no-registry",
    ])
    assert proc.returncode == 2
    assert "between 0 and 10" in proc.stderr


def test_cli_scorecard_no_silent_output(tmp_path):
    """Without a scorecard option, no scorecard files are written."""
    proc = _run_safeai([
        os.path.join(FIXTURES, "clean"),
        "--no-registry",
    ], cwd=str(tmp_path))
    assert proc.returncode == 0
    assert not (tmp_path / "safeai-scorecard.md").exists()
    assert not (tmp_path / "safeai-scorecard.json").exists()


def test_cli_scorecard_existing_behavior_preserved(tmp_path):
    """Existing SARIF/JSON/HTML outputs still work with scorecard options."""
    sarif_path = str(tmp_path / "results.sarif")
    json_path = str(tmp_path / "report.json")
    scorecard_path = str(tmp_path / "scorecard.md")
    proc = _run_safeai([
        os.path.join(FIXTURES, "clean"),
        "--sarif", sarif_path,
        "--json", json_path,
        "--scorecard", scorecard_path,
        "--no-registry",
    ])
    assert proc.returncode == 0
    assert os.path.exists(sarif_path)
    assert os.path.exists(json_path)
    assert os.path.exists(scorecard_path)


def test_cli_scorecard_severity_weights():
    """The severity weights match the documented model."""
    assert SEVERITY_WEIGHTS["critical"] == 4.0
    assert SEVERITY_WEIGHTS["high"] == 2.0
    assert SEVERITY_WEIGHTS["medium"] == 0.75
    assert SEVERITY_WEIGHTS["low"] == 0.25
    assert SEVERITY_WEIGHTS["info"] == 0.0


# --- Schema validation tests ---

SCHEMA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "safeai", "scorecard-schema.json"
)


def _load_schema():
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def test_scorecard_output_validates_against_schema():
    """build_scorecard output conforms to the published JSON schema."""
    import jsonschema

    findings = [_base_finding(severity="high")]
    report = _base_report(findings)
    scorecard = build_scorecard(report, _base_scan_meta(), _base_policy(), scan_args=_base_args())
    schema = _load_schema()
    jsonschema.validate(scorecard, schema)


def test_scorecard_schema_rejects_unknown_status():
    """Schema rejects an invalid status value."""
    import jsonschema

    schema = _load_schema()
    bad = {
        "safeai_security_scorecard": {
            "schema_version": 1,
            "summary": {"status": "INVALID", "score": 8.0},
        }
    }
    with pytest.raises(jsonschema.ValidationError, match="INVALID"):
        jsonschema.validate(bad, schema)


def test_scorecard_schema_rejects_missing_tool():
    """Schema rejects a scorecard missing the required tool object."""
    import jsonschema

    schema = _load_schema()
    bad = {
        "safeai_security_scorecard": {
            "schema_version": 1,
            "summary": {"status": "pass", "score": 10.0},
        }
    }
    with pytest.raises(jsonschema.ValidationError, match="tool"):
        jsonschema.validate(bad, schema)
