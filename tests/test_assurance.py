"""Assurance boundary.

v1.4 names tools and asserts their authority grew. These tests hold the
line on the other half of that claim: the boundary must be derived from
the scan that ran, must appear in every output format, and must never
harden into a fixed disclaimer.
"""

import json
import os

from safeai.cmd.cli import main
from safeai.engine.scan import run_scan
from safeai.kya.assurance import (
    NOT_VERIFIABLE_STATICALLY,
    VERIFIED_STATICALLY,
    build_assurance_boundary,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "claude_code")


def project(tmp_path, name="proj", extra=None):
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(
        "from langgraph.graph import StateGraph\nimport subprocess\n\n"
        "def run(x):\n    subprocess.run(x, shell=True)\n    return StateGraph(dict)\n",
        encoding="utf-8",
    )
    for filename, content in (extra or {}).items():
        target = root / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return str(root)


# --- shape ---------------------------------------------------------------


def test_boundary_has_the_documented_shape():
    boundary = build_assurance_boundary({})
    for key in ("verified_statically", "not_verifiable_statically",
                "coverage_notes", "inferred_value_count"):
        assert key in boundary
    assert boundary["verified_statically"] == list(VERIFIED_STATICALLY)
    assert boundary["not_verifiable_statically"] == list(NOT_VERIFIABLE_STATICALLY)
    assert isinstance(boundary["inferred_value_count"], int)


def test_runtime_claims_are_explicitly_out_of_scope():
    boundary = build_assurance_boundary({})
    joined = " ".join(boundary["not_verifiable_statically"])
    assert "IAM" in joined
    assert "runtime identity" in joined
    assert "network policy" in joined


def test_empty_report_never_raises():
    assert build_assurance_boundary(None)["coverage_notes"]


# --- derived from the real scan ------------------------------------------


def test_skipped_file_types_are_counted(tmp_path):
    root = project(tmp_path, extra={
        "notes.txt": "not scanned",
        "image.png": "not scanned either",
        "other.txt": "nor this",
    })
    boundary = run_scan(root)["assurance_boundary"]
    notes = " ".join(boundary["coverage_notes"])
    assert "unsupported file type .txt" in notes
    assert "2 files not read" in notes
    assert "unsupported file type .png" in notes


def test_parse_failures_are_named(tmp_path):
    root = project(tmp_path, extra={".claude/settings.json": '{"permissions": {'})
    boundary = run_scan(root)["assurance_boundary"]
    notes = " ".join(boundary["coverage_notes"])
    assert "could not be parsed" in notes
    assert ".claude/settings.json" in notes


def test_clean_scan_says_so_rather_than_staying_silent(tmp_path):
    root = project(tmp_path)
    boundary = run_scan(root)["assurance_boundary"]
    assert boundary["coverage_notes"]
    if boundary["inferred_value_count"] == 0:
        expected = (
            "no files were skipped, no configuration failed to parse, and no "
            "access mode was inferred in this scan"
        )
        assert boundary["coverage_notes"] == [expected]
    else:
        notes = " ".join(boundary["coverage_notes"])
        assert "inferred from naming or usage patterns" in notes


def test_inferred_access_modes_are_counted():
    report = {
        "tool_surface": [
            {"tool_key": "tool:mystery", "capabilities": [
                {"name": "external_apis", "access_mode": "read", "inferred": True},
                {"name": "shell", "access_mode": "execute", "inferred": False},
            ]},
            {"tool_key": "tool:other", "capabilities": [
                {"name": "memory", "access_mode": "write", "inferred": True},
            ]},
        ]
    }
    boundary = build_assurance_boundary(report)
    assert boundary["inferred_value_count"] == 2
    notes = " ".join(boundary["coverage_notes"])
    assert "inferred from naming or usage patterns" in notes
    assert "tool:mystery" in notes and "tool:other" in notes


def test_boundary_is_not_a_hardcoded_string(tmp_path):
    """Two different repositories must produce different coverage notes."""
    clean = run_scan(project(tmp_path, "clean"))["assurance_boundary"]
    noisy = run_scan(project(tmp_path, "noisy", extra={"a.txt": "x"}))["assurance_boundary"]
    assert clean["coverage_notes"] != noisy["coverage_notes"]


def test_pre_attribution_baseline_is_disclosed(tmp_path):
    report = {
        "capability_diff": {
            "baseline_available": True,
            "baseline_tool_attribution": False,
            "unattributed": {"capabilities_added": [{"name": "shell"}]},
        }
    }
    notes = " ".join(build_assurance_boundary(report)["coverage_notes"])
    assert "predates per-tool attribution" in notes
    assert "could not be attributed to a named tool" in notes


def test_boundary_is_deterministic(tmp_path):
    root = project(tmp_path, extra={"a.txt": "x", ".claude/settings.json": "{"})
    first = run_scan(root)["assurance_boundary"]
    second = run_scan(root)["assurance_boundary"]
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# --- present in every output format --------------------------------------


def test_boundary_in_the_json_report(tmp_path):
    root = project(tmp_path, extra={"a.txt": "x"})
    json_path = str(tmp_path / "report.json")
    main(["scan", root, "--json", json_path, "--no-registry",
          "--sarif", str(tmp_path / "r.sarif")])

    with open(json_path, encoding="utf-8") as handle:
        report = json.load(handle)
    assert report["assurance_boundary"]["verified_statically"]
    assert "unsupported file type .txt" in " ".join(
        report["assurance_boundary"]["coverage_notes"]
    )


def test_boundary_in_the_manifest(tmp_path):
    from safeai.kya import MANIFEST_SCHEMA_VERSION

    root = project(tmp_path, extra={"a.txt": "x"})
    manifest_path = str(tmp_path / "safeai-manifest.json")
    main(["scan", root, "--manifest", manifest_path, "--no-registry",
          "--sarif", str(tmp_path / "r.sarif")])

    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["schema_version"] == MANIFEST_SCHEMA_VERSION == "1.2"
    boundary = manifest["assurance_boundary"]
    assert boundary["not_verifiable_statically"]
    assert "unsupported file type .txt" in " ".join(boundary["coverage_notes"])
    # The single-line limitation is kept, not duplicated as prose.
    assert isinstance(manifest["limitations"], list)


def test_boundary_in_the_html_report(tmp_path):
    root = project(tmp_path, extra={"a.txt": "x"})
    html_path = str(tmp_path / "report.html")
    main(["scan", root, "--html", html_path, "--no-registry",
          "--sarif", str(tmp_path / "r.sarif")])

    with open(html_path, encoding="utf-8") as handle:
        html = handle.read()
    assert "Assurance boundary" in html
    assert "Not verifiable statically" in html
    assert "unsupported file type .txt" in html
    assert "IAM and cloud permissions" in html


def test_boundary_in_the_pr_comment(tmp_path):
    from safeai.report.pr_comment import render_pr_comment

    report = run_scan(project(tmp_path, extra={"a.txt": "x"}))
    report["assurance_boundary"]["inferred_value_count"] = 3
    text = render_pr_comment(report)
    assert "cannot verify deployed IAM permissions" in text
    assert "3 access modes in this scan were inferred" in text


def test_boundary_in_the_terminal_summary(tmp_path, capsys):
    root = project(tmp_path, extra={"a.txt": "x"})
    main(["scan", root, "--no-registry", "--sarif", str(tmp_path / "r.sarif")])
    out = capsys.readouterr().out
    assert "Coverage:" in out
    assert "unsupported file type .txt" in out
