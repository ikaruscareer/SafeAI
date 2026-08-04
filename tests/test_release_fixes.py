"""Regression tests for release-blocking fixes: secret masking, path
relativization, directory exclusions, and CLI exit codes."""

import json
import os

import pytest

import safeai.engine.orchestrator as scan_engine
from safeai.analysis.capabilities import resolve_access_mode
from safeai.analyzers.data_leakage.analyzer import (
    DataLeakageAnalyzer,
    mask_secret_evidence,
)
from safeai.cmd.cli import main
from safeai.engine.scan import collect_files, run_scan


def test_secret_values_are_masked_in_evidence():
    file_cache = {"app.py": 'api_key = "sk-1234567890abcdef1234"\n'}
    findings = DataLeakageAnalyzer().run(file_cache, [])
    assert findings, "expected at least one finding"
    for finding in findings:
        assert "sk-1234567890abcdef1234" not in finding["evidence"]
        assert "MASKED" in finding["evidence"]


def test_mask_secret_evidence_keeps_prefix_only():
    masked = mask_secret_evidence('token = "ghp_abcdef1234567890"')
    assert "ghp_" in masked
    assert "abcdef1234567890" not in masked


def test_env_secret_reference_does_not_leak_name():
    masked = mask_secret_evidence('os.environ["DATABASE_URL"]')
    # Env var references contain no secret value; nothing should be redacted.
    assert "DATABASE_URL" in masked


def test_collect_files_excludes_noise_directories(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / ".git" / "config.yaml").write_text("x: 1")
    (tmp_path / "node_modules" / "package.json").write_text("{}")
    (tmp_path / "__pycache__" / "mod.py").write_text("x = 1")
    (tmp_path / "src" / "app.py").write_text("x = 1")

    files = collect_files(str(tmp_path))
    assert len(files) == 1
    assert files[0].endswith("app.py")


def test_collect_files_skips_oversized_files(tmp_path):
    big = tmp_path / "big.py"
    big.write_bytes(b"#" * (2 * 1024 * 1024 + 1))
    small = tmp_path / "small.py"
    small.write_text("x = 1")

    files = collect_files(str(tmp_path))
    names = [os.path.basename(f) for f in files]
    assert "small.py" in names
    assert "big.py" not in names


def test_scan_report_paths_are_relative(tmp_path):
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "app.py").write_text('api_key = "sk-1234567890abcdef1234"\n')

    report = run_scan(str(tmp_path))
    for finding in report["findings"]:
        assert not os.path.isabs(finding["file"]), finding["file"]
        assert "\\" not in finding["file"]
    assert any(f["file"].endswith("app.py") for f in report["findings"])


def test_cli_returns_exit_code_on_threshold(tmp_path, capsys):
    (tmp_path / "app.py").write_text(
        'api_key = "sk-1234567890abcdef1234"\n'
    )
    code = main(["scan", str(tmp_path), "--sarif", "", "--fail-on", "high"])
    assert code == 1


def test_cli_returns_zero_on_clean_project(tmp_path, capsys):
    (tmp_path / "app.py").write_text("print('hello')\n")
    code = main(["scan", str(tmp_path), "--sarif", "", "--fail-on", "critical"])
    assert code == 0


def test_claude_settings_with_safeai_markers_is_still_scanned(tmp_path):
    (tmp_path / "agent.py").write_text("print('ok')\n", encoding="utf-8")
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(
        json.dumps(
            {
                "manifest_type": "safeai.kya",
                "permissions": {"allow": ["Bash(*)"]},
                "permissionMode": "bypassPermissions",
            }
        ),
        encoding="utf-8",
    )

    report = run_scan(str(tmp_path))
    ids = {f["rule_id"] for f in report["findings"]}
    assert "CC_WILDCARD_PERMISSION" in ids
    assert "CC_BYPASS_PERMISSIONS" in ids


def test_collect_files_excludes_only_explicit_output_paths(tmp_path):
    (tmp_path / "agent.py").write_text("print('ok')\n", encoding="utf-8")
    kept = tmp_path / "kept.json"
    kept.write_text('{"manifest_type": "safeai.kya"}', encoding="utf-8")
    excluded = tmp_path / "scan-report.json"
    excluded.write_text('{"report_type": "safeai.scan"}', encoding="utf-8")

    files = collect_files(
        str(tmp_path),
        excluded_paths=[str(excluded)],
    )
    names = {os.path.basename(path) for path in files}
    assert "scan-report.json" not in names
    assert "kept.json" in names


def test_collect_files_rejects_symlink_escape_outside_root(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"permissions": {"allow": ["Bash(*)"]}}', encoding="utf-8")
    claude_dir = root / ".claude"
    claude_dir.mkdir()
    link = claude_dir / "settings.json"
    try:
        os.symlink(str(outside), str(link))
    except (AttributeError, NotImplementedError, OSError):
        pytest.skip("symlink creation not supported in this environment")
    (root / "agent.py").write_text("print('ok')\n", encoding="utf-8")

    report = run_scan(str(root))
    notes = report.get("skipped_files") or {}
    assert notes.get("outside scan root (symlink or path traversal)", 0) >= 1
    assert not any(f["rule_id"].startswith("CC_") for f in report["findings"])


def test_access_mode_inference_marks_heuristic_modes():
    capability = {
        "name": "external_apis",
        "category": "External APIs",
        "evidence": "post webhook payload",
    }
    mode = resolve_access_mode(capability)
    assert mode == "write"
    assert capability["access_mode_inferred"] is True


def test_collect_files_sorts_walk_order_deterministically(tmp_path, monkeypatch):
    (tmp_path / "b.py").write_text("print('b')\n", encoding="utf-8")
    (tmp_path / "a.py").write_text("print('a')\n", encoding="utf-8")

    real_walk = scan_engine.os.walk

    def reversed_walk(root):
        for directory, dirs, files in real_walk(root):
            yield directory, list(reversed(dirs)), list(reversed(files))

    monkeypatch.setattr(scan_engine.os, "walk", reversed_walk)
    files = collect_files(str(tmp_path))
    assert [os.path.basename(path) for path in files] == ["a.py", "b.py"]


def test_claude_permission_secret_is_redacted_in_json_report(tmp_path):
    secret = "supersecretvalue123"
    (tmp_path / "agent.py").write_text("print('ok')\n", encoding="utf-8")
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(
        json.dumps({"permissions": {"allow": [f"Bash(API_KEY={secret})"]}}),
        encoding="utf-8",
    )
    output = tmp_path / "report.json"
    rc = main(["scan", str(tmp_path), "--json", str(output), "--sarif", "", "--no-registry"])
    assert rc in (0, 1)
    raw = output.read_text(encoding="utf-8")
    assert secret not in raw
    assert "***MASKED***" in raw
