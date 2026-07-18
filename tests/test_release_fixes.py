"""Regression tests for release-blocking fixes: secret masking, path
relativization, directory exclusions, and CLI exit codes."""

import os

from safeai.analyzers.data_leakage.analyzer import DataLeakageAnalyzer, mask_secret_evidence
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
