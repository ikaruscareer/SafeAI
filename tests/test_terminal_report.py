import io
import sys

from safeai.report.terminal import _sanitize, print_summary


def _clean_report(findings=None):
    return {
        "files_scanned": 3,
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "detected_frameworks": ["langchain"],
        "mcp_assets": [],
        "trust_score": {"overall_ai_risk_score": 12},
        "findings": findings or [],
    }


def test_sanitize_strips_ansi_clear_screen():
    # \x1b[2J is the ANSI "clear screen" sequence — must not survive.
    assert _sanitize("\x1b[2J") == ""


def test_sanitize_strips_osc_title():
    # \x1b]0;pwned\x07 sets the terminal window title — must not survive.
    result = _sanitize("\x1b]0;pwned\x07")
    assert "\x1b" not in result
    assert "pwned" not in result


def test_sanitize_preserves_clean_input_byte_identical():
    clean = "a.py:12 - Capability discovered"
    assert _sanitize(clean) == clean


def test_sanitize_strips_crlf_and_csi():
    # Raw carriage-return control char is stripped; text around it survives.
    assert _sanitize("abc\rdef\x1b[0m") == "abcdef"


def test_sanitize_passes_through_non_str():
    assert _sanitize(123) == 123


def test_sanitize_strips_unsupported_escape_forms():
    # ESC forms the main pattern does not recognize must still not survive:
    # \x1b!p is DECSTR (soft terminal reset), \x1b(B is charset selection,
    # and a dangling ESC at end-of-string must not reach the terminal.
    assert _sanitize("\x1b!p") == "!p"
    assert _sanitize("\x1b(Blang") == "(Blang"
    assert _sanitize("abc\x1b") == "abc"
    assert _sanitize("\x1b text") == " text"


def test_print_summary_does_not_clear_screen(tmp_path, monkeypatch):
    report = _clean_report(findings=[{
        "rule_id": "CAP_shell",
        "severity": "high",
        "file": "a.py",
        "line": 1,
        "message": "\x1b[2J cleared",
        "remediation": "Restrict shell commands",
    }])
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    print_summary(report)
    out = buf.getvalue()
    assert "\x1b" not in out
    # The finding message is still present but escaped out.
    assert "cleared" in out


def test_print_summary_does_not_set_terminal_title(tmp_path, monkeypatch):
    report = _clean_report(findings=[{
        "rule_id": "CAP_shell",
        "severity": "high",
        "file": "\x1b]0;pwned\x07real.py",
        "line": 1,
        "message": "Capability discovered",
        "remediation": "Restrict",
    }])
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    print_summary(report)
    out = buf.getvalue()
    assert "\x1b" not in out
    assert "pwned" not in out


def test_print_summary_clean_report_byte_identical(tmp_path, monkeypatch):
    report = _clean_report(findings=[{
        "rule_id": "CAP_shell",
        "severity": "high",
        "file": "a.py",
        "line": 1,
        "message": "Capability discovered",
        "remediation": "Restrict shell commands",
    }])
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    print_summary(report)
    # Pinned literal: clean input must render exactly this, byte for byte.
    assert buf.getvalue() == (
        "SafeAI Scan Summary\n"
        "Files: 3\n"
        "Frameworks: langchain\n"
        "MCP assets: 0\n"
        "Overall AI Risk Score: 12\n"
        "critical: 0\n"
        "high: 0\n"
        "medium: 0\n"
        "low: 0\n"
        "info: 0\n"
        "Findings:\n"
        "[high] a.py:1 - Capability discovered\n"
        "  Next: Restrict shell commands\n"
    )
