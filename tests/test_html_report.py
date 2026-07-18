from safeai.report.html import write_html


def test_write_html_report(tmp_path):
    report = {
        "files_scanned": 3,
        "counts": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 1},
        "detected_frameworks": ["langchain"],
        "mcp_assets": [],
        "normalized_capabilities": [{
            "name": "shell_execution",
            "category": "Shell",
            "source_frameworks": ["langchain"],
            "confidence": 0.8,
            "evidence": ["subprocess.run"],
        }],
        "trust_score": {
            "overall_ai_risk_score": 72,
            "categories": {"Capability": 60, "Safety": 85},
        },
        "findings": [{
            "rule_id": "CAP_shell",
            "severity": "high",
            "file": "a.py",
            "line": 1,
            "message": "Capability discovered",
            "evidence": "subprocess.run",
            "remediation": "Restrict shell commands",
            "risk_category": "Capability",
        }],
    }

    out = tmp_path / "report.html"
    write_html(report, str(out))
    content = out.read_text(encoding="utf-8")
    assert "SafeAI Early Preview Report" in content
    assert "Executive Summary" in content
    assert "Capability Matrix" in content
