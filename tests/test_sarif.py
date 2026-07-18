import json
from safeai.report.sarif import write_sarif


def test_sarif_structure(tmp_path):
    report = {
        "findings": [
            {
                "rule_id": "TEST",
                "message": "msg",
                "file": "a.py",
                "line": 1,
                "severity": "low",
                "owasp_llm": "LLM01",
            }
        ],
        "counts": {},
    }

    out = tmp_path / "out.sarif"
    write_sarif(report, str(out))

    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    assert "runs" in data
