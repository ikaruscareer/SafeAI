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
        "capability_diff": {
            "schema_version": 2,
            "counts": {"added": 1, "removed": 0, "changed": 1, "escalations": 1},
            "highest_escalation": "high",
            "baseline_tool_attribution": True,
            "tools": [{
                "tool_key": "tool:shell-run",
                "status": "escalated",
                "access_summary": {"before": "read", "after": "write"},
                "escalations": [{"id": "ESC_WRITE_TOOL_ADDED", "severity": "high",
                                 "summary": "write capability added", "inferred": False}],
            }],
        },
        "tool_surface": [{
            "tool_key": "tool:shell-run",
            "kind": "tool",
            "framework": "langchain",
            "access_summary": "write",
            "capabilities": [{"name": "filesystem", "access_mode": "write",
                              "access_mode_inferred": False}],
        }],
        "policy_decision": {"outcome": "warn", "reasons": ["review shell usage"]},
        "kya_agents": [{
            "name": "agent-1",
            "agent_id": "agent-abc",
            "framework": "langchain",
            "agent_type": "agent",
            "confidence": 0.9,
            "capabilities": [{"name": "shell"}],
            "source_locations": [{"path": "a.py", "line_start": 1}],
        }],
        "assurance_boundary": {
            "summary": "Static evidence only.",
            "verified_statically": ["declared tools"],
            "not_verifiable_statically": ["runtime identity"],
            "coverage_notes": ["no files skipped"],
            "inferred_value_count": 0,
        },
        "baseline": {"new": 1, "existing": 2, "resolved": 0, "new_high_critical": 0},
    }

    out = tmp_path / "report.html"
    write_html(report, str(out))
    content = out.read_text(encoding="utf-8")
    assert "SafeAI Early Preview Report" in content
    assert "Executive Summary" in content
    assert "Capability Matrix" in content
    assert "Capability Escalations" in content
    assert "ESC_WRITE_TOOL_ADDED" in content
    assert "Highest escalation" in content
    assert "Tool Capability Surface" in content
    assert "Assurance boundary" in content
    assert "Know Your Agent (KYA)" in content
    assert "Policy outcome" in content
    assert "Trust Scores" in content
    assert "data-theme=\"light\"" in content


def test_html_escapes_user_data(tmp_path):
    report = {
        "files_scanned": 1,
        "counts": {},
        "detected_frameworks": [],
        "findings": [{
            "severity": "high",
            "file": "<script>alert('x')</script>.py",
            "line": 1,
            "message": "<img src=x onerror=alert(1)>",
        }],
        "normalized_capabilities": [],
        "trust_score": {"overall_ai_risk_score": 50, "categories": {}},
    }
    out = tmp_path / "escaped.html"
    write_html(report, str(out))
    content = out.read_text(encoding="utf-8")
    assert "<script>alert" not in content
    assert "<img src=x" not in content
    assert "&lt;script&gt;alert" in content
    assert "&lt;img" in content
