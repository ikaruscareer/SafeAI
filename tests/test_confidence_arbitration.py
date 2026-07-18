from safeai.analyzers.capability.analyzer import CapabilityAnalyzer


def test_capability_confidence_arbitration_merges_frameworks():
    agent_models = [
        {
            "file": "a.py",
            "framework": "langchain",
            "data": {
                "capabilities": [
                    {"name": "shell_execution", "category": "Shell", "confidence": 0.6, "evidence": "tool A", "source": "ast"}
                ]
            },
        },
        {
            "file": "a.py",
            "framework": "openai_agents",
            "data": {
                "capabilities": [
                    {"name": "shell_execution", "category": "Shell", "confidence": 0.9, "evidence": "tool B", "source": "configuration"}
                ]
            },
        },
    ]
    findings = CapabilityAnalyzer().run({"a.py": ""}, rules=[], agent_models=agent_models)
    cap_findings = [f for f in findings if f.get("rule_id") == "CAP_shell"]
    assert len(cap_findings) == 1
    merged = cap_findings[0]
    assert merged["confidence"] == 0.9
    assert "langchain" in merged["affected_framework"]
    assert "openai_agents" in merged["affected_framework"]
