from safeai.scoring.engine import score_report


def test_scoring_engine_returns_category_scores():
    findings = [
        {"severity": "high", "rule_id": "A", "risk_category": "Capability", "score_contribution": 10},
        {"severity": "critical", "rule_id": "B", "risk_category": "Identity", "score_contribution": 20},
    ]
    scored = score_report(findings)
    assert "categories" in scored
    assert "overall_ai_risk_score" in scored
    assert 0 <= scored["overall_ai_risk_score"] <= 100
