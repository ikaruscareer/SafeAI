"""Deterministic risk scoring engine for SafeAI findings.

The trust score is a 0-100 value computed per risk category, then
averaged for an overall score. Each finding contributes a weighted
penalty based on its severity and the category's configured weight.
The result is deterministic: identical findings always produce the
same score.
"""

SEVERITY_POINTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 4,
    "info": 1,
}

CATEGORY_WEIGHTS = {
    "Capability": 1.0,
    "Governance": 1.0,
    "Safety": 1.0,
    "Identity": 1.0,
    "Integration": 1.0,
    "Autonomy": 1.0,
    "Enterprise Readiness": 1.0,
}


def _normalize_category(cat):
    """Map varied risk category strings to the canonical set of 7 categories."""
    if not cat:
        return "Capability"
    known = {
        "capability": "Capability",
        "governance": "Governance",
        "safety": "Safety",
        "identity": "Identity",
        "integration": "Integration",
        "autonomy": "Autonomy",
        "enterprise readiness": "Enterprise Readiness",
    }
    return known.get(cat.strip().lower(), "Capability")


def score_report(findings, config_weights=None):
    """Compute category scores and an overall AI risk score from findings.

    Each finding's ``score_contribution`` is multiplied by the category
    weight, summed as a penalty, then subtracted from 100 (clamped to
    0-100). The overall score is the unweighted average of all category
    scores.
    """
    weights = dict(CATEGORY_WEIGHTS)
    if config_weights:
        weights.update(config_weights)

    penalties = {k: 0.0 for k in weights.keys()}
    breakdown = {k: [] for k in weights.keys()}

    for finding in findings:
        category = _normalize_category(finding.get("risk_category"))
        sev_points = SEVERITY_POINTS.get(finding.get("severity", "medium"), 8)
        contribution = finding.get("score_contribution")
        if contribution is None:
            contribution = sev_points
        weighted = float(contribution) * float(weights.get(category, 1.0))
        penalties[category] += weighted
        breakdown[category].append({
            "rule_id": finding.get("rule_id"),
            "severity": finding.get("severity"),
            "contribution": weighted,
        })

    category_scores = {}
    for category, penalty in penalties.items():
        score = 100 - int(round(penalty))
        category_scores[category] = max(0, min(100, score))

    overall = int(round(sum(category_scores.values()) / len(category_scores))) if category_scores else 100

    return {
        "categories": category_scores,
        "overall_ai_risk_score": overall,
        "explainability": breakdown,
        "model": {
            "severity_points": SEVERITY_POINTS,
            "category_weights": weights,
            "formula": "category_score = clamp(100 - sum(weighted_contributions), 0, 100)",
        },
    }
