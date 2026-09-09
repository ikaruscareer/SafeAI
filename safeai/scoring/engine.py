"""Deterministic risk scoring engine for SafeAI findings.

The trust score is a 0-100 value computed per risk category, then
averaged for an overall score. Each finding contributes a weighted
penalty based on its severity and the category's configured weight.
The result is deterministic: identical findings always produce the
same score.
"""

from safeai.severity import SEVERITY_POINTS

CATEGORY_WEIGHTS = {
    "Capability": 1.2,      # Core agent capabilities - high impact on trust
    "Governance": 1.0,      # Operational controls - moderate impact
    "Safety": 1.3,          # Safety-critical findings - highest impact
    "Identity": 1.1,        # Identity/auth issues - significant impact
    "Integration": 1.0,     # External integrations - moderate impact
    "Autonomy": 1.2,        # Autonomous decision-making - high impact
    "Enterprise Readiness": 0.8,  # Enterprise features - lower impact
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

    penalties = {k: 0.0 for k in weights}
    breakdown = {k: [] for k in weights}

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
        score = 100 - round(penalty)
        category_scores[category] = max(0, min(100, score))

    overall = round(sum(category_scores.values()) / len(category_scores)) if category_scores else 100

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
