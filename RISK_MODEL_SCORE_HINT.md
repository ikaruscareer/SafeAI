# Risk Model Interpretation Hint

This note should accompany the risk-model documentation and HTML report implementation.

The field `overall_ai_risk_score` is computed from weighted finding contributions and category aggregation. It is not calculated as the number of vulnerabilities. A single high finding can coexist with a score near 100 when:

- its `score_contribution` is limited;
- only one category is affected;
- other categories have no findings and remain at 100; or
- category scores are averaged or otherwise aggregated across mostly clean categories.

For example, a category contribution of 12 can produce a category score of approximately 88 under the current `100 - weighted_contributions` formula, while untouched categories remain 100. The aggregate may therefore remain in the high 90s.

The implementation and presentation should be aligned in a future scoring revision. Choose one consistent contract:

1. **Posture score:** higher is better; rename the HTML label and use green for high values; or
2. **Risk score:** higher is worse; invert the formula or presentation consistently and document the new behavior.

Until then, do not use `overall_ai_risk_score` as a release gate by itself. Gate on finding severity, policy outcome, new/regressed status, capability escalation, and coverage.
