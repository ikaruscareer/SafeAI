# SafeAI Score Interpretation

## HTML `Overall AI Risk Score`

The HTML report displays a 0–100 aggregate called `Overall AI Risk Score`. It is a static-analysis triage indicator, not a percentage probability of compromise, a vulnerability count, or proof of exploitability.

The current HTML gauge uses these visual bands:

| Score | Gauge band | Operational interpretation |
|---:|---|---|
| 0–24 | Green | Low aggregate static-risk signal; continue normal review. |
| 25–49 | Yellow | Moderate signal; review material findings before release. |
| 50–79 | Orange | High signal; require security or senior engineering review. |
| 80–100 | Red | Very high apparent signal according to the gauge; investigate before deployment. |

## Important direction warning

The current implementation contains a naming-direction ambiguity. The HTML gauge colors higher values as worse, but the scoring model calculates category scores using a form of:

```text
category_score = clamp(100 - weighted_contributions, 0, 100)
```

That formula makes a high number look more like a clean security/posture score. Consequently, a report can show one high-severity finding and an aggregate value near 100 when most other categories are empty or score 100.

Until the scoring direction is made consistent, treat the headline value as an aggregate posture/triage indicator and treat the individual findings, severity, evidence, confidence, and coverage as authoritative.

## Review order

1. Critical findings.
2. High findings.
3. New or regressed findings.
4. Secrets, credentials, private endpoints, and sensitive configuration.
5. Capability escalations involving shell, filesystem, network, data, MCP, or external tools.
6. Coverage limitations and skipped analyzers.

A high aggregate number must never override a critical or high finding.

## Safe wording

Use:

> SafeAI identified a finding requiring maintainer review.

Do not state that SafeAI proved a project vulnerable unless an authorised human reviewer independently validates the issue and the disclosure policy permits that claim.

SafeAI cannot verify deployed IAM, runtime identity, network policy, actual runtime behavior, or dynamically constructed bindings.