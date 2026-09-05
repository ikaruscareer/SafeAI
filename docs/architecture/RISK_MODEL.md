# SafeAI — Risk & Scoring Model

This document is the single reference for how SafeAI scores risk. It covers the
0–100 **Trust Score**, the 0–10 **Security Scorecard**, the risk categories,
severity interpretation, and how to read the numbers safely.

---

## Two Scores in SafeAI

SafeAI produces two distinct scores. Do not conflate them:

| | Trust Score | Security Scorecard |
|---|---|---|
| **Range** | 0–100 | 0–10 |
| **Direction** | Higher = cleaner (posture-style) | Higher = better (10 = no findings) |
| **Computed by** | `safeai/scoring/engine.py` | `safeai/scorecard.py` |
| **Report key** | `overall_ai_risk_score` | `safeai_security_scorecard.summary.score` |
| **Output** | Terminal / JSON / HTML | `--scorecard`, `--scorecard-json`, `--scorecard-summary` |
| **CI gate** | Not a gate by itself | `--scorecard-fail-under N` |
| **Introduced** | v1.0 | v1.6 |

The **Trust Score** is a per-category posture aggregate (see below). The
**Security Scorecard** is a reviewer-facing 0–10 summary with a
`pass`/`warn`/`fail` outcome; its model is documented in `safeai/scorecard.py`
and its contract in `safeai/scorecard-schema.json`.

---

## Risk Assessment Philosophy

SafeAI performs **static risk assessment** by analyzing source code,
configuration files, and dependency manifests. It evaluates:

- **What capabilities** does the AI system expose?
- **What governance controls** are in place?
- **What security patterns** indicate risk (prompt injection, secrets, autonomy)?

SafeAI does not execute code, call models, or perform runtime testing. Findings
are based on static evidence.

---

## Risk Categories

The Trust Score categorizes findings into **7 risk categories** (defined in
`safeai/scoring/engine.py`, default weight `1.0` each):

| # | Category | Evaluates | Example sub-factors |
|---|----------|-----------|---------------------|
| 1 | **Capability** | Breadth/risk of exposed capabilities | shell, filesystem, network, database, code execution |
| 2 | **Governance** | Security controls in MCP/agent config | authentication, permissions, audit, rate limiting |
| 3 | **Safety** | Prompt security & instruction boundaries | injection, delimiters, system leak, role override |
| 4 | **Identity** | Credential exposure & secret management | hardcoded keys/tokens/passwords, env secrets |
| 5 | **Integration** | External service / MCP risk | MCP config, endpoint exposure, dangerous tools |
| 6 | **Autonomy** | Autonomous behaviour patterns | unbounded loops, recursive planning |
| 7 | **Enterprise Readiness** | Production/operational controls | approval gates, timeouts, retry policies |

---

## Severity Levels

Severity vocabulary and point values live in `safeai/severity.py` (the single
source of truth shared by the CLI, escalation engine, policy evaluator, scorers,
and renderers).

| Severity | Meaning | Point Value |
|----------|---------|-------------|
| Critical | Immediate risk of compromise | 25 |
| High | Significant capability exposure | 15 |
| Medium | Moderate risk | 8 |
| Low | Minor / informational | 4 |
| Info | Scanner metadata | 1 |

---

## Trust Score Calculation

The Trust Score is a deterministic, weighted model producing a 0–100 score per
category and an overall score.

### Formula

```
category_score = clamp(100 - sum(weighted_contributions), 0, 100)
overall_score  = average(category_scores)
```

### Step-by-Step

1. **Collect findings** — all findings identified during the scan.
2. **Determine risk category** — each finding maps to one of the 7 categories.
3. **Calculate contribution** — each finding contributes points by severity (or
   an explicit `score_contribution`).
4. **Apply weight** — contribution × category weight (default 1.0).
5. **Sum penalties** — total penalty per category accumulates.
6. **Compute category score** — `100 - penalty`, clamped to 0–100.
7. **Compute overall score** — average of all category scores.

### Example Calculation

| Finding | Category | Severity | Contribution | Weight | Weighted Impact |
|---------|----------|----------|-------------|--------|----------------|
| Prompt injection | Safety | Critical | 18 | 1.0 | 18 |
| Capability: shell | Capability | High | 12 | 1.0 | 12 |
| MCP missing auth | Integration | High | 15 | 1.0 | 15 |
| Hardcoded API key | Identity | High | 16 | 1.0 | 16 |
| Autonomous loop | Autonomy | High | 12 | 1.0 | 12 |

**Resulting category scores:**

| Category | Penalty | Score (100 - penalty) |
|----------|---------|---------------------|
| Capability | 12 | 88 |
| Integration | 15 | 85 |
| Safety | 18 | 82 |
| Identity | 16 | 84 |
| Autonomy | 12 | 88 |
| Governance | 0 | 100 |
| Enterprise Readiness | 0 | 100 |

**Overall:** (88 + 85 + 82 + 84 + 88 + 100 + 100) / 7 = **90**

---

## Reading the Score

### Score direction warning (important)

The Trust Score field is named `overall_ai_risk_score`, but the formula
(`100 - weighted_contributions`) makes a **high number mean a cleaner project**,
like a posture score. The HTML gauge colors higher values as worse, which is the
opposite direction. Because untouched categories score 100 and are averaged in,
a repository with one high finding can still show an aggregate near 100.

**Until the naming and direction are aligned, treat the headline number as a
triage/posture indicator only.** Do not use `overall_ai_risk_score` as a release
gate by itself — gate on finding severity, policy outcome, new/regressed status,
capability escalation, coverage, or the Security Scorecard's
`--scorecard-fail-under`.

### HTML gauge bands

The HTML report's `Overall AI Risk Score` gauge uses these visual bands:

| Score | Gauge band | Operational interpretation |
|---:|---|---|
| 0–24 | Green | Low aggregate static-risk signal; continue normal review |
| 25–49 | Yellow | Moderate signal; review material findings before release |
| 50–79 | Orange | High signal; require security/senior engineering review |
| 80–100 | Red | Very high apparent signal per the gauge; investigate before deployment |

### Review checklist

Read the findings before trusting any aggregate:

1. All **critical** findings.
2. All **high** findings.
3. **New or regressed** findings (vs baseline).
4. Secrets, credentials, private endpoints, sensitive configuration.
5. **Capability escalations** involving shell, filesystem, network, data, MCP,
   or external tools.
6. **Coverage limitations** and skipped analyzers (assurance boundary).

A high aggregate number must never override a critical or high finding.

### Safe wording

> Use: "SafeAI identified a finding requiring maintainer review."

Do not state that SafeAI proved a project vulnerable unless an authorised human
reviewer independently validates the issue and the disclosure policy permits the
claim. SafeAI cannot verify deployed IAM, runtime identity, network policy,
actual runtime behaviour, or dynamically constructed bindings.

---

## Explainability

Every finding includes fields that explain its contribution:

```json
{
  "rule_id": "CAP_shell",
  "severity": "high",
  "message": "Capability discovered: shell_execution",
  "evidence": "subprocess.run('ls')",
  "reason": "Capability derived from confidence-arbitrated framework semantic discovery.",
  "risk_category": "Capability",
  "affected_framework": "langchain, openai_agents",
  "affected_capability": "Shell",
  "score_contribution": 12,
  "remediation": "Review this capability and restrict access paths where possible.",
  "confidence": 0.9,
  "source": "ast"
}
```

The scanner output includes an `explainability` section with per-category
contribution details:

```json
{
  "explainability": {
    "Capability": [
      { "rule_id": "CAP_shell", "severity": "high", "contribution": 12.0 }
    ],
    "Integration": [
      { "rule_id": "MCP_AUTH_MISSING", "severity": "high", "contribution": 15.0 }
    ]
  }
}
```

---

## Custom Weights

Category weights can be customized by supplying rules with weight
configurations. The default weight for all categories is `1.0`. Weights act as
multipliers on the penalty contribution.

```json
{
  "category_weights": {
    "Capability": 2.0,
    "Governance": 1.0,
    "Safety": 1.0,
    "Identity": 1.5,
    "Integration": 1.5,
    "Autonomy": 1.2,
    "Enterprise Readiness": 1.0
  }
}
```

---

## Limitations

1. **Static-only analysis** — cannot detect runtime-configurable capabilities.
2. **Heuristic detection** — unconventional patterns may be missed.
3. **No dynamic scoring** — scores are based solely on static evidence.
4. **Equal default weights** — all categories weigh equally by default; custom
   weights are not yet exposed via CLI.
5. **False positive impact** — false positives inflate the penalty.
6. **Direction ambiguity** — the Trust Score naming/direction is not yet aligned
   with the HTML gauge (see "Reading the Score"). Prefer the Security Scorecard
   for CI gating.
