# SafeAI — Risk Model

This document explains how SafeAI calculates risk scores, the categories used, severity interpretation, and the mathematical model behind the Trust Score.

---

## Risk Assessment Philosophy

SafeAI performs **static risk assessment** by analyzing source code, configuration files, and dependency manifests. It evaluates:

- **What capabilities** does the AI system expose?
- **What governance controls** are in place?
- **What security patterns** indicate risk (prompt injection, secrets, autonomy)?

SafeAI does not execute code, call models, or perform runtime testing. Findings are based on static evidence.

---

## Risk Categories

SafeAI categorizes findings into **7 risk categories**. Each category contributes to the overall Trust Score.

### 1. Capability

**Evaluates:** The breadth and risk level of agent capabilities exposed.

| Sub-factors | Description |
|-------------|-------------|
| Shell execution | Capability to run OS commands |
| Filesystem access | Capability to read/write files |
| Network access | Capability to make HTTP requests |
| Database access | Capability to query databases |
| Code execution | Capability to run arbitrary code |

**Default weight:** 1.0

### 2. Governance

**Evaluates:** Presence of security controls in MCP and agent configurations.

| Sub-factors | Description |
|-------------|-------------|
| Authentication | MCP auth configuration |
| Permissions | MCP permission model |
| Audit trails | Logging and audit configuration |
| Rate limiting | Request rate controls |

**Default weight:** 1.0

### 3. Safety

**Evaluates:** Prompt security and instruction boundary protection.

| Sub-factors | Description |
|-------------|-------------|
| Prompt injection | Untrusted input in prompts |
| Missing delimiters | System/user concatenation |
| System leak | Exposure of system prompts |
| Role override | Instruction override attempts |

**Default weight:** 1.0

### 4. Identity

**Evaluates:** Credential exposure and secret management.

| Sub-factors | Description |
|-------------|-------------|
| Hardcoded API keys | API key literal in source |
| Hardcoded tokens | Token literal in source |
| Hardcoded passwords | Password literal in source |
| Environment secrets | Credential environment variables |

**Default weight:** 1.0

### 5. Integration

**Evaluates:** Risk from external service integrations, especially MCP.

| Sub-factors | Description |
|-------------|-------------|
| MCP configuration | MCP server/client definitions |
| MCP endpoint exposure | Public or insecure endpoints |
| MCP dangerous tools | Shell/exec tools |
| External service usage | GitHub, Slack, email, DB |

**Default weight:** 1.0

### 6. Autonomy

**Evaluates:** Autonomous agent behavior patterns.

| Sub-factors | Description |
|-------------|-------------|
| Infinite loops | `while True` with agent operations |
| Bounded loops | `for _ in range(...)` with agent operations |
| Recursive planning | Self-referencing agent calls |

**Default weight:** 1.0

### 7. Enterprise Readiness

**Evaluates:** Production readiness and operational controls.

| Sub-factors | Description |
|-------------|-------------|
| Human approval | Approval gate configuration |
| Rate limiting | Request limits |
| Timeouts | Execution timeout configuration |
| Retry policies | Error handling patterns |

**Default weight:** 1.0

---

## Severity Levels

Each finding has a severity level that determines its contribution to the risk score.

| Severity | Meaning | Point Value (default) |
|----------|---------|----------------------|
| Critical | Immediate risk of compromise | 25 |
| High | Significant capability exposure | 15 |
| Medium | Moderate risk | 8 |
| Low | Informational | 4 |
| Info | Scanner metadata | 1 |

---

## Trust Score Calculation

The Trust Score is a deterministic, weighted model that produces a 0–100 score for each category and an overall score.

### Formula

```
category_score = clamp(100 - sum(weighted_contributions), 0, 100)
overall_score = average(category_scores)
```

### Step-by-Step

1. **Collect findings** — All findings identified during the scan
2. **Determine risk category** — Each finding maps to one of 7 categories
3. **Calculate contribution** — Each finding contributes points based on severity and optional `score_contribution` field
4. **Apply weight** — Contribution is multiplied by the category weight (default 1.0, configurable)
5. **Sum penalties** — Total penalty per category accumulates
6. **Compute category score** — `100 - penalty`, clamped to 0–100
7. **Compute overall score** — Average of all category scores

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

**Overall AI Risk Score:** (88 + 85 + 82 + 84 + 88 + 100 + 100) / 7 = **90**

---

## Score Interpretation

| Score Range | Risk Level | Recommended Action |
|-------------|------------|-------------------|
| 0–20 | Excellent | Continue monitoring |
| 21–40 | Good | Review findings |
| 41–60 | Moderate | Prioritize high/critical findings for remediation |
| 61–80 | Significant | Remediate before deployment |
| 81–100 | Critical | Stop deployment, remediate immediately |

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

### Explainability Breakdown

The scanner output includes an `explainability` section with per-category contribution details:

```json
{
  "explainability": {
    "Capability": [
      {
        "rule_id": "CAP_shell",
        "severity": "high",
        "contribution": 12.0
      }
    ],
    "Integration": [
      {
        "rule_id": "MCP_AUTH_MISSING",
        "severity": "high",
        "contribution": 15.0
      }
    ]
  }
}
```

---

## Custom Weights

Category weights can be customized by supplying rules with weight configurations. The default weight for all categories is 1.0. Weights act as multipliers on the penalty contribution.

**Example:** Doubling the weight of the `Capability` category:

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

## Risk Model Limitations

1. **Static-only analysis** — The risk model cannot detect runtime-configurable capabilities
2. **Heuristic detection** — Some capabilities may be missed if they use unconventional patterns
3. **No dynamic scoring** — Trust scores are based solely on static evidence
4. **Equal default weights** — All categories weigh equally by default; custom weights are not yet exposed via CLI
5. **False positive impact** — False positive findings inflate the risk score
