# How to Add an Analyzer

This guide walks you through creating a new analyzer that detects a specific category of risk.

---

## Analyzer Interface

Every analyzer must implement:

```python
class MyAnalyzer:
    name = "my_analyzer"

    def run(self, file_cache, rules, agent_models=None) -> list[dict]:
        """Analyze files and agent models, return list of findings."""
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `file_cache` | `dict[str, str]` | Path → file contents for all scanned files |
| `rules` | `list[dict]` | Loaded YAML rules |
| `agent_models` | `list[dict]` | Normalized Agent Models from all parsers |

**Returns:** `list[dict]` — findings (see below).

---

## Finding Structure

Each finding is a dictionary with these fields:

```python
{
    "rule_id": "MY_RULE_001",
    "severity": "high",                    # critical, high, medium, low, info
    "message": "Human-readable description",
    "file": "path/to/file.py",
    "line": 42,
    "owasp_llm": "LLM06",                  # OWASP LLM category reference
    "evidence": "suspicious_code_here()",
    "reason": "Why this is a risk",
    "risk_category": "Capability",         # Safety, Identity, Governance, etc.
    "affected_framework": "langgraph",
    "affected_capability": "Shell",
    "score_contribution": 15,
    "remediation": "How to fix the issue",
    "confidence": 0.85,                    # 0.0 to 1.0
}
```

---

## Complete Example: Governance Analyzer

This analyzer checks whether agent tools have timeout configurations.

```python
"""Governance analyzer — detects missing governance controls in agent configurations."""


class GovernanceAnalyzer:
    name = "governance"

    def run(self, file_cache, rules, agent_models=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}

        for model in agent_models or []:
            path = model.get("file")
            framework = model.get("framework") or "generic"
            data = model.get("data", {})
            tools = data.get("tools") or []

            for tool in tools:
                kwargs = tool.get("kwargs", {})
                tool_name = tool.get("name", "unknown")

                # Check for timeout configuration
                if "timeout" not in kwargs:
                    rule = rule_map.get("GOV_TIMEOUT_MISSING", {})
                    findings.append({
                        "rule_id": "GOV_TIMEOUT_MISSING",
                        "severity": rule.get("severity", "medium"),
                        "message": f"Tool '{tool_name}' is missing timeout configuration",
                        "file": path,
                        "line": tool.get("line", 1),
                        "owasp_llm": rule.get("owasp_llm", "LLM06"),
                        "evidence": str(kwargs) if kwargs else "no timeout parameter",
                        "reason": "Tools without timeouts can hang indefinitely, enabling resource exhaustion.",
                        "risk_category": "Governance",
                        "affected_framework": framework,
                        "affected_capability": "Tools",
                        "score_contribution": 8,
                        "remediation": "Add a timeout parameter to tool definitions.",
                        "confidence": 0.7,
                    })

                # Check for retry configuration
                if "retry" not in kwargs:
                    rule = rule_map.get("GOV_RETRY_MISSING", {})
                    findings.append({
                        "rule_id": "GOV_RETRY_MISSING",
                        "severity": rule.get("severity", "medium"),
                        "message": f"Tool '{tool_name}' is missing retry configuration",
                        "file": path,
                        "line": tool.get("line", 1),
                        "owasp_llm": rule.get("owasp_llm", "LLM06"),
                        "evidence": str(kwargs) if kwargs else "no retry parameter",
                        "reason": "Tools without retry policies may fail silently.",
                        "risk_category": "Governance",
                        "affected_framework": framework,
                        "affected_capability": "Tools",
                        "score_contribution": 6,
                        "remediation": "Add a retry policy to tool definitions.",
                        "confidence": 0.65,
                    })

        return findings
```

---

## Step 1: Create the Analyzer

```
safeai/analyzers/my_analyzer/
    __init__.py       # (optional)
    analyzer.py       # main analyzer logic
```

---

## Step 2: Add Rules

Add associated rules to `rules/base_rules.yaml`:

```yaml
- id: GOV_TIMEOUT_MISSING
  description: Agent tool missing timeout configuration
  severity: medium
  owasp_llm: LLM06

- id: GOV_RETRY_MISSING
  description: Agent tool missing retry configuration
  severity: medium
  owasp_llm: LLM06
```

---

## Step 3: Register the Analyzer

In `safeai/engine/scan.py`:

```python
from safeai.analyzers.my_analyzer.analyzer import GovernanceAnalyzer

analyzers = [
    CapabilityAnalyzer(),
    PromptAnalyzer(),
    DataLeakageAnalyzer(),
    MCPAnalyzer(),
    GovernanceAnalyzer(),  # <-- add yours here
]
for analyzer in analyzers:
    findings.extend(analyzer.run(file_cache, rules, agent_models))
```

---

## Step 4: Write Tests

```python
from safeai.analyzers.my_analyzer.analyzer import GovernanceAnalyzer


def test_governance_detects_missing_timeout():
    analyzer = GovernanceAnalyzer()
    file_cache = {}
    rules = []

    agent_models = [{
        "file": "test.py",
        "framework": "langgraph",
        "data": {
            "tools": [
                {"name": "run_shell", "kwargs": {}, "line": 10},
                {"name": "read_file", "kwargs": {"timeout": 30}, "line": 20},
            ]
        },
    }]

    findings = analyzer.run(file_cache, rules, agent_models)
    assert len(findings) >= 1
    assert any(f["rule_id"] == "GOV_TIMEOUT_MISSING" for f in findings)
    assert any("run_shell" in f["message"] for f in findings)
```

---

## Step 5: Integrate with Scoring

Your findings automatically flow into the scoring engine. Each finding's `score_contribution` and `severity` determine its impact on the trust score.

---

## Best Practices

1. **One finding per issue** — don't bundle multiple issues into one finding
2. **Include evidence** — show the actual code that triggered the finding
3. **Provide remediation** — tell the user how to fix it
4. **Set confidence appropriately** — AST-based detections get higher confidence than regex
5. **Test edge cases** — empty tools, missing kwargs, multiple frameworks
