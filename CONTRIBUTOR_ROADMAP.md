# Contributor Roadmap

A learning path from first-time contributor to core maintainer.

---

## Level 1 — Add a Rule

**Difficulty:** Beginner  
**Knowledge required:** Basic Python, YAML  
**Estimated time:** 1–2 hours

### What you'll learn
- How SafeAI rules are structured (YAML)
- How rules are loaded and matched against findings
- How severity and OWASP categories work

### Tasks
- Add a new rule to `rules/base_rules.yaml`
- Write a detection pattern in an existing analyzer
- Test that the rule fires on matching code

### Example
```yaml
- id: SAFEAI-CUSTOM-001
  description: Detects unsafe eval() usage
  severity: critical
  owasp_llm: LLM06
```

### Recommended files
- `rules/base_rules.yaml`
- `analyzers/capability/analyzer.py`
- `tests/test_scan_phase11.py`

---

## Level 2 — Add Capability Detection

**Difficulty:** Beginner–Intermediate  
**Knowledge required:** Regular expressions, basic AST  
**Estimated time:** 2–4 hours

### What you'll learn
- The capability model (name, category, confidence, evidence)
- How regex and AST patterns work together
- How capabilities flow from detection → aggregation → scoring

### Tasks
- Add a new capability pattern (e.g., Docker, Redis, Teams)
- Register it in the capability analyzer
- Verify it appears in the normalized capabilities output

### Recommended files
- `analysis/capabilities.py`
- `analyzers/capability/analyzer.py`
- `tests/test_confidence_arbitration.py`

---

## Level 3 — Improve Report Generation

**Difficulty:** Intermediate  
**Knowledge required:** HTML/CSS, JSON, or Markdown  
**Estimated time:** 3–6 hours

### What you'll learn
- How report generators consume the scan report
- How findings, capabilities, and trust scores are formatted
- How to add new output formats

### Tasks
- Add filtering to the HTML report
- Create a new report format (Markdown, CSV)
- Improve SARIF metadata output

### Recommended files
- `report/html.py`
- `report/sarif.py`
- Create: `report/markdown.py`

---

## Level 4 — Add Framework Support

**Difficulty:** Intermediate–Advanced  
**Knowledge required:** Python AST, import systems, dependency parsing  
**Estimated time:** 4–8 hours

### What you'll learn
- The framework parser interface (detect + parse)
- How AST-based parsing extracts entities
- How the Normalized Agent Model is structured
- How parsers integrate with the scan pipeline

### Tasks
- Build a parser for a new AI framework (e.g., Google ADK, AutoGen)
- Handle detection via imports, configs, and regex fallback
- Extract agents, tools, workflows, and capabilities

### Recommended files
- Create: `frameworks/<name>/parser.py`
- `analysis/semantic.py`
- `analysis/import_graph.py`
- `tests/test_parser_aggregation.py`

### Example
```python
class MyFrameworkParser:
    name = "my_framework"

    def detect(self, path, content, scan_ctx=None):
        # Check imports, configs, dependencies
        return "my_framework" in content.lower()

    def parse(self, path, content, scan_ctx=None):
        # Extract agents, tools, workflows, capabilities
        return {"framework": self.name, "agents": [], ...}
```

---

## Level 5 — Build a New Analyzer

**Difficulty:** Advanced  
**Knowledge required:** System design, security analysis, Python  
**Estimated time:** 8–16 hours

### What you'll learn
- The full analyzer lifecycle (receive file cache → produce findings)
- How findings interact with rules, scoring, and reports
- How to design detection logic for new risk categories

### Tasks
- Build a governance analyzer (detect missing timeouts, retries, approvals)
- Build a dataflow analyzer (track tainted data through agent pipelines)
- Build an identity analyzer (detect hardcoded credentials with context)

### Recommended files
- Create: `analyzers/<name>/analyzer.py`
- `engine/scan.py` (register the analyzer)
- `rules/base_rules.yaml` (add associated rules)
- `tests/` (comprehensive test suite)

### Example analyzer structure
```python
class GovernanceAnalyzer:
    name = "governance"

    def run(self, file_cache, rules, agent_models=None):
        findings = []
        # Analyze agent models for governance signals
        for model in agent_models or []:
            # Check for timeout, retry, approval configurations
            ...
        return findings
```

---

## Summary

| Level | Skill | Time | Impact |
|-------|-------|------|--------|
| 1 | Add a rule | 1–2h | Small — immediate |
| 2 | Add capability | 2–4h | Small — detection quality |
| 3 | Improve reports | 3–6h | Medium — user experience |
| 4 | Add framework | 4–8h | Large — new ecosystem |
| 5 | Build analyzer | 8–16h | Large — new risk category |

---

## Moving Between Levels

You don't need to complete level 1 before trying level 2. If you're comfortable with Python, jump straight to level 4. The roadmap is a guide, not a gantt chart.

**Every contribution matters**, regardless of size.
