# Plugin Template

This directory contains a reusable template for creating new SafeAI plugins.

---

## Contents

```
PLUGIN_TEMPLATE/
    README.md              # This file
    parser.py              # Example framework parser
    analyzer.py            # Example analyzer
    capability.py          # Example capability detector
    rules.yaml             # Example YAML rules
    fixtures/
        safe_example.py    # Example code that should NOT trigger findings
        risky_example.py   # Example code that SHOULD trigger findings
    tests/
        test_parser.py     # Tests for the example parser
        test_analyzer.py   # Tests for the example analyzer
```

---

## How to Use This Template

1. Copy the template directory:
   ```bash
   cp -r PLUGIN_TEMPLATE safeai/frameworks/my_framework/
   ```
2. Rename classes and identifiers from `ExampleFramework` to your framework name
3. Implement the detection and parsing logic
4. Register the parser in `engine/scan.py`
5. Write tests

---

## File Reference

### `parser.py`

```python
"""Framework parser for ExampleFramework."""

import re
from safeai.analysis.capabilities import dedupe_capabilities, make_capability
from safeai.analysis.semantic import build_semantic_document, resolve_symbol, resolve_symbol_origin


class ExampleFrameworkParser:
    name = "example_framework"

    def detect(self, path, content, scan_ctx=None):
        if not path.endswith(".py"):
            return False
        doc = build_semantic_document(path, content)
        for imported in list(doc.imports.values()) + [v.rsplit(".", 1)[0] for v in doc.from_imports.values()]:
            if imported.startswith("example_framework"):
                return True
        return "example_framework" in content.lower()

    def parse(self, path, content, scan_ctx=None):
        module_name = ""
        import_graph = None
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
            import_graph = scan_ctx.get("import_graph")

        doc = build_semantic_document(path, content, module_name=module_name)

        agents = []
        tools = []
        workflows = []
        capabilities = []

        for call in doc.calls:
            resolved = resolve_symbol(doc, call["name"])
            origin = resolve_symbol_origin(doc, call["name"], import_graph=import_graph)
            lname = (resolved or call["name"]).lower()

            if "agent" in lname:
                agents.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {})})
            if "tool" in lname:
                tools.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {})})
            if "run" in lname or "workflow" in lname:
                workflows.append({"name": call["name"], "line": call.get("line")})
            if "subprocess" in lname or "shell" in lname:
                capabilities.append(make_capability("shell_execution", "Shell", self.name, call["name"], confidence=0.9))

        return {
            "framework": self.name,
            "agents": agents,
            "workflows": workflows,
            "tools": tools,
            "prompts": [],
            "memory": [],
            "models": [],
            "capabilities": dedupe_capabilities(capabilities),
            "relationships": [],
            "discovery_method": "ast+regex_fallback",
            "parser_confidence": 0.85,
            "detection_evidence": [f"imports:{self.name}"],
        }
```

### `analyzer.py`

```python
"""Example analyzer for framework-specific security checks."""


class ExampleAnalyzer:
    name = "example_analyzer"

    def run(self, file_cache, rules, agent_models=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}

        for model in agent_models or []:
            path = model.get("file")
            data = model.get("data", {})
            tools = data.get("tools") or []

            for tool in tools:
                kwargs = tool.get("kwargs", {})
                if "timeout" not in kwargs:
                    findings.append({
                        "rule_id": "EXAMPLE_TIMEOUT",
                        "severity": "medium",
                        "message": f"Tool missing timeout: {tool.get('name', 'unknown')}",
                        "file": path,
                        "line": tool.get("line", 1),
                        "owasp_llm": "LLM06",
                        "evidence": str(kwargs),
                        "reason": "Tools without timeouts may cause resource exhaustion.",
                        "risk_category": "Governance",
                        "affected_framework": "example_framework",
                        "affected_capability": "Tools",
                        "score_contribution": 8,
                        "remediation": "Add a timeout parameter to tool configuration.",
                        "confidence": 0.7,
                    })

        return findings
```

### `rules.yaml`

```yaml
- id: EXAMPLE_TIMEOUT
  description: Example framework tool missing timeout configuration
  severity: medium
  owasp_llm: LLM06

- id: EXAMPLE_AUTH
  description: Example framework missing authentication configuration
  severity: high
  owasp_llm: LLM06
```

### Fixture: `fixtures/safe_example.py`

```python
"""Example of safe usage — should not trigger findings."""

from example_framework import Agent

agent = Agent(name="helper")
agent.run(task="summarize", timeout=30)
```

### Fixture: `fixtures/risky_example.py`

```python
"""Example of risky usage — should trigger findings."""

from example_framework import Agent
import subprocess

agent = Agent(name="runner")
agent.run(task=subprocess.run("rm -rf /"))
```

### Tests: `tests/test_parser.py`

```python
from safeai.frameworks.example_framework.parser import ExampleFrameworkParser


def test_detect_positive():
    parser = ExampleFrameworkParser()
    assert parser.detect("test.py", "from example_framework import Agent")


def test_detect_negative():
    parser = ExampleFrameworkParser()
    assert not parser.detect("test.py", "import os")


def test_parse_returns_agents():
    parser = ExampleFrameworkParser()
    result = parser.parse("test.py", "from example_framework import Agent\nagent = Agent()\n")
    assert isinstance(result["agents"], list)
    assert result["framework"] == "example_framework"
```

### Tests: `tests/test_analyzer.py`

```python
from safeai.analyzers.example_analyzer.analyzer import ExampleAnalyzer


def test_example_analyzer_detects_missing_timeout():
    analyzer = ExampleAnalyzer()
    agent_models = [{
        "file": "test.py",
        "data": {
            "tools": [{"name": "run", "kwargs": {}, "line": 10}],
        },
    }]
    findings = analyzer.run({}, [], agent_models)
    assert any(f["rule_id"] == "EXAMPLE_TIMEOUT" for f in findings)
```

---

## Registration

Add your parser and analyzer to `safeai/engine/scan.py`:

```python
from safeai.frameworks.example_framework.parser import ExampleFrameworkParser
from safeai.analyzers.example_analyzer.analyzer import ExampleAnalyzer

# In the parsers list:
parsers = [..., ExampleFrameworkParser()]

# In the analyzers list:
analyzers = [..., ExampleAnalyzer()]
```

---

## Next Steps

- Add more capability detection patterns
- Add extraction of prompts, memory, and model references
- Add relationship extraction for entity graphs
- Add YAML/JSON configuration file support
