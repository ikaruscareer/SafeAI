# How to Add a Framework Adapter

This guide walks you through adding support for a new AI framework to SafeAI.

---

## Framework Interface

Every framework adapter must implement two methods:

```python
class MyFrameworkParser:
    name = "my_framework"

    def detect(self, path, content, scan_ctx=None) -> bool:
        """Return True if this file uses the framework."""

    def parse(self, path, content, scan_ctx=None) -> dict:
        """Return the Normalized Agent Model."""
```

---

## Directory Structure

Create a new directory under `safeai/frameworks/`:

```
safeai/frameworks/my_framework/
    __init__.py          # (optional — namespace packages work without it)
    parser.py            # detection + parsing logic
```

---

## Step 1: Implement `detect()`

Check whether a file belongs to your framework. Use multiple strategies:

```python
def detect(self, path, content, scan_ctx=None):
    if not path.endswith(".py"):
        return False

    module_name = ""
    deps = set()
    if scan_ctx:
        module_name = scan_ctx.get("module_by_file", {}).get(path, "")
        deps = scan_ctx.get("dependencies", set())

    # Strategy 1: Dependency manifest
    if "my-framework" in deps:
        return True

    # Strategy 2: AST import analysis
    doc = build_semantic_document(path, content, module_name=module_name)
    for imported in list(doc.imports.values()) + [v.rsplit(".", 1)[0] for v in doc.from_imports.values()]:
        if imported.startswith("my_framework"):
            return True

    # Strategy 3: Regex fallback
    if "my_framework" in content.lower():
        return True

    return False
```

---

## Step 2: Implement `parse()`

Extract all entities from the file and return the Normalized Agent Model:

```python
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

        if lname.endswith("agent"):
            agents.append({"name": call["name"], "line": call.get("line"), "kwargs": call.get("kwargs", {})})

        if "tool" in lname:
            tools.append({"name": call["name"], "line": call.get("line")})

        if "run" in lname or "execute" in lname:
            workflows.append({"name": call["name"], "line": call.get("line")})

        if "shell" in lname or "subprocess" in lname:
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
        "detection_evidence": [f"imports:{self.name}", "ast:calls"],
    }
```

---

## Step 3: Register the Parser

Add your parser to `safeai/engine/scan.py`:

```python
from safeai.frameworks.my_framework.parser import MyFrameworkParser

parsers = [
    # ... existing parsers ...
    MyFrameworkParser(),
]
```

---

## Step 4: Write Tests

Create `tests/test_my_framework.py`:

```python
from safeai.frameworks.my_framework.parser import MyFrameworkParser


def test_detect_positive(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("import my_framework\nagent = MyAgent()\n")
    parser = MyFrameworkParser()
    assert parser.detect(str(f), f.read_text())


def test_detect_negative(tmp_path):
    f = tmp_path / "other.py"
    f.write_text("import os\n")
    parser = MyFrameworkParser()
    assert not parser.detect(str(f), f.read_text())


def test_parse_returns_expected_structure(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("from my_framework import Agent\nagent = Agent()\n")
    parser = MyFrameworkParser()
    result = parser.parse(str(f), f.read_text())
    assert result["framework"] == "my_framework"
    assert isinstance(result["agents"], list)
    assert isinstance(result["capabilities"], list)
```

---

## Step 5: Update Documentation

- Add your framework to `README.md` supported frameworks table
- Update `FRAMEWORK_SUPPORT.md` with detection details

---

## Checklist Before Submitting

- [ ] `detect()` works with imports, dependencies, and regex fallback
- [ ] `parse()` returns a complete Normalized Agent Model
- [ ] Tests cover positive detection, negative detection, and parse output
- [ ] Parser is registered in `engine/scan.py`
- [ ] Framework is added to `README.md` and `FRAMEWORK_SUPPORT.md`
- [ ] All existing tests still pass (`python -m pytest`)

---

## Complete Example: LangGraph Parser

See `safeai/frameworks/langgraph/parser.py` for a complete, production-quality example of a framework adapter.
