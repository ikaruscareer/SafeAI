# How to Add a Capability

Capabilities represent what an AI agent **can do** — shell execution, filesystem access, database queries, external API calls, etc. SafeAI detects capabilities through framework parsers and regex fallback patterns.

---

## Capability Model

Each capability is a dictionary:

```python
{
    "name": "shell_execution",           # Machine-readable identifier
    "category": "Shell",                  # Human-readable category
    "source_framework": "langgraph",      # Which framework detected it
    "evidence": "subprocess.run('ls')",   # The code that triggered detection
    "confidence": 0.9,                    # 0.0 to 1.0
    "risk_weight": 1.6,                   # Multiplier for scoring (default 1.0)
    "source": "ast",                      # Detection method: ast, configuration, regex
    "resolved_definition": "subprocess.run@/usr/lib/python3.11/subprocess.py",
}
```

---

## Canonical Capability Categories

Defined in `safeai/analysis/capabilities.py`:

| Category | Examples |
|----------|----------|
| `Filesystem` | File read/write, path traversal |
| `Shell` | Command execution, subprocess |
| `Browser` | Playwright, Selenium |
| `Planner` | Workflow planning, task decomposition |
| `Delegation` | Agent handoff, sub-agent creation |
| `Memory` | State persistence, checkpointing |
| `RAG` | Document retrieval, vector search |
| `GitHub` | Repository access, PR management |
| `Slack` | Channel messaging, user lookup |
| `Email` | SMTP, sending/receiving mail |
| `Databases` | SQL queries, connection management |
| `Cloud` | AWS, Azure, GCP service access |
| `External APIs` | HTTP, REST, GraphQL calls |
| `MCP` | Model Context Protocol integration |
| `Human Approval` | Human-in-the-loop gates |
| `Multi-Agent` | Inter-agent communication |

---

## Step 1: Add the Capability Category (if new)

If your capability doesn't fit an existing category, add it to `safeai/analysis/capabilities.py`:

```python
CAPABILITY_CATEGORIES = {
    # ... existing categories ...
    "container": "Container",
}
```

---

## Step 2: Add Detection Logic

### Option A: In the Capability Analyzer (regex fallback)

Add a pattern to `safeai/analyzers/capability/analyzer.py`:

```python
CAP_PATTERNS = {
    # ... existing patterns ...
    "docker": re.compile(r"docker|DockerClient|containers\.run", re.I),
}

RULE_BY_CAP = {
    # ... existing mappings ...
    "docker": "CAP_docker",
}

CATEGORY_BY_CAP = {
    # ... existing mappings ...
    "docker": "Container",
}
```

### Option B: In a Framework Parser (AST-based)

Add capability inference to a framework parser. Example from LangGraph parser:

```python
if any(s in lname for s in ["subprocess", "os.system", "popen"]):
    capabilities.append(make_capability(
        "shell_execution",
        "Shell",
        self.name,
        call["name"],
        confidence=0.9,
        risk_weight=1.6,
        resolved_definition=f"{origin.get('qualified_name')}@{origin.get('file') or 'unknown'}",
    ))
```

For a new capability like Docker:

```python
if any(s in lname for s in ["docker", "DockerClient", "container.run"]):
    capabilities.append(make_capability(
        "docker",
        "Container",
        self.name,
        call["name"],
        confidence=0.85,
        risk_weight=1.2,
    ))
```

---

## Step 3: Add the Rule

Add a corresponding rule to `rules/base_rules.yaml`:

```yaml
- id: CAP_docker
  description: Docker container management capability detected
  severity: medium
  owasp_llm: LLM06
```

---

## Step 4: Write Tests

```python
def test_docker_capability_detected_via_regex():
    """Verify that Docker API calls trigger capability detection."""
    from safeai.analyzers.capability.analyzer import CapabilityAnalyzer

    file_cache = {"test.py": "import docker\nclient = docker.DockerClient()\n"}
    rules = [{"id": "CAP_docker", "severity": "medium", "owasp_llm": "LLM06"}]

    analyzer = CapabilityAnalyzer()
    findings = analyzer.run(file_cache, rules)

    assert any(f["rule_id"] == "CAP_docker" for f in findings)
```

---

## Step 5: Update Documentation

- Add the capability to `CAPABILITIES.md` (if it exists) or document in release notes
- Update the capability matrix in documentation

---

## Capability Flow Diagram

```mermaid
flowchart LR
    A[Framework Parser] -->|make_capability()| B[Normalized Agent Model]
    C[Regex Fallback] -->|CapabilityAnalyzer| B
    B --> D[Aggregation - dedupe + merge]
    D --> E[Scoring Engine]
    E --> F[Report]
```

---

## Checklist

- [ ] Capability category exists (or was added to `capabilities.py`)
- [ ] Detection logic added (framework parser or capability analyzer)
- [ ] Rule added to `rules/base_rules.yaml`
- [ ] Tests pass
- [ ] Documentation updated
