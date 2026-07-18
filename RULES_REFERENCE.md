# SafeAI — Rules Reference

This document describes every rule implemented in SafeAI's rule engine.

Rules are defined in YAML format in `rules/base_rules.yaml`. Custom rules can be added via the `--rules` CLI flag.

---

## Rule Format

```yaml
- id: RULE_ID
  description: Human-readable description
  severity: critical|high|medium|low|info
  owasp_llm: LLM01-LLM06
```

---

## Prompt Injection Rules

### PROMPT_INJECTION

| Field | Value |
|-------|-------|
| **Rule ID** | `PROMPT_INJECTION` |
| **Name** | Prompt Injection |
| **Description** | Untrusted input interpolated into prompt |
| **Severity** | Critical |
| **OWASP LLM** | LLM01 (Prompt Injection) |
| **Risk Category** | Safety |
| **Score Contribution** | 18 |
| **Detection** | Lines containing f-strings or `.format()` combined with user-controlled variable names (`user_input`, `request`, `input`, `response`) |

**Evidence example:**
```python
prompt = f"System: do X {user_input}"
```

**Why it matters:** Untrusted input directly interpolated into prompts allows users to inject instructions, override system prompts, and manipulate agent behavior.

**Recommendation:** Sanitize user input using parameterized prompt templates. Isolate system instructions from user content using message roles.

---

### PROMPT_DELIMITER

| Field | Value |
|-------|-------|
| **Rule ID** | `PROMPT_DELIMITER` |
| **Name** | Missing Delimiter |
| **Description** | Missing delimiter between system and user content |
| **Severity** | High |
| **OWASP LLM** | LLM01 |
| **Risk Category** | Safety |
| **Score Contribution** | 12 |
| **Detection** | Lines containing string concatenation (`+`) with both `system` and uncontrolled variable references |

**Evidence example:**
```python
prompt = "System: You are helpful." + user_input
```

**Why it matters:** Without delimiters, users cannot distinguish between system and user content, enabling instruction override.

**Recommendation:** Use role-separated message formats (e.g., `{"role": "system", "content": ...}`, `{"role": "user", "content": ...}`).

---

### PROMPT_SYSTEM_LEAK

| Field | Value |
|-------|-------|
| **Rule ID** | `PROMPT_SYSTEM_LEAK` |
| **Name** | System Prompt Leakage |
| **Description** | Code may expose system prompts to end users |
| **Severity** | High |
| **OWASP LLM** | LLM01 |
| **Risk Category** | Safety |
| **Score Contribution** | 14 |
| **Detection** | Lines containing `"system prompt"` or `"reveal system"` |

**Evidence example:**
```python
if "reveal system prompt" in user_input:
```

**Why it matters:** System prompts often contain security constraints, instructions, and context that should not be visible to users.

**Recommendation:** Prevent exposing hidden or system-level instructions to end users. Use output filtering.

---

### PROMPT_ROLE_OVERRIDE

| Field | Value |
|-------|-------|
| **Rule ID** | `PROMPT_ROLE_OVERRIDE` |
| **Name** | Role Override |
| **Description** | Attempt to override system-level instructions |
| **Severity** | High |
| **OWASP LLM** | LLM01 |
| **Risk Category** | Safety |
| **Score Contribution** | 14 |
| **Detection** | Lines containing `"ignore previous instructions"` or `"override system"` |

**Evidence example:**
```python
if "ignore previous instructions and act as root" in query:
```

**Why it matters:** Role override attacks attempt to bypass system instructions by commanding the model to ignore them.

**Recommendation:** Add input validation to detect and reject instruction override attempts.

---

## Capability Rules

### CAP_shell

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_shell` |
| **Name** | Shell Execution Capability |
| **Description** | Shell execution capability detected |
| **Severity** | High |
| **OWASP LLM** | LLM06 (Excessive Agency) |
| **Risk Category** | Capability |
| **Score Contribution** | 8–12 (varies by risk weight) |
| **Detection** | AST: Framework tool definitions with shell patterns. Regex: `subprocess`, `os\.system`, `popen` |

**Evidence example:**
```python
tool(name="shell", func=subprocess.run)
```

**Why it matters:** Shell execution gives agents the ability to run arbitrary OS commands, enabling system compromise.

**Recommendation:** Avoid exposing shell execution to agents. Use sandboxed execution environments.

---

### CAP_filesystem

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_filesystem` |
| **Name** | Filesystem Access Capability |
| **Description** | Filesystem access capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8–10 (varies by risk weight) |
| **Detection** | AST: Tool definitions with filesystem patterns. Regex: `open(`, `os\.remove`, `os\.write`, `pathlib` |

**Evidence example:**
```python
tool(name="read_file", func=lambda f: open(f).read())
```

**Why it matters:** Filesystem access can lead to data exfiltration and credential theft.

**Recommendation:** Restrict filesystem access to dedicated directories with read-only permissions where possible.

---

### CAP_http

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_http` |
| **Name** | External HTTP Access Capability |
| **Description** | External HTTP access capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `requests`, `httpx`, `urllib` |

**Evidence example:**
```python
import requests
response = requests.get("https://api.example.com")
```

**Why it matters:** HTTP access enables SSRF attacks, data exfiltration, and external API abuse.

**Recommendation:** Restrict outbound network access, use URL allowlisting, and implement rate limiting.

---

### CAP_db

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_db` |
| **Name** | Database Access Capability |
| **Description** | Database access capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `sqlite3`, `psycopg2`, `mysql`, `postgres`, `sqlalchemy` |

**Evidence example:**
```python
conn = sqlite3.connect("customer_data.db")
```

**Why it matters:** Database access can lead to SQL injection, data breaches, and unauthorized data modification.

**Recommendation:** Grant read-only access where possible, use parameterized queries, and audit all database operations.

---

### CAP_code_exec

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_code_exec` |
| **Name** | Code Execution Capability |
| **Description** | Code execution (`exec`/`eval`) capability detected |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `exec(`, `eval(` |

**Evidence example:**
```python
result = eval(user_formula)
```

**Why it matters:** Arbitrary code execution gives agents full runtime control.

**Recommendation:** Never execute untrusted code. Use safe evaluation libraries for formula evaluation.

---

### CAP_AUTONOMY

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_AUTONOMY` |
| **Name** | Autonomous Agent Behavior |
| **Description** | Potential autonomous agent loop detected |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Autonomy |
| **Score Contribution** | 12 |
| **Detection** | `while True` combined with agent-related content; `for _ in range(...)` with agent content |

**Evidence example:**
```python
while True:
    agent.run()
```

**Why it matters:** Unbounded autonomous loops can result in infinite execution, cost escalation, and out-of-control agent behavior.

**Recommendation:** Impose iteration limits, implement timeout and circuit breaker patterns, and require human approval for long-running loops.

---

## Data Leakage Rules

### DATA_LEAKAGE

| Field | Value |
|-------|-------|
| **Rule ID** | `DATA_LEAKAGE` |
| **Name** | Data Leakage |
| **Description** | Potential secret exposure detected |
| **Severity** | High |
| **OWASP LLM** | LLM02 (Data Leakage) |
| **Risk Category** | Identity |
| **Score Contribution** | 16 |
| **Detection** | Regex patterns matching API keys, tokens, passwords, and environment variable references |

**Sub-patterns:**

| Pattern | Example Match |
|---------|--------------|
| `API_KEY` | `api_key = "sk-1234567890abcdef1234567890abcdef"` |
| `TOKEN` | `token = "ghp_1234567890abcdef1234"` |
| `PASSWORD` | `password = "supersecret"` |
| `ENV_SECRET` | `os.environ["SECRET_KEY"]` |

**Why it matters:** Hardcoded credentials can be extracted from source code, leading to unauthorized access.

**Recommendation:** Remove hardcoded secrets from source code. Use environment variables or secure secret storage. Add `.env` to `.gitignore`.

---

### CAP_subprocess_shell

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_subprocess_shell` |
| **Name** | Subprocess with shell=True |
| **Description** | `subprocess` invoked with `shell=True`, enabling shell injection |
| **Severity** | Critical |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 15 |
| **Detection** | Regex: `subprocess` followed by `shell=True` on the same line |

**Evidence example:**
```python
subprocess.run(user_command, shell=True)
```

**Why it matters:** `shell=True` passes the command through the system shell, making injection trivial when any part of the command is influenced by user or model output.

**Recommendation:** Pass commands as argument lists without `shell=True`, and validate any dynamic arguments.

---

### CAP_file_write

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_file_write` |
| **Name** | File Write Capability |
| **Description** | File opened in write, append, or exclusive-create mode |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 7 |
| **Detection** | Regex: `open(..., "w"|"a"|"x"...)` mode flags |

**Evidence example:**
```python
with open(filename, "w") as f:
    f.write(agent_output)
```

**Why it matters:** Write access enables data tampering and persistent payloads when file paths or contents are model-influenced.

**Recommendation:** Restrict writes to dedicated output directories and validate paths against an allowlist.

---

## Removed and Consolidated Rules

The following rule IDs were removed from `rules/base_rules.yaml` because they
had no dedicated detection logic. Their coverage is provided by other rules:

| Rule ID | Description | Replacement |
|---------|-------------|-------------|
| `CAP_eval` | Use of `eval()` | `CAP_code_exec` |
| `CAP_exec` | Use of `exec()` | `CAP_code_exec` |
| `PROMPT_TOOL_OUTPUT` | Tool output directly injected into prompt | Planned (see roadmap) |
| `GOAL_HIJACK` | Dangerous instruction keywords | Planned (see roadmap) |

Every rule currently declared in `rules/base_rules.yaml` has active detection logic.

---

## MCP-Specific Rules

MCP-related rules are generated dynamically by the MCP analyzer and are documented in [MCP_SECURITY.md](MCP_SECURITY.md). The following MCP rule IDs are used:

| Rule ID | Description | Severity |
|---------|-------------|----------|
| `MCP_SCHEMA_REQUIRED` | Missing required MCP configuration field | Medium |
| `MCP_SCHEMA_TYPE` | MCP field type mismatch | Medium |
| `MCP_SCHEMA_ENDPOINT_TYPE` | MCP endpoint entry type mismatch | Low |
| `MCP_PY_REFERENCE` | Python source references MCP | Low |
| `MCP_AUTH_MISSING` | MCP authentication not configured | High |
| `MCP_AUTH_WEAK` | MCP authentication is weak/disabled | High |
| `MCP_PERMISSIONS_MISSING` | MCP permissions not configured | High |
| `MCP_ENDPOINT_EXPOSURE` | Potentially exposed MCP endpoint | High |
| `MCP_HARDCODED_SECRET` | Hardcoded secret in MCP configuration | Critical |
| `MCP_DANGEROUS_TOOL` | MCP tool may allow unrestricted execution | High |
| `MCP_ASSETS_DISCOVERED` | Scanner metadata: MCP discovery summary | Info |

---

## Adding Custom Rules

1. Create a YAML file with your rule definitions
2. Use the same format as `rules/base_rules.yaml`
3. Pass the directory via `--rules`:

```bash
python -m safeai scan /path/to/project --rules /path/to/custom-rules/
```

Custom rules merge with built-in rules. If a custom rule has the same ID as a built-in rule, the custom severity and OWASP category override the built-in values.
