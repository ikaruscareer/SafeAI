# How to Add a Rule

Rules define **what SafeAI looks for** and **how severe each finding is**. They are written in YAML and loaded at scan time.

---

## Rule Structure

```yaml
- id: SAFEAI-001
  description: Short description of what this rule detects
  severity: high              # critical, high, medium, low, info
  owasp_llm: LLM02           # OWASP LLM Application category
```

Each rule maps to detection logic inside an analyzer. The rule tells the analyzer what severity and OWASP category to use for matching findings.

---

## Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier. Convention: `SAFEAI-NNN` or framework-specific prefixes |
| `description` | Yes | Human-readable description of the rule |
| `severity` | Yes | Risk severity: `critical`, `high`, `medium`, `low`, `info` |
| `owasp_llm` | No | OWASP LLM Application category: `LLM01`–`LLM06` |
| `category` | No | Risk category override (defaults to what the analyzer sets) |

---

## Example Rule Set

Save these to a `.yaml` file and pass them via `--rules`:

```yaml
# custom_rules.yaml

- id: SAFEAI-001
  description: Hardcoded API key detected in source code
  severity: critical
  owasp_llm: LLM02

- id: SAFEAI-002
  description: User input directly interpolated into prompt string
  severity: critical
  owasp_llm: LLM01

- id: SAFEAI-003
  description: Shell execution capability detected in agent tool
  severity: high
  owasp_llm: LLM06

- id: SAFEAI-004
  description: Agent tool missing timeout configuration
  severity: medium
  owasp_llm: LLM06

- id: SAFEAI-005
  description: Filesystem write access detected in agent
  severity: high
  owasp_llm: LLM06

- id: SAFEAI-006
  description: Database connection without read-only restriction
  severity: medium
  owasp_llm: LLM06

- id: SAFEAI-007
  description: No authentication configured for MCP endpoint
  severity: high
  owasp_llm: LLM06

- id: SAFEAI-008
  description: System prompt leakage via user-facing commands
  severity: high
  owasp_llm: LLM01

- id: SAFEAI-009
  description: Agent delegation without human approval gate
  severity: high
  owasp_llm: LLM06

- id: SAFEAI-010
  description: Hardcoded token in MCP configuration file
  severity: critical
  owasp_llm: LLM02
```

---

## How Rules Connect to Detection

Rules themselves don't contain detection logic. **Detection logic lives in analyzers.** The rule provides metadata that the analyzer attaches to findings.

```python
# In an analyzer:
rule = rule_map.get("SAFEAI-003", {})
findings.append({
    "rule_id": "SAFEAI-003",
    "severity": rule.get("severity", "high"),
    "message": "Shell execution capability detected",
    # ... other fields
})
```

---

## Matching Rules to Findings

When an analyzer creates a finding, it sets `rule_id` to match a rule. The scanner:

1. Loads all rules from YAML
2. Passes them to each analyzer
3. Analyzer looks up its rule by ID and uses the configured severity
4. Finding severity defaults to rule severity, but can be overridden

---

## Adding Rules Without Writing Code

You can add rules without modifying Python code by:

1. Creating a custom YAML file with your rules
2. Passing the directory via `--rules`:

```bash
python -m safeai scan . --rules ./my-rules/
```

Custom rules merge with built-in rules. If a custom rule has the same ID as a built-in rule, the custom values override the built-in ones.

---

## Testing Rules

To verify a rule fires correctly:

1. Create a test file with the pattern you want to detect
2. Run SafeAI against it
3. Check that the finding includes the expected rule ID

```python
def test_safeai_001_fires_on_hardcoded_key(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('api_key = "sk-123456789012345678901234"\n')
    report = run_scan(str(tmp_path))
    assert any(f["rule_id"] == "SAFEAI-001" for f in report["findings"])
```

---

## Built-in Rules Reference

Built-in rules are in `rules/base_rules.yaml`. Categories:

| Prefix | Category | Example |
|--------|----------|---------|
| `PROMPT_` | Prompt Safety | `PROMPT_INJECTION`, `PROMPT_DELIMITER` |
| `CAP_` | Capability | `CAP_shell`, `CAP_filesystem`, `CAP_AUTONOMY` |
| `DATA_` | Data Leakage | `DATA_LEAKAGE` |
| `MCP_` | MCP Security | `MCP_AUTH_MISSING`, `MCP_HARDCODED_SECRET` |
| `GOV_` | Governance | `GOV_TIMEOUT_MISSING` |

---

## Rule Design Guidelines

1. **One rule per detection pattern** — don't bundle multiple patterns
2. **Be specific** — `SAFEAI-hardcoded-aws-key` is better than `SAFEAI-001`
3. **Set severity honestly** — not everything is critical
4. **Document OWASP mapping** — helps users understand the risk framework
5. **Include remediation** in the finding, not just in the rule
