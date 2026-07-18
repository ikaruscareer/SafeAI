# Testing Corpus Guide

A benchmark repository helps ensure SafeAI detects real-world risks accurately and avoids false positives. This guide explains how to build and maintain a testing corpus.

---

## Purpose of the Testing Corpus

A testing corpus serves three purposes:

1. **Verify detections** — confirm that SafeAI finds risks it should find
2. **Prevent regressions** — ensure new changes don't break existing detections
3. **Benchmark accuracy** — measure false positive and false negative rates

---

## Corpus Structure

```
corpus/
    safe/                   # Examples that should have NO findings (or minimal info-level)
        langgraph/
        crewai/
        mcp/
        prompts/

    risky/                  # Examples that SHOULD trigger findings
        langgraph/
        crewai/
        mcp/
        prompts/

    benchmark/              # Real open-source agent projects (anonymized)
        agent-1/
        agent-2/

    false-positives/        # Past false positive cases (regression tests)
        issue-123/
        issue-456/
```

---

## Adding Open-Source Agent Projects

### Step 1: Select a project
Choose a real open-source AI agent from GitHub. Prefer projects that:
- Are actively maintained
- Use one of SafeAI's supported frameworks
- Have diverse tool and capability usage

### Step 2: Add to corpus
```bash
mkdir -p corpus/benchmark/agent-name
cp -r /path/to/cloned-repo/* corpus/benchmark/agent-name/
```

### Step 3: Run SafeAI
```bash
python -m safeai scan corpus/benchmark/agent-name --json results.json
```

### Step 4: Review findings
Check that SafeAI's findings are reasonable:
- Are there false positives? (file an issue)
- Are there missed detections? (file an enhancement)
- Are confidence levels appropriate?

---

## Anonymizing Examples

If a project contains sensitive information, anonymize it before adding to the corpus:

### What to anonymize:
- API keys and tokens → `sk-xxx...xxx`
- Internal URLs → `https://internal.example.com`
- Person names → `[Author Name]`
- Email addresses → `user@example.com`
- IP addresses → `10.0.0.1`

### Automated anonymization script:

```python
import re


def anonymize(content):
    # API keys
    content = re.sub(r'(api[_-]?key\s*=\s*["\']?)[A-Za-z0-9_-]{16,}', r'\1***REDACTED***', content)
    # Tokens
    content = re.sub(r'(token\s*=\s*["\']?)[A-Za-z0-9._-]{16,}', r'\1***REDACTED***', content)
    # Email
    content = re.sub(r'[\w.+-]+@[\w-]+\.[\w.-]+', 'user@example.com', content)
    # IPs
    content = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '10.0.0.1', content)
    return content
```

---

## Creating Intentionally Risky Examples

Create examples that demonstrate specific security issues:

### Prompt injection:
```python
prompt = f"Translate the following: {user_input}"
system_prompt = "You are a helpful assistant." + user_input
```

### Hardcoded credentials:
```python
api_key = "sk-1234567890abcdef1234567890abcdef"
password = "supersecret123"
os.environ["SECRET_KEY"] = "super-secret-value"
```

### Excessive capabilities:
```python
import subprocess
result = subprocess.run(user_command, shell=True)
with open("/etc/passwd", "r") as f:
    data = f.read()
```

### MCP misconfiguration:
```json
{
    "mcp": {
        "servers": [{"name": "exec"}],
        "tools": ["shell", "exec"],
        "endpoints": ["http://0.0.0.0:8080"]
    }
}
```

---

## Validating Detections

For each risky example, define the expected findings:

```python
EXPECTED_FINDINGS = {
    "prompt_injection.py": [
        {"rule_id": "PROMPT_INJECTION", "severity": "critical"},
        {"rule_id": "PROMPT_DELIMITER", "severity": "high"},
    ],
    "hardcoded_secrets.py": [
        {"rule_id": "DATA_LEAKAGE", "severity": "high"},
    ],
    "shell_execution.py": [
        {"rule_id": "CAP_shell", "severity": "high"},
    ],
}
```

Then automate validation:

```bash
python -m safeai scan corpus/risky/ --json results.json
python scripts/validate_detections.py corpus/risky/ results.json
```

---

## Reporting False Positives

If SafeAI reports a finding that isn't a real risk:

1. **Open an issue** with the `bug` label
2. **Include the code snippet** that triggered the false positive
3. **Explain why it's a false positive** — what makes it safe?
4. **Add the example** to `corpus/false-positives/` for regression testing

### False positive issue template:

```
## Description
SafeAI detects [RULE_ID] on code that is not actually risky.

## Code
```python
# paste the triggering code here
```

## Why it's a false positive
[Explain why this code is safe despite matching the pattern]

## Expected behavior
SafeAI should NOT generate a finding for this code.
```

---

## Automated Corpus Testing

Add a CI job that runs SafeAI against the corpus and validates detections:

```yaml
corpus-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Run SafeAI against corpus
      run: |
        python -m safeai scan corpus/risky/ --json corpus-results.json
    - name: Validate detections
      run: |
        python scripts/validate_detections.py corpus/ corpus-results.json
```

---

## Maintenance

- **Review corpus quarterly** — ensure examples are still relevant
- **Update SafeAI references** — keep expected findings aligned with current rules
- **Add regression tests** — every bug fix should include a corpus example
- **Remove stale examples** — retire examples for deprecated frameworks or patterns
