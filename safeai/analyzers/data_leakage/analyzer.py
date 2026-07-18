"""Data leakage analyzer — detects hardcoded secrets in source files.

Scans all files (Python, JSON, YAML) for patterns matching API keys,
tokens, passwords, and environment variable references that could
indicate credentials are embedded in source code.

Evidence included in findings is masked so that reports never contain
full secret values.
"""

import re


PATTERNS = {
    "API_KEY": re.compile(r"(api[_-]?key)\s*=\s*[\"']?[A-Za-z0-9_-]{16,}" , re.I),
    "TOKEN": re.compile(r"(token)\s*=\s*[\"']?[A-Za-z0-9._-]{16,}", re.I),
    "PASSWORD": re.compile(r"(password|passwd)\s*=\s*[\"']?.+", re.I),
    "ENV_SECRET": re.compile(r"os\.environ\[.*\]", re.I),
}

# Matches ``key = value`` style assignments for credential-like names so the
# value portion can be masked in report evidence.
_SECRET_VALUE_RE = re.compile(
    r"((?:api[_-]?key|token|password|passwd|secret)[\"']?\s*[:=]\s*[\"']?)([^\s\"',}]+)",
    re.I,
)


def mask_secret_evidence(line):
    """Mask credential values in a source line for safe inclusion in reports.

    Keeps the first four characters of the value for identification and
    replaces the remainder with ``***MASKED***``.
    """
    def _repl(match):
        value = match.group(2)
        return f"{match.group(1)}{value[:4]}***MASKED***"

    return _SECRET_VALUE_RE.sub(_repl, line.strip())


class DataLeakageAnalyzer:
    name = "data_leakage"

    def run(self, file_cache, rules, agent_models=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}

        for path, content in file_cache.items():
            for i, line in enumerate(content.splitlines(), 1):
                for key, pattern in PATTERNS.items():
                    if pattern.search(line):
                        rule = rule_map.get("DATA_LEAKAGE", {})
                        findings.append({
                            "rule_id": "DATA_LEAKAGE",
                            "severity": rule.get("severity", "high"),
                            "message": f"Potential secret exposure: {key}",
                            "file": path,
                            "line": i,
                            "owasp_llm": rule.get("owasp_llm", "LLM02"),
                            "evidence": mask_secret_evidence(line),
                            "reason": "Static pattern indicates potential credential leakage.",
                            "risk_category": "Identity",
                            "affected_framework": "generic",
                            "affected_capability": "Identity",
                            "score_contribution": 16,
                            "remediation": "Remove hardcoded secrets and use secure secret storage.",
                        })
        return findings
