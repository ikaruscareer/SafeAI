"""Data leakage analyzer — detects hardcoded secrets in source files.

Scans all files (Python, JSON, YAML) for patterns matching API keys,
tokens, passwords, environment variable references, private keys,
JWT tokens, AWS access keys, connection strings, and encoded secrets
that could indicate credentials are embedded in source code.

Evidence included in findings is masked so that reports never contain
full secret values.
"""

import re

PATTERNS = {
    "API_KEY": re.compile(r"(api[_-]?key)\s*=\s*[\"']?[A-Za-z0-9_-]{16,}" , re.IGNORECASE),
    "TOKEN": re.compile(r"(token)\s*=\s*[\"']?[A-Za-z0-9._-]{16,}", re.IGNORECASE),
    "PASSWORD": re.compile(r"(password|passwd)\s*=\s*[\"']?.+", re.IGNORECASE),
    "ENV_SECRET": re.compile(r"os\.environ\[.*\]", re.IGNORECASE),
    # v1.8 deepened patterns
    "RSA_PRIVATE_KEY": re.compile(
        r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s*KEY-----",
        re.IGNORECASE,
    ),
    "JWT_TOKEN": re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}",
    ),
    "AWS_ACCESS_KEY": re.compile(
        r"(?:AKIA|ASIA)[A-Z0-9]{16}",
    ),
    "CONNECTION_STRING": re.compile(
        r"(?:mongodb|postgres|postgresql|mysql|redis|mssql|amqp|smtp|ftp)"
        r"://[^\s\"']+",
        re.IGNORECASE,
    ),
    "BASE64_SECRET": re.compile(
        r"""(?:secret|key|token|password)\s*[:=]\s*["']?[A-Za-z0-9+/]{40,}={0,2}["']?""",
        re.IGNORECASE,
    ),
    "HEX_SECRET": re.compile(
        r"""(?:secret|key|token|password)\s*[:=]\s*["']?[0-9a-fA-F]{32,}["']?""",
        re.IGNORECASE,
    ),
}

# Matches ``key = value`` style assignments for credential-like names so the
# value portion can be masked in report evidence.
_SECRET_VALUE_RE = re.compile(
    r"((?:api[_-]?key|token|password|passwd|secret)[\"']?\s*[:=]\s*[\"']?)([^\s\"',}]+)",
    re.IGNORECASE,
)

# Severity weights per pattern type (for per-pattern differentiation)
_SEVERITY_WEIGHTS = {
    "RSA_PRIVATE_KEY": "critical",
    "JWT_TOKEN": "high",
    "AWS_ACCESS_KEY": "critical",
    "CONNECTION_STRING": "high",
    "BASE64_SECRET": "medium",
    "HEX_SECRET": "medium",
    "API_KEY": "high",
    "TOKEN": "high",
    "PASSWORD": "critical",
    "ENV_SECRET": "medium",
}


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
                        severity = _SEVERITY_WEIGHTS.get(
                            key, rule.get("severity", "high")
                        )
                        findings.append({
                            "rule_id": "DATA_LEAKAGE",
                            "severity": severity,
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
