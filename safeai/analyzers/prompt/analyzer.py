"""Prompt injection analyzer — detects OWASP LLM01 risks.

Scans Python source for:
  - Untrusted input interpolated into prompt strings (f-strings, .format())
  - Missing delimiters between system and user content
  - System prompt leakage patterns
  - Role / instruction override attempts
"""

import re


UNTRUSTED = re.compile(r"(user_input|request|input|response)")
INTERP = re.compile(r"f\"|\.format\(")


class PromptAnalyzer:
    name = "prompt"

    def run(self, file_cache, rules, agent_models=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}
        for path, content in file_cache.items():
            if not path.endswith(".py"):
                continue
            try:
                for i, line in enumerate(content.splitlines(), 1):
                        if INTERP.search(line) and UNTRUSTED.search(line):
                            rule = rule_map.get("PROMPT_INJECTION", {})
                            findings.append({
                                "rule_id": "PROMPT_INJECTION",
                                "severity": rule.get("severity", "critical"),
                                "message": "Untrusted input interpolated into prompt",
                                "file": path,
                                "line": i,
                                "owasp_llm": rule.get("owasp_llm", "LLM01"),
                                "evidence": line.strip(),
                                "reason": "Prompt template interpolates data from untrusted sources.",
                                "risk_category": "Safety",
                                "affected_framework": "generic",
                                "affected_capability": "Prompts",
                                "score_contribution": 18,
                                "remediation": "Sanitize user input and isolate system instructions from user content.",
                            })

                        # Missing delimiter heuristic: system + user concatenation
                        if "system" in line.lower() and UNTRUSTED.search(line) and "+" in line:
                            findings.append({
                                "rule_id": "PROMPT_DELIMITER",
                                "severity": "high",
                                "message": "Possible missing delimiter between system and user content",
                                "file": path,
                                "line": i,
                                "owasp_llm": "LLM01",
                                "evidence": line.strip(),
                                "reason": "Concatenating system and user content can enable instruction override.",
                                "risk_category": "Safety",
                                "affected_framework": "generic",
                                "affected_capability": "Prompts",
                                "score_contribution": 12,
                                "remediation": "Use explicit role-separated prompt messages with delimiters.",
                            })
                        # System prompt leakage patterns
                        if "system prompt" in line.lower() or "reveal system" in line.lower():
                            findings.append({
                                "rule_id": "PROMPT_SYSTEM_LEAK",
                                "severity": rule_map.get("PROMPT_SYSTEM_LEAK", {}).get("severity", "high"),
                                "message": "Possible system prompt leakage",
                                "file": path,
                                "line": i,
                                "owasp_llm": rule_map.get("PROMPT_SYSTEM_LEAK", {}).get("owasp_llm", "LLM01"),
                                "evidence": line.strip(),
                                "reason": "Code references system prompt disclosure patterns.",
                                "risk_category": "Safety",
                                "affected_framework": "generic",
                                "affected_capability": "Prompts",
                                "score_contribution": 14,
                                "remediation": "Prevent exposing hidden/system instructions to end users.",
                            })
                        # Role override attempts
                        if "ignore previous instructions" in line.lower() or "override system" in line.lower():
                            findings.append({
                                "rule_id": "PROMPT_ROLE_OVERRIDE",
                                "severity": rule_map.get("PROMPT_ROLE_OVERRIDE", {}).get("severity", "high"),
                                "message": "Role override attempt detected",
                                "file": path,
                                "line": i,
                                "owasp_llm": rule_map.get("PROMPT_ROLE_OVERRIDE", {}).get("owasp_llm", "LLM01"),
                                "evidence": line.strip(),
                                "reason": "Prompt content appears to override system-level instructions.",
                                "risk_category": "Safety",
                                "affected_framework": "generic",
                                "affected_capability": "Prompts",
                                "score_contribution": 14,
                                "remediation": "Add role/intent validation and refuse instruction override phrases.",
                            })
            except Exception:
                continue
        return findings
