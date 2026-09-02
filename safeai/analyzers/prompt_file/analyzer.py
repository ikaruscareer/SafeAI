"""Prompt file analyzer — deep analysis of standalone prompt files.

Scans ``.prompt`` files, inline prompt templates in YAML/JSON configs,
and raw prompt text for security risks:
  - Injection-prone patterns (untrusted placeholder interpolation)
  - System prompt exposure / leakage
  - Role-override / jailbreak language
  - Untrusted input placeholders
"""

import re

_UNTRUSTED_PLACEHOLDER_RE = re.compile(
    r"\{\{\s*(user_input|input|query|request|prompt|text|message|data|context)\s*\}\}"
    r"|\{\s*(user_input|input|query|request|prompt|text|message|data|context)\s*\}"
    r"|\$\{(user_input|input|query|request|prompt|text|message|data|context)\}",
    re.IGNORECASE,
)

_SYSTEM_PROMPT_EXPOSURE_RE = re.compile(
    r"system prompt|system message|reveal.*prompt|show.*prompt|print.*prompt|output.*prompt"
    r"|what.*your.*instructions|tell.*your.*instructions",
    re.IGNORECASE,
)

_ROLE_OVERRIDE_RE = re.compile(
    r"ignore\s+(previous|prior|above)\s+instructions?"
    r"|forget\s+(previous|prior|above)\s+instructions?"
    r"|override\s+system"
    r"|you\s+are\s+now\s+(a|an)\s+"
    r"|new\s+personality"
    r"|act\s+as\s+(if|though)\s+you\s+(are|were)",
    re.IGNORECASE,
)

_INJECTION_PRONE_RE = re.compile(
    r"\{\{.*\}\}"           # Mustache / Handlebars
    r"|\{[a-z_]+\}"          # Python .format()
    r"|\$\{[a-z_]+\}"        # Shell-style
    r"|%\([a-z_]+\)s",       # Old Python %
    re.IGNORECASE,
)


def _base_finding(rule_id, rule, message, path, line, evidence=None, reason=None, score_contribution=8):
    return {
        "rule_id": rule_id,
        "evidence_type": "static-pattern",  # #94 - regex patterns over prompt files
        "severity": rule.get("severity", "medium"),
        "message": message,
        "file": path,
        "line": line,
        "owasp_llm": rule.get("owasp_llm", "LLM01"),
        "evidence": evidence or message,
        "reason": reason or message,
        "risk_category": "Safety",
        "affected_framework": "component",
        "affected_capability": "Prompt",
        "score_contribution": score_contribution,
        "remediation": "Harden prompt templates against injection and unauthorized disclosure.",
        "confidence": 0.7,
    }


class PromptFileAnalyzer:
    name = "prompt_file"

    def run(self, file_cache, rules, agent_models=None, components=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}

        for comp in (components or []):
            if comp.get("type") != "prompt":
                continue

            path = comp["file"]
            line = comp.get("line", 1)
            content = comp.get("data") or file_cache.get(path, "")

            if not isinstance(content, str):
                # Structured data (dict from YAML/JSON) — serialize to string
                import json
                content = json.dumps(content, default=str)

            # --- Injection-prone interpolation ---
            if _INJECTION_PRONE_RE.search(content) and _UNTRUSTED_PLACEHOLDER_RE.search(content):
                findings.append(_base_finding(
                    "PROMPT_FILE_INJECTION",
                    rule_map.get("PROMPT_FILE_INJECTION", {}),
                    "Prompt file contains injection-prone untrusted placeholder",
                    path, line,
                    evidence=content[:200],
                    reason="Untrusted placeholders in prompt templates enable injection attacks.",
                    score_contribution=15,
                ))

            # --- System prompt exposure ---
            if _SYSTEM_PROMPT_EXPOSURE_RE.search(content):
                findings.append(_base_finding(
                    "PROMPT_FILE_SYSTEM_LEAK",
                    rule_map.get("PROMPT_FILE_SYSTEM_LEAK", {}),
                    "Prompt file references system prompt exposure",
                    path, line,
                    evidence=content[:200],
                    reason="References to system prompt content can enable extraction attacks.",
                    score_contribution=12,
                ))

            # --- Role override / jailbreak ---
            if _ROLE_OVERRIDE_RE.search(content):
                findings.append(_base_finding(
                    "PROMPT_FILE_ROLE_OVERRIDE",
                    rule_map.get("PROMPT_FILE_ROLE_OVERRIDE", {}),
                    "Prompt file contains role-override or jailbreak language",
                    path, line,
                    evidence=content[:200],
                    reason="Role override patterns can be used to bypass safety guidelines.",
                    score_contribution=13,
                ))

            # --- Untrusted placeholder (standalone check) ---
            if _UNTRUSTED_PLACEHOLDER_RE.search(content):
                findings.append(_base_finding(
                    "PROMPT_FILE_UNTRUSTED_PLACEHOLDER",
                    rule_map.get("PROMPT_FILE_UNTRUSTED_PLACEHOLDER", {}),
                    "Prompt file contains untrusted input placeholder",
                    path, line,
                    evidence=content[:200],
                    reason="Untrusted placeholders must be sanitized before model consumption.",
                    score_contribution=10,
                ))

        return findings
