"""Prompt injection analyzer — detects OWASP LLM01 risks.

Scans Python source and other text files for:
  - Untrusted input interpolated into prompt strings (f-strings, .format())
  - Missing delimiters between system and user content
  - System prompt leakage patterns
  - Role / instruction override attempts
  - Multi-line prompt concatenation (v1.8)
  - Cross-file prompt interpolation (v1.8)
  - Indirect injection via tool calls in prompts (v1.8)
  - XML/HTML tag injection in prompts (v1.8)
  - Template variable injection in .md files (v1.8)
"""

import re

UNTRUSTED = re.compile(r"(user_input|request|input|response)")
INTERP = re.compile(r"f\"|\.format\(")

# v1.8 deepened patterns
_MULTI_LINE_CONCAT = re.compile(
    r"""(?:["'].*?["']\s*\+\s*){2,}""", re.DOTALL
)
_PROMPT_FILE_INTERP = re.compile(
    r"""(?:read|load|open|Path|file).*\.(?:read|read_text|readlines)\(\)""",
    re.IGNORECASE,
)
_INDIRECT_INJECTION = re.compile(
    r"""(?:tool_call|function_call|invoke|execute|run)\s*\(""",
    re.IGNORECASE,
)
_XML_TAG_INJECTION = re.compile(
    r"""<(?:system|assistant|user|instructions?|context|prompt)""",
    re.IGNORECASE,
)
_TEMPLATE_VAR = re.compile(
    r"""\{\{.*?\}\}|\{[a-zA-Z_]\w*\}""",
)


def _has_multiline_concat(lines, start_idx):
    """Check if a prompt assignment spans multiple lines via concatenation."""
    block = "\n".join(lines[max(0, start_idx - 2):start_idx + 3])
    return bool(_MULTI_LINE_CONCAT.search(block))


def analyze_prompt_text(path, content, rule_map=None, framework="generic"):
    """Run the prompt-injection checks over any instruction text.

    Extracted verbatim from ``PromptAnalyzer.run`` so that non-Python
    instruction surfaces — Claude Code slash commands, subagent
    definitions — are analyzed by the same detectors instead of a second,
    divergent implementation. Behaviour for Python files is unchanged.
    """
    findings = []
    rule_map = rule_map or {}
    lines = content.splitlines()
    try:
        for i, line in enumerate(lines, 1):
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

            # --- v1.8 deepened detections ---

            # Multi-line prompt concatenation
            if ("+" in line
                    and any(kw in line.lower() for kw in ("prompt", "system", "message", "instruction"))
                    and _has_multiline_concat(lines, i - 1)):
                findings.append({
                    "rule_id": "PROMPT_MULTI_LINE_CONCAT",
                    "severity": "medium",
                    "message": "Multi-line prompt concatenation detected",
                    "file": path,
                    "line": i,
                    "owasp_llm": "LLM01",
                    "evidence": line.strip(),
                    "reason": "Multi-line string concatenation in prompts can obscure injected content.",
                    "risk_category": "Safety",
                    "affected_framework": framework,
                    "affected_capability": "Prompts",
                    "score_contribution": 10,
                    "remediation": "Use prompt templates or message arrays instead of string concatenation.",
                })

            # Cross-file prompt interpolation (reading a file into a prompt)
            if _PROMPT_FILE_INTERP.search(line) and any(kw in line.lower() for kw in ("prompt", "system", "message")):
                findings.append({
                    "rule_id": "PROMPT_CROSS_FILE_INTERP",
                    "severity": "medium",
                    "message": "Prompt content loaded from external file",
                    "file": path,
                    "line": i,
                    "owasp_llm": "LLM01",
                    "evidence": line.strip(),
                    "reason": "Loading prompt content from files allows indirect injection via file modification.",
                    "risk_category": "Safety",
                    "affected_framework": framework,
                    "affected_capability": "Prompts",
                    "score_contribution": 10,
                    "remediation": "Validate and sanitize file-loaded prompt content; use integrity checks.",
                })

            # Indirect injection via tool calls in prompts
            if _INDIRECT_INJECTION.search(line) and any(kw in line.lower() for kw in ("prompt", "system", "message", "user")):
                findings.append({
                    "rule_id": "PROMPT_INDIRECT_INJECTION",
                    "severity": "medium",
                    "message": "Tool call pattern detected near prompt context",
                    "file": path,
                    "line": i,
                    "owasp_llm": "LLM01",
                    "evidence": line.strip(),
                    "reason": "Heuristic: tool calls near prompt content may enable indirect injection if user-controlled.",
                    "risk_category": "Safety",
                    "affected_framework": framework,
                    "affected_capability": "Prompts",
                    "score_contribution": 10,
                    "remediation": "Separate tool execution from prompt construction; validate tool arguments.",
                })

            # XML/HTML tag injection in prompts
            if _XML_TAG_INJECTION.search(line):
                findings.append({
                    "rule_id": "PROMPT_XML_INJECTION",
                    "severity": "low",
                    "message": "XML/HTML tag pattern detected in prompt context",
                    "file": path,
                    "line": i,
                    "owasp_llm": "LLM01",
                    "evidence": line.strip(),
                    "reason": "Heuristic: XML tags in prompts may override system instructions if user-controlled.",
                    "risk_category": "Safety",
                    "affected_framework": framework,
                    "affected_capability": "Prompts",
                    "score_contribution": 6,
                    "remediation": "Escape or strip XML/HTML tags from user-controlled prompt content.",
                })

            # Template variable injection in .md files
            if (path.endswith((".md", ".txt", ".prompt", ".prompt.md", ".prompt.txt"))
                    and _TEMPLATE_VAR.search(line)
                    and any(kw in line.lower() for kw in ("system", "prompt", "instruction", "ignore"))):
                findings.append({
                    "rule_id": "PROMPT_TEMPLATE_INJECTION",
                    "severity": "medium",
                    "message": "Template variable in prompt file may enable injection",
                    "file": path,
                    "line": i,
                    "owasp_llm": "LLM01",
                    "evidence": line.strip(),
                    "reason": "Template variables in prompt files can be exploited to inject instructions.",
                    "risk_category": "Safety",
                    "affected_framework": framework,
                    "affected_capability": "Prompts",
                    "score_contribution": 10,
                    "remediation": "Validate template variables; avoid user-controlled values in system prompts.",
                })

    except Exception:
        return findings
    for finding in findings:
        finding["affected_framework"] = framework
    return findings


class PromptAnalyzer:
    name = "prompt"

    def run(self, file_cache, rules, agent_models=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}
        for path, content in sorted(file_cache.items()):
            if not path.endswith(".py"):
                continue
            findings.extend(analyze_prompt_text(path, content, rule_map))
        return findings
