"""Tool definition analyzer — deep analysis of agent tool implementations.

Examines tool function bodies in Python code for security risks:
  - Missing input validation
  - Dangerous parameter patterns
  - Excessive permission grants
  - Shell execution access
"""

import ast
import re

from safeai.analysis.semantic import _name_of

_SHELL_RE = re.compile(r"subprocess|os\.system|popen|os\.popen|shell\s*=\s*True", re.IGNORECASE)
_EXEC_RE = re.compile(r"\bexec\(|\beval\(|os\.system", re.IGNORECASE)
_WRITE_RE = re.compile(r"\bopen\([^)]*[\"'](?:w|a|x|r\+)[bt+]?[\"']", re.IGNORECASE)
_DELETE_RE = re.compile(r"\bos\.(remove|unlink|rmdir|removedirs|rename|replace)\b", re.IGNORECASE)

_DANGEROUS_PARAM_NAMES = {"cmd", "command", "shell", "script", "code", "expression", "eval", "exec", "query", "sql", "path", "filename", "file_path", "filepath", "url", "uri", "endpoint"}

_PERMISSION_KEYWORDS = {"permission", "permissions", "allowed", "scope", "scopes", "grant", "access", "role", "roles", "admin", "write", "delete", "execute", "all", "*"}


def _base_finding(rule_id, rule, message, path, line, evidence=None, reason=None, score_contribution=8):
    return {
        "rule_id": rule_id,
        "evidence_type": "static-config",  # #94 - parses tool definitions from the AST
        "severity": rule.get("severity", "medium"),
        "message": message,
        "file": path,
        "line": line,
        "owasp_llm": rule.get("owasp_llm", "LLM06"),
        "evidence": evidence or message,
        "reason": reason or message,
        "risk_category": "Capability",
        "affected_framework": "component",
        "affected_capability": "Tool",
        "score_contribution": score_contribution,
        "remediation": "Apply input validation, least privilege, and sandboxing to tool functions.",
        "confidence": 0.7,
    }


class ToolDefAnalyzer:
    name = "tool_def"

    def run(self, file_cache, rules, agent_models=None, components=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}

        for comp in (components or []):
            if comp.get("type") != "tool":
                continue

            path = comp["file"]
            line = comp.get("line", 1)
            content = file_cache.get(path, "")

            if not path.endswith(".py") or not content:
                continue

            try:
                tree = ast.parse(content)
            except Exception:
                continue

            # Find the tool function definition in the AST
            tool_name = comp.get("name")
            func_node = None
            if tool_name:
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == tool_name:
                        func_node = node
                        break

            if func_node is None:
                continue

            # --- Missing input validation ---
            has_validation = self._has_input_validation(func_node)
            if not has_validation:
                findings.append(_base_finding(
                    "TOOL_MISSING_VALIDATION",
                    rule_map.get("TOOL_MISSING_VALIDATION", {}),
                    f"Tool function '{tool_name}' lacks input validation",
                    path, func_node.lineno,
                    evidence=f"Function {tool_name} has no type checks, isinstance, or validation calls",
                    score_contribution=7,
                ))

            # --- Dangerous parameter names ---
            dangerous = self._find_dangerous_params(func_node)
            if dangerous:
                findings.append(_base_finding(
                    "TOOL_DANGEROUS_PARAMS",
                    rule_map.get("TOOL_DANGEROUS_PARAMS", {}),
                    f"Tool function '{tool_name}' accepts dangerous parameters: {', '.join(dangerous)}",
                    path, func_node.lineno,
                    evidence=f"params={dangerous}",
                    reason="Parameter names like cmd/command/shell suggest command execution risk.",
                    score_contribution=12,
                ))

            # --- Shell access ---
            func_source = ast.get_source_segment(content, func_node) or ""
            if _SHELL_RE.search(func_source):
                findings.append(_base_finding(
                    "TOOL_SHELL_ACCESS",
                    rule_map.get("TOOL_SHELL_ACCESS", {}),
                    f"Tool function '{tool_name}' invokes shell execution",
                    path, func_node.lineno,
                    evidence=func_source[:200],
                    score_contribution=15,
                ))

            # --- Excessive permissions in decorator/call kwargs ---
            excessive = self._find_excessive_permissions(comp, content)
            if excessive:
                findings.append(_base_finding(
                    "TOOL_EXCESSIVE_PERMISSIONS",
                    rule_map.get("TOOL_EXCESSIVE_PERMISSIONS", {}),
                    f"Tool '{tool_name}' grants excessive permissions",
                    path, line,
                    evidence=excessive,
                    score_contribution=12,
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _has_input_validation(func_node):
        """Check if the function body contains any input validation patterns."""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                cname = _name_of(node.func) or ""
                base = cname.rsplit(".", 1)[-1] if "." in cname else cname
                if base in {"isinstance", "issubclass", "validate", "check", "assert_"}:
                    return True
            if isinstance(node, ast.Assert):
                return True
            if isinstance(node, ast.If):
                # Heuristic: if there's a conditional before any dangerous call,
                # treat it as basic validation
                return True
        return False

    @staticmethod
    def _find_dangerous_params(func_node):
        """Find parameter names that suggest dangerous operations."""
        dangerous = []
        for arg in func_node.args.args + func_node.args.posonlyargs + func_node.args.kwonlyargs:
            if arg.arg in _DANGEROUS_PARAM_NAMES:
                dangerous.append(arg.arg)
        if func_node.args.vararg and func_node.args.vararg.arg in _DANGEROUS_PARAM_NAMES:
            dangerous.append(func_node.args.vararg.arg)
        if func_node.args.kwarg and func_node.args.kwarg.arg in _DANGEROUS_PARAM_NAMES:
            dangerous.append(func_node.args.kwarg.arg)
        return dangerous

    @staticmethod
    def _find_excessive_permissions(comp, content):
        """Check decorator or constructor kwargs for excessive permission values."""
        # For decorated functions, look at the decorator line
        if comp.get("decorator"):
            # Search for permission-related kwargs in the decorator call
            deco_line = comp.get("line", 1)
            lines = content.splitlines()
            if deco_line <= len(lines):
                deco_text = lines[deco_line - 1]
                for kw in _PERMISSION_KEYWORDS:
                    if kw in deco_text.lower() and ("all" in deco_text.lower() or "*" in deco_text or "admin" in deco_text.lower()):
                        return f"decorator={deco_text.strip()}"
        return None
