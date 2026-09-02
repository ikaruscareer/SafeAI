"""Governance analyzer — detects missing operational governance controls.

Scans agent tool configurations and code for missing governance signals:
timeout configuration, retry policy, approval workflow (HITL), audit logging,
and rate limiting. These are operational controls that should be present
on production agent deployments.

Each missing governance control emits a finding with ``risk_category:
"Governance"`` and a ``GOV_*`` rule ID, feeding the existing governance
scoring category and HTML report governance summary section.
"""

import re

# Patterns for detecting governance controls in code
_TIMEOUT_RE = re.compile(
    r"\b(?:timeout|time_out|request_timeout|connect_timeout|read_timeout)"
    r"(?:\s*[=:]\s*|\s*\()",
    re.IGNORECASE,
)
_RETRY_RE = re.compile(
    r"\b(?:retry|retries|max_retries|retry_count|retry_policy|backoff|exponential_backoff)"
    r"(?:\s*[=:]\s*|\s*\()",
    re.IGNORECASE,
)
_APPROVAL_RE = re.compile(
    r"\b(?:approval|approve|human_in_the_loop|hitl|confirm|confirmation)"
    r"(?:\s*[=:]\s*|\s*\()",
    re.IGNORECASE,
)
_AUDIT_RE = re.compile(
    r"\b(?:audit|logging|log_event|trace|tracing|structured_log)"
    r"(?:\s*[=:]\s*|\s*\()",
    re.IGNORECASE,
)
_RATE_LIMIT_RE = re.compile(
    r"\b(?:rate_limit|rate_limiting|throttle|throttling|requests_per|rate_per)"
    r"(?:\s*[=:]\s*|\s*\()",
    re.IGNORECASE,
)
_CIRCUIT_BREAKER_RE = re.compile(
    r"\b(?:circuit_breaker|CircuitBreaker|breaker|circuit_break)"
    r"(?:\s*[=:]\s*|\s*\()",
    re.IGNORECASE,
)
_BACKPRESSURE_RE = re.compile(
    r"\b(?:backpressure|back_pressure|queue_size|max_concurrent|max_workers)"
    r"(?:\s*[=:]\s*|\s*\()",
    re.IGNORECASE,
)
_HEALTH_CHECK_RE = re.compile(
    r"\b(?:health_check|healthcheck|liveness|readiness|is_healthy)"
    r"(?:\s*[=:]\s*|\s*\()",
    re.IGNORECASE,
)

def _find_governance_controls(content, near_line=None, window=10):
    """Scan file content for governance control patterns.

    When ``near_line`` is provided only lines within ``window`` lines of
    that position are checked.  This scopes the search to the tool's own
    definition region and avoids masking missing controls in other tools
    in the same module.

    Returns a set of control names found in the scanned region.
    """
    controls = set()

    patterns = {
        "timeout": _TIMEOUT_RE,
        "retry": _RETRY_RE,
        "approval": _APPROVAL_RE,
        "audit": _AUDIT_RE,
        "rate_limit": _RATE_LIMIT_RE,
        "circuit_breaker": _CIRCUIT_BREAKER_RE,
        "backpressure": _BACKPRESSURE_RE,
        "health_check": _HEALTH_CHECK_RE,
    }

    for i, line in enumerate(content.splitlines(), 1):
        if near_line is not None and (i < near_line - window or i > near_line + window):
            continue
        for name, pattern in patterns.items():
            if pattern.search(line):
                controls.add(name)

    return controls


def _tool_has_control(tool_data, control_name):
    """Check if a tool's kwargs contain a governance control."""
    kwargs = tool_data.get("kwargs") or tool_data.get("config") or {}
    if isinstance(kwargs, dict):
        key_map = {
            "timeout": ["timeout", "time_out", "request_timeout", "connect_timeout"],
            "retry": ["retry", "retries", "max_retries", "retry_policy", "backoff"],
            "approval": ["approval", "human_in_the_loop", "hitl", "confirm"],
            "audit": ["audit", "logging", "log_event", "trace"],
            "rate_limit": ["rate_limit", "throttle", "rate_per"],
            "circuit_breaker": ["circuit_breaker", "breaker", "circuit_break"],
            "backpressure": ["backpressure", "back_pressure", "queue_size", "max_concurrent", "max_workers"],
            "health_check": ["health_check", "healthcheck", "liveness", "readiness", "is_healthy"],
        }
        for key in key_map.get(control_name, []):
            if key in kwargs:
                return True
    return False


def _finding(rule_id, rule, message, path, line, tool_name=None, evidence=None, control=None):
    """Create a governance finding dict, deriving severity/owasp from the rule."""
    sev = rule.get("severity", "medium")
    owasp = rule.get("owasp_llm", "LLM05")
    if control:
        remediation = rule.get("remediation") or f"Add {control} configuration to this tool."
    else:
        remediation = rule.get("remediation") or "Add the missing governance control to this tool."
    return {
        "rule_id": rule_id,
        "evidence_type": "static-config",  # #94 - reports a declared control being absent
        "severity": sev,
        "message": message,
        "file": path,
        "line": line,
        "owasp_llm": owasp,
        "evidence": evidence or message,
        "reason": f"Missing governance control on agent tool: {tool_name or 'unknown'}",
        "risk_category": "Governance",
        "affected_framework": "generic",
        "affected_capability": "Governance",
        "score_contribution": int(rule.get("score_contribution", 8)),
        "remediation": remediation,
        "confidence": "heuristic",
        "scope": "static-analysis",
        "limitation": (
            "Source-level pattern matching only; no runtime verification of "
            "whether the control is actually enforced."
        ),
    }


class GovernanceAnalyzer:
    """Detects missing operational governance controls on agent tools.

    Checks for: timeout, retry, approval (HITL), audit logging, and rate limiting.
    Each missing control emits a ``GOV_*`` finding with medium severity.
    """

    name = "governance"

    def run(self, file_cache, rules, agent_models=None, components=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}
        seen = set()

        # Phase 1: Check tool-level governance controls from agent_models.
        # Dedup per (file, tool, control) so every real tool gap is reported
        # rather than collapsing to a single finding per control.
        for model in agent_models or []:
            path = model.get("file")
            data = model.get("data", {})
            tools = data.get("tools") or []
            content = (file_cache or {}).get(path, "") if path else ""

            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                tool_name = tool.get("name") or tool.get("tool_name") or "unknown"
                tool_line = tool.get("line", 1)
                # Source-level confirmation scoped to the tool's definition
                # region: if the module declares the control near this tool,
                # treat it as present (reduces false positives where the
                # control lives elsewhere in the module).
                source_controls = (
                    _find_governance_controls(content, near_line=tool_line)
                    if content
                    else set()
                )

                for control in ["timeout", "retry", "approval", "audit", "rate_limit",
                                "circuit_breaker", "backpressure", "health_check"]:
                    if _tool_has_control(tool, control):
                        continue
                    if control in source_controls:
                        continue

                    rule_id = f"GOV_{control.upper()}_MISSING"
                    key = (path, tool_name, rule_id)
                    if key in seen:
                        continue
                    seen.add(key)

                    rule = rule_map.get(rule_id, {})
                    findings.append(_finding(
                        rule_id=rule_id,
                        rule=rule,
                        message=(
                            f"Observation: tool '{tool_name}' does not declare "
                            f"{control} in source within ±10 lines of its definition "
                            f"(not verified at runtime)"
                        ),
                        path=path,
                        line=tool.get("line", 1),
                        tool_name=tool_name,
                        evidence=f"tool={tool_name} missing={control}",
                        control=control,
                    ))

        return findings
