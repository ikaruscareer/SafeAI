"""Workflow template analyzer — deep analysis of workflow definitions.

Examines workflow YAML/JSON templates for security risks:
  - Missing human approval / gate steps
  - Insecure defaults
  - Capability sprawl (excessive permissions)
  - Missing input validation
"""

import json
import re

_APPROVAL_RE = re.compile(r"approv|gate|review|manual|human|sign[-_]?off|confirm", re.IGNORECASE)
_INSECURE_DEFAULT_RE = re.compile(
    r"auto_approve|allow_all|skip_validation|no_auth|no_gate|bypass|disabled.*auth|skip.*check",
    re.IGNORECASE,
)
_DANGEROUS_CAPABILITY_RE = re.compile(r"shell|exec|command|subprocess|delete|write|admin|root|sudo", re.IGNORECASE)
_VALIDATION_RE = re.compile(r"validat|check|verify|sanitiz|assert", re.IGNORECASE)


def _base_finding(rule_id, rule, message, path, line, evidence=None, reason=None, score_contribution=8):
    return {
        "rule_id": rule_id,
        "evidence_type": "static-config",  # #94 - reads declared workflow/graph structure
        "severity": rule.get("severity", "medium"),
        "message": message,
        "file": path,
        "line": line,
        "owasp_llm": rule.get("owasp_llm", "LLM06"),
        "evidence": evidence or message,
        "reason": reason or message,
        "risk_category": "Governance",
        "affected_framework": "component",
        "affected_capability": "Workflow",
        "score_contribution": score_contribution,
        "remediation": "Add approval gates, input validation, and scope capabilities.",
        "confidence": 0.7,
    }


class WorkflowAnalyzer:
    name = "workflow"

    def run(self, file_cache, rules, agent_models=None, components=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}

        for comp in (components or []):
            if comp.get("type") != "workflow":
                continue

            path = comp["file"]
            line = comp.get("line", 1)
            data = comp.get("data")

            if not isinstance(data, dict):
                continue

            serialized = json.dumps(data, default=str)

            # --- Missing approval gates ---
            steps = self._extract_steps(data)
            has_approval = any(_APPROVAL_RE.search(json.dumps(s, default=str)) for s in steps)
            if steps and not has_approval:
                findings.append(_base_finding(
                    "WORKFLOW_NO_APPROVAL",
                    rule_map.get("WORKFLOW_NO_APPROVAL", {}),
                    f"Workflow has {len(steps)} steps but no approval/gate step",
                    path, line,
                    evidence=f"steps={len(steps)}, no approval gate found",
                    reason="Autonomous workflows without human approval increase unchecked action risk.",
                    score_contribution=8,
                ))

            # --- Insecure defaults ---
            if _INSECURE_DEFAULT_RE.search(serialized):
                findings.append(_base_finding(
                    "WORKFLOW_INSECURE_DEFAULT",
                    rule_map.get("WORKFLOW_INSECURE_DEFAULT", {}),
                    "Workflow uses insecure defaults (auto-approve, skip validation, etc.)",
                    path, line,
                    evidence=serialized[:200],
                    score_contribution=8,
                ))

            # --- Capability sprawl ---
            dangerous_caps = []
            for step in steps:
                step_text = json.dumps(step, default=str)
                if _DANGEROUS_CAPABILITY_RE.search(step_text):
                    dangerous_caps.append(step.get("name", step.get("id", "unnamed")))
            if len(dangerous_caps) > 2:
                findings.append(_base_finding(
                    "WORKFLOW_CAPABILITY_SPRAWL",
                    rule_map.get("WORKFLOW_CAPABILITY_SPRAWL", {}),
                    f"Workflow grants dangerous capabilities in {len(dangerous_caps)} steps: {', '.join(dangerous_caps[:5])}",
                    path, line,
                    evidence=f"dangerous_steps={dangerous_caps}",
                    reason="Excessive capability grants without scoping increase attack surface.",
                    score_contribution=12,
                ))

            # --- Missing input validation ---
            has_validation = _VALIDATION_RE.search(serialized)
            if steps and not has_validation:
                findings.append(_base_finding(
                    "WORKFLOW_MISSING_VALIDATION",
                    rule_map.get("WORKFLOW_MISSING_VALIDATION", {}),
                    "Workflow steps lack input validation",
                    path, line,
                    evidence=f"steps={len(steps)}, no validation keywords found",
                    score_contribution=6,
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_steps(data):
        """Extract workflow steps/stages/nodes from a workflow dict."""
        for key in ("steps", "stages", "pipeline", "nodes", "tasks", "actions"):
            val = data.get(key)
            if isinstance(val, list):
                return val
        # Check nested structure
        for v in data.values():
            if isinstance(v, dict):
                result = WorkflowAnalyzer._extract_steps(v)
                if result:
                    return result
        return []
