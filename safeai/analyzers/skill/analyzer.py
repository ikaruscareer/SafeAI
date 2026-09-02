"""Skill analyzer — deep analysis of reusable AI skill files.

Analyzes standalone skill files (Semantic Kernel ``*.skill.*``, OpenAI
skill configs, custom skill definitions) for security risks:
  - Embedded prompts (injection surface)
  - Excessive permissions
  - Hardcoded secrets
  - Insecure defaults
  - Risky capability grants
"""

import json
import re

_SECRET_RE = re.compile(
    r"api[_-]?key\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    r"|token\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    r"|password\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    r"|secret\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)

_DANGEROUS_PERMISSIONS = {"admin", "root", "sudo", "system", "all", "*", "full_access", "write_all", "execute_all"}
_RISKY_CAPABILITY_RE = re.compile(r"shell|exec|command|subprocess|os\.system|eval\(|exec\(|file_write|delete", re.IGNORECASE)

_PROMPT_KEYS = {"prompt", "system_prompt", "user_prompt", "instructions", "template", "system_message", "content"}
_PERMISSION_KEYS = {"permissions", "allowed_actions", "scopes", "grants", "access"}
_DEFAULT_KEYS = {"default", "defaults", "fallback", "auto_approve", "allow_all"}
_CAPABILITY_KEYS = {"capabilities", "tools", "actions", "functions", "operations"}


def _base_finding(rule_id, rule, message, path, line, evidence=None, reason=None, score_contribution=8):
    return {
        "rule_id": rule_id,
        "evidence_type": "static-config",  # #94 - reads declared skill frontmatter
        "severity": rule.get("severity", "medium"),
        "message": message,
        "file": path,
        "line": line,
        "owasp_llm": rule.get("owasp_llm", "LLM06"),
        "evidence": evidence or message,
        "reason": reason or message,
        "risk_category": "Capability",
        "affected_framework": "component",
        "affected_capability": "Skill",
        "score_contribution": score_contribution,
        "remediation": "Harden skill configuration and apply least privilege.",
        "confidence": 0.7,
    }


class SkillAnalyzer:
    name = "skill"

    def run(self, file_cache, rules, agent_models=None, components=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}

        for comp in (components or []):
            if comp.get("type") != "skill":
                continue

            path = comp["file"]
            data = comp.get("data")
            content = file_cache.get(path, "")
            line = comp.get("line", 1)

            # ---- Parse raw content for text-level checks ----
            if _SECRET_RE.search(content):
                findings.append(_base_finding(
                    "SKILL_HARDCODED_SECRET",
                    rule_map.get("SKILL_HARDCODED_SECRET", {}),
                    "Hardcoded secret detected in skill file",
                    path, line,
                    evidence="secret pattern found in skill content",
                    score_contribution=20,
                ))

            # ---- Structured analysis of parsed YAML/JSON ----
            if not isinstance(data, dict):
                continue

            # Flatten nested dicts to a single level for key scanning.
            flat = self._flatten(data)

            # Embedded prompt
            prompt_keys = _PROMPT_KEYS & set(flat.keys())
            if prompt_keys:
                prompt_vals = [str(flat[k])[:120] for k in prompt_keys]
                findings.append(_base_finding(
                    "SKILL_EMBEDDED_PROMPT",
                    rule_map.get("SKILL_EMBEDDED_PROMPT", {}),
                    f"Skill contains embedded prompt keys: {', '.join(prompt_keys)}",
                    path, line,
                    evidence="; ".join(prompt_vals),
                    score_contribution=6,
                ))

            # Excessive permissions
            perm_keys = _PERMISSION_KEYS & set(flat.keys())
            for pk in perm_keys:
                perms = self._extract_permission_values(flat[pk])
                dangerous = [p for p in perms if p.lower() in _DANGEROUS_PERMISSIONS]
                if dangerous:
                    findings.append(_base_finding(
                        "SKILL_EXCESSIVE_PERMISSIONS",
                        rule_map.get("SKILL_EXCESSIVE_PERMISSIONS", {}),
                        f"Skill grants excessive permissions: {', '.join(dangerous)}",
                        path, line,
                        evidence=f"key={pk}, values={dangerous}",
                        score_contribution=14,
                    ))

            # Insecure defaults
            def_keys = _DEFAULT_KEYS & set(flat.keys())
            for dk in def_keys:
                val = flat[dk]
                if self._is_insecure_default(val):
                    findings.append(_base_finding(
                        "SKILL_INSECURE_DEFAULT",
                        rule_map.get("SKILL_INSECURE_DEFAULT", {}),
                        f"Skill has insecure default: {dk}={val}",
                        path, line,
                        evidence=f"{dk}: {val}",
                        score_contribution=7,
                    ))

            # Risky capability grants
            cap_keys = _CAPABILITY_KEYS & set(flat.keys())
            for ck in cap_keys:
                cap_text = json.dumps(flat[ck], default=str)
                if _RISKY_CAPABILITY_RE.search(cap_text):
                    findings.append(_base_finding(
                        "SKILL_RISKY_CAPABILITY",
                        rule_map.get("SKILL_RISKY_CAPABILITY", {}),
                        f"Skill grants risky capabilities via '{ck}'",
                        path, line,
                        evidence=cap_text[:160],
                        score_contribution=12,
                    ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _flatten(data, prefix="", out=None):
        """Flatten a nested dict to dot-notation keys."""
        if out is None:
            out = {}
        if not isinstance(data, dict):
            return out
        for k, v in data.items():
            key = f"{prefix}{k}" if prefix else k
            if isinstance(v, dict):
                SkillAnalyzer._flatten(v, prefix=f"{key}.", out=out)
            else:
                out[key] = v
        return out

    @staticmethod
    def _extract_permission_values(value):
        """Normalize a permission value to a list of strings."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        if isinstance(value, dict):
            return list(value.keys())
        return [str(value)]

    @staticmethod
    def _is_insecure_default(value):
        """Check if a default value represents an insecure configuration."""
        if isinstance(value, str):
            low = value.lower()
            return low in {"true", "yes", "allow", "all", "any", "none", "disabled", "off", "skip", "bypass", "*"}
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value == 0  # e.g. timeout=0 means no timeout
        return False
