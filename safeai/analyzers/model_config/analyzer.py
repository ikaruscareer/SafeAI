"""Model configuration analyzer — deep analysis of AI model settings.

Examines model constructor calls and config blocks for unsafe settings:
  - Unsafe temperature values
  - Missing content filters or safety settings
  - Explicitly disabled safety features
"""

_UNSAFE_TEMP_THRESHOLD = 1.0

# Keys that indicate content filtering / safety mechanisms
_SAFETY_KEYS = {
    "safety_settings", "content_filter", "moderation", "guardrails",
    "safety", "content_policy", "filter", "blocked_categories",
    "safe_search", "grounding", "recitation_check",
}

# Values that explicitly disable safety
_DISABLED_VALUES = {"none", "disabled", "off", "false", "0", "block_none", "no_filter"}

# Absence is only actionable where the provider exposes a known safety
# control. Generic OpenAI/Anthropic wrapper defaults are not observable here.
_REQUIRED_SAFETY_KEYS = {
    "google": {"safety_settings"},
    "bedrock": {"guardrail_config"},
    "azure": {"content_filter", "content_policy"},
}


def _base_finding(rule_id, rule, message, path, line, evidence=None, reason=None, score_contribution=8):
    return {
        "rule_id": rule_id,
        "evidence_type": "static-config",  # #94 - reads declared model kwargs
        "severity": rule.get("severity", "medium"),
        "message": message,
        "file": path,
        "line": line,
        "owasp_llm": rule.get("owasp_llm", "LLM06"),
        "evidence": evidence or message,
        "reason": reason or message,
        "risk_category": "Safety",
        "affected_framework": "component",
        "affected_capability": "Model",
        "score_contribution": score_contribution,
        "remediation": "Enable content filters and set conservative generation parameters.",
        "confidence": 0.7,
    }


class ModelConfigAnalyzer:
    name = "model_config"

    def run(self, file_cache, rules, agent_models=None, components=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}

        for comp in (components or []):
            if comp.get("type") != "model_config":
                continue

            path = comp["file"]
            line = comp.get("line", 1)

            # --- Constructor call kwargs (Python) ---
            kwargs = comp.get("kwargs")
            if kwargs is not None:
                self._check_kwargs(kwargs, rule_map, path, line, findings, comp.get("provider", "unknown"))
                continue

            # --- Config file dict (YAML/JSON) ---
            data = comp.get("data")
            if isinstance(data, dict):
                self._check_config_dict(data, rule_map, path, line, findings, comp.get("provider", "unknown"))

        return findings

    def _check_kwargs(self, kwargs, rule_map, path, line, findings, provider):
        """Analyze model constructor keyword arguments."""
        temp = kwargs.get("temperature")
        if isinstance(temp, (int, float)) and temp > _UNSAFE_TEMP_THRESHOLD:
            findings.append(_base_finding(
                "MODEL_UNSAFE_TEMPERATURE",
                rule_map.get("MODEL_UNSAFE_TEMPERATURE", {}),
                f"Model temperature set to {temp} (>{_UNSAFE_TEMP_THRESHOLD})",
                path, line,
                evidence=f"temperature={temp}",
                reason="High temperature increases unpredictability and hallucination risk.",
                score_contribution=7,
            ))

        # Check for safety settings
        required_keys = _REQUIRED_SAFETY_KEYS.get(provider, set())
        has_safety = any(k in kwargs for k in required_keys)
        if required_keys and not has_safety:
            model_name = kwargs.get("model", kwargs.get("model_name", "unknown"))
            findings.append(_base_finding(
                "MODEL_MISSING_CONTENT_FILTER",
                rule_map.get("MODEL_MISSING_CONTENT_FILTER", {}),
                f"Model '{model_name}' lacks content filter / safety settings",
                path, line,
                evidence=f"kwargs: {sorted(kwargs.keys())}",
                reason="Absence of content filtering increases exposure to harmful outputs.",
                score_contribution=6,
            ))
        # Explicitly disabled settings are actionable for every provider.
        for sk in _SAFETY_KEYS:
            val = kwargs.get(sk)
            if val is not None and self._is_disabled(val):
                findings.append(_base_finding(
                    "MODEL_DISABLED_SAFETY",
                    rule_map.get("MODEL_DISABLED_SAFETY", {}),
                    f"Model safety setting '{sk}' is disabled ({val})",
                    path, line,
                    evidence=f"{sk}={val}",
                    reason="Explicitly disabled safety settings bypass output protections.",
                    score_contribution=12,
                ))

    def _check_config_dict(self, data, rule_map, path, line, findings, provider):
        """Analyze a model configuration dictionary from YAML/JSON."""
        temp = data.get("temperature")
        if isinstance(temp, (int, float)) and temp > _UNSAFE_TEMP_THRESHOLD:
            findings.append(_base_finding(
                "MODEL_UNSAFE_TEMPERATURE",
                rule_map.get("MODEL_UNSAFE_TEMPERATURE", {}),
                f"Model temperature set to {temp} (>{_UNSAFE_TEMP_THRESHOLD})",
                path, line,
                evidence=f"temperature={temp}",
                reason="High temperature increases unpredictability and hallucination risk.",
                score_contribution=7,
            ))

        # Flatten nested dicts to check all keys
        flat = self._flatten(data)

        required_keys = _REQUIRED_SAFETY_KEYS.get(provider, set())
        has_safety = any(k in flat for k in required_keys)
        if required_keys and not has_safety:
            model_name = data.get("model", data.get("model_name", "unknown"))
            findings.append(_base_finding(
                "MODEL_MISSING_CONTENT_FILTER",
                rule_map.get("MODEL_MISSING_CONTENT_FILTER", {}),
                f"Model '{model_name}' config lacks content filter / safety settings",
                path, line,
                evidence=f"keys: {sorted(flat.keys())}",
                reason="Absence of content filtering increases exposure to harmful outputs.",
                score_contribution=6,
            ))
        for sk in _SAFETY_KEYS:
            val = flat.get(sk)
            if val is not None and self._is_disabled(val):
                findings.append(_base_finding(
                    "MODEL_DISABLED_SAFETY",
                    rule_map.get("MODEL_DISABLED_SAFETY", {}),
                    f"Model safety setting '{sk}' is disabled ({val})",
                    path, line,
                    evidence=f"{sk}={val}",
                    reason="Explicitly disabled safety settings bypass output protections.",
                    score_contribution=12,
                ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_disabled(value):
        """Check if a safety setting value means 'disabled'."""
        if isinstance(value, str):
            return value.lower() in _DISABLED_VALUES
        if isinstance(value, bool):
            return not value
        if isinstance(value, (int, float)):
            return value == 0
        if isinstance(value, dict):
            # e.g. {"enabled": false}
            for k, v in value.items():
                if k.lower() in {"enabled", "active", "on"}:
                    return not v
        if isinstance(value, list):
            # e.g. safety_settings: [] means no settings configured
            return len(value) == 0
        return False

    @staticmethod
    def _flatten(data, prefix="", out=None):
        if out is None:
            out = {}
        if not isinstance(data, dict):
            return out
        for k, v in data.items():
            key = f"{prefix}{k}" if prefix else k
            if isinstance(v, dict):
                ModelConfigAnalyzer._flatten(v, prefix=f"{key}.", out=out)
            else:
                out[key] = v
        return out
