"""Minimal, deterministic policy-as-code evaluation (``.safeai/policy.yml``).

Intentionally constrained — this is not OPA/Rego/Cedar. Policies select
on static scan evidence (rule IDs, severities, capabilities, frameworks,
agents, paths, MCP posture) and map to one of four actions:

    allow < warn < require_review < deny

The overall outcome is the highest-precedence action across all matched
policies (``default_action`` when nothing matches). A ``deny`` outcome
never means "the application is unsafe"; a ``pass``/``allow`` outcome
never means "the application is safe or compliant". It is a statement
about *static evidence matched against local policy* only.
"""

import fnmatch
import os

import yaml

from safeai.severity import rank as _severity_rank

DEFAULT_POLICY_PATH = os.path.join(".safeai", "policy.yml")

ACTIONS = ("allow", "warn", "require_review", "deny")
_ACTION_RANK = {action: index for index, action in enumerate(ACTIONS)}

#: Built-in profile names and their bundled YAML files.
_BUILTIN_PROFILES = {
    "developer": "developer.yml",
    "strict-ci": "strict-ci.yml",
    "mcp": "mcp.yml",
    "rag": "rag.yml",
    "production-agent": "production-agent.yml",
}


class PolicyError(Exception):
    """Raised for invalid policy files."""


def load_profile(name):
    """Load a built-in policy profile by name. Returns the profile dict
    (with ``policies`` list) or ``None`` if the name is unknown.

    Built-in profiles are bundled in ``safeai/policy_profiles/`` as YAML
    files. The profile's policies are composable: they extend (not replace)
    the user's ``.safeai/policy.yml`` policies.
    """
    filename = _BUILTIN_PROFILES.get(name)
    if not filename:
        return None
    profile_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policy_profiles")
    path = os.path.join(profile_dir, filename)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            document = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"Unable to read profile {name!r}: {exc}") from exc
    if not isinstance(document, dict):
        raise PolicyError(f"Profile {name!r}: document must be a mapping.")
    policies = document.get("policies") or []
    if not isinstance(policies, list):
        raise PolicyError(f"Profile {name!r}: 'policies' must be a list.")
    validated = []
    for index, raw in enumerate(policies, 1):
        if not isinstance(raw, dict):
            raise PolicyError(f"Profile {name!r} policy #{index}: entry must be a mapping.")
        action = str(raw.get("action", "")).lower()
        if action not in _ACTION_RANK:
            raise PolicyError(f"Profile {name!r} policy #{index}: invalid action {action!r}.")
        if not raw.get("id"):
            raise PolicyError(f"Profile {name!r} policy #{index}: missing required 'id'.")
        validated.append({
            "id": str(raw["id"]),
            "when": raw.get("when") or {},
            "action": action,
            "message": raw.get("message") or raw.get("reason") or "",
        })
    return {
        "version": str(document.get("version", "1")),
        "description": document.get("description") or "",
        "default_action": str(document.get("default_action", "warn")).lower(),
        "policies": validated,
    }


def merge_profile(profile, user_policy):
    """Merge a built-in profile into a user policy document.

    Returns a new policy dict with the profile's policies prepended to the
    user's policies. The user's ``default_action`` is preserved. Profile
    policy IDs are prefixed with the profile name to avoid collisions.
    """
    if profile is None:
        return user_policy
    prefix = profile.get("description", "").split(".")[0].lower().replace(" ", "_")[:16] or "profile"
    profile_policies = []
    for pol in profile.get("policies") or []:
        merged = dict(pol)
        merged["id"] = f"{prefix}:{pol['id']}"
        merged["profile"] = True
        profile_policies.append(merged)
    user_policies = user_policy.get("policies") if user_policy else []
    merged_doc = {
        "version": "1",
        "default_action": (user_policy or {}).get("default_action", profile.get("default_action", "warn")),
        "policies": profile_policies + list(user_policies),
    }
    return merged_doc


def default_policy_path(root):
    return os.path.join(root, DEFAULT_POLICY_PATH)


def load_policy(path):
    """Load and validate a policy file. Returns ``None`` when absent."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            document = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"Unable to read policy file {path}: {exc}") from exc

    if not isinstance(document, dict):
        raise PolicyError(f"Policy file {path}: top-level document must be a mapping.")

    default_action = str(document.get("default_action", "warn")).lower()
    if default_action not in _ACTION_RANK:
        raise PolicyError(f"Policy file {path}: invalid default_action {default_action!r}.")

    policies = document.get("policies") or []
    if not isinstance(policies, list):
        raise PolicyError(f"Policy file {path}: 'policies' must be a list.")

    validated = []
    for index, raw in enumerate(policies, 1):
        if not isinstance(raw, dict):
            raise PolicyError(f"Policy #{index}: entry must be a mapping.")
        action = str(raw.get("action", "")).lower()
        if action not in _ACTION_RANK:
            raise PolicyError(f"Policy #{index}: invalid or missing action {action!r}.")
        if not raw.get("id"):
            raise PolicyError(f"Policy #{index}: missing required 'id'.")
        validated.append({
            "id": str(raw["id"]),
            "when": raw.get("when") or {},
            "action": action,
            "message": raw.get("message") or raw.get("reason") or "",
        })

    return {
        "version": str(document.get("version", "1")),
        "default_action": default_action,
        "policies": validated,
    }


def _finding_capabilities(report, finding):
    """Capabilities relevant to a finding: its own affected capability plus
    all normalized project capabilities (static, project-wide evidence)."""
    caps = set()
    affected = finding.get("affected_capability")
    if affected:
        caps.add(str(affected).lower())
    for cap in report.get("normalized_capabilities") or []:
        if cap.get("name"):
            caps.add(str(cap["name"]).lower())
    return caps


def _matches_when(when, finding, report):
    """Evaluate one policy's ``when`` block against a finding. Returns a
    list of human-readable match reasons (empty when not matched)."""
    reasons = []

    finding_ids = when.get("finding_ids") or when.get("rule_ids") or []
    if finding_ids:
        rid = str(finding.get("rule_id", ""))
        if rid not in [str(x) for x in finding_ids]:
            return []
        reasons.append(f"rule_id={rid}")

    severity = when.get("severity")
    if severity:
        wanted = [str(s).lower() for s in (severity if isinstance(severity, list) else [severity])]
        if str(finding.get("severity", "")).lower() not in wanted:
            return []
        reasons.append(f"severity={finding.get('severity')}")

    min_severity = when.get("min_severity")
    if min_severity:
        if _severity_rank(finding.get("severity")) < _severity_rank(min_severity):
            return []
        reasons.append(f"severity>={min_severity}")

    capabilities_all = when.get("capabilities_all") or []
    capabilities_any = when.get("capabilities_any") or []
    if capabilities_all or capabilities_any:
        caps = _finding_capabilities(report, finding)
        caps |= {str(c.get("category", "")).lower() for c in report.get("normalized_capabilities") or []}
        if capabilities_all and not all(str(c).lower() in caps for c in capabilities_all):
            return []
        if capabilities_any and not any(str(c).lower() in caps for c in capabilities_any):
            return []
        reasons.append("capability-match")

    frameworks = when.get("frameworks") or []
    if frameworks:
        fw = str(finding.get("affected_framework", "")).lower()
        detected = {str(f).lower() for f in report.get("detected_frameworks") or []}
        wanted = {str(f).lower() for f in frameworks}
        if fw not in wanted and not (detected & wanted):
            return []
        reasons.append(f"framework={fw or 'detected'}")

    agent = when.get("agent")
    if agent:
        agent_models = report.get("agent_models") or []
        names = set()
        for model in agent_models:
            for item in (model.get("data", {}).get("agents") or []):
                names.add(str(item.get("name") if isinstance(item, dict) else item).lower())
        if str(agent).lower() not in names:
            return []
        reasons.append(f"agent={agent}")

    path_glob = when.get("path_glob")
    if path_glob:
        finding_path = str(finding.get("file") or "").replace("\\", "/")
        if not fnmatch.fnmatch(finding_path, path_glob):
            return []
        reasons.append(f"path={finding_path}")

    mcp = when.get("mcp")
    if mcp:
        assets = report.get("mcp_assets") or []
        matched_asset = None
        for asset in assets:
            if "remote" in mcp:
                is_remote = bool(asset.get("remote")) or str(asset.get("transport", "")).lower() in {"http", "sse", "streamable-http"}
                if is_remote != bool(mcp["remote"]):
                    continue
            auth_req = mcp.get("authentication_evidence")
            if auth_req:
                has_auth = bool(asset.get("authentication") or asset.get("auth") or asset.get("auth_evidence"))
                if auth_req == "absent" and has_auth:
                    continue
                if auth_req == "present" and not has_auth:
                    continue
            matched_asset = asset
            break
        if matched_asset is None:
            return []
        reasons.append("mcp-posture-match")

    return reasons or ["matched"]


def evaluate_policy(policy, report):
    """Evaluate a policy document against a scan report.

    Suppressed findings do not contribute to blocking outcomes but are
    still recorded in match details for auditability. Evaluation order is
    deterministic (file order), and the outcome uses action precedence.

    Returns a decision dict: ``outcome``, ``reasons``, ``matches``.
    """
    if policy is None:
        return {
            "outcome": "warn",
            "reasons": ["No policy file supplied; default posture 'warn'."],
            "matches": [],
        }

    matches = []
    highest = _ACTION_RANK[policy["default_action"]]
    outcome = policy["default_action"]

    for pol in policy["policies"]:
        matched_findings = []
        for finding in report.get("findings") or []:
            reasons = _matches_when(pol["when"], finding, report)
            if reasons:
                matched_findings.append({
                    "fingerprint": finding.get("fingerprint"),
                    "rule_id": finding.get("rule_id"),
                    "status": finding.get("status", "unknown"),
                    "reasons": reasons,
                })
        if not matched_findings:
            continue

        active = [m for m in matched_findings if m["status"] != "suppressed"]
        match_record = {
            "policy_id": pol["id"],
            "action": pol["action"],
            "message": pol["message"],
            "matched": matched_findings,
        }
        matches.append(match_record)

        if active and _ACTION_RANK[pol["action"]] > highest:
            highest = _ACTION_RANK[pol["action"]]
            outcome = pol["action"]

    reasons = [
        f"Policy '{m['policy_id']}' matched {len(m['matched'])} finding(s) -> {m['action']}"
        for m in matches
    ]
    if not reasons:
        reasons.append(f"No policies matched; default action '{policy['default_action']}'.")

    return {"outcome": outcome, "reasons": reasons, "matches": matches}
