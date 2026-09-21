"""Tests for the minimal policy-as-code evaluator."""

import os

import pytest

from safeai.cmd.cli import main
from safeai.kya.policy import PolicyError, evaluate_policy, load_policy


def _report(findings, capabilities=None, frameworks=None, mcp_assets=None):
    return {
        "findings": findings,
        "normalized_capabilities": capabilities or [],
        "detected_frameworks": frameworks or [],
        "mcp_assets": mcp_assets or [],
        "agent_models": [],
    }


def _finding(rule="CAP_shell", severity="high", status="new", **kw):
    base = {
        "rule_id": rule,
        "severity": severity,
        "status": status,
        "fingerprint": "f" * 64,
        "file": "src/agent.py",
    }
    base.update(kw)
    return base


def _write(tmp_path, content):
    path = os.path.join(str(tmp_path), "policy.yml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def test_default_when_no_policy():
    decision = evaluate_policy(None, _report([_finding()]))
    assert decision["outcome"] == "warn"
    assert decision["matches"] == []


def test_deny_outcome_on_match(tmp_path):
    path = _write(tmp_path, """
version: "1"
default_action: warn
policies:
  - id: deny-shell
    when:
      finding_ids: [CAP_shell]
    action: deny
    message: "No shell."
""")
    policy = load_policy(path)
    decision = evaluate_policy(policy, _report([_finding()]))
    assert decision["outcome"] == "block"
    assert decision["matches"][0]["policy_id"] == "deny-shell"
    assert decision["matches"][0]["matched"][0]["rule_id"] == "CAP_shell"


def test_action_precedence_deny_beats_review(tmp_path):
    path = _write(tmp_path, """
policies:
  - id: review-first
    when: {finding_ids: [CAP_shell]}
    action: require_review
  - id: deny-second
    when: {finding_ids: [CAP_shell]}
    action: deny
""")
    policy = load_policy(path)
    decision = evaluate_policy(policy, _report([_finding()]))
    assert decision["outcome"] == "block"
    assert len(decision["matches"]) == 2


def test_allow_policy(tmp_path):
    path = _write(tmp_path, """
default_action: warn
policies:
  - id: allow-examples
    when: {path_glob: "examples/**"}
    action: allow
    reason: "Intentionally vulnerable fixture."
""")
    policy = load_policy(path)
    decision = evaluate_policy(policy, _report([_finding(file="examples/demo.py")]))
    assert decision["outcome"] == "warn"  # allow never raises above default
    assert decision["matches"][0]["action"] == "allow"


def test_severity_selector(tmp_path):
    path = _write(tmp_path, """
policies:
  - id: deny-critical
    when: {min_severity: critical}
    action: deny
""")
    policy = load_policy(path)
    low = evaluate_policy(policy, _report([_finding(severity="high")]))
    assert low["outcome"] == "warn"
    crit = evaluate_policy(policy, _report([_finding(severity="critical")]))
    assert crit["outcome"] == "block"


def test_capability_selector(tmp_path):
    path = _write(tmp_path, """
policies:
  - id: deny-shell-cap
    when:
      capabilities_all: [shell]
      finding_ids: [CAP_shell]
    action: deny
""")
    policy = load_policy(path)
    caps = [{"name": "shell", "category": "Shell"}]
    decision = evaluate_policy(policy, _report([_finding()], capabilities=caps))
    assert decision["outcome"] == "block"
    no_caps = evaluate_policy(policy, _report([_finding()], capabilities=[]))
    assert no_caps["outcome"] == "warn"


def test_mcp_posture_selector(tmp_path):
    path = _write(tmp_path, """
policies:
  - id: review-remote-mcp-no-auth
    when:
      mcp:
        remote: true
        authentication_evidence: absent
    action: require_review
""")
    policy = load_policy(path)
    assets = [{"name": "remote-server", "remote": True, "authentication": None}]
    decision = evaluate_policy(policy, _report([_finding()], mcp_assets=assets))
    assert decision["outcome"] == "review-required"

    auth_assets = [{"name": "remote-server", "remote": True, "authentication": {"type": "oauth"}}]
    decision2 = evaluate_policy(policy, _report([_finding()], mcp_assets=auth_assets))
    assert decision2["outcome"] == "warn"


def test_suppressed_findings_do_not_block(tmp_path):
    path = _write(tmp_path, """
policies:
  - id: deny-shell
    when: {finding_ids: [CAP_shell]}
    action: deny
""")
    policy = load_policy(path)
    decision = evaluate_policy(policy, _report([_finding(status="suppressed")]))
    assert decision["outcome"] == "warn"  # match recorded, but not blocking
    assert len(decision["matches"]) == 1


def test_invalid_action_rejected(tmp_path):
    path = _write(tmp_path, """
policies:
  - id: bad
    when: {finding_ids: [X]}
    action: obliterate
""")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_policy_deny_fails_scan(kya_project, tmp_path):
    safeai_dir = os.path.join(kya_project["root"], ".safeai")
    os.makedirs(safeai_dir, exist_ok=True)
    with open(os.path.join(safeai_dir, "policy.yml"), "w") as fh:
        fh.write("""
policies:
  - id: deny-shell
    when: {finding_ids: [CAP_subprocess_shell]}
    action: deny
    message: "shell=True is not permitted."
""")
    rc = main(["scan", kya_project["root"],
               "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    assert rc == 1


def test_policy_match_reasons_in_manifest(kya_project, tmp_path):
    safeai_dir = os.path.join(kya_project["root"], ".safeai")
    os.makedirs(safeai_dir, exist_ok=True)
    with open(os.path.join(safeai_dir, "policy.yml"), "w") as fh:
        fh.write("""
policies:
  - id: review-shell
    when: {finding_ids: [CAP_subprocess_shell]}
    action: require_review
""")
    import json
    manifest_path = os.path.join(str(tmp_path), "m.json")
    main(["scan", kya_project["root"], "--manifest", manifest_path,
          "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    with open(manifest_path) as fh:
        manifest = json.load(fh)
    decision = manifest["summary"]["policy_decision"]
    assert decision["outcome"] == "review-required"
    assert any("review-shell" in r for r in decision["reasons"])


# ── WS1 (v2.4): review decision lanes ──────────────────────────────────

from safeai.kya.policy import (
    ACTION_OUTCOME,
    LANE_OF_ACTION,
    lane_of_finding,
)


def _policy_doc(policies, default_action="warn"):
    return {"version": "1", "default_action": default_action, "policies": policies}


def _matched(policy_id="p1", action="deny"):
    return {
        "version": "1",
        "default_action": "warn",
        "policies": [{
            "id": policy_id,
            "when": {"finding_ids": ["CAP_shell"]},
            "action": action,
            "message": f"{action} shell",
        }],
    }


def test_action_outcome_vocabulary_matches_contract():
    from safeai.kya.contract import POLICY_OUTCOMES

    assert set(ACTION_OUTCOME.values()) <= set(POLICY_OUTCOMES)
    assert ACTION_OUTCOME == {
        "allow": "pass",
        "warn": "warn",
        "require_review": "review-required",
        "deny": "block",
    }


def test_lane_assignment():
    assert LANE_OF_ACTION == {"allow": "A", "warn": "A", "require_review": "B", "deny": "A"}
    assert lane_of_finding({"gateability": "review-only"}) == "B"
    assert lane_of_finding({"gateability": "deterministic"}) == "A"
    assert lane_of_finding({}) == "A"


def test_decision_carries_action_lane_lanes(tmp_path):
    path = _write(tmp_path, """
policies:
  - id: deny-shell
    when: {finding_ids: [CAP_shell]}
    action: deny
""")
    policy = load_policy(path)
    decision = evaluate_policy(policy, _report([_finding()]))
    assert decision["outcome"] == "block"
    assert decision["action"] == "deny"
    assert decision["lane"] == "A"
    assert decision["lanes"] == {"A": 1, "B": 0}
    assert decision["matches"][0]["lane"] == "A"


def test_review_match_is_lane_b_question(tmp_path):
    path = _write(tmp_path, """
policies:
  - id: review-shell
    when: {finding_ids: [CAP_shell]}
    action: require_review
""")
    policy = load_policy(path)
    decision = evaluate_policy(policy, _report([_finding()]))
    assert decision["outcome"] == "review-required"
    assert decision["lane"] == "B"
    assert decision["lanes"] == {"A": 0, "B": 1}
    assert decision["matches"][0]["lane"] == "B"


def test_review_floor_new_prompt_definition(tmp_path):
    path = _write(tmp_path, """
default_action: allow
policies: []
""")
    policy = load_policy(path)
    finding = _finding(rule="PROMPT_INJECTION", severity="high", status="new")
    decision = evaluate_policy(policy, _report([finding]))
    assert decision["outcome"] == "review-required"
    assert decision["lane"] == "B"
    assert any("floor" in r for r in decision["reasons"])


def test_review_floor_ignores_suppressed(tmp_path):
    path = _write(tmp_path, """
default_action: allow
policies: []
""")
    policy = load_policy(path)
    finding = _finding(rule="PROMPT_INJECTION", severity="high", status="suppressed")
    decision = evaluate_policy(policy, _report([finding]))
    assert decision["outcome"] == "pass"


def test_review_floor_ignores_resolved(tmp_path):
    path = _write(tmp_path, """
default_action: allow
policies: []
""")
    policy = load_policy(path)
    finding = _finding(rule="SKILL_EMBEDDED_PROMPT", severity="medium", status="resolved")
    decision = evaluate_policy(policy, _report([finding]))
    assert decision["outcome"] == "pass"


def test_review_floor_never_lowers_deny(tmp_path):
    path = _write(tmp_path, """
default_action: warn
policies:
  - id: deny-prompt
    when: {finding_ids: [PROMPT_INJECTION]}
    action: deny
""")
    policy = load_policy(path)
    finding = _finding(rule="PROMPT_INJECTION", severity="critical", status="new")
    decision = evaluate_policy(policy, _report([finding]))
    assert decision["outcome"] == "block"


def test_manifest_decision_validates_against_contract(kya_project, tmp_path):
    import json

    from safeai.kya.contract import validate_manifest

    safeai_dir = os.path.join(kya_project["root"], ".safeai")
    os.makedirs(safeai_dir, exist_ok=True)
    with open(os.path.join(safeai_dir, "policy.yml"), "w") as fh:
        fh.write("""
policies:
  - id: deny-shell
    when: {finding_ids: [CAP_subprocess_shell]}
    action: deny
""")
    manifest_path = os.path.join(str(tmp_path), "m.json")
    main(["scan", kya_project["root"], "--manifest", manifest_path,
          "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    with open(manifest_path) as fh:
        manifest = json.load(fh)
    errors, _ = validate_manifest(manifest)
    assert errors == []
