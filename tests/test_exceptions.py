"""Tests for file-backed policy exception records (WS4, v2.4)."""

import os

import pytest

from safeai.cmd.cli import main
from safeai.kya.exceptions import (
    ExceptionError,
    evaluate_exceptions,
    load_exceptions,
)


def _write(path, content):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _entry(**overrides):
    base = {
        "exception_id": "SAFEAI-EXC-0042",
        "finding_or_policy": "GOV_APPROVAL_MISSING",
        "risk_owner": "eng-director@example.com",
        "rationale": "Read-only internal retrieval; no side effects.",
    }
    base.update(overrides)
    return base


def _finding(rule_id="GOV_APPROVAL_MISSING"):
    return {"rule_id": rule_id, "severity": "medium", "status": "new"}


class TestLoadExceptions:
    def test_missing_file_yields_empty(self, tmp_path):
        entries, warnings = load_exceptions(str(tmp_path / "nope.yml"))
        assert entries == [] and warnings == []

    def test_valid_file(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: SAFEAI-EXC-0042
    finding_or_policy: GOV_APPROVAL_MISSING
    scope:
      repository: acme/agent
      commit_range: "v2.4.0..v2.4.3"
    risk_owner: eng-director@example.com
    rationale: "Read-only internal retrieval."
    compensating_controls:
      - Human review before customer response
    expires_at: "2099-01-31"
    review_trigger:
      - New external tool
""")
        entries, _ = load_exceptions(path)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["exception_id"] == "SAFEAI-EXC-0042"
        assert entry["expired"] is False
        assert entry["compensating_controls"] == ["Human review before customer response"]
        assert entry["review_trigger"] == ["New external tool"]

    def test_expired_flagged(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E1
    finding_or_policy: CAP_shell
    risk_owner: owner@example.com
    rationale: "Legacy."
    expires_at: "2000-01-31"
""")
        entries, _ = load_exceptions(path)
        assert entries[0]["expired"] is True

    def test_missing_required_field_rejected(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E1
    finding_or_policy: CAP_shell
    rationale: "No owner."
""")
        with pytest.raises(ExceptionError):
            load_exceptions(path)

    def test_bad_date_rejected(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E1
    finding_or_policy: CAP_shell
    risk_owner: o@example.com
    rationale: "x"
    expires_at: "31-01-2099"
""")
        with pytest.raises(ExceptionError):
            load_exceptions(path)

    def test_explicit_target_type(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E2
    target_type: escalation
    target_id: ESC_MCP_SERVER_ADDED
    risk_owner: o@example.com
    rationale: "Reviewed."
""")
        entries, _ = load_exceptions(path)
        assert entries[0]["target_type"] == "escalation"
        assert entries[0]["target_id"] == "ESC_MCP_SERVER_ADDED"

    def test_legacy_key_auto_classified(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E3
    finding_or_policy: CAP_shell
    risk_owner: o@example.com
    rationale: "Legacy file."
""")
        entries, _ = load_exceptions(path)
        assert entries[0]["target_type"] == "unspecified"
        assert entries[0]["target_id"] == "CAP_shell"

    def test_unknown_target_type_rejected(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E4
    target_type: vibe
    target_id: X
    risk_owner: o@example.com
    rationale: "x"
""")
        with pytest.raises(ExceptionError):
            load_exceptions(path)

    def test_split_target_keys_rejected(self, tmp_path):
        path = _write(str(tmp_path / "e.yml"), """
exceptions:
  - exception_id: E5
    target_type: finding
    risk_owner: o@example.com
    rationale: "x"
""")
        with pytest.raises(ExceptionError):
            load_exceptions(path)


class TestEvaluateExceptions:
    def test_active(self):
        evaluations = evaluate_exceptions([_entry()], [_finding()], [])
        assert evaluations[0]["state"] == "active"
        assert evaluations[0]["warnings"] == []

    def test_expired(self):
        entry = _entry()
        entry["expired"] = True
        entry["expires_at"] = "2000-01-31"
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] == "expired"
        assert evaluations[0]["warnings"]

    def test_stale_when_nothing_matches(self):
        evaluations = evaluate_exceptions([_entry()], [_finding("CAP_http")], [])
        assert evaluations[0]["state"] == "stale"
        assert evaluations[0]["warnings"]

    def test_escalation_id_matches(self):
        evaluations = evaluate_exceptions(
            [_entry(finding_or_policy="ESC_MCP_SERVER_ADDED")], [],
            [{"id": "ESC_MCP_SERVER_ADDED", "severity": "high"}])
        assert evaluations[0]["state"] == "active"

    def test_policy_target_matches_policy_id(self):
        entry = _entry()
        entry.update({"target_type": "policy", "target_id": "deny-shell"})
        evaluations = evaluate_exceptions(
            [entry], [_finding()], [], policy_ids=["deny-shell"])
        assert evaluations[0]["state"] == "active"

    def test_policy_target_stale_without_match(self):
        entry = _entry()
        entry.update({"target_type": "policy", "target_id": "deny-shell"})
        evaluations = evaluate_exceptions([entry], [_finding()], [], policy_ids=[])
        assert evaluations[0]["state"] == "stale"

    def test_authority_change_target_matches_tool(self):
        entry = _entry()
        entry.update({"target_type": "authority_change", "target_id": "tool:x"})
        evaluations = evaluate_exceptions(
            [entry], [], [], changed_tool_keys=["tool:x"])
        assert evaluations[0]["state"] == "active"

    def test_invalid_target_type_state(self):
        entry = _entry()
        entry.update({"target_type": "vibe", "target_id": "X"})
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] == "invalid"
        assert evaluations[0]["warnings"]

    def test_review_trigger_is_metadata_only(self):
        entry = _entry()
        entry["review_trigger"] = ["New external tool"]
        entry["scope"] = {"repository": None, "commit_range": "v1..v2"}
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] == "active"

    def test_scope_mismatch_state(self):
        entry = _entry()
        entry["scope"] = {"repository": "acme/other", "commit_range": None}
        evaluations = evaluate_exceptions(
            [entry], [_finding()], [], project_identities={"acme/agent"})
        assert evaluations[0]["state"] == "scope-mismatch"
        assert evaluations[0]["warnings"]

    def test_scope_match_stays_active(self):
        entry = _entry()
        entry["scope"] = {"repository": "acme/agent", "commit_range": None}
        evaluations = evaluate_exceptions(
            [entry], [_finding()], [], project_identities={"acme/agent"})
        assert evaluations[0]["state"] == "active"

    def test_unverified_scope_recorded_not_enforced(self):
        entry = _entry()
        entry["scope"] = {"repository": "acme/agent", "commit_range": None}
        evaluations = evaluate_exceptions([entry], [_finding()], [])
        assert evaluations[0]["state"] == "active"
        assert evaluations[0]["warnings"]


class TestExceptionsCli:
    def _exceptions_file(self, root, body):
        safeai_dir = os.path.join(root, ".safeai")
        os.makedirs(safeai_dir, exist_ok=True)
        return _write(os.path.join(safeai_dir, "exceptions.yml"), body)

    def test_warn_by_default(self, kya_project, tmp_path, capsys):
        self._exceptions_file(kya_project["root"], """
exceptions:
  - exception_id: E-STALE
    finding_or_policy: RULE_THAT_NEVER_FIRES
    risk_owner: o@example.com
    rationale: "Nothing matches."
""")
        rc = main(["scan", kya_project["root"],
                   "--sarif", os.path.join(str(tmp_path), "r.sarif"), "--no-registry"])
        assert rc in (0, 1)  # warn-only: never fails the scan by itself
        assert "matches no current" in capsys.readouterr().err

    def test_strict_exceptions_fails(self, kya_project, tmp_path):
        self._exceptions_file(kya_project["root"], """
exceptions:
  - exception_id: E-STALE
    finding_or_policy: RULE_THAT_NEVER_FIRES
    risk_owner: o@example.com
    rationale: "Nothing matches."
""")
        rc = main(["scan", kya_project["root"],
                   "--sarif", os.path.join(str(tmp_path), "r.sarif"), "--no-registry",
                   "--strict-exceptions"])
        assert rc == 1

    def test_active_exception_no_warning(self, kya_project, tmp_path, capsys):
        self._exceptions_file(kya_project["root"], """
exceptions:
  - exception_id: E-OK
    finding_or_policy: CAP_subprocess_shell
    risk_owner: o@example.com
    rationale: "Reviewed; constrained usage."
    expires_at: "2099-01-31"
""")
        main(["scan", kya_project["root"],
              "--sarif", os.path.join(str(tmp_path), "r.sarif"), "--no-registry"])
        assert "E-OK" not in capsys.readouterr().err

    def test_invalid_file_is_hard_error(self, kya_project, tmp_path):
        self._exceptions_file(kya_project["root"], """
exceptions:
  - exception_id: E-BAD
    finding_or_policy: CAP_shell
    rationale: "No owner."
""")
        with __import__("pytest").raises(SystemExit):
            main(["scan", kya_project["root"],
                  "--sarif", os.path.join(str(tmp_path), "r.sarif"), "--no-registry"])
