"""Tests for Manifest Contract v1 (schemas/safeai-manifest/v1.0.0.json).

Proves: generated manifests validate; minimal + full manifests validate;
invalid manifests fail with field-level diagnostics; old manifests still
validate; unknown fields are ignored; serialization is byte-identical.
"""

import copy
import json
import os

from safeai.cmd.cli import main
from safeai.cmd.manifest_cli import run_manifest_command
from safeai.kya import MANIFEST_SCHEMA_VERSION
from safeai.kya.contract import (
    CONTRACT_NAME,
    CONTRACT_VERSION,
    validate_manifest,
)
from safeai.kya.manifest import serialize_manifest


class _Args:
    def __init__(self, manifest_command, file):
        self.manifest_command = manifest_command
        self.file = file


def _scan_manifest(project_root, tmp_path):
    manifest_path = os.path.join(str(tmp_path), "safeai-manifest.json")
    rc = main(["scan", project_root, "--manifest", manifest_path,
               "--sarif", os.path.join(str(tmp_path), "r.sarif"),
               "--no-registry"])
    assert rc in (0, 1)
    with open(manifest_path, encoding="utf-8") as fh:
        return json.load(fh), manifest_path


def test_generated_manifest_validates(kya_project, tmp_path):
    manifest, _ = _scan_manifest(kya_project["root"], tmp_path)
    errors, _ = validate_manifest(manifest)
    assert errors == []
    assert manifest["contract"]["name"] == CONTRACT_NAME
    assert manifest["contract"]["version"] == CONTRACT_VERSION


def test_minimal_manifest_validates(tmp_path):
    minimal = {
        "schema_version": "1.2",
        "manifest_type": "safeai.kya",
        "safeai": {"version": "2.2.0"},
        "project": {"project_id": "local-demo"},
        "agents": [],
        "findings": [],
        "summary": {"policy_decision": {"outcome": "pass"}},
        "assurance_boundary": {},
        "limitations": ["static analysis only"],
    }
    errors, _ = validate_manifest(minimal)
    assert errors == []


def test_representative_manifest_validates(kya_project, tmp_path):
    manifest, _ = _scan_manifest(kya_project["root"], tmp_path)
    assert manifest["agents"], "fixture should yield agents"
    assert manifest["findings"], "fixture should yield findings"
    errors, _ = validate_manifest(manifest)
    assert errors == []


def test_invalid_manifest_actionable_diagnostics():
    bad = {
        "schema_version": "9.9",
        "manifest_type": "something.else",
        "safeai": {},
        "project": {"project_id": ""},
        "agents": [{"name": "no-id"}],
        "findings": [{"rule_id": "", "severity": "extreme"}],
        "summary": {"policy_decision": {"outcome": "maybe"}},
        "limitations": [],
    }
    errors, _ = validate_manifest(bad)
    text = "\n".join(errors)
    assert "$.schema_version" in text
    assert "$.manifest_type" in text
    assert "$.safeai.version" in text
    assert "$.project.project_id" in text
    assert "$.agents[0].agent_id" in text
    assert "$.findings[0].severity" in text
    assert "$.summary.policy_decision.outcome" in text
    assert "$.assurance_boundary" in text
    assert "$.limitations" in text


def test_old_manifest_without_contract_still_validates(kya_project, tmp_path):
    manifest, _ = _scan_manifest(kya_project["root"], tmp_path)
    old = copy.deepcopy(manifest)
    old.pop("contract", None)
    old.pop("integrity", None)
    old["schema_version"] = "1.0"
    errors, warnings = validate_manifest(old)
    assert errors == []
    assert any("1.0" in w for w in warnings)


def test_unknown_fields_ignored(kya_project, tmp_path):
    manifest, _ = _scan_manifest(kya_project["root"], tmp_path)
    manifest["future_section"] = {"anything": [1, 2, 3]}
    manifest["findings"][0]["future_key"] = "x"
    errors, _ = validate_manifest(manifest)
    assert errors == []


def test_serialization_byte_identical(kya_project, tmp_path):
    m1, _ = _scan_manifest(kya_project["root"], tmp_path)
    m2, _ = _scan_manifest(kya_project["root"], tmp_path)
    for volatile in ("generated_at",):
        m1.pop(volatile, None)
        m2.pop(volatile, None)
    for key in ("scan_id", "started_at", "completed_at"):
        m1["scan"].pop(key, None)
        m2["scan"].pop(key, None)
    assert serialize_manifest(m1) == serialize_manifest(m2)


def test_schema_file_exists_and_matches_contract():
    path = os.path.join("schemas", "safeai-manifest", "v1.0.0.json")
    with open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    assert schema["properties"]["contract"]["properties"]["name"]["const"] == CONTRACT_NAME
    assert schema["properties"]["schema_version"]["enum"] == ["1.0", "1.1", "1.2"]
    required = {"schema_version", "manifest_type", "safeai", "project",
                "agents", "findings", "summary", "assurance_boundary",
                "limitations"}
    assert required.issubset(set(schema["required"]))


def test_cli_validate_command(kya_project, tmp_path, capsys):
    _, path = _scan_manifest(kya_project["root"], tmp_path)
    rc = run_manifest_command(_Args("validate", path))
    assert rc == 0
    assert "valid:" in capsys.readouterr().out


def test_cli_validate_rejects_bad_file(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": "1.2"}), encoding="utf-8")
    rc = run_manifest_command(_Args("validate", str(bad)))
    assert rc == 1
    out = capsys.readouterr().out
    assert "invalid:" in out
    assert "$.project" in out


def test_legacy_schema_version_constant_unchanged():
    assert MANIFEST_SCHEMA_VERSION == "1.2"
