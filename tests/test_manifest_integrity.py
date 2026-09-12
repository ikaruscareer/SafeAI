"""Tests for offline manifest integrity (Contract v1, Workstream 2)."""

import copy
import json
import os

from safeai.cmd.cli import main
from safeai.cmd.manifest_cli import run_manifest_command
from safeai.kya.integrity import (
    MISMATCH,
    NO_INTEGRITY,
    OK,
    UNSUPPORTED_VERSION,
    payload_digest,
    verify_document,
    verify_manifest_file,
)


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


def test_generated_manifest_verifies(kya_project, tmp_path):
    manifest, _ = _scan_manifest(kya_project["root"], tmp_path)
    assert manifest["integrity"]["algorithm"] == "sha256"
    assert manifest["integrity"]["canonicalization"] == "safeai-manifest-v1"
    assert manifest["integrity"]["verified"] is False
    status, _ = verify_document(manifest)
    assert status == OK


def test_repeated_scan_identical_digest(kya_project, tmp_path):
    m1, _ = _scan_manifest(kya_project["root"], tmp_path)
    m2, _ = _scan_manifest(kya_project["root"], tmp_path)
    assert payload_digest(m1) == payload_digest(m2)
    assert m1["integrity"]["payload_sha256"] == m2["integrity"]["payload_sha256"]


def test_semantic_change_fails_verification(kya_project, tmp_path):
    manifest, _ = _scan_manifest(kya_project["root"], tmp_path)
    assert manifest["findings"], "fixture should yield findings"
    tampered = copy.deepcopy(manifest)
    tampered["findings"][0]["message"] = (
        tampered["findings"][0].get("message", "") + " [tampered]")
    status, detail = verify_document(tampered)
    assert status == MISMATCH
    assert "changed" in detail


def test_reformatting_does_not_fail(kya_project, tmp_path, tmp_path_factory):
    _, path = _scan_manifest(kya_project["root"], tmp_path)
    with open(path, encoding="utf-8") as fh:
        document = json.load(fh)
    # Reformat: different whitespace, reversed key order, trailing newline.
    other = tmp_path_factory.mktemp("reformat") / "m.json"
    other.write_text(json.dumps(document, indent=4)[::-1][::-1] + "\n", encoding="utf-8")
    assert verify_manifest_file(str(other)) == 0


def test_mismatch_output_leaks_no_values(kya_project, tmp_path, capsys):
    manifest, path = _scan_manifest(kya_project["root"], tmp_path)
    tampered = copy.deepcopy(manifest)
    secret_msg = "leak-test-value-sk-abcdef123456"
    tampered["findings"][0]["message"] = secret_msg
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(tampered, fh)
    assert verify_manifest_file(path) == 1
    out = capsys.readouterr().out
    assert secret_msg not in out
    assert "mismatch" in out


def test_old_manifest_no_integrity(kya_project, tmp_path):
    manifest, _ = _scan_manifest(kya_project["root"], tmp_path)
    old = copy.deepcopy(manifest)
    del old["integrity"]
    status, detail = verify_document(old)
    assert status == NO_INTEGRITY
    assert "importable" in detail


def test_old_manifest_importable_by_default(kya_project, tmp_path):
    from safeai.kya.exporter import export_inventory  # noqa - shape reference
    manifest, _ = _scan_manifest(kya_project["root"], tmp_path)
    old = copy.deepcopy(manifest)
    del old["integrity"]
    # Contract validation (the import-compatibility gate) still passes.
    from safeai.kya.contract import validate_manifest
    errors, _ = validate_manifest(old)
    assert errors == []


def test_require_integrity_rejects(tmp_path):
    from safeai.kya.importer import load_inventory
    from safeai.kya.registry import RegistryError
    doc = {
        "schema_version": "1.1",
        "export_type": "safeai.kya.inventory",
        "generated_at": "t",
        "projects": [],
        "limitations": ["x"],
    }
    path = os.path.join(str(tmp_path), "inv.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    # Default: accepted (backward compatible).
    assert load_inventory(path)["schema_version"] == "1.1"
    # Strict: rejected.
    try:
        load_inventory(path, require_integrity=True)
    except RegistryError as exc:
        assert "Integrity check failed" in str(exc)
    else:
        raise AssertionError("expected RegistryError")


def test_unsupported_version_fails_safely():
    status, detail = verify_document({"schema_version": "3.0", "integrity": {}})
    assert status == UNSUPPORTED_VERSION
    assert "3.0" in detail


def test_cli_verify_command(kya_project, tmp_path, capsys):
    _, path = _scan_manifest(kya_project["root"], tmp_path)
    assert run_manifest_command(_Args("verify", path)) == 0
    assert "verified:" in capsys.readouterr().out
