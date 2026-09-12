"""Release asset invariants (supply-chain: no misattributed evidence)."""

import hashlib
import importlib.util
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "verify_release_assets.py")


def _load():
    spec = importlib.util.spec_from_file_location("verify_release_assets", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write(path, content=b"x"):
    with open(path, "wb") as fh:
        fh.write(content if isinstance(content, bytes) else content.encode())


def _clean_tree(tmp_path, version="2.2.1"):
    wheel = f"safeai_static_analyzer-{version}-py3-none-any.whl"
    sdist = f"safeai_static_analyzer-{version}.tar.gz"
    sbom = f"safeai-{version}-sbom.spdx.json"
    slsa = f"safeai-{version}-slsa-provenance.json"
    for name, content in (
        (wheel, b"wheel-bytes"),
        (sdist, b"sdist-bytes"),
        (sbom, json.dumps({"spdxVersion": "SPDX-2.3"})),
        (slsa, json.dumps({"_type": "in-toto"})),
    ):
        _write(os.path.join(str(tmp_path), name), content)
    for name in (wheel, sdist):
        _write(os.path.join(str(tmp_path), name + ".sig"), b"sig")
        _write(os.path.join(str(tmp_path), name + ".pem"), b"pem")
    lines = []
    for name in (wheel, sdist, sbom, slsa):
        with open(os.path.join(str(tmp_path), name), "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        lines.append(f"{digest}  {name}")
    _write(os.path.join(str(tmp_path), "SHA256SUMS"), "\n".join(lines) + "\n")
    return str(tmp_path)


def test_clean_release_passes(tmp_path):
    mod = _load()
    assert mod.verify(_clean_tree(tmp_path), "2.2.1") == []


def test_historical_artifact_fails(tmp_path):
    mod = _load()
    root = _clean_tree(tmp_path)
    _write(os.path.join(root, "safeai-2.0.1-sbom.spdx.json"), b"{}")
    problems = mod.verify(root, "2.2.1")
    assert any("2.0.1" in p and "foreign version" in p for p in problems)


def test_generic_provenance_fails(tmp_path):
    mod = _load()
    root = _clean_tree(tmp_path)
    _write(os.path.join(root, "provenance.json"), b"{}")
    problems = mod.verify(root, "2.2.1")
    assert any("generically named" in p for p in problems)


def test_missing_sidecar_fails(tmp_path):
    mod = _load()
    root = _clean_tree(tmp_path)
    os.remove(os.path.join(root, "safeai_static_analyzer-2.2.1.tar.gz.sig"))
    problems = mod.verify(root, "2.2.1")
    assert any("sidecar" in p for p in problems)


def test_checksum_mismatch_fails(tmp_path):
    mod = _load()
    root = _clean_tree(tmp_path)
    _write(os.path.join(root, "safeai_static_analyzer-2.2.1.tar.gz"), b"tampered")
    problems = mod.verify(root, "2.2.1")
    assert any("digest mismatch" in p for p in problems)


def test_unlisted_file_fails(tmp_path):
    mod = _load()
    root = _clean_tree(tmp_path)
    wheel = "safeai_static_analyzer-2.2.1-py3-none-any.whl"
    sums = os.path.join(root, "SHA256SUMS")
    with open(sums, encoding="utf-8") as fh:
        kept = [ln for ln in fh if wheel not in ln]
    with open(sums, "w", encoding="utf-8") as fh:
        fh.writelines(kept)
    problems = mod.verify(root, "2.2.1")
    assert any("absent from SHA256SUMS" in p for p in problems)


def test_bad_version_usage():
    mod = _load()
    assert mod.main([".", "not-a-version"]) == 2
