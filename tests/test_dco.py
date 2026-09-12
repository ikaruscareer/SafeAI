"""DCO sign-off check tests (WS5)."""

import importlib.util
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "check_dco.py")


def _load():
    spec = importlib.util.spec_from_file_location("check_dco", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_signed_commit_passes():
    mod = _load()
    message = "feat: x\n\nSigned-off-by: Ada Dev <ada@example.com>\n"
    assert mod.check_commit(message, "Ada Dev", "ada@example.com") == []


def test_missing_trailer_fails():
    mod = _load()
    assert mod.check_commit("feat: x", "Ada Dev", "ada@example.com") != []


def test_wrong_email_fails():
    mod = _load()
    message = "feat: x\n\nSigned-off-by: Mallory <mallory@example.com>\n"
    assert mod.check_commit(message, "Ada Dev", "ada@example.com") != []


def test_email_match_is_case_insensitive():
    mod = _load()
    message = "feat: x\n\nSigned-off-by: Ada Dev <ADA@EXAMPLE.COM>\n"
    assert mod.check_commit(message, "Ada Dev", "ada@example.com") == []


def test_dco_doc_exists():
    assert os.path.exists(os.path.join(REPO_ROOT, "DCO.md"))


def test_governance_doc_linked():
    for rel in ("README.md", "CONTRIBUTING.md"):
        with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as fh:
            text = fh.read()
        assert "GOVERNANCE_AND_EDITIONS" in text, rel
