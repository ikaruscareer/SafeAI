"""Every finding declares how it was arrived at (#94).

The assurance boundary says what a static scan can claim overall;
``evidence_type`` says it per finding, so a consumer can separate what was
*declared* from what was *matched* from what was actually *executed*.

The point of testing it at the analyzer level rather than on a sample report is
that a NEW analyzer which forgets the field fails here. A central default would
have made that same omission silently claim `static-config`, which is the
stronger of the two static values.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from safeai.kya.assurance import EVIDENCE_TYPES

_ANALYZER_DIR = pathlib.Path(__file__).resolve().parents[1] / "safeai" / "analyzers"
_RULE_ID = re.compile(r'"rule_id":')
_EVIDENCE = re.compile(r'"evidence_type":\s*"([a-z-]+)"')


def _analyzer_files():
    return sorted(
        path for path in _ANALYZER_DIR.glob("*/analyzer.py")
        if _RULE_ID.search(path.read_text(encoding="utf-8"))
    )


def test_there_are_analyzers_to_check():
    """Guard the guard: a glob that matched nothing would pass everything."""
    assert len(_analyzer_files()) >= 13


@pytest.mark.parametrize(
    "path", _analyzer_files(), ids=lambda p: p.parent.name
)
def test_every_finding_carries_a_valid_evidence_type(path):
    text = path.read_text(encoding="utf-8")
    rule_sites = len(_RULE_ID.findall(text))
    values = _EVIDENCE.findall(text)

    assert len(values) == rule_sites, (
        f"{path.parent.name}: {rule_sites} finding site(s) but "
        f"{len(values)} evidence_type value(s) - every finding must declare one"
    )
    for value in values:
        assert value in EVIDENCE_TYPES, f"{path.parent.name}: unknown value {value!r}"


def test_runtime_observed_is_defined_but_unused():
    """It exists for a future integration. If something starts emitting it,
    that is a real capability change and this test should be the thing that
    makes someone say so out loud."""
    emitted = set()
    for path in _analyzer_files():
        emitted.update(_EVIDENCE.findall(path.read_text(encoding="utf-8")))

    assert "runtime-observed" in EVIDENCE_TYPES
    assert "runtime-observed" not in emitted, (
        "an analyzer now claims runtime-observed evidence; static analysis "
        "cannot support that claim - see the assurance boundary"
    )


def test_evidence_type_reaches_sarif_properties(tmp_path):
    """The field is only useful if it survives into the artifact consumers read."""
    import json

    from safeai.report.sarif import write_sarif

    report = {"findings": [{
        "rule_id": "TEST_RULE", "severity": "low", "message": "m",
        "file": "a.py", "line": 1, "owasp_llm": "LLM01",
        "evidence_type": "static-pattern",
    }]}
    out = tmp_path / "out.sarif"
    write_sarif(report, str(out))

    doc = json.loads(out.read_text(encoding="utf-8"))
    props = doc["runs"][0]["results"][0].get("properties", {})
    assert props.get("evidence_type") == "static-pattern"
