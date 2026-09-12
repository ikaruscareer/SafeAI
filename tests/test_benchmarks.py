"""Benchmark system tests (WS4): catalog validity, determinism, honesty."""

import copy
import importlib.util
import json
import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNNER = os.path.join(REPO_ROOT, "scripts", "run_benchmarks.py")
CATALOG = os.path.join(REPO_ROOT, "benchmarks", "catalog.yml")


def _load_runner():
    spec = importlib.util.spec_from_file_location("run_benchmarks", RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_catalog_validates_and_has_corpus():
    runner = _load_runner()
    entries = runner.load_catalog()
    assert len(entries) == 20
    assert len({e["id"] for e in entries}) == 20


def test_every_fixture_exists_and_is_referenced():
    runner = _load_runner()
    for entry in runner.load_catalog():
        if entry.get("path"):
            assert os.path.isdir(os.path.join(REPO_ROOT, entry["path"])), entry["id"]
        for key in ("files", "before_files", "after_files"):
            for rel, content in (entry.get(key) or {}).items():
                assert rel and content is not None, (entry["id"], key)


def test_smoke_subset_deterministic():
    runner = _load_runner()
    entries = [e for e in runner.load_catalog() if e.get("smoke")]
    assert entries, "smoke subset must not be empty"
    first = [runner.run_entry(copy.deepcopy(e)) for e in entries]
    second = [runner.run_entry(copy.deepcopy(e)) for e in entries]
    for one, two in zip(first, second):
        assert one["status"] == two["status"] == "pass", (one["id"], one["mismatches"])
        assert one["observed"] == two["observed"], one["id"]


def test_runner_detects_intentional_mismatch():
    runner = _load_runner()
    entry = {
        "id": "mismatch-probe",
        "intent": "positive",
        "kind": "scan",
        "path": "tests/fixtures/action/clean",
        "expected_rules": {"CAP_shell": "critical"},
    }
    result = runner.run_entry(entry)
    assert result["status"] == "fail"
    assert any("CAP_shell" in m for m in result["mismatches"])


def test_runner_never_uses_network_or_execution():
    with open(RUNNER, encoding="utf-8") as fh:
        source = fh.read()
    for banned in ("import socket", "urllib", "requests", "subprocess",
                   "os.system", "os.popen", "eval(", "exec("):
        assert banned not in source, banned


def test_catalog_contains_no_secrets():
    with open(CATALOG, encoding="utf-8") as fh:
        text = fh.read()
    assert "AKIA" not in text
    assert re.search(r"sk-[A-Za-z0-9]{8,}", text) is None


def test_result_payload_structured(tmp_path):
    runner = _load_runner()
    out = os.path.join(str(tmp_path), "results.json")
    rc = runner.main(["--subset", "smoke", "--results", out])
    assert rc == 0
    with open(out, encoding="utf-8") as fh:
        payload = json.load(fh)
    assert payload["benchmark_version"] == "1.0"
    assert payload["fixture_count"] == payload["passes"] + len(
        [r for r in payload["results"] if r["status"] == "limitation"])
    assert payload["failures"] == 0
    for result in payload["results"]:
        assert set(result) >= {"id", "intent", "status", "mismatches",
                               "observed", "duration_s"}
