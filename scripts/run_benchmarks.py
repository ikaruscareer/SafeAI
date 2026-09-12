"""Deterministic offline benchmark runner for SafeAI (v2.2, WS4).

Runs the pinned corpus in ``benchmarks/catalog.yml`` through the real
scanner and checks expected outcomes. Fully offline: no network, no
fixture-code execution (static analysis only — findings, never imports).

Usage:
    python scripts/run_benchmarks.py [--subset smoke|full] [--results PATH]

Exit codes: 0 all pass · 1 expected outcome regressed · 2 usage/catalog error.
Timing is recorded as environmental measurement, never asserted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import safeai
from safeai.engine.scan import run_scan
from safeai.severity import rank as severity_rank

CATALOG = os.path.join(REPO_ROOT, "benchmarks", "catalog.yml")
RESULTS_DIR = os.path.join(REPO_ROOT, "benchmarks", "results")
BENCHMARK_VERSION = "1.0"

INTENTS = ("positive", "negative", "regression", "limitation", "escalation")
KINDS = ("scan", "escalation")
FAIL_SEVERITIES = ("critical", "high", "medium")


def fail(message):
    print(f"benchmark error: {message}", file=sys.stderr)
    raise SystemExit(2)


def load_catalog(path=CATALOG):
    try:
        with open(path, encoding="utf-8") as fh:
            entries = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        fail(f"unable to read catalog {path}: {exc}")
    if not isinstance(entries, list) or not entries:
        fail("catalog must be a non-empty list")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("id"):
            fail("every catalog entry needs an id")
        if entry["id"] in seen:
            fail(f"duplicate fixture id {entry['id']!r}")
        seen.add(entry["id"])
        if entry.get("intent") not in INTENTS:
            fail(f"{entry['id']}: intent must be one of {', '.join(INTENTS)}")
        if entry.get("kind", "scan") not in KINDS:
            fail(f"{entry['id']}: kind must be one of {', '.join(KINDS)}")
        kind = entry.get("kind", "scan")
        if kind == "scan" and not entry.get("path") and not entry.get("files"):
            fail(f"{entry['id']}: scan entries need path or files")
        if kind == "escalation" and not (
                entry.get("before_files") and entry.get("after_files")):
            fail(f"{entry['id']}: escalation entries need before_files and after_files")
        if entry.get("path"):
            full = os.path.join(REPO_ROOT, entry["path"])
            if not os.path.isdir(full):
                fail(f"{entry['id']}: path not found: {entry['path']}")
    return entries


def materialize(files):
    """Write inline fixture files to a temp dir; return the dir."""
    root = tempfile.mkdtemp(prefix="safeai-bench-")
    for rel, content in (files or {}).items():
        dest = os.path.join(root, rel)
        os.makedirs(os.path.dirname(dest) or root, exist_ok=True)
        if isinstance(content, str):
            text = content
        else:
            text = json.dumps(content, indent=2) + "\n"
        with open(dest, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return root


def finding_index(report):
    """Map rule_id -> highest severity observed."""
    index = {}
    for finding in report.get("findings") or []:
        rule_id = finding.get("rule_id")
        severity = str(finding.get("severity") or "").lower()
        if not rule_id:
            continue
        if rule_id not in index or severity_rank(severity) > severity_rank(index[rule_id]):
            index[rule_id] = severity
    return index


def check_scan(entry, report):
    """Return a list of mismatch strings (empty = pass)."""
    mismatches = []
    intent = entry["intent"]
    index = finding_index(report)

    if intent == "negative":
        bad = sorted(f"{rule}:{sev}" for rule, sev in index.items()
                     if sev in FAIL_SEVERITIES)
        if bad:
            mismatches.append(f"negative fixture fired: {', '.join(bad)}")
        return mismatches

    if intent == "limitation":
        return mismatches  # recorded, never fails

    for rule_id, severity in sorted((entry.get("expected_rules") or {}).items()):
        actual = index.get(rule_id)
        if actual != str(severity).lower():
            mismatches.append(
                f"rule {rule_id}: expected {severity}, got {actual or 'absent'}")

    actual_fw = set(report.get("detected_frameworks") or [])
    for framework in entry.get("expected_frameworks") or []:
        if framework not in actual_fw:
            mismatches.append(f"framework {framework!r} not detected "
                              f"(got {sorted(actual_fw)})")

    actual_caps = {str(c.get("name")) for c in
                   (report.get("normalized_capabilities") or []) if c.get("name")}
    for capability in entry.get("expected_capabilities") or []:
        if capability not in actual_caps:
            mismatches.append(f"capability {capability!r} not detected")
    return mismatches


def run_scan_entry(entry):
    if entry.get("files"):
        target = materialize(entry["files"])
    else:
        target = os.path.join(REPO_ROOT, entry["path"])
    return run_scan(target)


def run_escalation_entry(entry):
    before = materialize(entry["before_files"])
    after = materialize(entry["after_files"])
    baseline = run_scan(before)
    current = run_scan(after, baseline_report=baseline)
    diff = current.get("capability_diff") or {}
    actual = set()
    for tool in diff.get("tools") or []:
        for escalation in tool.get("escalations") or []:
            if escalation.get("id"):
                actual.add(escalation["id"])
    mismatches = []
    for expected in entry.get("expected_escalations") or []:
        if expected not in actual:
            mismatches.append(f"escalation {expected} absent (got {sorted(actual)})")
    return mismatches, sorted(actual)


def run_entry(entry):
    started = time.perf_counter()
    try:
        if entry.get("kind", "scan") == "escalation":
            mismatches, actual = run_escalation_entry(entry)
            observed = {"escalations": actual}
        else:
            report = run_scan_entry(entry)
            mismatches = check_scan(entry, report)
            observed = {
                "frameworks": sorted(report.get("detected_frameworks") or []),
                "rules": sorted(f"{r}:{s}" for r, s in finding_index(report).items()),
            }
    except Exception as exc:
        mismatches = [f"runner exception: {type(exc).__name__}: {exc}"]
        observed = {}
    duration_s = round(time.perf_counter() - started, 3)
    status = "pass" if not mismatches else "fail"
    if entry["intent"] == "limitation":
        status = "limitation"
    return {
        "id": entry["id"],
        "intent": entry["intent"],
        "status": status,
        "mismatches": mismatches,
        "observed": observed,
        "duration_s": duration_s,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="SafeAI offline benchmark runner")
    parser.add_argument("--subset", choices=("smoke", "full"), default="full")
    parser.add_argument("--results", default=None,
                        help="Write machine-readable JSON here "
                             "(default: benchmarks/results/<version>.json)")
    args = parser.parse_args(argv)

    entries = load_catalog()
    if args.subset == "smoke":
        entries = [e for e in entries if e.get("smoke")]
        if not entries:
            fail("smoke subset is empty")

    results = [run_entry(entry) for entry in sorted(entries, key=lambda e: e["id"])]
    failures = [r for r in results if r["status"] == "fail"]
    passes = [r for r in results if r["status"] == "pass"]

    for result in results:
        mark = {"pass": "PASS", "fail": "FAIL", "limitation": "NOTE"}[result["status"]]
        print(f"[{mark}] {result['id']} ({result['duration_s']}s)")
        for mismatch in result["mismatches"]:
            print(f"       - {mismatch}")

    payload = {
        "benchmark_version": BENCHMARK_VERSION,
        "safeai_version": getattr(safeai, "__version__", "unknown"),
        "subset": args.subset,
        "fixture_count": len(results),
        "passes": len(passes),
        "failures": len(failures),
        "results": results,
    }
    out = args.results or os.path.join(RESULTS_DIR, f"{payload['safeai_version']}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True, default=str)
        fh.write("\n")

    total_s = round(sum(r["duration_s"] for r in results), 1)
    print(f"{len(passes)}/{len(results)} pass, {len(failures)} fail "
          f"({total_s}s environmental, not asserted)")
    print(f"results: {out}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
