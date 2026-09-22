"""Baseline compatibility: v1.3 / v2.3 / v2.4 baselines against current scans (WS9).

A legacy baseline must never be represented as 'everything is new': it
must communicate 'authority attribution unavailable' via UNKNOWN change
classes, and current fields must survive the round trip.
"""

from safeai.analysis.capability_diff import compute_capability_diff
from safeai.engine.scan import run_scan


def _tool(key, caps):
    return {
        "tool_key": key,
        "tool": {"kind": "tool", "name": key, "framework": None},
        "capabilities": [
            {"name": c, "access_mode": "read", "evidence": [],
             "confidence": 1.0, "inferred": False} for c in caps
        ],
        "access_summary": "read",
    }


def _current():
    return {"tool_surface": [_tool("tool:a", ["shell"])], "findings": []}


class TestLegacyBaselines:
    def test_v13_baseline_days_unknown_not_new(self):
        baseline = {"findings": []}  # v1.3: no tool_surface at all
        diff = compute_capability_diff(_current(), baseline)
        assert diff["baseline_tool_attribution"] is False
        for entry in diff["tools"]:
            assert entry["status"] == "unknown"
            assert entry["change_class"] == "UNKNOWN"
        assert diff["highest_change_class"] == "NO_CHANGE"

    def test_v23_baseline_without_change_fields(self):
        baseline = {"tool_surface": [_tool("tool:a", ["shell"])]}
        diff = compute_capability_diff(_current(), baseline)
        assert diff["tools"][0]["status"] == "unchanged"
        assert diff["tools"][0]["change_class"] == "NO_CHANGE"
        assert "change_types" in diff["tools"][0]
        assert "authority" in diff["tools"][0]

    def test_v24_baseline_round_trip(self):
        baseline = {"tool_surface": [_tool("tool:a", ["shell"])]}
        current = {"tool_surface": [_tool("tool:a", ["shell", "http"])]}
        diff = compute_capability_diff(current, baseline)
        assert diff["highest_change_class"] in ("MATERIAL_CHANGE", "HIGH_RISK_CHANGE")


class TestBaselineFileScan:
    def test_scan_against_minimal_legacy_file(self, tmp_path):
        import json

        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "agent.py").write_text(
            "import subprocess\nsubprocess.run(['ls'])\n", encoding="utf-8")
        legacy = tmp_path / "legacy.json"
        legacy.write_text(json.dumps({"findings": []}), encoding="utf-8")
        report = run_scan(str(proj), baseline_report=json.loads(legacy.read_text()))
        diff = report.get("capability_diff") or {}
        for entry in diff.get("tools", []):
            assert entry["change_class"] == "UNKNOWN"
