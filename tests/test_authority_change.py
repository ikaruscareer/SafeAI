"""Tests for v2.4 authority/material-change classification + gate (WS2)."""

import json
import os

from safeai.analysis.capability_diff import (
    CHANGE_CLASSES,
    authority_gate_tripped,
    change_class_for,
)
from safeai.cmd.cli import main


class TestChangeClass:
    def test_vocabulary_is_stable(self):
        assert CHANGE_CLASSES == (
            "NO_CHANGE",
            "LOW_CHANGE",
            "MATERIAL_CHANGE",
            "HIGH_RISK_CHANGE",
            "UNKNOWN",
        )

    def test_unchanged(self):
        assert change_class_for("unchanged", [], [], []) == "NO_CHANGE"

    def test_reduced_is_low(self):
        assert change_class_for("reduced", [], [], []) == "LOW_CHANGE"
        assert change_class_for("removed", [], [], []) == "LOW_CHANGE"

    def test_new_tool_is_material(self):
        added = [{"name": "http", "inferred": False}]
        assert change_class_for("new", [], [], added) == "MATERIAL_CHANGE"

    def test_critical_escalation_is_high_risk(self):
        escs = [{"id": "ESC_X", "severity": "critical"}]
        assert change_class_for("escalated", escs, [], []) == "HIGH_RISK_CHANGE"
        assert change_class_for("new", escs, [], []) == "HIGH_RISK_CHANGE"

    def test_access_widening_is_material(self):
        changes = [{"capability": "db", "before": "read", "after": "write",
                    "inferred": False}]
        assert change_class_for("escalated", [], changes, []) == "MATERIAL_CHANGE"

    def test_high_escalation_without_structure_is_material(self):
        escs = [{"id": "ESC_Y", "severity": "high"}]
        assert change_class_for("escalated", escs, [], []) == "MATERIAL_CHANGE"

    def test_unknown_status(self):
        assert change_class_for("unknown", [], [], []) == "UNKNOWN"
        assert change_class_for(None, [], [], []) == "UNKNOWN"

    def test_escalated_without_signals_is_low(self):
        assert change_class_for("escalated", [], [], []) == "LOW_CHANGE"


class TestAuthorityGateTripped:
    def _tool(self, cls, inferred_only=False):
        return {"tool_key": "t", "change_class": cls, "inferred_only": inferred_only}

    def test_material_trips_material(self):
        assert authority_gate_tripped([self._tool("MATERIAL_CHANGE")], "material") is True

    def test_material_does_not_trip_high_risk(self):
        assert authority_gate_tripped([self._tool("MATERIAL_CHANGE")], "high-risk") is False

    def test_high_risk_trips_both(self):
        tools = [self._tool("HIGH_RISK_CHANGE")]
        assert authority_gate_tripped(tools, "material") is True
        assert authority_gate_tripped(tools, "high-risk") is True

    def test_inferred_only_never_trips(self):
        tools = [self._tool("HIGH_RISK_CHANGE", inferred_only=True)]
        assert authority_gate_tripped(tools, "material") is False
        assert authority_gate_tripped(tools, "high-risk") is False

    def test_unknown_never_trips(self):
        assert authority_gate_tripped([self._tool("UNKNOWN")], "material") is False

    def test_low_and_no_change_never_trip(self):
        tools = [self._tool("LOW_CHANGE"), self._tool("NO_CHANGE")]
        assert authority_gate_tripped(tools, "material") is False

    def test_empty_tools(self):
        assert authority_gate_tripped([], "material") is False


class TestChangeClassCounts:
    def test_counts_and_highest(self):
        from safeai.analysis.capability_diff import compute_capability_diff

        def tool(key, caps):
            return {
                "tool_key": key,
                "tool": {"kind": "tool", "name": key, "framework": None},
                "capabilities": [
                    {"name": c, "access_mode": "read", "evidence": [],
                     "confidence": 1.0, "inferred": False}
                    for c in caps
                ],
                "access_summary": "read",
            }

        current = {"tool_surface": [
            tool("tool:a", ["shell", "http"]),
            tool("tool:b", ["fs"]),
        ]}
        baseline = {"tool_surface": [tool("tool:a", ["shell"]), tool("tool:b", ["fs"])]}
        diff = compute_capability_diff(current, baseline)
        assert diff["counts"]["by_change_class"]["MATERIAL_CHANGE"] >= 1
        assert diff["highest_change_class"] in ("MATERIAL_CHANGE", "HIGH_RISK_CHANGE")


class TestFailOnAuthorityChange:
    @staticmethod
    def _write(root, servers):
        payload = {"mcpServers": {
            name: {"command": "node", "args": ["server.js"],
                   "tools": [{"name": f"{name}_tool", "description": f"{name} read tool"}]}
            for name in servers
        }}
        root.mkdir(parents=True, exist_ok=True)
        (root / ".mcp.json").write_text(json.dumps(payload), encoding="utf-8")
        (root / "agent.py").write_text(
            "from langgraph.graph import StateGraph\n\n"
            "def build():\n    return StateGraph(dict)\n",
            encoding="utf-8",
        )
        return str(root)

    def test_new_server_is_material_change(self, tmp_path):
        from safeai.engine.scan import run_scan

        before = self._write(tmp_path / "before", ["lookup"])
        after = self._write(tmp_path / "after", ["lookup", "writer"])
        baseline = run_scan(before)
        current = run_scan(after, baseline_report=baseline)
        diff = current["capability_diff"]
        added = next(t for t in diff["tools"] if t["tool_key"] == "mcp_server:writer")
        assert added["status"] == "new"
        assert added["change_class"] in ("MATERIAL_CHANGE", "HIGH_RISK_CHANGE")
        assert diff["highest_change_class"] in ("MATERIAL_CHANGE", "HIGH_RISK_CHANGE")

    def test_new_server_fails_gate(self, tmp_path):
        before = self._write(tmp_path / "before", ["lookup"])
        after = self._write(tmp_path / "after", ["lookup", "writer"])
        baseline_json = str(tmp_path / "baseline.json")
        main(["scan", before, "--json", baseline_json, "--no-registry",
              "--sarif", str(tmp_path / "b.sarif")])
        plain = main(["scan", after, "--baseline", baseline_json, "--no-registry",
                      "--sarif", str(tmp_path / "p.sarif"),
                      "--fail-on", "critical"])
        gated = main(["scan", after, "--baseline", baseline_json, "--no-registry",
                      "--sarif", str(tmp_path / "g.sarif"),
                      "--fail-on", "critical",
                      "--fail-on-authority-change", "material"])
        assert gated == 1
        assert plain == 0

    def test_identical_scan_passes(self, tmp_path):
        before = self._write(tmp_path / "before", ["lookup"])
        baseline_json = str(tmp_path / "baseline.json")
        main(["scan", before, "--json", baseline_json, "--no-registry",
              "--sarif", str(tmp_path / "b.sarif")])
        rc = main(["scan", before, "--baseline", baseline_json, "--no-registry",
                   "--sarif", str(tmp_path / "m.sarif"),
                   "--fail-on", "critical",
                   "--fail-on-authority-change", "material"])
        assert rc == 0

    def test_requires_baseline(self, kya_project, tmp_path, capsys):
        with __import__("pytest").raises(SystemExit):
            main(["scan", kya_project["root"],
                  "--sarif", os.path.join(str(tmp_path), "r.sarif"),
                  "--no-registry", "--fail-on-authority-change", "material"])
        assert "--fail-on-authority-change requires --baseline" in capsys.readouterr().err


class TestActionWiring:
    @staticmethod
    def _driver():
        import importlib.util
        import os as _os

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = _os.path.join(repo_root, "scripts", "safeai-action.py")
        spec = importlib.util.spec_from_file_location("safeai_action", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_argv_includes_flag(self):
        import sys

        build_scan_argv = self._driver().build_scan_argv
        argv = build_scan_argv(".", "critical", "r.sarif",
                               fail_on_authority_change="material")
        assert "--fail-on-authority-change" in argv
        assert "material" in argv
        assert argv[0] == sys.executable

    def test_argv_omits_flag_by_default(self):
        build_scan_argv = self._driver().build_scan_argv
        argv = build_scan_argv(".", "critical", "r.sarif")
        assert "--fail-on-authority-change" not in argv
