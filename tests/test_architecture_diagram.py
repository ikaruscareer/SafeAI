"""Tests for the architecture diagram feature (PR #158)."""

from safeai.analysis.component_graph import export_component_graph
from safeai.report.html import (
    _arch_node_id,
    _architecture_mermaid,
    _architecture_table,
    _mermaid_escape,
    write_html,
)

# ── export_component_graph ────────────────────────────────────────────

class TestExportComponentGraph:
    def test_empty_graph(self):
        result = export_component_graph({})
        assert result == {"nodes": [], "edges": []}

    def test_basic_edges(self):
        graph = {
            "edges": [
                {"from": "agent:main", "to": "tool:shell", "kind": "uses"},
                {"from": "agent:main", "to": "mcp:server", "kind": "connects"},
            ],
            "orphaned_refs": [],
        }
        result = export_component_graph(graph)
        assert len(result["nodes"]) == 3
        assert len(result["edges"]) == 2
        ids = {n["id"] for n in result["nodes"]}
        assert "agent:main" in ids
        assert "tool:shell" in ids
        assert "mcp:server" in ids

    def test_orphaned_refs(self):
        graph = {
            "edges": [{"from": "agent:a", "to": "tool:b", "kind": "uses"}],
            "orphaned_refs": ["tool:b", "tool:lost"],
        }
        result = export_component_graph(graph)
        nodes_by_id = {n["id"]: n for n in result["nodes"]}
        assert nodes_by_id["tool:b"]["is_orphan"] is True
        assert nodes_by_id["tool:lost"]["is_orphan"] is True
        assert nodes_by_id["agent:a"]["is_orphan"] is False

    def test_node_type_inferred_from_id(self):
        graph = {
            "edges": [{"from": "workflow:pipe", "to": "model:gpt", "kind": "calls"}],
            "orphaned_refs": [],
        }
        result = export_component_graph(graph)
        nodes = {n["id"]: n for n in result["nodes"]}
        assert nodes["workflow:pipe"]["type"] == "workflow"
        assert nodes["model:gpt"]["type"] == "model"

    def test_node_without_colon_is_unknown_type(self):
        graph = {
            "edges": [{"from": "orphan_node", "to": "agent:a", "kind": "ref"}],
            "orphaned_refs": [],
        }
        result = export_component_graph(graph)
        nodes = {n["id"]: n for n in result["nodes"]}
        assert nodes["orphan_node"]["type"] == "unknown"


# ── _mermaid_escape ───────────────────────────────────────────────────

class TestMermaidEscape:
    def test_plain_text(self):
        assert _mermaid_escape("hello") == "hello"

    def test_html_escape(self):
        result = _mermaid_escape("<script>alert('x')</script>")
        assert "<script>" not in result
        assert "&lt;" in result

    def test_mermaid_special_chars(self):
        result = _mermaid_escape('a"b]c}d')
        assert '"' not in result or "#quot;" in result
        assert "]" not in result or "#93;" in result
        assert "}" not in result or "#125;" in result

    def test_non_string_input(self):
        result = _mermaid_escape(42)
        assert result == "42"


# ── _arch_node_id ─────────────────────────────────────────────────────

class TestArchNodeId:
    def test_simple_id(self):
        seen = {}
        result = _arch_node_id("agent_main", seen)
        assert result == "agent_main"
        assert "agent_main" in seen

    def test_special_chars_replaced(self):
        seen = {}
        result = _arch_node_id("tool:foo-bar", seen)
        assert ":" not in result
        assert "-" not in result
        assert result == "tool_foo_bar"

    def test_leading_digit_prefixed(self):
        seen = {}
        result = _arch_node_id("123tool", seen)
        assert result.startswith("n_")

    def test_collision_disambiguation(self):
        seen = {}
        id1 = _arch_node_id("tool:foo:bar", seen)
        id2 = _arch_node_id("tool_foo:bar", seen)
        # Both clean to "tool_foo_bar" but should be disambiguated
        assert id1 != id2
        assert len(seen) == 2

    def test_no_collision_returns_clean(self):
        seen = {}
        id1 = _arch_node_id("agent:alpha", seen)
        id2 = _arch_node_id("agent:beta", seen)
        assert id1 != id2


# ── _architecture_table ───────────────────────────────────────────────

class TestArchitectureTable:
    def test_empty_graph_returns_empty(self):
        assert _architecture_table({}) == ""

    def test_renders_table(self):
        graph = {
            "edges": [{"from": "agent:a", "to": "tool:b", "kind": "uses"}],
            "orphaned_refs": [],
        }
        html = _architecture_table(graph)
        assert "Architecture" in html
        assert "Components" in html
        assert "Relationships" in html
        assert "agent:a" in html
        assert "tool:b" in html
        assert "uses" in html

    def test_orphan_highlighted(self):
        graph = {
            "edges": [],
            "orphaned_refs": ["tool:lost"],
        }
        html = _architecture_table(graph)
        assert "orphan" in html

    def test_no_mermaid_cdn(self):
        graph = {
            "edges": [{"from": "a", "to": "b", "kind": "ref"}],
            "orphaned_refs": [],
        }
        html = _architecture_table(graph)
        assert "cdn.jsdelivr" not in html
        assert "mermaid" not in html.lower() or "mermaid" not in html


# ── _architecture_mermaid ─────────────────────────────────────────────

class TestArchitectureMermaid:
    def test_empty_graph_returns_empty(self):
        assert _architecture_mermaid({}) == ""

    def test_renders_mermaid_block(self):
        graph = {
            "edges": [{"from": "agent:a", "to": "tool:b", "kind": "uses"}],
            "orphaned_refs": [],
        }
        html = _architecture_mermaid(graph)
        assert "graph TD" in html
        assert "cdn.jsdelivr.net/npm/mermaid" in html
        assert "mermaid.initialize" in html

    def test_orphan_dashed_border(self):
        graph = {
            "edges": [],
            "orphaned_refs": ["tool:lost"],
        }
        html = _architecture_mermaid(graph)
        assert "stroke-dasharray: 5 5" in html

    def test_injection_in_label_is_escaped(self):
        graph = {
            "edges": [{"from": 'agent:<script>', "to": "tool:b", "kind": 'ref">x'}],
            "orphaned_refs": [],
        }
        html = _architecture_mermaid(graph)
        # The label content should be escaped, not raw HTML
        assert 'agent:&lt;script&gt;' in html
        assert "&gt;" in html  # > is escaped
        # Raw injection in label must not appear
        assert 'agent:<script>' not in html

    def test_node_id_collision_no_duplicate_ids(self):
        graph = {
            "edges": [
                {"from": "tool:foo:bar", "to": "agent:x", "kind": "ref"},
                {"from": "tool_foo:bar", "to": "agent:y", "kind": "ref"},
            ],
            "orphaned_refs": [],
        }
        html = _architecture_mermaid(graph)
        # Both should render without duplicate Mermaid IDs
        assert "graph TD" in html


# ── write_html integration ────────────────────────────────────────────

class TestArchitectureWriteHtml:
    def _base_report(self, **overrides):
        report = {
            "files_scanned": 1,
            "counts": {},
            "detected_frameworks": [],
            "findings": [],
            "normalized_capabilities": [],
            "trust_score": {"overall_ai_risk_score": 50, "categories": {}},
            "capability_diff": {},
            "tool_surface": [],
            "policy_decision": {"outcome": "pass", "reasons": []},
        }
        report.update(overrides)
        return report

    def test_default_includes_architecture_table(self, tmp_path):
        report = self._base_report(component_graph={
            "edges": [{"from": "agent:a", "to": "tool:b", "kind": "uses"}],
            "orphaned_refs": [],
        })
        out = tmp_path / "report.html"
        write_html(report, str(out))
        content = out.read_text(encoding="utf-8")
        assert "Architecture" in content
        assert "agent:a" in content

    def test_no_architecture_flag(self, tmp_path):
        report = self._base_report(component_graph={
            "edges": [{"from": "agent:a", "to": "tool:b", "kind": "uses"}],
            "orphaned_refs": [],
        })
        out = tmp_path / "report.html"
        write_html(report, str(out), include_architecture=False)
        content = out.read_text(encoding="utf-8")
        assert "Architecture" not in content

    def test_mermaid_opt_in(self, tmp_path):
        report = self._base_report(component_graph={
            "edges": [{"from": "agent:a", "to": "tool:b", "kind": "uses"}],
            "orphaned_refs": [],
        })
        out = tmp_path / "report.html"
        write_html(report, str(out), include_architecture=True, include_mermaid=True)
        content = out.read_text(encoding="utf-8")
        assert "cdn.jsdelivr.net/npm/mermaid" in content

    def test_mermaid_not_present_by_default(self, tmp_path):
        report = self._base_report(component_graph={
            "edges": [{"from": "agent:a", "to": "tool:b", "kind": "uses"}],
            "orphaned_refs": [],
        })
        out = tmp_path / "report.html"
        write_html(report, str(out))
        content = out.read_text(encoding="utf-8")
        assert "cdn.jsdelivr.net/npm/mermaid" not in content

    def test_empty_component_graph_no_architecture_section(self, tmp_path):
        report = self._base_report()
        out = tmp_path / "report.html"
        write_html(report, str(out))
        content = out.read_text(encoding="utf-8")
        assert "Architecture" not in content

    def test_injection_in_graph_data_is_escaped(self, tmp_path):
        report = self._base_report(component_graph={
            "edges": [{"from": 'agent:<img src=x>', "to": "tool:b", "kind": "ref"}],
            "orphaned_refs": [],
        })
        out = tmp_path / "report.html"
        write_html(report, str(out))
        content = out.read_text(encoding="utf-8")
        assert "<img src=x>" not in content

    def test_backward_compat_no_architecture_kwarg(self, tmp_path):
        """write_html(report, path) still works — no TypeError."""
        report = self._base_report()
        out = tmp_path / "report.html"
        write_html(report, str(out))
        assert out.exists()
