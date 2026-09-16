"""Tests for scripts/scan_framework.py.

Covers target resolution, report summarisation, comparison building, and
rendering. Fully offline: nothing here clones a repository or runs a scan.
"""

import importlib.util
import json
import os

import pytest

_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "scan_framework.py",
)
_spec = importlib.util.spec_from_file_location("scan_framework", _SCRIPT)
sf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sf)


CATALOG = {
    "langgraph": {
        "id": "langgraph",
        "repository": "langchain-ai/langgraph",
        "display_name": "LangGraph",
        "default_ref": "main",
        "upstream_url": "https://github.com/langchain-ai/langgraph",
    },
    "llamaindex": {
        "id": "llamaindex",
        "repository": "run-llama/llama_index",
        "display_name": "LlamaIndex",
        "default_ref": "main",
        "upstream_url": "https://github.com/run-llama/llama_index",
    },
}


def _report(rules, capabilities, frameworks, files=10, counts=None):
    """Build a minimal SafeAI-shaped JSON report."""
    findings = [
        {"rule_id": rule, "severity": severity, "risk_category": "Capability", "owasp_llm": "LLM06"}
        for rule, severity in rules
    ]
    return {
        "findings": findings,
        "counts": counts or {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "files_scanned": files,
        "detected_frameworks": frameworks,
        "normalized_capabilities": [{"name": c.lower(), "category": c} for c in capabilities],
        "trust_score": {"overall_ai_risk_score": 62, "categories": {"Capability": 40, "Safety": 84}},
        "scanner_metadata": {"engine_version": "2.2.1", "ruleset": {"file": "base_rules.yaml", "rule_count": 79}},
        "assurance_boundary": {"coverage_notes": ["1 file not read: larger than the 2 MiB read limit"]},
        "policy_decision": {"outcome": "warn"},
        "mcp_assets": [{"a": 1}],
        "components": [],
        "kya_agents": [{"agent_id": "x"}],
    }


def _scorecard(score=4.5, status="warn"):
    return {"safeai_security_scorecard": {"summary": {"score": score, "status": status, "blocking_findings": 2}}}


def _record(target_id, rules, capabilities, counts, score=4.5):
    return {
        "id": target_id,
        "display_name": target_id.title(),
        "repository": f"org/{target_id}",
        "upstream_url": f"https://github.com/org/{target_id}",
        "requested_ref": "main",
        "commit": "abcdef1234567890",
        "status": "scanned",
        "stage": "",
        "error": "",
        "clone_seconds": 1.0,
        "scan_seconds": 2.0,
        "summary": sf.summarise(
            _report(rules, capabilities, [target_id], counts=counts), _scorecard(score)
        ),
    }


def _args(**overrides):
    args = sf.build_parser().parse_args(["--frameworks", "langgraph"])
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


# --------------------------------------------------------------------------
# Target resolution
# --------------------------------------------------------------------------


def test_resolve_by_catalog_id():
    target = sf.resolve_target("langgraph", CATALOG)
    assert target["repository"] == "langchain-ai/langgraph"
    assert target["default_ref"] == "main"
    assert target["source"] == "catalog"


@pytest.mark.parametrize("token", ["LlamaIndex", "llama-index", "llama_index", "LLAMAINDEX"])
def test_resolve_is_slug_insensitive(token):
    assert sf.resolve_target(token, CATALOG)["id"] == "llamaindex"


def test_resolve_by_url_reuses_catalog_metadata():
    target = sf.resolve_target("https://github.com/langchain-ai/langgraph", CATALOG)
    assert target["default_ref"] == "main"
    assert target["source"] == "catalog"


def test_resolve_by_owner_repo_reuses_catalog_metadata():
    target = sf.resolve_target("langchain-ai/langgraph", CATALOG)
    assert target["id"] == "langgraph"
    assert target["default_ref"] == "main"


def test_resolve_unknown_repo_still_scannable():
    target = sf.resolve_target("https://github.com/some-org/new-agent-thing.git", CATALOG)
    assert target["repository"] == "some-org/new-agent-thing"
    assert target["upstream_url"] == "https://github.com/some-org/new-agent-thing"
    assert target["default_ref"] == ""
    assert target["source"] == "url"


def test_resolve_rejects_unknown_name():
    with pytest.raises(ValueError, match="unknown framework"):
        sf.resolve_target("not-a-framework", CATALOG)


@pytest.mark.parametrize(
    "token",
    [
        "git@github.com:org/repo.git",
        "file:///etc/passwd",
        "https://gitlab.com/org/repo",
        "ssh://example.com/repo",
    ],
)
def test_resolve_rejects_non_github_sources(token):
    with pytest.raises(ValueError):
        sf.resolve_target(token, CATALOG)


def test_clone_rejects_unsafe_ref(tmp_path):
    target = {
        "id": "x",
        "upstream_url": "https://github.com/org/repo",
        "default_ref": "main; rm -rf /",
    }
    with pytest.raises(RuntimeError, match="unsafe ref"):
        sf.clone(target, str(tmp_path / "x"), depth=1, timeout=5)


# --------------------------------------------------------------------------
# Summarisation
# --------------------------------------------------------------------------


def test_summarise_extracts_the_comparison_fields():
    summary = sf.summarise(
        _report(
            [("CAP_shell", "high"), ("CAP_shell", "high"), ("PROMPT_INJECTION", "critical")],
            ["Shell", "Memory"],
            ["crewai"],
            counts={"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
        ),
        _scorecard(3.0, "fail"),
    )
    assert summary["files_scanned"] == 10
    assert summary["findings_total"] == 3
    assert summary["rule_counts"]["CAP_shell"] == 2
    assert summary["rule_severity"]["PROMPT_INJECTION"] == "critical"
    assert summary["capabilities"] == ["Memory", "Shell"]
    assert summary["scorecard_score"] == 3.0
    assert summary["scorecard_status"] == "fail"
    assert summary["trust_score"] == 62
    assert summary["mcp_assets"] == 1
    assert summary["kya_agents"] == 1
    assert summary["policy_outcome"] == "warn"


def test_summarise_tolerates_an_empty_report():
    summary = sf.summarise({}, {})
    assert summary["findings_total"] == 0
    assert summary["severity_counts"] == dict.fromkeys(sf.SEVERITIES, 0)
    assert summary["trust_score"] is None
    assert summary["capabilities"] == []


def test_summary_carries_no_finding_text():
    """The shared comparison must not leak code excerpts or file paths."""
    report = _report([("DATA_LEAKAGE", "high")], ["Shell"], ["crewai"])
    report["findings"][0]["message"] = "Potential secret exposure: sk-live-SHOULDNOTAPPEAR"
    report["findings"][0]["file"] = "src/private/secrets.py"
    blob = json.dumps(sf.summarise(report, {}))
    assert "SHOULDNOTAPPEAR" not in blob
    assert "secrets.py" not in blob


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------


def _two_records():
    noisy = _record(
        "noisy",
        [("CAP_shell", "high"), ("PROMPT_INJECTION", "critical")],
        ["Shell", "Memory"],
        {"critical": 4, "high": 2, "medium": 1, "low": 0, "info": 0},
    )
    quiet = _record(
        "quiet",
        [("CAP_shell", "high")],
        ["Shell", "Databases"],
        {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    )
    return [quiet, noisy]


def test_comparison_orders_by_blocking_severity():
    data = sf.build_comparison(_two_records(), _args())
    assert [r["id"] for r in data["scanned"]] == ["noisy", "quiet"]


def test_comparison_separates_failures_and_keeps_going():
    failed = {
        "id": "broken",
        "display_name": "Broken",
        "status": "clone_failed",
        "stage": "clone",
        "error": "repository not found",
    }
    data = sf.build_comparison([*_two_records(), failed], _args())
    assert len(data["scanned"]) == 2
    assert [r["id"] for r in data["failed"]] == ["broken"]
    assert data["requested"] == 3


def test_comparison_aggregates_rules_across_targets():
    data = sf.build_comparison(_two_records(), _args())
    by_rule = {r["rule_id"]: r for r in data["top_rules"]}
    assert by_rule["CAP_shell"]["total"] == 2
    assert by_rule["CAP_shell"]["per_target"] == {"noisy": 1, "quiet": 1}
    assert by_rule["PROMPT_INJECTION"]["per_target"]["quiet"] == 0


def test_comparison_collects_the_capability_union():
    data = sf.build_comparison(_two_records(), _args())
    assert data["capabilities"] == ["Databases", "Memory", "Shell"]


def test_observations_flag_shared_and_unique_signals():
    notes = " ".join(sf.observations(sf.build_comparison(_two_records(), _args())["scanned"]))
    assert "CAP_shell" in notes
    assert "Shell" in notes
    assert "Only noisy exposes" in notes or "Only quiet exposes" in notes


def test_observations_need_two_targets():
    assert sf.observations(_two_records()[:1]) == []


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def test_markdown_sections_are_contiguously_numbered():
    markdown = sf.render_markdown(sf.build_comparison(_two_records(), _args()))
    numbers = [int(line.split(".")[0][3:]) for line in markdown.splitlines() if line.startswith("## ")
               and line[3].isdigit()]
    assert numbers == list(range(1, len(numbers) + 1))


def test_markdown_labels_both_score_directions():
    markdown = sf.render_markdown(sf.build_comparison(_two_records(), _args()))
    assert "higher = cleaner" in markdown
    assert "higher = better" in markdown
    assert "static-analysis evidence" in markdown


def test_markdown_handles_a_run_where_everything_failed():
    failed = {
        "id": "broken", "display_name": "Broken", "status": "clone_failed",
        "stage": "clone", "error": "boom",
    }
    markdown = sf.render_markdown(sf.build_comparison([failed], _args()))
    assert "No target completed a scan" in markdown
    assert "boom" in markdown


def test_html_escapes_target_supplied_text():
    record = _record("evil", [("CAP_shell", "high")], ["Shell"], {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0})
    record["display_name"] = "<script>alert(1)</script>"
    page = sf.render_html(sf.build_comparison([record], _args()))
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_html_is_self_contained():
    page = sf.render_html(sf.build_comparison(_two_records(), _args()))
    assert page.startswith("<!DOCTYPE html>")
    assert "<script src=" not in page
    assert "http://" not in page


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def test_cli_requires_a_target(capsys):
    assert sf.main([]) == 2
    assert "pass --frameworks" in capsys.readouterr().err


def test_cli_rejects_an_unknown_framework(capsys):
    assert sf.main(["--frameworks", "definitely-not-a-framework"]) == 2
    assert "unknown framework" in capsys.readouterr().err


def test_cli_dry_run_resolves_without_network(capsys):
    assert sf.main(["--frameworks", "langgraph", "dspy", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "langchain-ai/langgraph" in out
    assert "stanfordnlp/dspy" in out
    assert "nothing cloned or scanned" in out


def test_cli_deduplicates_targets(capsys):
    assert sf.main(["--frameworks", "langgraph", "langchain-ai/langgraph", "--dry-run"]) == 0
    assert capsys.readouterr().out.count("https://github.com/langchain-ai/langgraph") == 1


# --------------------------------------------------------------------------
# Failure reporting
# --------------------------------------------------------------------------


class _Result:
    def __init__(self, returncode=1, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_failure_reason_names_the_exception_not_the_exit_code():
    """A scanner crash can still exit 1, so report the exception."""
    stderr = (
        "Traceback (most recent call last):\n"
        '  File "/x/safeai/analysis/import_graph.py", line 73, in resolve_symbol\n'
        "    return self.resolve_symbol(target.get(\"target\"))\n"
        "  [Previous line repeated 985 more times]\n"
        "RecursionError: maximum recursion depth exceeded\n"
    )
    reason = sf._failure_reason(_Result(returncode=1, stderr=stderr))
    assert "RecursionError: maximum recursion depth exceeded" in reason
    assert "scanner crashed" in reason


def test_failure_reason_falls_back_to_the_last_output_line():
    reason = sf._failure_reason(_Result(returncode=2, stderr="error: rules file not found\n"))
    assert "rules file not found" in reason
    assert "exit 2" in reason


def test_failure_reason_handles_silent_failure():
    assert "exit 3" in sf._failure_reason(_Result(returncode=3))
