import os

from safeai.engine.scan import run_scan
from safeai.frameworks.windsurf.parser import WindsurfParser

FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "windsurf", "representative"
)


def test_representative_windsurf_file_is_detected_and_parsed():
    report = run_scan(FIXTURE)

    assert "windsurf" in report["detected_frameworks"]
    model = next(
        model
        for model in report["unified_models"]
        if "windsurf" in model.get("frameworks", [])
    )
    artifacts = model["artifacts"]

    assert {tool["name"] for tool in artifacts["tools"]} == {
        "read_file", "run_tests",
    }
    assert "claude-sonnet-4-5" in {
        model_entry["name"] for model_entry in artifacts["models"]
    }

    capability_names = {
        capability["name"] for capability in model["capabilities"]
    }
    assert {"shell", "external_apis"}.issubset(capability_names)


class TestDetect:
    def test_detects_dotfile_by_name(self):
        parser = WindsurfParser()
        assert parser.detect(".windsurfrules", "{}") is True

    def test_detects_dotfile_in_subdirectory(self):
        parser = WindsurfParser()
        assert parser.detect("/repo/nested/.windsurfrules", "{}") is True

    def test_ignores_unrelated_file(self):
        parser = WindsurfParser()
        assert parser.detect("README.md", "some content") is False

    def test_ignores_similarly_named_file(self):
        parser = WindsurfParser()
        assert parser.detect("windsurf.json", "{}") is False


class TestParseJSON:
    def test_extracts_tools_and_model(self):
        parser = WindsurfParser()
        content = '{"tools": ["run_tests"], "model": "gpt-5"}'
        result = parser.parse(".windsurfrules", content)
        assert result["framework"] == "windsurf"
        assert "run_tests" in result["tools"]
        assert "gpt-5" in result["models"]

    def test_shell_mention_in_rules_yields_shell_capability(self):
        parser = WindsurfParser()
        content = '{"rules": ["You may run shell commands freely."]}'
        result = parser.parse(".windsurfrules", content)
        names = {c["name"] for c in result["capabilities"]}
        assert "shell" in names

    def test_unrestricted_tool_grant_is_flagged_in_evidence(self):
        parser = WindsurfParser()
        content = '{"tools": ["*"]}'
        result = parser.parse(".windsurfrules", content)
        assert any("unrestricted" in e for e in result["detection_evidence"])


class TestParseYAML:
    def test_extracts_tools_from_yaml(self):
        parser = WindsurfParser()
        content = "tools:\n  - read_file\n  - write_file\nmodel: claude-opus-4\n"
        result = parser.parse(".windsurfrules", content)
        assert set(result["tools"]) == {"read_file", "write_file"}
        assert "claude-opus-4" in result["models"]

    def test_filesystem_mention_in_yaml_rules_yields_filesystem_capability(self):
        parser = WindsurfParser()
        content = "rules:\n  - You may read and write file contents in this repo.\n"
        result = parser.parse(".windsurfrules", content)
        names = {c["name"] for c in result["capabilities"]}
        assert "filesystem" in names


class TestParseFreeform:
    def test_plain_text_falls_back_to_content_scan(self):
        parser = WindsurfParser()
        content = "You are an assistant. You may run shell commands to build the project."
        result = parser.parse(".windsurfrules", content)
        assert result["discovery_method"] == "content"
        names = {c["name"] for c in result["capabilities"]}
        assert "shell" in names

    def test_plain_text_with_no_capability_keywords_yields_no_capabilities(self):
        parser = WindsurfParser()
        content = "Always write concise commit messages and prefer clarity."
        result = parser.parse(".windsurfrules", content)
        assert result["capabilities"] == []


def test_mcp_reference_is_recorded_as_asset():
    parser = WindsurfParser()
    content = '{"rules": ["This project uses MCP servers for tool access."]}'
    result = parser.parse(".windsurfrules", content)
    assert len(result["mcp_assets"]) == 1
