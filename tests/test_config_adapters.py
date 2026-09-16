"""Tests for the OpenClaw and GitHub Copilot config-file adapters."""

from safeai.engine.scan import run_scan
from safeai.frameworks.copilot.parser import CopilotParser
from safeai.frameworks.openclaw.parser import OpenClawParser


class TestOpenClawDetection:
    def test_detects_directory_json_and_yaml(self):
        parser = OpenClawParser()
        assert parser.detect(".openclaw/config.json", "{}")
        assert parser.detect("/repo/.openclaw/agents/reviewer.yaml", "{}")
        assert parser.detect(r"C:\repo\.openclaw\config.yml", "{}")

    def test_detects_dotfile_yaml(self):
        parser = OpenClawParser()
        assert parser.detect(".openclaw.yaml", "{}")
        assert parser.detect("/repo/.openclaw.yml", "{}")

    def test_ignores_unrelated_files(self):
        parser = OpenClawParser()
        assert not parser.detect("openclaw.json", "{}")
        assert not parser.detect(".openclaw/README.md", "OpenClaw")


class TestOpenClawParsing:
    def test_extracts_json_tools_model_capabilities_and_mcp_servers(self):
        content = """{
            "model": "gpt-5",
            "tools": ["run_shell", "read_file", "call_api"],
            "systemPrompt": "Query the PostgreSQL database when needed.",
            "mcpServers": {"github": {"command": "server"}}
        }"""
        result = OpenClawParser().parse(".openclaw/config.json", content)

        assert result["discovery_method"] == "config"
        assert result["models"] == ["gpt-5"]
        assert result["tools"] == ["run_shell", "read_file", "call_api"]
        assert {cap["name"] for cap in result["capabilities"]} == {
            "shell", "filesystem", "external_apis", "databases", "mcp",
        }
        assert result["mcp_assets"] == [{
            "type": "server",
            "name": "github",
            "source": ".openclaw/config.json",
        }]

    def test_extracts_yaml_allowed_tools_and_instructions(self):
        content = """model: claude-sonnet
allowed_tools:
  - terminal
instructions: Write files in the workspace.
"""
        result = OpenClawParser().parse(".openclaw.yaml", content)

        assert result["models"] == ["claude-sonnet"]
        assert result["tools"] == ["terminal"]
        assert {cap["name"] for cap in result["capabilities"]} == {
            "shell", "filesystem",
        }

    def test_flags_unrestricted_tool_grant(self):
        result = OpenClawParser().parse(
            ".openclaw/config.json", '{"allowed_tools": ["*"]}',
        )
        assert any("unrestricted" in item for item in result["detection_evidence"])

    def test_malformed_json_uses_free_text_fallback(self):
        content = '{"tools": [\nRun shell commands and call the HTTP API'
        result = OpenClawParser().parse(".openclaw/config.json", content)
        assert result["discovery_method"] == "content"
        assert {cap["name"] for cap in result["capabilities"]} == {
            "shell", "external_apis",
        }

    def test_empty_file_has_no_artifacts(self):
        result = OpenClawParser().parse(".openclaw/config.json", "")
        assert result["tools"] == []
        assert result["models"] == []
        assert result["mcp_assets"] == []
        assert result["capabilities"] == []


class TestCopilotDetection:
    def test_detects_supported_markdown_paths(self):
        parser = CopilotParser()
        assert parser.detect(".github/copilot-instructions.md", "")
        assert parser.detect("/repo/.copilot/instructions.md", "")
        assert parser.detect(r"C:\repo\.github\copilot-instructions.md", "")

    def test_detects_copilot_yaml(self):
        parser = CopilotParser()
        assert parser.detect(".copilot/permissions.yml", "")
        assert parser.detect("/repo/.copilot/tools.yaml", "")

    def test_ignores_unrelated_files(self):
        parser = CopilotParser()
        assert not parser.detect("copilot-instructions.md", "")
        assert not parser.detect(".github/instructions.md", "")
        assert not parser.detect(".copilot/README.md", "")


class TestCopilotParsing:
    def test_scans_markdown_capability_keywords(self):
        content = """# Instructions
Run shell commands, read files, call an HTTP API, query SQL, and use MCP tools.
"""
        result = CopilotParser().parse(".github/copilot-instructions.md", content)

        assert result["discovery_method"] == "content"
        assert {cap["name"] for cap in result["capabilities"]} == {
            "shell", "filesystem", "external_apis", "databases", "mcp",
        }
        assert result["mcp_assets"] == [{
            "type": "reference",
            "source": ".github/copilot-instructions.md",
        }]

    def test_parses_markdown_frontmatter_before_body(self):
        content = """---
model: gpt-5
tools:
  - terminal
mcpServers:
  github: {}
---
Read files before making a change.
"""
        result = CopilotParser().parse(".github/copilot-instructions.md", content)

        assert result["discovery_method"] == "config"
        assert result["models"] == ["gpt-5"]
        assert result["tools"] == ["terminal"]
        assert {cap["name"] for cap in result["capabilities"]} == {
            "shell", "filesystem", "mcp",
        }
        assert result["mcp_assets"][0]["name"] == "github"

    def test_parses_yaml_permission_grants(self):
        content = """permissions:
  run_shell: allow
  database_query: allow
instructions: Call the internal API.
"""
        result = CopilotParser().parse(".copilot/permissions.yml", content)

        assert set(result["tools"]) == {"run_shell", "database_query"}
        assert {cap["name"] for cap in result["capabilities"]} == {
            "shell", "databases", "external_apis",
        }

    def test_malformed_yaml_uses_free_text_fallback(self):
        content = "tools: [\nUse the filesystem to read files"
        result = CopilotParser().parse(".copilot/permissions.yml", content)
        assert result["discovery_method"] == "content"
        assert {cap["name"] for cap in result["capabilities"]} == {"filesystem"}

    def test_empty_markdown_has_no_artifacts(self):
        result = CopilotParser().parse(".copilot/instructions.md", "")
        assert result["tools"] == []
        assert result["models"] == []
        assert result["mcp_assets"] == []
        assert result["capabilities"] == []


def test_full_scan_detects_both_config_adapters(tmp_path):
    openclaw_dir = tmp_path / ".openclaw"
    openclaw_dir.mkdir()
    (openclaw_dir / "config.json").write_text(
        '{"tools": ["run_shell"]}', encoding="utf-8",
    )
    copilot_dir = tmp_path / ".github"
    copilot_dir.mkdir()
    (copilot_dir / "copilot-instructions.md").write_text(
        "Read files before editing them.", encoding="utf-8",
    )

    report = run_scan(tmp_path)

    assert {"openclaw", "copilot"}.issubset(report["detected_frameworks"])


def test_full_scan_discovers_dot_copilot_markdown(tmp_path):
    copilot_dir = tmp_path / ".copilot"
    copilot_dir.mkdir()
    (copilot_dir / "instructions.md").write_text(
        "Run shell commands when needed.", encoding="utf-8",
    )

    report = run_scan(tmp_path)

    assert "copilot" in report["detected_frameworks"]
