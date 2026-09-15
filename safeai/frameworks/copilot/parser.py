"""GitHub Copilot instruction-file framework adapter.

Copilot repository instructions are Markdown, optionally with YAML
frontmatter, while ``.copilot/*.yml`` files may contain structured tool and
permission grants. Structured fields are parsed before the remaining text is
scanned for capability-relevant language.
"""

import re

import yaml

from safeai.analysis.capabilities import dedupe_capabilities, make_capability
from safeai.frameworks import register_parser

_INSTRUCTION_KEYS = ("instructions", "rules", "prompt", "content")
_TOOL_KEYS = ("tools", "allowed_tools", "allowed-tools", "permissions", "allow")
_MCP_KEYS = ("mcpServers", "mcp_servers", "mcp-servers")

_SHELL_RE = re.compile(r"shell|exec|command|subprocess|terminal", re.IGNORECASE)
_FILESYSTEM_RE = re.compile(r"file|filesystem|read.*file|write.*file", re.IGNORECASE)
_HTTP_RE = re.compile(r"\bhttp\b|\bapi\b|[_-]api\b|fetch|request", re.IGNORECASE)
_DATABASE_RE = re.compile(r"database|\bsql\b|postgres|mysql|mongodb", re.IGNORECASE)
_MCP_RE = re.compile(r"\bmcp\b|mcp[_-]?servers?|model.context.protocol", re.IGNORECASE)
_UNRESTRICTED_RE = re.compile(r"^(\*|all|any)$", re.IGNORECASE)
_COPILOT_YAML_RE = re.compile(r"(^|/)\.copilot/[^/]+\.ya?ml$", re.IGNORECASE)


def _scan_capabilities(text, caps, evidence_prefix):
    """Scan instruction text for capability keywords, appending to *caps*."""
    patterns = (
        (_SHELL_RE, "shell", "Shell", 0.7, "shell reference"),
        (_FILESYSTEM_RE, "filesystem", "Filesystem", 0.7, "filesystem reference"),
        (_HTTP_RE, "external_apis", "External APIs", 0.6, "HTTP/API reference"),
        (_DATABASE_RE, "databases", "Databases", 0.6, "database reference"),
        (_MCP_RE, "mcp", "MCP", 0.7, "MCP reference"),
    )
    for pattern, name, category, confidence, evidence in patterns:
        if pattern.search(text):
            caps.append(make_capability(
                name, category, "copilot",
                f"{evidence_prefix}: {evidence}",
                confidence=confidence, source="config",
            ))


def _load_yaml(content):
    """Return a YAML mapping, or ``None`` for malformed/non-mapping input."""
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


def _split_frontmatter(content):
    """Return ``(mapping, body)`` for Markdown YAML frontmatter."""
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, content
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            data = _load_yaml("\n".join(lines[1:index]))
            return data, "\n".join(lines[index + 1:])
    return None, content


def _named_items(value):
    """Return names from a string, list, or name-keyed mapping."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        items = []
        for entry in value:
            if isinstance(entry, dict) and entry.get("name"):
                items.append(str(entry["name"]))
            elif isinstance(entry, str):
                items.append(entry)
        return items
    if isinstance(value, dict):
        return [str(key) for key in value]
    return []


def _source_name(path):
    normalized = str(path).replace("\\", "/")
    for marker in ("/.github/", "/.copilot/"):
        if marker in normalized:
            return marker[1:] + normalized.split(marker, 1)[1]
    if normalized.startswith((".github/", ".copilot/")):
        return normalized
    return normalized.rsplit("/", 1)[-1]


@register_parser
class CopilotParser:
    """Parse GitHub Copilot Markdown and YAML instructions."""

    name = "copilot"

    def detect(self, path, content, scan_ctx=None):
        normalized = "/" + str(path).replace("\\", "/").lower().lstrip("/")
        return normalized.endswith((
            "/.github/copilot-instructions.md",
            "/.copilot/instructions.md",
        )) or bool(_COPILOT_YAML_RE.search(normalized))

    def parse(self, path, content, scan_ctx=None):
        source = _source_name(path)
        result = {
            "framework": "copilot",
            "agents": [],
            "tools": [],
            "workflows": [],
            "models": [],
            "mcp_assets": [],
            "capabilities": [],
            "relationships": [],
            "discovery_method": "filename",
            "parser_confidence": 0.8,
            "detection_evidence": [source],
        }

        caps = []
        is_markdown = source.lower().endswith(".md")
        if is_markdown:
            data, body = _split_frontmatter(content)
            if data is not None:
                result["discovery_method"] = "config"
                self._parse_structured(data, result, caps, source)
                _scan_capabilities(body, caps, "Markdown instructions")
            else:
                result["discovery_method"] = "content"
                _scan_capabilities(content, caps, "Markdown instructions")
        else:
            data = _load_yaml(content)
            if data is None:
                result["discovery_method"] = "content"
                _scan_capabilities(content, caps, "freeform config")
            else:
                result["discovery_method"] = "config"
                self._parse_structured(data, result, caps, source)

        if _MCP_RE.search(content) and not result["mcp_assets"]:
            result["mcp_assets"].append({"type": "reference", "source": source})

        result["capabilities"] = dedupe_capabilities(caps)
        return result

    def _parse_structured(self, data, result, caps, source):
        instruction_parts = []
        for key in _INSTRUCTION_KEYS:
            value = data.get(key)
            if isinstance(value, str):
                instruction_parts.append(value)
            elif isinstance(value, list):
                instruction_parts.extend(str(item) for item in value)
        if instruction_parts:
            _scan_capabilities("\n".join(instruction_parts), caps, "instructions")

        tools = []
        for key in _TOOL_KEYS:
            tools.extend(_named_items(data.get(key)))
        result["tools"].extend(tools)
        for tool in tools:
            _scan_capabilities(tool, caps, f"tool {tool}")
        if any(_UNRESTRICTED_RE.match(tool.strip()) for tool in tools):
            result["detection_evidence"].append(
                "unrestricted tool grant (no per-tool scoping)"
            )

        model = data.get("model")
        if isinstance(model, str):
            result["models"].append(model)

        servers = []
        for key in _MCP_KEYS:
            servers.extend(_named_items(data.get(key)))
        for server in servers:
            result["mcp_assets"].append({
                "type": "server", "name": server, "source": source,
            })
        if servers:
            _scan_capabilities("MCP servers", caps, "mcpServers")
