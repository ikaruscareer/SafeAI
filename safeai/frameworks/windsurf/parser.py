"""Windsurf IDE (.windsurfrules) framework adapter.

Detects the ``.windsurfrules`` config file Windsurf IDE uses to define agent
behavior, permissions, and tool access, and extracts the capability-relevant
signals it declares — mirroring the ``.cursorrules`` adapter but for this
narrower, single-file config.

``.windsurfrules`` has no fixed schema in the wild: some projects write JSON,
some YAML, and many just write free-text instructions. This adapter tries
structured parsing first and falls back to scanning the raw text for the
same capability keywords when the file is neither valid JSON nor YAML.
"""

import json
import re

import yaml

from safeai.analysis.capabilities import dedupe_capabilities, make_capability
from safeai.frameworks import register_parser

_RULE_TEXT_KEYS = ("rules", "instructions", "prompt", "content")
_TOOL_KEYS = ("tools", "allowed_tools", "permissions", "allow")

_SHELL_RE = re.compile(r"shell|exec|command|subprocess", re.IGNORECASE)
_FILESYSTEM_RE = re.compile(r"file|filesystem|read.*file|write.*file", re.IGNORECASE)
_HTTP_RE = re.compile(r"\bhttp\b|\bapi\b|fetch|request", re.IGNORECASE)
_DATABASE_RE = re.compile(r"database|\bsql\b|postgres|mysql|mongodb", re.IGNORECASE)
_MCP_RE = re.compile(r"\bmcp\b|model.context.protocol", re.IGNORECASE)
_UNRESTRICTED_RE = re.compile(r"^(\*|all|any)$", re.IGNORECASE)


def _scan_capabilities(text, caps, evidence_prefix):
    """Scan free text for capability keywords, appending to *caps*."""
    if _SHELL_RE.search(text):
        caps.append(make_capability(
            "shell", "Shell", "windsurf",
            f"{evidence_prefix}: shell reference", confidence=0.7, source="config",
        ))
    if _FILESYSTEM_RE.search(text):
        caps.append(make_capability(
            "filesystem", "Filesystem", "windsurf",
            f"{evidence_prefix}: filesystem reference", confidence=0.7, source="config",
        ))
    if _HTTP_RE.search(text):
        caps.append(make_capability(
            "external_apis", "External APIs", "windsurf",
            f"{evidence_prefix}: HTTP/API reference", confidence=0.6, source="config",
        ))
    if _DATABASE_RE.search(text):
        caps.append(make_capability(
            "databases", "Databases", "windsurf",
            f"{evidence_prefix}: database reference", confidence=0.6, source="config",
        ))


def _load_structured(content):
    """Try JSON then YAML. Returns a dict, or None if neither parses to one."""
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            return data
    except yaml.YAMLError:
        pass
    return None


@register_parser
class WindsurfParser:
    name = "windsurf"

    def detect(self, path, content, scan_ctx=None):
        fname = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        return fname == ".windsurfrules"

    def parse(self, path, content, scan_ctx=None):
        result = {
            "framework": "windsurf",
            "agents": [],
            "tools": [],
            "workflows": [],
            "models": [],
            "mcp_assets": [],
            "capabilities": [],
            "relationships": [],
            "discovery_method": "filename",
            "parser_confidence": 0.75,
            "detection_evidence": [".windsurfrules"],
        }

        caps = []
        data = _load_structured(content)
        if data is not None:
            self._parse_structured(data, result, caps)
        else:
            self._parse_freeform(content, result, caps)

        if _MCP_RE.search(content):
            result["mcp_assets"].append({"type": "reference", "source": ".windsurfrules"})

        result["capabilities"] = dedupe_capabilities(caps)
        return result

    def _parse_structured(self, data, result, caps):
        result["discovery_method"] = "config"

        rule_text_parts = []
        for key in _RULE_TEXT_KEYS:
            val = data.get(key)
            if isinstance(val, str):
                rule_text_parts.append(val)
            elif isinstance(val, list):
                rule_text_parts.extend(str(v) for v in val)
        rule_text = "\n".join(rule_text_parts)
        if rule_text:
            _scan_capabilities(rule_text, caps, "rules")

        tool_names = []
        for key in _TOOL_KEYS:
            val = data.get(key)
            if isinstance(val, str):
                tool_names.append(val)
            elif isinstance(val, list):
                tool_names.extend(str(v) for v in val)
            elif isinstance(val, dict):
                tool_names.extend(str(k) for k in val)
        for tool in tool_names:
            result["tools"].append(tool)
        if any(_UNRESTRICTED_RE.match(t.strip()) for t in tool_names):
            result["detection_evidence"].append("unrestricted tool grant (no per-tool scoping)")

        if "model" in data:
            result["models"].append(str(data["model"]))

    def _parse_freeform(self, content, result, caps):
        result["discovery_method"] = "content"
        _scan_capabilities(content, caps, "freeform rules")
