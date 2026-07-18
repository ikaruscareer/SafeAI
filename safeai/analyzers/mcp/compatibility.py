"""MCP schema version detection and data normalization utilities.

Handles the nested ``{mcp: {...}}`` wrapper convention and maps
version strings (``"1.0"``, ``"1.1"``) to canonical schema keys.
"""

from safeai.analyzers.mcp.schema import DEFAULT_SCHEMA_VERSION


def resolve_mcp_schema_version(mcp_data):
    version = None
    if isinstance(mcp_data, dict):
        version = mcp_data.get("version") or mcp_data.get("schema_version")
    if not version:
        return DEFAULT_SCHEMA_VERSION
    value = str(version).strip()
    if value.startswith("1.0"):
        return "1.0"
    if value.startswith("1.1"):
        return "1.1"
    return DEFAULT_SCHEMA_VERSION


def normalize_mcp_data(data):
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("mcp"), dict):
        merged = dict(data["mcp"])
        if "version" not in merged and "version" in data:
            merged["version"] = data.get("version")
        return merged
    return data
