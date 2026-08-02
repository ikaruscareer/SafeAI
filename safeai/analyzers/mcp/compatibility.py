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


def _servers_as_list(value):
    """Normalize a server mapping into a deterministic list of dicts.

    The client convention used by ``.mcp.json`` and Claude Code is a
    ``{"mcpServers": {"<name>": {...}}}`` mapping. Older SafeAI fixtures
    use a plain ``servers`` list. Both are accepted; output order is
    always sorted by name so serialization stays deterministic.
    """
    if isinstance(value, dict):
        return [
            {"name": name, **(payload if isinstance(payload, dict) else {"value": payload})}
            for name, payload in sorted(value.items(), key=lambda kv: str(kv[0]))
        ]
    if isinstance(value, list):
        return value
    return []


def normalize_mcp_data(data):
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("mcp"), dict):
        merged = dict(data["mcp"])
        if "version" not in merged and "version" in data:
            merged["version"] = data.get("version")
    else:
        merged = dict(data)

    # ``mcpServers`` is the on-disk convention; fold it into ``servers``
    # without discarding an explicitly provided ``servers`` list.
    client_servers = _servers_as_list(merged.get("mcpServers"))
    declared_servers = _servers_as_list(merged.get("servers"))
    if client_servers or isinstance(merged.get("servers"), dict):
        merged["servers"] = declared_servers + client_servers
    return merged
