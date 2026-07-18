from safeai.analyzers.mcp.analyzer import MCPAnalyzer


def test_mcp_validation_findings_for_missing_auth_and_permissions():
    file_cache = {
        "mcp.json": '{"mcp": {"servers": [{"name": "s1"}], "tools": ["exec"], "resources": [], "transports": ["http"]}}'
    }
    findings = MCPAnalyzer().run(file_cache, rules=[], agent_models=[])
    rule_ids = {f["rule_id"] for f in findings}
    assert "MCP_AUTH_MISSING" in rule_ids
    assert "MCP_PERMISSIONS_MISSING" in rule_ids
    assert "MCP_DANGEROUS_TOOL" in rule_ids
    assert "MCP_SCHEMA_REQUIRED" in rule_ids


def test_mcp_assets_embedded_in_summary_finding():
    file_cache = {"mcp.yaml": "mcp:\n  version: '1.1'\n  servers: []\n  tools: []\n  resources: []\n  transports: ['stdio']\n  auth: token\n  permissions: {}\n"}
    findings = MCPAnalyzer().run(file_cache, rules=[], agent_models=[])
    summary = [f for f in findings if f["rule_id"] == "MCP_ASSETS_DISCOVERED"][0]
    assert isinstance(summary.get("mcp_assets"), list)
    assert "1.1" in summary.get("schema_versions", [])
