"""MCP (Model Context Protocol) analyzer.

Discovers MCP configuration files across the project, resolves their
schema version (v1.0 or v1.1), validates structure, and produces
findings for:
  - Missing or weak authentication
  - Missing permissions configuration
  - Exposed endpoints (HTTP, 0.0.0.0, wildcard)
  - Hardcoded secrets in config
  - Dangerous tool definitions (exec, shell, subprocess)
  - Inferred capabilities from tool/resource/endpoint names
"""

import json
import re

import yaml

from safeai.analysis.capabilities import make_capability
from safeai.analyzers.mcp.compatibility import normalize_mcp_data, resolve_mcp_schema_version
from safeai.analyzers.mcp.validators import validate_mcp_schema


def _base_finding(
    rule_id,
    severity,
    message,
    path,
    line,
    framework="mcp",
    capability=None,
    evidence=None,
    reason=None,
    remediation=None,
    score_contribution=5,
    schema_version=None,
    validation_rule=None,
    affected_object=None,
):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": path,
        "line": line,
        "owasp_llm": "LLM06",
        "evidence": evidence or message,
        "reason": reason or message,
        "risk_category": "Integration",
        "affected_framework": framework,
        "affected_capability": capability,
        "score_contribution": score_contribution,
        "remediation": remediation or "Harden MCP configuration and enforce least privilege.",
        "schema_version": schema_version,
        "validation_rule": validation_rule,
        "affected_object": affected_object,
    }


class MCPAnalyzer:
    name = "mcp"

    CAPABILITY_MAP = {
        "filesystem": ["file", "filesystem", "fs"],
        "shell": ["shell", "exec", "command", "terminal", "subprocess"],
        "databases": ["sql", "db", "postgres", "mysql", "sqlite"],
        "external_apis": ["http", "https", "api", "request"],
        "cloud": ["aws", "azure", "gcp", "s3", "blob", "cloud"],
        "memory": ["memory", "vector", "embed", "retrieval"],
        "github": ["github", "git"],
        "slack": ["slack"],
        "email": ["smtp", "email", "mail"],
        "browser": ["browser", "playwright", "selenium"],
        "planner": ["plan", "planner"],
        "delegation": ["delegate", "handoff", "handover"],
        "human_approval": ["approval", "human"],
    }

    def _parse_config(self, path, content):
        if path.endswith(".json"):
            try:
                return json.loads(content)
            except Exception:
                return None
        if path.endswith((".yaml", ".yml")):
            try:
                return yaml.safe_load(content)
            except Exception:
                return None
        return None

    def _looks_like_mcp(self, path, content, data):
        low = content.lower()
        if "mcp" in low:
            return True
        if isinstance(data, dict):
            keys = {str(k).lower() for k in data.keys()}
            if "mcp" in keys or ("servers" in keys and "tools" in keys):
                return True
        if path.lower().endswith(("mcp.json", "mcp.yaml", "mcp.yml")):
            return True
        return False

    def _find_capabilities(self, text, framework="mcp"):
        low = text.lower()
        caps = []
        for cat, terms in self.CAPABILITY_MAP.items():
            if any(t in low for t in terms):
                category_name = {
                    "external_apis": "External APIs",
                    "human_approval": "Human Approval",
                    "databases": "Databases",
                }.get(cat, cat.title())
                caps.append(make_capability(cat, category_name, framework, text[:160], confidence=0.8, source="configuration"))
        return caps

    def run(self, file_cache, rules, agent_models=None):
        findings = []
        assets = []
        discovered_caps = []

        for path, content in file_cache.items():
            data = self._parse_config(path, content)
            if not self._looks_like_mcp(path, content, data):
                if path.endswith(".py") and re.search(r"\bmcp\b", content, flags=re.I):
                    findings.append(_base_finding(
                        "MCP_PY_REFERENCE",
                        "low",
                        "MCP reference detected in code",
                        path,
                        1,
                        capability="MCP",
                        evidence="python source contains mcp references",
                        score_contribution=2,
                        schema_version="code_reference",
                        validation_rule="heuristic_reference",
                        affected_object="python_source",
                    ))
                continue

            asset = {
                "file": path,
                "kind": "mcp_config" if isinstance(data, dict) else "mcp_reference",
                "schema_version": None,
                "clients": [],
                "servers": [],
                "tools": [],
                "resources": [],
                "prompts": [],
                "transports": [],
                "endpoints": [],
                "auth": None,
                "permissions": None,
                "capabilities": [],
            }

            if isinstance(data, dict):
                mcp_data = normalize_mcp_data(data)
                schema_version = resolve_mcp_schema_version(mcp_data)
                asset["schema_version"] = schema_version

                for issue in validate_mcp_schema(mcp_data, schema_version):
                    findings.append(_base_finding(
                        issue["rule"],
                        issue["severity"],
                        issue["message"],
                        path,
                        1,
                        capability="MCP",
                        score_contribution=7,
                        schema_version=issue.get("schema_version"),
                        validation_rule=issue.get("validation_rule"),
                        affected_object=issue.get("affected_object"),
                    ))

                clients = mcp_data.get("clients") or []
                servers = mcp_data.get("servers") or []
                tools = mcp_data.get("tools") or []
                resources = mcp_data.get("resources") or []
                prompts = mcp_data.get("prompts") or []
                transports = mcp_data.get("transports") or []
                endpoints = mcp_data.get("endpoints") or mcp_data.get("endpoint") or []
                auth = mcp_data.get("auth") or mcp_data.get("authentication")
                permissions = mcp_data.get("permissions")

                asset["clients"] = clients if isinstance(clients, list) else [clients]
                asset["servers"] = servers if isinstance(servers, list) else [servers]
                asset["tools"] = tools if isinstance(tools, list) else [tools]
                asset["resources"] = resources if isinstance(resources, list) else [resources]
                asset["prompts"] = prompts if isinstance(prompts, list) else [prompts]
                asset["transports"] = transports if isinstance(transports, list) else [transports]
                asset["endpoints"] = endpoints if isinstance(endpoints, list) else [endpoints]
                asset["auth"] = auth
                asset["permissions"] = permissions

                if not auth:
                    findings.append(_base_finding(
                        "MCP_AUTH_MISSING",
                        "high",
                        "MCP configuration does not define authentication",
                        path,
                        1,
                        capability="MCP",
                        reason="Unauthenticated MCP endpoints increase exposure risk.",
                        remediation="Configure authentication for all MCP clients and servers.",
                        score_contribution=15,
                        schema_version=schema_version,
                        validation_rule="auth_required",
                        affected_object="auth",
                    ))
                elif isinstance(auth, str) and auth.lower() in {"none", "anonymous", "disabled"}:
                    findings.append(_base_finding(
                        "MCP_AUTH_WEAK",
                        "high",
                        "MCP authentication is weak or disabled",
                        path,
                        1,
                        capability="MCP",
                        reason="Anonymous access enables unauthorized use of MCP tools and resources.",
                        remediation="Use token or certificate-based authentication with rotation.",
                        score_contribution=16,
                        schema_version=schema_version,
                        validation_rule="auth_strength",
                        affected_object="auth",
                    ))

                if not permissions:
                    findings.append(_base_finding(
                        "MCP_PERMISSIONS_MISSING",
                        "high",
                        "MCP permissions are not configured",
                        path,
                        1,
                        capability="MCP",
                        reason="Lack of permissions model allows broad access to MCP operations.",
                        remediation="Define least-privilege permissions per client and tool.",
                        score_contribution=14,
                        schema_version=schema_version,
                        validation_rule="permissions_required",
                        affected_object="permissions",
                    ))

                endpoint_text = " ".join(str(e) for e in asset["endpoints"])
                if endpoint_text and re.search(r"http://|0\.0\.0\.0|\*", endpoint_text, flags=re.I):
                    findings.append(_base_finding(
                        "MCP_ENDPOINT_EXPOSURE",
                        "high",
                        "Potentially exposed MCP endpoint detected",
                        path,
                        1,
                        capability="External APIs",
                        evidence=endpoint_text,
                        reason="Endpoint appears public or lacks transport security.",
                        remediation="Use TLS endpoints and restrict host/network exposure.",
                        score_contribution=14,
                        schema_version=schema_version,
                        validation_rule="endpoint_security",
                        affected_object="endpoints",
                    ))

                serialized = json.dumps(mcp_data, default=str)
                if re.search(r"api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]|token\s*[:=]\s*['\"][^'\"]+['\"]", serialized, flags=re.I):
                    findings.append(_base_finding(
                        "MCP_HARDCODED_SECRET",
                        "critical",
                        "Potential hardcoded secret in MCP configuration",
                        path,
                        1,
                        capability="Identity",
                        evidence="hardcoded token or api_key pattern",
                        reason="Embedded credentials can be exfiltrated and reused.",
                        remediation="Move secrets to environment variables or secret manager.",
                        score_contribution=20,
                        schema_version=schema_version,
                        validation_rule="secret_handling",
                        affected_object="auth",
                    ))

                tool_text = " ".join(str(t) for t in asset["tools"])
                if re.search(r"exec|shell|command|subprocess", tool_text, flags=re.I):
                    findings.append(_base_finding(
                        "MCP_DANGEROUS_TOOL",
                        "high",
                        "MCP tool may allow unrestricted command execution",
                        path,
                        1,
                        capability="Shell",
                        evidence=tool_text,
                        reason="Command execution tools can escalate privileges and exfiltrate data.",
                        remediation="Restrict tool parameters, sandbox execution, and enforce approval gates.",
                        score_contribution=17,
                        schema_version=schema_version,
                        validation_rule="dangerous_tool",
                        affected_object="tools",
                    ))

                cap_source_text = " ".join([
                    json.dumps(asset["tools"], default=str),
                    json.dumps(asset["resources"], default=str),
                    json.dumps(asset["prompts"], default=str),
                    json.dumps(asset["transports"], default=str),
                    json.dumps(asset["endpoints"], default=str),
                ])
                caps = self._find_capabilities(cap_source_text)
                asset["capabilities"] = caps
                discovered_caps.extend(caps)
            else:
                caps = self._find_capabilities(content)
                asset["capabilities"] = caps
                discovered_caps.extend(caps)

            assets.append(asset)

        findings.append({
            "rule_id": "MCP_ASSETS_DISCOVERED",
            "severity": "info",
            "message": f"Discovered MCP assets: {len(assets)}",
            "file": "<scan>",
            "line": 1,
            "owasp_llm": "LLM06",
            "evidence": f"assets={len(assets)}",
            "reason": "MCP discovery completed",
            "risk_category": "Integration",
            "affected_framework": "mcp",
            "affected_capability": "MCP",
            "score_contribution": 0,
            "remediation": "Review discovered MCP assets for governance and access controls.",
            "mcp_assets": assets,
            "mcp_capabilities": discovered_caps,
            "schema_versions": sorted({a.get("schema_version") for a in assets if a.get("schema_version")}),
        })

        return findings
