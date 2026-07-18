"""Schema validation rules for MCP configurations.

Validates against the versioned schema definitions by checking
required fields, field types, and endpoint entry formats.
"""

from safeai.analyzers.mcp.schema import SCHEMA_VERSIONS


def _type_ok(value, expected):
    if expected == "list":
        return isinstance(value, list)
    if expected == "dict":
        return isinstance(value, dict)
    if expected == "dict_or_list":
        return isinstance(value, (dict, list))
    return True


def validate_mcp_schema(mcp_data, version):
    findings = []
    spec = SCHEMA_VERSIONS.get(version) or SCHEMA_VERSIONS["1.1"]

    for required in spec.get("required", []):
        if required not in mcp_data:
            findings.append({
                "rule": "MCP_SCHEMA_REQUIRED",
                "severity": "medium",
                "message": f"Missing required MCP field: {required}",
                "schema_version": version,
                "validation_rule": "required_field",
                "affected_object": required,
            })

    for field, expected in spec.get("object_rules", {}).items():
        if field not in mcp_data:
            continue
        if not _type_ok(mcp_data.get(field), expected):
            findings.append({
                "rule": "MCP_SCHEMA_TYPE",
                "severity": "medium",
                "message": f"MCP field '{field}' must be of type {expected}",
                "schema_version": version,
                "validation_rule": "type_check",
                "affected_object": field,
            })

    for endpoint in mcp_data.get("endpoints", []) if isinstance(mcp_data.get("endpoints"), list) else []:
        if not isinstance(endpoint, str):
            findings.append({
                "rule": "MCP_SCHEMA_ENDPOINT_TYPE",
                "severity": "low",
                "message": "MCP endpoint entries should be strings",
                "schema_version": version,
                "validation_rule": "endpoint_type",
                "affected_object": "endpoints",
            })

    return findings
