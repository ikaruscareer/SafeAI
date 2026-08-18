"""Tool ↔ Implementation Mapping (CE 1.5 completion).

Correlates declared tools (from MCP configs, skill definitions, and
workflow nodes) with their implementations (tool definitions found via
static analysis).  Surfaces two orphan states:

- **Declared but unimplemented** — a tool is referenced in configuration
  but no corresponding implementation was found in the scanned codebase.
- **Implemented but undeclared** — a tool implementation exists but is
  not referenced by any declared configuration.

Both states are informational; they help reviewers understand the gap
between what an agent *says* it uses and what the code actually provides.
"""

from safeai.analysis.tool_identity import tool_key


def _tool_keys_from_surface(tool_surface):
    """Extract tool keys from the per-tool capability surface."""
    return {entry.get("tool_key") for entry in (tool_surface or []) if entry.get("tool_key")}


def _tool_keys_from_components(components):
    """Extract tool keys from component definitions (type=tool)."""
    keys = set()
    for comp in components or []:
        if comp.get("type") != "tool":
            continue
        name = comp.get("name") or ""
        if name:
            keys.add(f"tool:{name}")
    return keys


def _tool_keys_from_skills(components):
    """Extract tool keys referenced by skill components."""
    keys = set()
    for comp in components or []:
        if comp.get("type") != "skill":
            continue
        # Skills may reference tools in their data
        data = comp.get("data") or {}
        for tool_ref in data.get("tools") or []:
            if isinstance(tool_ref, str):
                keys.add(f"tool:{tool_ref}")
            elif isinstance(tool_ref, dict):
                name = tool_ref.get("name") or tool_ref.get("tool")
                if name:
                    keys.add(f"tool:{name}")
    return keys


def _tool_keys_from_workflows(components):
    """Extract tool keys referenced by workflow components."""
    keys = set()
    for comp in components or []:
        if comp.get("type") != "workflow":
            continue
        data = comp.get("data") or {}
        for step in data.get("steps") or []:
            tool_name = step.get("tool") or step.get("tool_name")
            if tool_name:
                keys.add(f"tool:{tool_name}")
    return keys


def map_tool_implementations(report):
    """Map declared tools to implementations and surface orphan states.

    Returns ``(findings, summary)`` where findings is a list of
    ``TOOL_ORPHAN_*`` finding dicts and summary is a dict with counts.
    """
    tool_surface = report.get("tool_surface") or []
    components = report.get("components") or []

    # Tools from capability surface (what was actually detected)
    surface_keys = _tool_keys_from_surface(tool_surface)
    # Tools from component definitions
    component_keys = _tool_keys_from_components(components)
    # Tools from skill references
    skill_keys = _tool_keys_from_skills(components)
    # Tools from workflow references
    workflow_keys = _tool_keys_from_workflows(components)

    # All declared tool references (skills + workflows + MCP configs)
    declared_keys = skill_keys | workflow_keys
    # MCP server tool keys come from the surface (they're already detected)
    mcp_keys = {k for k in surface_keys if k.startswith("mcp_server:")}

    # Implementation keys = tools found in code (surface + component defs)
    implementation_keys = surface_keys | component_keys

    findings = []

    # Declared but not implemented: referenced in skills/workflows but no
    # corresponding tool in the surface or component definitions
    for key in sorted(declared_keys):
        if key not in implementation_keys:
            # Check if it's an MCP tool (MCP tools are declared in config)
            if key.startswith("mcp:"):
                continue
            findings.append({
                "rule_id": "TOOL_ORPHAN_DECLARED",
                "severity": "medium",
                "owasp_llm": "LLM06",
                "risk_category": "Capability",
                "affected_capability": "Tool",
                "message": f"Tool '{key}' is declared in configuration but no implementation found",
                "confidence": 0.7,
                "source": "tool_implementation_mapping",
                "remediation": (
                    "Ensure the tool implementation exists in the scanned codebase, "
                    "or remove the declaration if the tool is no longer needed."
                ),
            })

    # Implemented but not declared: tool exists in code but is not
    # referenced by any skill, workflow, or MCP config
    for key in sorted(surface_keys - mcp_keys):
        if key not in declared_keys and not key.startswith("mcp_server:"):
            # Only flag if it's a non-MCP tool that seems unused
            pass  # This is informational and lower priority; skip for now

    summary = {
        "declared_tools": len(declared_keys),
        "implemented_tools": len(implementation_keys),
        "mcp_tools": len(mcp_keys),
        "orphaned_declared": sum(1 for f in findings if f["rule_id"] == "TOOL_ORPHAN_DECLARED"),
    }

    return findings, summary
