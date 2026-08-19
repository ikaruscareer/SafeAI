"""Cross-component relationship graph.

Builds a directed relationship graph between AI components: skills,
tools, workflows, prompts, MCP servers, and models.  Surfaces orphaned
relationships (e.g. a skill referencing a tool that no longer exists)
and unhealthy relationship chains (e.g. a workflow depending on an MCP
server with unresolved commands).
"""

from collections import defaultdict

# Empirical threshold: small repos rarely share >5 tools across both skills
# and workflows without intentional shared infrastructure.  This value may
# become configurable via policy in a future release (v1.9.0+).
_TOOL_COUPLING_THRESHOLD = 5


# Canonical component key.  Shared by ``build_component_graph`` (to build the
# node set and edge sources) and ``analyze_component_health`` (to map an
# orphaned target's referencing component back to its file/line).  Keeping a
# single source of truth prevents the two from drifting apart.
_TYPE_KEY_PREFIX = {
    "skill": "skill",
    "tool": "tool",
    "workflow": "workflow",
    "prompt": "prompt",
    "model_config": "model",
}


def _component_key(comp):
    """Return the stable graph key for a component dict."""
    ctype = comp.get("type", "")
    name = comp.get("name") or comp.get("file", "")
    subtype = comp.get("subtype", "")
    if ctype in _TYPE_KEY_PREFIX:
        return f"{_TYPE_KEY_PREFIX[ctype]}:{name}"
    return f"{subtype or ctype}:{name}"


def _extract_skill_refs(component):
    """Extract tool and prompt references from a skill component."""
    refs = {"tools": [], "prompts": []}
    data = component.get("data") or {}
    for tool in data.get("tools", []):
        if isinstance(tool, str):
            refs["tools"].append(f"tool:{tool}")
        elif isinstance(tool, dict):
            name = tool.get("name") or tool.get("tool") or ""
            if name:
                refs["tools"].append(f"tool:{name}")
    for prompt in data.get("prompts", []):
        if isinstance(prompt, str):
            refs["prompts"].append(f"prompt:{prompt}")
        elif isinstance(prompt, dict):
            name = prompt.get("name") or prompt.get("file") or ""
            if name:
                refs["prompts"].append(f"prompt:{name}")
    return refs


def _extract_workflow_refs(component):
    """Extract tool and MCP references from a workflow component."""
    refs = {"tools": [], "mcp_servers": []}
    data = component.get("data") or {}
    steps = data.get("steps") or data.get("nodes") or []
    for step in steps:
        if not isinstance(step, dict):
            continue
        tool_name = step.get("tool") or step.get("tool_name")
        if tool_name:
            refs["tools"].append(f"tool:{tool_name}")
        server = step.get("mcp_server") or step.get("server")
        if server:
            refs["mcp_servers"].append(f"mcp_server:{server}")
    return refs


def _extract_mcp_refs(component):
    """Extract model references from an MCP component."""
    refs = {"models": []}
    data = component.get("data") or {}
    for model in data.get("models", []):
        if isinstance(model, str):
            refs["models"].append(f"model:{model}")
    return refs


def build_component_graph(components):
    """Build a directed relationship graph from extracted components.

    Returns a dict with:
        - ``edges``: list of ``{"from": key, "to": key, "kind": relation}``
        - ``adjacency``: dict mapping source keys to list of target keys
        - ``reverse_adjacency``: dict mapping target keys to list of source keys
        - ``orphaned_refs``: refs that point to non-existent components
        - ``summary``: counts per relationship kind
    """
    edges = []
    adjacency = defaultdict(list)
    reverse_adjacency = defaultdict(list)

    known_keys = {_component_key(comp) for comp in components}

    for comp in components:
        ctype = comp.get("type", "")
        subtype = comp.get("subtype", "")
        src_key = _component_key(comp)

        if ctype == "skill":
            refs = _extract_skill_refs(comp)
            for tool_key in refs["tools"]:
                edges.append({"from": src_key, "to": tool_key, "kind": "skill_uses_tool"})
                adjacency[src_key].append(tool_key)
                reverse_adjacency[tool_key].append(src_key)
            for prompt_key in refs["prompts"]:
                edges.append({"from": src_key, "to": prompt_key, "kind": "skill_uses_prompt"})
                adjacency[src_key].append(prompt_key)
                reverse_adjacency[prompt_key].append(src_key)

        elif ctype == "workflow":
            refs = _extract_workflow_refs(comp)
            for tool_key in refs["tools"]:
                edges.append({"from": src_key, "to": tool_key, "kind": "workflow_uses_tool"})
                adjacency[src_key].append(tool_key)
                reverse_adjacency[tool_key].append(src_key)
            for mcp_key in refs["mcp_servers"]:
                edges.append({"from": src_key, "to": mcp_key, "kind": "workflow_uses_mcp"})
                adjacency[src_key].append(mcp_key)
                reverse_adjacency[mcp_key].append(src_key)

        elif comp.get("type") in ("mcp_server",) or subtype == "mcp_server":
            refs = _extract_mcp_refs(comp)
            for model_key in refs["models"]:
                edges.append({"from": src_key, "to": model_key, "kind": "mcp_uses_model"})
                adjacency[src_key].append(model_key)
                reverse_adjacency[model_key].append(src_key)

    orphaned = set()
    for edge in edges:
        if edge["to"] not in known_keys:
            orphaned.add(edge["to"])

    kind_counts = defaultdict(int)
    for edge in edges:
        kind_counts[edge["kind"]] += 1

    # Make output deterministic: sort edges, adjacency lists, and summary keys
    edges.sort(key=lambda e: (e["from"], e["to"], e["kind"]))
    sorted_adjacency = {k: sorted(v) for k, v in sorted(adjacency.items())}
    sorted_reverse_adj = {k: sorted(v) for k, v in sorted(reverse_adjacency.items())}
    sorted_summary = dict(sorted({
        "total_edges": len(edges),
        "orphaned_refs": len(orphaned),
        **dict(kind_counts),
    }.items()))

    return {
        "edges": edges,
        "adjacency": sorted_adjacency,
        "reverse_adjacency": sorted_reverse_adj,
        "orphaned_refs": sorted(orphaned),
        "summary": sorted_summary,
    }


def analyze_component_health(components):
    """Analyze component graph health and return findings.

    Returns ``(findings, graph)`` where findings flag orphaned refs
    and unhealthy relationship chains.
    """
    graph = build_component_graph(components)
    # Map each component back to its graph key so an orphaned target's
    # referencing component(s) can supply actionable file/line provenance.
    key_to_comp = {_component_key(c): c for c in components}
    findings = []

    for orphan in graph["orphaned_refs"]:
        sources = graph["reverse_adjacency"].get(orphan, [])
        src_comp = None
        for src_key in sources:
            comp = key_to_comp.get(src_key)
            if comp and (comp.get("path") or comp.get("file")):
                src_comp = comp
                break
        file_loc = (src_comp.get("path") or src_comp.get("file") or "") if src_comp else ""
        line_loc = src_comp.get("line", 0) if src_comp else 0
        ref_label = f" (referenced by {sources[0]})" if sources else ""
        findings.append({
            "rule_id": "COMPONENT_ORPHANED_REF",
            "severity": "medium",
            "message": f"Component references non-existent target: {orphan}{ref_label}",
            "file": file_loc,
            "line": line_loc,
            "owasp_llm": "LLM06",
            "evidence": (orphan + " referenced by " + ", ".join(sources)) if sources else orphan,
            "reason": "A component references a target that does not exist in the scanned codebase.",
            "risk_category": "Integrity",
            "affected_framework": "generic",
            "affected_capability": "Components",
            "score_contribution": 8,
            "remediation": "Remove or update the reference to a valid component.",
        })

    workflow_tools = set()
    for edge in graph["edges"]:
        if edge["kind"] == "workflow_uses_tool":
            workflow_tools.add(edge["to"])
    skill_tools = set()
    for edge in graph["edges"]:
        if edge["kind"] == "skill_uses_tool":
            skill_tools.add(edge["to"])

    tools_used_by_both = workflow_tools & skill_tools
    if len(tools_used_by_both) > _TOOL_COUPLING_THRESHOLD:
        findings.append({
            "rule_id": "COMPONENT_TOOL_COUPLING",
            "severity": "low",
            "message": f"High tool coupling: {len(tools_used_by_both)} tools shared across skills and workflows",
            "file": "",
            "line": 0,
            "owasp_llm": "LLM06",
            "evidence": sorted(tools_used_by_both)[:5],
            "reason": "Many tools are shared across skills and workflows, increasing blast radius of tool vulnerabilities.",
            "risk_category": "Integrity",
            "affected_framework": "generic",
            "affected_capability": "Components",
            "score_contribution": 4,
            "remediation": "Consider reducing shared tool surface or adding capability-based access controls.",
        })

    return findings, graph
