"""Cross-file entity aggregation for the project-level view.

Builds a project graph that summarizes all frameworks, agents,
workflows, tools, prompts, memory components, capabilities, MCP
assets, and external services discovered across every scanned file.
"""


def build_project_graph(agent_models, mcp_assets=None):
    graph = {
        "projects": 1,
        "frameworks": {},
        "agents": [],
        "workflows": [],
        "tools": [],
        "prompts": [],
        "memory": [],
        "capabilities": [],
        "mcp_assets": mcp_assets or [],
        "external_services": [],
    }

    for model in agent_models:
        fw = model.get("framework") or model.get("data", {}).get("framework")
        if not fw:
            continue
        graph["frameworks"][fw] = graph["frameworks"].get(fw, 0) + 1
        data = model.get("data", {})

        for k, target in [
            ("agents", "agents"),
            ("nodes", "workflows"),
            ("tasks", "workflows"),
            ("tools", "tools"),
            ("prompts", "prompts"),
            ("memory", "memory"),
            ("capabilities", "capabilities"),
            ("external_services", "external_services"),
        ]:
            values = data.get(k) or []
            if isinstance(values, list):
                graph[target].extend(values)
            elif values:
                graph[target].append(values)

    return graph
