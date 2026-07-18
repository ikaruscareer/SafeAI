"""Canonical capability categories and convenience builders.

Capabilities represent what an AI agent can *do* (shell execution,
filesystem access, database queries, memory, etc.). These categories
are used by all framework parsers and the capability analyzer to
produce a consistent risk picture.
"""

CAPABILITY_CATEGORIES = {
    "filesystem": "Filesystem",
    "shell": "Shell",
    "browser": "Browser",
    "planner": "Planner",
    "delegation": "Delegation",
    "memory": "Memory",
    "rag": "RAG",
    "github": "GitHub",
    "slack": "Slack",
    "email": "Email",
    "databases": "Databases",
    "cloud": "Cloud",
    "external_apis": "External APIs",
    "mcp": "MCP",
    "human_approval": "Human Approval",
    "multi_agent": "Multi-Agent",
}


def make_capability(name, category, framework, evidence, confidence=0.7, risk_weight=1.0, source="ast", resolved_definition=None):
    """Create a standardized capability dict consumed by the aggregation pipeline."""
    return {
        "name": name,
        "category": category,
        "source_framework": framework,
        "evidence": evidence,
        "confidence": confidence,
        "risk_weight": risk_weight,
        "source": source,
        "resolved_definition": resolved_definition,
    }


def dedupe_capabilities(caps):
    """Remove duplicate capabilities within a single parser result by (name, category, framework, definition)."""
    out = []
    seen = set()
    for c in caps:
        key = (c.get("name"), c.get("category"), c.get("source_framework"), c.get("resolved_definition"))
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out
