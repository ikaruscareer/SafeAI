import os

from safeai.engine.scan import run_scan

FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "langgraph", "representative"
)


def test_representative_langgraph_project_is_detected_and_parsed():
    report = run_scan(FIXTURE)

    assert "langgraph" in report["detected_frameworks"]
    model = next(
        model
        for model in report["unified_models"]
        if "langgraph" in model.get("frameworks", [])
    )
    artifacts = model["artifacts"]

    assert any("graph.add_edge" in workflow["name"] for workflow in artifacts["workflows"])
    assert any("ToolNode" in tool["name"] for tool in artifacts["tools"])
    assert any(
        memory["name"] == "MemorySaver"
        and "langgraph" in memory["frameworks"]
        for memory in artifacts["memory"]
    )

    capability_names = {
        capability["name"] for capability in model["capabilities"]
    }
    assert "memory" in capability_names
