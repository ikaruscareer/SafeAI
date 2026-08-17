import os

from safeai.engine.scan import run_scan

FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "crewai", "representative"
)


def test_representative_crewai_project_is_detected_and_parsed():
    report = run_scan(FIXTURE)

    assert "crewai" in report["detected_frameworks"]
    model = next(
        model
        for model in report["unified_models"]
        if "crewai" in model.get("frameworks", [])
    )
    artifacts = model["artifacts"]

    assert any("Agent" in agent["name"] for agent in artifacts["agents"])
    assert any("Task" in task["name"] for task in artifacts["workflows"])
    assert any(tool["name"] == "Tool" for tool in artifacts["tools"])
    assert any("Memory" in memory["name"] for memory in artifacts["memory"])
    assert any("LLM" in model_entry["name"] for model_entry in artifacts["models"])

    capability_names = {
        capability["name"] for capability in model["capabilities"]
    }
    assert {"memory", "external_model_api"}.issubset(capability_names)
