import os

from safeai.engine.scan import run_scan

FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "llamaindex", "representative"
)


def test_representative_llamaindex_project_is_detected_and_parsed():
    report = run_scan(FIXTURE)

    assert "llamaindex" in report["detected_frameworks"]
    model = next(
        model
        for model in report["unified_models"]
        if "llamaindex" in model.get("frameworks", [])
    )
    artifacts = model["artifacts"]

    assert "Support agent" in {agent["name"] for agent in artifacts["agents"]}
    assert "lookup_ticket" in {tool["name"] for tool in artifacts["tools"]}
    assert "synthetic-model" in {
        model_entry["name"] for model_entry in artifacts["models"]
    }

    capability_names = {
        capability["name"] for capability in model["capabilities"]
    }
    assert {"rag", "external_model_api", "databases"}.issubset(capability_names)
