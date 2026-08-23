import json
import os

from safeai.engine.scan import run_scan

FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "n8n", "representative"
)


def test_representative_n8n_workflow_is_detected_and_parsed():
    report = run_scan(FIXTURE)

    assert "n8n" in report["detected_frameworks"]
    model = next(
        model
        for model in report["unified_models"]
        if "n8n" in model.get("frameworks", [])
    )
    artifacts = model["artifacts"]
    assert [workflow["name"] for workflow in artifacts["workflows"]] == [
        "Support triage"
    ]
    assert {tool["name"] for tool in artifacts["tools"]} == {
        "Incoming webhook",
        "Classify request",
        "Load ticket context",
        "Run local check",
    }
    assert "synthetic-model" in {
        model_entry["name"] for model_entry in artifacts["models"]
    }
    assert len(model["relationships"]) == 3

    capability_names = {
        capability["name"] for capability in model["capabilities"]
    }
    assert {"external_apis", "databases", "shell", "external_model_api"}.issubset(
        capability_names
    )


def test_representative_n8n_fixture_has_no_credential_values_or_private_endpoints():
    workflow_path = os.path.join(FIXTURE, "workflow.json")
    with open(workflow_path, encoding="utf-8") as f:
        workflow_text = f.read()
    workflow = json.loads(workflow_text)

    assert "credential" in workflow_text
    assert "postgres-placeholder" in workflow_text
    assert "password" not in workflow_text.lower()
    assert "token" not in workflow_text.lower()
    assert all(
        node.get("parameters", {}).get("url", "").startswith("https://example.invalid")
        for node in workflow["nodes"]
        if "url" in node.get("parameters", {})
    )
