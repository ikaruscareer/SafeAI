from safeai.engine.scan import run_scan


def test_scan_detects_frameworks_and_trust_score(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "langchain==0.2.0\nsemantic-kernel==1.0.0\nopenai-agents==0.1.0\n"
    )
    (tmp_path / "app.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "from semantic_kernel import Kernel\n"
        "from openai import OpenAI\n"
        "import subprocess\n"
        "AgentExecutor()\n"
        "Kernel()\n"
        "subprocess.run('ls')\n"
    )
    (tmp_path / "mcp.json").write_text(
        '{"mcp": {"servers": [], "tools": ["exec"], "resources": [], "transports": ["http"], "endpoints": ["http://0.0.0.0:8080"]}}'
    )

    report = run_scan(str(tmp_path))

    assert report["files_scanned"] >= 2
    assert "langchain" in report["detected_frameworks"]
    assert "trust_score" in report
    assert "overall_ai_risk_score" in report["trust_score"]
    assert isinstance(report.get("mcp_assets"), list)


def test_project_graph_contains_capabilities(tmp_path):
    (tmp_path / "flow.py").write_text(
        "from langgraph import Graph\n"
        "import subprocess\n"
        "\n"
        "def node_a(state):\n"
        "    return state\n"
        "\n"
        "g = Graph()\n"
        "g.add_node(node_a)\n"
        "subprocess.run('ls')\n"
    )
    report = run_scan(str(tmp_path))
    assert "project_graph" in report
    assert "capabilities" in report["project_graph"]
