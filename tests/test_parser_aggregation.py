from safeai.engine.scan import run_scan


def test_multi_framework_single_file_parsing(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "langchain==0.2.0\nsemantic-kernel==1.0.0\nopenai-agents==0.1.0\n"
    )
    (tmp_path / "mixed.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "from semantic_kernel import Kernel\n"
        "from agents import Agent\n"
        "AgentExecutor()\n"
        "Kernel()\n"
        "Agent()\n"
    )

    report = run_scan(str(tmp_path))
    frameworks = set(report.get("detected_frameworks", []))
    assert "langchain" in frameworks
    assert "semantic_kernel" in frameworks
    assert "openai_agents" in frameworks
    assert report.get("unified_models")


def test_all_framework_parsers_exercised_integration(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "langgraph\ncrewai\nlangchain\nsemantic-kernel\nopenai-agents\nazure-ai-agents\n"
    )
    (tmp_path / "graph.py").write_text(
        "from langgraph import Graph\n"
        "from crewai import Agent, Task\n"
        "g = Graph()\n"
        "Agent(role='x')\n"
        "Task(description='y')\n"
    )
    (tmp_path / "chain.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "from semantic_kernel import Kernel\n"
        "from agents import Agent\n"
        "from azure.ai.agents import AgentClient\n"
        "AgentExecutor()\nKernel()\nAgent()\nAgentClient()\n"
    )
    (tmp_path / "foundry.yaml").write_text("azure: true\nname: app\ntools: []\n")

    report = run_scan(str(tmp_path))
    frameworks = set(report.get("detected_frameworks", []))
    expected = {
        "langgraph",
        "crewai",
        "langchain",
        "semantic_kernel",
        "openai_agents",
        "microsoft_agent_framework",
        "azure_foundry",
    }
    assert expected.issubset(frameworks)
