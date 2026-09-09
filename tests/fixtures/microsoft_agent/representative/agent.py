from azure.ai.agents import AgentClient
from azure.ai.agents.models import FunctionTool

client = AgentClient(azure_endpoint="https://synthetic.openai.azure.com/")
search_tool = FunctionTool(name="web_search")
agent = client.create_agent(
    name="triage_agent",
    model="gpt-4",
    tools=[search_tool],
    instructions="You are a support triage agent.",
)
result = client.run(agent.id, input="classify this request")
