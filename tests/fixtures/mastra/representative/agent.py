from mastra import Agent, Tool, Workflow
from mastra.models import OpenAI
from mastra.tools import createTool

search_tool = Tool(name="web_search")
email_tool = createTool(name="send_email")
workflow = Workflow(name="support_triage")
model = OpenAI(model="synthetic-model")
agent = Agent(name="triage_agent", tools=[search_tool, email_tool], model=model)
