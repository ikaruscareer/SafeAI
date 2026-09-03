from google.adk import Agent
from google.adk.tools import FunctionTool

web_search_tool = FunctionTool(func=lambda q: f"results for {q}")


def send_email(to: str, subject: str, body: str) -> str:
    return f"Sent to {to}"


email_tool = FunctionTool(func=send_email)

root_agent = Agent(
    name="research_agent",
    model="gemini-2.0-flash",
    description="Research assistant that searches the web and sends email summaries.",
    tools=[web_search_tool, email_tool],
    instruction="You are a helpful research assistant.",
)
