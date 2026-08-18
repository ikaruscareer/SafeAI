from crewai import LLM, Agent, Crew, Task
from crewai.memory import Memory
from crewai.tools import Tool

lookup_ticket = Tool(name="lookup_ticket")

model = LLM(model="synthetic-model")
crew_memory = Memory()
triage_agent = Agent(
    role="Support triage",
    goal="Classify synthetic support requests",
    tools=[lookup_ticket],
    llm=model,
)
triage_task = Task(
    description="Classify the incoming synthetic request",
    expected_output="A category",
    agent=triage_agent,
)
crew = Crew(agents=[triage_agent], tasks=[triage_task], memory=crew_memory)
