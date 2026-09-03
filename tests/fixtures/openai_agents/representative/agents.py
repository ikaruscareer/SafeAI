from agents import Agent, Runner

planner = Agent(
    name="planner",
    instructions="Break tasks into steps.",
    model="gpt-4o",
)

coder = Agent(
    name="coder",
    instructions="Write code to implement each step.",
    model="gpt-4o",
    tools=[],
)

runner = Runner(agents=[planner, coder])
