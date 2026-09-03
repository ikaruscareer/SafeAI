from crewai import Agent, Crew, Task
from crewai.tools import Tool


def process():
    return {"data": "value"}


def search(query):
    return [{"result": query}]


def fetch_data():
    """Simulate an unbounded loop without max_iterations."""
    while True:
        data = process()
        if data is None:
            import time
            time.sleep(1)
            continue
        return data


def recursive_search(query, depth=0):
    """Recursive tool call without depth guard."""
    results = search(query)
    if not results:
        return recursive_search(query, depth + 1)
    return results


fetch_tool = Tool(name="fetch_data", func=fetch_data)
search_tool = Tool(name="recursive_search", func=recursive_search)

agent = Agent(
    role="Data collector",
    goal="Fetch and search data",
    tools=[fetch_tool, search_tool],
)
task = Task(description="Collect data", agent=agent)
crew = Crew(agents=[agent], tasks=[task])
