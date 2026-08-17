from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode


def classify(state):
    return {"label": "synthetic"}


def answer(state):
    return {"answer": "synthetic response"}


graph = StateGraph(dict)
graph.add_node("classify", classify)
graph.add_node("answer", answer)
graph.add_edge("classify", "answer")
graph.add_edge("answer", END)
model = ChatOpenAI(model="synthetic-model")
checkpoint = MemorySaver()
tool_node = ToolNode([])
compiled = graph.compile(checkpointer=checkpoint)
