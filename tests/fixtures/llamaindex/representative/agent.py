from llama_index.core import SimpleDirectoryReader, VectorStoreIndex
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool
from llama_index.core.utilities.sql_wrapper import SQLDatabase
from llama_index.llms.openai import OpenAI


def lookup_ticket(ticket_id: str) -> str:
    return f"synthetic ticket {ticket_id}"


documents = SimpleDirectoryReader("./synthetic-docs").load_data()
index = VectorStoreIndex.from_documents(documents)
ticket_tool = FunctionTool(name="lookup_ticket")
model = OpenAI(model="synthetic-model")
database = SQLDatabase("synthetic-connection")
agent = ReActAgent(name="Support agent", tools=[ticket_tool], llm=model)
