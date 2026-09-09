from langchain.agents import initialize_agent
from langchain.memory import ConversationBufferMemory
from langchain.tools import Tool
from langchain_openai import ChatOpenAI

memory = ConversationBufferMemory()
model = ChatOpenAI(model="synthetic-model")
search_tool = Tool(name="web_search", func=lambda x: "results", description="Search the web")
agent = initialize_agent([search_tool], model, agent="react-description", memory=memory)
