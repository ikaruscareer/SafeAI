from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, initialize_agent
from langchain.tools import Tool
from langchain.memory import ConversationBufferMemory

memory = ConversationBufferMemory()
model = ChatOpenAI(model="synthetic-model")
search_tool = Tool(name="web_search", func=lambda x: "results", description="Search the web")
agent = initialize_agent([search_tool], model, agent="react-description", memory=memory)
