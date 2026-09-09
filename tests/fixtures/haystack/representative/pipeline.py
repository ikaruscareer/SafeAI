from haystack import Pipeline
from haystack.tools import Tool
from haystack.components.generators import OpenAIGenerator

generator = OpenAIGenerator(model="synthetic-model")
search_tool = Tool(name="web_search")
pipeline = Pipeline(name="support_triage")
