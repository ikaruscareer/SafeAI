from haystack import Pipeline
from haystack.components.generators import OpenAIGenerator
from haystack.tools import Tool

generator = OpenAIGenerator(model="synthetic-model")
search_tool = Tool(name="web_search")
pipeline = Pipeline(name="support_triage")
