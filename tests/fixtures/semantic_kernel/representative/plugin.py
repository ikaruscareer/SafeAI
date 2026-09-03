import semantic_kernel as sk
from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion
from semantic_kernel.functions import kernel_function

kernel = sk.Kernel()
kernel.add_service(OpenAIChatCompletion(service_id="chat", ai_model_id="gpt-4o"))


@kernel_function(description="Summarize text")
def summarize(text: str) -> str:
    return f"Summary of: {text}"


kernel.add_plugin(summarize, "text_tools")
