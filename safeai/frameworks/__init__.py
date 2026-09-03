"""Framework parser registry and installed parser-plugin loader.

Parsers register themselves here so that ``safeai.engine.scan`` does not
need a hard-coded import list.  To add a new framework adapter, create a
sub-package with a ``parser.py`` that exposes a class with ``detect()``
and ``parse()`` methods, then call ``register_parser`` below.

External plugins may register through the ``safeai.parsers`` Python entry
point group or call ``register_parser`` at import time.
"""

import logging
from importlib import metadata

_PARSER_REGISTRY = []
_PARSER_NAMES = set()
logger = logging.getLogger(__name__)


def register_parser(cls):
    """Register a framework parser class.

    The class must have ``detect(path, content, scan_ctx)`` and
    ``parse(path, content, scan_ctx)`` methods.  Instances are
    created once per scan.
    """
    name = getattr(cls, "name", None)
    if not name or not callable(getattr(cls, "detect", None)) or not callable(getattr(cls, "parse", None)):
        raise TypeError("Parser must define a non-empty name, detect(), and parse()")
    if name not in _PARSER_NAMES:
        _PARSER_REGISTRY.append(cls)
        _PARSER_NAMES.add(name)
    return cls


def _load_external_parsers():
    """Load parser classes exposed by installed ``safeai.parsers`` plugins."""
    try:
        entries = metadata.entry_points()
        if hasattr(entries, "select"):
            entries = entries.select(group="safeai.parsers")
        else:
            entries = entries.get("safeai.parsers", [])
    except Exception as exc:
        logger.debug("Unable to enumerate parser plugins: %s", exc)
        return

    for entry in entries:
        try:
            register_parser(entry.load())
        except Exception as exc:
            logger.warning("Unable to load parser plugin %s: %s", entry.name, exc)


def discover_parsers(include_external=True):
    """Return a list of all registered parser instances."""
    # Ensure all built-in parsers are imported so they register.
    from safeai.frameworks.azure_foundry.parser import AzureFoundryParser  # noqa: F401
    from safeai.frameworks.bedrock_agent.parser import BedrockAgentParser  # noqa: F401
    from safeai.frameworks.claude_code.parser import ClaudeCodeParser  # noqa: F401
    from safeai.frameworks.crewai.parser import CrewAIParser  # noqa: F401
    from safeai.frameworks.cursorrules.parser import CursorRulesParser  # noqa: F401
    from safeai.frameworks.dify.parser import DifyParser  # noqa: F401
    from safeai.frameworks.google_adk.parser import GoogleADKParser  # noqa: F401
    from safeai.frameworks.haystack.parser import HaystackParser  # noqa: F401
    from safeai.frameworks.langchain.parser import LangChainParser  # noqa: F401
    from safeai.frameworks.langgraph.parser import LangGraphParser  # noqa: F401
    from safeai.frameworks.llamaindex.parser import LlamaIndexParser  # noqa: F401
    from safeai.frameworks.mastra.parser import MastraParser  # noqa: F401
    from safeai.frameworks.microsoft_agent.parser import (
        MicrosoftAgentFrameworkParser,  # noqa: F401
    )
    from safeai.frameworks.n8n.parser import N8nParser  # noqa: F401
    from safeai.frameworks.openai_agents.parser import OpenAIAgentsParser  # noqa: F401
    from safeai.frameworks.semantic_kernel.parser import (
        SemanticKernelParser,  # noqa: F401
    )
    from safeai.frameworks.windsurf.parser import WindsurfParser  # noqa: F401
    if include_external:
        _load_external_parsers()
    return [cls() for cls in _PARSER_REGISTRY]
