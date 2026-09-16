"""Analyzer registry and installed analyzer-plugin loader.

Analyzers register themselves here so that ``safeai.engine.orchestrator``
does not need a hard-coded class list.  Built-in analyzers self-register
with a ``phase`` of ``"core"`` (run over file sources) or ``"component"``
(run over extracted components); the orchestrator preserves that order.

External plugins may register through the ``safeai.analyzers`` Python
entry point group or call ``register_analyzer`` at import time.  External
analyzers run after built-ins in the component phase, must accept
``components=None``, and never fail a scan: a raising external analyzer
is skipped with a warning (see orchestrator isolation).
"""

import inspect
import logging
from importlib import import_module, metadata

logger = logging.getLogger(__name__)

CORE = "core"
COMPONENT = "component"
_PHASES = (CORE, COMPONENT)

# Each entry: {"name", "cls", "phase", "external", "version"}.
# ``version`` is the installed distribution version for entry-point
# plugins, else None (resolved to the SafeAI version at record time).
_ANALYZER_REGISTRY = []
_ANALYZER_NAMES = set()


def register_analyzer(cls=None, *, phase=CORE, external=False, version=None):
    """Register an analyzer class.

    Usable bare (``@register_analyzer``) for core analyzers or with
    keywords (``@register_analyzer(phase="component")``).

    The class must define a non-empty ``name`` and a ``run()`` method.
    Component-phase analyzers must accept ``components=None``.
    """

    def _register(target):
        name = getattr(target, "name", None)
        run = getattr(target, "run", None)
        if not name or not callable(run):
            raise TypeError("Analyzer must define a non-empty name and run()")
        if phase not in _PHASES:
            raise ValueError(f"Analyzer phase must be one of {_PHASES}, got {phase!r}")
        if phase == COMPONENT:
            try:
                params = inspect.signature(run).parameters
            except (TypeError, ValueError):
                params = {}
            accepts_components = (
                "components" in params
                or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
            )
            if not accepts_components:
                raise TypeError(
                    f"Component-phase analyzer {name!r} must accept components=None"
                )
        if name not in _ANALYZER_NAMES:
            _ANALYZER_REGISTRY.append(
                {
                    "name": name,
                    "cls": target,
                    "phase": phase,
                    "external": external,
                    "version": version,
                }
            )
            _ANALYZER_NAMES.add(name)
        return target

    if cls is None:
        return _register
    return _register(cls)


def _load_external_analyzers():
    """Load analyzer classes exposed by installed ``safeai.analyzers`` plugins."""
    try:
        entries = metadata.entry_points()
        if hasattr(entries, "select"):
            entries = entries.select(group="safeai.analyzers")
        else:
            entries = entries.get("safeai.analyzers", [])
    except Exception as exc:
        logger.debug("Unable to enumerate analyzer plugins: %s", exc)
        return

    for entry in entries:
        try:
            dist_version = getattr(entry.dist, "version", None) if hasattr(entry, "dist") else None
            register_analyzer(
                entry.load(), phase=COMPONENT, external=True, version=dist_version
            )
        except Exception as exc:
            logger.warning("Unable to load analyzer plugin %s: %s", entry.name, exc)


# Built-in analyzers as (module, class, phase) in legacy run order.
# The table (not import order) is the source of truth for run order, so
# ``_import_builtin_analyzers`` is idempotent and order-canonical no
# matter which modules were already imported.
_BUILTIN_ANALYZERS = (
    ("safeai.analyzers.capability.analyzer", "CapabilityAnalyzer", CORE),
    ("safeai.analyzers.prompt.analyzer", "PromptAnalyzer", CORE),
    ("safeai.analyzers.data_leakage.analyzer", "DataLeakageAnalyzer", CORE),
    ("safeai.analyzers.env_dependency.analyzer", "EnvDependencyAnalyzer", CORE),
    ("safeai.analyzers.mcp.analyzer", "MCPAnalyzer", CORE),
    ("safeai.analyzers.claude_code.analyzer", "ClaudeCodeAnalyzer", CORE),
    ("safeai.analyzers.skill.analyzer", "SkillAnalyzer", COMPONENT),
    ("safeai.analyzers.prompt_file.analyzer", "PromptFileAnalyzer", COMPONENT),
    ("safeai.analyzers.tool_def.analyzer", "ToolDefAnalyzer", COMPONENT),
    ("safeai.analyzers.model_config.analyzer", "ModelConfigAnalyzer", COMPONENT),
    ("safeai.analyzers.workflow.analyzer", "WorkflowAnalyzer", COMPONENT),
    ("safeai.analyzers.governance.analyzer", "GovernanceAnalyzer", COMPONENT),
    ("safeai.analyzers.dataflow.analyzer", "DataFlowAnalyzer", COMPONENT),
)


def _import_builtin_analyzers():
    """Register built-in analyzers in legacy run order (idempotent)."""
    for module_name, class_name, phase in _BUILTIN_ANALYZERS:
        module = import_module(module_name)
        register_analyzer(getattr(module, class_name), phase=phase)


def discover_analyzers(phase=None, include_external=True):
    """Return registered analyzer instances, built-ins first, in run order.

    Parameters
    ----------
    phase : str, optional
        ``"core"`` or ``"component"`` to filter; None returns all in phase
        order (core first, then component).
    """
    _import_builtin_analyzers()
    if include_external:
        _load_external_analyzers()
    entries = list(_ANALYZER_REGISTRY)
    if phase is not None:
        entries = [e for e in entries if e["phase"] == phase]
    else:
        entries = sorted(entries, key=lambda e: (e["phase"] != CORE,))
    instances = []
    for entry in entries:
        instance = entry["cls"]()
        # Marker consumed by the orchestrator for plugin isolation.
        instance._safeai_external = entry["external"]
        instances.append(instance)
    return instances


def analyzer_records(include_external=True):
    """Return registry metadata (name/phase/external/version) for recording."""
    _import_builtin_analyzers()
    if include_external:
        _load_external_analyzers()
    return [
        {
            "name": e["name"],
            "phase": e["phase"],
            "external": e["external"],
            "version": e["version"],
        }
        for e in _ANALYZER_REGISTRY
    ]
