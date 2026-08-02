"""Main scan orchestration engine for SafeAI.

This module drives the entire pipeline:
  1. File collection (Python, YAML, JSON, dependency manifests)
  2. Dependency extraction
  3. Semantic document building (AST parsing)
  4. Import graph construction
  5. Framework parsing (all parsers, all files, no mutual exclusion)
  6. Parser result aggregation & deduplication
  7. Multi-analyser pipeline (capability, prompt, data leakage, MCP)
  8. Project graph & trust score computation
  9. Report assembly
"""

import logging
import os

from safeai.analysis.aggregation import aggregate_capabilities, aggregate_parser_models
from safeai.analysis.components import extract_components
from safeai.analysis.import_graph import build_import_graph, module_name_from_path
from safeai.analysis.project_graph import build_project_graph
from safeai.analysis.semantic import build_semantic_document
from safeai.analysis.tool_surface import build_tool_surface
from safeai.analyzers.capability.analyzer import CapabilityAnalyzer
from safeai.analyzers.claude_code.analyzer import ClaudeCodeAnalyzer
from safeai.analyzers.data_leakage.analyzer import DataLeakageAnalyzer
from safeai.analyzers.mcp.analyzer import MCPAnalyzer
from safeai.analyzers.prompt.analyzer import PromptAnalyzer
from safeai.frameworks import discover_parsers
from safeai.kya.assurance import build_assurance_boundary
from safeai.rules.loader import load_rules
from safeai.scoring.engine import score_report

logger = logging.getLogger("safeai")

# Directories that are never scanned (version control, dependency caches,
# virtual environments, build outputs, SafeAI's own local state).
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules",
    "__pycache__",
    ".venv", "venv", "env",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    "dist", "build", ".eggs",
    ".idea", ".vscode",
    ".safeai",
}

# SafeAI's own canonical artifacts are never re-scanned: scanning a
# previously generated manifest would create a findings feedback loop.
_EXCLUDED_FILES = {"safeai-manifest.json"}

# Files larger than this are skipped to avoid excessive memory use.
MAX_FILE_BYTES = 2 * 1024 * 1024


def _is_scannable_file(filename):
    """Return whether a file is source, configuration, or AI instructions."""
    lower = filename.lower()
    if lower in _EXCLUDED_FILES:
        return False
    if lower.endswith((".py", ".json", ".yaml", ".yml", ".prompt")):
        return True
    return lower in {"claude.md", "prompt.md", "system_prompt.md"} or lower.endswith((".prompt.md", ".prompt.txt"))


#: Additional extensions read inside a ``.claude/`` directory. Claude Code
#: keeps real agent authority in markdown (slash commands, subagents) and
#: shell hooks, which the generic source allowlist above does not cover.
_CLAUDE_CONFIG_EXTS = (".md", ".markdown", ".sh", ".bash", ".toml")


def _is_claude_config_file(full_path):
    """True for Claude Code configuration inside the scanned repository.

    Only paths under a repository-local ``.claude/`` directory qualify.
    User-level configuration is never reached: this predicate is applied
    to files already discovered by walking the scan root.
    """
    normalized = str(full_path).replace("\\", "/")
    if "/.claude/" not in normalized:
        return False
    return normalized.lower().endswith(_CLAUDE_CONFIG_EXTS)


def _is_own_manifest(path):
    """Return True when a JSON file is a SafeAI-generated artifact.

    Scanning a previously generated manifest or JSON report would create
    a findings feedback loop, so files declaring ``safeai.kya`` or
    ``safeai.scan`` type markers are skipped regardless of filename.
    """
    if not path.lower().endswith(".json"):
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return False
    return ('"manifest_type"' in content and '"safeai.kya"' in content) or (
        '"report_type"' in content and '"safeai.scan"' in content
    )


def collect_files(root, skipped=None):
    """Collect scannable files, pruning excluded directories and oversized files.

    ``skipped`` is an optional dict that accumulates ``reason -> count`` for
    files the walk declined to read. It feeds the assurance boundary, which
    has to state honestly what the scan did not look at. Passing nothing
    keeps the historical single-return behaviour.
    """
    files = []
    counters = skipped if skipped is not None else {}

    def note(reason):
        counters[reason] = counters.get(reason, 0) + 1

    for d, dirs, fs in os.walk(root):
        dirs[:] = [name for name in dirs if name not in EXCLUDED_DIRS]
        for f in fs:
            full = os.path.join(d, f)
            # SafeAI's own artifacts are not part of the project's attack
            # surface, so they are skipped silently. Counting them would
            # make coverage notes depend on whether a previous scan wrote
            # its output into the scanned directory.
            if f.lower() in _EXCLUDED_FILES or _is_own_manifest(full):
                continue
            if not (_is_scannable_file(f) or _is_claude_config_file(full)):
                extension = os.path.splitext(f)[1].lower() or "(no extension)"
                note(f"unsupported file type {extension}")
                continue
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    logger.debug("Skipping oversized file: %s", full)
                    note("larger than the 2 MiB read limit")
                    continue
            except OSError:
                note("unreadable")
                continue
            files.append(full)
    return files


def collect_dependency_files(root):
    files = []
    for filename in ["requirements.txt", "pyproject.toml", "Pipfile", "package.json"]:
        path = os.path.join(root, filename)
        if os.path.exists(path):
            files.append(path)
    return files


def extract_dependencies(paths):
    """Parse dependency manifests into a set of package names.

    Handles requirements.txt, Pipfile, pyproject.toml, and package.json.
    For structured manifests only known AI framework tokens are extracted.
    """
    deps = set()
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            continue

        low = content.lower()
        if path.endswith(("requirements.txt", "Pipfile")):
            for line in content.splitlines():
                raw = line.strip().split("#", 1)[0]
                if not raw:
                    continue
                name = raw.split("==", 1)[0].split(">=", 1)[0].split("<=", 1)[0].strip().lower()
                if name:
                    deps.add(name)
        elif path.endswith("pyproject.toml"):
            for token in [
                "langgraph",
                "crewai",
                "langchain",
                "semantic-kernel",
                "openai-agents",
                "azure-ai-agents",
                "azure-ai-projects",
                "google-adk",
                "haystack-ai",
                "llama-index",
                "mastra",
                "dify",
                "n8n",
            ]:
                if token in low:
                    deps.add(token)
        elif path.endswith("package.json"):
            for token in [
                "langchain", "openai", "@azure/ai-projects", "@microsoft/agents",
                "@mastra/core", "n8n",
            ]:
                if token in low:
                    deps.add(token)
    return deps


def _relativize(path, root):
    """Convert an absolute path to a root-relative, forward-slash path.

    Paths outside the scan root and sentinel values (e.g. ``<scan>``)
    are returned unchanged. Relative paths keep report output portable
    and allow GitHub code scanning to map SARIF results to files.
    """
    if not path or path.startswith("<"):
        return path
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return path
    if rel.startswith(".."):
        return path
    return rel.replace("\\", "/")


def run_scan(directory, rules_dir=None, baseline_report=None):
    directory = os.path.abspath(directory)
    skipped_files = {}
    files = collect_files(directory, skipped=skipped_files)
    logger.info("Collected %d scannable files in %s", len(files), directory)
    rules = load_rules(rules_dir)
    deps = extract_dependencies(collect_dependency_files(directory))

    parsers = discover_parsers()

    agent_models = []
    findings = []
    file_cache = {}
    module_by_file = {}
    semantic_docs = {}

    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as exc:
            logger.debug("Failed to read %s: %s", path, exc)
            continue

        file_cache[path] = content
        if path.endswith(".py"):
            module_name = module_name_from_path(directory, path)
            module_by_file[path] = module_name
            semantic_docs[path] = build_semantic_document(path, content, module_name=module_name)

    import_graph = build_import_graph(directory, files, semantic_docs)
    scan_ctx = {
        "root": directory,
        "files": files,
        "file_cache": file_cache,
        "dependencies": deps,
        "module_by_file": module_by_file,
        "semantic_docs": semantic_docs,
        "import_graph": import_graph,
    }

    detected_frameworks = []
    framework_methods = {}
    parser_results_by_file = {}
    parse_provenance = []

    for path in files:
        content = file_cache.get(path, "")
        for parser in parsers:
            if parser.detect(path, content, scan_ctx=scan_ctx):
                parsed = parser.parse(path, content, scan_ctx=scan_ctx)
                framework = parsed.get("framework")
                if not framework:
                    continue
                agent_models.append({
                    "file": path,
                    "framework": framework,
                    "data": parsed,
                })
                parser_results_by_file.setdefault(path, []).append(parsed)
                parse_provenance.append({
                    "file": path,
                    "framework": framework,
                    "confidence": parsed.get("parser_confidence", 0.65),
                    "source": parsed.get("discovery_method", "regex"),
                    "evidence": parsed.get("detection_evidence", []),
                })
                if framework and framework not in detected_frameworks:
                    detected_frameworks.append(framework)
                framework_methods.setdefault(framework, set()).add(parsed.get("discovery_method", "regex"))

    # --- Phase 1.5: component-level extraction ---
    diagnostics = []
    components = extract_components(files, file_cache, semantic_docs, diagnostics=diagnostics)
    logger.info("Extracted %d AI components", len(components))

    unified_models = aggregate_parser_models(parser_results_by_file)
    logger.info("Detected frameworks: %s", ", ".join(detected_frameworks) or "none")

    capabilities = []
    for model in agent_models:
        capabilities.extend(model.get("data", {}).get("capabilities") or [])
    normalized_capabilities = aggregate_capabilities(capabilities)

    analyzers = [
        CapabilityAnalyzer(),
        PromptAnalyzer(),
        DataLeakageAnalyzer(),
        MCPAnalyzer(),
        ClaudeCodeAnalyzer(),
    ]
    for analyzer in analyzers:
        findings.extend(analyzer.run(file_cache, rules, agent_models))

    # --- Phase 1.5: component-level analyzers ---
    from safeai.analyzers.model_config.analyzer import ModelConfigAnalyzer
    from safeai.analyzers.prompt_file.analyzer import PromptFileAnalyzer
    from safeai.analyzers.skill.analyzer import SkillAnalyzer
    from safeai.analyzers.tool_def.analyzer import ToolDefAnalyzer
    from safeai.analyzers.workflow.analyzer import WorkflowAnalyzer

    component_analyzers = [
        SkillAnalyzer(),
        PromptFileAnalyzer(),
        ToolDefAnalyzer(),
        ModelConfigAnalyzer(),
        WorkflowAnalyzer(),
    ]
    for analyzer in component_analyzers:
        findings.extend(analyzer.run(file_cache, rules, agent_models, components=components))
    logger.info("Analysis produced %d findings", len(findings))

    mcp_assets = []
    mcp_capabilities = []
    for finding in findings:
        if finding.get("rule_id") == "MCP_ASSETS_DISCOVERED":
            mcp_assets.extend(finding.get("mcp_assets") or [])
            mcp_capabilities.extend(finding.get("mcp_capabilities") or [])

    counts = {k: 0 for k in ["critical", "high", "medium", "low", "info"]}
    for finding in findings:
        sev = finding.get("severity", "medium")
        if sev not in counts:
            counts[sev] = 0
        counts[sev] += 1

    trust_score = score_report(findings)

    # Normalize all paths in the report to be relative to the scanned root so
    # that reports are portable and SARIF consumers (e.g. GitHub code scanning)
    # can map results back to repository files.
    for finding in findings:
        finding["file"] = _relativize(finding.get("file"), directory)
    for model in agent_models:
        model["file"] = _relativize(model.get("file"), directory)
    for entry in parse_provenance:
        entry["file"] = _relativize(entry.get("file"), directory)
    for asset in mcp_assets:
        asset["file"] = _relativize(asset.get("file"), directory)
    for model in unified_models:
        model["file"] = _relativize(model.get("file"), directory)
    for component in components:
        component["file"] = _relativize(component.get("file"), directory)
    for diagnostic in diagnostics:
        diagnostic["file"] = _relativize(diagnostic.get("file"), directory)
    project_graph = build_project_graph(agent_models, mcp_assets=mcp_assets, components=components)

    report = {
        "report_type": "safeai.scan",
        "findings": findings,
        "counts": counts,
        "files_scanned": len(files),
        "agent_models": agent_models,
        "detected_frameworks": detected_frameworks,
        "framework_discovery_methods": {k: sorted(v) for k, v in framework_methods.items()},
        "parser_provenance": parse_provenance,
        "unified_models": unified_models,
        "normalized_capabilities": normalized_capabilities,
        "dependencies": sorted(deps),
        "import_graph": {
            "modules": import_graph.module_to_file,
            "edges": {k: sorted(v) for k, v in import_graph.edges.items()},
        },
        "project_graph": project_graph,
        "mcp_assets": mcp_assets,
        "mcp_capabilities": mcp_capabilities,
        "components": components,
        "diagnostics": diagnostics,
        "skipped_files": dict(sorted(skipped_files.items())),
        "trust_score": trust_score,
    }
    # Per-tool capability surface (v1.4): the unit the diff compares and the
    # registry persists. Built from report data only — no extra file access.
    report["tool_surface"] = build_tool_surface(report)
    # Assurance boundary (v1.4): what this scan did and did not verify.
    # Derived from the run itself, never a fixed disclaimer string.
    report["assurance_boundary"] = build_assurance_boundary(report)
    if baseline_report is not None:
        from safeai.analysis.capability_diff import compute_capability_diff

        report["capability_diff"] = compute_capability_diff(report, baseline_report)
    return report
