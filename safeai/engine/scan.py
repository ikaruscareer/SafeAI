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
from safeai.analysis.import_graph import build_import_graph, module_name_from_path
from safeai.analysis.project_graph import build_project_graph
from safeai.analysis.semantic import build_semantic_document
from safeai.analyzers.capability.analyzer import CapabilityAnalyzer
from safeai.analyzers.data_leakage.analyzer import DataLeakageAnalyzer
from safeai.analyzers.mcp.analyzer import MCPAnalyzer
from safeai.analyzers.prompt.analyzer import PromptAnalyzer
from safeai.frameworks.azure_foundry.parser import AzureFoundryParser
from safeai.frameworks.bedrock_agent.parser import BedrockAgentParser
from safeai.frameworks.crewai.parser import CrewAIParser
from safeai.frameworks.langchain.parser import LangChainParser
from safeai.frameworks.langgraph.parser import LangGraphParser
from safeai.frameworks.microsoft_agent.parser import MicrosoftAgentFrameworkParser
from safeai.frameworks.openai_agents.parser import OpenAIAgentsParser
from safeai.frameworks.semantic_kernel.parser import SemanticKernelParser
from safeai.rules.loader import load_rules
from safeai.scoring.engine import score_report

logger = logging.getLogger("safeai")

# Directories that are never scanned (version control, dependency caches,
# virtual environments, build outputs).
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules",
    "__pycache__",
    ".venv", "venv", "env",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    "dist", "build", ".eggs",
    ".idea", ".vscode",
}

# Files larger than this are skipped to avoid excessive memory use.
MAX_FILE_BYTES = 2 * 1024 * 1024


def collect_files(root):
    """Collect scannable files, pruning excluded directories and oversized files."""
    files = []
    for d, dirs, fs in os.walk(root):
        dirs[:] = [name for name in dirs if name not in EXCLUDED_DIRS]
        for f in fs:
            if not f.endswith((".py", ".json", ".yaml", ".yml")):
                continue
            full = os.path.join(d, f)
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    logger.debug("Skipping oversized file: %s", full)
                    continue
            except OSError:
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
            ]:
                if token in low:
                    deps.add(token)
        elif path.endswith("package.json"):
            for token in ["langchain", "openai", "@azure/ai-projects", "@microsoft/agents"]:
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


def run_scan(directory, rules_dir=None):
    directory = os.path.abspath(directory)
    files = collect_files(directory)
    logger.info("Collected %d scannable files in %s", len(files), directory)
    rules = load_rules(rules_dir)
    deps = extract_dependencies(collect_dependency_files(directory))

    parsers = [
        LangGraphParser(),
        CrewAIParser(),
        LangChainParser(),
        SemanticKernelParser(),
        OpenAIAgentsParser(),
        MicrosoftAgentFrameworkParser(),
        BedrockAgentParser(),
        AzureFoundryParser(),
    ]

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

    unified_models = aggregate_parser_models(parser_results_by_file)
    logger.info("Detected frameworks: %s", ", ".join(detected_frameworks) or "none")

    capabilities = []
    for model in agent_models:
        capabilities.extend(model.get("data", {}).get("capabilities") or [])
    normalized_capabilities = aggregate_capabilities(capabilities)

    analyzers = [CapabilityAnalyzer(), PromptAnalyzer(), DataLeakageAnalyzer(), MCPAnalyzer()]
    for analyzer in analyzers:
        findings.extend(analyzer.run(file_cache, rules, agent_models))
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

    project_graph = build_project_graph(agent_models, mcp_assets=mcp_assets)
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

    return {
        "findings": findings,
        "counts": counts,
        "files_scanned": len(files),
        "agent_models": agent_models,
        "detected_frameworks": detected_frameworks,
        "framework_discovery_methods": {k: sorted(list(v)) for k, v in framework_methods.items()},
        "parser_provenance": parse_provenance,
        "unified_models": unified_models,
        "normalized_capabilities": normalized_capabilities,
        "dependencies": sorted(list(deps)),
        "import_graph": {
            "modules": import_graph.module_to_file,
            "edges": {k: sorted(list(v)) for k, v in import_graph.edges.items()},
        },
        "project_graph": project_graph,
        "mcp_assets": mcp_assets,
        "mcp_capabilities": mcp_capabilities,
        "trust_score": trust_score,
    }
