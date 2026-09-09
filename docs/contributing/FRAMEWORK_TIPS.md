# Framework-Specific Scan Tips

This document provides tips for scanning projects that use specific AI frameworks.

## General Tips

- Use `--no-registry` for CI/CD pipelines to avoid writing to the local KYA registry
- Use `--fail-on critical` for strict CI gates, `--fail-on high` for moderate gates
- Use `--sarif` for GitHub Advanced Security integration
- Use `--html` for interactive reports during local development

## Claude Code

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI automatically detects `.claude/settings.json`, `CLAUDE.md`, and `.mcp.json`
- Permission precedence follows Claude Code's documented rules: `deny > ask > allow`
- Scoped permissions (user vs project) are both analyzed
- MCP server configurations are checked for auth, transport, and tool poisoning

**Known issues:**
- Large monorepos with many `.claude/` directories may slow detection
- Use `--rules` to limit scanning to specific rule families if needed

## LangChain / LangGraph

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI detects Python imports from `langchain`, `langgraph`, `langchain_openai`, etc.
- Agent executors, chains, tools, prompts, and memory are all detected
- Graph-based workflows in LangGraph are detected as workflows

**Known issues:**
- Very large codebases with many LangChain imports may produce many findings
- Use `--fail-on high` to focus on critical issues

## CrewAI

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI detects CrewAI agents, tasks, tools, and memory
- Agent-to-agent delegation patterns are detected
- Tool definitions and executions are tracked

**Known issues:**
- CrewAI projects often have complex agent topologies - review the tool surface carefully

## Cursor Rules

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI scans `.cursorrules` files for permission declarations
- Tool permissions (allow/deny) are analyzed for conflicts
- MCP server references in rules are detected

**Known issues:**
- `.cursorrules` files may contain large amounts of text - focus on tool permission sections

## Windsurf

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI scans `.windsurfrules` files for permission declarations
- Similar analysis to Cursor Rules

## Dify

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI detects Dify workflow configurations (YAML/JSON)
- Look for `app` key in YAML files for Dify-specific detection
- Tools, agents, and models are extracted from workflow configs

**Known issues:**
- Dify projects may have multiple workflow files - scan the entire directory

## Haystack

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI detects Haystack pipelines, tools, and generators
- RAG patterns (retrievers, document stores) are detected
- Web search tools are flagged as browser capabilities

**Known issues:**
- Haystack projects often use virtual environments - ensure dependencies are visible

## n8n

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI scans n8n workflow JSON files
- Node types and connections are analyzed
- External service integrations are detected

**Known issues:**
- n8n workflows can be very large JSON files
- Focus on HTTP Request nodes and webhook configurations

## Google ADK

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI detects Google ADK agent configurations
- Tool and model configurations are extracted

## OpenAI Agents

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI detects OpenAI Agents SDK usage
- Agent definitions, tools, and runners are detected

**Known issues:**
- There's a known recursion issue in import graph resolution - skip this framework if you encounter RecursionError

## Semantic Kernel

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI detects Semantic Kernel plugins and functions
- Kernel configurations are analyzed

## Microsoft Agent Framework

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI detects Azure AI Agents SDK usage
- Agent clients, tools, and models are detected
- Cloud service capabilities are inferred

## Mastra

**Scan command:**
```bash
python -m safeai scan . --no-registry
```

**Tips:**
- SafeAI detects Mastra agents, workflows, and tools
- Model provider integrations are detected

## Troubleshooting

### Slow scans
- Use `--no-registry` to skip registry operations
- Use `--rules` to limit scanning to specific rule families
- Scan specific directories instead of entire monorepos

### Too many findings
- Use `--fail-on high` or `--fail-on critical` to focus on severe issues
- Use `--baseline` to compare against previous scans and see only new findings

### Missing detections
- Ensure framework dependencies are in `requirements.txt` or `pyproject.toml`
- Check that framework config files are in standard locations
- Use `--verbose` to see detection details
