# SafeAI — Release Notes

## v1.0.0-beta (2026-07-14)

Initial beta release of SafeAI — the Static AI Capability & Risk Analyzer for AI agent codebases.

### Features

- **Multi-Framework Scanning**
  - LangGraph, CrewAI, LangChain, Semantic Kernel, OpenAI Agents
  - Microsoft Agent, Azure AI Foundry, Bedrock Agent
  - Automatic framework detection (AST + config + dependency analysis)

- **Prompt Injection Detection**
  - Direct user input interpolation into prompts (LLM01)
  - Missing delimiters between system and user content
  - System prompt leakage detection
  - Role override / instruction override attempts

- **Capability Analysis**
  - Shell execution, filesystem, HTTP, database, code execution
  - Autonomous agent loop detection
  - OWASP LLM06 (Excessive Agency) coverage

- **Data Leakage Detection**
  - Hardcoded API keys, tokens, passwords
  - Environment variable references to secrets

- **MCP (Model Context Protocol) Analysis**
  - Configuration discovery across project files
  - Schema validation (v1.0, v1.1)
  - Authentication and permissions gap detection
  - Endpoint exposure and secret detection

- **Trust Score**
  - Deterministic, reproducible risk scoring (0–100)
  - 7 risk categories with configurable weights
  - Confidence-weighted findings

- **Report Output**
  - Terminal (human-readable summary)
  - JSON (machine-readable)
  - SARIF 2.1.0 (GitHub Advanced Security compatible)
  - HTML (self-contained interactive report)

- **Custom Rules**
  - User-defined YAML rule overrides via `--rules`
  - Merge with built-in rules

- **Exit Code Integration**
  - Configurable `--fail-on` threshold for CI/CD pipelines

### Known Limitations (Beta)

- Dynamic prompt injection at runtime is not detectable via static analysis
- Framework detection is heuristic-based; some complex configurations may not be detected
- Python-only source analysis (JavaScript/TypeScript agent code not yet supported)
- MCP analysis supports v1.0 and v1.1 schemas only
- Dependency scanning is framework-agnostic (name/version extraction only; no CVE matching)

### Installation

```bash
pip install git+https://github.com/ikaruscareer/SafeAI.git
```

### Quick Start

```bash
safeai scan /path/to/project
safeai scan /path/to/project --json report.json
safeai scan /path/to/project --html report.html --fail-on medium
```
