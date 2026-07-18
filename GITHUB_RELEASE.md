# SafeAI — GitHub Release

## v1.0.0-beta

Static AI Capability & Risk Analyzer for detecting prompt injection, data leakage, excessive agency, and MCP misconfigurations in AI agent codebases.

### Installation

```bash
pip install git+https://github.com/ikaruscareer/SafeAI.git
```

### Quick Start

```bash
safeai scan /path/to/project
safeai scan /path/to/project --json results.json
safeai scan /path/to/project --html report.html
```

### What It Detects

| Category | Examples |
|----------|----------|
| Prompt Injection | User input in prompts, missing delimiters, system prompt leaks |
| Data Leakage | Hardcoded API keys, tokens, passwords |
| Excessive Agency | Shell exec, filesystem access, HTTP, database, code exec, autonomous loops |
| MCP Misconfig | Missing auth, weak permissions, exposed endpoints, hardcoded secrets |
| Supply Chain | AI framework dependency detection |

### Supported Frameworks

- LangGraph
- CrewAI
- LangChain
- Semantic Kernel
- OpenAI Agents
- Microsoft Agent
- Azure AI Foundry
- Bedrock Agent

### Output Formats

- Terminal (human-readable)
- JSON (machine-readable)
- SARIF 2.1.0 (GitHub Advanced Security)
- HTML (interactive report)

### Links

- [Landing Page](https://safeai-analyzer.ikaruscareer.com)
- [Source Code](https://github.com/ikaruscareer/SafeAI)
- [Issue Tracker](https://github.com/ikaruscareer/SafeAI/issues)
- [Changelog](RELEASE_NOTES.md)

### Assets

- `safeai-1.0.0b0-py3-none-any.whl`
- `safeai-1.0.0b0.tar.gz`
