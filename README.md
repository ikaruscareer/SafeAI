# SafeAI — Static AI Capability & Risk Analyzer

[![CI](https://github.com/ikaruscareer/SafeAI/actions/workflows/ci.yml/badge.svg)](https://github.com/ikaruscareer/SafeAI/actions/workflows/ci.yml)
[![Website](https://img.shields.io/badge/web-safeai--analyzer.ikaruscareer.com-0f766e)](https://safeai-analyzer.ikaruscareer.com)

**SafeAI** is a static analysis tool that scans AI application source code for security risks, capability exposure, and governance gaps. It runs entirely offline, never executes agents or calls LLMs, and integrates into CI/CD pipelines.

> 🌐 [safeai-analyzer.ikaruscareer.com](https://safeai-analyzer.ikaruscareer.com) — project landing page

<img width="1024" height="1024" alt="SafeAI_Agent_Software_Static_Analyzer" src="https://github.com/user-attachments/assets/de40f40b-14b9-4cd6-bc2c-27e81e8253fe" />

---

## Why SafeAI?

Traditional application security tools (SAST, SCA, IaC scanning) are not designed for AI agent systems. AI applications introduce new risk surfaces:

- **Prompt injection** — untrusted input flows into model prompts
- **Agent tool misuse** — agents with filesystem, shell, or database access
- **Capability sprawl** — frameworks expose capabilities without visibility
- **MCP exposure** — Model Context Protocol endpoints and tools
- **Governance gaps** — missing authentication, permissions, audit trails

SafeAI fills this gap by analyzing frameworks, agents, tools, capabilities, and MCP integrations at rest—before deployment.

SafeAI analyzes AI applications without executing them, helping developers discover capabilities, identify potential risks, and improve governance early in the software lifecycle.

Designed to be lightweight, explainable, and community-driven, SafeAI aims to become an open foundation for AI capability and risk analysis.

SafeAI sits before runtime guardrails and red-teaming tools in the security lifecycle. It scans agent source code at commit time — detecting framework-specific capabilities, MCP misconfigurations, and prompt injection patterns — before you ever deploy an agent to staging. It does not replace runtime tools (Microsoft AGT), evaluation frameworks (LangSmith, DeepEval), or red-teaming scanners (Promptfoo, Garak). It complements them: find the risk in code first, then validate at runtime.

<img width="1024" height="1024" alt="SafeAI_Concept" src="https://github.com/user-attachments/assets/c07999b2-79d5-4200-9eec-ce1ab4e63cc8" />


---

## Key Features

| Feature | Description |
|---------|-------------|
| **Framework Detection** | Detects and parses 8 AI agent frameworks |
| **Capability Discovery** | Identifies filesystem, shell, network, database, and other capabilities |
| **AI Risk Analysis** | Categorizes findings into 7 risk categories with weighted trust scoring |
| **Prompt Risk Analysis** | Detects injection patterns, delimiter issues, system leak, role override |
| **Tool Analysis** | Identifies agent-bound tools and their risk profiles |
| **Memory Analysis** | Detects memory/checkpointer usage in agent workflows |
| **MCP Analysis** | Discovers MCP servers, clients, tools, resources, and validates configuration |
| **Data Leakage Detection** | Flags hardcoded secrets, tokens, and API keys |
| **CI/CD Integration** | SARIF output, exit codes, GitHub Actions workflow included |
| **Multi-Format Reports** | Terminal summary, JSON, SARIF 2.1.0, HTML |
| **Cross-File Analysis** | Import graph, symbol resolution, and project graph |
| **Confidence-Arbitrated Parsing** | Multiple parsers per file, merged with provenance |

---

## How It Works

```
Source Code
    │
    ▼
Framework Detection — identifies AI frameworks via imports, configs, deps
    │
    ▼
Static Analysis — AST parsing, capability patterns, dependency scanning
    │
    ▼
Capability Mapping — maps framework objects to normalized risk categories
    │
    ▼
Risk Rules — applies rule engine with configurable severity and weights
    │
    ▼
Trust Score — deterministic category-weighted scoring from 0–100
    │
    ▼
Reports — terminal, JSON, SARIF, HTML
```
<img width="1024" height="1024" alt="SafeAI_AI_Capability_Risk_Analyzer" src="https://github.com/user-attachments/assets/618f9ebc-030b-40c9-a98e-b0a5c41e07cc" />

---

## Supported Frameworks

| Framework | Detection | Discovery | Capability Analysis | Risk Analysis | Status |
|-----------|-----------|-----------|-------------------|---------------|--------|
| LangGraph | ✔ | Partial | Partial | Partial | Early Preview |
| CrewAI | ✔ | Partial | Partial | Partial | Early Preview |
| LangChain | ✔ | Partial | Partial | Partial | Early Preview |
| Semantic Kernel | ✔ | Partial | Partial | Partial | Early Preview |
| OpenAI Agents SDK | ✔ | Partial | Partial | Partial | Early Preview |
| Microsoft Agent Framework | ✔ | Partial | Partial | Partial | Early Preview |
| Azure AI Foundry | ✔ | Minimal | Minimal | Minimal | Early Preview |
| Bedrock Agent | ✔ | Minimal | Minimal | Minimal | Early Preview |


### Framework Support Details

- **LangGraph** — detects `StateGraph`, `add_edge`, `bind_tools`, nodes, models
- **CrewAI** — detects `Agent`, `Task`, tools, models
- **LangChain** — detects `AgentExecutor`, `Chain`, `Tool`, `PromptTemplate`, models
- **Semantic Kernel** — detects `Kernel.invoke`, plugins, functions, skills, memory
- **OpenAI Agents SDK** — detects `Agent`, tools, handoffs, MCP references
- **Microsoft Agent Framework** — detects `AgentClient`, tools, workflows, Azure models
- **Azure AI Foundry** — detects YAML configurations with Azure resources
- **Bedrock Agent** — detects JSON configurations with Bedrock resources

---

## Supported Capabilities

SafeAI fingerprints capabilities at the framework object level and via fallback regex patterns. Each capability includes evidence, confidence score, resolved definition, and provenance.

<img width="1024" height="1024" alt="SafeAI_Capability_Risk_Report" src="https://github.com/user-attachments/assets/ae924e9d-650f-4480-b5b2-2984e5c57087" />

| Capability | Category | Risk Impact |
|------------|----------|-------------|
| Shell Execution | Shell | Command injection, host compromise |
| Filesystem Access | Filesystem | Data exfiltration, file tampering |
| Browser Automation | Browser | UI-based attacks, credential theft |
| Planning / Orchestration | Planner | Autonomous decision chain risk |
| Agent Delegation | Delegation | Unchecked sub-agent authority |
| Memory / Checkpoint | Memory | Data retention across sessions |
| RAG / Retrieval | RAG | Document exfiltration, prompt injection via documents |
| GitHub Integration | GitHub | Repository access, secret leakage |
| Slack Integration | Slack | Channel monitoring, message injection |
| Email Integration | Email | Phishing, data exfiltration |
| Database Access | Databases | SQL injection, data breach |
| Cloud Services | Cloud | Cloud resource abuse, cost escalation |
| External APIs | External APIs | Third-party data exfiltration |
| MCP Services | MCP | Exposed endpoints, unauthorized tool access |
| Human Approval | Human Approval | Approval bypass risk |
| Multi-Agent | Multi-Agent | Delegation-based privilege escalation |

> **Note:** Some capabilities (Browser, GitHub, Slack, Email, RAG, Human Approval) are detected primarily through MCP configuration analysis. Framework adapter detection for these capabilities is planned.

---

## Installation

### Requirements

- Python 3.11 or 3.12
- PyYAML (for YAML configuration parsing)

### Install from source

```bash
git clone https://github.com/ikaruscareer/SafeAI.git
cd SafeAI
pip install -e .
```

### Install development dependencies

```bash
pip install -e ".[dev]"
```

---

## CLI Usage

```bash
python -m safeai scan <directory> [options]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `directory` | required | Path to scan |
| `--sarif` | `report.sarif` | SARIF output path (empty string to skip) |
| `--json` | — | JSON output path |
| `--html` | — | HTML report output path |
| `--rules` | built-in | Custom rules directory |
| `--fail-on` | `critical` | Exit code threshold: `critical`, `high`, `medium` |
| `--verbose` | — | Enable verbose output |

### Exit Codes

| Code | Condition |
|------|-----------|
| 0 | No findings at or above threshold |
| 1 | Finding at or above threshold detected |

---

## Example Output

### Terminal

```
SafeAI Scan Summary
Files: 12
Frameworks: langgraph, crewai
MCP assets: 2
Overall AI Risk Score: 73
critical: 1
high: 3
medium: 5
Findings:
[critical] app.py:10 - Untrusted input interpolated into prompt
[high] app.py:22 - Capability detected: shell_execution
[high] mcp.json:1 - MCP configuration does not define authentication
```

### Example: LangGraph agent with MCP

```json
{
  "Framework": "LangGraph",
  "Capabilities": ["Planner", "Memory", "Filesystem", "MCP"],
  "Risk Score": 73,
  "Findings": 9,
  "Critical": 1,
  "High": 3
}
```

---

## CI/CD Integration

### GitHub Actions

A workflow is included at `.github/workflows/ci.yml`. To use in your project:

```yaml
jobs:
  safeai-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install SafeAI
        run: |
          pip install -e .
      - name: Run scan
        run: |
          python -m safeai scan . --sarif results.sarif --html report.html
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
safeai-scan:
  image: python:3.12
  script:
    - pip install -e .
    - safeai scan . --sarif results.sarif --html report.html
  artifacts:
    paths:
      - results.sarif
      - report.html
```

### Azure DevOps

```yaml
- task: PythonScript@0
  inputs:
    scriptSource: 'inline'
    script: |
      import subprocess
      subprocess.run(["pip", "install", "-e", "."])
      subprocess.run(["safeai", "scan", ".", "--sarif", "$(Build.ArtifactStagingDirectory)/results.sarif"])
```

### SARIF Integration

SafeAI outputs SARIF 2.1.0 format, compatible with GitHub Advanced Security, Azure DevOps, and other SARIF-compliant tools.

---

## Roadmap

See [ROADMAP.md](./ROADMAP.md) for the detailed roadmap covering all 5 phases:

- **Phase 1** — Static AI Risk Scanner (OSS) — *in active development*
- **Phase 1.5** — AI Component Security
- **Phase 2** — AI Security Testing (optional future)
- **Phase 3** — Test Packs
- **Phase 4** — Enterprise (Commercial)
- **Phase 5** — Community Intelligence

<img width="1024" height="1024" alt="SafeAI_Roadmap" src="https://github.com/user-attachments/assets/2cdd1a8a-b4ae-4e1f-8f85-0108fdeb3194" />

---

## License

SafeAI is released under the Apache 2.0 License.
