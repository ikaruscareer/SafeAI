# SafeAI — Support Matrix

## Python Versions

| Version | Status | CI Tested |
|---------|--------|-----------|
| 3.11 | Supported | Yes |
| 3.12 | Supported | Yes |
| 3.13 | Supported | Yes |
| 3.10 | Not supported | No (`requires-python >= 3.11`) |

## Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| Linux (Ubuntu 24.04) | Supported | Primary CI platform |
| macOS | Supported | No platform-specific code |
| Windows | Supported | No platform-specific code |

## Framework Adapters

| Framework | Adapter | Detects | Config Files |
|-----------|---------|---------|--------------|
| Azure AI Foundry | `azure_foundry` | AzureFoundry framework | Python imports |
| Bedrock Agent | `bedrock_agent` | Bedrock Agent framework | Python imports |
| Claude Code | `claude_code` | Claude Code config | `.claude/settings.json`, `CLAUDE.md`, `.mcp.json` |
| CrewAI | `crewai` | CrewAI framework | Python imports |
| Cursor Rules | `cursorrules` | Cursor IDE config | `.cursorrules` |
| Dify | `dify` | Dify workflow | Python imports |
| Google ADK | `google_adk` | Google ADK framework | Python imports |
| Haystack | `haystack` | Haystack framework | Python imports |
| LangChain | `langchain` | LangChain framework | Python imports |
| LangGraph | `langgraph` | LangGraph framework | Python imports |
| LlamaIndex | `llamaindex` | LlamaIndex framework | Python imports |
| Mastra | `mastra` | Mastra framework | Python imports |
| Microsoft Agent | `microsoft_agent` | Microsoft Agent Framework | Python imports |
| n8n | `n8n` | n8n workflow | JSON workflow files |
| OpenAI Agents | `openai_agents` | OpenAI Agents SDK | Python imports |
| Semantic Kernel | `semantic_kernel` | Semantic Kernel | Python imports |
| Windsurf | `windsurf` | Windsurf IDE config | `.windsurfrules` |

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Terminal | (default) | Human-readable terminal output |
| JSON | `--json PATH` | Machine-readable JSON report |
| SARIF 2.1.0 | `--sarif PATH` | GitHub Advanced Security format |
| HTML | `--html PATH` | Self-contained interactive report |
| PR Comment | `--pr-comment-path PATH` | Reviewer-facing escalation summary |
| Scorecard | `--scorecard PATH` | Security scorecard (Markdown) |
| KYA Manifest | Auto-generated | `safeai-manifest.json` in `.safeai/` |

## CI Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| GitHub Actions | Supported | Primary CI, official Action available |
| GitLab CI | Supported | Via `safeai/kya/ci_context.py` |
| Azure Pipelines | Supported | Via `safeai/kya/ci_context.py` |
| Other | Best effort | Generic CI detection |

## GitHub Action

```yaml
- uses: ikaruscareer/SafeAI@v2
  with:
    path: .
    fail-on: critical
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `path` | No | `.` | Directory or file to scan |
| `version` | No | `''` | SafeAI PyPI version to install |
| `fail-on` | No | `critical` | Minimum severity for non-zero exit |
| `sarif` | No | `safeai-results.sarif` | SARIF output path |
| `rules` | No | `''` | Custom rules directory |
| `baseline` | No | `''` | Prior report for diff comparison |
| `fail-on-new` | No | `false` | Fail only on new/regressed findings |
| `fail-on-escalation` | No | `''` | Escalation severity threshold |
| `no-registry` | No | `true` | Skip registry creation |
| `extra-args` | No | `[]` | Additional CLI arguments |
| `scorecard` | No | `safeai-scorecard.md` | Scorecard output path |
| `scorecard-json` | No | `safeai-scorecard.json` | JSON scorecard path |
| `scorecard-summary` | No | `true` | Write scorecard to job summary |
| `scorecard-fail-under` | No | `''` | Minimum score threshold |

### Outputs

| Output | Description |
|--------|-------------|
| `sarif-path` | Absolute path to SARIF file |
| `scorecard-path` | Absolute path to scorecard |
| `safeai-version` | Installed SafeAI version |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan (no findings at/above threshold) |
| 1 | Findings at or above `--fail-on` threshold |
| 2 | Scan error (invalid path, parse failure, etc.) |

## Rule Coverage

| Category | Rules | Description |
|----------|-------|-------------|
| `CAP_*` | 28 | Capability detection |
| `CC_*` | 12 | Claude Code specific |
| `DATA_*` | 2 | Data classification |
| `DATAFLOW_*` | 6 | Data-flow tracking |
| `DEP_*` | 4 | Dependency correlation |
| `ENV_*` | 2 | Environment analysis |
| `GOV_*` | 10 | Governance controls |
| `MCP_*` | 2 | MCP configuration |
| `MODEL_*` | 2 | Model configuration |
| `PROMPT_*` | 14 | Prompt injection detection |
| `PROMPT_FILE_*` | 2 | Prompt file scanning |
| `SKILL_*` | 2 | Skill analysis |
| `TOOL_*` | 2 | Tool analysis |
| `WORKFLOW_*` | 2 | Workflow analysis |

## Links

- [README](./README.md)
- [Release Notes](./RELEASE_NOTES.md)
- [Upgrade Guide](./UPGRADE.md)
- [Release Channels](./RELEASE_CHANNELS.md)
- [Security Policy](./SECURITY.md)
- [Known Limitations](./KNOWN_LIMITATIONS.md)
