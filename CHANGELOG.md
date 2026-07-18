# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-beta] - 2026-07-18

### Added
- Multi-framework scanning: LangGraph, CrewAI, LangChain, Semantic Kernel,
  OpenAI Agents SDK, Microsoft Agent Framework, Azure AI Foundry, Bedrock Agent
- Prompt injection detection (LLM01): input interpolation, missing delimiters,
  system prompt leakage, role override attempts
- Capability analysis (LLM06): shell, filesystem, HTTP, database, code
  execution, autonomous loops, `subprocess` with `shell=True`, file writes
- Data leakage detection (LLM02): hardcoded API keys, tokens, passwords,
  environment secret references
- MCP analysis: config discovery, schema validation (v1.0/v1.1), missing auth,
  weak auth, missing permissions, exposed endpoints, hardcoded secrets
- Deterministic trust scoring across 7 risk categories (0–100)
- Reports: terminal, JSON, SARIF 2.1.0, HTML
- Custom YAML rules via `--rules`
- CI/CD exit codes via `--fail-on`
- GitHub Actions workflow with self-scan SARIF dogfooding
- Installable package with `safeai` console script and `python -m safeai`

### Security
- Credential values in findings evidence are masked in all report formats
- Scans exclude VCS directories, dependency caches, and oversized files
