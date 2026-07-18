# SafeAI — Roadmap

SafeAI is a **Static AI Capability & Risk Analyzer** — think SonarQube for AI agents and workflows.

This document describes the planned roadmap across five phases. Phases are not strictly sequential; work may proceed in parallel where dependencies allow.

---

## Phase 1 — Static AI Risk Scanner (OSS)

*Current state — in active development.*

**Scope:** Framework, agent, workflow, prompt, tool, skill, model, memory, MCP, identity, and integration discovery.

**Static analyzers for:**
- Capabilities — shell, filesystem, network, database, code execution
- Prompts — injection patterns, delimiter issues, system leaks, role overrides
- Tools — agent-bound tool definitions and their risk profiles
- Memory — checkpointer and memory object usage
- Workflows — workflow composition and execution paths
- Identities — credential and secret exposure
- Models — LLM provider references
- Autonomy — loop detection, unbounded execution
- Governance signals — auth, permissions, audit configurations
- Heuristic data flows — untrusted input propagation into prompts

**Outputs:** JSON, HTML, SARIF 2.1.0, capability graph, capability diff, trust score

---

## Phase 1.5 — AI Component Security

Deep analysis of reusable AI artifacts:

| Artifact | Analysis Focus |
|----------|---------------|
| **Skills** | Embedded prompts, excessive permissions, risky capabilities |
| **Prompts** | Injection resistance, system prompt exposure, role isolation |
| **MCP servers** | Auth gaps, endpoint exposure, tool misuse potential |
| **Workflow templates** | Insecure defaults, capability sprawl, approval gaps |
| **Tool definitions** | Overly broad permissions, missing validation, shell access |
| **Model configurations** | Unsafe parameters, lack of content filters |

Detect embedded prompts, hardcoded secrets, excessive permissions, insecure defaults, and risky component compositions.

Remains **offline and static** — no reputation services or vulnerability feeds at this stage.

---

## Phase 2 — AI Security Testing (optional future)

Runtime and dynamic analysis capabilities:

- Runtime sandbox for safe execution of agent workflows
- Hallucination and jailbreak testing
- Prompt injection resilience testing
- Goal hijacking detection
- Tool misuse detection
- Data exfiltration monitoring
- Reliability and consistency testing

---

## Phase 3 — Test Packs

Curated test suites for compliance and security validation:

| Pack | Coverage |
|------|----------|
| OWASP LLM | OWASP Top 10 for LLM Applications |
| Agent Security | Agent-specific threat patterns |
| MCP Security | Model Context Protocol misconfiguration |
| RAG Security | Retrieval-Augmented Generation risks |
| Healthcare | HIPAA, patient data handling |
| Finance | PCI, transaction security |
| GDPR | Data protection, consent, right-to-deletion |
| Custom | Organization-specific rule packs |

---

## Phase 4 — Enterprise (Commercial)

Scalability and management capabilities for enterprise adoption:

- Fleet-wide scanning across repositories and projects
- Central policy management with role-based access control
- Trend analysis and risk dashboards over time
- Enterprise integrations (Azure DevOps, GitLab, Jenkins, etc.)
- Reporting dashboards with executive summaries

---

## Phase 5 — Community Intelligence

Community-powered threat intelligence:

- Reputation services for MCP servers, tools, and prompts
- Known malicious prompts, skills, and MCP servers database
- Community-shared detection rules
- AI vulnerability database (curated from public sources)
- Public risk intelligence feeds

---

## Philosophy

SafeAI is intentionally:

- **Lightweight** — no external services, no runtime, no LLM calls
- **Environment agnostic** — works in any CI/CD pipeline, on any OS
- **CI/CD friendly** — SARIF output, exit codes, GitHub Actions ready
- **Plugin based** — frameworks, analyzers, and rules are all pluggable
- **Community driven** — built by and for the AI security community

The product is consistently described as a **Static AI Capability & Risk Analyzer** — emphasizing that it analyzes *capabilities* (what an agent *can do*) and *risk* (what could go wrong) entirely through static analysis, without executing code or calling external services.
