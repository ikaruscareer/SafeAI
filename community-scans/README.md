# SafeAI Community Scans Programme

## Purpose

This programme conducts static security and capability scans of publicly available AI-agent frameworks and tools using the SafeAI Static Analyzer. The goal is to produce research artifacts that help maintainers understand potential risks and guide responsible disclosure.

## Scope

Scanning **25+ frameworks** across four categories:

| Category | Frameworks |
|----------|------------|
| **Workflow & Agent Platforms** | n8n, Dify, Flowise, Activepieces, Composio |
| **LLM Application Frameworks** | LangChain, Haystack, Semantic Kernel, DSPy, Instructor |
| **Multi-Agent Frameworks** | CrewAI, AutoGen, MetaGPT, ChatDev, CAMEL |
| **RAG & Agent Frameworks** | LlamaIndex, RAGFlow, LangGraph |

See [`targets.yml`](targets.yml) for the full list with repository URLs and configuration.

## Selection Rationale

Targets are selected based on GitHub popularity, community adoption, and architectural diversity. Rankings are dynamic; this is a starting selection, not a permanent ranking.

## Static-Analysis Only

All scans are read-only static analysis. No target code is executed, no dependencies are installed, no Dockerfiles are run, and no target workflows are triggered. Results require maintainer validation and do not constitute confirmed vulnerabilities.

---

## Quick Start: Scan a Framework Locally

### Prerequisites

```bash
# Clone SafeAI
git clone https://github.com/ikaruscareer/SafeAI.git
cd SafeAI
pip install -e .
```

### Scan any framework

```bash
# Clone the framework
git clone https://github.com/langchain-ai/langchain.git /tmp/langchain

# Run SafeAI scan
python -m safeai scan /tmp/langchain \
  --sarif langchain.sarif \
  --json langchain.json \
  --html langchain.html \
  --scorecard langchain-scorecard.md \
  --no-registry
```

### Share your results

1. Fork this repository
2. Create `community-scans/reports/<your-username>/` directory
3. Copy your scan results there
4. Submit a PR with a brief summary

See [SCAN_AND_SHARE.md](SCAN_AND_SHARE.md) for detailed instructions.

---

## How to Contribute

### Level 1: Run a scan (5 minutes)

Pick a framework from the list below, run a scan, and share the results:

| Framework | Repository | Difficulty |
|-----------|------------|------------|
| LangChain | `langchain-ai/langchain` | Easy |
| CrewAI | `crewAIInc/crewAI` | Easy |
| LlamaIndex | `run-llama/llama_index` | Easy |
| LangGraph | `langchain-ai/langgraph` | Easy |
| n8n | `n8n-io/n8n` | Easy |
| Haystack | `deepset-ai/haystack` | Easy |
| AutoGen | `microsoft/autogen` | Easy |
| MetaGPT | `geekan/MetaGPT` | Medium |
| DSPy | `stanfordnlp/dspy` | Easy |
| Semantic Kernel | `microsoft/semantic-kernel` | Easy |

### Level 2: Add a golden fixture (1-2 hours)

Create a representative test fixture for a framework that doesn't have one yet:

**Missing fixtures:** Azure Foundry, Bedrock Agent, Dify, Haystack, LangChain, Mastra, Microsoft Agent

See [GOOD_FIRST_ISSUES.md](../../docs/contributing/GOOD_FIRST_ISSUES.md#test-fixtures--compatibility) for instructions.

### Level 3: Improve framework detection (2-4 hours)

Enhance a framework's parser to detect more patterns:

- [ ] Add AutoGen detector
- [ ] Improve LangGraph parser (conditional edges)
- [ ] Add Microsoft Teams integration detection
- [ ] Split browser automation into separate rules

See [GOOD_FIRST_ISSUES.md](../../docs/contributing/GOOD_FIRST_ISSUES.md) for the full list.

---

## Reproducing a Scan

```bash
# From the SafeAI repository root
python -m safeai scan /path/to/repo \
  --scorecard --scorecard-json --no-registry
```

Artifacts are generated in `reports/` directories.

## Output Artifacts Per Target

```
reports/raw/<target-id>.sarif          # Raw SARIF output
reports/raw/<target-id>.json           # Raw JSON report
reports/raw/<target-id>.md             # Raw Markdown scorecard
reports/manifests/<target-id>.json     # Provenance manifest
reports/public/<target-id>-summary.md  # Sanitized public summary
```

## Artifact Retention

- Private artifacts (raw reports, manifests): retained per GitHub Actions retention policy
- Public summaries: retained for review and analysis
- No automatic publishing to Reddit or third-party platforms

## Finding handling

SafeAI severity is not treated as confirmed exploitability. Findings are classified as:

| Classification | Description |
|----------------|-------------|
| `informational` | General observations, not security concerns |
| `review_recommended` | Requires maintainer review or runtime validation |
| `high_confidence_security_concern` | Clear static evidence with safe public explanation |
| `potentially_sensitive` | May contain secrets, personal data, or private endpoints |
| `not_publishable` | Cannot be safely published in any form |

## Feedback and Corrections

Maintainers can request report corrections or removal via the SafeAI issue tracker. All removals require human validation.
