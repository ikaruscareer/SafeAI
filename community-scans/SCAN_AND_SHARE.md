# Scan & Share Guide

This guide walks you through scanning a framework and sharing your results with the SafeAI community.

## Prerequisites

1. Python 3.11+ installed
2. SafeAI cloned and installed:
   ```bash
   git clone https://github.com/ikaruscareer/SafeAI.git
   cd SafeAI
   pip install -e .
   ```

## Step 1: Choose a Framework

Pick any AI framework from our target list. Here are some popular ones:

| Framework | Language | Repository |
|-----------|----------|------------|
| LangChain | Python | `langchain-ai/langchain` |
| CrewAI | Python | `crewAIInc/crewAI` |
| LlamaIndex | Python | `run-llama/llama_index` |
| LangGraph | Python | `langchain-ai/langgraph` |
| n8n | TypeScript | `n8n-io/n8n` |
| AutoGen | Python | `microsoft/autogen` |
| Haystack | Python | `deepset-ai/haystack` |
| DSPy | Python | `stanfordnlp/dspy` |

## Step 2: Clone the Framework

```bash
# Clone the framework to a temporary location
git clone https://github.com/<org>/<repo>.git /tmp/<framework>
```

## Step 3: Run the Scan

```bash
# Basic scan
python -m safeai scan /tmp/<framework> --no-registry

# Full scan with all outputs
python -m safeai scan /tmp/<framework> \
  --sarif /tmp/<framework>.sarif \
  --json /tmp/<framework>.json \
  --html /tmp/<framework>.html \
  --scorecard /tmp/<framework>-scorecard.md \
  --scorecard-json /tmp/<framework>-scorecard.json \
  --no-registry
```

### Useful scan options

| Option | Description |
|--------|-------------|
| `--no-registry` | Skip registry persistence (recommended for one-off scans) |
| `--sarif <path>` | Output SARIF format for GitHub Advanced Security |
| `--json <path>` | Output detailed JSON report |
| `--html <path>` | Output interactive HTML report |
| `--scorecard <path>` | Output security scorecard as Markdown |
| `--scorecard-json <path>` | Output scorecard as JSON |
| `--fail-on <level>` | Exit with code 1 if findings at or above this severity |
| `--verbose` | Show detailed scan progress |

## Step 4: Review the Results

Open the HTML report for an interactive view:

```bash
# macOS
open /tmp/<framework>.html

# Linux
xdg-open /tmp/<framework>.html

# Windows
start /tmp/<framework>.html
```

Key things to look for:
- **Trust Score**: 0-100 score across 7 risk categories
- **Capabilities**: What the framework can do (shell, filesystem, network, etc.)
- **Findings**: Security issues detected, sorted by severity
- **Escalations**: Changes in capability between scans (if baseline provided)

## Step 5: Share Your Results

### Option A: Submit a PR with your scan results

1. Fork the SafeAI repository
2. Create a directory for your results:
   ```bash
   mkdir -p community-scans/reports/<your-github-username>/<framework>
   ```
3. Copy your scan results there:
   ```bash
   cp /tmp/<framework>.* community-scans/reports/<your-github-username>/<framework>/
   ```
4. Create a brief summary file:
   ```bash
   cat > community-scans/reports/<your-github-username>/<framework>/README.md << EOF
   # <Framework> Scan Results

   **Scanned by:** @<your-github-username>
   **Date:** $(date +%Y-%m-%d)
   **SafeAI version:** $(python -c "from safeai.version import SAFEAI_VERSION; print(SAFEAI_VERSION)")
   **Framework commit:** $(cd /tmp/<framework> && git rev-parse HEAD)

   ## Summary

   - Trust Score: <score>
   - Findings: <count> (<critical> critical, <high> high, <medium> medium)
   - Capabilities detected: <list>

   ## Key Findings

   1. <finding 1>
   2. <finding 2>
   3. <finding 3>

   ## Notes

   <any observations about the scan or the framework>
   EOF
   ```
5. Submit your PR

### Option B: Open an issue

If you don't want to submit a PR, open an issue with:
- Framework name and version
- Trust Score
- Number of findings by severity
- Any interesting observations
- Attach the HTML report if possible

## Step 6: Help Improve SafeAI

Based on your scan, you might discover:
- **Missing detection patterns** → Open an issue or submit a PR to improve the framework parser
- **False positives** → Report them so we can tune the rules
- **New capability patterns** → Help us add detection for new framework features

## Troubleshooting

### "No module named safeai"

Make sure you installed SafeAI in development mode:
```bash
cd SafeAI
pip install -e .
```

### "Permission denied" or "Connection refused"

Some frameworks are large. Make sure you have:
- Enough disk space (10GB+ recommended)
- Good internet connection for cloning
- Write permission to the output directory

### Scan takes too long

Large repositories like LangChain can take 10+ minutes to scan. This is normal. Use `--verbose` to see progress.

### "No frameworks detected"

This is normal for some frameworks. SafeAI detects frameworks by analyzing imports, configuration files, and code patterns. If a framework uses unusual patterns, it might not be detected. Open an issue to let us know.

## Questions?

- Open an issue: https://github.com/ikaruscareer/SafeAI/issues
- Check existing issues for answers: https://github.com/ikaruscareer/SafeAI/issues?q=is%3Aissue+is%3Aopen
