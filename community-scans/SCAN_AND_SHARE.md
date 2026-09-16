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

## Shortcut: scan several frameworks at once

`scripts/scan_framework.py` replaces Steps 2 and 3 when you want to cover more
than one framework. It clones each target, scans it, and writes a side-by-side
comparison. A target that fails to clone or scan is recorded and skipped, so one
bad repository never ends the run.

```bash
# By id from community-scans/targets.yml
python scripts/scan_framework.py --frameworks langgraph crewai instructor

# By URL, for anything not in the target list
python scripts/scan_framework.py --urls https://github.com/langchain-ai/langgraph

# Mixed, with an HTML comparison
python scripts/scan_framework.py \
  --frameworks langgraph instructor \
  --urls https://github.com/some-org/their-agent \
  --html

# See what you can scan, or check a plan before committing to it
python scripts/scan_framework.py --list
python scripts/scan_framework.py --frameworks langgraph dspy --dry-run
```

Names are matched loosely, so `LlamaIndex`, `llama-index`, and `llama_index` all
resolve to the same catalog entry. A bare `owner/repo` works too, and picks up
the catalog's pinned `default_ref` when the repository is a known target.

### Options

| Option | Description |
|--------|-------------|
| `--frameworks ID [ID ...]` | Target ids from `targets.yml`, or `owner/repo` |
| `--urls URL [URL ...]` | `https://github.com/<owner>/<repo>` URLs |
| `--output-dir DIR` | Where results land (default: `community-scans/reports/automated/`) |
| `--html` | Also render `comparison.html` |
| `--list` | Print the known target ids and exit |
| `--dry-run` | Resolve targets and print the plan without cloning |
| `--depth N` | Clone depth (default: 1, a shallow clone) |
| `--clone-timeout SEC` | Per-target clone timeout (default: 600) |
| `--scan-timeout SEC` | Per-target scan timeout (default: 1800) |
| `--top-rules N` | Rows in the most-frequent-rules table (default: 15) |
| `--keep-clones` | Keep the cloned repositories for follow-up investigation |
| `--workspace DIR` | Clone into `DIR` instead of a temporary directory |
| `--verbose` | Pass `--verbose` to each scan |

### Output layout

```
community-scans/reports/automated/
├── COMPARISON.md          # the side-by-side report
├── comparison.json        # the same data, machine-readable
├── comparison.html        # with --html
├── langgraph/
│   ├── langgraph.json     langgraph.sarif     langgraph.html
│   ├── langgraph-scorecard.json               langgraph-scorecard.md
│   └── langgraph-scan.log # kept even when a scan fails
└── crewai/ ...
```

`COMPARISON.md` covers severity counts, both scores, detected frameworks, a
capability matrix, per-category trust scores, the most frequent rules across all
targets, and auto-generated observations (rules that fired everywhere, which are
the likeliest systematic false positives).

Exit codes: `0` every target scanned · `1` partial, some targets failed ·
`2` usage error, or nothing scanned at all.

### Before you share the results

`community-scans/reports/` is git-ignored, so nothing here is committed or
published by accident. That is deliberate — see
[`disclosure-policy.md`](disclosure-policy.md).

- The per-target JSON, SARIF, and HTML are **raw and unreviewed**. They can quote
  code from the scanned repository. Run
  `community-scans/scripts/sanitise_report.py --report <file> --out <file>`
  before anything goes public.
- `COMPARISON.md` and `comparison.json` are aggregate-only by design: rule ids,
  counts, and capability names, with no finding messages or file paths.
- Everything is static-analysis evidence and needs human validation before you
  open an issue against a framework.

### Notes from real runs

- Scan time does not track repository size. In one run CrewAI (2,172 files) took
  145s while agno (4,877 files) ran past 200s and dspy was slower still. Set
  `--scan-timeout` deliberately when you queue up unfamiliar targets.
- A scanner crash can still exit `1`, so the script treats a missing JSON report
  as the failure signal and pulls the real cause into the failures table
  (for example `scanner crashed: RecursionError: maximum recursion depth
  exceeded`). If you see that, the scan log in the target's directory has the
  full traceback and is worth an issue.

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
