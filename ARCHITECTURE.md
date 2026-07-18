# SafeAI — Technical Architecture

This document describes the technical architecture of the SafeAI Static AI Capability & Risk Analyzer.

---

## Overview

SafeAI is a modular, plugin-based static analysis tool. It is designed as a pipeline of independent stages:

```
Source Code
    │
    ▼
Collect Files ───► Build Semantic Docs ───► Build Import Graph
    │                                              │
    ▼                                              ▼
Framework Parser Registry ────► Multi-Parser Aggregation (per file)
    │                                              │
    ▼                                              ▼
Capability Analyzer ──── Prompt Analyzer ──── Data Leakage Analyzer ──── MCP Analyzer
    │                                              │
    ▼                                              ▼
Finding Deduplication ──── Trust Score Calculation
    │
    ▼
Report Generation (Terminal / JSON / SARIF / HTML)
```

---

## Package Structure

```
safeai/
├── cmd/                    # CLI entry point
│   └── cli.py
├── engine/                 # Scanner orchestration
│   └── scan.py
├── analysis/              # Core analysis primitives
│   ├── semantic.py        # AST document, symbol resolution
│   ├── import_graph.py    # Project-wide import tracking
│   ├── capabilities.py    # Capability model & helpers
│   ├── aggregation.py     # Multi-parser merge & arbitration
│   └── project_graph.py   # Cross-file entity graph
├── analyzers/             # Analysis modules
│   ├── capability/        # Capability fingerprinting
│   ├── prompt/            # Prompt injection analysis
│   ├── data_leakage/      # Secret detection
│   └── mcp/               # MCP discovery & validation
│       ├── analyzer.py    # MCP analyzer logic
│       ├── schema.py      # Versioned MCP schemas
│       ├── compatibility.py # Schema version resolution
│       └── validators.py  # Schema validation rules
├── frameworks/            # Framework adapters (plugins)
│   ├── langgraph/
│   ├── crewai/
│   ├── langchain/
│   ├── semantic_kernel/
│   ├── openai_agents/
│   ├── microsoft_agent/
│   ├── azure_foundry/
│   └── bedrock_agent/
├── report/                # Output generators
│   ├── terminal.py        # Terminal summary
│   ├── json_report.py     # JSON output
│   ├── sarif.py           # SARIF 2.1.0 output
│   └── html.py            # HTML report
├── rules/                 # Rule definitions
│   ├── loader.py          # Rule loading
│   └── base_rules.yaml    # Built-in rules
├── scoring/               # Risk scoring engine
│   └── engine.py          # Deterministic trust score
└── tests/                 # Test suite
```

---

## Component Descriptions

### 1. CLI (`cmd/cli.py`)

Entry point for the `safeai` command. Parses CLI arguments and invokes `run_scan()`. Handles report generation and exit codes.

**Key design decisions:**
- Uses Python `argparse` (no external CLI framework)
- Single subcommand (`scan`) with optional output flags
- Exit code 0/1 based on `--fail-on` threshold

### 2. Scanner Engine (`engine/scan.py`)

Orchestrates the entire scan pipeline:

1. **File collection** — Walks directory, collects `.py`, `.json`, `.yaml`, `.yml` files and dependency manifests
2. **Dependency extraction** — Parses `requirements.txt`, `pyproject.toml`, `Pipfile`, `package.json`
3. **Semantic document building** — Creates AST-based semantic documents for each Python file
4. **Import graph construction** — Builds a project-wide module/symbol graph
5. **Framework parsing** — Runs all framework parsers on each file (no mutual exclusion)
6. **Parser aggregation** — Merges results from multiple parsers per file
7. **Analysis** — Runs capability, prompt, data leakage, and MCP analyzers
8. **Project graph** — Builds cross-file entity relationship graph
9. **Trust scoring** — Computes category scores and overall risk score

### 3. Semantic Analysis (`analysis/semantic.py`)

Performs AST-level analysis of Python files:

- **SemanticDocument** — Holds imports, function definitions, class definitions, variable assignments, and call expressions
- **Symbol resolution** — Resolves local names to fully qualified names via imports and aliases
- **Origin resolution** — Maps symbols to their defining module/file via the import graph
- **Literal value extraction** — Extracts literal arguments from function calls

### 4. Import Graph (`analysis/import_graph.py`)

Builds a project-wide dependency graph:

- **Module resolution** — Maps module names to file paths
- **Edge tracking** — Records import relationships between files
- **Symbol indexing** — Tracks functions, classes, and re-exports per file
- **Re-export resolution** — Follows re-exports through `__init__.py`

### 5. Framework Adapters (`frameworks/*/parser.py`)

Each framework adapter is a self-contained Python module implementing:

```python
class FrameworkParser:
    name = "framework_name"

    def detect(self, path, content, scan_ctx=None): ...
    def parse(self, path, content, scan_ctx=None): ...
```

**Detection priority:**
1. AST import analysis (highest confidence)
2. Dependency manifest (requirements.txt, etc.)
3. Configuration files (YAML, JSON)
4. Regex fallback (lowest confidence)

**Output contract:**

```python
{
    "framework": "framework_name",
    "agents": [...],
    "workflows": [...],
    "planners": [...],
    "tools": [...],
    "prompts": [...],
    "memory": [...],
    "models": [...],
    "capabilities": [...],
    "relationships": [...],
    "discovery_method": "ast+config+regex_fallback",
    "parser_confidence": 0.85,
    "detection_evidence": ["imports:framework", "ast:calls"]
}
```

### 6. Multi-Parser Aggregation (`analysis/aggregation.py`)

Merges output from multiple framework parsers for the same file:

- **Artifact deduplication** — Named entities merged by name (case-insensitive)
- **Evidence accumulation** — Evidence strings merged across frameworks
- **Confidence arbitration** — Max confidence per artifact
- **Provenance tracking** — Records which frameworks contributed
- **Capability aggregation** — Merges capabilities by name+category, max confidence

### 7. Analyzers (`analyzers/*/analyzer.py`)

Each analyzer implements:

```python
class Analyzer:
    name = "analyzer_name"

    def run(self, file_cache, rules, agent_models=None): ...
```

**Current analyzers:**

| Analyzer | Purpose |
|----------|---------|
| `CapabilityAnalyzer` | Framework capability arbitration + regex fallback |
| `PromptAnalyzer` | Prompt injection, delimiter, system leak, role override |
| `DataLeakageAnalyzer` | API keys, tokens, passwords, env secrets |
| `MCPAnalyzer` | MCP config discovery, schema validation, security analysis |

### 8. MCP Analysis (`analyzers/mcp/`)

Multi-layer MCP analysis:

- **`schema.py`** — Versioned schema definitions (v1.0, v1.1)
- **`compatibility.py`** — Schema version resolution and data normalization
- **`validators.py`** — Spec-driven validation against schema rules
- **`analyzer.py`** — Discovery, security analysis, capability mapping

### 9. Trust Scoring (`scoring/engine.py`)

Deterministic scoring engine:

- **7 risk categories** with configurable weights
- **Severity point values** — Critical=25, High=15, Medium=8, Low=4, Info=1
- **Formula:** `category_score = clamp(100 - sum(weighted_contributions), 0, 100)`
- **Overall:** Average of all category scores
- **Explainability:** Per-category breakdown of contributions

### 10. Report Generators (`report/*.py`)

| Generator | Output | Format |
|-----------|--------|--------|
| `terminal.py` | Console summary | Plain text |
| `json_report.py` | Raw scanner output | JSON |
| `sarif.py` | SARIF 2.1.0 | JSON (SARIF) |
| `html.py` | HTML report | HTML (self-contained) |

---

## Data Flow

```
              ┌─────────────────────────────┐
              │       Project Directory      │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │      collect_files()         │
              │   .py, .json, .yaml, .yml   │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │   Dependency extraction      │
              │   (requirements.txt, etc.)   │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │  Semantic Document Builder   │
              │    (AST parsing per file)    │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │    Import Graph Builder      │
              │  (module + symbol resolution)│
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │    Framework Parsing         │
              │  (all parsers, all files)    │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │  Parser Aggregation          │
              │  (merge, dedup, arbitrate)   │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │   Analyzer Pipeline          │
              │  Capability │ Prompt │ MCP  │
              │  Data Leakage                │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │    Project Graph Builder     │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │   Trust Score Calculation    │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │     Report Generation        │
              │  Terminal │ JSON │ SARIF │HTML│
              └─────────────────────────────┘
```

---

## Plugin Architecture

Framework adapters follow a plugin-like pattern. Each adapter:

1. **Self-contained** — No cross-framework dependencies
2. **Auto-detection** — Implements `detect()` to determine applicability
3. **Structured output** — Returns a consistent dictionary schema
4. **Confidence-aware** — Reports parser-level confidence and discovery method

**To add a new framework adapter:**
1. Create `frameworks/new_framework/parser.py`
2. Implement `detect()` and `parse()` methods
3. Register in `engine/scan.py` parsers list

---

## Configuration Sources

SafeAI reads configuration from:

1. **Rule YAML files** — `rules/base_rules.yaml` (built-in) + custom via `--rules`
2. **Dependency manifests** — `requirements.txt`, `pyproject.toml`, `Pipfile`, `package.json`
3. **Source code** — Python files (`.py`)
4. **Configuration files** — `.json`, `.yaml`, `.yml`
5. **CLI arguments** — Output paths, thresholds, custom rules
