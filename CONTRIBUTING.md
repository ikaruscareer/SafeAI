# Contributing to SafeAI

Welcome, and thank you for considering contributing to SafeAI.

SafeAI is a **community-driven Static AI Capability & Risk Analyzer** — think SonarQube for AI agents and workflows. We believe that making AI systems safer should be open, collaborative, and accessible to everyone.

This guide will help you get started, whether you're adding your first rule or building a complete framework adapter.

---

## Project Vision

SafeAI is intentionally:

- **Lightweight** — no external services, no runtime, no LLM calls
- **Environment agnostic** — works in any CI/CD pipeline, on any OS
- **CI/CD friendly** — SARIF output, exit codes, GitHub Actions ready
- **Plugin based** — frameworks, analyzers, and rules are all pluggable
- **Community driven** — built by and for the AI security community

Our mission: **The lightweight, open-source Static AI Capability & Risk Analyzer for CI/CD pipelines.**

---

## Quick Start for Contributors

```bash
git clone https://github.com/ikaruscareer/SafeAI.git
cd SafeAI
pip install -e ".[dev]"
```

---

## Development Workflow

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feat/my-contribution
   ```
3. **Make your changes** — keep them focused and small
4. **Run tests**:
   ```bash
   python -m pytest
   ```
5. **Lint your code**:
   ```bash
   ruff check .
   ```
6. **Commit** using conventional commits (see below)
7. **Push** and open a Pull Request

---

## Running Tests

```bash
# Run all tests
python -m pytest

# Run specific test file
python -m pytest tests/test_semantic.py

# Run with verbose output
python -m pytest -v

# Run with coverage
python -m pytest --cov=safeai
```

---

## Coding Standards

- Follow **PEP 8**
- Use **type hints** for all public functions and methods
- Keep functions small — one responsibility per function
- Prefer **clarity over cleverness**
- Avoid unnecessary abstractions
- Include **docstrings** for modules, classes, and public functions
- Use **f-strings** for string formatting

---

## Pull Request Process

1. Ensure all tests pass
2. Add tests for new functionality
3. Update documentation if needed
4. Fill out the PR template completely
5. Reference any related issues

### What reviewers look for:

- **Correctness** — does the code do what it claims?
- **Simplicity** — can it be simpler?
- **Security** — does it introduce new risks?
- **Test coverage** — are edge cases covered?
- **Documentation** — will contributors understand this next month?

---

## Commit Message Recommendations

Use [conventional commits](https://www.conventionalcommits.org/):

```
feat: add Docker capability detection
fix: correct false positive in prompt injection rule
docs: improve architecture documentation for contributors
test: add coverage for capability analyzer
refactor: simplify parser result merging
chore: update dependency versions
```

---

## Documentation Standards

- Keep explanations **simple and practical**
- Include **concrete examples** — not abstract descriptions
- Use **diagrams** where helpful (Mermaid preferred)
- Update documentation **in the same PR** as the code change
- Prefer **active voice** ("Run the scanner" not "The scanner should be run")

---

## Getting Help

- Open a [Discussion](https://github.com/ikaruscareer/SafeAI/discussions)
- Check [GOOD_FIRST_ISSUES.md](./GOOD_FIRST_ISSUES.md) for starter tasks
- Read [ARCHITECTURE_FOR_CONTRIBUTORS.md](./ARCHITECTURE_FOR_CONTRIBUTORS.md) to understand the codebase

---

## Code of Conduct

Be respectful, inclusive, and constructive. We welcome contributors of all backgrounds and experience levels.

---

Thank you for making AI safer — one contribution at a time.
