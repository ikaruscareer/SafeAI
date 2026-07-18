# Good First Issues

Welcome, and thank you for considering contributing to SafeAI!

This document lists **40 beginner-friendly issues** designed for first-time contributors. Each issue includes the files you'll need to modify, the tests you should write, and the acceptance criteria.

> **For maintainers:** These issues are defined in `.github/good-first-issues/` as YAML templates. Run the [create-good-first-issues workflow](../../actions/workflows/create-good-first-issues.yml) to create them in the GitHub issue tracker with the `good first issue` label. Once created, this file serves as a curated index.

---

## Framework Adapters

### 1. Add Google ADK detector
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Description:** Detect the Google Agent Development Kit (ADK) by scanning Python imports (`from google.adk import`) and configuration files.
- **Suggested files:** `safeai/frameworks/google_adk/parser.py`
- **Suggested tests:** `tests/test_google_adk.py`
- **Suggested docs:** Update `FRAMEWORK_SUPPORT.md`, add entry to `README.md` supported frameworks table

### 2. Add Mastra detector
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/frameworks/mastra/parser.py`
- **Suggested tests:** `tests/test_mastra.py`

### 3. Add Haystack detector
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/frameworks/haystack/parser.py`
- **Suggested tests:** `tests/test_haystack.py`

### 4. Add AutoGen detector
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/frameworks/autogen/parser.py`
- **Suggested tests:** `tests/test_autogen.py`

### 5. Add n8n workflow detector
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/frameworks/n8n/parser.py`

### 6. Improve CrewAI parser — extract tool definitions
- **Difficulty:** Medium | **Effort:** 3–4 hours
- **Suggested files:** `safeai/frameworks/crewai/parser.py`
- **Suggested tests:** Extend `tests/test_parser_aggregation.py`

### 7. Improve LangGraph parser — detect conditional edges
- **Difficulty:** Medium | **Effort:** 3–4 hours
- **Suggested files:** `safeai/frameworks/langgraph/parser.py`

### 8. Add Dify detector
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/frameworks/dify/parser.py`

---

## Capability Detection

### 9. Detect Microsoft Teams integration
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/analyzers/capability/analyzer.py`, `safeai/analysis/capabilities.py`

### 10. Detect SharePoint access
- **Difficulty:** Easy | **Effort:** 2 hours

### 11. Detect OneDrive access
- **Difficulty:** Easy | **Effort:** 2 hours

### 12. Detect Docker capability
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/analyzers/capability/analyzer.py`, `safeai/analysis/capabilities.py`

### 13. Detect Kubernetes capability
- **Difficulty:** Easy | **Effort:** 2–3 hours

### 14. Detect Redis capability
- **Difficulty:** Easy | **Effort:** 2 hours

### 15. Detect S3 / cloud storage access
- **Difficulty:** Easy | **Effort:** 2 hours

### 16. Detect GCP / Google Cloud services
- **Difficulty:** Easy | **Effort:** 2 hours

### 17. Detect Slack integration
- **Difficulty:** Easy | **Effort:** 2 hours

### 18. Detect Jira integration
- **Difficulty:** Easy | **Effort:** 2 hours

### 19. Detect browser automation capability
- **Difficulty:** Easy | **Effort:** 2 hours

---

## Prompt Rules

### 20. Detect unsafe prompt instruction patterns
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `safeai/analyzers/prompt/analyzer.py`, `safeai/rules/base_rules.yaml`

### 21. Detect unrestricted instruction overrides
- **Difficulty:** Easy | **Effort:** 2 hours

### 22. Detect hidden system prompt injection
- **Difficulty:** Medium | **Effort:** 3–4 hours

### 23. Detect prompt extraction attempts
- **Difficulty:** Medium | **Effort:** 3–4 hours

---

## Governance Signals

### 24. Detect timeout configuration
- **Difficulty:** Easy | **Effort:** 2 hours

### 25. Detect retry policy configuration
- **Difficulty:** Easy | **Effort:** 2 hours

### 26. Detect approval workflow requirement
- **Difficulty:** Medium | **Effort:** 3–4 hours

### 27. Detect audit logging configuration
- **Difficulty:** Medium | **Effort:** 3–4 hours

### 28. Detect rate limiting configuration
- **Difficulty:** Easy | **Effort:** 2 hours

---

## Reports

### 29. Improve HTML report — add filtering and search
- **Difficulty:** Medium | **Effort:** 4–6 hours
- **Suggested files:** `safeai/report/html.py`

### 30. Improve SARIF output — add code flow
- **Difficulty:** Medium | **Effort:** 3–4 hours
- **Suggested files:** `safeai/report/sarif.py`

### 31. Add Markdown report generator
- **Difficulty:** Easy | **Effort:** 3–4 hours
- **Suggested files:** `safeai/report/markdown.py`

### 32. Improve JSON schema — add versioning
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `safeai/report/json_report.py`

### 33. Add dependency graph visualization in HTML
- **Difficulty:** Medium | **Effort:** 4–6 hours
- **Suggested files:** `safeai/report/html.py`

### 34. Add CSV report generator
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `safeai/report/csv_report.py`

---

## Documentation

### 35. Improve architecture diagram
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `ARCHITECTURE_FOR_CONTRIBUTORS.md`

### 36. Add framework-specific documentation page
- **Difficulty:** Easy | **Effort:** 3–4 hours

### 37. Improve installation guide for Windows users
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `USER_GUIDE.md`

### 38. Add FAQ with common troubleshooting scenarios
- **Difficulty:** Easy | **Effort:** 2–3 hours
- **Suggested files:** `USER_GUIDE.md`

### 39. Add glossary of terms
- **Difficulty:** Easy | **Effort:** 2 hours
- **Suggested files:** `GLOSSARY.md`

### 40. Create video or animated GIF guide for scan workflow
- **Difficulty:** Medium | **Effort:** 4–6 hours

---

## Detailed Templates

Each issue above has a corresponding YAML template in `.github/good-first-issues/` with the full description, acceptance criteria, and labels. Run the GitHub Actions workflow to create them all in the issue tracker at once.

## How to Claim an Issue

1. Find an issue in the [GitHub issue tracker](https://github.com/ikaruscareer/SafeAI/issues) labeled `good first issue`
2. Comment to let others know you're working on it
3. Ask questions if anything is unclear
4. Submit a draft PR early for feedback
5. Reference the issue in your PR description

**All first-time contributors are welcome.** If you're unsure where to start, pick the smallest issue that interests you and start there.
