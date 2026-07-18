# Community Projects

Ideas for recurring community initiatives to grow SafeAI's ecosystem.

---

## Framework of the Month

Each month, the community focuses on adding or improving support for one AI framework.

**Format:**
- Month 1: AutoGen
- Month 2: Haystack
- Month 3: Dify
- Month 4: Mastra

**How it works:**
- Create a tracking issue for the framework
- Break into sub-tasks: parser, analyzer, tests, docs
- Celebrate completion with a release blog post

---

## Rule of the Month

Each month, the community defines and implements one high-impact detection rule.

**Format:**
- Month 1: Detect prompt extraction attempts
- Month 2: Detect hardcoded cloud credentials
- Month 3: Detect excessive tool permissions

**How it works:**
- Discussion thread to define the rule
- Implementation PR
- Test fixtures and documentation

---

## Capability Challenge

A sprint to add capability detection for a specific category.

**Example:**
- "Cloud Capability Month" — add AWS, Azure, GCP, Kubernetes, Docker detection
- "Communication Capability Month" — Slack, Teams, Email, Discord detection

**Goal:** Add 5+ capability patterns in one sprint.

---

## MCP Challenge

Focus on improving MCP (Model Context Protocol) analysis.

**Tasks:**
- Add support for new MCP schema versions
- Improve endpoint validation
- Add MCP tool risk classification
- Create MCP security best-practices guide

---

## Agent Zoo

A community-curated collection of open-source AI agents, each with a SafeAI scan report.

**Goal:** Create a public gallery showing SafeAI results for real-world agents.

**How it works:**
- Community submits agent repositories
- SafeAI scans them
- Results are published with permission

---

## False Positive Hunt

A regular event where contributors find and fix false positive detections.

**How it works:**
- Create test fixtures that should NOT trigger findings
- Run SafeAI against them
- Fix any false positives found
- Document patterns that cause false positives

---

## Documentation Sprint

A focused effort to improve project documentation.

**Tasks:**
- Review all docs for accuracy
- Add missing examples
- Improve architecture diagrams
- Create video tutorials
- Translate to other languages

---

## Student Projects

Ideas suitable for university capstone projects or research:

- **Interprocedural dataflow analysis** for taint tracking in agent pipelines
- **Agent behavioral fingerprinting** from static analysis
- **MCP protocol fuzzing** configuration validator
- **Multi-language support** (TypeScript, Java agents)
- **VS Code extension** for real-time scanning

---

## Hacktoberfest

SafeAI participates in Hacktoberfest annually.

**Preparation:**
- Tag 20+ issues with `hacktoberfest` label
- Create beginner-friendly tasks
- Write contributor guides
- Set up a Discord channel for participants

---

## Google Summer of Code

Potential GSoC project ideas:

- **AI Agent Security Benchmark** — a benchmark suite for static AI risk analysis
- **Plugin System for SafeAI** — extend the architecture with a proper plugin API
- **Visual Studio Code Extension** — integrate SafeAI into the IDE
- **Cross-Language Agent Analysis** — detect agents in TypeScript, Java, Go

---

## Starting a Community Project

1. Open a Discussion with your idea
2. Gauge interest from other contributors
3. Create a tracking issue with sub-tasks
4. Announce on social media
5. Ship it

---

We encourage community members to lead these initiatives. If you want to run a Framework of the Month or lead a Documentation Sprint, let us know.
