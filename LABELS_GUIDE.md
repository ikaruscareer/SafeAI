# GitHub Labels Guide

These labels are used across the SafeAI repository to organize issues, pull requests, and discussions.

---

## Issue Type Labels

| Label | Color | Description |
|-------|-------|-------------|
| `bug` | `#d73a4a` | Something isn't working as expected |
| `enhancement` | `#a2eeef` | New feature or improvement request |
| `documentation` | `#0075ca` | Documentation improvements |
| `question` | `#d876e3` | User questions or support requests |
| `discussion` | `#c5def5` | Open-ended discussion topics |
| `research` | `#fef2c0` | Needs investigation or research before implementation |

---

## Component Labels

| Label | Color | Description |
|-------|-------|-------------|
| `framework` | `#bfdadc` | Related to framework adapters |
| `rule` | `#c2e0c6` | Related to detection rules |
| `analyzer` | `#d4c5f9` | Related to analyzer modules |
| `report` | `#ffd1dc` | Related to report generation |
| `mcp` | `#cce5ff` | Related to MCP analysis |
| `cli` | `#e6e6e6` | Related to CLI interface |
| `scoring` | `#ffeeba` | Related to trust scoring |
| `tests` | `#d4edda` | Related to testing infrastructure |

---

## Priority Labels

| Label | Color | Description |
|-------|-------|-------------|
| `priority/high` | `#ff0000` | Must be addressed soon |
| `priority/medium` | `#ffa500` | Should be addressed in current milestone |
| `priority/low` | `#008000` | Nice-to-have, no immediate urgency |

---

## Contributor Labels

| Label | Color | Description |
|-------|-------|-------------|
| `good first issue` | `#7057ff` | Beginner-friendly task for newcomers |
| `help wanted` | `#008672` | Extra attention is needed |
| `hacktoberfest` | `#ff7518` | Eligible for Hacktoberfest contributions |

---

## Status Labels

| Label | Color | Description |
|-------|-------|-------------|
| `blocked` | `#b60205` | Blocked by another issue or dependency |
| `duplicate` | `#cfd3d7` | Already exists |
| `wontfix` | `#ffffff` | Will not be addressed |
| `in-progress` | `#fbca04` | Someone is actively working on this |
| `needs-review` | `#fbca04` | Ready for maintainer review |
| `stale` | `#cfd3d7` | No activity for 60+ days |

---

## How to Apply Labels

### Maintainers
Apply labels when triaging issues. Use component labels to indicate which part of the codebase is affected.

### Contributors
You can suggest labels in your issue description. A maintainer will apply the appropriate ones.

---

## Label Combinations

Common combinations:

- `bug` + `framework` = bug in a framework adapter
- `enhancement` + `rule` = request for a new rule
- `good first issue` + `rule` = beginner-friendly rule task
- `good first issue` + `documentation` = beginner-friendly docs task
- `priority/high` + `bug` = critical bug to fix immediately
- `help wanted` + `framework` = looking for a framework adapter contributor
