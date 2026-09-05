# SafeAI — Tier 1 Adoption Report (August 30, 2026)

## Executive Summary

| Metric | Value | Source |
|--------|-------|--------|
| GitHub Stars | 20 | GitHub repo page |
| GitHub Forks | 10 | GitHub repo page |
| Open Issues | 11 | GitHub repo page |
| Commits | 117 | GitHub repo page |
| Release Age | ~43 days (Jul 18 → Aug 30) | GitHub repo creation |
| PyPI Releases | 4 (v1.6.0, v1.7.0, v1.8.0, v1.9.0) | PyPI API |
| PyPI Downloads (last 18d) | 453 (without mirrors) | pypistats.org |
| PyPI Downloads (last 18d) | 1,425 (with mirrors) | pypistats.org |
| Framework Coverage | 16 frameworks | README.md |
| Built-in Rules | 76 rules (8 GOV_*, 14 escalation) | base_rules.yaml |
| Test Suite | 608 passing, 1 skipped | pytest |
| Open Issues (GitHub) | 11 | GitHub repo page |
| Merged PRs | 8+ (from issue/PR history) | GitHub |
| GitHub Topics | agent-security, agentic-ai, ai-security, devsecops, owasp, prompt-injection, sarif | GitHub topics page |

---

## GitHub Signal

### Repository Stats
- **Stars**: 20
- **Forks**: 10
- **Watchers**: 0
- **Open Issues**: 11
- **Open PRs**: 0 (clean merge queue)
- **Commits**: 117
- **Default branch**: main
- **License**: Apache-2.0
- **Created**: 2026-07-18

### Topic Tags
SafeAI is listed under:
- `agent-security`, `agent-security-scanner`
- `agentic-ai`, `agentic-ai-security`
- `ai-security`, `ai-security-governance`, `ai-security-tool`
- `devsecops`
- `owasp`, `owasp-llm-top-10`
- `prompt-injection`
- `sarif`, `sarif-reports`
- `security-scanner`

### GitHub Topics Presence
SafeAI appears on the **ai-security-tool** topic page alongside:
- `trnt-ai/trent-openclaw-security-assessment`
- `MaazAhmed47/Interlock`
- `Mikacr1138/claude-bug-bounty`
- `ASCIT31/Dark-Moon`
- `GH05TCREW/pentestagent`
- `cosai-oasis/secure-ai-tooling`
- `vdalal/agentx-security-sdk`
- `HPBhoir/AgentSecBench`
- `votal-ai-hq/wb-red-team`

---

## PyPI Distribution

### Package Info
- **Package name**: `SafeAI-Static-Analyzer`
- **Latest version**: 1.9.0
- **Release date**: 2026-08-30 00:04:17 UTC
- **Python**: >=3.11
- **License**: Apache-2.0
- **Status**: 5 - Production/Stable
- **Wheel size**: 244 KB
- **Sdist size**: 276 KB
- **Dependencies**: PyYAML>=6.0.3 (runtime only)

### Release History
| Version | Release Date | PyPI Wheel | Sdist |
|---------|-------------|------------|-------|
| 1.9.0 | 2026-08-30 | 244 KB | 276 KB |
| 1.8.0 | 2026-08-23 | 225 KB | 250 KB |
| 1.7.0 | 2026-08-18 | — | — |
| 1.6.0 | 2026-08-13 | 204 KB | 217 KB |

All releases published via GitHub Actions PyPI publish workflow (no manual uploads).

### Download Stats (Aug 11–28, 2026)

**Without mirrors (real unique installs)**:
| Date | Downloads | Notes |
|------|-----------|-------|
| Aug 11 | 85 | |
| Aug 12 | 17 | |
| Aug 13 | 156 | v1.6.0 release day |
| Aug 14 | 4 | |
| Aug 15 | 10 | |
| Aug 16 | 0 | (no data) |
| Aug 17 | 2 | |
| Aug 18 | 8 | |
| Aug 19 | 2 | |
| Aug 20 | 6 | |
| Aug 21 | 2 | |
| Aug 22 | 2 | |
| Aug 23 | 94 | v1.8.0 release day |
| Aug 24 | 18 | |
| Aug 25 | 9 | |
| Aug 26 | 6 | |
| Aug 27 | 8 | |
| Aug 28 | 24 | |
| **Total** | **453** | |

**With mirrors (includes CDN/bot traffic)**:
| Date | Downloads |
|------|-----------|
| Aug 11 | 300 |
| Aug 13 | 430 |
| Aug 23 | 258 |
| Aug 24 | 96 |
| Aug 28 | 43 |
| **Total** | **1,425** |

### Download-to-Star Ratio
- 453 real installs / 20 stars = **22.7 installs per star**
- This ratio is **strong** for a security tool — indicates real usage beyond "drive-by stargazing"

---

## GitHub Actions Marketplace

### Action Published
- **Marketplace listing**: [Available on GitHub Marketplace](https://github.com/marketplace/actions/safeai-static-analysis)
- **Badge**: Present in README.md
- **Uses**: `ikaruscareer/SafeAI@v1.0.0`
- **Type**: Composite action (pure Python driver)

### Action Inputs (8)
`path`, `version`, `fail-on`, `sarif`, `rules`, `baseline`, `fail-on-new`, `fail-on-escalation`, `no-registry`, `extra-args`

### Action Outputs (1)
`sarif-path`

### CI/CD Integration Examples
- GitHub Actions (Marketplace action + manual workflow)
- GitLab CI
- Azure DevOps
- Capability escalation gating with PR comments

---

## Community Engagement

### Issues & PRs
- **Open Issues**: 11
- **Open PRs**: 0 (clean merge queue)
- **Closed GFIs reviewed**: 11 (all examined, 1 gap found and fixed)
- **New Issues Created**: #93 (GFI), #94 (enhancement), #95 (GFI), #96 (GFI)

### Contributors
| Contributor | Contributions |
|-------------|---------------|
| @Aming9303 | `safeai registry components` CLI (#82), `safeai init` command (#83), GitHub Actions workflow example (#84) |
| @ikaruscareer | Core maintainer, all other commits |

### Blog Post / External Coverage
- **ikaruscareer.com** (Jul 26, 2026): "From an Idea to an Open-Source Community: Building SafeAI Together" — describes the project philosophy, community-building approach, and technical capabilities
- Covers: static analysis for AI, offline-first design, capability escalation detection, community-driven development

### OpenSSF Scorecard
- Badge present in README.md
- Best Practices badge present (bestpractices.dev/projects/14126)

---

## Competitive Landscape

SafeAI sits in a growing space of AI agent security tools. Key differentiators from the topic page competitors:

| Differentiator | SafeAI | Typical Competitor |
|----------------|--------|-------------------|
| Static analysis (at rest) | Yes | Often runtime-only |
| Offline-first | Yes | Often requires cloud |
| Framework coverage | 16 | 1-3 |
| Capability escalation detection | Yes (14 rules) | Rare |
| KYA shared registry | Yes | No |
| GitHub Marketplace action | Yes | No |
| OWASP/NIST mappings | Yes | Rare |
| SARIF output | Yes | Sometimes |

---

## What's Working

1. **Release velocity**: 4 releases in 17 days (Aug 13 → Aug 30) shows active development
2. **PyPI automation**: All releases via GitHub Actions, no manual uploads
3. **Download momentum**: 453 real installs in 18 days, with clear spikes on release days
4. **Clean PR queue**: 0 open PRs means community contributions are being merged
5. **Topic visibility**: Listed on `ai-security-tool`, `agent-security`, `prompt-injection` GitHub topics
6. **Marketplace action**: Published and documented with version pinning guidance
7. **Test coverage**: 608 passing tests, comprehensive framework fixtures
8. **Documentation depth**: 20+ markdown files covering architecture, rules, frameworks, capabilities, testing, contributing

---

## Gaps & Risks

| Gap | Impact | Recommendation |
|-----|--------|----------------|
| 20 stars / 10 forks | Low social proof | Continue community outreach; the download-to-star ratio (22.7x) suggests real usage exceeds star count |
| 0 watchers | No passive observers | Add "Watch" CTA to README and blog post |
| AutoGen appears twice in README table | Minor quality issue | Fix duplicate row in README.md |
| v1.7.0 release not tagged on GitHub | Inconsistent release tracking | Tag v1.7.0 if release was published |
| No dependents/public repos found | No adoption proof | Track GitHub "Used by" once repos start referencing SafeAI |
| Single contributor (@Aming9303) | Bus factor risk | Continue GFI program, evangelize at conferences/meetups |
| No external blog coverage | Limited awareness | Submit to AI security newsletters, Reddit r/netsec, Hacker News |
| No comparison to competitors | Hard to evaluate | Add "How SafeAI compares to X" section in README or docs |

---

## Tier 1 Summary

| Category | Grade | Evidence |
|----------|-------|----------|
| **Distribution** | A | PyPI published, 453 installs, automated releases |
| **GitHub Signal** | B+ | 20 stars, 10 forks, 117 commits, clean PR queue |
| **Community** | B | 1 external contributor, 11 open issues, active GFI program |
| **CI/CD Integration** | A | Marketplace action, 3 CI platform examples, SARIF |
| **Documentation** | A+ | 20+ docs, comprehensive rules/frameworks/capabilities references |
| **Testing** | A | 608 tests, framework fixtures, CI validation |
| **Overall Tier 1** | **A-** | Strong foundations, early-stage community growth |

---

## Next Steps (Community Growth)

1. **Hacker News "Show HN" post** — "Show HN: SafeAI – Static security analyzer for AI agents"
2. **Reddit r/netsec** — "I built a static analyzer for AI agent security risks"
3. **AI security newsletter outreach** — TLDR AI, Ben's Bites, AI Security Newsletter
4. **Conference talks** — AI Engineer Summit, BSides, OWASP meetups
5. **Competitive comparison page** — "SafeAI vs [X]" in README
6. **GitHub Discussions** — Enable for Q&A and community
7. **"Used by" tracking** — Monitor GitHub dependents once public repos adopt

---

*Report generated: 2026-08-30*
*Data sources: GitHub API, PyPI API, pypistats.org, ikaruscareer.com blog*
