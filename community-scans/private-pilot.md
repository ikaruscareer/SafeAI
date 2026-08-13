# Community Scan Private Pilot

Status: private pilot only. No schedule is enabled and no public report is automatically published.

## Implementation baseline

This branch hardens the Community Scan workflow against the current SafeAI `main` implementation.

- SafeAI release: `v1.6`
- Marketplace Action ref: `ikaruscareer/SafeAI@v1.6`
- Immutable Action commit: `fef9781e3a68ba591448aa18e9d2f299b3869589`
- Target checkout: shallow, read-only, `persist-credentials: false`
- Registry: disabled with `no-registry`
- Target code: never executed
- Target dependencies, tests, workflows, setup scripts, and Dockerfiles: never run

The repository does not currently expose a `v1` tag. The workflow therefore uses the published `v1.6` release by immutable commit and records the release ref and commit in every manifest.

## Targets and point-in-time resolutions

These are review-time resolutions, not permanent popularity rankings. The workflow resolves the configured default ref again at each run and records the result in the target manifest.

| Target | Repository | Configured ref | Review-time resolved SHA |
|---|---|---|---|
| n8n | `n8n-io/n8n` | `master` | `cbb55770537b0874f684dab9dda992d461bd577a` |
| LangChain | `langchain-ai/langchain` | `master` | `3c6c3ba7bffe12248030c565038d1060b4d0556d` |
| LlamaIndex | `run-llama/llama_index` | `main` | `a2b8ee27b20c834d1963c1b93316635ae0499a5e` |
| CrewAI | `crewAIInc/crewAI` | `main` | `27083f41319a7d71d4c65d541c558d79ad2a30a1` |
| LangGraph | `langchain-ai/langgraph` | `main` | `644815f9e5bc52ad8f7a5227a456227e9c3e639b` |

## Workflow controls

- Trigger: manual `workflow_dispatch` only.
- Default mode: `private`.
- Optional single-target dispatch is supported; `all` runs the five-target matrix.
- Matrix jobs use `fail-fast: false` so one target does not hide another result.
- Workflow permissions are limited to `contents: read`.
- Third-party Actions are pinned to full commit SHAs.
- No `contents: write`, pull-request write, issue write, repository administration, cloud, or Reddit credentials are requested.
- No forks, target issues, pull requests, comments, releases, or Reddit API calls are performed.

## Outputs

Each target produces raw JSON, SARIF, HTML, Markdown scorecard, JSON scorecard, a provenance manifest, a sanitised summary, a Reddit draft, and a private maintainer-notification draft. Raw reports and notification drafts are uploaded as private-pilot artifacts. Manifests and sanitised summaries are uploaded as public-review artifacts for human review only.

Artifact naming is target-specific. GitHub artifact visibility is still controlled at the workflow-run/repository-access level; separate artifact names are organizational separation, not an independent confidentiality boundary.

## Finding handling

SafeAI severity is not treated as confirmed exploitability. Findings are classified as informational, review-recommended, high-confidence security concern, potentially sensitive, or not publishable. Secrets, personal data, private endpoints, exploit chains, weaponisable evidence, and unvalidated sensitive configuration are withheld from public summaries.

Public language must remain limited to statements such as:

> SafeAI identified a finding requiring maintainer review.

A finding that requires runtime validation remains `review_recommended`.

## Pilot gates before public reporting

Before enabling a schedule or using a public-report mode, a human reviewer must confirm:

1. All five scans complete with exact resolved commit SHAs.
2. Raw and sanitised outputs are reproducible at those SHAs.
3. Secret and Markdown sanitisation tests pass.
4. Sensitive findings are withheld correctly.
5. At least one maintainer-notification draft has been reviewed privately.
6. Security-policy URLs and disclosure contacts have been checked manually.
7. The first public summary for each target is explicitly approved.

Reddit drafts are generated only for human review. Publication, maintainer notification, correction, and removal are manual operations outside this workflow.

## Assurance boundary

SafeAI can inspect source and repository-local configuration evidence, but cannot verify deployed IAM permissions, runtime identity, network policy, or actual runtime behavior. SafeAI scan results are automated static-analysis observations, not proof of exploitability and not a substitute for a maintainer-led security review.