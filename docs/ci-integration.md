# CI Integration Guidance

SafeAI can be used as a review gate for changes to an agent's declared capabilities, prompts, tools, and MCP configuration. The safest CI pattern is to scan the same manifest that will be deployed and to make the report available as a build artifact.

## Recommended pipeline

Run a baseline scan on the default branch, store the approved baseline as a reviewed artifact, and compare pull requests against that baseline. A pull request should fail only when it introduces a new or regressed finding according to the repository's chosen policy. This keeps existing technical debt visible without making every unrelated change impossible to merge.

## Review boundaries

A generated report is evidence for review, not a substitute for review. Teams should decide which findings are blocking, which require a human acknowledgement, and which are informational. Keep secrets out of manifests and configure CI logs so that tokens and private prompts cannot be echoed accidentally.

## Reproducibility

Pin the SafeAI version used by CI, record the input manifest path, and publish the machine-readable report alongside the human-readable summary. When a policy changes, update the baseline in a separate pull request so the reason for the change remains visible.
