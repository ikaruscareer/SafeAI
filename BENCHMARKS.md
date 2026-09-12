# SafeAI Benchmarks — Evidence, Not Proof

## Purpose and non-claims

This corpus demonstrates, reproducibly, what SafeAI detects on pinned
fixtures, where it is expected to be uncertain, and whether accuracy
regresses between releases. It is **not** a claim of exhaustive
precision or recall, runtime security, compliance, or safe deployment.
There is no independently labeled representative sample here — results
are fixture pass rates plus documented false-positive/false-negative
observations.

## How to reproduce

```bash
python scripts/run_benchmarks.py --subset full
```

Offline, no fixture code executed, no network. Exit non-zero on any
expected-outcome regression. Corpus: `benchmarks/catalog.yml` (v1.0).
Runner: `scripts/run_benchmarks.py`. Per-fixture docs: `benchmarks/README.md`.

## Definitions

- **Expected finding** — a rule+severity the catalog pins for a fixture.
- **True positive (corpus sense)** — an expected finding that fired.
- **False positive** — a `negative` fixture firing at medium or above.
- **Known limitation** — an entry with intent `limitation`: recorded, never failing.
- **Regression** — a previously passing expectation that now fails (release blocker).

## Corpus (v1.0, 20 fixtures)

| ID | Intent | Target |
|---|---|---|
| claude-code-deny-allow | positive | Claude Code permission precedence |
| claude-code-wildcard | positive | Wildcard permission grant |
| mcp-golden-posture | positive | MCP posture + tool poisoning |
| mcp-poisoned-description | positive | Tool-description injection (synthetic) |
| mcp-clean-transport | positive | Insecure transport, no injection |
| action-risky-shell | positive | Shell execution + shell dataflow |
| action-medium-http | positive | Medium HTTP capability |
| action-clean-negative | negative | Benign agent, stays quiet |
| governance-suppression-quiet | negative | Suppression-adjacent config stays info-only |
| crewai-delegation | positive | CrewAI recognition + approval gap |
| langgraph-conditional | positive | LangGraph recognition |
| langchain-tools | positive | LangChain recognition |
| runaway-loop-governance | regression | Iteration/recursion guards (v2.0.0) |
| dataflow-shell-flow | positive | Casing-robust flow matching |
| n8n-workflow | positive | n8n recognition + approval gap |
| semantic-kernel-validation | positive | Tool validation gap |
| llamaindex-rag | positive | RAG/database recognition |
| esc-mcp-read-to-mutate | escalation | Read-only → mutating MCP server |
| esc-mcp-server-added | escalation | New MCP server binding |
| mcp-attribution-limitation | limitation | MCP-only configs lack framework attribution |

## Results

| SafeAI | Corpus | Pass | Fail | Notes |
|---|---|---|---|---|
| 2.2.1 | v1.0 (20) | 19 | 0 | 1 limitation note (mcp-attribution-limitation); full corpus ~1s |
| 2.2.0 | v1.0 (20) | 19 | 0 | 1 limitation note (mcp-attribution-limitation); full corpus ~1s |
| 2.1.2 | v1.0 (20) | 19 | 0 | 1 limitation note (mcp-attribution-limitation); full corpus ~1s |

Breakdown at 2.2.1: framework recognition 8/8 applicable; capability
detection pinned on 4 fixtures; escalation detection 2/2; governance
detection via `GOV_*` pins on crewai/runaway-loop; negative controls 2/2
quiet. Raw payload: `benchmarks/results/2.2.1.json`.

## Warning

Fixture pass rates measure the scanner against itself on pinned inputs.
They say nothing about real-world recall, adversarial robustness,
runtime behavior, or compliance. Do not cite them as such.
