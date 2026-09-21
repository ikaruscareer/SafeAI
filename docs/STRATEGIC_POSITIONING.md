# Strategic Positioning

SafeAI is **Agent Authority Security for the Software Supply Chain**.
Technically, it is a *Static AI Capability & Risk Analyzer*.

> **Core product question:** what authority does this AI agent have, what
> changed, what evidence supports that conclusion, and should the change
> be allowed?

SafeAI does not try to answer "Is this AI safe?" No static scan can
certify a system as lawful, secure, or safe.

## Product model

- **DISCOVER** — what can the agent access or control?
- **COMPARE** — what changed from the approved baseline?
- **GOVERN** — should that change be allowed (`pass | review-required |
  block | accepted-exception`, with evidence)?

## Where SafeAI sits

```
Traditional AppSec (SAST / SCA / IaC security)
  → code, dependencies, infrastructure-as-code

SafeAI
  → agent authority + authority change
  → CI/CD decision + portable evidence

Runtime / AI security platforms
  → runtime enforcement, monitoring, adversarial testing
```

SafeAI scans agent source and configuration at commit time, before
deployment. It complements — never replaces — runtime guardrails,
evaluation frameworks, and red-teaming scanners: find the authority
change in code first, then validate at runtime.

## Adjacent categories (neutral landscape)

The following categories surround SafeAI's position. This list describes
*where SafeAI stops*, not what any specific product does — no claim is
made here about any vendor's capabilities.

- **Application-security platforms** (SAST/SCA/IaC): own code,
  dependency, and infrastructure-misconfiguration findings. SafeAI
  consumes none of their outputs and replaces none of them; agent
  authority is a different question from code vulnerability.
- **Cloud-security / exposure-management platforms**: own deployed
  asset inventory and cloud-permission posture. SafeAI never reads live
  IAM; repository IaC is evidence, not proof of deployed state.
- **AI red-teaming / evaluation harnesses** (e.g. prompt-injection and
  adversarial test tooling): own runtime adversarial testing. SafeAI's
  direction is to *export* capability-informed validation plans to such
  tools and link resulting evidence back — not to become one.
- **AI governance / GRC tooling**: own control workflows, attestations,
  and audit management. SafeAI produces portable evidence artifacts that
  such systems can consume; it is not a compliance suite and issues no
  compliance determinations.
- **MCP / agent-framework scanners**: overlap partially on
  configuration checks. SafeAI's durable asset is the authority model,
  evidence model, and change semantics — not adapter count.
- **SIEM / ticketing / observability**: own detection-response
  workflows. SafeAI exports findings (SARIF, JSON, webhooks in
  Corporate) rather than duplicating them.

## Boundary statements

- SafeAI proves no agent secure, compliant, or safe.
- Unknown (runtime IAM, deployed network policy, runtime identity) is an
  evidence state, not evidence of safety.
- Scores inform; deterministic policy decisions decide.
- Community Edition stays offline, local-first, and detection-complete;
  Corporate adds evidence, governance, and reconciliation on the same
  scanner — never a better scanner.

See `ROADMAP.md` (strategy and phases), `GOVERNANCE_AND_EDITIONS.md`
(edition boundary), and every report's assurance boundary block.
