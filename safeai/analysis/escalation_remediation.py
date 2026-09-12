"""Structured remediation for authority escalations (ChangeGuard).

Every ``ESC_*`` rule in :mod:`safeai.analysis.escalation` gets one entry:

* ``summary`` — one line, safe to render in PR comments.
* ``why_it_matters`` — the authority implication in plain language.
* ``review_questions`` — what a reviewer must answer before approving.
* ``recommended_actions`` — minimum safer actions (review/restrict/verify
  language; never auto-fix instructions, never patch diffs).
* ``safe_configuration_patterns`` — deterministic, framework-neutral
  patterns a reviewer can recognize (not code to paste).
* ``limitations`` — what static analysis did and did not verify.

SafeAI proposes remediation; it never modifies code, opens pull requests,
calls APIs, or claims a suggestion is universally correct. No source
values or secret values appear here — all strings are static prose.
"""

from __future__ import annotations

_STATIC_LIMIT = (
    "Static analysis cannot confirm the runtime identity, IAM role, "
    "deployed network policy, or actual tool execution."
)

REMEDIATION = {
    "ESC_SHELL_ADDED": {
        "summary": "Remove shell execution or gate it behind approval.",
        "why_it_matters": (
            "A tool that previously could not run commands can now execute "
            "arbitrary shell or code. A compromised instruction path can turn "
            "this into full host control."
        ),
        "review_questions": [
            "Is shell execution required for this tool's intended purpose?",
            "Which commands must it run — can they be an explicit allowlist?",
            "Is a human approval step required before execution?",
        ],
        "recommended_actions": [
            "Remove shell execution if the tool can work without it.",
            "Restrict to an explicit command allowlist with argument validation.",
            "Require human approval before execution in production profiles.",
        ],
        "safe_configuration_patterns": [
            "No shell capability; or allowlisted commands with validated arguments and an approval gate.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_ACCESS_MODE_INCREASED": {
        "summary": "Confirm the widened access is intended and scoped.",
        "why_it_matters": (
            "A capability moved up the access ladder "
            "(none < read < write < mutate < execute). Broader authority means "
            "a misdirected plan can change more state."
        ),
        "review_questions": [
            "Which change required the wider access mode?",
            "Is the widened mode the minimum the task needs?",
        ],
        "recommended_actions": [
            "Confirm the wider mode is intentional and scoped to the task.",
            "Split the tool if one operation needs write while others need read.",
            "Record the justification in the PR or policy exception.",
        ],
        "safe_configuration_patterns": [
            "Each tool holds the minimum access mode its documented purpose needs.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_FILESYSTEM_WRITE_ADDED": {
        "summary": "Scope filesystem writes to explicit paths.",
        "why_it_matters": (
            "The agent can now modify files. Unscoped writes risk config "
            "corruption, log tampering, or planting executable content."
        ),
        "review_questions": [
            "Which directories must the agent write to?",
            "Are read-only paths separated from writable ones?",
        ],
        "recommended_actions": [
            "Restrict writes to explicit directories.",
            "Keep credentials, configs, and code paths read-only.",
            "Add an approval step before writes outside the sandbox.",
        ],
        "safe_configuration_patterns": [
            "Writable paths enumerated; everything else read-only or unreachable.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_EXTERNAL_ACCESS_ADDED": {
        "summary": "Confirm each new external endpoint is intended.",
        "why_it_matters": (
            "New HTTP/API reach expands the exfiltration and supply-chain "
            "surface: data can now leave to a destination it could not reach "
            "before."
        ),
        "review_questions": [
            "Which endpoints were added and why?",
            "What data may be sent to each endpoint?",
        ],
        "recommended_actions": [
            "Allowlist the required endpoints; deny the rest.",
            "Verify request payloads carry no secrets or PII beyond necessity.",
            "Add timeouts and retry bounds to new external calls.",
        ],
        "safe_configuration_patterns": [
            "Explicit endpoint allowlist with bounded retries and timeouts.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_MCP_SERVER_ADDED": {
        "summary": "Review the new MCP server's identity and permissions.",
        "why_it_matters": (
            "A new MCP server extends the agent's authority to a new service. "
            "Its transport, authentication, and tool permissions are now part "
            "of the trust boundary."
        ),
        "review_questions": [
            "Is the server's transport (stdio vs remote) appropriate?",
            "Is authentication configured and least-privilege?",
            "Which tools does it expose, and are all of them needed?",
        ],
        "recommended_actions": [
            "Pin the server identity (command path or endpoint) explicitly.",
            "Configure authentication; remove wildcard permissions.",
            "Disable unneeded tools or resources on the server.",
        ],
        "safe_configuration_patterns": [
            "Pinned server identity, authenticated transport, least-privilege tool set.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_MCP_READ_TO_MUTATE": {
        "summary": "Restrict the new mutating operations or add approval.",
        "why_it_matters": (
            "A previously read-only MCP server now exposes mutating "
            "operations. A compromised instruction path or overly broad plan "
            "can now change external state."
        ),
        "review_questions": [
            "Are the mutating operations required for this agent's purpose?",
            "Is a human approval boundary required before mutation?",
            "Are server identity, transport, and auth constraints explicit?",
        ],
        "recommended_actions": [
            "Restrict the tool allowlist to the minimum mutating operations.",
            "Require approval before destructive or financial mutations.",
            "Bind authentication and destination scope to the specific service.",
        ],
        "safe_configuration_patterns": [
            "Read-only by default; mutating tools individually allowlisted with approval.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_APPROVAL_GATE_REMOVED": {
        "summary": "Restore the human-approval gate or document its replacement.",
        "why_it_matters": (
            "The last human checkpoint before a side effect is gone. The "
            "agent can now act on its own judgment where a person used to "
            "confirm."
        ),
        "review_questions": [
            "What replaces the removed gate, if anything?",
            "Which side effects are now ungated?",
        ],
        "recommended_actions": [
            "Restore the approval gate, or record an accepted-exception with owner and expiry.",
            "Verify remaining gates still cover destructive operations.",
            "Add audit logging for ungated actions if the removal stands.",
        ],
        "safe_configuration_patterns": [
            "Every mutating/executing tool path passes an approval checkpoint or a recorded exception.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_MEMORY_SCOPE_EXPANDED": {
        "summary": "Confirm the broadened memory scope and retention.",
        "why_it_matters": (
            "Wider memory/RAG scope means more data — possibly sensitive — is "
            "retrievable into future prompts, increasing leakage and "
            "poisoning surface."
        ),
        "review_questions": [
            "What new data sources entered the memory scope?",
            "What is the retention and redaction policy for stored content?",
        ],
        "recommended_actions": [
            "Limit retrieval scope to the task's data sources.",
            "Confirm secrets and PII are excluded or redacted.",
            "Review retention windows for stored conversation and documents.",
        ],
        "safe_configuration_patterns": [
            "Scoped retrieval sources with redaction and bounded retention.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_WRITE_TOOL_ADDED": {
        "summary": "Review the new write-capable tool's necessity and scope.",
        "why_it_matters": (
            "A brand-new tool with write-level authority appeared. New tools "
            "have no review history, so their scope deserves explicit scrutiny."
        ),
        "review_questions": [
            "What task requires this new tool?",
            "What is the blast radius of its write operations?",
        ],
        "recommended_actions": [
            "Confirm the tool is necessary; remove it otherwise.",
            "Scope its inputs and destinations to the documented task.",
            "Add the tool to the appropriate policy profile.",
        ],
        "safe_configuration_patterns": [
            "New tools start narrowly scoped and gain authority only by reviewed change.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_NEW_EXTERNAL_DESTINATION": {
        "summary": "Verify the new write destination and what may flow to it.",
        "why_it_matters": (
            "Agent output can now reach a new external destination. Each new "
            "sink is a potential exfiltration path."
        ),
        "review_questions": [
            "Who operates the destination and under what terms?",
            "What data categories may be written there?",
        ],
        "recommended_actions": [
            "Confirm the destination is intended and documented.",
            "Restrict payload to the minimum data the task needs.",
            "Ensure audit logging covers writes to the new destination.",
        ],
        "safe_configuration_patterns": [
            "Enumerated destinations with payload minimization and audit coverage.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_AUTONOMY_INCREASED": {
        "summary": "Bound the new autonomous planning with limits and checkpoints.",
        "why_it_matters": (
            "Planner/delegation capability joined a tool with side effects. "
            "The agent can now chain actions toward goals with less oversight."
        ),
        "review_questions": [
            "What bounds the planner: iterations, depth, timeouts?",
            "Where are the human checkpoints in multi-step plans?",
        ],
        "recommended_actions": [
            "Add iteration/depth/timeout bounds to autonomous loops.",
            "Require approval before high-impact plan steps.",
            "Log plans and tool calls for post-hoc review.",
        ],
        "safe_configuration_patterns": [
            "Bounded autonomy: limits plus checkpoints plus audit trail.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_COMBO_UNTRUSTED_INPUT_SHELL": {
        "summary": "Break the untrusted-input-to-shell path or sandbox it.",
        "why_it_matters": (
            "Untrusted input can reach shell execution in the current state. "
            "This is the classic injection-to-compromise chain."
        ),
        "review_questions": [
            "Which input source is untrusted, and can it be validated?",
            "Is there any sanitization between input and shell?",
        ],
        "recommended_actions": [
            "Validate and sanitize all untrusted input before shell use.",
            "Prefer argument arrays over shell strings; avoid shell=True.",
            "Sandbox execution and require approval for shell steps.",
        ],
        "safe_configuration_patterns": [
            "No untrusted bytes reach a shell without validation and an approval boundary.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_COMBO_AUTONOMY_BROAD_DATA": {
        "summary": "Scope data access for the autonomous planner.",
        "why_it_matters": (
            "An autonomous planner combined with broad data access can "
            "exfiltrate or corrupt far more than a single-step tool — and do "
            "it without asking."
        ),
        "review_questions": [
            "Does the planner need all reachable data sources?",
            "What stops a misdirected plan from reading sensitive stores?",
        ],
        "recommended_actions": [
            "Restrict the planner's data sources to the task at hand.",
            "Separate sensitive stores from planner-reachable retrieval.",
            "Add approval before plans touch sensitive data.",
        ],
        "safe_configuration_patterns": [
            "Planners see task-scoped data; sensitive stores need explicit approval.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
    "ESC_COMBO_DELEGATION_EXTERNAL_SIDE_EFFECT": {
        "summary": "Constrain delegated authority over external effects.",
        "why_it_matters": (
            "Delegation combined with external writes lets subagents act on "
            "outside systems with the parent's authority — a confused-deputy "
            "shape."
        ),
        "review_questions": [
            "What authority does each delegate actually need?",
            "Can a delegate trigger external effects the parent never reviewed?",
        ],
        "recommended_actions": [
            "Give delegates the minimum authority for their subtask.",
            "Require parent or human approval for external side effects.",
            "Log delegation chains with the originating intent.",
        ],
        "safe_configuration_patterns": [
            "Least-privilege delegates; external effects approved at the parent level.",
        ],
        "limitations": [_STATIC_LIMIT],
    },
}

#: Rules covered — must equal the rule table in escalation.py.
COVERED_RULE_IDS = frozenset(REMEDIATION)


def remediation_for(rule_id):
    """Return the structured remediation dict for an escalation rule ID.

    Returns a copy so renderers cannot mutate the catalog. Unknown IDs
    yield a generic least-privilege entry (never ``None``) so every
    escalation renders *something* actionable.
    """
    entry = REMEDIATION.get(str(rule_id))
    if entry is None:
        return {
            "summary": "Review this authority change before approving.",
            "why_it_matters": (
                "An authority change was detected that has no specific "
                "guidance entry."
            ),
            "review_questions": ["Is this authority change intended?"],
            "recommended_actions": [
                "Confirm the change is intentional and scoped to the task.",
            ],
            "safe_configuration_patterns": [],
            "limitations": [_STATIC_LIMIT],
        }
    return {
        "summary": entry["summary"],
        "why_it_matters": entry["why_it_matters"],
        "review_questions": list(entry["review_questions"]),
        "recommended_actions": list(entry["recommended_actions"]),
        "safe_configuration_patterns": list(entry["safe_configuration_patterns"]),
        "limitations": list(entry["limitations"]),
    }
