"""Failure-class coverage matrix — groups GOV_* findings by failure class.

Not new detection logic: it is a view layer over existing GOV_* findings
that shifts the operator question from "which rules fired?" to "which
failure modes can this agent survive?"

Each failure class maps to one or more GOV_* rule IDs. A class is
"covered" if none of its associated rules appear in the findings; it is
"uncovered" if any of its rules fired.
"""

# Maps failure class → (description, list of GOV_* rule IDs that address it)
FAILURE_CLASSES = {
    "Dependency timeout": (
        "Agent tool may hang or block indefinitely without timeout/retry.",
        ["GOV_TIMEOUT_MISSING", "GOV_RETRY_MISSING"],
    ),
    "Dependency unavailable": (
        "Agent tool may fail permanently if a downstream service is unreachable.",
        ["GOV_CIRCUIT_BREAKER_MISSING", "GOV_HEALTH_CHECK_MISSING"],
    ),
    "Resource exhaustion": (
        "Agent tool may consume unbounded resources (tokens, API calls, compute).",
        ["GOV_RATE_LIMIT_MISSING", "GOV_BACKPRESSURE_MISSING", "GOV_MAX_ITERATIONS_MISSING"],
    ),
    "Cascading failure": (
        "Agent tool failure may cascade to other tools or services without backpressure.",
        ["GOV_CIRCUIT_BREAKER_MISSING", "GOV_BACKPRESSURE_MISSING"],
    ),
    "Unbounded recursion": (
        "Agent may enter unbounded recursive calls without depth limits.",
        ["GOV_RECURSION_GUARD_MISSING"],
    ),
    "Missing accountability": (
        "Agent actions may lack audit trail or human approval.",
        ["GOV_AUDIT_MISSING", "GOV_APPROVAL_MISSING"],
    ),
}


def build_failure_class_matrix(findings):
    """Build a failure-class coverage matrix from GOV_* findings.

    Parameters
    ----------
    findings : list[dict]
        The full findings list from a scan.

    Returns
    -------
    list[dict]
        One entry per failure class, each with:
        - ``failure_class``: the class name
        - ``description``: what the failure mode means
        - ``covered_rules``: GOV_* rule IDs that fired for this class
        - ``uncovered_rules``: GOV_* rule IDs that did NOT fire (controls present)
        - ``status``: ``"uncovered"`` if any rules fired, ``"covered"`` otherwise
    """
    fired_rules = {
        f["rule_id"] for f in findings
        if f.get("rule_id", "").startswith("GOV_")
    }

    matrix = []
    for class_name, (description, rule_ids) in sorted(FAILURE_CLASSES.items()):
        covered = [r for r in rule_ids if r in fired_rules]
        uncovered = [r for r in rule_ids if r not in fired_rules]
        matrix.append({
            "failure_class": class_name,
            "description": description,
            "covered_rules": covered,
            "uncovered_rules": uncovered,
            "status": "uncovered" if covered else "covered",
        })

    return matrix
