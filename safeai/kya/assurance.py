"""Assurance boundary: what a SafeAI scan did and did not verify.

v1.4 makes stronger claims than earlier releases. It names a tool and
says its authority increased. That is exactly when a tool must be
clearest about the edge of its own knowledge, because a confident
statement with an unstated boundary is how static analysis gets mistaken
for runtime assurance.

Everything here is derived from the scan that just ran — real skipped
file types, real parse failures, real inference counts. Nothing is a
fixed disclaimer string, because a fixed string stops being read.
"""

#: Claims a static scan can support. Stable across runs; these describe
#: the analysis SafeAI performs, not the contents of any one repository.
VERIFIED_STATICALLY = (
    "declared tools",
    "prompt and instruction files",
    "MCP server configuration",
    "workflow structure",
    "permission configuration",
)

#: Claims a static scan can never support, however complete the parse.
NOT_VERIFIABLE_STATICALLY = (
    "IAM and cloud permissions",
    "runtime identity",
    "deployed network policy",
    "actual runtime behaviour",
    "dynamically constructed tool bindings",
)

#: One-line summary reused by the terminal, HTML and PR-comment footers.
BOUNDARY_SENTENCE = (
    "Static analysis of repository configuration and source. SafeAI cannot "
    "verify deployed IAM permissions, runtime identity, or network policy."
)

#: Findings that mean "SafeAI could not read this", as opposed to
#: "SafeAI read this and found a problem". They bound coverage.
_PARSE_FAILURE_RULES = ("CC_SETTINGS_UNPARSEABLE",)

_SCHEMA_VERSION = 1


def _plural(count, noun):
    return noun if count == 1 else noun + "s"


def _skipped_notes(report):
    notes = []
    skipped = report.get("skipped_files") or {}
    if isinstance(skipped, dict):
        for reason, count in sorted(skipped.items()):
            if not count:
                continue
            notes.append(f"{count} {_plural(count, 'file')} not read: {reason}")
    return notes


def _parse_failure_notes(report):
    notes = []
    failures = {}
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        if finding.get("rule_id") in _PARSE_FAILURE_RULES:
            path = finding.get("file") or "(unknown file)"
            failures[path] = failures.get(path, 0) + 1
    for diagnostic in report.get("diagnostics") or []:
        if not isinstance(diagnostic, dict):
            continue
        kind = str(diagnostic.get("kind") or diagnostic.get("type") or "")
        if "parse" in kind.lower() or "error" in kind.lower():
            path = diagnostic.get("file") or "(unknown file)"
            failures[path] = failures.get(path, 0) + 1
    if failures:
        count = len(failures)
        listed = ", ".join(sorted(failures)[:3])
        suffix = ", …" if count > 3 else ""
        verb = "was" if count == 1 else "were"
        notes.append(
            f"{count} configuration {_plural(count, 'file')} could not be parsed "
            f"and {verb} not analysed: {listed}{suffix}"
        )
    return notes


def _inferred_capabilities(report):
    """Return ``(count, sorted tool keys)`` for inferred access modes.

    An inferred access mode is a heuristic reading of what a tool can do,
    not a declared fact. Counting them tells a reader how much of the
    escalation output rests on inference.
    """
    count = 0
    tools = set()
    for entry in report.get("tool_surface") or []:
        if not isinstance(entry, dict):
            continue
        for capability in entry.get("capabilities") or []:
            if isinstance(capability, dict) and capability.get("inferred"):
                count += 1
                if entry.get("tool_key"):
                    tools.add(str(entry["tool_key"]))
    return count, sorted(tools)


def _inference_notes(report, count, tools):
    if not count:
        return []
    listed = ", ".join(tools[:3])
    suffix = ", …" if len(tools) > 3 else ""
    detail = f" on {listed}{suffix}" if listed else ""
    note = (
        f"{count} access {_plural(count, 'mode')} inferred from naming or usage "
        f"patterns rather than declared configuration{detail}; treat as "
        "indicative, not confirmed"
    )
    return [note]


def _attribution_notes(report):
    notes = []
    diff = report.get("capability_diff") or {}
    if diff and not diff.get("baseline_tool_attribution", True):
        notes.append(
            "the baseline predates per-tool attribution, so only combination "
            "escalations could be evaluated for this comparison"
        )
    unattributed = diff.get("unattributed") if isinstance(diff, dict) else None
    if isinstance(unattributed, dict):
        orphaned = len(unattributed.get("capabilities_added") or [])
        if orphaned:
            notes.append(
                f"{orphaned} {_plural(orphaned, 'capability')} could not be "
                "attributed to a named tool and are reported as unattributed"
            )
    return notes


def build_assurance_boundary(report):
    """Return the assurance boundary for ``report``.

    The result is deterministic: every list is ordered, and no value
    derives from wall-clock time, iteration order, or the host machine.
    """
    report = report or {}
    inferred_count, inferred_tools = _inferred_capabilities(report)

    coverage_notes = []
    coverage_notes.extend(_skipped_notes(report))
    coverage_notes.extend(_parse_failure_notes(report))
    coverage_notes.extend(_inference_notes(report, inferred_count, inferred_tools))
    coverage_notes.extend(_attribution_notes(report))
    if not coverage_notes:
        coverage_notes.append(
            "no files were skipped, no configuration failed to parse, and no "
            "access mode was inferred in this scan"
        )

    return {
        "schema_version": _SCHEMA_VERSION,
        "verified_statically": list(VERIFIED_STATICALLY),
        "not_verifiable_statically": list(NOT_VERIFIABLE_STATICALLY),
        "coverage_notes": coverage_notes,
        "inferred_value_count": inferred_count,
        "summary": BOUNDARY_SENTENCE,
    }
