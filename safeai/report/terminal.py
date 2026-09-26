"""Terminal (stdout) report writer.

Prints a human-readable summary of the scan including file count,
detected frameworks, MCP asset count, overall risk score, finding
severity counts, and a per-finding list.
"""

import re

# ANSI escape (CSI, e.g. \x1b[2J) and OSC (\x1b]...\x07 / \x1b]...\x1b\\)
# sequences, plus raw carriage-return control characters.
_ANSI_OSC_RE = re.compile(r"\x1b(\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[0-9;]*[@-~])|\r")


def _sanitize(value):
    """Strip terminal control sequences from a value before printing.

    Removes ANSI CSI/OSC escape sequences and raw carriage returns so a
    scanned repo with malicious filenames or finding content cannot spoof
    terminal output. Any residual ESC byte the pattern does not recognize
    (charset selection, DECSTR, dangling ESC) is dropped as a backstop, so
    no ``\\x1b`` can ever reach the terminal. Clean strings pass through
    byte-identical.
    """
    if not isinstance(value, str):
        return value
    return _ANSI_OSC_RE.sub("", value).replace("\x1b", "")


def _first_sentence(text):
    """First sentence of a remediation string (single-line, capped)."""
    sentence = str(_sanitize(text)).strip().split(". ")[0].rstrip(".")
    if len(sentence) > 160:
        sentence = sentence[:157] + "..."
    return sentence


def print_summary(report):
    print("SafeAI Scan Summary")
    print("Files:", _sanitize(report["files_scanned"]))
    if report.get("detected_frameworks"):
        print("Frameworks:", ", ".join(_sanitize(f) for f in report["detected_frameworks"]))
    if report.get("mcp_assets") is not None:
        print("MCP assets:", len(report.get("mcp_assets", [])))
    if report.get("components") is not None:
        component_counts = {}
        for component in report.get("components", []):
            kind = _sanitize(component.get("type", "unknown"))
            component_counts[kind] = component_counts.get(kind, 0) + 1
        print("Components:", ", ".join(f"{k}={v}" for k, v in sorted(component_counts.items())) or "none")
    inventory = report.get("dependency_inventory")
    if inventory is not None:
        print("External config/credential names:", len(inventory))
    correlation = report.get("dependency_correlation")
    if correlation and correlation.get("counts"):
        counts = correlation["counts"]
        print(
            "Dependency correlation:",
            f"{counts.get('undeclared', 0)} undeclared-capability candidates /",
            f"{counts.get('orphaned', 0)} orphaned declared tools",
        )
    if report.get("diagnostics"):
        print("Diagnostics:", len(report["diagnostics"]))
    if report.get("capability_diff"):
        capability_diff = report["capability_diff"]
        diff = capability_diff["counts"]
        print("Capability diff:", f"+{diff['added']} / -{diff['removed']} / ~{diff['changed']}")
        if capability_diff.get("schema_version", 1) >= 2:
            if not capability_diff.get("baseline_tool_attribution", True):
                print("Tool diff: baseline predates tool-level tracking; "
                      "showing capability-level diff only.")
            else:
                print(
                    "Tool diff:",
                    f"{diff.get('tools_new', 0)} new /",
                    f"{diff.get('tools_escalated', 0)} escalated /",
                    f"{diff.get('tools_removed', 0)} removed",
                )
            highest = capability_diff.get("highest_escalation")
            if highest:
                print("Highest escalation:", _sanitize(highest))
    if report.get("trust_score"):
        print("Overall AI Risk Score:", _sanitize(report["trust_score"].get("overall_ai_risk_score")))

    # --- KYA (Know Your Agent) summary ---
    kya_agents = report.get("kya_agents")
    if kya_agents is not None:
        print("Agents/workflows detected:", len(kya_agents))
    registry = report.get("registry")
    if registry:
        state = _sanitize(registry.get("state", "skipped"))
        path = _sanitize(registry.get("path"))
        stats = registry.get("stats") or {}
        line = f"Registry: {state}"
        if path:
            line += f" ({path})"
        print(line)
        if stats:
            print(
                "Registry delta:",
                f"+{stats.get('new_agents', 0)} new agents,",
                f"{stats.get('updated_agents', 0)} updated,",
                f"+{stats.get('new_findings', 0)} new findings,",
                f"{stats.get('regressed_findings', 0)} regressed",
            )
        elif registry.get("reason"):
            print("Registry note:", _sanitize(registry["reason"]))

    baseline = report.get("baseline")
    if baseline:
        print(
            "Baseline:",
            f"{baseline['new']} new /",
            f"{baseline['existing']} existing /",
            f"{baseline['resolved']} resolved /",
            f"{baseline['new_high_critical']} new high+critical",
        )

    policy = report.get("policy_decision")
    if policy:
        print("Policy outcome:", _sanitize(policy.get("outcome")))
        profile = _sanitize(report.get("policy_profile"))
        if profile:
            print("Policy profile:", profile)
        for reason in (policy.get("reasons") or [])[:5]:
            print(f"  - {_sanitize(reason)}")
        # Lane B prints questions for a human; Lane A prints verdicts.
        questions = [
            m for m in (policy.get("matches") or [])
            if m.get("lane") == "B"
        ]
        for match in questions[:5]:
            print(f"  ? [{_sanitize(match.get('policy_id'))}] {_sanitize(match.get('message') or 'requires human review')}")

    suppressions = report.get("suppressions")
    if suppressions and suppressions.get("suppressed"):
        print("Suppressed findings:", suppressions["suppressed"], "(visible in reports, excluded from gating)")

    for k, v in report["counts"].items():
        print(f"{_sanitize(k)}: {v}")
    print("Findings:")
    for f in report["findings"]:
        status = f.get("status")
        tag = f" [{_sanitize(status)}]" if status and status != "new" else ""
        print(f"[{_sanitize(f['severity'])}] {_sanitize(f['file'])}:{_sanitize(f['line'])} - {_sanitize(f['message'])}{tag}")
        # Concise next action for high/critical findings only; the full
        # remediation text lives in JSON/HTML/SARIF reports.
        if str(f.get("severity", "")).lower() in ("high", "critical") and f.get("remediation"):
            print(f"  Next: {_first_sentence(f['remediation'])}")

    if kya_agents is not None or registry:
        print()
        print("Note: SafeAI results are static analysis evidence and do not verify")
        print("deployed runtime permissions, identities, or behavior.")

    # Assurance boundary: what this particular scan could not see. Printed
    # last so it qualifies the findings above rather than prefacing them.
    boundary = report.get("assurance_boundary")
    if isinstance(boundary, dict) and boundary.get("coverage_notes"):
        print()
        print("Coverage:")
        for note in boundary["coverage_notes"]:
            print(f"  - {_sanitize(note)}")
