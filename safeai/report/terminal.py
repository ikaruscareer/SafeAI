"""Terminal (stdout) report writer.

Prints a human-readable summary of the scan including file count,
detected frameworks, MCP asset count, overall risk score, finding
severity counts, and a per-finding list.
"""


def print_summary(report):
    print("SafeAI Scan Summary")
    print("Files:", report["files_scanned"])
    if report.get("detected_frameworks"):
        print("Frameworks:", ", ".join(report["detected_frameworks"]))
    if report.get("mcp_assets") is not None:
        print("MCP assets:", len(report.get("mcp_assets", [])))
    if report.get("components") is not None:
        component_counts = {}
        for component in report.get("components", []):
            kind = component.get("type", "unknown")
            component_counts[kind] = component_counts.get(kind, 0) + 1
        print("Components:", ", ".join(f"{k}={v}" for k, v in sorted(component_counts.items())) or "none")
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
                print("Highest escalation:", highest)
    if report.get("trust_score"):
        print("Overall AI Risk Score:", report["trust_score"].get("overall_ai_risk_score"))

    # --- KYA (Know Your Agent) summary ---
    kya_agents = report.get("kya_agents")
    if kya_agents is not None:
        print("Agents/workflows detected:", len(kya_agents))
    registry = report.get("registry")
    if registry:
        state = registry.get("state", "skipped")
        path = registry.get("path")
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
            print("Registry note:", registry["reason"])

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
        print("Policy outcome:", policy.get("outcome"))
        for reason in (policy.get("reasons") or [])[:5]:
            print(f"  - {reason}")

    suppressions = report.get("suppressions")
    if suppressions and suppressions.get("suppressed"):
        print("Suppressed findings:", suppressions["suppressed"], "(visible in reports, excluded from gating)")

    for k, v in report["counts"].items():
        print(f"{k}: {v}")
    print("Findings:")
    for f in report["findings"]:
        status = f.get("status")
        tag = f" [{status}]" if status and status != "new" else ""
        print(f"[{f['severity']}] {f['file']}:{f['line']} - {f['message']}{tag}")

    if kya_agents is not None or registry:
        print()
        print("Note: SafeAI results are static analysis evidence and do not verify")
        print("deployed runtime permissions, identities, or behavior.")
