"""``safeai registry`` command group: list, show, history, diff, export.

All commands are offline, local-first, and read only static-analysis
evidence from a SQLite registry. Output formats: ``table`` (default),
``json``, and ``html`` (a self-contained, shareable report page).
"""

import json
import os
import sys

from safeai.kya import STATIC_ANALYSIS_DISCLAIMER
from safeai.kya.exporter import export_inventory, write_export
from safeai.kya.registry import (
    RegistryError,
    agent_history,
    connect,
    default_registry_path,
    get_agent,
    get_agent_scan_findings,
    get_snapshot,
    get_tool_snapshots,
    list_agents,
    registry_exists,
    resolve_scan_ref,
    shared_registry_path,
)


def _open_registry(path):
    if not registry_exists(path):
        raise RegistryError(
            f"Registry not found at {path}. Run 'safeai scan <dir>' first "
            f"(registry persistence is enabled by default). To inspect another "
            f"project's registry use --project-dir <dir> or --registry <path>."
        )
    return connect(path)


def _print_json(payload):
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _table(rows, headers):
    if not rows:
        print("(no records)")
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))


def _freshness_label(freshness):
    """Return a plain-text freshness label for CLI table output."""
    if not freshness:
        return "unknown"
    label = freshness.get("label", "unknown")
    age = freshness.get("age_days")
    if age is not None:
        return f"{label} ({age}d)"
    return label


def cmd_list(args):
    conn = _open_registry(args.registry_path)
    try:
        agents = list_agents(conn, getattr(args, "project", None))
    finally:
        conn.close()
    if args.format == "json":
        _print_json({"agents": agents, "disclaimer": STATIC_ANALYSIS_DISCLAIMER})
        return 0
    if args.format == "html":
        from safeai.report.registry_html import render_agents_list
        sys.stdout.write(render_agents_list(agents, registry_path=args.registry_path))
        return 0
    rows = [
        (
            a["agent_id"],
            (a.get("name") or "")[:28],
            a.get("framework") or "-",
            a.get("agent_type") or "-",
            a.get("first_seen", "-")[:10],
            a.get("last_seen", "-")[:10],
            _freshness_label(a.get("freshness")),
            a.get("scan_count", 0),
            a.get("policy_outcome") or "-",
            a.get("risk_score") if a.get("risk_score") is not None else "-",
        )
        for a in agents
    ]
    print(f"Known agents ({len(rows)}) - static evidence only")
    _table(rows, ["AGENT ID", "NAME", "FRAMEWORK", "TYPE", "FIRST SEEN", "LAST SEEN", "FRESHNESS", "SCANS", "POLICY", "RISK"])
    return 0


def cmd_show(args):
    conn = _open_registry(args.registry_path)
    try:
        agent = get_agent(conn, args.agent_id, scan_id=getattr(args, "scan", None))
    finally:
        conn.close()
    if agent is None:
        print(f"error: agent '{args.agent_id}' not found in registry", file=sys.stderr)
        return 2
    if args.format == "json":
        agent["disclaimer"] = STATIC_ANALYSIS_DISCLAIMER
        _print_json(agent)
        return 0
    if args.format == "html":
        from safeai.report.registry_html import render_agent_show
        sys.stdout.write(render_agent_show(agent, registry_path=args.registry_path))
        return 0

    snapshot = agent.get("snapshot") or {}
    print(f"Agent: {agent.get('name')} ({agent['agent_id']})")
    print(f"  Type: {agent.get('agent_type')}   Framework: {agent.get('framework')}")
    print(f"  First seen: {agent.get('first_seen')}   Last seen: {agent.get('last_seen')}")
    scan = agent.get("scan") or {}
    if scan:
        print(f"  Scan: {scan.get('scan_id')} @ {scan.get('completed_at')}")
        print(f"  Policy outcome: {scan.get('policy_outcome')}   Risk score: {scan.get('risk_score')}")
    locations = snapshot.get("source_locations") or []
    if locations:
        print("  Source locations:")
        for loc in locations:
            print(f"    - {loc.get('path')}:{loc.get('line_start')}")
    caps = snapshot.get("capabilities") or []
    if caps:
        print("  Capabilities (detected in source/configuration):")
        for cap in caps:
            print(f"    - {cap.get('name')} [{cap.get('category')}]")
    tools = snapshot.get("tools") or []
    if tools:
        print("  Tools:", ", ".join(tools))
    findings = agent.get("findings") or []
    if findings:
        print(f"  Findings in scan ({len(findings)}):")
        for f in findings:
            print(f"    - [{f.get('severity')}] {f.get('rule_id')} {f.get('path')}:{f.get('line')} ({f.get('status')})")
    print(f"  Confidence: {snapshot.get('confidence', '-')}")
    print()
    print(f"Note: {STATIC_ANALYSIS_DISCLAIMER}")
    return 0


def cmd_history(args):
    conn = _open_registry(args.registry_path)
    try:
        history = agent_history(conn, args.agent_id)
    finally:
        conn.close()
    if not history:
        print(f"error: no history for agent '{args.agent_id}'", file=sys.stderr)
        return 2
    if args.format == "json":
        _print_json({"agent_id": args.agent_id, "history": history})
        return 0
    if args.format == "html":
        from safeai.report.registry_html import render_history
        sys.stdout.write(render_history(args.agent_id, history, registry_path=args.registry_path))
        return 0
    rows = [
        (
            h["scan_id"][:8],
            h.get("completed_at", "-"),
            (h.get("commit_sha") or "-")[:8],
            h.get("policy_outcome") or "-",
            h.get("risk_score") if h.get("risk_score") is not None else "-",
            h.get("capability_count", 0),
            ",".join(f"{k}:{v}" for k, v in sorted((h.get("severity_counts") or {}).items()) if v),
        )
        for h in history
    ]
    print(f"History for agent {args.agent_id} ({len(rows)} scans)")
    _table(rows, ["SCAN", "COMPLETED", "COMMIT", "POLICY", "RISK", "CAPS", "SEVERITIES"])
    return 0


def _index_capabilities(snapshot):
    return {
        str(c.get("name", "")).lower(): c.get("category", "Capability")
        for c in (snapshot.get("capabilities") or [])
    }


def _tool_diff(surface_from, surface_to):
    """Tool-centric view over two persisted tool surfaces."""
    from safeai.analysis.capability_diff import compute_capability_diff

    return compute_capability_diff(
        {"tool_surface": surface_to, "normalized_capabilities": []},
        {"tool_surface": surface_from, "normalized_capabilities": []},
    )


def _print_tool_diff(tool_diff):
    tools = [t for t in tool_diff.get("tools") or [] if t.get("status") != "unchanged"]
    if not tool_diff.get("baseline_tool_attribution"):
        print("  Tools: baseline predates tool-level tracking; showing capability-level diff only.")
        return
    if not tools:
        print("  Tools: no tool-level authority changes")
        return
    print(f"  Tools changed: {len(tools)}")
    for tool in tools:
        summary = tool.get("access_summary") or {}
        before, after = summary.get("before") or "-", summary.get("after") or "-"
        print(f"    {tool['tool_key']} [{tool['status']}] {before} -> {after}")
        for escalation in tool.get("escalations") or []:
            flag = " (inferred)" if escalation.get("inferred") else ""
            print(f"      ! [{escalation['severity']}] {escalation['id']}: {escalation['summary']}{flag}")


def cmd_diff(args):
    conn = _open_registry(args.registry_path)
    try:
        from_id = resolve_scan_ref(conn, args.agent_id, args.from_ref)
        to_id = resolve_scan_ref(conn, args.agent_id, args.to_ref)
        if not from_id or not to_id:
            print("error: unable to resolve scan references (need at least two scans for 'previous')",
                  file=sys.stderr)
            return 2
        snap_from = get_snapshot(conn, args.agent_id, from_id)
        snap_to = get_snapshot(conn, args.agent_id, to_id)
        surface_from = get_tool_snapshots(conn, from_id)
        surface_to = get_tool_snapshots(conn, to_id)
        findings_from = {f.get("fingerprint"): f for f in get_agent_scan_findings(conn, args.agent_id, from_id)}
        findings_to = {f.get("fingerprint"): f for f in get_agent_scan_findings(conn, args.agent_id, to_id)}
    finally:
        conn.close()

    if snap_from is None or snap_to is None:
        print(f"error: no snapshot for agent '{args.agent_id}' in one of the scans", file=sys.stderr)
        return 2

    caps_from, caps_to = _index_capabilities(snap_from), _index_capabilities(snap_to)
    tools_from = {str(t).lower() for t in snap_from.get("tools") or []}
    tools_to = {str(t).lower() for t in snap_to.get("tools") or []}
    fps_from, fps_to = set(findings_from), set(findings_to)

    new_findings = [findings_to[fp] for fp in sorted(fps_to - fps_from)]
    resolved_findings = [findings_from[fp] for fp in sorted(fps_from - fps_to)]
    regressed = [f for f in new_findings if f.get("status") == "regressed"]

    diff = {
        "agent_id": args.agent_id,
        "from_scan": from_id,
        "to_scan": to_id,
        "capabilities": {
            "added": sorted(caps_to.keys() - caps_from.keys()),
            "removed": sorted(caps_from.keys() - caps_to.keys()),
        },
        "tools": {
            "added": sorted(tools_to - tools_from),
            "removed": sorted(tools_from - tools_to),
        },
        "findings": {
            "new": [{"rule_id": f.get("rule_id"), "severity": f.get("severity"),
                     "fingerprint": f.get("fingerprint")} for f in new_findings],
            "resolved": [{"rule_id": f.get("rule_id"), "severity": f.get("severity"),
                          "fingerprint": f.get("fingerprint")} for f in resolved_findings],
            "regressed": [{"rule_id": f.get("rule_id"), "severity": f.get("severity"),
                           "fingerprint": f.get("fingerprint")} for f in regressed],
        },
        "confidence": {"from": snap_from.get("confidence"), "to": snap_to.get("confidence")},
    }

    # v1.4: tool-centric authority view. A pre-1.4 scan has no persisted
    # tool surface; say so instead of rendering a misleading tool diff.
    tool_diff = _tool_diff(surface_from, surface_to)
    if not surface_from:
        tool_diff["baseline_tool_attribution"] = False
    diff["tool_diff"] = tool_diff

    if args.format == "json":
        _print_json(diff)
    elif args.format == "html":
        from safeai.report.registry_html import render_diff
        sys.stdout.write(render_diff(args.agent_id, diff, registry_path=args.registry_path))
    else:
        print(f"Diff for agent {args.agent_id}")
        print(f"  from scan {from_id[:8]} -> to scan {to_id[:8]}")
        print(f"  Capabilities: +{len(diff['capabilities']['added'])} / -{len(diff['capabilities']['removed'])}")
        for name in diff["capabilities"]["added"]:
            print(f"    + {name}")
        for name in diff["capabilities"]["removed"]:
            print(f"    - {name}")
        print(f"  Tools: +{len(diff['tools']['added'])} / -{len(diff['tools']['removed'])}")
        _print_tool_diff(tool_diff)
        print(f"  Findings: {len(new_findings)} new / {len(resolved_findings)} resolved / {len(regressed)} regressed")
        for f in new_findings:
            print(f"    + [{f.get('severity')}] {f.get('rule_id')}")
        for f in resolved_findings:
            print(f"    - [{f.get('severity')}] {f.get('rule_id')}")

    # Documented exit contract: 1 when risk-relevant changes exist.
    changed = bool(
        diff["capabilities"]["added"]
        or new_findings
        or regressed
        or (tool_diff.get("highest_escalation") is not None)
    )
    return 1 if changed else 0


def cmd_export(args):
    conn = _open_registry(args.registry_path)
    try:
        document = export_inventory(
            conn,
            project_id=getattr(args, "project", None),
            include_history=getattr(args, "include_history", False),
            include_suppressed=getattr(args, "include_suppressed", False),
        )
    finally:
        conn.close()
    if args.format == "html":
        from safeai.report.registry_html import render_inventory
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render_inventory(document, registry_path=args.registry_path))
    else:
        write_export(document, args.output)
    print(f"Exported KYA inventory to {args.output}")
    print(f"Note: {STATIC_ANALYSIS_DISCLAIMER}")
    return 0


def resolve_registry_arg(args, scan_root=None):
    """Resolve which registry database a command should read.

    Precedence: ``--registry PATH``, then ``--project-dir DIR`` (the
    per-project ``DIR/.safeai/registry.db``), then the shared org registry
    (``SAFEAI_REGISTRY`` env var or ``~/.safeai/registry.db``).
    """
    explicit = getattr(args, "registry", None)
    if explicit:
        return explicit
    project_dir = getattr(args, "project_dir", None) or scan_root
    if project_dir:
        return default_registry_path(os.path.abspath(project_dir))
    return shared_registry_path()


def run_registry_command(args):
    """Dispatch a parsed ``registry`` subcommand. Returns an exit code."""
    args.registry_path = resolve_registry_arg(args)
    try:
        handler = {
            "list": cmd_list,
            "show": cmd_show,
            "history": cmd_history,
            "diff": cmd_diff,
            "export": cmd_export,
        }[args.registry_command]
        return handler(args)
    except RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
