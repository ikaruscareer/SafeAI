"""Self-contained HTML renderers for the ``safeai registry`` commands.

Uses the shared SafeAI design system (:mod:`safeai.report.html_kit`).
Every renderer returns a complete HTML document string; the CLI prints
it to stdout (``list``/``show``/``history``/``diff``) or writes it to a
file (``export --format html``). All data is static-analysis evidence
from the registry and is HTML-escaped.
"""

from html import escape

from safeai.kya import STATIC_ANALYSIS_DISCLAIMER
from safeai.report import html_kit


def _page(title, body, registry_path=None, footer=STATIC_ANALYSIS_DISCLAIMER):
    return html_kit.page(
        title=title,
        subtitle=f"registry: {registry_path}" if registry_path else None,
        body=body,
        footer=footer,
    )


def _capability_badges(capabilities):
    """Render a capability list as badges (name + category)."""
    if not capabilities:
        return "<span class='muted'>-</span>"
    badges = []
    for cap in capabilities:
        name = cap.get("name", "")
        access = cap.get("access_mode")
        mode = f" <code>{escape(str(access))}</code>" if access else ""
        inferred = "<span class='muted'> (inferred)</span>" if cap.get("access_mode_inferred") else ""
        badges.append(
            f"<span class='badge' style='color:#0f766e;background:#ecfdf5;border-color:#0f766e33'>"
            f"{escape(str(name))}</span>{mode}{inferred}"
        )
    return " ".join(badges)


def render_agents_list(agents, registry_path=None):
    """Render ``registry list`` as an inventory page."""
    summary = "".join(
        html_kit.kpi(label, value, accent="#0f766e")
        for label, value in [
            ("Agents", len(agents)),
            ("Frameworks", len({a.get("framework") for a in agents if a.get("framework")})),
            ("Projects", len({a.get("project_id") for a in agents if a.get("project_id")})),
        ]
    )
    rows = [
        [
            f"<code>{escape(str(a.get('agent_id', '')))}</code>",
            escape(str(a.get("name", ""))),
            escape(str(a.get("framework", "-"))),
            escape(str(a.get("agent_type", "-"))),
            escape(str(a.get("project_id", "-"))),
            escape(str((a.get("first_seen") or "-")[:10])),
            escape(str((a.get("last_seen") or "-")[:10])),
            html_kit.sev_badge(a.get("policy_outcome") or "warn"),
            escape(str(a.get("risk_score") if a.get("risk_score") is not None else "-")),
        ]
        for a in agents
    ]
    body = f"""
    <section class='hero'>{summary}</section>
    <h2>Known Agents</h2>
    {html_kit.data_table(
        ["Agent ID", "Name", "Framework", "Type", "Project", "First seen", "Last seen", "Policy", "Risk"],
        rows,
        empty="No agents in the registry yet - run 'safeai scan <dir>' first.",
    )}
    """
    return _page("SafeAI - Registry Inventory", body, registry_path)


def render_agent_show(agent, registry_path=None):
    """Render ``registry show`` for a single agent."""
    snapshot = agent.get("snapshot") or {}
    scan = agent.get("scan") or {}
    findings = agent.get("findings") or []
    caps = snapshot.get("capabilities") or []

    meta_rows = [
        ["Agent ID", f"<code>{escape(str(agent.get('agent_id', '')))}</code>"],
        ["Name", escape(str(agent.get("name", "")))],
        ["Type", escape(str(agent.get("agent_type", "-")))],
        ["Framework", escape(str(agent.get("framework", "-")))],
        ["First seen", escape(str(agent.get("first_seen", "-")))],
        ["Last seen", escape(str(agent.get("last_seen", "-")))],
        ["Scan", escape(str(scan.get("scan_id", "-")))],
        ["Completed", escape(str(scan.get("completed_at", "-")))],
        ["Policy outcome", escape(str(scan.get("policy_outcome", "-")))],
        ["Risk score", escape(str(scan.get("risk_score", "-")))],
        ["Confidence", escape(str(snapshot.get("confidence", "-")))],
    ]
    locations = "".join(
        f"<li><code>{escape(str(loc.get('path', '')))}:{escape(str(loc.get('line_start', '')))}</code></li>"
        for loc in (snapshot.get("source_locations") or [])
    ) or "<li class='muted'>no source locations</li>"

    finding_rows = [
        [
            html_kit.sev_badge(f.get("severity", "info")),
            escape(str(f.get("status", ""))),
            f"<code>{escape(str(f.get('rule_id', '')))}</code>",
            escape(str(f.get("path", ""))),
            escape(str(f.get("line", ""))),
            f"<code>{escape(str(f.get('fingerprint', '')))[:16]}</code>",
        ]
        for f in findings
    ]

    body = f"""
    <div class='grid-2'>
      <div class='card'>
        <h3>Agent</h3>
        <dl class='kv'>{"".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in meta_rows)}</dl>
      </div>
      <div class='card'>
        <h3>Source locations</h3>
        <ul>{locations}</ul>
        <h3>Capabilities (static evidence)</h3>
        <div>{_capability_badges(caps)}</div>
        <h3>Tools</h3>
        <div>{", ".join(f"<code>{escape(str(t))}</code>" for t in (snapshot.get("tools") or [])) or "<span class='muted'>-</span>"}</div>
      </div>
    </div>
    <h2>Findings in this scan</h2>
    {html_kit.data_table(
        ["Severity", "Status", "Rule", "Path", "Line", "Fingerprint"],
        finding_rows,
        empty="No findings recorded for this agent.",
    )}
    """
    return _page(f"SafeAI - Agent {agent.get('name', agent.get('agent_id', ''))}", body, registry_path)


def render_history(agent_id, history, registry_path=None):
    """Render ``registry history`` as a timeline of scans."""
    rows = []
    for h in history:
        sev_counts = " ".join(
            f"{html_kit.sev_badge(k)} {escape(str(v))}" for k, v in sorted((h.get("severity_counts") or {}).items())
        ) or "<span class='muted'>-</span>"
        rows.append([
            f"<code>{escape(str(h.get('scan_id', '')))}</code>",
            escape(str(h.get("completed_at", "-"))),
            escape(str((h.get("commit_sha") or "-")[:8])),
            html_kit.sev_badge(h.get("policy_outcome") or "warn"),
            escape(str(h.get("risk_score") if h.get("risk_score") is not None else "-")),
            escape(str(h.get("capability_count", 0))),
            sev_counts,
        ])
    body = f"""
    <h2>Scan history for {escape(str(agent_id))}</h2>
    <p class='muted'>{len(history)} scans recorded - append-only history, newest first.</p>
    {html_kit.data_table(
        ["Scan", "Completed", "Commit", "Policy", "Risk", "Caps", "Severities"],
        rows,
        empty="No history recorded for this agent.",
    )}
    """
    return _page("SafeAI - Agent History", body, registry_path)


def render_diff(agent_id, diff, registry_path=None):
    """Render ``registry diff`` between two snapshots of an agent."""
    caps = diff.get("capabilities", {})
    tools = diff.get("tools", {})
    findings = diff.get("findings", {})
    tool_diff = diff.get("tool_diff", {})

    summary = "".join(
        html_kit.kpi(label, value, accent="#0f766e")
        for label, value in [
            ("Capabilities", f"+{len(caps.get('added', []))} / -{len(caps.get('removed', []))}"),
            ("Tools", f"+{len(tools.get('added', []))} / -{len(tools.get('removed', []))}"),
            ("Findings", f"{len(findings.get('new', []))} new"),
            ("Highest escalation", escape(str(tool_diff.get("highest_escalation") or "none"))),
        ]
    )

    cap_rows = (
        [[f"<code>{escape(str(name))}</code>", "added"] for name in caps.get("added", [])]
        + [[f"<code>{escape(str(name))}</code>", "removed"] for name in caps.get("removed", [])]
    )
    finding_rows = (
        [
            [html_kit.sev_badge(f.get("severity", "info")), "new", f"<code>{escape(str(f.get('rule_id', '')))}</code>", escape(str(f.get("fingerprint", "")))]
            for f in findings.get("new", [])
        ]
        + [
            [html_kit.sev_badge(f.get("severity", "info")), "resolved", f"<code>{escape(str(f.get('rule_id', '')))}</code>", escape(str(f.get("fingerprint", "")))]
            for f in findings.get("resolved", [])
        ]
        + [
            [html_kit.sev_badge(f.get("severity", "info")), "regressed", f"<code>{escape(str(f.get('rule_id', '')))}</code>", escape(str(f.get("fingerprint", "")))]
            for f in findings.get("regressed", [])
        ]
    )

    tool_rows = []
    for tool in tool_diff.get("tools") or []:
        summary_map = tool.get("access_summary") or {}
        escs = "".join(
            f"<div>{html_kit.sev_badge(e.get('severity', 'info'))} <code>{escape(str(e.get('id', '')))}</code> - {escape(str(e.get('summary', '')))}</div>"
            for e in (tool.get("escalations") or [])
        ) or "<span class='muted'>no escalation</span>"
        tool_rows.append([
            f"<code>{escape(str(tool.get('tool_key', '')))}</code>",
            escape(str(tool.get("status", ""))),
            f"{escape(str(summary_map.get('before', '-')))} &rarr; {escape(str(summary_map.get('after', '-')))}",
            escs,
        ])

    if tool_diff.get("baseline_tool_attribution") is False:
        tool_note = "<div class='note'>Baseline predates per-tool attribution; showing capability-level diff only.</div>"
    else:
        tool_note = ""

    body = f"""
    <h2>Diff for agent {escape(str(agent_id))}</h2>
    <p class='muted'>from scan <code>{escape(str(diff.get('from_scan', '')))}</code> -> to scan <code>{escape(str(diff.get('to_scan', '')))}</code></p>
    <section class='hero'>{summary}</section>
    <h2>Tool-level authority</h2>
    {tool_note}
    {html_kit.data_table(["Tool", "Status", "Access (before -> after)", "Escalations"], tool_rows, empty="No tool-level authority changes.")}
    <h2>Capabilities</h2>
    {html_kit.data_table(["Capability", "Change"], cap_rows, empty="No capability changes.")}
    <h2>Findings</h2>
    {html_kit.data_table(["Severity", "Status", "Rule", "Fingerprint"], finding_rows, empty="No finding changes.")}
    """
    return _page("SafeAI - Agent Diff", body, registry_path)


def render_inventory(document, registry_path=None):
    """Render ``registry export`` inventory document as an HTML page."""
    projects = document.get("projects", [])
    summary = "".join(
        html_kit.kpi(label, value, accent="#0f766e")
        for label, value in [
            ("Projects", len(projects)),
            ("Agents", sum(len(p.get("agents", [])) for p in projects)),
        ]
    )

    sections = []
    for project in projects:
        agents = project.get("agents", [])
        rows = [
            [
                f"<code>{escape(str(a.get('agent_id', '')))}</code>",
                escape(str(a.get("name", ""))),
                escape(str(a.get("framework", "-"))),
                escape(str(a.get("agent_type", "-"))),
                escape(str((a.get("last_seen") or "-")[:10])),
                _capability_badges(a.get("capabilities") or []),
                escape(str(a.get("confidence", "-"))),
            ]
            for a in agents
        ]
        latest_findings = project.get("latest_findings") or []
        sev_badges = " ".join(
            html_kit.sev_badge(f.get("severity", "info")) for f in latest_findings
        ) or "<span class='muted'>none</span>"
        sections.append(f"""
        <h2>Project: {escape(str(project.get('name', project.get('project_id'))))}</h2>
        <dl class='kv'>
          <dt>Project ID</dt><dd><code>{escape(str(project.get('project_id', '')))}</code></dd>
          <dt>Source root</dt><dd>{escape(str(project.get('source_root', '-')))}</dd>
          <dt>Latest scan</dt><dd><code>{escape(str(project.get('latest_scan_id', '-')))}</code></dd>
          <dt>Latest findings</dt><dd>{sev_badges}</dd>
        </dl>
        {html_kit.data_table(["Agent ID", "Name", "Framework", "Type", "Last seen", "Capabilities", "Confidence"], rows, empty="No agents in this project.")}
        """)

    body = f"""
    <section class='hero'>{summary}</section>
    {''.join(sections) if sections else "<div class='card'><p>No projects in the registry.</p></div>"}
    """
    return _page("SafeAI - KYA Inventory Export", body, registry_path)
