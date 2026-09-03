"""Self-contained HTML report generator.

Produces a single-file HTML report with the shared SafeAI design system
(:mod:`safeai.report.html_kit`). Includes an executive summary with a
risk gauge, trust score breakdown, capability matrix, capability
escalations (v1.4), governance summary, the full findings table, KYA
agent records, per-tool capability surface, and the assurance boundary.
"""

from datetime import UTC, datetime
from html import escape

from safeai.report import html_kit


def _sev_badge(severity):
    return html_kit.sev_badge(severity)


def _escalation_section(report):
    """Render the capability escalation summary (v1.4 capability_diff)."""
    diff = report.get("capability_diff")
    if not diff:
        return ""
    counts = diff.get("counts") or {}
    highest = diff.get("highest_escalation")

    cards = "".join(
        html_kit.kpi(label, value, accent="#0f766e")
        for label, value in [
            ("Added", counts.get("added", 0)),
            ("Removed", counts.get("removed", 0)),
            ("Changed", counts.get("changed", 0)),
            ("Escalations", counts.get("escalations", 0)),
        ]
    )

    tool_rows = []
    for tool in diff.get("tools") or []:
        summary = tool.get("access_summary") or {}
        escalations = tool.get("escalations") or []
        esc_html = "".join(
            f"<div>{_sev_badge(e.get('severity', 'info'))} "
            f"<code>{escape(str(e.get('id', '')))}</code> "
            f"{escape(str(e.get('summary', '')))}{' <span class=muted>(inferred)</span>' if e.get('inferred') else ''}</div>"
            for e in escalations
        ) or "<span class='muted'>no per-rule escalation</span>"
        tool_rows.append(
            "<tr>"
            f"<td><code>{escape(str(tool.get('tool_key', '')))}</code></td>"
            f"<td>{escape(str(tool.get('status', '')))}</td>"
            f"<td>{escape(str(summary.get('before', '-')))} &rarr; {escape(str(summary.get('after', '-')))}</td>"
            f"<td>{esc_html}</td>"
            "</tr>"
        )
    tools_table = (
        f"<table><thead><tr><th>Tool</th><th>Status</th><th>Access (before -> after)</th>"
        f"<th>Escalation rules</th></tr></thead><tbody>{''.join(tool_rows) or '<tr><td colspan=4 class=muted center>No tool-level changes.</td></tr>'}</tbody></table>"
    )

    baseline_note = (
        "<div class='note'>Baseline predates per-tool attribution; only combination rules were "
        "evaluated (individual per-tool escalation rules suppressed).</div>"
        if diff.get("baseline_tool_attribution") is False
        else ""
    )

    return f"""
    <h2>Capability Escalations</h2>
    <div class='hero'>{cards}</div>
    {baseline_note}
    {tools_table}
    <p class='muted'>Highest escalation: {escape(str(highest or 'none'))}</p>"""


def _dependency_section(report):
    """Render the CE 1.5 dependency inventory + correlation summary."""
    inventory = report.get("dependency_inventory") or []
    correlation = report.get("dependency_correlation") or {}
    if not inventory and not correlation:
        return ""
    parts = []

    if inventory:
        rows = [
            [
                escape(str(e.get("name", ""))),
                "Yes" if e.get("secret") else "No",
                str(e.get("source_count", 0)),
                ", ".join(
                    f"{escape(str(s.get('file', '')))}:{s.get('line', '')}"
                    for s in (e.get("sources") or [])[:3]
                ) or "-",
            ]
            for e in inventory
        ]
        parts.append(html_kit.data_table(
            ["Name", "Secret-backed", "Refs", "Sources"],
            rows,
            empty="No external configuration/credential references detected.",
        ))

    counts = correlation.get("counts") or {}
    undeclared = counts.get("undeclared", 0)
    orphaned = counts.get("orphaned", 0)
    families = counts.get("families") or {}
    fam_rows = [
        [escape(str(fam)), str(info.get("referenced", 0)),
         "Yes" if info.get("declared") else "No"]
        for fam, info in sorted(families.items())
    ]
    parts.append(f"""
    <h3>Correlation</h3>
    <div class='hero'>
      {html_kit.kpi("Undeclared capability candidates", undeclared, accent='#b45309')}
      {html_kit.kpi("Orphaned declared tools", orphaned, accent='#6b7280')}
    </div>
    {html_kit.data_table(
        ["Family", "Referenced names", "Declared"],
        fam_rows,
        empty="No correlated families.",
        searchable=False,
    )}
    <p class='muted'>Name-family heuristic correlation from static references; not proof of runtime behaviour.</p>""")

    return f"""
    <h2>Dependency Inventory & Correlation</h2>
    {'<h3>Referenced configuration / credentials</h3><p class="muted">Names and source locations only — values are never read or stored.</p>' if inventory else ''}
    {''.join(parts)}"""


def _kya_section(report):
    """Render the Know Your Agent section: agents, policy, registry status."""
    agents = report.get("kya_agents")
    registry = report.get("registry") or {}
    policy = report.get("policy_decision") or {}
    if agents is None and not policy and not registry:
        return ""

    rows = []
    for agent in agents or []:
        caps = ", ".join(sorted({str(c.get("name", "")) for c in agent.get("capabilities") or [] if c.get("name")})) or "-"
        locations = ", ".join(
            f"{loc.get('path')}:{loc.get('line_start')}" for loc in (agent.get("source_locations") or [])
        ) or "-"
        rows.append(
            "<tr>"
            f"<td>{escape(str(agent.get('name', '')))}</td>"
            f"<td><code>{escape(str(agent.get('agent_id', '')))}</code></td>"
            f"<td>{escape(str(agent.get('framework', '')))}</td>"
            f"<td>{escape(str(agent.get('agent_type', '')))}</td>"
            f"<td>{escape(caps)}</td>"
            f"<td>{escape(locations)}</td>"
            f"<td>{escape(str(agent.get('confidence', '')))}</td>"
            "</tr>"
        )

    registry_html = ""
    if registry:
        registry_html = (
            f"<p class='muted'>Registry: {escape(str(registry.get('state', 'skipped')))}"
            + (f" - <code>{escape(str(registry.get('path')))}</code>" if registry.get("path") else "")
            + "</p>"
        )

    policy_html = ""
    if policy:
        reasons = "".join(f"<li>{escape(str(r))}</li>" for r in (policy.get("reasons") or []))
        policy_html = (
            f"<p><strong>Policy outcome:</strong> {escape(str(policy.get('outcome', '')))}</p>"
            f"<ul>{reasons}</ul>"
        )

    return f"""
    <h2>Know Your Agent (KYA)</h2>
    {registry_html}
    {policy_html}
    <table>
      <thead><tr><th>Agent</th><th>Agent ID</th><th>Framework</th><th>Type</th><th>Capabilities (static evidence)</th><th>Source</th><th>Confidence</th></tr></thead>
      <tbody>{''.join(rows) or "<tr><td colspan='7' class='muted center'>No agents/workflows detected in source/configuration.</td></tr>"}</tbody>
    </table>"""


def _tool_surface_section(report):
    """Render the per-tool capability surface (tool identity + access modes)."""
    surface = report.get("tool_surface")
    if not surface:
        return ""
    rows = []
    for tool in surface:
        tool_key = tool.get("tool_key") or tool.get("name") or "-"
        caps = tool.get("capabilities") or []
        caps_html = ", ".join(
            f"{escape(str(c.get('name', '')))} "
            f"<span class='muted'>({escape(str(c.get('access_mode', 'read')))})</span>"
            for c in caps
        ) or "-"
        inferred = sum(1 for c in caps if c.get("access_mode_inferred"))
        rows.append(
            "<tr>"
            f"<td><code>{escape(str(tool_key))}</code></td>"
            f"<td>{escape(str(tool.get('kind', '')))}</td>"
            f"<td>{escape(str(tool.get('framework', '')))}</td>"
            f"<td>{caps_html}</td>"
            f"<td>{escape(str(tool.get('access_summary', '')))}</td>"
            f"<td>{escape(str(inferred))}</td>"
            "</tr>"
        )
    return f"""
    <h2>Tool Capability Surface</h2>
    <p class='muted'>Per-tool authority: capabilities are attributed to the named tool (agent, MCP server, skill, tool, workflow node) with their access modes.</p>
    <table>
      <thead><tr><th>Tool</th><th>Kind</th><th>Framework</th><th>Capabilities (access mode)</th><th>Access summary</th><th>Inferred modes</th></tr></thead>
      <tbody>{''.join(rows) or "<tr><td colspan='6' class='muted center'>No tool surface captured.</td></tr>"}</tbody>
    </table>"""


def _assurance_section(report):
    """Render the assurance boundary: what this scan did and did not verify."""
    boundary = report.get("assurance_boundary")
    if not isinstance(boundary, dict) or not boundary:
        return ""

    def items(values):
        return "".join(f"<li>{escape(str(value))}</li>" for value in values or [])

    inferred = boundary.get("inferred_value_count") or 0
    return f"""
    <h2>Assurance boundary</h2>
    <p class='muted'>{escape(str(boundary.get("summary", "")))}</p>
    <div class='grid-2'>
      <div class='card'>
        <h3>Verified statically</h3>
        <ul>{items(boundary.get("verified_statically"))}</ul>
      </div>
      <div class='card'>
        <h3>Not verifiable statically</h3>
        <ul>{items(boundary.get("not_verifiable_statically"))}</ul>
      </div>
    </div>
    <h3>Coverage notes</h3>
    <ul>{items(boundary.get("coverage_notes"))}</ul>
    <p class='muted'>Inferred values in this scan: {escape(str(inferred))}</p>"""


def write_html(report, path):
    trust = report.get("trust_score", {})
    categories = trust.get("categories", {})
    counts = report.get("counts", {})
    frameworks = report.get("detected_frameworks", [])
    findings = report.get("findings", [])
    components = report.get("components", [])
    diagnostics = report.get("diagnostics", [])
    capability_diff = report.get("capability_diff", {})

    capability_rows = []
    for cap in report.get("normalized_capabilities", []):
        capability_rows.append(
            [
                cap.get("name", ""),
                cap.get("category", ""),
                ", ".join(cap.get("source_frameworks", [])),
                f"{float(cap.get('confidence', 0.0)):.2f}",
                "; ".join(cap.get("evidence", [])),
            ]
        )

    trust_rows = [[k, str(v)] for k, v in categories.items()]

    governance_summary = [
        f for f in findings if f.get("risk_category") in {"Governance", "Integration", "Identity"}
    ]

    from safeai.report.failure_matrix import build_failure_class_matrix
    failure_matrix = build_failure_class_matrix(findings)

    severity_counts = "".join(
        f"<div style='margin:2px 0'>{_sev_badge(k)} <strong>{v}</strong></div>"
        for k, v in counts.items()
    )

    diff_counts = capability_diff.get("counts") or {}
    baseline_summary = report.get("baseline")
    baseline_html = ""
    if baseline_summary:
        baseline_html = (
            f"<div class='kv'>"
            f"<dt>New</dt><dd>{baseline_summary.get('new', 0)}</dd>"
            f"<dt>Existing</dt><dd>{baseline_summary.get('existing', 0)}</dd>"
            f"<dt>Resolved</dt><dd>{baseline_summary.get('resolved', 0)}</dd>"
            f"<dt>New high+critical</dt><dd>{baseline_summary.get('new_high_critical', 0)}</dd>"
            f"</div>"
        )

    body = f"""
    <section class='hero'>
      {html_kit.kpi("Overall AI Risk Score", html_kit.risk_gauge(trust.get('overall_ai_risk_score')), accent='#0f766e')}
      {html_kit.kpi("Files Scanned", report.get('files_scanned', 0), accent='#2563eb')}
      {html_kit.kpi("Findings", len(findings), accent='#dc2626')}
      {html_kit.kpi("Frameworks", escape(', '.join(frameworks) if frameworks else 'None'), f"{len(report.get('mcp_assets', []))} MCP assets", accent='#7c3aed')}
    </section>
    <section class='hero'>
      <div class='card'><h3>Risk Summary</h3>{severity_counts}</div>
      <div class='card'><h3>Components</h3><div>{len(components)}</div><div class='muted'>Diagnostics: {len(diagnostics)}</div><div class='muted'>Capability diff: {escape(str(diff_counts or 'N/A'))}</div></div>
      <div class='card'><h3>Baseline</h3>{baseline_html or "<div class='muted'>No baseline supplied.</div>"}</div>
    </section>

    <h2>Executive Summary</h2>
    <div class='card'><p>{escape("SafeAI scanned " + str(report.get("files_scanned", 0)) + " files" + (" for " + ", ".join(frameworks) if frameworks else "") + " and produced " + str(len(findings)) + " findings.")}</p>
    <p class='muted'>All results are static analysis evidence from source/configuration - they do not verify deployed runtime permissions, identities, or behavior.</p></div>

    <h2>Trust Scores</h2>
    {html_kit.data_table(["Category", "Score"], trust_rows, empty="No category scores.", searchable=False)}

    <h2>Capability Matrix</h2>
    {html_kit.data_table(["Capability", "Category", "Frameworks", "Confidence", "Evidence"], capability_rows, empty="No capabilities detected.")}

    {_escalation_section(report)}

    {_dependency_section(report)}

    <h2>Governance Summary</h2>
    {html_kit.data_table(
        ["Rule", "Category", "Message", "Recommendation"],
        [[f.get('rule_id', ''), f.get('risk_category', ''), f.get('message', ''), f.get('remediation', '')] for f in governance_summary],
        empty="No governance findings.",
    )}

    <h2>Failure-Class Coverage Matrix</h2>
    <p class='muted'>Groups governance findings by the class of failure they leave the agent unprepared for. A class is "uncovered" if any of its associated controls are missing.</p>
    {html_kit.data_table(
        ["Failure Class", "Status", "Description", "Uncovered Controls"],
        [[
            entry["failure_class"],
            '<span style="color:#dc2626">Uncovered</span>' if entry["status"] == "uncovered" else '<span style="color:#16a34a">Covered</span>',
            entry["description"],
            ", ".join(entry["covered_rules"]) or "—",
        ] for entry in failure_matrix],
        empty="No governance controls to evaluate.",
    )}

    <h2>Findings</h2>
    {html_kit.data_table(
        ["Severity", "Status", "Rule", "Category", "Location", "Message", "Evidence", "Recommendation"],
        [[
            f.get('severity', 'info'),
            f.get('status', ''),
            f.get('rule_id', ''),
            f.get('risk_category', ''),
            f"{f.get('file', '')}:{f.get('line', 1)}",
            f.get('message', ''),
            f.get('evidence', ''),
            f.get('remediation', ''),
        ] for f in findings],
        empty="No findings.",
    )}

    {_kya_section(report)}

    {_tool_surface_section(report)}

    {_assurance_section(report)}
    """

    html = html_kit.page(
        title="SafeAI Early Preview Report",
        subtitle=escape(", ".join(frameworks) if frameworks else ""),
        body=body,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        footer="SafeAI - static AI capability & risk analysis. No source code or secrets are uploaded or stored in this file.",
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
