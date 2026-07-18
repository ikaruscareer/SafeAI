"""Self-contained HTML report generator.

Produces a single-file HTML report with embedded CSS styling.
Includes executive summary, trust score breakdown, capability matrix,
governance summary, and a detailed findings table.
"""

from datetime import datetime, timezone
from html import escape


def _sev_class(severity):
    return {
        "critical": "sev-critical",
        "high": "sev-high",
        "medium": "sev-medium",
        "low": "sev-low",
        "info": "sev-info",
    }.get((severity or "").lower(), "sev-info")


def _findings_rows(findings):
    rows = []
    for finding in findings:
        sev = escape(str(finding.get("severity", "info")))
        cls = _sev_class(sev)
        rows.append(
            "<tr>"
            f"<td><span class='badge {cls}'>{sev}</span></td>"
            f"<td>{escape(str(finding.get('rule_id', '')))}</td>"
            f"<td>{escape(str(finding.get('file', '')))}:{escape(str(finding.get('line', 1)))}</td>"
            f"<td>{escape(str(finding.get('message', '')))}</td>"
            f"<td>{escape(str(finding.get('evidence', '')))}</td>"
            f"<td>{escape(str(finding.get('remediation', '')))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def write_html(report, path):
    trust = report.get("trust_score", {})
    categories = trust.get("categories", {})
    counts = report.get("counts", {})
    frameworks = report.get("detected_frameworks", [])
    findings = report.get("findings", [])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    capability_rows = []
    for cap in report.get("normalized_capabilities", []):
        capability_rows.append(
            "<tr>"
            f"<td>{escape(str(cap.get('name', '')))}</td>"
            f"<td>{escape(str(cap.get('category', '')))}</td>"
            f"<td>{escape(', '.join(cap.get('source_frameworks', [])))}</td>"
            f"<td>{escape(str(round(float(cap.get('confidence', 0.0)), 2)))}</td>"
            f"<td>{escape('; '.join(cap.get('evidence', [])))}</td>"
            "</tr>"
        )

    governance_summary = [f for f in findings if f.get("risk_category") in {"Governance", "Integration", "Identity"}]

    html = f"""<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>SafeAI Report</title>
  <style>
    :root {{ --bg:#f5f7fb; --card:#ffffff; --ink:#1f2937; --muted:#6b7280; --line:#e5e7eb; --brand:#0f766e; }}
    body {{ margin:0; font-family: 'Segoe UI', Tahoma, sans-serif; background:var(--bg); color:var(--ink); }}
    .container {{ max-width: 1200px; margin:0 auto; padding:24px; }}
    .hero {{ background: linear-gradient(135deg, #ecfeff, #f0fdf4); border:1px solid var(--line); border-radius:16px; padding:20px; }}
    .grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(220px,1fr)); gap:12px; margin-top:16px; }}
    .card {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px; }}
    h1,h2,h3 {{ margin:0 0 10px 0; }}
    h1 {{ font-size: 28px; }} h2 {{ margin-top:24px; font-size:20px; }}
    .muted {{ color:var(--muted); font-size:13px; }}
    table {{ width:100%; border-collapse: collapse; background:var(--card); border:1px solid var(--line); border-radius:12px; overflow:hidden; }}
    th, td {{ text-align:left; font-size:13px; padding:10px; border-bottom:1px solid var(--line); vertical-align:top; }}
    th {{ background:#f8fafc; }}
    .badge {{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; font-weight:600; }}
    .sev-critical {{ background:#fee2e2; color:#991b1b; }}
    .sev-high {{ background:#ffedd5; color:#9a3412; }}
    .sev-medium {{ background:#fef9c3; color:#854d0e; }}
    .sev-low {{ background:#dbeafe; color:#1e3a8a; }}
    .sev-info {{ background:#ecfeff; color:#155e75; }}
    @media print {{ body {{ background:#fff; }} .hero {{ background:#fff; }} }}
  </style>
</head>
<body>
  <div class='container'>
    <section class='hero'>
      <h1>SafeAI Early Preview Report</h1>
      <div class='muted'>Generated {escape(now)}</div>
      <div class='grid'>
        <div class='card'><h3>Executive Summary</h3><div>Files Scanned: {report.get('files_scanned', 0)}</div><div>Findings: {len(findings)}</div><div>Overall AI Risk Score: {trust.get('overall_ai_risk_score', 'N/A')}</div></div>
        <div class='card'><h3>Detected Frameworks</h3><div>{escape(', '.join(frameworks) if frameworks else 'None')}</div><div class='muted'>MCP Assets: {len(report.get('mcp_assets', []))}</div></div>
        <div class='card'><h3>Risk Summary</h3><div>Critical: {counts.get('critical', 0)}</div><div>High: {counts.get('high', 0)}</div><div>Medium: {counts.get('medium', 0)}</div></div>
      </div>
    </section>

    <h2>Trust Scores</h2>
    <table>
      <thead><tr><th>Category</th><th>Score</th></tr></thead>
      <tbody>
        {''.join([f"<tr><td>{escape(k)}</td><td>{escape(str(v))}</td></tr>" for k, v in categories.items()])}
      </tbody>
    </table>

    <h2>Capability Matrix</h2>
    <table>
      <thead><tr><th>Capability</th><th>Category</th><th>Frameworks</th><th>Confidence</th><th>Evidence</th></tr></thead>
      <tbody>{''.join(capability_rows)}</tbody>
    </table>

    <h2>Governance Summary</h2>
    <table>
      <thead><tr><th>Rule</th><th>Category</th><th>Message</th><th>Recommendation</th></tr></thead>
      <tbody>
        {''.join([f"<tr><td>{escape(str(f.get('rule_id', '')))}</td><td>{escape(str(f.get('risk_category', '')))}</td><td>{escape(str(f.get('message', '')))}</td><td>{escape(str(f.get('remediation', '')))}</td></tr>" for f in governance_summary])}
      </tbody>
    </table>

    <h2>Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th><th>Evidence</th><th>Recommendations</th></tr></thead>
      <tbody>{_findings_rows(findings)}</tbody>
    </table>
  </div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
