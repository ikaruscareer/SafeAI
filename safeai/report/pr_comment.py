"""Pull-request comment renderer.

A reviewer has seconds, not minutes. This renderer exists to answer one
question at a glance: **did a named tool or MCP server acquire new
authority in this change?** Everything that does not serve that question
is left out — no inventory tables, no severity legends, no "0 findings"
banners, no unchanged surface.

Design constraints, all enforced by tests:

* The stable marker ``<!-- safeai:pr-comment:v1 -->`` is always the first
  line, so CI can update one comment in place instead of posting a new
  one on every push.
* Blocks are grouped **by tool**, ordered by severity. Rules are detail,
  tools are the subject.
* A typical change renders in under 20 lines; the hard cap is 60, after
  which the body is truncated with a pointer to the full report.
* Deterministic: no timestamps, no run IDs, no durations, no elapsed
  times. Two runs on the same report are byte-identical.
* Nothing is posted anywhere. This module returns a string.
"""

from safeai.analysis.tool_identity import display_name
from safeai.kya.assurance import BOUNDARY_SENTENCE

#: CI keys on this to find its own previous comment.
MARKER = "<!-- safeai:pr-comment:v1 -->"

#: Hard ceiling on rendered lines, including marker and footer.
MAX_LINES = 60

#: Target for a typical change. Not enforced, but the layout is tuned
#: so that a two-escalation report lands well inside it.
TARGET_LINES = 20

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

#: Severity marks. Text, not colour: PR comments render on many themes.
_SEVERITY_MARK = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

_FOOTER = f"_{BOUNDARY_SENTENCE}_"

#: Escalations below this severity are not worth a reviewer's attention
#: in the summary block; they remain in the full report.
_MIN_SEVERITY = "medium"


def _severity_rank(severity):
    return _SEVERITY_ORDER.get(str(severity or "low").lower(), 99)


def _plural(count, singular, plural=None):
    return singular if count == 1 else (plural or singular + "s")


def _evidence_label(evidence):
    """Render the first evidence location as ``path:line``.

    Only a path and a line number are emitted — never source text.
    """
    for item in evidence or []:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if not path:
            continue
        line = item.get("line")
        return f"`{path}:{line}`" if line else f"`{path}`"
    return None


def _tool_blocks(diff):
    """Return one renderable block per tool that escalated, worst first."""
    blocks = []
    entries = list(diff.get("tools") or [])
    unattributed = diff.get("unattributed")
    if isinstance(unattributed, dict) and unattributed.get("escalations"):
        entries.append(unattributed)

    for entry in entries:
        escalations = [
            e for e in (entry.get("escalations") or [])
            if _severity_rank(e.get("severity")) <= _severity_rank(_MIN_SEVERITY)
        ]
        if not escalations:
            continue
        escalations = sorted(
            escalations,
            key=lambda e: (_severity_rank(e.get("severity")), str(e.get("id"))),
        )
        worst = escalations[0]
        blocks.append({
            "tool_key": entry.get("tool_key"),
            "label": display_name(entry.get("tool") or {}) or entry.get("tool_key"),
            "status": entry.get("status"),
            "access": entry.get("access_summary") or {},
            "access_changes": entry.get("access_mode_changes") or [],
            "severity": worst.get("severity"),
            "escalations": escalations,
        })

    return sorted(
        blocks,
        key=lambda b: (_severity_rank(b["severity"]), str(b["tool_key"])),
    )


def _access_phrase(block):
    """Short 'read → mutate' or 'new' phrase for the block heading.

    The tool-wide summary is the *maximum* mode across every capability,
    so it can stay flat while a specific capability escalates — an MCP
    server that already spawned a process still reads at ``execute``
    after its tools go from read-only to mutating. When that happens the
    capability-level change is the honest thing to show.
    """
    access = block["access"]
    before = access.get("before") if isinstance(access, dict) else None
    after = access.get("after") if isinstance(access, dict) else None
    if before and after and before != after:
        return f"{before} → {after}"
    if before and after and before == after:
        for change in block.get("access_changes") or []:
            change_before = change.get("before")
            change_after = change.get("after")
            if change_before and change_after and change_before != change_after:
                return f"{change.get('capability')}: {change_before} → {change_after}"
    if block["status"] == "new" and after:
        return f"new · {after}"
    if after:
        return str(after)
    return str(block["status"] or "changed")


def _render_block(block):
    """Two lines per tool: what it is, then why it matters."""
    mark = _SEVERITY_MARK.get(block["severity"], block["severity"])
    lines = [f"**`{block['tool_key']}`** — {_access_phrase(block)}  ⚠️ {mark}"]
    primary = block["escalations"][0]
    detail = str(primary.get("summary") or primary.get("id") or "").strip()
    evidence = _evidence_label(primary.get("evidence"))
    extra = len(block["escalations"]) - 1
    parts = [detail] if detail else []
    if evidence:
        parts.append(evidence)
    if extra > 0:
        parts.append(f"+{extra} more {_plural(extra, 'escalation')}")
    if parts:
        lines.append("  " + " · ".join(parts))
    lines.append("")
    return lines


def _first_scan_summary(report):
    """Rendered when there is no baseline: state facts, never a fake diff."""
    surface = report.get("tool_surface") or []
    agents = report.get("kya_agents") or report.get("agent_models") or []
    capabilities = []
    for entry in surface:
        for capability in entry.get("capabilities") or []:
            mode = capability.get("access_mode")
            if mode in {"execute", "mutate", "write"}:
                capabilities.append((capability.get("name"), mode, entry.get("tool_key")))
    capabilities = sorted(set(capabilities))[:3]

    scope = (
        f"{len(agents)} {_plural(len(agents), 'agent')} · "
        f"{len(surface)} {_plural(len(surface), 'tool')} in scope. "
        "No prior baseline, so no capability change can be shown yet."
    )
    lines = ["### SafeAI — first scan, establishing a baseline", "", scope]
    if capabilities:
        lines.append("")
        lines.append("Highest-authority capabilities found:")
        for name, mode, tool_key in capabilities:
            lines.append(f"- `{tool_key}` — {name} ({mode})")
    return lines


def _details_line(report, diff, shown):
    """One collapsed line of context. Never expands the reviewer's work."""
    counts = diff.get("counts") or {}
    bits = []
    policy = report.get("policy_decision") or {}
    outcome = policy.get("outcome")
    if outcome:
        bits.append(f"Policy: {outcome}")
    unchanged = counts.get("tools_unchanged")
    if unchanged:
        bits.append(f"{unchanged} unchanged {_plural(unchanged, 'tool')}")
    removed = counts.get("tools_removed")
    if removed:
        bits.append(f"{removed} removed {_plural(removed, 'tool')}")
    if not diff.get("baseline_tool_attribution", True):
        bits.append("baseline predates tool attribution")
    if not bits:
        return []
    return [f"<sub>{' · '.join(bits)} · {shown} shown</sub>", ""]


def _footer(report):
    """One-line assurance boundary, with the scan's real inference count.

    The generic sentence alone is easy to skim past. Naming how many
    values in *this* scan were inferred keeps the caveat specific.
    """
    boundary = report.get("assurance_boundary") or {}
    sentence = str(boundary.get("summary") or BOUNDARY_SENTENCE)
    inferred = boundary.get("inferred_value_count") or 0
    if inferred:
        sentence += (
            f" {inferred} access mode{'' if inferred == 1 else 's'} in this scan "
            "were inferred rather than declared."
        )
    return f"_{sentence}_"


def _truncate(lines, total_blocks, shown_blocks):
    """Enforce the hard line cap, leaving room for the notice and footer."""
    remaining = total_blocks - shown_blocks
    if len(lines) + 2 <= MAX_LINES and remaining <= 0:
        return lines
    budget = MAX_LINES - 3  # truncation notice, blank line, footer
    trimmed = lines[:budget]
    while trimmed and trimmed[-1] == "":
        trimmed.pop()
    if remaining > 0 or len(trimmed) < len(lines):
        hidden = max(remaining, 1)
        trimmed.append("")
        trimmed.append(f"_{hidden} more — see full report_")
    return trimmed


def render_pr_comment(report, ci_context=None):
    """Render the Markdown PR comment for ``report``.

    ``ci_context`` is accepted for provenance in the collapsed detail
    line and may be ``None``. The output is deterministic and contains no
    source text, secret values, or timestamps.
    """
    report = report or {}
    diff = report.get("capability_diff") or {}
    lines = [MARKER, ""]

    if not diff or not diff.get("baseline_available", False):
        lines.extend(_first_scan_summary(report))
        lines.extend(["", _footer(report)])
        return "\n".join(lines) + "\n"

    blocks = _tool_blocks(diff)
    if not blocks:
        lines.append("### SafeAI — no capability escalations in this change")
        lines.extend(["", _footer(report)])
        return "\n".join(lines) + "\n"

    total = sum(len(block["escalations"]) for block in blocks)
    heading = (
        f"### SafeAI — {total} capability "
        f"{_plural(total, 'escalation')} across "
        f"{len(blocks)} {_plural(len(blocks), 'tool')}"
    )
    lines.extend([heading, ""])

    body = []
    shown = 0
    for block in blocks:
        candidate = body + _render_block(block)
        # Reserve space for the detail line, footer, and blank separators.
        if len(lines) + len(candidate) > MAX_LINES - 4 and shown:
            break
        body = candidate
        shown += 1

    lines.extend(body)
    lines.extend(_details_line(report, diff, shown))
    lines = _truncate(lines, len(blocks), shown)

    while lines and lines[-1] == "":
        lines.pop()
    lines.extend(["", _footer(report)])
    return "\n".join(lines) + "\n"


def write_pr_comment(report, path, ci_context=None):
    """Write the rendered comment to ``path`` and return the text."""
    text = render_pr_comment(report, ci_context=ci_context)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return text
