"""IaC authority correlation (v2.5 IaC evidence, Lane B).

Compares **declared capability** (tool surface) against **granted
authority** (Grant triples from in-repo Terraform / Kubernetes YAML)
and records one verdict per authority family:

- ``MATCH`` — declared capability and IaC grant in the same family with
  a statically evidenced Agent→Identity link. Recorded only (no finding).
- ``EXCESS_AUTHORITY`` — IaC grants authority no declared capability
  consumes (least-privilege gap).
- ``AUTHORITY_MISMATCH`` — declared capability with no IaC grant in its
  family while the repo does carry IaC (probable breakage, or the grant
  lives outside this repository — the message says so).
- ``UNVERIFIED_LINK`` — both sides present but no static link between
  the agent and the granted identity (the common case).
- ``UNKNOWN`` — IaC present but unparseable, or no usable signal.

Every finding pre-sets ``provenance_class="repo-iac-observed"`` and
``gateability="review-only"`` (preserved by ``enrich.normalize_findings``
via setdefault). IaC output never fails a gate — see ADR-0008 and the
architectural invariant suite. Repository IaC is evidence of declared
grants, never proof of deployed permission.
"""

#: Correlation finding rule ids.
RULE_EXCESS = "IAC_EXCESS_AUTHORITY"
RULE_MISMATCH = "IAC_AUTHORITY_MISMATCH"
RULE_UNVERIFIED = "IAC_UNVERIFIED_LINK"

#: Correlation verdict vocabulary (ADR-0007).
VERDICTS = ("MATCH", "EXCESS_AUTHORITY", "AUTHORITY_MISMATCH",
            "UNVERIFIED_LINK", "UNKNOWN")

#: Authority families with IaC coverage in v2.5.
FAMILIES = ("cloud", "kubernetes")

#: Declared capability name -> IaC family. Exact match on the lowercased
#: name only — never substring (house rule against jdbc/db-style FPs).
_DECLARED_CAP_TO_FAMILY = {
    "s3": "cloud",
    "cloud": "cloud",
    "cloud_services": "cloud",
    "gcp": "cloud",
    "kubernetes": "kubernetes",
}

_PROVENANCE = "repo-iac-observed"
_GATEABILITY = "review-only"


def _cap_name(cap):
    if isinstance(cap, dict):
        return cap.get("name")
    return str(cap)


def _declared_by_family(report):
    """Map IaC family -> set of declaring tool keys (tool surface first)."""
    by_family = {}
    surface = report.get("tool_surface")
    tools = []
    if isinstance(surface, list):
        tools = surface
    elif isinstance(surface, dict):
        tools = surface.get("tools") or []
    for entry in tools:
        if not isinstance(entry, dict):
            continue
        tool_key = entry.get("tool_key") or entry.get("name")
        for cap in entry.get("capabilities") or []:
            fam = _DECLARED_CAP_TO_FAMILY.get(str(_cap_name(cap) or "").lower())
            if fam:
                by_family.setdefault(fam, set()).add(str(tool_key))
    if not by_family:
        for cap in report.get("normalized_capabilities") or []:
            fam = _DECLARED_CAP_TO_FAMILY.get(str(_cap_name(cap) or "").lower())
            if fam:
                by_family.setdefault(fam, set()).add("<surface>")
    return by_family


def _inventory_names(report):
    """Lowercased config/credential names referenced by the agent."""
    names = set()
    for finding in report.get("findings") or []:
        if finding.get("rule_id") == "ENV_DEP_INVENTORY":
            for entry in finding.get("dep_inventory") or []:
                name = entry.get("name")
                if name:
                    names.add(str(name).lower())
    return names


def _link_evidence(name, inventory_names, tool_keys):
    """Return link evidence string when an identity is statically linked.

    A link exists only on case-insensitive exact match against a name the
    agent references (env/config inventory) or a tool key. Partial and
    substring matches never link — they stay UNVERIFIED_LINK.
    """
    lowered = str(name or "").lower().strip()
    if not lowered or lowered in ("<unattached>", "<unnamed>", "<unknown-role>"):
        return None
    if lowered in inventory_names:
        return f"identity {name!r} referenced in dependency inventory"
    if lowered in {str(k).lower() for k in tool_keys}:
        return f"identity {name!r} matches a tool key"
    return None


def correlate_iac_authority(report, grants, bindings, identities, meta=None):
    """Correlate IaC grants against the declared tool surface.

    Returns ``(findings, summary)``. Findings target the ``IAC_*`` rule
    ids, all review-only. ``summary`` carries grants, bindings,
    identities, per-family verdicts, and counts for report rendering,
    the manifest, and PR output.
    """
    meta = meta or {}
    grants = [g for g in grants or [] if isinstance(g, dict)]
    bindings = [b for b in bindings or [] if isinstance(b, dict)]
    identities = [i for i in identities or [] if isinstance(i, dict)]

    declared = _declared_by_family(report)
    inventory_names = _inventory_names(report)
    tool_keys = set()
    surface = report.get("tool_surface")
    tools = surface if isinstance(surface, list) else (surface or {}).get("tools") or []
    for entry in tools:
        if isinstance(entry, dict) and entry.get("tool_key"):
            tool_keys.add(entry["tool_key"])

    grants_by_family = {}
    for grant in grants:
        fam = grant.get("family")
        if fam in FAMILIES:
            grants_by_family.setdefault(fam, []).append(grant)

    identity_names = [i.get("name") for i in identities]
    principal_names = [g.get("principal") for g in grants]
    for binding in bindings:
        principal_names.append(binding.get("subject_name"))
        principal_names.append(binding.get("role"))

    findings = []
    verdicts = []
    has_iac = bool((meta.get("tf_files") or meta.get("rbac_files"))
                   or grants or bindings or identities)

    for fam in FAMILIES:
        family_grants = grants_by_family.get(fam, [])
        family_tools = sorted(declared.get(fam, ()))
        linked = None
        for candidate in identity_names + principal_names:
            evidence = _link_evidence(candidate, inventory_names, tool_keys)
            if evidence:
                linked = evidence
                break
        refs = sorted({f"{g.get('source_file')}:{g.get('line', 1)}"
                       for g in family_grants})
        grant_refs = [
            {"principal": g.get("principal"), "action": g.get("action"),
             "resource": g.get("resource"), "source_file": g.get("source_file"),
             "line": g.get("line", 1), "provenance": g.get("provenance")}
            for g in family_grants
        ]

        if family_grants and family_tools and linked:
            verdict = "MATCH"
        elif family_grants and family_tools:
            verdict = "UNVERIFIED_LINK"
        elif family_grants:
            verdict = "EXCESS_AUTHORITY"
        elif family_tools and has_iac:
            # IaC exists but this family is uncovered — except when the
            # IaC itself failed to parse, in which case claiming absence
            # would be dishonest: UNKNOWN, recorded but silent.
            if meta.get("unparsed_files"):
                verdict = "UNKNOWN"
            else:
                verdict = "AUTHORITY_MISMATCH"
        else:
            continue

        verdicts.append({
            "family": fam,
            "verdict": verdict,
            "declared_tools": family_tools,
            "grants": grant_refs,
            "linked": bool(linked),
            "link_evidence": linked,
            "evidence_refs": refs,
        })
        finding = _verdict_finding(fam, verdict, family_tools, family_grants,
                                   linked, refs)
        if finding is not None:
            findings.append(finding)

    findings.sort(key=lambda f: (f.get("file", ""), int(f.get("line") or 0),
                                 f.get("rule_id", "")))
    counts = {"grants": len(grants), "verdicts": len(verdicts)}
    for verdict in verdicts:
        key = verdict["verdict"].lower()
        counts[key] = counts.get(key, 0) + 1
    summary = {
        "schema_version": 1,
        "correlation_model": "grant-triple vs tool-surface families (ADR-0007)",
        "lane": "B",
        "files": {
            "terraform": list(meta.get("tf_files") or []),
            "kubernetes_rbac": list(meta.get("rbac_files") or []),
            "unparsed": list(meta.get("unparsed_files") or []),
        },
        "grants": [
            {"principal": g.get("principal"), "action": g.get("action"),
             "resource": g.get("resource"), "source": g.get("source"),
             "source_file": g.get("source_file"), "line": g.get("line", 1),
             "provenance": g.get("provenance"),
             "fidelity_notes": list(g.get("fidelity_notes") or []),
             "family": g.get("family")}
            for g in grants
        ],
        "bindings": bindings,
        "identities": identities,
        "verdicts": verdicts,
        "counts": counts,
    }
    return findings, summary


def _verdict_finding(fam, verdict, tools, grants, linked, refs):
    """Build the review-only finding for a verdict (None for MATCH/UNKNOWN)."""
    if verdict in ("MATCH", "UNKNOWN"):
        return None
    first = grants[0] if grants else {}
    location = (first.get("source_file") or "<scan>",
                int(first.get("line") or 1))
    base = {
        "file": location[0],
        "line": location[1],
        "risk_category": "Integration",
        "affected_framework": "generic",
        "affected_capability": fam,
        "provenance_class": _PROVENANCE,
        "gateability": _GATEABILITY,
        "iac_family": fam,
        "iac_verdict": verdict,
        "evidence": f"verdict={verdict} family={fam} refs={', '.join(refs) or 'none'}",
    }
    if verdict == "EXCESS_AUTHORITY":
        base.update({
            "rule_id": RULE_EXCESS,
            "severity": "medium",
            "message": "Repository IaC grants authority no declared capability consumes",
            "owasp_llm": "LLM06",
            "reason": (
                f"Infrastructure-as-code grants {len(grants)} permission(s) in "
                f"family '{fam}' but no declared tool or capability consumes "
                "them — excess authority under least privilege. IaC is "
                "repository evidence, not proof of deployed permission."
            ),
            "remediation": (
                "Remove the unneeded grant, or declare and justify the "
                "capability that requires it; re-review on every IaC change."
            ),
            "confidence": 0.6,
            "score_contribution": 6,
        })
    elif verdict == "AUTHORITY_MISMATCH":
        base.update({
            "rule_id": RULE_MISMATCH,
            "severity": "low",
            "message": "Declared capability has no matching IaC grant in this repository",
            "reason": (
                f"Tool(s) {', '.join(tools) or 'unknown'} declare '{fam}' "
                "capability but no IaC grant covers it — probable breakage, "
                "or the grant lives outside this repository."
            ),
            "remediation": (
                "Confirm where the capability is granted; if it is granted "
                "outside this repository, record that link explicitly."
            ),
            "confidence": 0.5,
            "score_contribution": 3,
        })
    else:  # UNVERIFIED_LINK
        base.update({
            "rule_id": RULE_UNVERIFIED,
            "severity": "low",
            "message": "Declared capability and IaC grant coexist without a static link",
            "reason": (
                f"Both a declared '{fam}' capability "
                f"({', '.join(tools) or 'unknown'}) and {len(grants)} IaC "
                "grant(s) exist, but no static Agent-to-Identity link was "
                "found — the grant may or may not reach this agent."
            ),
            "remediation": (
                "Establish which identity the agent assumes (service account, "
                "role) and record it; without that link this stays review-only."
            ),
            "confidence": 0.55,
            "score_contribution": 3,
        })
    return base
