"""Canonical KYA manifest: ``safeai-manifest.json`` (schema version 1.2).

The manifest is the portable public contract for scan-derived KYA
evidence. The SQLite registry is an implementation detail; integrations
should consume the manifest, not the database.

Determinism contract:
  * Same repository, configuration, ruleset, and commit produce an
    equivalent manifest (``generated_at``/``scan_id``/timestamps aside).
  * Serialization uses sorted keys and stable ordering of agents and
    findings so diffs between runs are meaningful.
  * No raw source code or unredacted secret values are ever included.
"""

import json

from safeai.kya import (
    MANIFEST_SCHEMA_VERSION,
    MANIFEST_TYPE,
    STATIC_ANALYSIS_DISCLAIMER,
)
from safeai.kya.assurance import build_assurance_boundary
from safeai.kya.fingerprints import normalize_path
from safeai.kya.util import confidence_label, redact_secrets, sha256_text
from safeai.severity import SEVERITIES

SEVERITY_ORDER = list(reversed(SEVERITIES))


def config_hash(effective_config):
    """Compute a deterministic SHA-256 hash of normalized configuration."""
    canonical = json.dumps(effective_config or {}, sort_keys=True, separators=(",", ":"), default=str)
    return sha256_text(canonical)


def _finding_entry(finding):
    return {
        "finding_id": finding.get("finding_id") or finding.get("fingerprint"),
        "rule_id": finding.get("rule_id"),
        "severity": finding.get("severity", "medium"),
        "title": finding.get("title") or str(finding.get("message", "")).split("\n")[0][:120],
        "message": redact_secrets(str(finding.get("message", ""))),
        "remediation": finding.get("remediation"),
        "confidence": confidence_label(finding.get("confidence_label") or finding.get("confidence")),
        "provenance": finding.get("provenance") or {"analyzer": "unknown", "evidence": []},
        "location": {
            "path": normalize_path(finding.get("file")),
            "line_start": int(finding.get("line") or 0),
            "line_end": int(finding.get("line") or 0),
        },
        "fingerprint": finding.get("fingerprint"),
        "status": finding.get("status", "unknown"),
    }


def _capability_counts(agents, report):
    counts = {}
    seen = set()
    for agent in agents:
        for cap in agent.get("capabilities") or []:
            name = str(cap.get("name", "")).lower()
            if name and name not in seen:
                seen.add(name)
                category = cap.get("category", "Capability")
                counts[category] = counts.get(category, 0) + 1
    if not counts:
        for cap in report.get("normalized_capabilities") or []:
            category = cap.get("category", "Capability")
            counts[category] = counts.get(category, 0) + 1
    return dict(sorted(counts.items()))


def build_manifest(report, *, project, scan_meta, safeai_meta, agents,
                   policy_decision=None, limitations=None):
    """Assemble the canonical manifest dict from a normalized scan report.

    Parameters
    ----------
    report : dict
        The scan report (findings already normalized via ``enrich``).
    project : dict
        Keys: ``project_id``, ``name``, ``source_root``, ``repository``.
    scan_meta : dict
        Keys: ``scan_id``, ``started_at``, ``completed_at``.
    safeai_meta : dict
        Keys: ``version``, ``ruleset_version``, ``config_hash``.
    agents : list
        KYA agent records (from ``enrich.build_agent_records``).
    policy_decision : dict, optional
        Evaluated policy outcome; defaults to ``warn``-style neutral.
    """
    findings = [_finding_entry(f) for f in report.get("findings", [])]
    findings.sort(key=lambda f: (f["fingerprint"] or ""))

    severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        sev = finding.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    trust = report.get("trust_score") or {}

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "manifest_type": MANIFEST_TYPE,
        "generated_at": scan_meta.get("completed_at"),
        "safeai": {
            "version": safeai_meta.get("version"),
            "ruleset_version": safeai_meta.get("ruleset_version"),
            "config_hash": safeai_meta.get("config_hash"),
        },
        "project": {
            "project_id": project.get("project_id"),
            "name": project.get("name"),
            "source_root": project.get("source_root"),
            "repository": project.get("repository") or {},
        },
        "scan": {
            "scan_id": scan_meta.get("scan_id"),
            "started_at": scan_meta.get("started_at"),
            "completed_at": scan_meta.get("completed_at"),
            "files_scanned": int(report.get("files_scanned") or 0),
            "analysis_coverage": {
                "languages": sorted({"python"} & {"python"}) if report.get("semantic_docs") else ["python"],
                "frameworks_detected": sorted(report.get("detected_frameworks") or []),
                "limitations": ["Static analysis only; dynamic/custom wrappers may reduce coverage."],
            },
        },
        "agents": sorted(agents, key=lambda a: a["agent_id"]),
        # v1.1: per-tool capability surface. Which named tool holds which
        # capability, at which access mode — the unit the v1.4 diff compares.
        "tool_surface": sorted(
            report.get("tool_surface") or [],
            key=lambda t: str(t.get("tool_key")),
        ),
        "components": [
            {
                "type": c.get("type", "unknown"),
                "name": c.get("name"),
                "path": normalize_path(c.get("file")),
            }
            for c in (report.get("components") or [])
        ],
        "findings": findings,
        "summary": {
            "risk_score": trust.get("overall_ai_risk_score"),
            "severity_counts": severity_counts,
            "capability_counts": _capability_counts(agents, report),
            "agent_count": len(agents),
            "component_count": len(report.get("components") or []),
            "policy_decision": policy_decision or {"outcome": "warn", "reasons": ["No policy file supplied; default posture."]},
        },
        # v1.2: the assurance boundary states what this scan verified and
        # what it structurally cannot. ``limitations`` is kept as the
        # single-line form rather than duplicated prose.
        "assurance_boundary": report.get("assurance_boundary") or build_assurance_boundary(report),
        "limitations": limitations or [STATIC_ANALYSIS_DISCLAIMER],
    }
    return manifest


def serialize_manifest(manifest):
    """Serialize a manifest deterministically (sorted keys, 2-space indent)."""
    return json.dumps(manifest, indent=2, sort_keys=True, default=str) + "\n"


def write_manifest(manifest, path):
    """Write the manifest to ``path`` with deterministic serialization."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(serialize_manifest(manifest))


def manifest_fingerprints(manifest):
    """Return the set of finding fingerprints in a manifest document."""
    return {
        f.get("fingerprint")
        for f in (manifest.get("findings") or [])
        if f.get("fingerprint")
    }
