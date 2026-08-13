#!/usr/bin/env python3
"""Sanitise a private SafeAI report into a public-safe summary.

This module performs classification and redaction. It never writes raw
secret values, tokens, API keys, or personal data into the public summary.
It is pure static processing of the SafeAI JSON report.

Public fields are additionally hardened against Markdown/HTML/URL injection
because finding text originates from the scanned (potentially adversarial)
repository.
"""
from __future__ import annotations

import argparse
import json
import re
from typing import Any

# Patterns that strongly suggest secret material. Redacted before any public output.
_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"ghr_[A-Za-z0-9]{36,}"),
    re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}"),
    re.compile(r"(?i)api[_-]?key[\"'=:\s]+[A-Za-z0-9._-]{16,}"),
    re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----"),
    re.compile(r"(?:mongodb|postgres(?:ql)?|mysql|redis)://\S+"),
]

_SENSITIVE_KEYWORDS = [
    "password", "secret", "token", "apikey", "api_key", "credential",
    "privatekey", "private_key", "passphrase", "auth", "authorization",
]

# Public text hardening.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HTML_RE = re.compile(r"<[^>]+>")
_URL_RE = re.compile(r"https?://\S+")
# Dangerous URI schemes that could execute code if rendered as a link.
_DANGEROUS_SCHEME_RE = re.compile(r"(?i)\b(?:javascript|data|vbscript):[^\s)]*")
_MARKDOWN_META_RE = re.compile(r"([\\`*_{}\[\]()#+\-.!|>&~^])")
_WS_RE = re.compile(r"\s+")

# Maximum length (in characters) allowed for any public text field.
MAX_PUBLIC_TEXT_LEN = 280
# Maximum length for a sanitised source path.
MAX_PATH_LEN = 160


def redact_secret(text: str) -> str:
    """Return text with any obvious secret material replaced by a placeholder."""
    if not text:
        return text
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED_SECRET]", text)
    return text


def sanitize_text(value: Any, max_len: int = MAX_PUBLIC_TEXT_LEN) -> str:
    """Return a safely escaped, bounded, de-identified string.

    Strips control characters, HTML tags, and URLs; escapes Markdown
    metacharacters; and truncates to ``max_len``.
    """
    if value is None:
        return ""
    text = str(value)
    text = _CONTROL_RE.sub("", text)
    text = _HTML_RE.sub("", text)
    text = _MARKDOWN_META_RE.sub(r"\\\1", text)
    text = redact_secret(text)
    # URL redaction runs last so its placeholder brackets are not re-escaped.
    text = _URL_RE.sub("[URL_REDACTED]", text)
    text = _DANGEROUS_SCHEME_RE.sub("[URL_REDACTED]", text)
    text = _WS_RE.sub(" ", text).strip()
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "\u2026"
    return text


def sanitize_location(loc: Any) -> Any:
    """Return a safe location dict or ``None``.

    Only relative source paths using a safe character set and small integer
    line numbers are preserved; anything else is dropped.  Secrets embedded
    in the path (e.g. ``src/sk-abcdef…py``) are redacted.
    """
    if not isinstance(loc, dict):
        return None
    raw_file = str(loc.get("file", "") or "")
    if not re.match(rf"^[\w./\-]{{1,{MAX_PATH_LEN}}}$", raw_file):
        return {"file": "[REDACTED_PATH]", "line": None}
    raw_file = redact_secret(raw_file)
    line = loc.get("line")
    if isinstance(line, int) and 0 < line < 10_000_000:
        safe_line = line
    else:
        safe_line = None
    return {"file": raw_file, "line": safe_line}


def looks_sensitive(finding: dict[str, Any]) -> bool:
    blob = json.dumps(finding, default=str).lower()
    return any(kw in blob for kw in _SENSITIVE_KEYWORDS)


def classify(finding: dict[str, Any]) -> str:
    """Classify a finding into one of the five disclosure categories."""
    severity = str(finding.get("severity", "")).lower()
    if severity not in ("critical", "high", "medium", "low", "informational"):
        severity = "informational"
    if looks_sensitive(finding):
        return "potentially_sensitive"
    if severity in ("critical", "high"):
        # Clear static evidence may be high confidence, but remains review
        # unless a human confirms. Default to review_recommended.
        return "review_recommended"
    return "informational"


def classify_all(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {
        "informational": 0,
        "review_recommended": 0,
        "high_confidence_security_concern": 0,
        "potentially_sensitive": 0,
        "not_publishable": 0,
    }
    for f in findings:
        counts[classify(f)] += 1
    return counts


def _extract_score(report: dict[str, Any]) -> Any:
    scorecard = report.get("safeai_security_scorecard")
    if isinstance(scorecard, dict):
        summary = scorecard.get("summary")
        if isinstance(summary, dict) and "score" in summary:
            return summary["score"]
        if "score" in scorecard:
            return scorecard["score"]
    return report.get("score")


def sanitise_report(report: dict[str, Any]) -> dict[str, Any]:
    """Produce a public-safe summary object derived from a private report."""
    findings = report.get("findings", []) or []
    counts = classify_all(findings)

    public_findings = []
    for f in findings:
        cls = classify(f)
        if cls in ("potentially_sensitive", "not_publishable"):
            continue
        public_findings.append({
            "id": sanitize_text(f.get("id") or f.get("rule_id"), 64),
            "rule_id": sanitize_text(f.get("rule_id"), 64),
            "severity": sanitize_text(f.get("severity"), 24),
            "category": sanitize_text(f.get("category"), 64),
            "classification": cls,
            "location": sanitize_location(f.get("location")),
            "summary": sanitize_text(f.get("summary")),
        })

    score = _extract_score(report)

    return {
        "display_name": sanitize_text(report.get("display_name", "unknown"), 64),
        "repository": sanitize_text(report.get("repository"), 120),
        "resolved_commit_sha": sanitize_text(report.get("resolved_commit_sha"), 64),
        "safeai_version": sanitize_text(report.get("safeai_version"), 32),
        "scan_timestamp_utc": sanitize_text(report.get("scan_timestamp_utc"), 32),
        "scope": sanitize_text(report.get("scope"), 64),
        "safeai_score": sanitize_text(score, 16) if isinstance(score, str) else score,
        "status": sanitize_text(report.get("status", "REVIEW"), 16),
        "finding_counts": counts,
        "review_count": counts["review_recommended"],
        "high_confidence_count": counts["high_confidence_security_concern"],
        "sensitive_count": counts["potentially_sensitive"] + counts["not_publishable"],
        "main_themes": _derive_themes(public_findings),
        "findings": public_findings,
    }


def _derive_themes(findings: list[dict[str, Any]]) -> list[str]:
    themes: dict[str, int] = {}
    for f in findings:
        cat = sanitize_text(f.get("category") or "uncategorized", 48)
        themes[cat] = themes.get(cat, 0) + 1
    return [f"{cat} ({n})" for cat, n in sorted(themes.items(), key=lambda kv: kv[1], reverse=True)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sanitise a private SafeAI report.")
    parser.add_argument("--report", required=True, help="Path to private SafeAI JSON report")
    parser.add_argument("--out", required=True, help="Path to write the public summary JSON")
    args = parser.parse_args(argv)

    with open(args.report, "r", encoding="utf-8") as fh:
        report = json.load(fh)

    summary = sanitise_report(report)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"Wrote sanitised summary to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
