#!/usr/bin/env python3
"""Coverage-guided fuzz target for public SafeAI report sanitisation."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import atheris

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "community-scans" / "scripts"))

from sanitise_report import sanitise_report  # noqa: E402


def test_one_input(data: bytes) -> None:
    try:
        value = json.loads(data.decode("utf-8", errors="replace"))
    except (UnicodeError, json.JSONDecodeError):
        return
    if not isinstance(value, dict):
        return

    report = {
        "display_name": value.get("display_name", "fuzz"),
        "repository": value.get("repository", "owner/repository"),
        "resolved_commit_sha": value.get("resolved_commit_sha", ""),
        "safeai_version": value.get("safeai_version", "test"),
        "scan_timestamp_utc": value.get("scan_timestamp_utc", ""),
        "scope": "static",
        "status": "REVIEW",
        "findings": value.get("findings", []),
    }
    try:
        summary = sanitise_report(report)
    except (AttributeError, KeyError, TypeError, ValueError):
        return
    if not isinstance(summary, dict):
        raise AssertionError("sanitise_report must return a mapping")
    public = json.dumps(summary, default=str)
    for secret_prefix in ("sk-", "AKIA", "ghp_", "github_pat_", "xoxb-"):
        if secret_prefix in public:
            raise AssertionError(f"public summary exposed secret-like prefix: {secret_prefix}")


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
