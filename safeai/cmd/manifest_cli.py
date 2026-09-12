"""``safeai manifest`` subcommands — local manifest contract operations.

All operations are offline: read a JSON file, validate or verify it
against the local contract, print deterministic results. No network,
no execution of scanned code.
"""

from __future__ import annotations

import json

from safeai.kya.contract import validate_manifest


def run_manifest_command(args):
    """Dispatch ``safeai manifest <validate|verify>``. Returns exit code."""
    sub = getattr(args, "manifest_command", None)
    if sub == "validate":
        return _validate(args.file)
    if sub == "verify":
        from safeai.kya.integrity import verify_manifest_file
        return verify_manifest_file(args.file)
    print("Usage: safeai manifest {validate|verify} <file>")
    return 2


def _validate(path):
    try:
        with open(path, encoding="utf-8") as fh:
            document = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"invalid: unable to read {path}: {exc}")
        return 1
    errors, warnings = validate_manifest(document)
    for warning in warnings:
        print(f"warning: {warning}")
    if errors:
        print(f"invalid: {path} ({len(errors)} error(s))")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"valid: {path} (contract safeai-manifest v1, "
          f"schema_version {document.get('schema_version')})")
    return 0
