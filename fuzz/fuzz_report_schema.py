#!/usr/bin/env python3
"""Coverage-guided fuzz target for provenance-report JSON schema validation."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import atheris
import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "community-scans" / "report-schema.json").read_text(encoding="utf-8"))
VALIDATOR = jsonschema.Draft7Validator(SCHEMA)


def test_one_input(data: bytes) -> None:
    try:
        candidate = json.loads(data.decode("utf-8", errors="replace"))
    except (UnicodeError, json.JSONDecodeError):
        return
    try:
        list(VALIDATOR.iter_errors(candidate))
    except (AttributeError, KeyError, TypeError, ValueError):
        return


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
