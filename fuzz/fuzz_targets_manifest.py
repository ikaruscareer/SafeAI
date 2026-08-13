#!/usr/bin/env python3
"""Coverage-guided fuzz target for community target-manifest YAML handling."""
from __future__ import annotations

import sys
from pathlib import Path

import atheris
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "community-scans" / "scripts"))

from validate_targets import validate_yaml_structure  # noqa: E402


def test_one_input(data: bytes) -> None:
    try:
        candidate = yaml.safe_load(data.decode("utf-8", errors="replace"))
    except (UnicodeError, yaml.YAMLError):
        return
    try:
        errors = validate_yaml_structure(candidate)
    except (AttributeError, KeyError, TypeError, ValueError):
        return
    if not isinstance(errors, list):
        raise AssertionError("target manifest validator must return a list")


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
