"""Regression tests for SafeAI version reporting."""
from __future__ import annotations

import subprocess
import sys

import safeai
from safeai.version import version_requested


def test_version_requested_accepts_long_and_short_flags():
    assert version_requested(["--version"])
    assert version_requested(["-V"])
    assert not version_requested([])
    assert not version_requested(["--version", "extra"])


def test_module_version_command():
    result = subprocess.run(
        [sys.executable, "-m", "safeai", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == safeai.__version__
    assert "unrecognized arguments" not in result.stderr


def test_module_short_version_command():
    result = subprocess.run(
        [sys.executable, "-m", "safeai", "-V"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == safeai.__version__
