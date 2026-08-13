"""Module entry point for ``python -m safeai``."""
# ruff: noqa: I001
from __future__ import annotations

import sys

from safeai.version import SAFEAI_VERSION, print_version, version_requested


if __name__ == "__main__":
    if version_requested(sys.argv[1:]):
        print_version(SAFEAI_VERSION)
        raise SystemExit(0)

    from safeai.cmd.cli import main

    sys.exit(main())
