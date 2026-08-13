"""Module entry point for ``python -m safeai``."""
from __future__ import annotations

import sys

from safeai import __version__
from safeai.version import print_version, version_requested


if __name__ == "__main__":
    if version_requested(sys.argv[1:]):
        print_version(__version__)
        raise SystemExit(0)

    from safeai.cmd.cli import main

    sys.exit(main())
