"""Entry point for ``python -m safeai``."""

import sys

from safeai.cmd.cli import main

if __name__ == "__main__":
    sys.exit(main())
