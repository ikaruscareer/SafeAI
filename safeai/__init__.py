"""SafeAI — Static AI Capability & Risk Analyzer for AI agents and workflows."""

from __future__ import annotations

import os
import sys

from safeai.version import SAFEAI_VERSION

__version__ = SAFEAI_VERSION

# The setuptools console script imports ``safeai.cmd.cli`` before calling its
# main function. Handle the standalone version option at package import time
# so ``safeai --version`` does not reach the scan parser as an unknown option.
if (
    os.path.basename(sys.argv[0]).lower() in {"safeai", "safeai.exe"}
    and len(sys.argv) == 2
    and sys.argv[1] in {"--version", "-V"}
):
    print(__version__)
    raise SystemExit(0)
