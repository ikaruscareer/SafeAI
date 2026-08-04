"""Public scan API for SafeAI (backward-compatible facade).

The pipeline implementation now lives in :mod:`safeai.engine.orchestrator`
(see :class:`~safeai.engine.orchestrator.ScanOrchestrator`, whose stage
methods replace the former monolithic ``run_scan``). This module keeps the
historical entry points — ``run_scan`` and ``collect_files`` — so existing
imports keep working unchanged.
"""

from safeai.engine.orchestrator import (
    EXCLUDED_DIRS,
    MAX_FILE_BYTES,
    ScanOrchestrator,
    collect_dependency_files,
    collect_files,
    extract_dependencies,
    run_scan,
)

__all__ = [
    "EXCLUDED_DIRS",
    "MAX_FILE_BYTES",
    "ScanOrchestrator",
    "collect_dependency_files",
    "collect_files",
    "extract_dependencies",
    "run_scan",
]
