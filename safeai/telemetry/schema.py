"""Telemetry event schema.

The event dict built here must match PRIVACY.md field-for-field.
"""

import platform
import sys
from datetime import UTC, datetime

from safeai.telemetry.config import get_install_id, get_invocation_context
from safeai.version import SAFEAI_VERSION

# Valid command values — constrained enum, never raw argv
_VALID_COMMANDS = frozenset({"scan", "init", "registry", "welcome", "other"})


def build_event(command: str, invocation_context: str | None = None) -> dict:
    """Build a telemetry event dict matching PRIVACY.md schema.

    Args:
        command: One of "scan", "init", "registry", "welcome", "other"
        invocation_context: Override invocation context (for testing)

    Returns:
        Event dict with exactly the fields documented in PRIVACY.md.
    """
    if command not in _VALID_COMMANDS:
        command = "other"

    ctx = invocation_context or get_invocation_context()

    return {
        "schema_version": 1,
        "safeai_version": SAFEAI_VERSION,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "os_family": platform.system().lower(),
        "invocation_context": ctx,
        "command": command,
        "install_id": get_install_id(),
        "date": datetime.now(tz=UTC).date().isoformat(),
    }


def get_event_field_names() -> set[str]:
    """Return the set of field names in a telemetry event.

    Used for testing that the schema matches PRIVACY.md exactly.
    """
    return set(build_event("scan").keys())
