"""Telemetry client — sends opt-in usage events.

Uses urllib.request (stdlib) with a hard 2-second timeout. Any failure is
silent and non-fatal. The endpoint URL must be configured before sending.
"""

import json
import urllib.error
import urllib.request
from threading import Thread

from safeai.telemetry.config import is_telemetry_enabled
from safeai.telemetry.schema import build_event

# TODO(maintainer): confirm telemetry endpoint URL
# The module refuses to send while this placeholder is present.
_TELEMETRY_ENDPOINT = "TODO(maintainer): confirm telemetry endpoint URL"

_SEND_TIMEOUT_SECONDS = 2


def _send_event(event: dict) -> None:
    """Send a telemetry event via HTTP POST. Silently ignores all errors."""
    if _TELEMETRY_ENDPOINT.startswith("TODO"):
        return

    try:
        data = json.dumps(event).encode("utf-8")
        req = urllib.request.Request(
            _TELEMETRY_ENDPOINT,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_SEND_TIMEOUT_SECONDS) as resp:
            resp.read()
    except Exception:
        pass


def send_telemetry(command: str) -> None:
    """Send a telemetry event if enabled. Non-blocking, best-effort.

    This function should be called after the command's real work and
    exit-code determination, never before or interleaved with scan logic.

    Args:
        command: The command that was invoked (scan, init, registry, welcome, other)
    """
    if not is_telemetry_enabled():
        return

    event = build_event(command)

    # Fire in a background thread with daemon=True so it doesn't block exit
    thread = Thread(target=_send_event, args=(event,), daemon=True)
    thread.start()
