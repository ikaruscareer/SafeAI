"""Telemetry configuration — env vars, state file, CI detection.

Implements the precedence rules from PRIVACY.md:
1. DO_NOT_TRACK=1 → off (highest priority)
2. SAFEAI_TELEMETRY=0 → off
3. CI detected + SAFEAI_TELEMETRY_IN_CI != 1 → off
4. SAFEAI_TELEMETRY=1 → on
5. State file enabled=true → on
6. Default → off
"""

import json
import os
import uuid
from pathlib import Path

# CI-indicator environment variables
_CI_INDICATORS = frozenset({
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "TRAVIS",
    "CIRCLECI",
    "JENKINS_URL",
    "BUILDKITE",
    "TF_BUILD",
})

# State file location
_STATE_DIR = Path.home() / ".safeai"
_STATE_FILE = _STATE_DIR / "telemetry.json"


def is_ci() -> bool:
    """Detect CI environments. Returns True if any CI-indicator env var is truthy."""
    for var in _CI_INDICATORS:
        if os.environ.get(var):
            return True
    return False


def _get_state() -> dict:
    """Read the telemetry state file. Returns empty dict if not found or invalid."""
    try:
        return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _write_state(state: dict) -> None:
    """Write the telemetry state file. Creates parent directories if needed."""
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _get_or_create_install_id() -> str:
    """Get existing install_id or generate a new one."""
    state = _get_state()
    install_id = state.get("install_id")
    if not install_id:
        install_id = str(uuid.uuid4())
        state["install_id"] = install_id
        _write_state(state)
    return install_id


def is_telemetry_enabled() -> bool:
    """Check if telemetry is enabled, following the precedence rules.

    Returns True only if telemetry should be sent. The precedence is:
    1. DO_NOT_TRACK=1 → False
    2. SAFEAI_TELEMETRY=0 → False
    3. CI detected + SAFEAI_TELEMETRY_IN_CI != 1 → False
    4. SAFEAI_TELEMETRY=1 → True
    5. State file enabled=true → True
    6. Default → False
    """
    # 1. DO_NOT_TRACK overrides everything
    do_not_track = os.environ.get("DO_NOT_TRACK", "").strip().lower()
    if do_not_track in ("1", "true", "yes"):
        return False

    # 2. Explicit disable
    safeai_telemetry = os.environ.get("SAFEAI_TELEMETRY", "").strip()
    if safeai_telemetry == "0":
        return False

    # 3. CI auto-disable (unless explicitly overridden)
    if is_ci() and os.environ.get("SAFEAI_TELEMETRY_IN_CI", "").strip() != "1":
        return False

    # 4. Explicit enable via env var
    if safeai_telemetry == "1":
        return True

    # 5. State file
    state = _get_state()
    # 6. Default off
    return state.get("enabled") is True


def set_telemetry_enabled(enabled: bool) -> None:
    """Enable or disable telemetry in the state file.

    Preserves the install_id if it exists. Does nothing if disabling
    and no state file exists.
    """
    state = _get_state()
    if not enabled and not state:
        return
    state["enabled"] = enabled
    if "install_id" not in state:
        state["install_id"] = str(uuid.uuid4())
    _write_state(state)


def get_install_id() -> str:
    """Get the installation ID, creating one if needed."""
    return _get_or_create_install_id()


def get_invocation_context() -> str:
    """Detect how SafeAI was invoked.

    Returns one of: "github-action", "ci-other", "cli", "unknown".
    """
    if os.environ.get("GITHUB_ACTIONS"):
        return "github-action"
    if is_ci():
        return "ci-other"
    return "cli"


def get_status_text() -> str:
    """Return human-readable telemetry status."""
    enabled = is_telemetry_enabled()
    state = _get_state()
    install_id = state.get("install_id", "not generated")

    lines = [
        f"Telemetry: {'ON' if enabled else 'OFF'}",
        f"Install ID: {install_id}",
    ]

    if enabled:
        lines.append(f"Invocation context: {get_invocation_context()}")
        lines.append("Auto-disabled in CI unless SAFEAI_TELEMETRY_IN_CI=1 is also set.")

    lines.append("To disable: safeai telemetry off or export DO_NOT_TRACK=1")
    return "\n".join(lines)
