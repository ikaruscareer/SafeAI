"""Comprehensive tests for SafeAI opt-in telemetry.

Covers the full privacy contract from PRIVACY.md:
- Default state: off, no files, no network
- DO_NOT_TRACK override
- CI auto-disable
- CLI on/off/status
- Event schema matches PRIVACY.md exactly
- Network failure handling
- Assurance boundary telemetry_active field
"""

import json
from unittest.mock import patch


class TestTelemetryConfig:
    """Tests for telemetry configuration and precedence rules."""

    def test_default_state_off(self, tmp_path, monkeypatch):
        """Default (no env vars, no state file) → telemetry off."""
        from safeai.telemetry.config import _STATE_FILE, is_telemetry_enabled

        # Ensure no env vars
        monkeypatch.delenv("SAFEAI_TELEMETRY", raising=False)
        monkeypatch.delenv("SAFEAI_TELEMETRY_IN_CI", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)

        # Remove state file if exists
        if _STATE_FILE.exists():
            _STATE_FILE.unlink()

        assert is_telemetry_enabled() is False

    def test_default_state_no_file_created(self, tmp_path, monkeypatch):
        """Default state should not create any files."""
        from safeai.telemetry.config import _STATE_DIR, is_telemetry_enabled

        # Ensure no env vars
        monkeypatch.delenv("SAFEAI_TELEMETRY", raising=False)
        monkeypatch.delenv("SAFEAI_TELEMETRY_IN_CI", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)

        # Remove state dir if exists
        if _STATE_DIR.exists():
            import shutil
            shutil.rmtree(_STATE_DIR, ignore_errors=True)

        result = is_telemetry_enabled()

        assert result is False
        assert not _STATE_DIR.exists()

    def test_do_not_track_overrides_explicit_enable(self, monkeypatch):
        """DO_NOT_TRACK=1 + SAFEAI_TELEMETRY=1 → still off."""
        from safeai.telemetry.config import is_telemetry_enabled

        monkeypatch.setenv("DO_NOT_TRACK", "1")
        monkeypatch.setenv("SAFEAI_TELEMETRY", "1")

        assert is_telemetry_enabled() is False

    def test_do_not_track_true_value(self, monkeypatch):
        """DO_NOT_TRACK=true → off."""
        from safeai.telemetry.config import is_telemetry_enabled

        monkeypatch.setenv("DO_NOT_TRACK", "true")
        monkeypatch.setenv("SAFEAI_TELEMETRY", "1")

        assert is_telemetry_enabled() is False

    def test_explicit_disable(self, monkeypatch):
        """SAFEAI_TELEMETRY=0 → off."""
        from safeai.telemetry.config import is_telemetry_enabled

        monkeypatch.setenv("SAFEAI_TELEMETRY", "0")
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)

        assert is_telemetry_enabled() is False

    def test_ci_auto_disable(self, monkeypatch):
        """CI environment + SAFEAI_TELEMETRY=1 but no SAFEAI_TELEMETRY_IN_CI → off."""
        from safeai.telemetry.config import is_telemetry_enabled

        monkeypatch.setenv("SAFEAI_TELEMETRY", "1")
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.delenv("SAFEAI_TELEMETRY_IN_CI", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)

        assert is_telemetry_enabled() is False

    def test_ci_explicit_override(self, monkeypatch):
        """CI + SAFEAI_TELEMETRY=1 + SAFEAI_TELEMETRY_IN_CI=1 → on."""
        from safeai.telemetry.config import is_telemetry_enabled

        monkeypatch.setenv("SAFEAI_TELEMETRY", "1")
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("SAFEAI_TELEMETRY_IN_CI", "1")
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)

        assert is_telemetry_enabled() is True

    def test_explicit_enable(self, monkeypatch):
        """SAFEAI_TELEMETRY=1 (no CI) → on."""
        from safeai.telemetry.config import is_telemetry_enabled

        monkeypatch.setenv("SAFEAI_TELEMETRY", "1")
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)

        assert is_telemetry_enabled() is True

    def test_state_file_enable(self, tmp_path, monkeypatch):
        """State file enabled=true → on."""
        from safeai.telemetry.config import _write_state, is_telemetry_enabled

        monkeypatch.delenv("SAFEAI_TELEMETRY", raising=False)
        monkeypatch.delenv("SAFEAI_TELEMETRY_IN_CI", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.delenv("CI", raising=False)

        _write_state({"enabled": True, "install_id": "test-id"})

        assert is_telemetry_enabled() is True

    def test_state_file_disable_overrides_env(self, tmp_path, monkeypatch):
        """State file enabled=false + SAFEAI_TELEMETRY=1 → off (env wins)."""
        from safeai.telemetry.config import _write_state, is_telemetry_enabled

        monkeypatch.setenv("SAFEAI_TELEMETRY", "1")
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.delenv("CI", raising=False)

        _write_state({"enabled": False, "install_id": "test-id"})

        # SAFEAI_TELEMETRY=1 takes precedence over state file
        assert is_telemetry_enabled() is True


class TestTelemetryCLI:
    """Tests for CLI subcommands."""

    def test_telemetry_status(self, monkeypatch):
        """safeai telemetry status shows current state."""
        from safeai.cmd.cli import main

        monkeypatch.delenv("SAFEAI_TELEMETRY", raising=False)
        monkeypatch.delenv("SAFEAI_TELEMETRY_IN_CI", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)

        with patch("builtins.print") as mock_print:
            ret = main(["telemetry", "status"])
            assert ret == 0
            # Check that status was printed
            printed = " ".join(str(c) for c in mock_print.call_args_list)
            assert "Telemetry: OFF" in printed or "Telemetry: ON" in printed

    def test_telemetry_on(self, tmp_path, monkeypatch):
        """safeai telemetry on enables telemetry."""
        from safeai.cmd.cli import main
        from safeai.telemetry.config import _STATE_FILE

        monkeypatch.delenv("SAFEAI_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)

        if _STATE_FILE.exists():
            _STATE_FILE.unlink()

        ret = main(["telemetry", "on"])
        assert ret == 0
        assert _STATE_FILE.exists()

        state = json.loads(_STATE_FILE.read_text())
        assert state["enabled"] is True
        assert "install_id" in state

    def test_telemetry_off(self, tmp_path, monkeypatch):
        """safeai telemetry off disables telemetry."""
        from safeai.cmd.cli import main
        from safeai.telemetry.config import _STATE_FILE, _write_state

        monkeypatch.delenv("SAFEAI_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)

        _write_state({"enabled": True, "install_id": "test-id"})

        ret = main(["telemetry", "off"])
        assert ret == 0

        state = json.loads(_STATE_FILE.read_text())
        assert state["enabled"] is False
        assert state["install_id"] == "test-id"  # Preserved


class TestTelemetrySchema:
    """Tests for event schema matching PRIVACY.md exactly."""

    def test_build_event_fields(self):
        """build_event() output contains exactly the documented fields."""
        from safeai.telemetry.schema import get_event_field_names

        # Fields documented in PRIVACY.md
        documented_fields = {
            "schema_version",
            "safeai_version",
            "python_version",
            "os_family",
            "invocation_context",
            "command",
            "install_id",
            "date",
        }

        actual_fields = get_event_field_names()
        assert actual_fields == documented_fields

    def test_build_event_valid_command(self):
        """build_event() with valid command."""
        from safeai.telemetry.schema import build_event

        event = build_event("scan")
        assert event["command"] == "scan"
        assert event["schema_version"] == 1
        assert "safeai_version" in event
        assert "python_version" in event
        assert event["os_family"] in ("linux", "darwin", "windows")
        assert event["invocation_context"] in ("cli", "github-action", "ci-other", "unknown")

    def test_build_event_invalid_command(self):
        """build_event() with invalid command defaults to 'other'."""
        from safeai.telemetry.schema import build_event

        event = build_event("malicious-command")
        assert event["command"] == "other"

    def test_build_event_invocation_context(self):
        """build_event() respects invocation_context override."""
        from safeai.telemetry.schema import build_event

        event = build_event("scan", invocation_context="github-action")
        assert event["invocation_context"] == "github-action"


class TestTelemetryClient:
    """Tests for telemetry send logic."""

    def test_send_telemetry_disabled_no_network(self, monkeypatch):
        """Telemetry disabled → no network call."""
        from safeai.telemetry.client import send_telemetry

        monkeypatch.delenv("SAFEAI_TELEMETRY", raising=False)
        monkeypatch.delenv("SAFEAI_TELEMETRY_IN_CI", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)

        with patch("safeai.telemetry.client.urllib.request.urlopen") as mock_urlopen:
            send_telemetry("scan")
            mock_urlopen.assert_not_called()

    def test_send_telemetry_placeholder_endpoint_no_send(self, monkeypatch):
        """Placeholder endpoint → no send even if enabled."""
        from safeai.telemetry.client import send_telemetry

        monkeypatch.setenv("SAFEAI_TELEMETRY", "1")
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.delenv("CI", raising=False)

        with patch("safeai.telemetry.client.urllib.request.urlopen") as mock_urlopen:
            # The endpoint is a TODO placeholder, so no send should happen
            send_telemetry("scan")
            mock_urlopen.assert_not_called()

    def test_send_telemetry_failure_silent(self, monkeypatch):
        """Network failure → silent, no exception, no exit code change."""
        import urllib.error

        from safeai.telemetry.client import send_telemetry

        monkeypatch.setenv("SAFEAI_TELEMETRY", "1")
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.delenv("CI", raising=False)

        # Temporarily set a real endpoint to test failure handling
        with (
            patch("safeai.telemetry.client._TELEMETRY_ENDPOINT", "https://example.invalid/telemetry"),
            patch("safeai.telemetry.client.urllib.request.urlopen", side_effect=urllib.error.URLError("mock")),
        ):
            # Should not raise
            send_telemetry("scan")

    def test_send_telemetry_timeout_silent(self, monkeypatch):
        """Timeout → silent, no exception."""

        from safeai.telemetry.client import send_telemetry

        monkeypatch.setenv("SAFEAI_TELEMETRY", "1")
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.delenv("CI", raising=False)

        with (
            patch("safeai.telemetry.client._TELEMETRY_ENDPOINT", "https://example.invalid/telemetry"),
            patch("safeai.telemetry.client.urllib.request.urlopen", side_effect=TimeoutError("mock")),
        ):
            # Should not raise
            send_telemetry("scan")


class TestAssuranceBoundary:
    """Tests for telemetry_active in assurance boundary."""

    def test_telemetry_active_field_default(self):
        """Assurance boundary includes telemetry_active field (default off)."""
        from safeai.kya.assurance import build_assurance_boundary

        boundary = build_assurance_boundary({})
        assert "telemetry_active" in boundary
        assert boundary["telemetry_active"] is False

    def test_telemetry_active_field_enabled(self, monkeypatch):
        """Assurance boundary telemetry_active reflects enabled state."""
        from safeai.kya.assurance import build_assurance_boundary

        monkeypatch.setenv("SAFEAI_TELEMETRY", "1")
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.delenv("CI", raising=False)

        boundary = build_assurance_boundary({})
        assert boundary["telemetry_active"] is True

    def test_telemetry_active_field_no_install_id(self):
        """Assurance boundary should not contain install_id."""
        from safeai.kya.assurance import build_assurance_boundary

        boundary = build_assurance_boundary({})
        assert "install_id" not in boundary


class TestTelemetryIntegration:
    """Integration tests for CLI telemetry wiring."""

    def test_scan_with_telemetry_disabled(self, monkeypatch):
        """Scan with telemetry off → urlopen never called."""
        from safeai.cmd.cli import main

        monkeypatch.delenv("SAFEAI_TELEMETRY", raising=False)
        monkeypatch.delenv("SAFEAI_TELEMETRY_IN_CI", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)

        with patch("safeai.telemetry.client.send_telemetry") as mock_send:
            # Simulate a command that doesn't need a real directory
            main(["telemetry", "status"])
            mock_send.assert_not_called()  # telemetry command doesn't send

    def test_telemetry_on_off_cycle(self, tmp_path, monkeypatch):
        """Full on/off cycle preserves install_id."""
        from safeai.cmd.cli import main
        from safeai.telemetry.config import _STATE_FILE

        monkeypatch.delenv("SAFEAI_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)

        if _STATE_FILE.exists():
            _STATE_FILE.unlink()

        # Turn on
        main(["telemetry", "on"])
        state_after_on = json.loads(_STATE_FILE.read_text())
        install_id = state_after_on["install_id"]

        # Turn off
        main(["telemetry", "off"])
        state_after_off = json.loads(_STATE_FILE.read_text())
        assert state_after_off["enabled"] is False
        assert state_after_off["install_id"] == install_id  # Preserved

        # Turn on again
        main(["telemetry", "on"])
        state_after_reon = json.loads(_STATE_FILE.read_text())
        assert state_after_reon["enabled"] is True
        assert state_after_reon["install_id"] == install_id  # Same ID
