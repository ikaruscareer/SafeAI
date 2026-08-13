#!/usr/bin/env python3
"""Driver for the SafeAI GitHub composite action.

Runs inside ``action.yml``. The composite action passes every input to this
script through the ``INPUT_*`` environment variables that GitHub Actions
exposes to composite-action steps, so no user-controlled value ever reaches a
shell command line.

Behavior:

* Validates inputs (severity threshold, version, path existence, extra-args).
* Installs ``SafeAI-Static-Analyzer`` from PyPI by default; installs the exact
  version when ``INPUT_VERSION`` is set. Install can be skipped with the
  ``SAFEAI_ACTION_SKIP_INSTALL=true`` env var (used by local tests only).
* Builds the ``python -m safeai scan ...`` argv as a plain Python list and
  executes it without a shell, preserving SafeAI's native exit code.
* Resolves ``path``/``sarif`` to absolute paths against the workspace and runs
  the scan from a neutral working directory, so the CLI runs the *installed*
  package rather than any ``safeai/`` directory the checked-out repository may
  contain.
* Creates the SARIF parent directory and leaves the SARIF artifact in place
  even when the scan returns a policy-failure exit code, so a later
  ``upload-sarif`` step with ``if: always()`` still has a file to upload.
* Writes ``sarif-path`` to ``$GITHUB_OUTPUT``.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

DIST = "SafeAI-Static-Analyzer"
FAIL_ON_CHOICES = ("critical", "high", "medium")
# PEP 440 public-version shape; restrictive enough that a caller-supplied
# version cannot smuggle extra pip arguments or shell metacharacters.
_PEP440_SAFE_RE = re.compile(
    r"^[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc|\.dev|\.post)[0-9]+)?\Z"
)


def env_val(name, default=""):
    """Read an environment variable, stripping whitespace."""
    return os.environ.get(name, default).strip()


def action_input(name, default=""):
    """Read the ``INPUT_*`` env var GitHub sets for an action input."""
    return env_val(f"INPUT_{name.upper().replace('-', '_')}", default)


def as_bool(value):
    return str(value).strip().lower() in {"true", "1", "yes", "on"}


def build_install_command(version, find_links=""):
    """Return the argv that installs SafeAI at ``version`` (no shell).

    When ``find_links`` points at a directory of wheels, pip prefers the local
    wheel there (e.g. a freshly built ``SafeAI-Static-Analyzer``) over PyPI,
    letting CI exercise the real install command without depending on a
    published version. Dependencies such as PyYAML still resolve from PyPI, so
    we deliberately avoid ``--no-index`` here.
    """
    if version:
        spec = f"{DIST}=={version}"
    else:
        spec = DIST
    cmd = [sys.executable, "-m", "pip", "install", "--quiet", spec]
    if find_links:
        cmd += ["--find-links", find_links]
    return cmd


def build_scan_argv(path, fail_on, sarif, rules="", baseline="", fail_on_new=False,
                    fail_on_escalation="", no_registry=True, extra_args=None,
                    scorecard="", scorecard_json="", scorecard_summary="",
                    scorecard_fail_under=""):
    """Build the ``python -m safeai scan`` argv as a list (no shell)."""
    argv = [sys.executable, "-m", "safeai", "scan", path]
    if sarif:
        argv += ["--sarif", sarif]
    argv += ["--fail-on", fail_on]
    if rules:
        argv += ["--rules", rules]
    if baseline:
        argv += ["--baseline", baseline]
    if fail_on_new:
        argv += ["--fail-on-new"]
    if fail_on_escalation:
        argv += ["--fail-on-escalation", fail_on_escalation]
    if no_registry:
        argv += ["--no-registry"]
    if scorecard:
        argv += ["--scorecard", scorecard]
    if scorecard_json:
        argv += ["--scorecard-json", scorecard_json]
    if scorecard_summary:
        argv += ["--scorecard-summary", scorecard_summary]
    if scorecard_fail_under:
        argv += ["--scorecard-fail-under", scorecard_fail_under]
    if extra_args:
        argv += list(extra_args)
    return argv


def parse_extra_args(raw):
    """Parse ``extra-args`` input (JSON array of strings) without eval."""
    raw = (raw or "[]").strip()
    if not raw:
        return []
    parsed = json.loads(raw)
    if not isinstance(parsed, list):
        raise TypeError("extra-args must be a JSON array of strings")
    for item in parsed:
        if not isinstance(item, str):
            raise TypeError("extra-args elements must be strings")
    return parsed


def validate_version(version):
    """Return None if ``version`` is safe, else an error message."""
    if not version:
        return None
    if not _PEP440_SAFE_RE.match(version):
        return (
            f"version {version!r} is not a safe PyPI version; "
            "expected e.g. '1.5.0' or '1.5.0rc1'"
        )
    return None


def workspace_root():
    """Return the GitHub workspace (or the process cwd as a fallback)."""
    return os.environ.get("GITHUB_WORKSPACE") or os.getcwd()


def resolve_path(value):
    """Resolve an input path to absolute against the GitHub workspace."""
    if not value:
        return ""
    return os.path.abspath(os.path.join(workspace_root(), value))


def validate_no_control_chars(value, label):
    """Return an error message if ``value`` contains control characters.

    GitHub Actions parses ``$GITHUB_OUTPUT`` line-by-line; a newline smuggled
    through a path input would inject additional output keys. The same applies
    to ``::error::``/``::warning::`` messages, which are newline-delimited.
    """
    for char in value:
        if ord(char) < 0x20 or char == "\x7f":
            return (
                f"{label} contains a control character "
                f"(U+{ord(char):04X}), which is not allowed"
            )
    return None


def set_output(name, value):
    """Append a single ``name=value`` line to ``$GITHUB_OUTPUT`` when present.

    Each output is written independently so a missing value cannot clobber a
    neighbouring output (the previous ``write_outputs`` overload required
    callers to pass positional empty strings, which was error-prone).
    """
    out_file = os.environ.get("GITHUB_OUTPUT")
    if not out_file:
        return
    with open(out_file, "a", encoding="utf-8") as fh:
        fh.write(f"{name}={value}\n")


def get_safeai_version():
    """Return installed SafeAI version string, or 'unknown' on failure.

    Runs from a neutral working directory so a checked-out target tree cannot
    shadow the installed ``safeai`` package. Failures are surfaced as a
    ``::warning::`` rather than swallowed, so a broken install is diagnosable.
    """
    try:
        neutral_cwd = os.environ.get("RUNNER_TEMP") or tempfile.mkdtemp(prefix="safeai-ver-")
        proc = subprocess.run(
            [sys.executable, "-m", "safeai", "--version"],
            capture_output=True,
            text=True,
            check=False,
            cwd=neutral_cwd,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip().split()[0]
        print(
            f"::warning::could not determine installed SafeAI version "
            f"(exit {proc.returncode}; stderr: {proc.stderr.strip()[:200]})",
            file=sys.stderr,
        )
    except Exception as exc:
        print(f"::warning::could not determine installed SafeAI version: {exc}", file=sys.stderr)
    return "unknown"


def main(argv=None):
    scan_dir = action_input("path", ".") or "."
    version = action_input("version")
    fail_on = action_input("fail-on", "critical") or "critical"
    sarif = action_input("sarif", "safeai-results.sarif")
    rules = action_input("rules")
    baseline = action_input("baseline")
    fail_on_new = as_bool(action_input("fail-on-new", "false"))
    fail_on_escalation = action_input("fail-on-escalation")
    no_registry = as_bool(action_input("no-registry", "true"))
    skip_install = as_bool(env_val("SAFEAI_ACTION_SKIP_INSTALL"))
    scorecard = action_input("scorecard", "safeai-scorecard.md")
    scorecard_json = action_input("scorecard-json", "safeai-scorecard.json")
    scorecard_summary = action_input("scorecard-summary", "true")
    scorecard_fail_under = action_input("scorecard-fail-under")

    scan_dir = resolve_path(scan_dir)
    sarif = resolve_path(sarif)
    rules = resolve_path(rules)
    baseline = resolve_path(baseline)
    scorecard = resolve_path(scorecard)
    scorecard_json = resolve_path(scorecard_json)
    scorecard_summary_path = ""
    if as_bool(scorecard_summary):
        summary_env = env_val("GITHUB_STEP_SUMMARY")
        if summary_env:
            scorecard_summary_path = summary_env

    for label, value in (
        ("path", scan_dir),
        ("sarif", sarif),
        ("rules", rules),
        ("baseline", baseline),
        ("scorecard", scorecard),
        ("scorecard-json", scorecard_json),
        ("scorecard-summary", scorecard_summary_path),
    ):
        if value:
            error = validate_no_control_chars(value, label)
            if error:
                print(f"::error::{error}", file=sys.stderr)
                return 2

    if fail_on not in FAIL_ON_CHOICES:
        print(
            f"::error::fail-on must be one of {', '.join(FAIL_ON_CHOICES)}; got {fail_on!r}",
            file=sys.stderr,
        )
        return 2
    if fail_on_escalation and fail_on_escalation not in FAIL_ON_CHOICES:
        print(
            f"::error::fail-on-escalation must be one of "
            f"{', '.join(FAIL_ON_CHOICES)}; got {fail_on_escalation!r}",
            file=sys.stderr,
        )
        return 2
    version_error = validate_version(version)
    if version_error:
        print(f"::error::{version_error}", file=sys.stderr)
        return 2

    if scorecard_fail_under:
        try:
            fail_under = float(scorecard_fail_under)
        except ValueError:
            print(
                f"::error::scorecard-fail-under must be numeric; got {scorecard_fail_under!r}",
                file=sys.stderr,
            )
            return 2
        if not (0.0 <= fail_under <= 10.0):
            print(
                f"::error::scorecard-fail-under must be between 0 and 10; got {fail_under}",
                file=sys.stderr,
            )
            return 2

    try:
        extra_args = parse_extra_args(action_input("extra-args", "[]"))
    except (TypeError, json.JSONDecodeError) as exc:
        print(f"::error::extra-args: {exc}", file=sys.stderr)
        return 2

    if not os.path.exists(scan_dir):
        print(f"::error::scan path does not exist: {scan_dir}", file=sys.stderr)
        return 2

    if not skip_install:
        find_links = env_val("SAFEAI_ACTION_FIND_LINKS")
        install_cmd = build_install_command(version, find_links=find_links)
        install_rc = subprocess.call(install_cmd)
        if install_rc != 0:
            print(
                f"::error::failed to install {DIST}"
                + (f"=={version}" if version else "")
                + f" (pip exit code {install_rc})",
                file=sys.stderr,
            )
            # Install failure is an operational error, not a scan/policy
            # outcome, so it must not be conflated with exit code 1.
            return 2

    if sarif:
        sarif_dir = os.path.dirname(os.path.abspath(sarif))
        if sarif_dir:
            try:
                os.makedirs(sarif_dir, exist_ok=True)
            except OSError as exc:
                print(
                    f"::error::could not create SARIF directory {sarif_dir!r}: {exc}",
                    file=sys.stderr,
                )
                return 2

    cmd = build_scan_argv(
        scan_dir,
        fail_on,
        sarif,
        rules=rules,
        baseline=baseline,
        fail_on_new=fail_on_new,
        fail_on_escalation=fail_on_escalation,
        no_registry=no_registry,
        extra_args=extra_args,
        scorecard=scorecard,
        scorecard_json=scorecard_json,
        scorecard_summary=scorecard_summary_path,
        scorecard_fail_under=scorecard_fail_under,
    )
    # Run from a neutral working directory so ``python -m safeai`` imports the
    # installed PyPI package, never a ``safeai/`` directory in the consumer's
    # checked-out tree. All report paths are already absolute.
    neutral_cwd = os.environ.get("RUNNER_TEMP") or tempfile.mkdtemp(prefix="safeai-action-")
    proc = subprocess.run(cmd, cwd=neutral_cwd, check=False)

    if sarif and not os.path.exists(sarif):
        print(
            f"::warning::no SARIF artifact was generated at {sarif}; "
            f"the scan failed before report output (exit code {proc.returncode})",
            file=sys.stderr,
        )

    if sarif and os.path.exists(sarif):
        set_output("sarif-path", os.path.abspath(sarif))

    # Write the scorecard-path output when the scorecard was generated.
    # The scorecard path is preserved even when the scan fails, so a later
    # step with ``if: always()`` can still read it.
    scorecard_path = os.path.abspath(scorecard) if scorecard else ""
    if scorecard_path and os.path.exists(scorecard_path):
        set_output("scorecard-path", scorecard_path)

    safeai_version = get_safeai_version()
    set_output("safeai-version", safeai_version)

    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
