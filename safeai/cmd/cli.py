"""Command-line interface for SafeAI.

Usage::

    safeai scan <directory> [--sarif <path>] [--json <path>] [--html <path>]
                            [--manifest <path>] [--baseline <path>]
                            [--policy <path>] [--suppressions <path>]
                            [--registry <path> | --no-registry] [--strict-registry]
                            [--pr-comment <path>] [--pr-comment-stdout]
                            [--fail-on <level>] [--fail-on-new]
                            [--fail-on-escalation <level>]
    safeai registry list|show|history|diff|export ...

KYA (Know Your Agent) behavior:
  * Every scan produces normalized findings (stable fingerprints,
    confidence labels, provenance, remediation).
  * Scans persist to a single shared SQLite registry by default —
    ``SAFEAI_REGISTRY`` env var or ``~/.safeai/registry.db`` — so agents
    from every scanned project accumulate in one place and can be listed
    with ``safeai registry list`` from anywhere. ``--registry PATH``
    overrides the location; CI jobs persist only when a registry is
    configured explicitly.
  * ``--pr-comment`` writes a reviewer-facing Markdown summary of
    capability escalations to a file. SafeAI never posts it anywhere;
    publishing is the CI workflow's job.
  * All outputs remain local: no network calls, no uploads.
"""

import argparse
import sys

from safeai.cmd.postprocess import ScanPostProcessor


def _build_parser():
    parser = argparse.ArgumentParser(prog="safeai")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Statically scan a directory for AI agent capabilities and risks")
    scan.add_argument("directory")
    scan.add_argument("--sarif", default="report.sarif")
    scan.add_argument("--json", dest="json_path")
    scan.add_argument("--html", dest="html_path")
    scan.add_argument("--rules")
    scan.add_argument("--fail-on", default="critical", choices=["critical", "high", "medium"])
    scan.add_argument("--verbose", action="store_true")
    scan.add_argument("--baseline",
                      help="Prior safeai-manifest.json (or legacy JSON report) for new/existing comparison")
    scan.add_argument("--fail-on-new", action="store_true",
                      help="With --baseline: fail only on NEW or REGRESSED findings at/above --fail-on severity")
    scan.add_argument("--manifest", dest="manifest_path",
                      help="Write the canonical KYA manifest (safeai-manifest.json) to this path")
    scan.add_argument("--registry",
                      help="Registry database path (default: shared registry — "
                           "SAFEAI_REGISTRY env var or ~/.safeai/registry.db)")
    scan.add_argument("--no-registry", action="store_true",
                      help="Do not create or update the local KYA registry")
    scan.add_argument("--strict-registry", action="store_true",
                      help="Fail the scan if registry persistence fails")
    scan.add_argument("--pr-comment", dest="pr_comment_path",
                      help="Write a reviewer-facing Markdown summary of capability "
                           "escalations to PATH (never posted anywhere)")
    scan.add_argument("--pr-comment-stdout", action="store_true",
                      help="Print the PR comment Markdown to stdout")
    scan.add_argument("--fail-on-escalation", choices=["critical", "high", "medium"],
                      help="Fail the scan when a capability escalation at or above "
                           "this severity is detected (requires --baseline)")
    scan.add_argument("--policy",
                      help="Policy-as-code YAML file (default: <scan-root>/.safeai/policy.yml if present)")
    scan.add_argument("--policy-profile",
                      choices=["developer", "strict-ci", "mcp", "rag", "production-agent"],
                      help="Named policy profile to load (extends --policy, does not replace it)")
    scan.add_argument("--suppressions",
                      help="Suppressions YAML file (default: <scan-root>/.safeai/suppressions.yml if present)")
    scan.add_argument("--strict-suppressions", action="store_true",
                      help="Fail the scan (exit 1) when expired or moved suppressions are detected")
    # --- SafeAI Security Scorecard ---
    scan.add_argument("--scorecard", dest="scorecard_path",
                      help="Write the SafeAI Security Scorecard Markdown report to PATH")
    scan.add_argument("--scorecard-json", dest="scorecard_json_path",
                      help="Write the SafeAI Security Scorecard JSON report to PATH")
    scan.add_argument("--scorecard-md", dest="scorecard_md_path",
                      help="Write the SafeAI Security Scorecard Markdown report to PATH")
    scan.add_argument("--scorecard-summary", dest="scorecard_summary_path",
                      help="Append the SafeAI Security Scorecard to the GitHub Actions "
                           "job summary at PATH (or $GITHUB_STEP_SUMMARY when no PATH "
                           "is given); outside GitHub Actions this is a no-op")
    scan.add_argument("--scorecard-fail-under", dest="scorecard_fail_under",
                      type=float, metavar="SCORE",
                      help="Fail the scan when the overall score is below SCORE "
                           "(0-10). This is an additional score-based gate and does "
                           "not change --fail-on/--fail-on-new/--fail-on-escalation.")
    scan.add_argument("--mcp-ide-scopes", action="store_true",
                      help="Discover MCP configs in IDE scopes (.cursor/, .windsurf/, "
                           ".vscode/) in addition to the scanned repo")

    registry = sub.add_parser("registry", help="Inspect the local KYA registry")
    reg_sub = registry.add_subparsers(dest="registry_command")

    def _common(p):
        p.add_argument("--registry", help="Registry database path")
        p.add_argument("--project-dir", dest="project_dir",
                       help="Inspect the per-project registry at DIR/.safeai/registry.db "
                            "instead of the shared registry")
        p.add_argument("--format", choices=["table", "json", "html"], default="table")

    reg_list = reg_sub.add_parser("list", help="List known agents/workflows")
    _common(reg_list)
    reg_list.add_argument("--project", help="Filter by project ID")

    reg_show = reg_sub.add_parser("show", help="Show the latest KYA record for an agent")
    _common(reg_show)
    reg_show.add_argument("agent_id")
    reg_show.add_argument("--scan", help="Show record from a specific scan ID")

    reg_hist = reg_sub.add_parser("history", help="List scan history for an agent")
    _common(reg_hist)
    reg_hist.add_argument("agent_id")

    reg_diff = reg_sub.add_parser("diff", help="Compare two snapshots of an agent")
    _common(reg_diff)
    reg_diff.add_argument("agent_id")
    reg_diff.add_argument("--from", dest="from_ref", default="previous",
                          help="Scan ID, 'previous', or 'latest' (default: previous)")
    reg_diff.add_argument("--to", dest="to_ref", default="latest",
                          help="Scan ID or 'latest' (default: latest)")

    reg_export = reg_sub.add_parser("export", help="Export a KYA inventory document")
    _common(reg_export)
    reg_export.add_argument("--output", required=True, help="Output file path")
    reg_export.add_argument("--project", help="Export a single project ID")
    reg_export.add_argument("--include-history", action="store_true")
    reg_export.add_argument("--include-suppressed", action="store_true")

    return parser


def _run_scan_command(args, parser):
    """Run the post-scan pipeline for ``safeai scan``.

    The pipeline itself lives in :class:`safeai.cmd.postprocess.ScanPostProcessor`
    (normalize, suppress, baseline, policy, identity, manifest, registry,
    outputs, exit code); this keeps the CLI a thin parsing shell.
    """
    return ScanPostProcessor(args, parser).run()


def _configure_stdout():
    """Emit UTF-8 on stdout so output survives redirection/pipes on Windows.

    Without this, ``sys.stdout`` uses the locale encoding (e.g. cp1252)
    and HTML/JSON output containing non-ASCII text is mangled when
    redirected to a file or piped. Safe no-op under test capture, where
    stdout has no ``reconfigure``.
    """
    try:
        reconfigure = getattr(sys.stdout, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main(argv=None):
    _configure_stdout()
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan_command(args, parser)

    if args.command == "registry":
        if not getattr(args, "registry_command", None):
            parser.error("registry requires a subcommand: list|show|history|diff|export")
        from safeai.cmd.registry_cli import run_registry_command
        return run_registry_command(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
