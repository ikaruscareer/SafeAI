"""Command-line interface for SafeAI.

Usage::

    safeai scan <directory> [--sarif <path>] [--json <path>] [--html <path>]
                            [--manifest <path>] [--baseline <path>]
                            [--policy <path>] [--suppressions <path>]
                            [--registry <path> | --no-registry] [--strict-registry]
                            [--fail-on <level>] [--fail-on-new]
    safeai registry list|show|history|diff|export ...

KYA (Know Your Agent) behavior:
  * Every scan produces normalized findings (stable fingerprints,
    confidence labels, provenance, remediation).
  * A local SQLite registry at ``.safeai/registry.db`` is created or
    updated by default on interactive scans (auto-disabled in CI unless
    ``--registry`` is given explicitly).
  * All outputs remain local: no network calls, no uploads.
"""

import argparse
import json
import logging
import os
import sys

from safeai.engine.scan import run_scan

LEVELS = ["info", "low", "medium", "high", "critical"]


def _safeai_version():
    try:
        from importlib.metadata import version
        return version("safeai")
    except Exception:
        import safeai
        return getattr(safeai, "__version__", "unknown")


def _ruleset_version(rules):
    from safeai.kya.util import sha256_text
    canonical = json.dumps(rules or [], sort_keys=True, default=str)
    return f"sha256:{sha256_text(canonical)[:16]}"


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
                      help="Registry database path (default: <scan-root>/.safeai/registry.db)")
    scan.add_argument("--no-registry", action="store_true",
                      help="Do not create or update the local KYA registry")
    scan.add_argument("--strict-registry", action="store_true",
                      help="Fail the scan if registry persistence fails")
    scan.add_argument("--policy",
                      help="Policy-as-code YAML file (default: <scan-root>/.safeai/policy.yml if present)")
    scan.add_argument("--suppressions",
                      help="Suppressions YAML file (default: <scan-root>/.safeai/suppressions.yml if present)")

    registry = sub.add_parser("registry", help="Inspect the local KYA registry")
    reg_sub = registry.add_subparsers(dest="registry_command")

    def _common(p):
        p.add_argument("--registry", help="Registry database path")
        p.add_argument("--format", choices=["table", "json"], default="table")

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
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="[%(levelname)s] %(name)s: %(message)s",
    )

    from safeai.kya import baseline as kya_baseline
    from safeai.kya import policy as kya_policy
    from safeai.kya import registry as kya_registry
    from safeai.kya import suppressions as kya_suppressions
    from safeai.kya.enrich import build_agent_records, normalize_findings
    from safeai.kya.identity import git_metadata, resolve_project_id
    from safeai.kya.manifest import build_manifest, config_hash, write_manifest
    from safeai.kya.util import new_scan_id, utc_now_iso
    from safeai.rules.loader import load_rules

    directory = os.path.abspath(args.directory)
    started_at = utc_now_iso()

    # --- Baseline: KYA fingerprint comparison + legacy capability diff ---
    baseline_fps = None
    baseline_report = None
    if args.baseline:
        try:
            baseline_fps, baseline_doc = kya_baseline.load_baseline(args.baseline)
        except (TypeError, ValueError) as exc:
            parser.error(str(exc))
        # A legacy JSON report supplies ``normalized_capabilities``; a KYA
        # manifest (v1.1+) supplies ``tool_surface``. Either enables a diff.
        if isinstance(baseline_doc, dict) and (
            "normalized_capabilities" in baseline_doc or "tool_surface" in baseline_doc
        ):
            baseline_report = baseline_doc

    report = run_scan(args.directory, args.rules, baseline_report=baseline_report)
    completed_at = utc_now_iso()

    # --- Normalize findings (fingerprints, confidence, provenance, ...) ---
    normalize_findings(report["findings"])

    # --- Suppressions (never silent; suppressed findings stay visible) ---
    suppressions_path = args.suppressions or kya_suppressions.default_suppressions_path(directory)
    try:
        suppression_entries, suppression_warnings = kya_suppressions.load_suppressions(suppressions_path)
    except kya_suppressions.SuppressionError as exc:
        parser.error(str(exc))
    suppression_summary = kya_suppressions.apply_suppressions(report["findings"], suppression_entries)
    for warning in suppression_warnings:
        print(f"warning: {warning}", file=sys.stderr)
    report["suppressions"] = {
        "path": suppressions_path if suppression_entries else None,
        **suppression_summary,
    }

    # --- Baseline comparison ---
    baseline_summary = None
    if baseline_fps is not None:
        baseline_summary = kya_baseline.compare_with_baseline(report["findings"], baseline_fps)
        report["baseline"] = baseline_summary

    # --- Policy-as-code evaluation ---
    policy_path = args.policy or kya_policy.default_policy_path(directory)
    try:
        policy_doc = kya_policy.load_policy(policy_path)
    except kya_policy.PolicyError as exc:
        parser.error(str(exc))
    policy_decision = kya_policy.evaluate_policy(policy_doc, report)
    report["policy_decision"] = policy_decision

    # --- Project/agent identity ---
    project_id, remote_fp = resolve_project_id(directory)
    git_meta = git_metadata(directory)
    agents = build_agent_records(report, project_id)
    report["kya_agents"] = agents

    rules = load_rules(args.rules)
    scan_id = new_scan_id()

    effective_config = {
        "rules_dir": os.path.abspath(args.rules) if args.rules else None,
        "safeai_version": _safeai_version(),
        "fail_on": args.fail_on,
    }
    safeai_meta = {
        "version": _safeai_version(),
        "ruleset_version": _ruleset_version(rules),
        "config_hash": config_hash(effective_config),
    }
    try:
        source_root = os.path.relpath(directory, os.getcwd())
    except ValueError:
        source_root = "."
    project_meta = {
        "project_id": project_id,
        "name": os.path.basename(directory) or directory,
        "source_root": source_root.replace("\\", "/"),
        "repository": {
            "remote_fingerprint": remote_fp,
            "commit_sha": git_meta.get("commit_sha"),
            "branch": git_meta.get("branch"),
            "tag": git_meta.get("tag"),
        },
    }
    scan_meta = {"scan_id": scan_id, "started_at": started_at, "completed_at": completed_at}

    manifest = build_manifest(
        report,
        project=project_meta,
        scan_meta=scan_meta,
        safeai_meta=safeai_meta,
        agents=agents,
        policy_decision={
            "outcome": policy_decision["outcome"],
            "reasons": policy_decision["reasons"],
            "matches": policy_decision.get("matches") or [],
        },
    )

    # --- Registry persistence (default on; CI-aware) ---
    registry_status = {"state": "skipped", "path": None, "reason": None, "stats": None}
    in_ci = os.environ.get("CI", "").lower() in {"1", "true", "yes"}
    registry_disabled = args.no_registry or (in_ci and not args.registry)
    if in_ci and not args.registry and not args.no_registry:
        registry_status["reason"] = "CI environment detected; use --registry PATH to enable explicitly"

    if not registry_disabled:
        registry_path = args.registry or kya_registry.default_registry_path(directory)
        registry_status["path"] = registry_path
        try:
            conn, created = kya_registry.init_registry(registry_path)
            try:
                stats = kya_registry.persist_scan(conn, manifest)
            finally:
                conn.close()
            registry_status["state"] = "initialized" if created else "updated"
            registry_status["stats"] = stats
            if created:
                print(f"Initialized local KYA registry at {registry_path}")
                print("Hint: add '.safeai/registry.db' to .gitignore to keep it out of version control.")
        except kya_registry.RegistryError as exc:
            registry_status["state"] = "failed"
            registry_status["reason"] = str(exc)
            print(f"warning: registry persistence failed: {exc}", file=sys.stderr)
            if args.strict_registry:
                print("error: --strict-registry is set; failing scan", file=sys.stderr)
                return 2
    else:
        registry_status["reason"] = registry_status["reason"] or "disabled by --no-registry"

    report["registry"] = registry_status

    # --- Output artifacts ---
    if args.manifest_path:
        write_manifest(manifest, args.manifest_path)

    if args.sarif:
        from safeai.report.sarif import write_sarif
        write_sarif(report, args.sarif)

    if args.json_path:
        from safeai.report.json_report import write_json
        write_json(report, args.json_path)

    if args.html_path:
        from safeai.report.html import write_html
        write_html(report, args.html_path)

    from safeai.report.terminal import print_summary
    print_summary(report)

    # --- Exit code semantics (backward compatible) ---
    # Suppressed findings never trigger failure. --fail-on-new restricts the
    # failing set to new/regressed findings (requires --baseline). A policy
    # 'deny' outcome always fails the scan; this is documented behavior.
    active = [f for f in report["findings"] if f.get("status") != "suppressed"]
    threshold_index = LEVELS.index(args.fail_on)

    if args.fail_on_new:
        if not args.baseline:
            parser.error("--fail-on-new requires --baseline")
        candidates = [f for f in active if f.get("status") in {"new", "regressed"}]
    else:
        candidates = active

    fail = any(LEVELS.index(f["severity"]) >= threshold_index for f in candidates)
    if policy_decision["outcome"] == "deny":
        fail = True

    return 1 if fail else 0


def main(argv=None):
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
