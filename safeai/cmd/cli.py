"""Command-line interface for SafeAI.

Usage::

    safeai scan <directory> [--sarif <path>] [--json <path>] [--html <path>] [--fail-on <level>]
"""

import argparse
import logging
import sys
from safeai.engine.scan import run_scan


def main(argv=None):
    parser = argparse.ArgumentParser(prog="safeai")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan")
    scan.add_argument("directory")
    scan.add_argument("--sarif", default="report.sarif")
    scan.add_argument("--json", dest="json_path")
    scan.add_argument("--html", dest="html_path")
    scan.add_argument("--rules")
    scan.add_argument("--fail-on", default="critical", choices=["critical", "high", "medium"])
    scan.add_argument("--verbose", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "scan":
        logging.basicConfig(
            level=logging.DEBUG if args.verbose else logging.WARNING,
            format="[%(levelname)s] %(name)s: %(message)s",
        )

        report = run_scan(args.directory, args.rules)

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

        levels = ["info", "low", "medium", "high", "critical"]
        threshold = args.fail_on
        fail = any(
            levels.index(f["severity"]) >= levels.index(threshold)
            for f in report["findings"]
        )
        return 1 if fail else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
