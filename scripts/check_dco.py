"""DCO sign-off check (local + CI, no third-party actions).

Verifies every non-merge commit in a range carries a
``Signed-off-by: Name <email>`` trailer matching its author.
See DCO.md.

Usage:
    python scripts/check_dco.py --range main..HEAD
    python scripts/check_dco.py --range <base-sha>...<head-sha>
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

TRAILER = re.compile(r"^Signed-off-by:\s*(.+?)\s*<([^<>@\s]+@[^<>@\s]+)>\s*$",
                     re.MULTILINE)


def check_commit(message, author_name, author_email):
    """Return a list of problems (empty = signed off correctly)."""
    matches = TRAILER.findall(message or "")
    if not matches:
        return ["missing Signed-off-by trailer (see DCO.md: git commit -s)"]
    author_email = (author_email or "").lower()
    if any(email.lower() == author_email for _, email in matches):
        return []
    return [f"no Signed-off-by trailer matches author <{author_email}>"]


def commits_in_range(rev_range):
    """Yield (sha, author_name, author_email, message) for non-merge commits."""
    out = subprocess.run(
        ["git", "log", "--no-merges", "--format=%H%x1f%an%x1f%ae%x1f%B%x1e",
         rev_range],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False)
    if out.returncode != 0:
        raise SystemExit(f"git log failed for range {rev_range!r}: {(out.stderr or '').strip()}")
    for record in out.stdout.split("\x1e"):
        record = record.strip("\n")
        if not record.strip():
            continue
        sha, name, email, message = record.split("\x1f", 3)
        yield sha, name, email, message


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check DCO sign-off trailers")
    parser.add_argument("--range", dest="rev_range", default="HEAD",
                        help="git revision range (default: HEAD)")
    args = parser.parse_args(argv)
    try:
        reconfigure = getattr(sys.stdout, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    failures = 0
    checked = 0
    for sha, name, email, message in commits_in_range(args.rev_range):
        checked += 1
        for problem in check_commit(message, name, email):
            print(f"{sha[:8]} ({name} <{email}>): {problem}")
            failures += 1
    if not checked:
        print("no commits in range; nothing to check")
        return 0
    if failures:
        print(f"DCO check failed: {failures} problem(s) in {checked} commit(s)")
        return 1
    print(f"DCO check passed: {checked} commit(s) signed off")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
