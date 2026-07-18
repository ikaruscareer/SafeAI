#!/usr/bin/env python3
"""Bulk-create good-first-issue GitHub issues from .github/good-first-issues/issues.json.

Usage:
    export GITHUB_TOKEN=ghp_...
    export GITHUB_REPOSITORY=ikaruscareer/SafeAI
    python scripts/create_good_first_issues.py [--dry-run]
"""

import json
import os
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("requests library required. Install with: pip install requests")
    sys.exit(1)


DATA_FILE = Path(__file__).resolve().parent.parent / ".github" / "good-first-issues" / "issues.json"
API_URL = "https://api.github.com"


def create_issue(session, repo, title, body, labels, dry_run=False):
    url = f"{API_URL}/repos/{repo}/issues"
    payload = {"title": title, "body": body, "labels": labels}

    if dry_run:
        print(f"[DRY-RUN] Would create: [{', '.join(labels)}] {title}")
        return None

    resp = session.post(url, json=payload)
    if resp.status_code in (201,):
        data = resp.json()
        print(f"  Created: {data['html_url']}")
        return data
    else:
        print(f"  FAILED ({resp.status_code}): {resp.text}")
        return None


def main():
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY", "ikaruscareer/SafeAI")
    dry_run = "--dry-run" in sys.argv

    if not token and not dry_run:
        print("GITHUB_TOKEN environment variable is required (unless --dry-run)")
        sys.exit(1)

    with open(DATA_FILE, "r") as f:
        issues = json.load(f)

    session = requests.Session()
    if token:
        session.headers.update({"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"})

    print(f"Creating {len(issues)} good-first-issues in {repo}...\n")
    created = 0
    for issue in issues:
        result = create_issue(
            session,
            repo,
            title=issue["title"],
            body=issue["body"],
            labels=issue["labels"],
            dry_run=dry_run,
        )
        if result:
            created += 1

    print(f"\nDone. {created} issues created.")


if __name__ == "__main__":
    main()
