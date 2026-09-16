"""Scan several AI frameworks with SafeAI and build a comparison report.

Clones each requested framework (shallow, read-only), runs ``safeai scan``
against it, collects the JSON report and Security Scorecard, and renders a
side-by-side comparison in Markdown, JSON, and optionally HTML.

Targets can be given by id from ``community-scans/targets.yml``, by
``owner/repo``, or by full URL. Frameworks that fail to clone or scan are
recorded and skipped; the run continues.

Usage:
    python scripts/scan_framework.py --frameworks langgraph crewai dspy
    python scripts/scan_framework.py --urls https://github.com/langchain-ai/langgraph
    python scripts/scan_framework.py --frameworks langgraph dspy --html
    python scripts/scan_framework.py --list

No target code is executed, no dependencies are installed, and nothing is
published. Output lands in ``community-scans/reports/automated/``, which is
git-ignored: review before sharing (see ``community-scans/SCAN_AND_SHARE.md``).

Exit codes: 0 every target scanned · 1 partial (some targets failed) ·
2 usage error or no target scanned.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess  # nosec-style note: every call uses a fixed argv list, never shell=True
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML ships with SafeAI
    yaml = None

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS_FILE = os.path.join(REPO_ROOT, "community-scans", "targets.yml")
DEFAULT_OUTPUT_DIR = os.path.join(REPO_ROOT, "community-scans", "reports", "automated")

SEVERITIES = ("critical", "high", "medium", "low", "info")
SAFE_REF = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
REPO_SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_URL = re.compile(
    r"^https://(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)

SCHEMA_VERSION = 1
ACCENT = "#0f766e"
RISK_MODEL_URL = "https://github.com/ikaruscareer/SafeAI/blob/main/docs/architecture/RISK_MODEL.md"

DISCLAIMER = (
    "SafeAI results are static-analysis evidence. They describe what the "
    "source and configuration of a repository *declare*, not what a deployed "
    "system does at runtime, and they are not confirmed vulnerabilities. "
    "Every finding needs human validation before any public claim or "
    "maintainer contact (see community-scans/disclosure-policy.md)."
)


# --------------------------------------------------------------------------
# Target resolution
# --------------------------------------------------------------------------


def load_catalog(path: str = TARGETS_FILE) -> dict[str, dict[str, Any]]:
    """Load community-scans/targets.yml into a mapping of id -> target."""
    if yaml is None:
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError):
        return {}
    if not isinstance(data, dict):
        return {}
    catalog: dict[str, dict[str, Any]] = {}
    for entry in data.get("targets") or []:
        if isinstance(entry, dict) and entry.get("id"):
            catalog[str(entry["id"])] = entry
    return catalog


def _slug(value: str) -> str:
    """Normalise a name so 'LlamaIndex', 'llama_index' and 'llama-index' match."""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _target_from_repo(repository: str, ref: str | None) -> dict[str, Any]:
    name = repository.split("/")[-1]
    return {
        "id": _slug(name) or "target",
        "display_name": name,
        "repository": repository,
        "upstream_url": f"https://github.com/{repository}",
        "default_ref": ref or "",
        "source": "url",
    }


def resolve_target(token: str, catalog: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Resolve a CLI token (catalog id, owner/repo, or GitHub URL) to a target."""
    token = token.strip()
    if not token:
        raise ValueError("empty target")

    def _from_repository(repository: str) -> dict[str, Any]:
        for entry in catalog.values():
            if entry.get("repository", "").lower() == repository.lower():
                return dict(entry, source="catalog")
        return _target_from_repo(repository, None)

    match = GITHUB_URL.match(token)
    if match:
        return _from_repository(f"{match.group('owner')}/{match.group('repo')}")

    if token.startswith(("http://", "https://", "git@", "ssh://", "file://")):
        raise ValueError(f"unsupported URL {token!r}: only https://github.com/<owner>/<repo> is accepted")

    wanted = _slug(token)
    for entry in catalog.values():
        candidates = {
            _slug(str(entry.get("id", ""))),
            _slug(str(entry.get("display_name", ""))),
            _slug(entry.get("repository", "").split("/")[-1]),
        }
        if wanted in candidates - {""}:
            return dict(entry, source="catalog")

    if REPO_SLUG.match(token):
        return _from_repository(token)

    known = ", ".join(sorted(catalog)) or "(catalog unavailable)"
    raise ValueError(f"unknown framework {token!r}. Known ids: {known}. Or pass owner/repo.")


# --------------------------------------------------------------------------
# Clone and scan
# --------------------------------------------------------------------------


def clone(target: dict[str, Any], dest: str, depth: int, timeout: int) -> tuple[str, str]:
    """Shallow-clone a target. Returns (commit_sha, ref). Raises RuntimeError."""
    ref = target.get("default_ref") or ""
    if ref and not SAFE_REF.match(ref):
        raise RuntimeError(f"unsafe ref {ref!r}")

    cmd = ["git", "clone", "--quiet", "--single-branch", "--depth", str(depth)]
    if ref:
        cmd += ["--branch", ref]
    cmd += [target["upstream_url"], dest]

    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="echo", GCM_INTERACTIVE="never")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"clone timed out after {timeout}s") from None
    except FileNotFoundError:
        raise RuntimeError("git is not installed or not on PATH") from None

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        raise RuntimeError(detail[-1] if detail else f"git clone exited {result.returncode}")

    sha = ""
    try:
        rev = subprocess.run(
            ["git", "-C", dest, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if rev.returncode == 0:
            sha = rev.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        sha = ""
    return sha, ref


def _failure_reason(result: subprocess.CompletedProcess) -> str:
    """Pull the most useful one-line reason out of a failed scan.

    A scanner crash can still exit 1, so the exit code alone says little.
    Prefer the final exception line of a traceback, which names the actual
    fault (e.g. ``RecursionError: maximum recursion depth exceeded``).
    """
    stderr = result.stderr or ""
    if "Traceback (most recent call last)" in stderr:
        for line in reversed(stderr.strip().splitlines()):
            stripped = line.strip()
            if stripped and not stripped.startswith(("File \"", "^", "~", "[Previous line")):
                return f"scanner crashed: {stripped[:180]}"
    tail = (stderr or result.stdout or "").strip().splitlines()
    if tail:
        return f"no JSON report (exit {result.returncode}): {tail[-1].strip()[:180]}"
    return f"scan produced no JSON report (exit {result.returncode})"


def scan(repo_dir: str, out_dir: str, target_id: str, timeout: int, verbose: bool) -> dict[str, str]:
    """Run ``safeai scan`` and return the paths of the artifacts it wrote."""
    os.makedirs(out_dir, exist_ok=True)
    paths = {
        "json": os.path.join(out_dir, f"{target_id}.json"),
        "sarif": os.path.join(out_dir, f"{target_id}.sarif"),
        "html": os.path.join(out_dir, f"{target_id}.html"),
        "scorecard_json": os.path.join(out_dir, f"{target_id}-scorecard.json"),
        "scorecard_md": os.path.join(out_dir, f"{target_id}-scorecard.md"),
    }
    cmd = [
        sys.executable, "-m", "safeai", "scan", repo_dir,
        "--json", paths["json"],
        "--sarif", paths["sarif"],
        "--html", paths["html"],
        "--scorecard-json", paths["scorecard_json"],
        "--scorecard", paths["scorecard_md"],
        "--no-registry",
    ]
    if verbose:
        cmd.append("--verbose")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=REPO_ROOT, check=False
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"scan timed out after {timeout}s") from None

    # Always keep the log, especially for a failed target: it is the only
    # record of why the scanner stopped.
    log_path = os.path.join(out_dir, f"{target_id}-scan.log")
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(result.stdout or "")
        if result.stderr:
            handle.write("\n--- stderr ---\n")
            handle.write(result.stderr)

    # Exit 0 = no blocking findings, 1 = findings at/above --fail-on (expected
    # on real repositories), 2+ = a real scanner error. A crash can still exit
    # 1, so the JSON report is the authoritative success signal.
    if not os.path.exists(paths["json"]):
        raise RuntimeError(_failure_reason(result))
    return paths


# --------------------------------------------------------------------------
# Result collection
# --------------------------------------------------------------------------


def _read_json(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def summarise(report: dict[str, Any], scorecard: dict[str, Any]) -> dict[str, Any]:
    """Reduce a full SafeAI report to the fields the comparison needs.

    Aggregate only: rule ids, counts, and capability names. No code
    excerpts, file paths, or finding messages cross into the shared report.
    """
    findings = [f for f in report.get("findings", []) if isinstance(f, dict)]
    counts = report.get("counts") or {}
    trust = report.get("trust_score") or {}
    card = (scorecard or {}).get("safeai_security_scorecard") or {}
    card_summary = card.get("summary") or {}
    metadata = report.get("scanner_metadata") or {}
    boundary = report.get("assurance_boundary") or {}

    rule_counts: Counter[str] = Counter()
    rule_severity: dict[str, str] = {}
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "UNKNOWN")
        rule_counts[rule_id] += 1
        rule_severity.setdefault(rule_id, str(finding.get("severity") or "info"))

    capabilities = sorted({
        str(cap.get("category") or cap.get("name") or "").strip()
        for cap in report.get("normalized_capabilities", [])
        if isinstance(cap, dict)
    } - {""})

    return {
        "files_scanned": int(report.get("files_scanned") or 0),
        "severity_counts": {sev: int(counts.get(sev) or 0) for sev in SEVERITIES},
        "findings_total": len(findings),
        "trust_score": trust.get("overall_ai_risk_score"),
        "trust_categories": trust.get("categories") or {},
        "scorecard_score": card_summary.get("score"),
        "scorecard_status": card_summary.get("status"),
        "blocking_findings": card_summary.get("blocking_findings"),
        "policy_outcome": (report.get("policy_decision") or {}).get("outcome"),
        "detected_frameworks": sorted(report.get("detected_frameworks") or []),
        "capabilities": capabilities,
        "mcp_assets": len(report.get("mcp_assets") or []),
        "components": len(report.get("components") or []),
        "kya_agents": len(report.get("kya_agents") or []),
        "rule_counts": dict(rule_counts),
        "rule_severity": rule_severity,
        "risk_categories": dict(Counter(
            str(f.get("risk_category") or "Unknown") for f in findings
        )),
        "owasp": dict(Counter(
            str(f.get("owasp_llm")) for f in findings if f.get("owasp_llm")
        )),
        "coverage_notes": [str(n) for n in (boundary.get("coverage_notes") or [])][:5],
        "engine_version": metadata.get("engine_version"),
        "ruleset": metadata.get("ruleset") or {},
    }


def scan_one(
    target: dict[str, Any],
    output_dir: str,
    workspace: str,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Clone + scan a single target, never raising on a target-level failure."""
    target_id = str(target["id"])
    record: dict[str, Any] = {
        "id": target_id,
        "display_name": target.get("display_name") or target_id,
        "repository": target.get("repository") or "",
        "upstream_url": target.get("upstream_url") or "",
        "ecosystem": target.get("ecosystem") or "",
        "category": target.get("category") or "",
        "requested_ref": target.get("default_ref") or "(default branch)",
        "commit": "",
        "status": "pending",
        "stage": "",
        "error": "",
        "clone_seconds": 0.0,
        "scan_seconds": 0.0,
        "artifacts_dir": os.path.relpath(os.path.join(output_dir, target_id), REPO_ROOT),
    }

    checkout = os.path.join(workspace, target_id)
    started = time.monotonic()
    try:
        print(f"  cloning {record['upstream_url']} ...", flush=True)
        sha, _ = clone(target, checkout, args.depth, args.clone_timeout)
        record["commit"] = sha
        record["clone_seconds"] = round(time.monotonic() - started, 1)
    except RuntimeError as exc:
        record.update(status="clone_failed", stage="clone", error=str(exc))
        print(f"  !! clone failed: {exc}", flush=True)
        return record

    started = time.monotonic()
    try:
        print(f"  scanning {target_id} ...", flush=True)
        paths = scan(checkout, os.path.join(output_dir, target_id), target_id, args.scan_timeout, args.verbose)
        record["scan_seconds"] = round(time.monotonic() - started, 1)
    except RuntimeError as exc:
        record.update(
            status="scan_failed",
            stage="scan",
            error=str(exc),
            scan_seconds=round(time.monotonic() - started, 1),
        )
        print(f"  !! scan failed: {exc}", flush=True)
        return record

    report = _read_json(paths["json"])
    if not report:
        record.update(status="report_unreadable", stage="parse", error="JSON report missing or invalid")
        print("  !! report unreadable", flush=True)
        return record

    record["status"] = "scanned"
    record["summary"] = summarise(report, _read_json(paths["scorecard_json"]))
    counts = record["summary"]["severity_counts"]
    print(
        f"  ok: {record['summary']['files_scanned']} files, "
        f"{counts['critical']} critical / {counts['high']} high "
        f"({record['scan_seconds']}s)",
        flush=True,
    )
    return record


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------


def _severity_key(record: dict[str, Any]) -> tuple:
    counts = record.get("summary", {}).get("severity_counts", {})
    return (
        -counts.get("critical", 0),
        -counts.get("high", 0),
        -counts.get("medium", 0),
        -counts.get("low", 0),
        record["id"],
    )


def observations(scanned: list[dict[str, Any]]) -> list[str]:
    """Derive a few cross-target patterns worth a human's attention."""
    notes: list[str] = []
    if len(scanned) < 2:
        return notes

    ids = [r["id"] for r in scanned]
    rule_sets = {r["id"]: set(r["summary"]["rule_counts"]) for r in scanned}
    cap_sets = {r["id"]: set(r["summary"]["capabilities"]) for r in scanned}

    universal_rules = sorted(set.intersection(*rule_sets.values()))
    if universal_rules:
        shown = ", ".join(universal_rules[:6])
        if len(universal_rules) > 6:
            shown += f", +{len(universal_rules) - 6} more"
        notes.append(
            f"{len(universal_rules)} rule(s) fired on every target ({shown}) — check these "
            "for systematic false positives before reporting them upstream."
        )

    universal_caps = set.intersection(*cap_sets.values())
    if universal_caps:
        notes.append(f"Capabilities common to all targets: {', '.join(sorted(universal_caps))}.")

    for target_id in ids:
        unique = cap_sets[target_id] - set().union(*(cap_sets[o] for o in ids if o != target_id))
        if unique:
            notes.append(f"Only {target_id} exposes: {', '.join(sorted(unique))}.")

    undetected = [r["id"] for r in scanned if not r["summary"]["detected_frameworks"]]
    if undetected:
        notes.append(
            f"No framework detected in: {', '.join(undetected)} — either the repository uses "
            "patterns SafeAI does not recognise yet, or it is not an agent framework. Worth an issue."
        )

    graded = [r for r in scanned if isinstance(r["summary"].get("scorecard_score"), (int, float))]
    if len(graded) >= 2:
        best = min(graded, key=lambda r: r["summary"]["scorecard_score"])
        worst = max(graded, key=lambda r: r["summary"]["scorecard_score"])
        if best["id"] != worst["id"]:
            notes.append(
                f"Security Scorecard spread: {best['id']} {best['summary']['scorecard_score']}/10 "
                f"to {worst['id']} {worst['summary']['scorecard_score']}/10 (higher is better)."
            )
    return notes


def build_comparison(records: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    scanned = [r for r in records if r["status"] == "scanned"]
    failed = [r for r in records if r["status"] != "scanned"]
    scanned.sort(key=_severity_key)

    engine = next((r["summary"].get("engine_version") for r in scanned), None)
    ruleset = next((r["summary"].get("ruleset") for r in scanned), {}) or {}

    totals: Counter[str] = Counter()
    severity_of: dict[str, str] = {}
    for record in scanned:
        totals.update(record["summary"]["rule_counts"])
        severity_of.update(record["summary"]["rule_severity"])

    capabilities = sorted({c for r in scanned for c in r["summary"]["capabilities"]})
    categories = sorted({c for r in scanned for c in r["summary"]["trust_categories"]})

    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "safeai.framework-comparison",
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "safeai_version": engine,
        "ruleset": ruleset,
        "python_version": ".".join(str(p) for p in sys.version_info[:3]),
        "requested": len(records),
        "scanned": scanned,
        "failed": failed,
        "top_rules": [
            {"rule_id": rule, "severity": severity_of.get(rule, "info"), "total": count,
             "per_target": {r["id"]: r["summary"]["rule_counts"].get(rule, 0) for r in scanned}}
            for rule, count in totals.most_common(args.top_rules)
        ],
        "capabilities": capabilities,
        "risk_categories": categories,
        "observations": observations(scanned),
        "disclaimer": DISCLAIMER,
    }


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _counter():
    """Return a callable yielding 1, 2, 3 ... so section numbers stay contiguous."""
    state = {"n": 0}

    def next_number() -> int:
        state["n"] += 1
        return state["n"]

    return next_number


def _cell(value: Any) -> str:
    return "—" if value is None or value == "" else str(value)


def render_markdown(data: dict[str, Any]) -> str:
    scanned = data["scanned"]
    lines: list[str] = []
    add = lines.append

    add("# SafeAI Framework Comparison")
    add("")
    add(f"**Generated:** {data['generated_at']} · "
        f"**SafeAI:** {_cell(data['safeai_version'])} · "
        f"**Python:** {data['python_version']}")
    ruleset = data.get("ruleset") or {}
    if ruleset:
        add(f"**Ruleset:** `{_cell(ruleset.get('file'))}` "
            f"({_cell(ruleset.get('rule_count'))} rules, sha256 `{str(ruleset.get('sha256', ''))[:12]}`)")
    add(f"**Targets:** {data['requested']} requested · {len(scanned)} scanned · {len(data['failed'])} failed")
    add("")
    add(f"> {data['disclaimer']}")
    add("")
    add("Two different scores appear below; they run in opposite directions. See "
        f"[`docs/architecture/RISK_MODEL.md`]({RISK_MODEL_URL}).")
    add("")
    add("- **Trust Score** — 0–100, *higher = cleaner*. Untouched categories score 100 and are "
        "averaged in, so a large repository with real findings can still score high. Triage signal only.")
    add("- **Security Scorecard** — 0–10, *higher = better*, with a pass/warn/fail outcome.")
    add("")

    section = _counter()

    if not scanned:
        add("No target completed a scan. See the failures table below.")
        add("")
    else:
        add(f"## {section()}. Summary")
        add("")
        add("Ordered by blocking severity (critical, then high).")
        add("")
        add("| # | Target | Repository | Commit | Files | Crit | High | Med | Low | Info | Trust ↑ | Scorecard ↑ | Outcome | Scan (s) |")
        add("|---|--------|------------|--------|------:|-----:|-----:|----:|----:|-----:|--------:|------------:|---------|---------:|")
        for index, record in enumerate(scanned, start=1):
            summary = record["summary"]
            counts = summary["severity_counts"]
            add(
                f"| {index} | **{record['display_name']}** | `{_cell(record['repository'])}` | "
                f"`{record['commit'][:8] or 'n/a'}` | {summary['files_scanned']} | "
                f"{counts['critical']} | {counts['high']} | {counts['medium']} | "
                f"{counts['low']} | {counts['info']} | {_cell(summary['trust_score'])} | "
                f"{_cell(summary['scorecard_score'])} | {_cell(summary['scorecard_status'])} | "
                f"{record['scan_seconds']} |"
            )
        add("")

        add(f"## {section()}. What SafeAI detected")
        add("")
        add("| Target | Frameworks detected | Agents (KYA) | MCP assets | Components | Findings |")
        add("|--------|--------------------|-------------:|-----------:|-----------:|---------:|")
        for record in scanned:
            summary = record["summary"]
            frameworks = ", ".join(f"`{f}`" for f in summary["detected_frameworks"]) or "*none*"
            add(
                f"| {record['display_name']} | {frameworks} | {summary['kya_agents']} | "
                f"{summary['mcp_assets']} | {summary['components']} | {summary['findings_total']} |"
            )
        add("")

        if data["capabilities"]:
            add(f"## {section()}. Capability matrix")
            add("")
            header = " | ".join(r["id"] for r in scanned)
            add(f"| Capability | {header} |")
            add("|------------|" + "|".join([":---:"] * len(scanned)) + "|")
            for capability in data["capabilities"]:
                marks = " | ".join(
                    "✔" if capability in r["summary"]["capabilities"] else "–" for r in scanned
                )
                add(f"| {capability} | {marks} |")
            add("")

        if data["risk_categories"]:
            add(f"## {section()}. Trust score by risk category")
            add("")
            add("Per-category posture, 0–100, higher = cleaner.")
            add("")
            header = " | ".join(r["id"] for r in scanned)
            add(f"| Risk category | {header} |")
            add("|---------------|" + "|".join(["---:"] * len(scanned)) + "|")
            for category in data["risk_categories"]:
                cells = " | ".join(
                    _cell(r["summary"]["trust_categories"].get(category)) for r in scanned
                )
                add(f"| {category} | {cells} |")
            add("")

        if data["top_rules"]:
            add(f"## {section()}. Most frequent rules (top {len(data['top_rules'])})")
            add("")
            header = " | ".join(r["id"] for r in scanned)
            add(f"| Rule | Severity | Total | {header} |")
            add("|------|----------|------:|" + "|".join(["---:"] * len(scanned)) + "|")
            for rule in data["top_rules"]:
                cells = " | ".join(str(rule["per_target"].get(r["id"], 0)) for r in scanned)
                add(f"| `{rule['rule_id']}` | {rule['severity']} | {rule['total']} | {cells} |")
            add("")

        if data["observations"]:
            add(f"## {section()}. Observations")
            add("")
            add("Generated from the data above. Confirm each one by hand before acting on it.")
            add("")
            for note in data["observations"]:
                add(f"- {note}")
            add("")

        notes = [(r["display_name"], n) for r in scanned for n in r["summary"]["coverage_notes"]]
        if notes:
            add(f"## {section()}. Coverage limits reported by the scanner")
            add("")
            for name, note in notes:
                add(f"- **{name}:** {note}")
            add("")

    if data["failed"]:
        add("## Failed targets")
        add("")
        add("| Target | Stage | Reason |")
        add("|--------|-------|--------|")
        for record in data["failed"]:
            reason = record["error"].replace("|", "\\|")[:200]
            add(f"| {record['display_name']} | {record['stage']} | {reason} |")
        add("")

    add("## Reproduce a single target")
    add("")
    add("```bash")
    for record in scanned:
        add(f"git clone --depth 1 {record['upstream_url']} /tmp/{record['id']}")
        add(f"python -m safeai scan /tmp/{record['id']} --html {record['id']}.html --no-registry")
    add("```")
    add("")
    add("Per-target JSON, SARIF, HTML, and scorecards are written next to this file. "
        "They are raw and unreviewed: run `community-scans/scripts/sanitise_report.py` before "
        "sharing anything publicly.")
    return "\n".join(lines) + "\n"


def render_html(data: dict[str, Any]) -> str:
    esc = html.escape
    scanned = data["scanned"]
    rows = []
    for index, record in enumerate(scanned, start=1):
        summary = record["summary"]
        counts = summary["severity_counts"]
        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td><a href=\"{esc(record['upstream_url'])}\">{esc(record['display_name'])}</a></td>"
            f"<td><code>{esc(record['commit'][:8] or 'n/a')}</code></td>"
            f"<td class=n>{summary['files_scanned']}</td>"
            f"<td class='n crit'>{counts['critical']}</td>"
            f"<td class='n high'>{counts['high']}</td>"
            f"<td class=n>{counts['medium']}</td>"
            f"<td class=n>{counts['low']}</td>"
            f"<td class=n>{esc(_cell(summary['trust_score']))}</td>"
            f"<td class=n>{esc(_cell(summary['scorecard_score']))}</td>"
            f"<td>{esc(_cell(summary['scorecard_status']))}</td>"
            f"<td class=n>{record['scan_seconds']}</td>"
            "</tr>"
        )

    cap_header = "".join(f"<th>{esc(r['id'])}</th>" for r in scanned)
    cap_rows = []
    for capability in data["capabilities"]:
        cells = "".join(
            f"<td class=n>{'✔' if capability in r['summary']['capabilities'] else '–'}</td>"
            for r in scanned
        )
        cap_rows.append(f"<tr><td>{esc(capability)}</td>{cells}</tr>")

    rule_rows = []
    for rule in data["top_rules"]:
        cells = "".join(f"<td class=n>{rule['per_target'].get(r['id'], 0)}</td>" for r in scanned)
        rule_rows.append(
            f"<tr><td><code>{esc(rule['rule_id'])}</code></td>"
            f"<td>{esc(rule['severity'])}</td><td class=n>{rule['total']}</td>{cells}</tr>"
        )

    failed_rows = "".join(
        f"<tr><td>{esc(r['display_name'])}</td><td>{esc(r['stage'])}</td>"
        f"<td>{esc(r['error'][:200])}</td></tr>"
        for r in data["failed"]
    )
    observations = "".join(f"<li>{esc(note)}</li>" for note in data["observations"])

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SafeAI Framework Comparison</title>
<style>
 body {{ font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        margin: 0 auto; max-width: 1100px; padding: 2rem 1.25rem; color: #12212b; }}
 h1 {{ margin: 0 0 .25rem; }} h2 {{ margin-top: 2.25rem; border-bottom: 2px solid {ACCENT}20;
        padding-bottom: .3rem; }}
 .meta {{ color: #5b6b76; font-size: .875rem; }}
 .note {{ background: {ACCENT}0d; border-left: 4px solid {ACCENT}; padding: .8rem 1rem;
        margin: 1.25rem 0; font-size: .9rem; }}
 table {{ border-collapse: collapse; width: 100%; margin: .75rem 0; font-size: .88rem; }}
 th, td {{ border-bottom: 1px solid #e2e8ec; padding: .45rem .55rem; text-align: left; }}
 th {{ background: {ACCENT}; color: #fff; font-weight: 600; }}
 td.n {{ text-align: right; font-variant-numeric: tabular-nums; }}
 td.crit {{ color: #b0142b; font-weight: 600; }} td.high {{ color: #c2410c; font-weight: 600; }}
 code {{ background: #f1f5f7; padding: .1rem .3rem; border-radius: 3px; font-size: .85em; }}
 tbody tr:hover {{ background: #f7fafb; }}
</style></head><body>
<h1>SafeAI Framework Comparison</h1>
<p class="meta">Generated {esc(data['generated_at'])} · SafeAI {esc(_cell(data['safeai_version']))}
 · {len(scanned)} scanned, {len(data['failed'])} failed</p>
<div class="note">{esc(data['disclaimer'])}</div>
<div class="note"><strong>Two scores, opposite directions.</strong> Trust Score is 0&ndash;100 where
 higher means cleaner and untouched categories score 100, so treat it as triage signal only.
 Security Scorecard is 0&ndash;10 where higher is better.</div>

<h2>Summary</h2>
<table><thead><tr><th>#</th><th>Target</th><th>Commit</th><th>Files</th><th>Crit</th><th>High</th>
<th>Med</th><th>Low</th><th>Trust &uarr;</th><th>Score &uarr;</th><th>Outcome</th><th>Scan s</th>
</tr></thead><tbody>{''.join(rows) or '<tr><td colspan=12>No target scanned.</td></tr>'}</tbody></table>

<h2>Capability matrix</h2>
<table><thead><tr><th>Capability</th>{cap_header}</tr></thead>
<tbody>{''.join(cap_rows) or '<tr><td>No capabilities detected.</td></tr>'}</tbody></table>

<h2>Most frequent rules</h2>
<table><thead><tr><th>Rule</th><th>Severity</th><th>Total</th>{cap_header}</tr></thead>
<tbody>{''.join(rule_rows) or '<tr><td>No findings.</td></tr>'}</tbody></table>

<h2>Observations</h2>
<ul>{observations or '<li>Nothing notable across targets.</li>'}</ul>

<h2>Failed targets</h2>
<table><thead><tr><th>Target</th><th>Stage</th><th>Reason</th></tr></thead>
<tbody>{failed_rows or '<tr><td colspan=3>None.</td></tr>'}</tbody></table>
</body></html>
"""


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan_framework.py",
        description="Scan several AI frameworks with SafeAI and build a comparison report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scripts/scan_framework.py --frameworks langgraph crewai dspy\n"
            "  python scripts/scan_framework.py --urls https://github.com/langchain-ai/langgraph\n"
            "  python scripts/scan_framework.py --frameworks langgraph dspy --html --keep-clones\n"
        ),
    )
    parser.add_argument("--frameworks", nargs="+", default=[], metavar="ID",
                        help="target ids from community-scans/targets.yml, or owner/repo")
    parser.add_argument("--urls", nargs="+", default=[], metavar="URL",
                        help="https://github.com/<owner>/<repo> URLs to scan")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                        help="where to write results (default: community-scans/reports/automated/)")
    parser.add_argument("--html", action="store_true", help="also render comparison.html")
    parser.add_argument("--depth", type=int, default=1, help="git clone depth (default: 1)")
    parser.add_argument("--clone-timeout", type=int, default=600, metavar="SEC",
                        help="per-target clone timeout (default: 600)")
    parser.add_argument("--scan-timeout", type=int, default=1800, metavar="SEC",
                        help="per-target scan timeout (default: 1800)")
    parser.add_argument("--top-rules", type=int, default=15,
                        help="rows in the most-frequent-rules table (default: 15)")
    parser.add_argument("--keep-clones", action="store_true",
                        help="keep the cloned repositories instead of deleting them")
    parser.add_argument("--workspace", default=None,
                        help="directory for clones (default: a temporary directory)")
    parser.add_argument("--list", action="store_true", dest="list_targets",
                        help="list the known target ids and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="resolve targets and print the plan without cloning")
    parser.add_argument("--verbose", action="store_true", help="pass --verbose to each scan")
    return parser


def print_catalog(catalog: dict[str, dict[str, Any]]) -> int:
    if not catalog:
        print("No catalog found at community-scans/targets.yml (is PyYAML installed?)", file=sys.stderr)
        return 2
    print(f"{len(catalog)} targets in community-scans/targets.yml:\n")
    print(f"  {'id':<18} {'repository':<32} {'ecosystem':<12} category")
    for entry in catalog.values():
        print(f"  {entry['id']:<18} {entry.get('repository', ''):<32} "
              f"{entry.get('ecosystem', ''):<12} {entry.get('category', '')}")
    print("\nAny owner/repo or https://github.com/<owner>/<repo> also works.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    catalog = load_catalog()

    if args.list_targets:
        return print_catalog(catalog)

    tokens = list(args.frameworks) + list(args.urls)
    if not tokens:
        print("error: pass --frameworks and/or --urls (or --list to see the catalog)", file=sys.stderr)
        return 2

    targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for token in tokens:
        try:
            target = resolve_target(token, catalog)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if target["id"] in seen:
            print(f"note: skipping duplicate target {target['id']}")
            continue
        seen.add(target["id"])
        targets.append(target)

    print(f"SafeAI multi-framework scan · {len(targets)} target(s)")
    for target in targets:
        print(f"  - {target['id']:<16} {target['upstream_url']} @ {target.get('default_ref') or '(default)'}")
    if args.dry_run:
        print("\n--dry-run: nothing cloned or scanned.")
        return 0

    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)
    workspace = args.workspace or tempfile.mkdtemp(prefix="safeai-scan-")
    os.makedirs(workspace, exist_ok=True)

    records: list[dict[str, Any]] = []
    try:
        for position, target in enumerate(targets, start=1):
            print(f"\n[{position}/{len(targets)}] {target['id']}")
            records.append(scan_one(target, output_dir, workspace, args))
    except KeyboardInterrupt:
        print("\ninterrupted — writing the comparison for targets completed so far", file=sys.stderr)
    finally:
        if not args.keep_clones and not args.workspace:
            shutil.rmtree(workspace, ignore_errors=True)
        elif args.keep_clones:
            print(f"\nClones kept in {workspace}")

    comparison = build_comparison(records, args)

    json_path = os.path.join(output_dir, "comparison.json")
    md_path = os.path.join(output_dir, "COMPARISON.md")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(comparison, handle, indent=2, sort_keys=True)
        handle.write("\n")
    with open(md_path, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(comparison))
    written = [md_path, json_path]
    if args.html:
        html_path = os.path.join(output_dir, "comparison.html")
        with open(html_path, "w", encoding="utf-8") as handle:
            handle.write(render_html(comparison))
        written.append(html_path)

    scanned = len(comparison["scanned"])
    failed = len(comparison["failed"])
    print(f"\nDone: {scanned} scanned, {failed} failed")
    for path in written:
        print(f"  {os.path.relpath(path, os.getcwd())}")

    if scanned == 0:
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # e.g. `... --list | head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
