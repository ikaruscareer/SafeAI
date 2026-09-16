"""Expected-findings checker for community rule packs (CE 2.3, WS7).

A rule pack is a directory of ``*.yaml`` rule files plus an optional
``fixtures/`` directory:

- ``fixtures/risky_*.py`` — each file must produce at least one finding
  whose rule ID comes from the pack, at the pack's severity. This proves
  the pack's overrides actually take effect in a scan.
- ``fixtures/safe_*.py`` — must produce zero findings with pack rule IDs.

Pack rules with IDs no analyzer emits can only act as documentation;
they are reported as warnings, not failures (custom rules override
built-in severity/OWASP — see ``safeai/rules/loader.py``).

Fully offline. Never executes fixture code.
"""

import json
import os
import tempfile

import yaml

from safeai.rules.loader import _iter_rule_files, _validate_rule, load_rules

FIXTURES_DIRNAME = "fixtures"


def _pack_rule_ids(pack_dir):
    """Return (valid id->rule, builtin ids, file_errors) for a pack directory."""
    builtin_ids = {r.get("id") for r in load_rules()[0]}
    valid = {}
    errors = []
    if not os.path.isdir(pack_dir):
        return valid, builtin_ids, errors
    for filename in _iter_rule_files(pack_dir):
        path = os.path.join(pack_dir, filename)
        try:
            with open(path, encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle) or []
        except Exception as exc:
            errors.append(f"{filename}: unreadable ({exc})")
            continue
        if not isinstance(loaded, list):
            errors.append(f"{filename}: top level must be a YAML list of rules")
            continue
        for rule in loaded:
            checked = _validate_rule(rule, f"pack:{filename}")
            if checked is None:
                rule_id = rule.get("id", "?") if isinstance(rule, dict) else "?"
                errors.append(
                    f"{filename}: rule {rule_id} "
                    "missing id/description/severity or bad severity"
                )
            else:
                valid[checked["id"]] = checked
    return valid, builtin_ids, errors


def check_pack(pack_dir):
    """Check a rule pack. Returns ``(errors, warnings)`` string lists.

    Empty errors means the pack is sound. Runs one offline scan over
    ``fixtures/``; fixture code is never executed.
    """
    errors, warnings = [], []
    pack_rules, builtin_ids, file_errors = _pack_rule_ids(pack_dir)
    errors.extend(file_errors)
    if not pack_rules and not errors:
        errors.append("no valid rules found: pack needs at least one rule with id/description/severity")
        return errors, warnings

    for rule_id in sorted(pack_rules):
        if rule_id not in builtin_ids:
            warnings.append(
                f"rule {rule_id}: no analyzer emits this ID — "
                "it documents intent but changes no finding (override a built-in ID to take effect)"
            )

    fixtures = os.path.join(pack_dir, FIXTURES_DIRNAME)
    if not os.path.isdir(fixtures):
        errors.append(
            f"no {FIXTURES_DIRNAME}/ directory: add risky_*.py / safe_*.py fixtures "
            "so the pack proves its overrides take effect"
        )
        return errors, warnings

    risky = sorted(
        f for f in os.listdir(fixtures)
        if f.startswith("risky_") and f.endswith(".py")
    )
    safe = sorted(
        f for f in os.listdir(fixtures)
        if f.startswith("safe_") and f.endswith(".py")
    )
    if not risky:
        errors.append("no fixtures/risky_*.py files: at least one risky fixture is required")
        return errors, warnings

    findings = _scan_fixtures(fixtures, pack_dir)
    if findings is None:
        errors.append("fixture scan failed to produce a JSON report")
        return errors, warnings

    pack_ids = set(pack_rules)
    pack_severity = {rid: pack_rules[rid].get("severity") for rid in pack_ids}
    by_file = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if finding.get("rule_id") not in pack_ids:
            continue
        by_file.setdefault(os.path.basename(str(finding.get("file") or "")), []).append(finding)

    for fixture in risky:
        hits = by_file.get(fixture, [])
        if not hits:
            errors.append(
                f"fixtures/{fixture}: expected a finding with a pack rule ID, got none"
            )
        for hit in hits:
            expected = pack_severity.get(hit.get("rule_id"))
            if expected and hit.get("severity") != expected:
                errors.append(
                    f"fixtures/{fixture}: rule {hit.get('rule_id')} severity "
                    f"{hit.get('severity')!r} != pack severity {expected!r}"
                )
    for fixture in safe:
        hits = by_file.get(fixture, [])
        if hits:
            errors.append(
                f"fixtures/{fixture}: expected no pack findings, got "
                + ", ".join(sorted({str(h.get('rule_id')) for h in hits}))
            )
    return errors, warnings


def _scan_fixtures(fixtures_dir, pack_dir):
    """Run one offline scan over fixtures; return findings or None."""
    from safeai.cmd.cli import main

    tmpdir = tempfile.mkdtemp(prefix="safeai-pack-")
    json_path = os.path.join(tmpdir, "pack.json")
    sarif_path = os.path.join(tmpdir, "pack.sarif")
    main([
        "scan", fixtures_dir, "--rules", pack_dir,
        "--json", json_path, "--sarif", sarif_path, "--no-registry",
    ])
    try:
        with open(json_path, encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError):
        return None
    findings = report.get("findings")
    return findings if isinstance(findings, list) else None
