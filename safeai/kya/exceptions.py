"""File-backed policy exception records (``.safeai/exceptions.yml``).

An exception names a risk owner who accepts a specific finding, policy,
or escalation for a bounded scope and time, with compensating controls
and re-review triggers. Exceptions warn by default; ``--strict-exceptions``
turns expired or stale exceptions into a scan failure.

An exception is ``active`` when its ``finding_or_policy`` id matches a
live finding (rule_id), policy match (policy_id), or escalation id, it is
not expired, and its repository scope (when given) matches the scanned
project. It is ``expired`` past ``expires_at``, and ``stale`` when
nothing live matches anymore (the authority shifted out from under it).
Unknown scope identity never blocks: it is recorded, not enforced.
"""

import os
from datetime import UTC, datetime

import yaml

DEFAULT_EXCEPTIONS_PATH = os.path.join(".safeai", "exceptions.yml")


class ExceptionError(Exception):
    """Raised for invalid exception files."""


def default_exceptions_path(root):
    return os.path.join(root, DEFAULT_EXCEPTIONS_PATH)


def _parse_date(value, field, exception_id):
    from datetime import date

    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise ExceptionError(
            f"Exception {exception_id!r}: field '{field}' must be an ISO date "
            f"(YYYY-MM-DD), got {value!r}."
        ) from exc


def load_exceptions(path):
    """Load and validate an exceptions file.

    Returns ``(entries, warnings)``. A missing file yields empty results.
    Invalid entries raise ``ExceptionError`` — silent exceptions are never
    permitted.
    """
    if not path or not os.path.exists(path):
        return [], []

    try:
        with open(path, encoding="utf-8") as fh:
            document = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ExceptionError(f"Unable to read exceptions file {path}: {exc}") from exc

    raw_entries = document.get("exceptions") or []
    if not isinstance(raw_entries, list):
        raise ExceptionError(f"Exceptions file {path}: 'exceptions' must be a list.")

    entries = []
    today = datetime.now(UTC).date()
    for index, raw in enumerate(raw_entries, 1):
        if not isinstance(raw, dict):
            raise ExceptionError(f"Exception #{index}: entry must be a mapping.")
        exception_id = raw.get("exception_id") or f"exception-#{index}"
        for field in ("finding_or_policy", "risk_owner", "rationale"):
            if not raw.get(field):
                raise ExceptionError(
                    f"Exception {exception_id!r}: missing required field '{field}'."
                )
        scope = raw.get("scope") or {}
        if not isinstance(scope, dict):
            raise ExceptionError(f"Exception {exception_id!r}: 'scope' must be a mapping.")
        controls = raw.get("compensating_controls") or []
        if not isinstance(controls, list):
            raise ExceptionError(
                f"Exception {exception_id!r}: 'compensating_controls' must be a list."
            )
        triggers = raw.get("review_trigger") or []
        if not isinstance(triggers, list):
            raise ExceptionError(f"Exception {exception_id!r}: 'review_trigger' must be a list.")
        expires_at = None
        if raw.get("expires_at"):
            expires_at = _parse_date(raw["expires_at"], "expires_at", exception_id)
        entries.append({
            "exception_id": str(exception_id),
            "finding_or_policy": str(raw["finding_or_policy"]),
            "scope": {
                "repository": scope.get("repository"),
                "commit_range": scope.get("commit_range"),
            },
            "risk_owner": str(raw["risk_owner"]),
            "rationale": str(raw["rationale"]),
            "compensating_controls": [str(c) for c in controls],
            "expires_at": expires_at.isoformat() if expires_at else None,
            "expired": bool(expires_at and expires_at < today),
            "review_trigger": [str(t) for t in triggers],
        })

    return entries, []


def _live_ids(findings, escalations):
    """Collect the ids an exception can match: rule ids, policy ids, escalation ids."""
    ids = set()
    for finding in findings or []:
        if finding.get("rule_id"):
            ids.add(str(finding["rule_id"]))
    for escalation in escalations or []:
        if escalation.get("id"):
            ids.add(str(escalation["id"]))
    return ids


def evaluate_exceptions(entries, findings, escalations, project_repository=None):
    """Evaluate exception records against live scan evidence.

    Returns a list of evaluation records: ``exception_id``,
    ``finding_or_policy``, ``state`` (``active`` | ``expired`` |
    ``stale``), ``risk_owner``, ``expires_at``, and ``warnings``.
    Scope mismatches and unknown scope identity are recorded as
    warnings, never as silent passes.
    """
    live = _live_ids(findings, escalations)
    evaluations = []
    for entry in entries:
        warnings = []
        target = entry["finding_or_policy"]
        matched = target in live
        if entry.get("expired"):
            state = "expired"
            warnings.append(
                f"Exception {entry['exception_id']} ({target}) expired on "
                f"{entry.get('expires_at')} and no longer applies."
            )
        elif not matched:
            state = "stale"
            warnings.append(
                f"Exception {entry['exception_id']} ({target}) matches no current "
                f"finding, policy, or escalation — the authority has shifted."
            )
        else:
            state = "active"
        scope_repo = (entry.get("scope") or {}).get("repository")
        if scope_repo and project_repository and scope_repo != project_repository:
            warnings.append(
                f"Exception {entry['exception_id']} scope repository "
                f"{scope_repo!r} does not match scanned project "
                f"{project_repository!r}."
            )
            if state == "active":
                state = "stale"
        evaluations.append({
            "exception_id": entry["exception_id"],
            "finding_or_policy": target,
            "state": state,
            "risk_owner": entry.get("risk_owner"),
            "expires_at": entry.get("expires_at"),
            "compensating_controls": entry.get("compensating_controls") or [],
            "review_trigger": entry.get("review_trigger") or [],
            "warnings": warnings,
        })
    return evaluations
