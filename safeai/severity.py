"""Canonical severity vocabulary — the single source of truth.

Findings use five levels; escalations use four (never ``info``). Every
module derives its ordering, ranking, and score weights from this file,
so the scales cannot drift between the CLI, the escalation engine, the
policy evaluator, the scorers, and the report renderers.
"""

#: Finding severities, ascending: each level is more severe than the last.
SEVERITIES = ("info", "low", "medium", "high", "critical")

#: Escalation severities, ascending. Escalations never use ``info``.
ESCALATION_SEVERITIES = ("low", "medium", "high", "critical")

#: Trust-score weight per finding severity (see ``safeai.scoring.engine``).
SEVERITY_POINTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 4,
    "info": 1,
}

_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def rank(severity, default=0):
    """Ordinal of ``severity``; higher is more severe.

    Unknown values return ``default`` (``0``, the ``info`` rank), the
    least-alarming value — an unrecognised severity must never outrank a
    real one.
    """
    return _RANK.get(str(severity or "").strip().lower(), default)
