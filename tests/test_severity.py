"""Canonical severity vocabulary: one scale, two views, no drift."""

from safeai.severity import (
    ESCALATION_SEVERITIES,
    SEVERITIES,
    SEVERITY_POINTS,
    rank,
)


def test_finding_scale_is_ascending():
    assert SEVERITIES == ("info", "low", "medium", "high", "critical")


def test_escalation_scale_is_finding_scale_minus_info():
    assert ESCALATION_SEVERITIES == tuple(s for s in SEVERITIES if s != "info")


def test_rank_orders_by_severity():
    assert rank("critical") > rank("high") > rank("medium") > rank("low") > rank("info")


def test_rank_is_case_insensitive_and_tolerant():
    assert rank(" Critical ") == rank("critical")
    assert rank(None) == rank("info") == 0
    assert rank("bogus") == 0


def test_rank_custom_default_for_unknown():
    assert rank("bogus", default=-1) == -1


def test_points_cover_every_finding_severity():
    assert set(SEVERITY_POINTS) == set(SEVERITIES)
    assert SEVERITY_POINTS["critical"] > SEVERITY_POINTS["high"] > SEVERITY_POINTS["medium"]
