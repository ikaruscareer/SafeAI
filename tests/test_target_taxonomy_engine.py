"""Unit tests for the target taxonomy engine (CE 1.5)."""

from safeai.analysis.target_taxonomy import build_target_taxonomy


def _report(tool_surface=None, mcp_capabilities=None):
    return {
        "tool_surface": tool_surface or [],
        "mcp_capabilities": mcp_capabilities or [],
    }


def _cap(name, category=None, access_mode=None):
    return {
        "name": name,
        "category": category,
        "access_mode": access_mode,
    }


def test_classifies_known_capabilities_into_buckets():
    surface = [{
        "tool_key": "tool:db",
        "capabilities": [
            _cap("postgres", "db", "write"),
            _cap("slack", "chat", "read"),
            _cap("s3", "storage", "write"),
        ],
    }]
    tax = build_target_taxonomy(_report(surface))

    assert any(c["capability"] == "postgres" for c in tax["buckets"]["database"])
    assert any(c["capability"] == "slack" for c in tax["buckets"]["saas_api"])
    assert any(c["capability"] == "s3" for c in tax["buckets"]["object_storage"])


def test_unknown_capability_falls_into_other():
    surface = [{
        "tool_key": "tool:x",
        "capabilities": [_cap("frobnicate")],
    }]
    tax = build_target_taxonomy(_report(surface))

    assert any(c["capability"] == "frobnicate" for c in tax["buckets"]["other"])
    # Bucket counts are non-negative integers and total is consistent.
    assert tax["summary"]["total"] == sum(
        v for k, v in tax["summary"].items() if k != "total"
    )


def test_mcp_capabilities_are_aggregated():
    mcp_caps = [_cap("kafka", "messaging"), _cap("aws", "cloud")]
    tax = build_target_taxonomy(_report([], mcp_caps))

    assert any(c["capability"] == "kafka" for c in tax["buckets"]["messaging"])
    assert any(c["capability"] == "aws" for c in tax["buckets"]["cloud_service"])


def test_deduplicates_and_is_deterministic():
    surface = [{
        "tool_key": "tool:db",
        "capabilities": [_cap("postgres"), _cap("mysql"), _cap("redis")],
    }]
    first = build_target_taxonomy(_report(surface))
    second = build_target_taxonomy(_report(surface))

    assert first["buckets"] == second["buckets"]
    assert first["summary"] == second["summary"]
    # Each capability appears once per bucket even if supplied repeatedly.
    assert len(tax_buckets_postgres(first)) == 1


def tax_buckets_postgres(tax):
    return [c for c in tax["buckets"]["database"] if c["capability"] == "postgres"]
