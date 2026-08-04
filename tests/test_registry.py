"""Tests for the SQLite KYA registry: persistence, identity, history, queries."""

import os

from safeai.cmd.cli import main
from safeai.kya.registry import (
    SAFEAI_REGISTRY_ENV,
    agent_history,
    connect,
    get_agent,
    get_snapshot,
    init_registry,
    latest_scan_id,
    list_agents,
    registry_exists,
    resolve_scan_ref,
    shared_registry_path,
)


def _scan(root, tmp_path, extra=None):
    registry = os.path.join(root, ".safeai", "registry.db")
    argv = ["scan", root, "--sarif", os.path.join(tmp_path, "r.sarif")]
    if not extra or ("--registry" not in extra and "--no-registry" not in extra):
        argv += ["--registry", registry]
    if extra:
        argv += extra
    return main(argv)


def test_first_scan_initializes_registry(kya_project, tmp_path):
    rc = _scan(kya_project["root"], str(tmp_path))
    assert rc in (0, 1)
    assert registry_exists(kya_project["registry"])

    conn = connect(kya_project["registry"])
    try:
        version = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()["v"]
        assert version >= 1
        agents = list_agents(conn)
        assert len(agents) >= 1
    finally:
        conn.close()


def test_subsequent_scan_appends_history(kya_project, tmp_path):
    _scan(kya_project["root"], str(tmp_path))
    _scan(kya_project["root"], str(tmp_path))

    conn = connect(kya_project["registry"])
    try:
        scans = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        assert scans == 2  # history preserved, never overwritten

        agents = list_agents(conn)
        assert len(agents) == 1  # same agent identity across scans
        history = agent_history(conn, agents[0]["agent_id"])
        assert len(history) == 2
    finally:
        conn.close()


def test_stable_agent_id_across_equivalent_scans(kya_project, tmp_path):
    _scan(kya_project["root"], str(tmp_path))
    conn = connect(kya_project["registry"])
    first = [a["agent_id"] for a in list_agents(conn)]
    conn.close()

    _scan(kya_project["root"], str(tmp_path))
    conn = connect(kya_project["registry"])
    second = [a["agent_id"] for a in list_agents(conn)]
    conn.close()
    assert first == second


def test_registry_stores_no_raw_secret(kya_project, tmp_path):
    _scan(kya_project["root"], str(tmp_path))
    conn = connect(kya_project["registry"])
    try:
        rows = conn.execute("SELECT manifest_json, message FROM scans s JOIN findings f ON f.last_seen_scan = s.scan_id").fetchall()
        blob = " ".join(str(dict(r)) for r in rows)
        assert "sk-1234567890abcdefghij" not in blob
    finally:
        conn.close()
    with open(kya_project["registry"], "rb") as fh:
        raw_db = fh.read()
    assert b"sk-1234567890abcdefghij" not in raw_db


def test_no_registry_flag(kya_project, tmp_path):
    rc = _scan(kya_project["root"], str(tmp_path), extra=["--no-registry"])
    assert rc in (0, 1)
    assert not registry_exists(kya_project["registry"])


def test_explicit_registry_path(kya_project, tmp_path):
    custom = os.path.join(str(tmp_path), "custom", "reg.db")
    rc = _scan(kya_project["root"], str(tmp_path), extra=["--registry", custom])
    assert rc in (0, 1)
    assert registry_exists(custom)
    assert not registry_exists(kya_project["registry"])


def test_registry_write_failure_warns_but_scan_succeeds(kya_project, tmp_path, capsys):
    bad_path = os.path.join(str(tmp_path), "blocked", "reg.db")
    os.makedirs(bad_path)  # a directory with the target name -> open fails
    rc = _scan(kya_project["root"], str(tmp_path), extra=["--registry", bad_path])
    assert rc in (0, 1)  # scan still succeeds
    err = capsys.readouterr().err
    assert "registry persistence failed" in err


def test_strict_registry_fails_on_error(kya_project, tmp_path, capsys):
    bad_path = os.path.join(str(tmp_path), "blocked", "reg.db")
    os.makedirs(bad_path)
    rc = _scan(kya_project["root"], str(tmp_path),
               extra=["--registry", bad_path, "--strict-registry"])
    assert rc == 2


def test_migration_idempotent(tmp_path):
    path = os.path.join(str(tmp_path), "reg.db")
    conn, created = init_registry(path)
    assert created
    conn.close()
    conn2, created2 = init_registry(path)
    assert not created2  # existing DB never destroyed
    v = conn2.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()["v"]
    assert v >= 1
    conn2.close()


def test_regressed_detection(kya_project, tmp_path):
    # Scan 1: secret present.
    _scan(kya_project["root"], str(tmp_path))
    # Scan 2: secret removed (v2 has no API_KEY).
    kya_project["write_version"](kya_project["v2"])
    _scan(kya_project["root"], str(tmp_path))
    # Scan 3: secret reintroduced -> regressed.
    kya_project["write_version"](kya_project["v1"])
    _scan(kya_project["root"], str(tmp_path))

    conn = connect(kya_project["registry"])
    try:
        latest = latest_scan_id(conn)
        rows = conn.execute(
            "SELECT status, rule_id FROM scan_findings WHERE scan_id = ?", (latest,)
        ).fetchall()
        statuses = {r["rule_id"]: r["status"] for r in rows}
        assert statuses.get("DATA_LEAKAGE") == "regressed"
    finally:
        conn.close()


def test_get_agent_and_snapshot(kya_project, tmp_path):
    _scan(kya_project["root"], str(tmp_path))
    conn = connect(kya_project["registry"])
    try:
        agent = list_agents(conn)[0]
        record = get_agent(conn, agent["agent_id"])
        assert record["snapshot"]
        assert record["scan"]["scan_id"]
        assert record["findings"]
        assert record["snapshot"]["framework"] == "langgraph"
    finally:
        conn.close()


def test_resolve_scan_refs(kya_project, tmp_path):
    _scan(kya_project["root"], str(tmp_path))
    _scan(kya_project["root"], str(tmp_path))
    conn = connect(kya_project["registry"])
    try:
        agent_id = list_agents(conn)[0]["agent_id"]
        latest = resolve_scan_ref(conn, agent_id, "latest")
        previous = resolve_scan_ref(conn, agent_id, "previous")
        assert latest and previous and latest != previous
        assert resolve_scan_ref(conn, agent_id, latest) == latest
        assert get_snapshot(conn, agent_id, latest)
    finally:
        conn.close()


def test_shared_registry_path_respects_env(monkeypatch, tmp_path):
    expected = str(tmp_path / "custom" / "registry.db")
    monkeypatch.setenv(SAFEAI_REGISTRY_ENV, expected)
    assert shared_registry_path() == expected


def test_shared_registry_path_defaults_to_home(monkeypatch):
    monkeypatch.delenv(SAFEAI_REGISTRY_ENV, raising=False)
    import os

    assert shared_registry_path() == os.path.join(
        os.path.expanduser("~"), ".safeai", "registry.db"
    )
