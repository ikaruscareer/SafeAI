"""Tests for the CE 2.3 analyzer plugin SDK (WS1).

Covers the ``safeai.analyzers`` registry: built-in order preservation,
third-party registration, component-phase contract validation, and
orchestrator isolation of raising external analyzers.
"""

import pytest

from safeai import analyzers as analyzer_registry
from safeai.analyzers import (
    COMPONENT,
    CORE,
    discover_analyzers,
    register_analyzer,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    """Reset to canonical built-ins; drop test-registered analyzers after each test."""
    analyzer_registry._ANALYZER_REGISTRY.clear()
    analyzer_registry._ANALYZER_NAMES.clear()
    analyzer_registry._import_builtin_analyzers()
    yield
    analyzer_registry._ANALYZER_REGISTRY.clear()
    analyzer_registry._ANALYZER_NAMES.clear()
    analyzer_registry._import_builtin_analyzers()


def test_builtin_run_order_matches_legacy_orchestrator():
    core = [a.name for a in discover_analyzers(phase=CORE, include_external=False)]
    component = [a.name for a in discover_analyzers(phase=COMPONENT, include_external=False)]
    assert core == [
        "capability", "prompt", "data_leakage", "env_dependency", "mcp", "claude_code",
    ]
    assert component == [
        "skill", "prompt_file", "tool_def", "model_config",
        "workflow", "governance", "dataflow",
    ]


def test_thirteen_builtins_registered():
    assert len(discover_analyzers(include_external=False)) == 13


def test_external_analyzer_registers_and_runs_last():
    @register_analyzer(phase=COMPONENT)
    class ExtraAnalyzer:
        name = "extra_test_plugin"

        def run(self, file_cache, rules, agent_models=None, components=None):
            return []

    found = discover_analyzers(phase=COMPONENT, include_external=False)
    assert found[-1].name == "extra_test_plugin"
    assert found[-1]._safeai_external is False  # direct registration is trusted


def test_component_phase_requires_components_kwarg():
    class BadAnalyzer:
        name = "bad_test_plugin"

        def run(self, file_cache, rules, agent_models=None):
            return []

    with pytest.raises(TypeError, match="must accept components=None"):
        register_analyzer(BadAnalyzer, phase=COMPONENT)


def test_register_rejects_nameless_or_methodless():
    with pytest.raises(TypeError):
        register_analyzer(type("NoName", (), {"run": lambda self: []}))
    with pytest.raises(TypeError):
        register_analyzer(type("NoRun", (), {"name": "no_run_test"}))


def test_orchestrator_isolates_raising_external_analyzer(tmp_path, monkeypatch):
    """A crashing third-party analyzer must not fail the scan."""
    from safeai.engine.scan import run_scan

    @register_analyzer(phase=COMPONENT)
    class BoomAnalyzer:
        name = "boom_test_plugin"

        def run(self, file_cache, rules, agent_models=None, components=None):
            raise RuntimeError("plugin exploded")

    # Mark it as external (entry-point loaded) so isolation applies.
    for entry in analyzer_registry._ANALYZER_REGISTRY:
        if entry["name"] == "boom_test_plugin":
            entry["external"] = True

    target = tmp_path / "agent.py"
    target.write_text("import subprocess\nsubprocess.run(['ls'])\n", encoding="utf-8")
    report = run_scan(str(tmp_path))
    assert "boom_test_plugin" not in str(report.get("findings", []))
    assert report["files_scanned"] >= 1


# --------------------------------------------------------------------------
# WS2: per-scan plugin/pack version recording
# --------------------------------------------------------------------------


def _scan_manifest(root, tmp_path):
    import json
    import os

    from safeai.cmd.cli import main

    manifest_path = os.path.join(str(tmp_path), "safeai-manifest.json")
    rc = main(["scan", root, "--manifest", manifest_path,
               "--sarif", os.path.join(str(tmp_path), "r.sarif"), "--no-registry"])
    assert rc in (0, 1)
    with open(manifest_path, encoding="utf-8") as fh:
        return json.load(fh)


def test_manifest_records_analyzer_and_parser_versions(kya_project, tmp_path):
    import safeai

    # NOTE: the parser registry is process-global; other test modules may
    # import extra parser modules directly (e.g. autogen), so assert the
    # built-in set as a subset, not an exact count.
    EXPECTED_PARSERS = {
        "azure_foundry", "bedrock_agent", "claude_code", "copilot", "crewai",
        "cursorrules", "dify", "google_adk", "haystack", "langchain",
        "langgraph", "llamaindex", "mastra", "microsoft_agent_framework",
        "n8n", "openai_agents", "openclaw", "semantic_kernel", "windsurf",
    }
    manifest = _scan_manifest(kya_project["root"], str(tmp_path))
    analyzers = manifest["safeai"]["analyzer_versions"]
    parsers = manifest["safeai"]["parser_versions"]
    assert len(analyzers) == 13
    assert EXPECTED_PARSERS <= set(parsers)
    # Built-ins resolve to the SafeAI version.
    assert set(analyzers.values()) == {safeai.__version__}
    assert all(parsers[name] == safeai.__version__ for name in EXPECTED_PARSERS)
    assert analyzers["governance"] == safeai.__version__
    assert parsers["copilot"] == safeai.__version__


def test_registry_persists_plugin_versions(kya_project, tmp_path):
    import json
    import sqlite3

    from safeai.kya.registry.connection import migrate
    from safeai.kya.registry.persist import persist_scan

    manifest = _scan_manifest(kya_project["root"], str(tmp_path))
    db_path = str(tmp_path / "registry.db")
    conn = sqlite3.connect(db_path)
    try:
        assert migrate(conn) == 6
        persist_scan(conn, manifest)
        row = conn.execute("SELECT plugin_versions_json FROM scans").fetchone()
        stored = json.loads(row[0])
        assert set(stored["analyzers"]) == set(manifest["safeai"]["analyzer_versions"])
        assert set(stored["parsers"]) == set(manifest["safeai"]["parser_versions"])
        assert stored["rule_packs"] == manifest["safeai"]["rule_pack_ids"]
    finally:
        conn.close()


def test_migration_v6_adds_nullable_column(tmp_path):
    import sqlite3

    from safeai.kya.registry.connection import migrate
    from safeai.kya.registry.schema import _MIGRATIONS

    db_path = str(tmp_path / "old.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        # Simulate a pre-v2.3 database: migrations 1-5 only, with a legacy row.
        for target in (1, 2, 3, 4, 5):
            conn.executescript(_MIGRATIONS[target])
            conn.execute(
                "INSERT OR REPLACE INTO schema_migrations(version, applied_at)"
                " VALUES (?, datetime('now'))",
                (target,),
            )
        conn.execute(
            "INSERT INTO scans(scan_id, project_id, safeai_version, manifest_json, manifest_hash)"
            " VALUES ('s1', 'p1', '2.2.1', '{}', 'abc')"
        )
        conn.commit()
        assert migrate(conn) == 6
        row = conn.execute(
            "SELECT safeai_version, plugin_versions_json FROM scans WHERE scan_id = 's1'"
        ).fetchone()
        assert row[0] == "2.2.1"
        assert row[1] is None
    finally:
        conn.close()


# --------------------------------------------------------------------------
# WS3: pack lifecycle (policy profile pin, export pins, import drift)
# --------------------------------------------------------------------------


def test_manifest_records_policy_profile(kya_project, tmp_path):
    manifest = _scan_manifest(kya_project["root"], str(tmp_path))
    assert "policy_profile" in manifest["safeai"]


def test_manifest_records_policy_profile_name(kya_project, tmp_path):
    import os

    from safeai.cmd.cli import main

    manifest_path = os.path.join(str(tmp_path), "safeai-manifest.json")
    rc = main(["scan", kya_project["root"], "--manifest", manifest_path,
               "--sarif", os.path.join(str(tmp_path), "r.sarif"),
               "--no-registry", "--policy-profile", "strict-ci"])
    assert rc in (0, 1)
    import json

    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    assert manifest["safeai"]["policy_profile"] == "strict-ci"


def _persisted_registry(tmp_path):
    import sqlite3

    from safeai.kya.registry.connection import migrate
    from safeai.kya.registry.persist import persist_scan

    manifest = _scan_manifest(str(tmp_path / "proj"), str(tmp_path))
    db_path = str(tmp_path / "registry.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    migrate(conn)
    persist_scan(conn, manifest)
    conn.commit()
    return conn


def test_export_carries_plugin_pins(tmp_path):
    from safeai.kya.exporter import export_inventory

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "agent.py").write_text("x = 1\n", encoding="utf-8")
    conn = _persisted_registry(tmp_path)
    try:
        document = export_inventory(conn)
        assert document["projects"], "expected one exported project"
        pins = document["projects"][0]["plugin_versions"]
        assert len(pins["analyzers"]) == 13
        assert "governance" in pins["analyzers"]
        assert "copilot" in pins["parsers"]
        assert "openclaw" in pins["parsers"]
        assert isinstance(pins["rule_packs"], list)
    finally:
        conn.close()


def test_import_dry_run_warns_on_pin_drift(tmp_path):
    import sqlite3

    from safeai.kya.importer import plan_import
    from safeai.kya.registry.connection import migrate

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    migrate(conn)
    document = {
        "export_type": "safeai.kya.inventory",
        "schema_version": "1.1",
        "projects": [{
            "project_id": "p1",
            "agents": [],
            "latest_findings": [],
            "plugin_versions": {
                "analyzers": {"governance": "0.0.0-stale"},
                "parsers": {},
            },
        }],
    }
    stats = plan_import(conn, document)
    assert any("governance" in w and "0.0.0-stale" in w for w in stats["pin_drift"])
    conn.close()


def test_import_dry_run_quiet_when_pins_match(tmp_path):
    from safeai.kya.exporter import export_inventory
    from safeai.kya.importer import plan_import

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "agent.py").write_text("x = 1\n", encoding="utf-8")
    conn = _persisted_registry(tmp_path)
    try:
        document = export_inventory(conn)
        stats = plan_import(conn, document)
        assert stats["pin_drift"] == []
    finally:
        conn.close()


# --------------------------------------------------------------------------
# WS5: lockfile-style component integrity
# --------------------------------------------------------------------------


def _scan_to_shared_registry(root, tmp_path):
    import os

    from safeai.cmd.cli import main

    rc = main(["scan", root, "--sarif", os.path.join(str(tmp_path), "r.sarif")])
    assert rc in (0, 1)


def test_lockfile_round_trip_holds(tmp_path):
    import json

    from safeai.cmd.cli import main

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "agent.py").write_text("x = 1\n", encoding="utf-8")
    (proj / "helper.skill.yaml").write_text(
        "skill_type: helper\ntools: [read_file]\n", encoding="utf-8"
    )
    _scan_to_shared_registry(str(proj), tmp_path)

    lock_path = str(tmp_path / "components.lock.json")
    assert main(["registry", "components", "--lockfile", lock_path]) == 0
    with open(lock_path, encoding="utf-8") as fh:
        lockfile = json.load(fh)
    assert lockfile["lockfile_type"] == "safeai.component-lockfile"
    assert any(c["type"] == "skill" for c in lockfile["components"])
    assert main(["registry", "components", "--check-lockfile", lock_path]) == 0


def test_lockfile_detects_changed_component(tmp_path):
    from safeai.cmd.cli import main

    proj = tmp_path / "proj"
    proj.mkdir()
    skill = proj / "helper.skill.yaml"
    skill.write_text("skill_type: helper\ntools: [read_file]\n", encoding="utf-8")
    _scan_to_shared_registry(str(proj), tmp_path)

    lock_path = str(tmp_path / "components.lock.json")
    assert main(["registry", "components", "--lockfile", lock_path]) == 0

    skill.write_text("skill_type: helper\ntools: [run_shell]\n", encoding="utf-8")
    _scan_to_shared_registry(str(proj), tmp_path)
    assert main(["registry", "components", "--check-lockfile", lock_path]) == 1


def test_check_lockfile_rejects_malformed_input():
    import pytest

    from safeai.kya.lockfile import check_lockfile

    with pytest.raises(TypeError):
        check_lockfile(None, {"nope": True})


def _project_ids(db_path):
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        return {
            r[1]: r[0]
            for r in conn.execute("SELECT project_id, name FROM projects")
        }
    finally:
        conn.close()


def test_lockfile_scopes_to_project(tmp_path, monkeypatch):
    import json

    from safeai.cmd.cli import main

    db_path = str(tmp_path / "registry.db")
    monkeypatch.setenv("SAFEAI_REGISTRY", db_path)
    for name, tool in (("projA", "read_file"), ("projB", "run_shell")):
        proj = tmp_path / name
        proj.mkdir()
        (proj / "agent.py").write_text("x = 1\n", encoding="utf-8")
        (proj / "helper.skill.yaml").write_text(
            f"skill_type: helper\ntools: [{tool}]\n", encoding="utf-8"
        )
        _scan_to_shared_registry(str(proj), tmp_path)

    by_name = _project_ids(db_path)
    pid_a = by_name["projA"]
    lock_a = str(tmp_path / "a.lock.json")
    assert main(["registry", "components", "--lockfile", lock_a, "--project", pid_a]) == 0
    with open(lock_a, encoding="utf-8") as fh:
        assert json.load(fh)["project_id"] == pid_a
    # Same relative path in the other project must not pollute A's pin.
    assert main(["registry", "components", "--check-lockfile", lock_a]) == 0

    (tmp_path / "projB" / "helper.skill.yaml").write_text(
        "skill_type: helper\ntools: [database_query]\n", encoding="utf-8"
    )
    _scan_to_shared_registry(str(tmp_path / "projB"), tmp_path)
    assert main(["registry", "components", "--check-lockfile", lock_a]) == 0
    assert main(["registry", "components", "--lockfile",
                 str(tmp_path / "b.lock.json")]) == 0
    assert main(["registry", "components", "--check-lockfile",
                 str(tmp_path / "b.lock.json")]) == 0


# --------------------------------------------------------------------------
# WS7: rule-authoring scaffold (init + rules check)
# --------------------------------------------------------------------------


def test_init_scaffolds_pack_authoring_files(tmp_path, monkeypatch):
    from safeai.cmd.cli import main

    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    rules_dir = tmp_path / ".safeai" / "rules"
    assert (rules_dir / "pack_example.yaml").is_file()
    assert (rules_dir / "fixtures" / "risky_example.py").is_file()
    assert (rules_dir / "fixtures" / "safe_example.py").is_file()
    assert (rules_dir / "tests" / "test_pack.py").is_file()


def test_rules_check_passes_on_scaffolded_pack(tmp_path, monkeypatch):
    from safeai.cmd.cli import main

    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    assert main(["rules", "check", str(tmp_path / ".safeai" / "rules")]) == 0


def test_rules_check_fails_on_broken_rule(tmp_path):
    from safeai.rules.pack_test import check_pack

    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "bad.yaml").write_text(
        "- description: missing id and severity\n", encoding="utf-8"
    )
    errors, _warnings = check_pack(str(pack))
    assert errors, "expected validation errors for a rule without id/severity"


def test_rules_check_warns_on_unknown_rule_id(tmp_path):
    from safeai.rules.pack_test import check_pack

    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "rules.yaml").write_text(
        "- id: CUSTOM_BRAND_NEW_ID\n"
        "  description: documents intent only\n"
        "  severity: low\n",
        encoding="utf-8",
    )
    (pack / "fixtures").mkdir()
    (pack / "fixtures" / "risky_a.py").write_text("x = 1\n", encoding="utf-8")
    errors, warnings = check_pack(str(pack))
    assert any("CUSTOM_BRAND_NEW_ID" in w for w in warnings)
    assert any("risky_a.py" in e for e in errors)
