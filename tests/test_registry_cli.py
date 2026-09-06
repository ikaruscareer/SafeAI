"""Tests for `safeai registry` CLI commands and export."""

import json
import os

from safeai.cmd.cli import main


def _two_scans(kya_project, tmp_path):
    main([
        "scan",
        kya_project["root"],
        "--registry",
        kya_project["registry"],
        "--sarif",
        os.path.join(tmp_path, "r.sarif"),
    ])
    kya_project["write_version"](kya_project["v2"])
    main([
        "scan",
        kya_project["root"],
        "--registry",
        kya_project["registry"],
        "--sarif",
        os.path.join(tmp_path, "r.sarif"),
    ])


def _agent_id(registry_path):
    from safeai.kya.registry import connect, list_agents
    conn = connect(registry_path)
    try:
        return list_agents(conn)[0]["agent_id"]
    finally:
        conn.close()


def test_registry_list_table_and_json(kya_project, tmp_path, capsys):
    _two_scans(kya_project, tmp_path)
    reg = kya_project["registry"]

    assert main(["registry", "list", "--registry", reg]) == 0
    out = capsys.readouterr().out
    assert "AGENT ID" in out and "langgraph" in out

    assert main(["registry", "list", "--registry", reg, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["agents"]
    assert "disclaimer" in payload


def test_registry_show(kya_project, tmp_path, capsys):
    _two_scans(kya_project, tmp_path)
    reg = kya_project["registry"]
    agent_id = _agent_id(reg)

    assert main(["registry", "show", agent_id, "--registry", reg]) == 0
    out = capsys.readouterr().out
    assert "Capabilities" in out
    assert "static analysis evidence" in out

    assert main(["registry", "show", agent_id, "--registry", reg, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["agent_id"] == agent_id
    assert payload["snapshot"]["source_locations"]

    assert main(["registry", "show", "nonexistent", "--registry", reg]) == 2


def test_registry_history(kya_project, tmp_path, capsys):
    _two_scans(kya_project, tmp_path)
    reg = kya_project["registry"]
    agent_id = _agent_id(reg)
    capsys.readouterr()  # discard scan output before capturing JSON

    assert main(["registry", "history", agent_id, "--registry", reg, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["history"]) == 2
    assert payload["history"][0]["scan_id"]


def test_registry_diff(kya_project, tmp_path, capsys):
    _two_scans(kya_project, tmp_path)
    reg = kya_project["registry"]
    agent_id = _agent_id(reg)
    capsys.readouterr()  # discard scan output before capturing JSON

    rc = main(["registry", "diff", agent_id, "--from", "previous", "--to", "latest",
               "--registry", reg, "--format", "json"])
    assert rc == 1  # documented: 1 when risk-relevant changes exist
    payload = json.loads(capsys.readouterr().out)
    assert payload["from_scan"] != payload["to_scan"]
    assert "capabilities" in payload and "findings" in payload


def test_registry_diff_identical(kya_project, tmp_path):
    main(["scan", kya_project["root"], "--registry", kya_project["registry"],
          "--sarif", os.path.join(tmp_path, "r.sarif")])
    main(["scan", kya_project["root"], "--registry", kya_project["registry"],
          "--sarif", os.path.join(tmp_path, "r.sarif")])
    reg = kya_project["registry"]
    agent_id = _agent_id(reg)
    rc = main(["registry", "diff", agent_id, "--from", "previous", "--to", "latest", "--registry", reg])
    assert rc == 0  # no changes


def test_registry_export(kya_project, tmp_path):
    _two_scans(kya_project, tmp_path)
    reg = kya_project["registry"]
    out_path = os.path.join(str(tmp_path), "inventory.json")

    rc = main(["registry", "export", "--registry", reg, "--format", "json",
               "--output", out_path, "--include-history"])
    assert rc == 0
    with open(out_path) as fh:
        document = json.load(fh)
    assert document["export_type"] == "safeai.kya.inventory"
    assert document["schema_version"] == "1.1"
    project = document["projects"][0]
    assert project["agents"]
    assert project["agents"][0]["history"]
    assert project["latest_findings"]
    assert "limitations" in document
    assert "component_snapshots" in project
    assert "tool_snapshots" in project
    assert "finding_lifecycle" in project

    with open(out_path, encoding="utf-8") as fh:
        raw = fh.read()
    assert "sk-1234567890abcdefghij" not in raw


def test_registry_import_is_complete_and_idempotent(kya_project, tmp_path, capsys):
    _two_scans(kya_project, tmp_path)
    source = kya_project["registry"]
    agent_id = _agent_id(source)

    from safeai.kya.registry import connect, latest_scan_id, set_agent_metadata

    conn = connect(source)
    try:
        set_agent_metadata(
            conn,
            agent_id,
            owner="source-team",
            environment="production",
            purpose="risk review",
        )
        scan_id = latest_scan_id(conn)
        conn.execute(
            "INSERT INTO component_snapshots(scan_id, component_type, name, file_path, "
            "data_json, first_seen_scan, last_seen_scan, content_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                "prompt",
                "system-prompt",
                "prompts/system.txt",
                json.dumps({"type": "prompt", "name": "system-prompt", "path": "prompts/system.txt"}),
                scan_id,
                scan_id,
                "component-hash",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    inventory = os.path.join(str(tmp_path), "portable.json")
    assert main([
        "registry", "export", "--registry", source, "--output", inventory,
        "--include-history",
    ]) == 0
    capsys.readouterr()

    target = os.path.join(str(tmp_path), "imported", "registry.db")
    assert main(["registry", "import", inventory, "--registry", target]) == 0
    first_output = capsys.readouterr().out
    assert "Imported inventory" in first_output

    conn = connect(target)
    try:
        first_counts = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "projects", "scans", "agents", "agent_snapshots", "findings",
                "scan_findings", "component_snapshots", "finding_lifecycle",
                "agent_tool_snapshots", "agent_metadata",
            )
        }
        metadata = conn.execute(
            "SELECT owner, environment, purpose FROM agent_metadata WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        assert tuple(metadata) == ("source-team", "production", "risk review")
        assert first_counts["scans"] == 1
        assert first_counts["agents"] >= 1
        assert first_counts["findings"] >= 1
        assert first_counts["component_snapshots"] >= 1
        assert first_counts["finding_lifecycle"] >= 1
        assert first_counts["agent_tool_snapshots"] >= 1
    finally:
        conn.close()

    assert main(["registry", "import", inventory, "--registry", target]) == 0
    capsys.readouterr()
    conn = connect(target)
    try:
        second_counts = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in first_counts
        }
    finally:
        conn.close()
    assert second_counts == first_counts


def test_registry_import_metadata_merge_dry_run_and_force(kya_project, tmp_path, capsys):
    main([
        "scan", kya_project["root"], "--registry", kya_project["registry"],
        "--sarif", os.path.join(tmp_path, "r.sarif"),
    ])
    source = kya_project["registry"]
    agent_id = _agent_id(source)
    from safeai.kya.registry import connect, set_agent_metadata

    conn = connect(source)
    try:
        set_agent_metadata(conn, agent_id, owner="source", environment="production")
        conn.commit()
    finally:
        conn.close()
    inventory = os.path.join(str(tmp_path), "portable.json")
    main(["registry", "export", "--registry", source, "--output", inventory])
    capsys.readouterr()

    absent = os.path.join(str(tmp_path), "dry-run", "registry.db")
    assert main(["registry", "import", inventory, "--registry", absent, "--dry-run"]) == 0
    assert "Would import inventory" in capsys.readouterr().out
    assert not os.path.exists(absent)

    target = os.path.join(str(tmp_path), "target", "registry.db")
    main(["registry", "import", inventory, "--registry", target])
    capsys.readouterr()
    conn = connect(target)
    try:
        conn.execute(
            "UPDATE agent_metadata SET owner = ?, environment = ? WHERE agent_id = ?",
            ("local", "staging", agent_id),
        )
        conn.commit()
    finally:
        conn.close()

    main(["registry", "import", inventory, "--registry", target])
    capsys.readouterr()
    conn = connect(target)
    try:
        row = conn.execute(
            "SELECT owner, environment FROM agent_metadata WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        assert tuple(row) == ("local", "staging")
    finally:
        conn.close()

    main(["registry", "import", inventory, "--registry", target, "--force"])
    capsys.readouterr()
    conn = connect(target)
    try:
        row = conn.execute(
            "SELECT owner, environment FROM agent_metadata WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        assert tuple(row) == ("source", "production")
    finally:
        conn.close()


def test_registry_import_rejects_corrupt_and_invalid_json(tmp_path, capsys):
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    target = tmp_path / "registry.db"
    assert main(["registry", "import", str(corrupt), "--registry", str(target)]) == 2
    assert "Unable to read inventory" in capsys.readouterr().err
    assert not target.exists()

    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps({"schema_version": "1.1", "projects": []}), encoding="utf-8")
    assert main(["registry", "import", str(invalid), "--registry", str(target)]) == 2
    assert "export_type" in capsys.readouterr().err
    assert not target.exists()


def test_registry_import_rejects_oversized_inventory(tmp_path, capsys):
    oversized = tmp_path / "huge.json"
    # Create a JSON file exceeding the 10MB limit
    huge_payload = {"data": "x" * (11 * 1024 * 1024)}
    oversized.write_text(json.dumps(huge_payload), encoding="utf-8")
    target = tmp_path / "registry.db"
    assert main(["registry", "import", str(oversized), "--registry", str(target)]) == 2
    assert "exceeds 10MB limit" in capsys.readouterr().err
    assert not target.exists()


def test_registry_import_backup_flag(kya_project, tmp_path, capsys):
    from pathlib import Path

    main([
        "scan", kya_project["root"], "--registry", kya_project["registry"],
        "--sarif", os.path.join(tmp_path, "r.sarif"),
    ])
    source = kya_project["registry"]
    agent_id = _agent_id(source)
    from safeai.kya.registry import connect, set_agent_metadata

    conn = connect(source)
    try:
        set_agent_metadata(conn, agent_id, owner="original", environment="staging")
        conn.commit()
    finally:
        conn.close()

    inventory = os.path.join(str(tmp_path), "portable.json")
    main(["registry", "export", "--registry", source, "--output", inventory])
    capsys.readouterr()

    target = os.path.join(str(tmp_path), "target", "registry.db")
    main(["registry", "import", inventory, "--registry", target])
    capsys.readouterr()

    # Overwrite metadata locally
    conn = connect(target)
    try:
        conn.execute(
            "UPDATE agent_metadata SET owner = ?, environment = ? WHERE agent_id = ?",
            ("local-owner", "production", agent_id),
        )
        conn.commit()
    finally:
        conn.close()

    # Import with --force and --backup
    main(["registry", "import", inventory, "--registry", target, "--force", "--backup"])
    output = capsys.readouterr().out
    assert "Backup saved to" in output
    backup_path = Path(target + ".bak")
    assert backup_path.exists()

    # Verify backup contains the pre-import state
    import sqlite3
    backup_conn = sqlite3.connect(str(backup_path))
    backup_conn.row_factory = sqlite3.Row
    try:
        row = backup_conn.execute(
            "SELECT owner, environment FROM agent_metadata WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        assert tuple(row) == ("local-owner", "production")
    finally:
        backup_conn.close()

    # Verify target has the imported values
    conn = connect(target)
    try:
        row = conn.execute(
            "SELECT owner, environment FROM agent_metadata WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        assert tuple(row) == ("original", "staging")
    finally:
        conn.close()


def test_registry_export_excludes_suppressed_by_default(kya_project, tmp_path):
    main(["scan", kya_project["root"], "--registry", kya_project["registry"],
          "--sarif", os.path.join(tmp_path, "r.sarif")])
    reg = kya_project["registry"]

    from safeai.kya.registry import connect, get_scan_findings, latest_scan_id
    conn = connect(reg)
    findings = get_scan_findings(conn, latest_scan_id(conn))
    carrying = {"ENV_DEP_INVENTORY", "MCP_ASSETS_DISCOVERED"}
    fp = next(
        f["fingerprint"]
        for f in findings
        if f.get("rule_id") not in carrying
    )
    conn.close()

    safeai_dir = os.path.join(kya_project["root"], ".safeai")
    with open(os.path.join(safeai_dir, "suppressions.yml"), "w") as fh:
        fh.write(f"""
suppressions:
  - fingerprint: "{fp}"
    reason: "test suppression"
    owner: "team"
    created: "2026-01-01"
""")
    main(["scan", kya_project["root"], "--registry", kya_project["registry"],
          "--sarif", os.path.join(tmp_path, "r.sarif")])

    out_default = os.path.join(str(tmp_path), "inv_default.json")
    out_with = os.path.join(str(tmp_path), "inv_with.json")
    main(["registry", "export", "--registry", reg, "--format", "json", "--output", out_default])
    main(["registry", "export", "--registry", reg, "--format", "json", "--output", out_with,
          "--include-suppressed"])

    with open(out_default) as fh:
        default_doc = json.load(fh)
    with open(out_with) as fh:
        with_doc = json.load(fh)
    default_fps = {f["fingerprint"] for f in default_doc["projects"][0]["latest_findings"]}
    with_fps = {f["fingerprint"] for f in with_doc["projects"][0]["latest_findings"]}
    assert fp not in default_fps
    assert fp in with_fps


def test_registry_missing_error(kya_project, tmp_path, capsys):
    missing = os.path.join(str(tmp_path), "nope", "registry.db")
    rc = main(["registry", "list", "--registry", missing])
    err = capsys.readouterr().err
    assert rc == 2
    assert "Registry not found" in err
    assert "--project-dir" in err


def test_registry_commands_accept_project_dir(kya_project, tmp_path, capsys):
    """registry list can find the registry a scan wrote into a project root
    without cd'ing there: --project-dir derives the same path scan used."""
    main(["scan", kya_project["root"], "--registry", kya_project["registry"],
          "--sarif", os.path.join(tmp_path, "r.sarif")])
    capsys.readouterr()  # discard scan output

    rc = main(["registry", "list", "--project-dir", kya_project["root"], "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["agents"]


def test_registry_list_html(kya_project, tmp_path, capsys):
    main(["scan", kya_project["root"], "--registry", kya_project["registry"],
          "--sarif", os.path.join(tmp_path, "r.sarif")])
    capsys.readouterr()
    rc = main(["registry", "list", "--registry", kya_project["registry"], "--format", "html"])
    assert rc == 0
    html = capsys.readouterr().out
    assert "<!doctype html>" in html.lower()
    assert "Registry Inventory" in html
    assert "data-theme=" in html


def test_registry_export_html(kya_project, tmp_path, capsys):
    main(["scan", kya_project["root"], "--registry", kya_project["registry"],
          "--sarif", os.path.join(tmp_path, "r.sarif")])
    capsys.readouterr()
    out_html = os.path.join(str(tmp_path), "inventory.html")
    rc = main(["registry", "export", "--registry", kya_project["registry"],
               "--format", "html", "--output", out_html])
    assert rc == 0
    with open(out_html, encoding="utf-8") as fh:
        content = fh.read()
    assert "Inventory Export" in content
    assert "data-theme=" in content


def test_registry_diff_html_exit_contract(kya_project, tmp_path, capsys):
    """HTML diff output must still honor the documented exit-code contract."""
    _two_scans(kya_project, tmp_path)
    reg = kya_project["registry"]
    agent_id = _agent_id(reg)
    capsys.readouterr()
    rc = main(["registry", "diff", agent_id, "--from", "previous", "--to", "latest",
               "--registry", reg, "--format", "html"])
    assert rc == 1  # risk-relevant changes exist
    assert "Agent Diff" in capsys.readouterr().out


def test_resolve_registry_arg_precedence(kya_project):
    from safeai.cmd.registry_cli import resolve_registry_arg

    explicit = type("Args", (), {"registry": "custom.db", "project_dir": kya_project["root"]})()
    assert resolve_registry_arg(explicit) == "custom.db"

    by_project = type("Args", (), {"registry": None, "project_dir": kya_project["root"]})()
    assert resolve_registry_arg(by_project) == kya_project["registry"]

    no_flags = type("Args", (), {"registry": None, "project_dir": None})()
    assert resolve_registry_arg(no_flags) == os.environ["SAFEAI_REGISTRY"]


def test_scan_and_list_share_one_registry(kya_project, tmp_path, monkeypatch, capsys):
    """Scans accumulate in one shared DB; registry list sees them from any cwd."""
    shared = os.path.join(str(tmp_path), "shared", "registry.db")
    monkeypatch.setenv("SAFEAI_REGISTRY", shared)
    monkeypatch.delenv("CI", raising=False)

    main(["scan", kya_project["root"], "--sarif", os.path.join(tmp_path, "r.sarif")])
    capsys.readouterr()
    assert os.path.exists(shared)

    rc = main(["registry", "list", "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["agents"]


def test_registry_diff_is_agent_scoped(tmp_path, capsys):
    root = tmp_path / "multi"
    root.mkdir()
    (root / "agent_a.py").write_text(
        "from langgraph.graph import StateGraph\n"
        "import subprocess\n"
        "\n"
        "def run_a(user_input):\n"
        "    graph = StateGraph(dict)\n"
        "    subprocess.run(user_input, shell=True)\n"
        "    return graph\n",
        encoding="utf-8",
    )
    (root / "agent_b.py").write_text(
        "from langgraph.graph import StateGraph\n"
        "\n"
        "def run_b(user_input):\n"
        "    graph = StateGraph(dict)\n"
        "    return graph\n",
        encoding="utf-8",
    )

    sarif = os.path.join(tmp_path, "r.sarif")
    reg = os.path.join(str(root), ".safeai", "registry.db")
    main(["scan", str(root), "--registry", reg, "--sarif", sarif])

    # Change only agent_a file between scans.
    (root / "agent_a.py").write_text(
        "from langgraph.graph import StateGraph\n"
        "import subprocess\n"
        "import requests\n"
        "\n"
        "def run_a(user_input):\n"
        "    graph = StateGraph(dict)\n"
        "    subprocess.run(user_input, shell=True)\n"
        '    requests.get("https://example.com")\n'
        "    return graph\n",
        encoding="utf-8",
    )
    main(["scan", str(root), "--registry", reg, "--sarif", sarif])

    capsys.readouterr()
    main(["registry", "list", "--registry", reg, "--format", "json"])
    listing = json.loads(capsys.readouterr().out)

    # Resolve the agent tied to agent_b.py.
    agent_a = next(a for a in listing["agents"] if a.get("primary_path") == "agent_a.py")
    agent_b = next(a for a in listing["agents"] if a.get("primary_path") == "agent_b.py")

    # Risk in registry list must be agent-scoped, not project-wide.
    assert agent_a["risk_score"] is not None
    assert agent_b["risk_score"] is not None
    assert agent_a["risk_score"] > agent_b["risk_score"]

    capsys.readouterr()
    rc = main([
        "registry",
        "diff",
        agent_b["agent_id"],
        "--from",
        "previous",
        "--to",
        "latest",
        "--registry",
        reg,
        "--format",
        "json",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["findings"]["new"] == []
    assert payload["findings"]["resolved"] == []
