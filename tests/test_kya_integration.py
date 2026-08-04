"""Integration fixtures for the KYA pipeline:

  * MCP configuration fixture
  * Intentionally vulnerable prompt/tool combination fixture
  * Secret fixture verifying redaction end-to-end
  * Capability-change fixture across two versions
  * CI-environment registry behavior
"""

import json
import os

from safeai.cmd.cli import main


def test_mcp_config_fixture_scanned(tmp_path):
    root = tmp_path / "mcp_proj"
    root.mkdir()
    (root / "mcp.json").write_text(json.dumps({
        "mcpServers": {
            "remote-fs": {
                "transport": "http",
                "url": "https://mcp.example.com/sse",
            }
        }
    }), encoding="utf-8")

    manifest_path = os.path.join(str(root), "safeai-manifest.json")
    rc = main(["scan", str(root), "--manifest", manifest_path,
               "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    assert rc in (0, 1)
    with open(manifest_path) as fh:
        manifest = json.load(fh)
    assert manifest["scan"]["files_scanned"] >= 1
    # Findings remain well-formed regardless of MCP detection depth.
    for finding in manifest["findings"]:
        assert finding["fingerprint"]
        assert finding["confidence"] in {"high", "medium", "low"}


def test_vulnerable_prompt_tool_fixture(tmp_path):
    root = tmp_path / "vuln"
    root.mkdir()
    (root / "agent.py").write_text(
        "from crewai import Agent\n"
        "import subprocess\n"
        "\n"
        "def handle(user_input):\n"
        '    prompt = "You are an assistant. User says: " + user_input\n'
        "    subprocess.run(user_input, shell=True)\n"
        "    return prompt\n",
        encoding="utf-8",
    )
    json_path = os.path.join(str(tmp_path), "report.json")
    rc = main(["scan", str(root), "--json", json_path,
               "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    assert rc == 1  # critical finding present
    with open(json_path) as fh:
        report = json.load(fh)
    rules = {f["rule_id"] for f in report["findings"]}
    assert "CAP_subprocess_shell" in rules


def test_secret_redaction_end_to_end(tmp_path):
    root = tmp_path / "secrets"
    root.mkdir()
    (root / "config.py").write_text(
        'API_KEY = "sk-abcdef0123456789abcdef"\n'
        'TOKEN = "ghp_0123456789abcdefghijkl"\n',
        encoding="utf-8",
    )
    manifest_path = os.path.join(str(root), "safeai-manifest.json")
    sarif_path = os.path.join(str(tmp_path), "out.sarif")
    registry_path = os.path.join(str(root), ".safeai", "registry.db")
    main([
        "scan",
        str(root),
        "--manifest",
        manifest_path,
        "--registry",
        registry_path,
        "--sarif",
        sarif_path,
    ])

    with open(manifest_path, encoding="utf-8") as fh:
        manifest_raw = fh.read()
    with open(sarif_path, encoding="utf-8") as fh:
        sarif_raw = fh.read()
    for secret in ("sk-abcdef0123456789abcdef", "ghp_0123456789abcdefghijkl"):
        assert secret not in manifest_raw
        assert secret not in sarif_raw

    # Registry storage must also be secret-free.
    db_path = os.path.join(str(root), ".safeai", "registry.db")
    with open(db_path, "rb") as fh:
        raw_db = fh.read()
    for secret in (b"sk-abcdef0123456789abcdef", b"ghp_0123456789abcdefghijkl"):
        assert secret not in raw_db


def test_capability_change_across_versions(kya_project, tmp_path):
    """v1 -> v2 introduces HTTP capability findings; registry diff surfaces changes."""
    reg = kya_project["registry"]
    main(["scan", kya_project["root"], "--registry", reg,
          "--sarif", os.path.join(tmp_path, "r.sarif")])
    kya_project["write_version"](kya_project["v2"])
    main(["scan", kya_project["root"], "--registry", reg,
          "--sarif", os.path.join(tmp_path, "r.sarif")])

    from safeai.kya.registry import connect, list_agents
    conn = connect(reg)
    try:
        agent_id = list_agents(conn)[0]["agent_id"]
    finally:
        conn.close()

    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(["registry", "diff", agent_id, "--from", "previous", "--to", "latest",
                   "--registry", reg, "--format", "json"])
    diff = json.loads(buf.getvalue())
    assert rc == 1
    new_rules = {f["rule_id"] for f in diff["findings"]["new"]}
    assert "CAP_http" in new_rules


def test_ci_env_disables_registry_by_default(kya_project, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CI", "true")
    monkeypatch.delenv("SAFEAI_REGISTRY", raising=False)
    rc = main(["scan", kya_project["root"],
               "--sarif", os.path.join(tmp_path, "r.sarif")])
    assert rc in (0, 1)
    assert not os.path.exists(kya_project["registry"])

    # Explicit --registry overrides CI auto-disable.
    custom = os.path.join(str(tmp_path), "ci-registry.db")
    main(["scan", kya_project["root"], "--registry", custom,
          "--sarif", os.path.join(tmp_path, "r.sarif")])
    assert os.path.exists(custom)


def test_safeai_registry_env_enables_ci_persistence(kya_project, tmp_path, monkeypatch):
    """An explicitly configured shared registry persists even in CI."""
    shared = os.path.join(str(tmp_path), "shared", "registry.db")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("SAFEAI_REGISTRY", shared)
    rc = main(["scan", kya_project["root"],
               "--sarif", os.path.join(tmp_path, "r.sarif")])
    assert rc in (0, 1)
    assert os.path.exists(shared)


def test_scan_succeeds_and_reports_even_without_registry(tmp_path):
    root = tmp_path / "plain"
    root.mkdir()
    (root / "a.py").write_text("import subprocess\nsubprocess.call('ls')\n", encoding="utf-8")
    json_path = os.path.join(str(tmp_path), "r.json")
    rc = main(["scan", str(root), "--json", json_path,
               "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    assert rc in (0, 1)
    with open(json_path) as fh:
        report = json.load(fh)
    assert report["findings"]
    assert report["findings"][0]["fingerprint"]
