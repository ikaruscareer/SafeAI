"""Deep Claude Code configuration analysis.

Fixtures under ``tests/fixtures/claude_code/`` model the configurations
that actually appear in real projects: a well-scoped baseline, a
permissive one, an injectable slash command, an over-privileged subagent,
and malformed settings.
"""

import builtins
import os

import pytest

from safeai.analysis.capability_diff import compute_capability_diff
from safeai.engine.scan import run_scan
from safeai.frameworks.claude_code import commands as cc_commands
from safeai.frameworks.claude_code import permissions as cc_permissions
from safeai.frameworks.claude_code import settings as cc_settings

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "claude_code")


def fixture(name):
    return os.path.join(FIXTURES, name)


def scan(name):
    return run_scan(fixture(name))


def rule_ids(report, prefix="CC_"):
    return {f["rule_id"] for f in report["findings"] if f["rule_id"].startswith(prefix)}


def findings_for(report, rule_id):
    return [f for f in report["findings"] if f["rule_id"] == rule_id]


def surface_keys(report):
    return [entry["tool_key"] for entry in report["tool_surface"]]


# --- baseline ------------------------------------------------------------


def test_minimal_project_raises_no_authority_findings():
    """A narrowly-scoped configuration must stay quiet."""
    report = scan("minimal")
    assert rule_ids(report) == set()


def test_minimal_project_still_extracts_named_tools():
    report = scan("minimal")
    assert "tool:read" in surface_keys(report)
    assert "tool:grep" in surface_keys(report)


def test_compatibility_fixture_detects_claude_code_project_surfaces():
    """Validate the common Claude Code project files in one deterministic fixture."""
    report = scan("compatibility")

    assert "claude_code" in report["detected_frameworks"]
    assert "mcp_server:docs" in surface_keys(report)
    assert "tool:read" in surface_keys(report)
    assert any(model["file"] == "CLAUDE.md" for model in report["agent_models"])
    assert any(f["rule_id"] == "MCP_ASSETS_DISCOVERED" for f in report["findings"])


# --- permissive ----------------------------------------------------------


def test_permissive_project_raises_expected_rules():
    report = scan("permissive")
    assert rule_ids(report) == {
        "CC_WILDCARD_PERMISSION",
        "CC_BYPASS_PERMISSIONS",
        "CC_FS_WRITE_OUTSIDE_ROOT",
        "CC_HOOK_SHELL_EXEC",
        "CC_MCP_UNCONSTRAINED",
    }


@pytest.mark.parametrize(
    "rule_id,severity",
    [
        ("CC_WILDCARD_PERMISSION", "high"),
        ("CC_BYPASS_PERMISSIONS", "critical"),
        ("CC_FS_WRITE_OUTSIDE_ROOT", "high"),
        ("CC_HOOK_SHELL_EXEC", "high"),
        ("CC_MCP_UNCONSTRAINED", "medium"),
    ],
)
def test_permissive_severities(rule_id, severity):
    report = scan("permissive")
    found = findings_for(report, rule_id)
    assert found, f"{rule_id} did not fire"
    assert any(f["severity"] == severity for f in found)


def test_wildcard_finding_names_the_offending_entry():
    report = scan("permissive")
    entries = {f["evidence"] for f in findings_for(report, "CC_WILDCARD_PERMISSION")}
    assert "Bash(*)" in entries
    assert "Write(*)" in entries


def test_a_deny_narrower_than_an_allow_is_not_reported():
    """The permissive fixture is CORRECT configuration, and used to be flagged.

    It carries allow ``Bash(*)`` and deny ``Bash(curl *)``. Claude Code
    evaluates deny first, so ``curl`` is denied and everything else is allowed
    — exactly what the two rules say. Neither is dead.

    The old ``CC_DENY_SHADOWED`` fired here at HIGH severity claiming the deny
    "cannot take effect", which is the opposite of the documented behaviour:

        "Rules are evaluated in order: deny, then ask, then allow. The first
         match in that order determines the outcome, and rule specificity
         doesn't change the order."
        -- https://code.claude.com/docs/en/permissions

    Asserting the absence, so re-introducing the false positive fails here.
    """
    report = scan("permissive")
    assert findings_for(report, "CC_DENY_SHADOWED") == []


def test_permissions_carry_tool_identity_and_access_mode():
    """Each grant must be attributable to a named tool at a known mode."""
    report = scan("permissive")
    by_key = {entry["tool_key"]: entry for entry in report["tool_surface"]}

    assert by_key["tool:bash"]["access_summary"] == "execute"
    assert by_key["tool:write"]["access_summary"] == "write"
    assert by_key["tool:read"]["access_summary"] == "read"

    shell = [c for c in by_key["tool:bash"]["capabilities"] if c["name"] == "shell"]
    assert shell and shell[0]["access_mode"] == "execute"


def test_hook_command_is_attributed_as_shell_execute():
    report = scan("permissive")
    by_key = {entry["tool_key"]: entry for entry in report["tool_surface"]}
    hook = by_key["tool:hook-pretooluse"]
    assert any(c["name"] == "shell" and c["access_mode"] == "execute" for c in hook["capabilities"])


def test_unnamed_mcp_config_is_not_reported_as_a_server():
    """Never invent a server name from a filename."""
    report = scan("permissive")
    assert "mcp_server:github" in surface_keys(report)
    assert not any(key.startswith("mcp_server:settings") for key in surface_keys(report))


# --- slash commands ------------------------------------------------------


def test_argument_interpolated_into_shell_is_critical():
    report = scan("slash_injection")
    found = findings_for(report, "CC_SLASH_COMMAND_ARG_INJECTION")
    assert found and found[0]["severity"] == "critical"
    assert found[0]["file"].endswith("commands/deploy.md")


def test_plain_shell_command_is_reported_but_not_critical():
    report = scan("slash_injection")
    status = [
        f for f in findings_for(report, "CC_SLASH_COMMAND_SHELL")
        if f["file"].endswith("commands/status.md")
    ]
    assert status and all(f["severity"] in {"medium", "low"} for f in status)


def test_file_reference_is_reported():
    report = scan("slash_injection")
    evidence = {f["evidence"] for f in findings_for(report, "CC_SLASH_COMMAND_SHELL")}
    assert "@docs/deploy-runbook.md" in evidence


def test_slash_command_argument_injection_triggers_the_combination_rule():
    """The documented end-to-end requirement for untrusted input + shell."""
    baseline = scan("minimal")
    current = scan("slash_injection")
    diff = compute_capability_diff(current, baseline)
    deploy = next(t for t in diff["tools"] if t["tool_key"] == "tool:command-deploy")
    assert "ESC_COMBO_UNTRUSTED_INPUT_SHELL" in {e["id"] for e in deploy["escalations"]}
    assert diff["highest_escalation"] == "critical"


def test_command_frontmatter_tools_are_attributed():
    report = scan("slash_injection")
    keys = surface_keys(report)
    assert "tool:command-deploy" in keys
    assert "tool:write" in keys  # granted via the command's allowed-tools


# --- subagents -----------------------------------------------------------


def test_subagent_with_broader_tools_is_flagged():
    report = scan("subagent_escalation")
    found = findings_for(report, "CC_SUBAGENT_PRIVILEGE_ESCALATION")
    assert found and found[0]["severity"] == "high"
    assert "Bash" in found[0]["evidence"] and "Write" in found[0]["evidence"]


def test_subagent_within_parent_scope_is_not_flagged():
    report = scan("minimal")
    assert findings_for(report, "CC_SUBAGENT_PRIVILEGE_ESCALATION") == []


# --- malformed input -----------------------------------------------------


def test_malformed_settings_degrade_to_a_finding():
    report = scan("malformed")
    found = findings_for(report, "CC_SETTINGS_UNPARSEABLE")
    assert found and found[0]["severity"] == "low"
    assert found[0]["file"] == ".claude/settings.json"


def test_lenient_parsing_accepts_comments_and_trailing_commas():
    report = scan("malformed")
    unparseable = {f["file"] for f in findings_for(report, "CC_SETTINGS_UNPARSEABLE")}
    assert ".claude/settings.local.json" not in unparseable
    assert "tool:bash" in surface_keys(report)


def test_malformed_finding_does_not_leak_source_text():
    report = scan("malformed")
    evidence = findings_for(report, "CC_SETTINGS_UNPARSEABLE")[0]["evidence"]
    assert evidence.startswith("parse error:")
    assert "Read(" not in evidence


# --- scope boundary ------------------------------------------------------


def test_analysis_reads_nothing_outside_the_scanned_root(monkeypatch):
    """User-level Claude configuration must never be opened."""
    opened = []
    real_open = builtins.open

    def tracking_open(file, *args, **kwargs):
        opened.append(str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", tracking_open)
    scan("permissive")

    root = os.path.abspath(fixture("permissive"))
    home = os.path.expanduser("~")
    for path in opened:
        absolute = os.path.abspath(path)
        if absolute.startswith(root):
            continue
        # Anything outside the fixture must not be Claude user configuration.
        assert ".claude" not in absolute.replace(root, ""), path
        assert not absolute.startswith(os.path.join(home, ".claude")), path


def test_source_modules_do_not_resolve_the_user_home():
    """A static guard against reintroducing multi-scope discovery.

    Comments and docstrings legitimately mention ``~/.claude`` to explain
    why it is out of scope, so only executable lines are inspected.
    """
    import inspect
    import io
    import tokenize

    forbidden = ("expanduser", "Path.home", "gethomedir", "HOME")
    for module in (cc_settings, cc_permissions, cc_commands):
        source = inspect.getsource(module)
        code = []
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            code.append(token.string)
        joined = "".join(code)
        for needle in forbidden:
            assert needle not in joined, f"{module.__name__} references {needle}"


# --- unit-level behaviour ------------------------------------------------


@pytest.mark.parametrize(
    "entry,tool,capability,mode",
    [
        ("Bash(*)", "Bash", "shell", "execute"),
        ("Write(src/**)", "Write", "filesystem", "write"),
        ("Read(README.md)", "Read", "filesystem", "read"),
        ("WebFetch(domain:example.com)", "WebFetch", "external_apis", "read"),
    ],
)
def test_entry_classification(entry, tool, capability, mode):
    record = cc_permissions.classify_entry(entry, "allow", ".claude/settings.json")
    assert record["tool"] == tool
    assert record["capability"] == capability
    assert record["access_mode"] == mode


def test_mcp_entry_is_scoped_to_its_server():
    record = cc_permissions.classify_entry(
        "mcp__github__create_issue", "allow", ".claude/settings.json"
    )
    assert record["mcp_server"] == "github"
    assert record["access_mode"] == "mutate"
    assert cc_permissions.classify_entry(
        "mcp__github__get_issue", "allow", ".claude/settings.json"
    )["access_mode"] == "read"


@pytest.mark.parametrize("value,expected", [
    ("bypassPermissions", "critical"),
    ("dangerously-skip-permissions", "critical"),
    ("acceptEdits", "medium"),
    ("default", None),
    ("plan", None),
])
def test_bypass_severity(value, expected):
    assert cc_permissions.bypass_severity(value) == expected


@pytest.mark.parametrize("broad,narrow,covered", [
    ("*", "rm -rf /", True),
    (None, "rm -rf /", True),
    ("git *", "git push", True),
    ("git push", "git push", True),
    ("git push", "rm -rf /", False),
])
def test_argument_coverage_is_conservative(broad, narrow, covered):
    assert cc_permissions.argument_covers(broad, narrow) is covered


def test_hook_extraction_ignores_scalar_metadata():
    """`"type": "command"` is metadata, not a hook command."""
    data = {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}}
    assert cc_settings.extract_hooks(data) == [("PreToolUse", "echo hi")]


def test_slash_command_parsing_is_deterministic():
    content = (
        "---\nallowed-tools: Bash(git push:*), Write\n---\n"
        "!`deploy.sh $ARGUMENTS`\n"
    )
    first = cc_commands.parse_command(".claude/commands/x.md", content)
    second = cc_commands.parse_command(".claude/commands/x.md", content)
    assert first == second
    assert first["allowed_tools"] == ["Bash(git push:*)", "Write"]
    assert first["arguments_in_shell"]


def test_scan_output_is_deterministic_for_claude_projects():
    import json

    first = json.dumps(scan("permissive")["tool_surface"], sort_keys=True)
    second = json.dumps(scan("permissive")["tool_surface"], sort_keys=True)
    assert first == second


def test_monorepo_claude_configs_do_not_overwrite_each_other(tmp_path):
    root = tmp_path / "mono"
    dangerous = root / "packages" / "aaa"
    benign = root / "packages" / "zzz"
    dangerous.mkdir(parents=True)
    benign.mkdir(parents=True)
    (dangerous / "agent.py").write_text("print('a')\n", encoding="utf-8")
    (benign / "agent.py").write_text("print('b')\n", encoding="utf-8")
    (dangerous / ".claude").mkdir()
    (benign / ".claude").mkdir()
    (dangerous / ".claude" / "settings.json").write_text(
        '{"permissions":{"allow":["Bash(*)"]},"permissionMode":"bypassPermissions"}',
        encoding="utf-8",
    )
    (benign / ".claude" / "settings.json").write_text(
        '{"permissions":{"allow":["Read(README.md)"]}}',
        encoding="utf-8",
    )

    report = run_scan(str(root))
    ids = {f["rule_id"] for f in report["findings"] if f["rule_id"].startswith("CC_")}
    assert "CC_BYPASS_PERMISSIONS" in ids
    assert "CC_WILDCARD_PERMISSION" in ids


# ---------------------------------------------------------------------------
# #93 - the documented evaluation order, pinned against the issue's premise
# ---------------------------------------------------------------------------
class TestDocumentedPermissionPrecedence:
    """Claude Code evaluates deny, then ask, then allow.

    Source: https://code.claude.com/docs/en/permissions

        "Rules are evaluated in order: deny, then ask, then allow. The first
         match in that order determines the outcome, and rule specificity
         doesn't change the order."

        "If a tool is denied at any level, no other level can allow it. [...]
         a user-level deny blocks a project-level allow, because deny rules
         from any scope are evaluated before allow rules."

    #93 proposed most-specific-match and last-match-wins. Neither exists. Two
    of its three worked examples expect an allow to win, which cannot happen,
    so they are inverted here with the citation attached.
    """

    @staticmethod
    def _rule(tool, argument, decision, path="settings.json"):
        return {
            "tool": tool, "argument": argument, "decision": decision,
            "path": path, "entry": f"{tool}({argument})", "line": 1,
        }

    def test_deny_beats_allow_regardless_of_scope(self):
        from safeai.frameworks.claude_code.permissions import resolve_effective_rules

        records = [
            self._rule("Bash", "*", "deny", "~/.claude/settings.json"),
            self._rule("Bash", "rm *", "allow", ".claude/settings.json"),
        ]
        assert resolve_effective_rules(records)["bash"]["decision"] == "deny"

    def test_deny_beats_allow_in_the_other_direction_too(self):
        """The issue's own first case, with the mechanism corrected: the deny
        wins because deny precedes allow, not because it is more specific."""
        from safeai.frameworks.claude_code.permissions import resolve_effective_rules

        records = [
            self._rule("Bash", "*", "allow", "~/.claude/settings.json"),
            self._rule("Bash", "rm *", "deny", ".claude/settings.json"),
        ]
        assert resolve_effective_rules(records)["bash"]["decision"] == "deny"

    def test_specificity_does_not_change_the_order(self):
        """A broad deny beats a narrow allow -- "a deny rule can't carry
        allowlist exceptions"."""
        from safeai.frameworks.claude_code.permissions import resolve_effective_rules

        records = [
            self._rule("Bash", "aws *", "deny"),
            self._rule("Bash", "aws s3 ls", "allow"),
        ]
        assert resolve_effective_rules(records)["bash"]["decision"] == "deny"

    def test_same_scope_is_not_last_match_wins(self):
        """#93 expected file order to decide. It does not: deny still wins
        whichever order the entries appear in."""
        from safeai.frameworks.claude_code.permissions import resolve_effective_rules

        deny_first = [self._rule("Bash", "*", "deny"), self._rule("Bash", "*", "allow")]
        allow_first = [self._rule("Bash", "*", "allow"), self._rule("Bash", "*", "deny")]
        assert resolve_effective_rules(deny_first)["bash"]["decision"] == "deny"
        assert resolve_effective_rules(allow_first)["bash"]["decision"] == "deny"

    def test_ask_sits_between_deny_and_allow(self):
        """The tier shadowed_denials never modelled."""
        from safeai.frameworks.claude_code.permissions import resolve_effective_rules

        records = [self._rule("Bash", "*", "ask"), self._rule("Bash", "*", "allow")]
        assert resolve_effective_rules(records)["bash"]["decision"] == "ask"

    def test_an_allow_covered_by_a_deny_is_dead_configuration(self):
        from safeai.frameworks.claude_code.permissions import ineffective_allows

        records = [
            self._rule("Bash", "*", "deny"),
            self._rule("Bash", "rm *", "allow"),
        ]
        pairs = ineffective_allows(records)
        assert [(a["entry"], d["entry"]) for a, d in pairs] == [("Bash(rm *)", "Bash(*)")]

    def test_a_narrower_deny_does_not_kill_a_broader_allow(self):
        """The control. Without it, a pass that called every allow dead
        whenever any deny existed would satisfy the test above."""
        from safeai.frameworks.claude_code.permissions import ineffective_allows

        records = [
            self._rule("Bash", "*", "allow"),
            self._rule("Bash", "curl *", "deny"),
        ]
        assert ineffective_allows(records) == []

    def test_other_tools_are_unaffected(self):
        from safeai.frameworks.claude_code.permissions import resolve_effective_rules

        records = [
            self._rule("Bash", "*", "deny"),
            self._rule("Read", "src/**", "allow"),
        ]
        effective = resolve_effective_rules(records)
        assert effective["bash"]["decision"] == "deny"
        assert effective["read"]["decision"] == "allow"
