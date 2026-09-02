"""Deep analysis of Claude Code project configuration.

Claude Code keeps real agent authority in ``.claude/settings.json``,
``.claude/commands/``, ``.claude/agents/``, hooks, and ``.mcp.json``.
Conventional SAST does not look at any of them. This analyzer does.

Scope boundary (v1.4): only configuration **inside the scanned
repository** is examined. This module never calls ``open``; it reads the
scan's file cache, which contains repository files only. User-level
configuration (``~/.claude/``, ``~/.claude.json``) is deliberately out of
scope — reading it would leak a developer's personal environment into a
CI artifact. Multi-scope discovery is deferred to a later release.
"""

from safeai.analyzers.prompt.analyzer import analyze_prompt_text
from safeai.frameworks.claude_code import commands as cc_commands
from safeai.frameworks.claude_code import permissions as cc_permissions
from safeai.frameworks.claude_code import settings as cc_settings

_REMEDIATION = {
    "CC_WILDCARD_PERMISSION": "Replace the wildcard grant with the narrowest "
                              "command or path pattern the workflow needs.",
    "CC_BYPASS_PERMISSIONS": "Remove the bypass/auto-approve setting and keep the "
                             "human approval gate enabled in committed settings.",
    "CC_DENY_SHADOWED": "Remove the allow entry that cannot apply, or narrow the "
                        "deny entry if the allow was the intended behaviour. The "
                        "deny is what takes effect.",
    "CC_FS_WRITE_OUTSIDE_ROOT": "Constrain write grants to paths inside the project root.",
    "CC_SLASH_COMMAND_SHELL": "Pin the command, avoid inline shell in stored "
                              "instructions, and review who can invoke it.",
    "CC_SLASH_COMMAND_ARG_INJECTION": "Never interpolate $ARGUMENTS into a shell "
                                      "invocation; validate and quote caller input.",
    "CC_SUBAGENT_PRIVILEGE_ESCALATION": "Grant the subagent no more tools than its "
                                        "parent scope allows.",
    "CC_HOOK_SHELL_EXEC": "Pin hook commands to a vendored script at a known "
                          "revision instead of fetching remote content.",
    "CC_MCP_UNCONSTRAINED": "Add explicit mcp__<server>__<tool> permission entries "
                            "so the server's authority is bounded.",
    "CC_SETTINGS_UNPARSEABLE": "Fix the configuration syntax so the file can be "
                               "reviewed and enforced.",
}

_OWASP = {
    "CC_WILDCARD_PERMISSION": "LLM06",
    "CC_BYPASS_PERMISSIONS": "LLM06",
    "CC_DENY_SHADOWED": "LLM06",
    "CC_FS_WRITE_OUTSIDE_ROOT": "LLM06",
    "CC_SLASH_COMMAND_SHELL": "LLM01",
    "CC_SLASH_COMMAND_ARG_INJECTION": "LLM01",
    "CC_SUBAGENT_PRIVILEGE_ESCALATION": "LLM08",
    "CC_HOOK_SHELL_EXEC": "LLM05",
    "CC_MCP_UNCONSTRAINED": "LLM06",
    "CC_SETTINGS_UNPARSEABLE": "LLM09",
}

_DEFAULT_SEVERITY = {
    "CC_WILDCARD_PERMISSION": "high",
    "CC_BYPASS_PERMISSIONS": "critical",
    "CC_DENY_SHADOWED": "high",
    "CC_FS_WRITE_OUTSIDE_ROOT": "high",
    "CC_SLASH_COMMAND_SHELL": "medium",
    "CC_SLASH_COMMAND_ARG_INJECTION": "critical",
    "CC_SUBAGENT_PRIVILEGE_ESCALATION": "high",
    "CC_HOOK_SHELL_EXEC": "high",
    "CC_MCP_UNCONSTRAINED": "medium",
    "CC_SETTINGS_UNPARSEABLE": "low",
}

_SCORE = {
    "critical": 22,
    "high": 15,
    "medium": 8,
    "low": 3,
}


def relative_path(path):
    """Repository-relative path, derived without knowing the scan root.

    Paths are only ever used for provenance, so a stable relative form is
    all that is needed — and it keeps absolute developer paths out of
    exported artifacts.
    """
    normalized = str(path).replace("\\", "/")
    marker = "/.claude/"
    if marker in normalized:
        return ".claude/" + normalized.split(marker, 1)[1]
    if normalized.endswith("/.claude.json"):
        return ".claude.json"
    basename = normalized.rsplit("/", 1)[-1]
    if basename in {".mcp.json", "CLAUDE.md"}:
        return basename
    return normalized


def _finding(rule_id, rule_map, message, path, line, evidence, reason, severity=None,
             capability="Permissions"):
    rule = rule_map.get(rule_id, {})
    resolved = severity or rule.get("severity") or _DEFAULT_SEVERITY.get(rule_id, "medium")
    return {
        "rule_id": rule_id,
        "evidence_type": "static-config",  # #94 - reads declared permission/hook/settings entries
        "severity": resolved,
        "message": message,
        "file": path,
        "line": line,
        "owasp_llm": rule.get("owasp_llm", _OWASP.get(rule_id, "LLM06")),
        "evidence": evidence,
        "reason": reason,
        "risk_category": "Capability",
        "affected_framework": "claude_code",
        "affected_capability": capability,
        "score_contribution": _SCORE.get(resolved, 8),
        "remediation": _REMEDIATION.get(rule_id, "Apply least privilege to the agent's configuration."),
        "confidence": 0.85,
    }


class ClaudeCodeAnalyzer:
    """Emit authority findings for Claude Code project configuration."""

    name = "claude_code"

    def run(self, file_cache, rules, agent_models=None, components=None):
        rule_map = {r.get("id"): r for r in (rules or [])}
        files = [
            {
                "abs_path": str(path).replace("\\", "/"),
                "rel_path": relative_path(path),
                "content": content,
            }
            for path, content in sorted(file_cache.items())
        ]
        claude_files = [
            entry
            for entry in files
            if cc_settings.is_claude_config(entry["rel_path"]) or entry["rel_path"] == "CLAUDE.md"
        ]
        if not claude_files:
            return []

        findings = []
        records = []

        settings_docs, findings_from_parse = self._parse_settings(claude_files, rule_map)
        findings.extend(findings_from_parse)

        for doc in settings_docs:
            records.extend(self._records_for(doc))

        findings.extend(self._permission_findings(records, rule_map))
        findings.extend(self._mcp_findings(settings_docs, records, rule_map))
        findings.extend(self._hook_findings(settings_docs, claude_files, rule_map))
        findings.extend(self._command_findings(claude_files, rule_map))
        findings.extend(self._subagent_findings(claude_files, records, rule_map))

        findings.sort(key=lambda f: (f["file"], f["rule_id"], f["line"]))
        return findings

    # --- settings -------------------------------------------------------

    def _parse_settings(self, claude_files, rule_map):
        documents = []
        findings = []
        ordered = sorted(
            (entry for entry in claude_files if entry["rel_path"].endswith(".json")),
            key=lambda entry: (
                cc_settings.SETTINGS_PRECEDENCE.index(entry["rel_path"])
                if entry["rel_path"] in cc_settings.SETTINGS_PRECEDENCE else 99,
                entry["rel_path"],
                entry["abs_path"],
            ),
        )
        for entry in ordered:
            rel = entry["rel_path"]
            path = entry["abs_path"]
            content = entry["content"]
            data, error = cc_settings.loads_lenient(content)
            if error is not None:
                findings.append(_finding(
                    "CC_SETTINGS_UNPARSEABLE", rule_map,
                    f"Claude Code configuration could not be parsed: {rel}",
                    path, 1,
                    evidence=f"parse error: {error}",
                    reason="Unparseable configuration cannot be reviewed or enforced, "
                           "and its declared permissions are unknown to this scan.",
                    capability="Configuration",
                ))
                continue
            documents.append({
                "path": path,
                "content": content,
                "data": data if isinstance(data, dict) else {},
                "kind": "mcp" if rel == cc_settings.MCP_CONFIG else "settings",
            })
        return documents, findings

    def _records_for(self, doc):
        records = []
        for decision, entry in cc_settings.extract_permission_entries(doc["data"]):
            line = cc_settings.line_of(doc["content"], entry)
            records.append(cc_permissions.classify_entry(entry, decision, doc["path"], line))
        return records

    # --- permissions ----------------------------------------------------

    def _permission_findings(self, records, rule_map):
        findings = []
        effective = cc_permissions.resolve_effective_rules(records)
        for record in records:
            if record["decision"] == "allow" and record["wildcard"] and record["tool"]:
                # #93 - a wildcard allow grants nothing the tool's denies do not
                # already take back, at any scope. Report it, but not as though
                # the surface were unbounded when it demonstrably is not.
                constrained = effective.get(str(record["tool"]).lower(), {}).get("decision") == "deny"
                findings.append(_finding(
                    "CC_WILDCARD_PERMISSION", rule_map,
                    f"Unconstrained Claude Code permission: {record['entry']}",
                    record["path"], record["line"],
                    evidence=record["entry"],
                    reason=(
                        f"{record['tool']} is allowed with no argument constraint, but a deny "
                        f"rule for the same tool is evaluated first, so the granted surface is "
                        f"bounded by that deny."
                        if constrained else
                        f"{record['tool']} is allowed with no argument constraint, granting "
                        f"{record['access_mode']} authority over its entire surface."
                    ),
                    severity="medium" if constrained else None,
                ))
            if cc_permissions.writes_outside_root(record):
                findings.append(_finding(
                    "CC_FS_WRITE_OUTSIDE_ROOT", rule_map,
                    f"Write permission targets a path outside the project: {record['entry']}",
                    record["path"], record["line"],
                    evidence=record["entry"],
                    reason="A write grant resolving outside the repository can modify developer "
                           "or system files that code review never sees.",
                    capability="Filesystem",
                ))

        # #93 - this finding used to be stated the wrong way round. Claude Code
        # evaluates deny, then ask, then allow, and "rule specificity doesn't
        # change the order", so a matching deny ALWAYS decides the call. It is
        # the allow that is dead configuration, not the deny, and the severity
        # follows: contradictory rules are a maintenance problem, not a hole.
        for allow, deny in cc_permissions.ineffective_allows(records):
            findings.append(_finding(
                "CC_DENY_SHADOWED", rule_map,
                f"Allow entry can never apply, a deny covers it: {allow['entry']}",
                allow["path"], allow["line"],
                evidence=f"allow {allow['entry']} overridden by deny {deny['entry']}",
                reason="Claude Code evaluates deny before allow and specificity does not change "
                       "that, so the deny decides every matching call and this allow widens "
                       "nothing. The deny is effective; the allow is dead configuration.",
                severity="low",
            ))
        return findings

    def _permission_modes(self, documents):
        for doc in documents:
            for key, value in cc_settings.extract_permission_modes(doc["data"]):
                severity = cc_permissions.bypass_severity(value)
                if severity:
                    yield doc, key, value, severity

    def _mcp_findings(self, documents, records, rule_map):
        findings = []
        for doc, key, value, severity in self._permission_modes(documents):
            findings.append(_finding(
                "CC_BYPASS_PERMISSIONS", rule_map,
                f"Approval gate weakened by {key}={value}",
                doc["path"], cc_settings.line_of(doc["content"], key),
                evidence=f"{key}: {value}",
                reason="The human approval gate is disabled or reduced in committed "
                       "configuration, so tool calls proceed without review.",
                severity=severity,
                capability="Human Approval",
            ))

        constrained = {
            record["mcp_server"] for record in records
            if record["mcp_server"] and record["decision"] in {"allow", "deny", "ask"}
            and not record["wildcard"]
        }
        for doc in documents:
            declared = set(cc_settings.extract_mcp_servers(doc["data"]))
            declared |= set(cc_settings.extract_enabled_mcp_servers(doc["data"]))
            for server in sorted(declared - constrained):
                findings.append(_finding(
                    "CC_MCP_UNCONSTRAINED", rule_map,
                    f"MCP server enabled without a permission constraint: {server}",
                    doc["path"], cc_settings.line_of(doc["content"], server),
                    evidence=f"mcp server: {server}",
                    reason="The server's tools are reachable without an explicit "
                           "mcp__<server>__<tool> permission entry bounding them.",
                    capability="MCP",
                ))
        return findings

    # --- hooks ----------------------------------------------------------

    def _hook_findings(self, documents, claude_files, rule_map):
        findings = []
        hooks = []
        for doc in documents:
            for event, command in cc_settings.extract_hooks(doc["data"]):
                hooks.append((doc["path"], cc_settings.line_of(doc["content"], command), event, command))

        for entry in claude_files:
            rel = entry["rel_path"]
            content = entry["content"]
            path = entry["abs_path"]
            if not rel.startswith(cc_commands.HOOKS_PREFIX):
                continue
            for index, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and cc_commands.is_unpinned(stripped):
                    hooks.append((path, index, "hook script", stripped))

        for path, line, event, command in hooks:
            unpinned = cc_commands.is_unpinned(command)
            findings.append(_finding(
                "CC_HOOK_SHELL_EXEC", rule_map,
                f"Lifecycle hook executes a shell command on {event}",
                path, line,
                evidence=command[:120],
                reason="Hooks run shell commands automatically on agent lifecycle events."
                       + (" This one fetches or installs unpinned remote content."
                          if unpinned else ""),
                severity="high" if unpinned else "medium",
                capability="Shell",
            ))
        return findings

    # --- slash commands -------------------------------------------------

    def _command_findings(self, claude_files, rule_map):
        findings = []
        for entry in sorted(claude_files, key=lambda item: (item["rel_path"], item["abs_path"])):
            rel = entry["rel_path"]
            path = entry["abs_path"]
            content = entry["content"]
            if not (rel.startswith(cc_commands.COMMANDS_PREFIX) and rel.endswith(".md")):
                continue
            command = cc_commands.parse_command(rel, content)

            for shell in command["arguments_in_shell"]:
                findings.append(_finding(
                    "CC_SLASH_COMMAND_ARG_INJECTION", rule_map,
                    f"Slash command /{command['name']} interpolates caller arguments into a shell command",
                    path, shell["line"],
                    evidence=shell["command"][:120],
                    reason="Caller-supplied text reaches command execution unvalidated: untrusted "
                           "input combined with shell authority.",
                    capability="Shell",
                ))

            plain_shell = [s for s in command["shell_invocations"] if not s["uses_arguments"]]
            for shell in plain_shell:
                findings.append(_finding(
                    "CC_SLASH_COMMAND_SHELL", rule_map,
                    f"Slash command /{command['name']} embeds a shell invocation",
                    path, shell["line"],
                    evidence=shell["command"][:120],
                    reason="Stored instructions execute with the agent's full authority when the "
                           "command is invoked."
                           + (" The command fetches or installs unpinned remote content."
                              if cc_commands.is_unpinned(shell["command"]) else ""),
                    severity="high" if cc_commands.is_unpinned(shell["command"]) else None,
                    capability="Shell",
                ))

            for reference in command["file_references"]:
                findings.append(_finding(
                    "CC_SLASH_COMMAND_SHELL", rule_map,
                    f"Slash command /{command['name']} pulls in external file content",
                    path, reference["line"],
                    evidence=f"@{reference['target']}",
                    reason="Referenced file content is inlined into the prompt and is not "
                           "reviewed at invocation time.",
                    severity="low",
                    capability="Prompts",
                ))

            # Instruction-override phrasing is detected by the existing prompt
            # analyzer so both surfaces share one implementation.
            findings.extend(
                analyze_prompt_text(path, content, rule_map, framework="claude_code")
            )
        return findings

    # --- subagents ------------------------------------------------------

    def _subagent_findings(self, claude_files, records, rule_map):
        parent_tools = {
            record["tool"].lower()
            for record in records
            if record["decision"] == "allow" and record["tool"]
        }
        parent_declared = bool(parent_tools)

        findings = []
        for entry in sorted(claude_files, key=lambda item: (item["rel_path"], item["abs_path"])):
            rel = entry["rel_path"]
            path = entry["abs_path"]
            content = entry["content"]
            if not (rel.startswith(cc_commands.AGENTS_PREFIX) and rel.endswith((".md", ".yaml", ".yml"))):
                continue
            subagent = cc_commands.parse_subagent(rel, content)
            if not parent_declared:
                # Without a declared parent scope there is nothing to compare
                # against; claiming escalation here would be unfounded.
                continue
            broader = sorted({
                tool for tool in subagent["tools"]
                if cc_permissions.parse_entry(tool)[0]
                and cc_permissions.parse_entry(tool)[0].lower() not in parent_tools
            })
            if broader:
                findings.append(_finding(
                    "CC_SUBAGENT_PRIVILEGE_ESCALATION", rule_map,
                    f"Subagent {subagent['name']} grants tools beyond the parent scope: "
                    f"{', '.join(broader)}",
                    path, 1,
                    evidence=", ".join(broader)[:120],
                    reason="A delegated subagent can act with authority the parent configuration "
                           "never granted, bypassing the project's permission boundary.",
                    capability="Delegation",
                ))
        return findings
