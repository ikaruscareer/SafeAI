"""Claude Code custom slash commands and subagent definitions.

A file under ``.claude/commands/`` is not configuration. It is a stored
instruction that runs with the agent's full authority, on an argument the
caller supplies. That makes it an injection surface, and it is treated as
one here: ``$ARGUMENTS`` reaching a shell invocation is untrusted input
reaching command execution.

Detection of instruction-override phrasing is delegated to the existing
prompt analyzer rather than reimplemented, so both surfaces stay in sync.
"""

import re

import yaml

COMMANDS_PREFIX = ".claude/commands/"
AGENTS_PREFIX = ".claude/agents/"
HOOKS_PREFIX = ".claude/hooks/"

#: ``!`command``` — Claude Code's inline shell execution syntax.
_BANG_BACKTICK_RE = re.compile(r"!`([^`]+)`")
#: A line that is itself a shell invocation, e.g. ``!npm run build``.
_BANG_LINE_RE = re.compile(r"^\s*!\s*(\S.*)$")
#: Argument interpolation: ``$ARGUMENTS``, ``$1`` … ``$9``.
_ARGUMENT_RE = re.compile(r"\$ARGUMENTS\b|\$\{ARGUMENTS\}|\$[1-9]\b")
#: ``@path/to/file`` external content references.
_FILE_REF_RE = re.compile(r"(?:^|\s)@([\w./-]+\.[\w]+)")

#: Commands that fetch and run remote content — unpinned by definition.
_UNPINNED_RE = re.compile(
    r"curl\s|wget\s|npx\s+-y|npx\s+--yes|pip\s+install\s+(?!-r)|"
    r"\|\s*(?:ba)?sh\b|iwr\s|irm\s",
    re.IGNORECASE,
)

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?", re.DOTALL)


def split_frontmatter(content):
    """Return ``(frontmatter_dict, body, body_offset)``.

    Malformed frontmatter yields an empty dict rather than raising, so a
    broken command file still gets its body analyzed.
    """
    match = _FRONTMATTER_RE.match(content or "")
    if not match:
        return {}, content or "", 0
    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        data = None
    offset = (content or "")[: match.end()].count("\n")
    return (data if isinstance(data, dict) else {}), (content or "")[match.end():], offset


def _as_tool_list(value):
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def allowed_tools(frontmatter):
    """Tools a command grants itself via frontmatter."""
    for key in ("allowed-tools", "allowed_tools", "allowedTools", "tools"):
        if key in (frontmatter or {}):
            return _as_tool_list(frontmatter[key])
    return []


def shell_invocations(body, line_offset=0):
    """Locate shell invocations inside a command body.

    Returns records of ``{"command", "line", "uses_arguments"}``.
    ``uses_arguments`` marks the critical case: caller-supplied text
    interpolated straight into a command line.
    """
    found = []
    for index, line in enumerate(body.splitlines(), 1):
        commands = _BANG_BACKTICK_RE.findall(line)
        if not commands:
            bang_line = _BANG_LINE_RE.match(line)
            if bang_line:
                commands = [bang_line.group(1)]
        for command in commands:
            found.append({
                "command": command.strip(),
                "line": index + line_offset,
                "uses_arguments": bool(_ARGUMENT_RE.search(command)),
            })
    return found


def argument_uses(body, line_offset=0):
    """Lines where ``$ARGUMENTS`` (or ``$1``…) appears."""
    return [
        {"line": index + line_offset}
        for index, line in enumerate(body.splitlines(), 1)
        if _ARGUMENT_RE.search(line)
    ]


def file_references(body, line_offset=0):
    """``@file`` references that pull external content into the prompt."""
    references = []
    for index, line in enumerate(body.splitlines(), 1):
        for target in _FILE_REF_RE.findall(line):
            references.append({"target": target, "line": index + line_offset})
    return references


def is_unpinned(command):
    """True when a command fetches or installs unpinned remote content."""
    return bool(_UNPINNED_RE.search(str(command or "")))


def command_name(rel_path):
    """Slash-command name derived from its path under ``.claude/commands/``."""
    stem = rel_path.removeprefix(COMMANDS_PREFIX)
    stem = stem.removesuffix(".md")
    return stem.replace("/", ":")


def parse_command(rel_path, content):
    """Parse one slash-command file into a structured record."""
    frontmatter, body, offset = split_frontmatter(content)
    shells = shell_invocations(body, offset)
    return {
        "name": command_name(rel_path),
        "path": rel_path,
        "frontmatter": frontmatter,
        "allowed_tools": allowed_tools(frontmatter),
        "body": body,
        "body_offset": offset,
        "shell_invocations": shells,
        "argument_uses": argument_uses(body, offset),
        "file_references": file_references(body, offset),
        "arguments_in_shell": [s for s in shells if s["uses_arguments"]],
    }


def parse_subagent(rel_path, content):
    """Parse a ``.claude/agents/*`` subagent definition."""
    frontmatter, body, offset = split_frontmatter(content)
    name = str(frontmatter.get("name") or "").strip()
    if not name:
        stem = rel_path.rsplit("/", 1)[-1]
        name = stem.removesuffix(".md")
    return {
        "name": name,
        "path": rel_path,
        "frontmatter": frontmatter,
        "tools": allowed_tools(frontmatter),
        "body": body,
        "body_offset": offset,
    }
