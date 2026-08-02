"""Claude Code permission model → capabilities with identity and access mode.

A Claude Code permission entry looks like ``Tool(argument)`` — for example
``Bash(npm run test:*)``, ``Write(*)``, ``Read(~/.zshrc)`` — or a bare tool
name such as ``Bash``, or an MCP-scoped grant ``mcp__github__create_issue``.

Each entry is translated into a capability carrying a stable tool identity
and an access mode, so the Workstream 1 diff can say *which named tool*
gained authority rather than only that "a permission changed".

Everything here is pure string analysis. Nothing is executed, no file is
opened, and no path outside the scanned repository is consulted.
"""

import re

from safeai.analysis.capabilities import make_capability
from safeai.analysis.tool_identity import make_tool_identity

#: ``Tool(argument)`` or a bare ``Tool``.
_ENTRY_RE = re.compile(r"^\s*(?P<tool>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\((?P<arg>.*)\)\s*)?$", re.DOTALL)

#: ``mcp__<server>`` or ``mcp__<server>__<tool>``. Segments are split on the
#: literal ``__`` separator rather than matched with a greedy character
#: class, so ``mcp__github__create_issue`` resolves to the *github* server
#: and not to a server literally named ``github__create_issue``.
_MCP_SEGMENT_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def split_mcp_entry(text):
    """Return ``(server, tool)`` for an MCP grant, or ``None``.

    ``tool`` is ``None`` when the grant covers the whole server. Tool names
    may themselves contain ``__``; only the first two segments are fixed.
    """
    parts = str(text or "").split("__")
    if len(parts) < 2 or parts[0] != "mcp":
        return None
    server = parts[1]
    if not _MCP_SEGMENT_RE.match(server):
        return None
    tool = "__".join(parts[2:]) or None
    return server, tool

#: Built-in Claude Code tools → (capability name, category, access mode).
#:
#: Access modes follow the tool's *documented* effect, not a guess: ``Bash``
#: executes, ``Write`` writes, ``Read`` reads. Anything not listed here is
#: recorded as an unknown tool at ``read`` and marked inferred by the
#: capability layer, so it can never drive a critical verdict on its own.
BUILTIN_TOOLS = {
    "bash": ("shell", "Shell", "execute"),
    "bashoutput": ("shell", "Shell", "read"),
    "killshell": ("shell", "Shell", "execute"),
    "write": ("filesystem", "Filesystem", "write"),
    "edit": ("filesystem", "Filesystem", "write"),
    "multiedit": ("filesystem", "Filesystem", "write"),
    "notebookedit": ("filesystem", "Filesystem", "write"),
    "read": ("filesystem", "Filesystem", "read"),
    "glob": ("filesystem", "Filesystem", "read"),
    "grep": ("filesystem", "Filesystem", "read"),
    "ls": ("filesystem", "Filesystem", "read"),
    "webfetch": ("external_apis", "External APIs", "read"),
    "websearch": ("external_apis", "External APIs", "read"),
    "task": ("delegation", "Delegation", "execute"),
    "agent": ("delegation", "Delegation", "execute"),
    "todowrite": ("memory", "Memory", "write"),
}

#: Tools whose authority is a write or worse. Used for scope checks.
WRITE_TOOLS = {name for name, (_, _, mode) in BUILTIN_TOOLS.items() if mode in {"write", "mutate", "execute"}}

#: MCP tool-name stems that indicate a mutating (not read-only) operation.
_MCP_MUTATE_STEMS = (
    "create", "update", "delete", "remove", "write", "merge", "push", "put",
    "post", "patch", "set", "add", "close", "publish", "deploy", "revoke",
)

#: Settings values that disable the human approval gate entirely.
BYPASS_VALUES = {"bypasspermissions", "bypass", "dangerously-skip-permissions", "yolo"}

#: Permissive but not fully bypassing — reported at a reduced severity.
PERMISSIVE_MODES = {"acceptedits", "acceptall", "auto"}

_OUTSIDE_ROOT_RE = re.compile(r"^\s*(?:/|~|\.\./)|(?:^|/)\.\./")


def _wildcard(argument):
    """True when the argument grants the tool's full surface."""
    if argument is None:
        return True  # a bare `Bash` grant is unconstrained
    stripped = argument.strip().strip("\"'")
    return stripped in {"", "*", "**", "*:*", "//*"}


def mcp_access_mode(tool_name):
    """Infer read vs mutate for an MCP tool from its verb stem."""
    lowered = str(tool_name or "").lower()
    if any(stem in lowered for stem in _MCP_MUTATE_STEMS):
        return "mutate"
    return "read"


def parse_entry(entry):
    """Split a permission entry into ``(tool, argument)``.

    Returns ``(None, None)`` when the entry is not in a recognized form,
    so the caller can record it as unparsed rather than guessing.
    """
    text = str(entry or "").strip()
    if not text:
        return None, None
    match = _ENTRY_RE.match(text)
    if not match:
        return None, None
    return match.group("tool"), match.group("arg")


def classify_entry(entry, decision, path, line=0):
    """Translate one permission entry into a structured record.

    ``decision`` is ``allow``, ``deny``, or ``ask``. The returned record
    carries provenance (path/line), the resolved tool identity, and the
    access mode the grant confers.
    """
    text = str(entry or "").strip()
    mcp_match = split_mcp_entry(text)
    if mcp_match:
        server, mcp_tool = mcp_match
        identity = make_tool_identity("mcp_server", server, "claude_code", source_path=path)
        return {
            "entry": text,
            "decision": decision,
            "tool": f"mcp__{server}",
            "argument": mcp_tool,
            "capability": "mcp",
            "category": "MCP",
            "access_mode": mcp_access_mode(mcp_tool) if mcp_tool else "mutate",
            "wildcard": mcp_tool in (None, "*"),
            "mcp_server": server,
            "identity": identity,
            "path": path,
            "line": line,
            "recognized": True,
        }

    tool, argument = parse_entry(text)
    if not tool:
        return {
            "entry": text,
            "decision": decision,
            "tool": None,
            "argument": None,
            "capability": None,
            "category": None,
            "access_mode": "read",
            "wildcard": False,
            "mcp_server": None,
            "identity": make_tool_identity("unknown", None, "claude_code", source_path=path),
            "path": path,
            "line": line,
            "recognized": False,
        }

    capability, category, access_mode = BUILTIN_TOOLS.get(
        tool.lower(), ("tool_grant", "Collaboration", "read")
    )
    return {
        "entry": text,
        "decision": decision,
        "tool": tool,
        "argument": argument,
        "capability": capability,
        "category": category,
        "access_mode": access_mode,
        "wildcard": _wildcard(argument),
        "mcp_server": None,
        "identity": make_tool_identity("tool", tool, "claude_code", source_path=path),
        "path": path,
        "line": line,
        "recognized": tool.lower() in BUILTIN_TOOLS,
    }


def capability_for(record, evidence_prefix="claude code permission"):
    """Build a SafeAI capability from a classified permission record.

    Only ``allow`` grants confer authority. ``deny`` and ``ask`` entries
    are recorded for shadowing analysis but never add capability.
    """
    if record["decision"] != "allow" or not record["capability"]:
        return None
    return make_capability(
        record["capability"],
        record["category"],
        "claude_code",
        f"{evidence_prefix}: {record['entry']}",
        confidence=0.9 if record["recognized"] else 0.6,
        source="config",
        tool_identity=record["identity"],
        access_mode=record["access_mode"],
        line=record.get("line", 0),
    )


def argument_covers(broad, narrow):
    """True when permission argument ``broad`` subsumes ``narrow``.

    Deliberately conservative: only a wildcard, an exact match, or an
    explicit ``prefix*`` glob counts as coverage. Anything cleverer risks
    claiming a shadow that does not exist.
    """
    if _wildcard(broad):
        return True
    if narrow is None:
        return False
    broad_s = str(broad).strip().strip("\"'")
    narrow_s = str(narrow).strip().strip("\"'")
    if broad_s == narrow_s:
        return True
    if broad_s.endswith("*"):
        return narrow_s.startswith(broad_s[:-1])
    return False


def shadowed_denials(records):
    """Return ``(deny_record, allow_record)`` pairs where allow wins.

    A ``deny`` that a broader ``allow`` contradicts is a false sense of
    safety, which is worth reporting precisely because it looks safe.
    """
    allows = [r for r in records if r["decision"] == "allow" and r["tool"]]
    pairs = []
    for deny in sorted(
        (r for r in records if r["decision"] == "deny" and r["tool"]),
        key=lambda r: (r["path"], r["entry"]),
    ):
        for allow in sorted(allows, key=lambda r: (r["path"], r["entry"])):
            if allow["tool"].lower() != deny["tool"].lower():
                continue
            if argument_covers(allow["argument"], deny["argument"]):
                pairs.append((deny, allow))
                break
    return pairs


def writes_outside_root(record):
    """True when a write-capable grant targets a path outside the project."""
    if record["decision"] != "allow":
        return False
    if not record["tool"] or record["tool"].lower() not in WRITE_TOOLS:
        return False
    argument = record.get("argument")
    if argument is None:
        return False
    return bool(_OUTSIDE_ROOT_RE.search(str(argument).strip().strip("\"'")))


def bypass_severity(value):
    """Classify a permission-mode value: critical, medium, or None."""
    lowered = str(value or "").strip().lower().replace("_", "").replace(" ", "")
    if lowered in BYPASS_VALUES or lowered.replace("-", "") in {
        v.replace("-", "") for v in BYPASS_VALUES
    }:
        return "critical"
    if lowered in PERMISSIVE_MODES:
        return "medium"
    return None
