"""Stable, path-independent identity for the things that hold authority.

SafeAI v1.3 keyed capabilities on ``(name, category)`` only, which made
the product blind to the question a reviewer actually asks: *which tool
gained which authority?* This module supplies the missing half of that
key — a deterministic identity for the tool, MCP server, skill,
workflow node or agent a capability belongs to.

Design rules:
  * Identity is **path-independent whenever a name exists**. Moving
    ``src/tools/report.py`` to ``src/agents/report.py`` must not read as
    "tool removed + tool added".
  * Identity is **deterministic**: same inputs, byte-identical key.
  * Capabilities that genuinely cannot be attributed are never dropped.
    They are attributed to :data:`UNATTRIBUTED` so an unowned shell
    capability still surfaces as a finding.

Everything here is pure, offline, and free of runtime dependencies.
"""

import hashlib
import re

#: Recognised identity kinds, ordered for stable rendering.
TOOL_KINDS = ("agent", "mcp_server", "skill", "tool", "workflow_node", "unknown")

_SLUG_STRIP_RE = re.compile(r"[^a-z0-9]+")


def _slug(value):
    """Lowercase, dash-separated slug of ``value`` (empty string when blank)."""
    if value is None:
        return ""
    text = str(value).strip().lower()
    if not text:
        return ""
    return _SLUG_STRIP_RE.sub("-", text).strip("-")


def _short_hash(*parts):
    """Deterministic 12-char digest over the supplied parts."""
    payload = "\u241f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def make_tool_identity(kind, name, framework, source_path=None, server=None):
    """Build a tool identity record.

    Parameters
    ----------
    kind : str
        One of :data:`TOOL_KINDS`. Unknown values normalise to ``"unknown"``.
    name : str or None
        The declared name of the tool/server/skill. ``None`` or blank
        falls back to path-derived identity.
    framework : str or None
        The framework adapter that observed it (``"mcp"``, ``"langgraph"``…).
    source_path : str or None
        Repository-relative path where it was declared. Used for identity
        **only** when no name is available.
    server : str or None
        Owning MCP server (or parent agent) that scopes the name.
    """
    normalized_kind = kind if kind in TOOL_KINDS else "unknown"
    clean_name = str(name).strip() if name is not None and str(name).strip() else None
    clean_server = str(server).strip() if server is not None and str(server).strip() else None
    clean_path = str(source_path).replace("\\", "/").strip() if source_path else None
    return {
        "kind": normalized_kind,
        "name": clean_name,
        "framework": str(framework).strip() if framework else None,
        "source_path": clean_path,
        "server": clean_server,
    }


def tool_key(identity):
    """Return the stable slug used as the primary key for an identity.

    Examples: ``mcp_server:invoice-lookup``, ``tool:send_email``,
    ``tool:invoice-lookup.create-invoice``, ``unknown:9f1c0b2a4d5e``.
    """
    if not isinstance(identity, dict):
        return "unknown:" + _short_hash(identity)
    kind = identity.get("kind") if identity.get("kind") in TOOL_KINDS else "unknown"
    name_slug = _slug(identity.get("name"))
    server_slug = _slug(identity.get("server"))

    if name_slug:
        local = f"{server_slug}.{name_slug}" if server_slug and server_slug != name_slug else name_slug
        return f"{kind}:{local}"
    if server_slug:
        return f"{kind}:{server_slug}"

    # No name anywhere: fall back to path-derived identity. This is the
    # only case where a file move changes the key, and it is unavoidable
    # because the path is the sole distinguishing evidence.
    path = identity.get("source_path")
    if path:
        return f"{kind}:" + _short_hash("path", path)
    return f"{kind}:" + _short_hash("anon", identity.get("framework"))


def unknown_identity(evidence, framework=None, source_path=None):
    """Identity for an unnamed item, keyed on a digest of its evidence."""
    identity = make_tool_identity("unknown", None, framework, source_path=source_path)
    identity["evidence_digest"] = _short_hash("evidence", evidence)
    return identity


#: Sentinel identity for capabilities with no resolvable owner. These are
#: reported separately rather than discarded — an unattributed shell
#: capability is still a finding.
UNATTRIBUTED = make_tool_identity("unknown", "unattributed", None)

#: Convenience constant so callers do not recompute the sentinel key.
UNATTRIBUTED_KEY = tool_key(UNATTRIBUTED)


def identity_summary(identity):
    """Public, serialisable subset of an identity (used in reports)."""
    if not isinstance(identity, dict):
        return {"kind": "unknown", "name": None, "framework": None}
    summary = {
        "kind": identity.get("kind", "unknown"),
        "name": identity.get("name"),
        "framework": identity.get("framework"),
    }
    if identity.get("server"):
        summary["server"] = identity["server"]
    return summary


def display_name(identity):
    """Human-facing label for an identity, e.g. ``mcp_server:invoice-lookup``."""
    return tool_key(identity)
