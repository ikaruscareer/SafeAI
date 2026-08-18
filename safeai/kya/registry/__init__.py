"""Local SQLite KYA registry.

Stores scan-derived, static-analysis agent records and evidence at
``.safeai/registry.db`` by default (or the org-wide shared registry —
``SAFEAI_REGISTRY`` env var or ``~/.safeai/registry.db``). Everything
stays on the local filesystem: no server, account, network call, or
source upload.

This package is a facade over focused submodules:

  * :mod:`safeai.kya.registry.schema` — schema DDL and forward-only
    migrations
  * :mod:`safeai.kya.registry.connection` — paths, open, migrate, init
  * :mod:`safeai.kya.registry.persist` — append-only scan persistence
  * :mod:`safeai.kya.registry.queries` — read-only query helpers

The public API is re-exported here so existing imports keep working.

Design notes:
  * Standard-library ``sqlite3`` only — no ORM, no new dependencies.
  * WAL journal mode for safe local CLI concurrency.
  * Versioned schema via ``schema_migrations``; migrations are additive.
  * Historical scans are append-only: a prior scan snapshot is never
    overwritten.
  * Raw source code and unredacted secrets are never stored.
"""

from safeai.kya.registry.connection import (
    DEFAULT_REGISTRY_DIRNAME,
    DEFAULT_REGISTRY_FILENAME,
    SAFEAI_REGISTRY_ENV,
    RegistryError,
    connect,
    default_registry_path,
    init_registry,
    migrate,
    registry_exists,
    shared_registry_path,
)
from safeai.kya.registry.persist import (
    get_tool_snapshots,
    persist_scan,
)
from safeai.kya.registry.queries import (
    agent_history,
    component_history,
    finding_lifecycle,
    finding_lifecycle_summary,
    get_agent,
    get_agent_scan_findings,
    get_component_agents,
    get_scan_findings,
    get_snapshot,
    latest_scan_id,
    list_agents,
    list_components,
    list_projects,
    recurring_risks,
    resolve_scan_ref,
)
from safeai.kya.registry.schema import _MIGRATIONS

__all__ = [
    "DEFAULT_REGISTRY_DIRNAME",
    "DEFAULT_REGISTRY_FILENAME",
    "SAFEAI_REGISTRY_ENV",
    "_MIGRATIONS",
    "RegistryError",
    "agent_history",
    "component_history",
    "connect",
    "default_registry_path",
    "finding_lifecycle",
    "finding_lifecycle_summary",
    "get_agent",
    "get_agent_scan_findings",
    "get_component_agents",
    "get_scan_findings",
    "get_snapshot",
    "get_tool_snapshots",
    "init_registry",
    "latest_scan_id",
    "list_agents",
    "list_components",
    "list_projects",
    "migrate",
    "persist_scan",
    "recurring_risks",
    "registry_exists",
    "resolve_scan_ref",
    "shared_registry_path",
]
