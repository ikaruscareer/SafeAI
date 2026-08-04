"""Registry connection lifecycle: paths, open, migrate, init.

Standard-library ``sqlite3`` only — no ORM, no new dependencies. WAL
journal mode keeps local CLI concurrency safe; forward-only versioned
migrations upgrade older databases without touching existing rows.
"""

import os
import sqlite3

from safeai.kya import REGISTRY_SCHEMA_VERSION
from safeai.kya.registry.schema import _MIGRATIONS
from safeai.kya.util import utc_now_iso

DEFAULT_REGISTRY_DIRNAME = ".safeai"
DEFAULT_REGISTRY_FILENAME = "registry.db"

#: Environment variable for the org-wide shared registry path. When set,
#: both ``safeai scan`` and the ``safeai registry`` commands use it, and it
#: counts as an explicit registry configuration (so it also enables
#: persistence in CI).
SAFEAI_REGISTRY_ENV = "SAFEAI_REGISTRY"


class RegistryError(Exception):
    """Raised for registry open, migration, or persistence failures."""


def default_registry_path(root):
    """Return the default registry path for a scan root."""
    return os.path.join(root, DEFAULT_REGISTRY_DIRNAME, DEFAULT_REGISTRY_FILENAME)


def shared_registry_path():
    """Return the org-wide shared registry path.

    ``SAFEAI_REGISTRY`` (e.g. a team-shared or network location) overrides
    the per-user default ``~/.safeai/registry.db``. Scans from every
    project accumulate in this one database, so ``safeai registry list``
    shows the organization's agents regardless of which folders were
    scanned or the current working directory.
    """
    env = os.environ.get(SAFEAI_REGISTRY_ENV)
    if env:
        return os.path.abspath(os.path.expanduser(env))
    return os.path.join(
        os.path.expanduser("~"), DEFAULT_REGISTRY_DIRNAME, DEFAULT_REGISTRY_FILENAME
    )


def registry_exists(path):
    return bool(path) and os.path.exists(path)


def connect(path):
    """Open a registry connection with safe local CLI pragmas."""
    try:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=3000")
        return conn
    except sqlite3.Error as exc:
        raise RegistryError(f"Unable to open registry at {path}: {exc}") from exc


def _current_version(conn):
    try:
        row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
    except sqlite3.Error:
        return 0
    return row["v"] if row and row["v"] is not None else 0


def migrate(conn):
    """Apply pending schema migrations in ascending order.

    Migrations are additive and forward-only: an existing v1.3 database
    opens, gains the new tables, and keeps every prior row untouched.
    """
    version = _current_version(conn)
    if version >= REGISTRY_SCHEMA_VERSION:
        return version
    with conn:
        for target in sorted(_MIGRATIONS):
            if target <= version:
                continue
            conn.executescript(_MIGRATIONS[target])
            conn.execute(
                "INSERT OR REPLACE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (target, utc_now_iso()),
            )
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES ('registry_version', ?)",
            (str(REGISTRY_SCHEMA_VERSION),),
        )
    return REGISTRY_SCHEMA_VERSION


def init_registry(path):
    """Create (if needed) and migrate the registry at ``path``.

    Returns ``(conn, created)``. Never destroys an existing database;
    parent directories are created safely.
    """
    created = not os.path.exists(path)
    parent = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        raise RegistryError(f"Unable to create registry directory {parent}: {exc}") from exc
    conn = connect(path)
    try:
        migrate(conn)
    except sqlite3.Error as exc:
        conn.close()
        raise RegistryError(f"Unable to migrate registry at {path}: {exc}") from exc
    return conn, created
