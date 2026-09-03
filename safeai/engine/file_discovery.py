"""File discovery and adapter dispatch for the SafeAI scan pipeline.

Extracted from the central orchestrator to provide a defined scan phase
that can be tested, replaced, or extended independently.

Usage::

    from safeai.engine.file_discovery import discover_files, dispatch_adapters

    files, skipped = discover_files(root, excluded_paths=excluded_paths)
    adapters = dispatch_adapters(files, file_cache)
"""

import logging
import os

logger = logging.getLogger("safeai")

# Directories that are never scanned (version control, dependency caches,
# virtual environments, build outputs, SafeAI's own local state).
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules",
    "__pycache__",
    ".venv", "venv", "env",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    "dist", "build", ".eggs",
    ".idea", ".vscode",
    ".safeai",
}

# SafeAI's own canonical artifacts are never re-scanned.
_EXCLUDED_FILES = {"safeai-manifest.json"}

# Files larger than this are skipped to avoid excessive memory use.
MAX_FILE_BYTES = 2 * 1024 * 1024

# Extensions considered scannable source/config files.
_SCANNABLE_EXTENSIONS = {".py", ".json", ".yaml", ".yml", ".prompt"}

# Files that are scannable by name (not extension).
_SCANNABLE_NAMES = {
    "claude.md", "prompt.md", "system_prompt.md",
    ".cursorrules", ".windsurfrules",
}

# Additional extensions read inside a ``.claude/`` directory.
_CLAUDE_CONFIG_EXTS = (".md", ".markdown", ".sh", ".bash", ".toml")


def is_scannable_file(filename):
    """Return whether a file is source, configuration, or AI instructions."""
    lower = filename.lower()
    if any(lower.endswith(ext) for ext in _SCANNABLE_EXTENSIONS):
        return True
    if lower.endswith((".prompt.md", ".prompt.txt")):
        return True
    return lower in _SCANNABLE_NAMES


def _is_claude_config_file(full_path):
    """True for Claude Code configuration inside the scanned repository."""
    normalized = str(full_path).replace("\\", "/")
    if "/.claude/" not in normalized:
        return False
    return normalized.lower().endswith(_CLAUDE_CONFIG_EXTS)


def _is_within_root(root, path):
    """True when ``path`` resolves inside ``root`` after symlink expansion."""
    root_real = os.path.normcase(os.path.realpath(root))
    path_real = os.path.normcase(os.path.realpath(path))
    try:
        return os.path.commonpath([root_real, path_real]) == root_real
    except ValueError:
        return False


def _is_canonical_manifest_path(path, root):
    """True for the canonical root-level manifest filename only."""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return False
    return rel.replace("\\", "/") in _EXCLUDED_FILES


def discover_files(root, excluded_paths=None):
    """Collect scannable files, pruning excluded directories and oversized files.

    Returns ``(files, skipped)`` where ``files`` is a sorted list of absolute
    paths and ``skipped`` is a ``reason -> count`` dict for files the walk
    declined to read.
    """
    files = []
    skipped = {}

    def note(reason):
        skipped[reason] = skipped.get(reason, 0) + 1

    excluded = {
        os.path.normcase(os.path.realpath(os.path.abspath(path)))
        for path in (excluded_paths or [])
        if path
    }

    for d, dirs, fs in os.walk(root):
        dirs[:] = sorted(name for name in dirs if name not in EXCLUDED_DIRS)
        for f in sorted(fs):
            full = os.path.join(d, f)

            full_real = os.path.normcase(os.path.realpath(full))
            if full_real in excluded:
                continue

            if _is_canonical_manifest_path(full, root):
                continue

            if not _is_within_root(root, full):
                note("outside scan root (symlink or path traversal)")
                continue

            if not (is_scannable_file(f) or _is_claude_config_file(full)):
                extension = os.path.splitext(f)[1].lower() or "(no extension)"
                note(f"unsupported file type {extension}")
                continue
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    logger.debug("Skipping oversized file: %s", full)
                    note("larger than the 2 MiB read limit")
                    continue
            except OSError:
                note("unreadable")
                continue
            files.append(full)

    return sorted(files), skipped


def dispatch_adapters(files, file_cache, parsers, scan_ctx=None):
    """Run all framework parsers on all files, returning parsed results.

    This is the adapter dispatch phase — each file is tested against every
    registered parser. No mutual exclusion: multiple parsers can match the
    same file.

    Returns ``(agent_models, parse_provenance, detected_frameworks,
    framework_methods, parser_results_by_file)``.
    """
    agent_models = []
    parse_provenance = []
    detected_frameworks = []
    framework_methods = {}
    parser_results_by_file = {}

    for path in files:
        content = file_cache.get(path, "")
        for parser in parsers:
            if parser.detect(path, content, scan_ctx=scan_ctx):
                parsed = parser.parse(path, content, scan_ctx=scan_ctx)
                if parsed is None:
                    continue
                framework = parsed.get("framework")
                if not framework:
                    continue
                agent_models.append({
                    "file": path,
                    "framework": framework,
                    "data": parsed,
                })
                parser_results_by_file.setdefault(path, []).append(parsed)
                parse_provenance.append({
                    "file": path,
                    "framework": framework,
                    "confidence": parsed.get("parser_confidence", 0.65),
                    "source": parsed.get("discovery_method", "regex"),
                    "evidence": parsed.get("detection_evidence", []),
                })
                if framework and framework not in detected_frameworks:
                    detected_frameworks.append(framework)
                framework_methods.setdefault(framework, set()).add(
                    parsed.get("discovery_method", "regex")
                )

    return agent_models, parse_provenance, detected_frameworks, framework_methods, parser_results_by_file
