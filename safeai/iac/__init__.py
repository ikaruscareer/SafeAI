"""IaC authority evidence collectors (v2.5, Lane B).

Walks the scan root for Terraform (``*.tf``) and Kubernetes YAML files,
extracts Grant triples / bindings / identities, and hands them to
``safeai.analysis.iac_correlation``. Self-contained: never touches the
analyzer file cache, never executes anything, never leaves the repo.

Fidelity ceiling (ADR-0006): heuristic extraction only. Unparseable
files are recorded in ``meta["unparsed_files"]`` and skipped — never
guessed.
"""

import os

from safeai.iac.k8s import parse_k8s_file
from safeai.iac.terraform import parse_terraform_file

#: Per-file read cap for IaC sources (pathological files are skipped).
_MAX_IAC_BYTES = 1024 * 1024

#: YAML extensions sniffed for RBAC kinds.
_YAML_EXTS = (".yaml", ".yml")


def _is_within_root(root, path):
    root_real = os.path.normcase(os.path.realpath(root))
    path_real = os.path.normcase(os.path.realpath(path))
    try:
        return os.path.commonpath([root_real, path_real]) == root_real
    except ValueError:
        return False


def _excluded(rel_path, excluded_paths):
    normalized = rel_path.replace("\\", "/")
    for excluded in excluded_paths or []:
        marker = str(excluded).replace("\\", "/").strip("/")
        if normalized == marker or normalized.startswith(marker + "/"):
            return True
    return False


def collect_iac_files(root, excluded_paths=None):
    """Return ``(tf_files, yaml_files)`` as root-relative paths.

    Mirrors ``collect_dependency_files``: a side collection pass that
    leaves the analyzer file cache untouched.
    """
    tf_files, yaml_files = [], []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Never descend into version-control internals; everything else is
        # fair game (IaC lives in arbitrary directories, dot-dirs included).
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for filename in sorted(filenames):
            full = os.path.join(dirpath, filename)
            if not _is_within_root(root, full):
                continue
            try:
                rel = os.path.relpath(full, root).replace("\\", "/")
            except ValueError:
                continue
            if _excluded(rel, excluded_paths):
                continue
            lower = filename.lower()
            if lower.endswith(".tf"):
                tf_files.append(rel)
            elif lower.endswith(_YAML_EXTS):
                yaml_files.append(rel)
    return tf_files, yaml_files


def _read_capped(root, rel_path):
    """Read a file with size cap; return ``None`` when unreadable/huge."""
    full = os.path.join(root, rel_path)
    try:
        if os.path.getsize(full) > _MAX_IAC_BYTES:
            return None
        with open(full, "r", encoding="utf-8") as handle:
            return handle.read()
    except Exception:
        return None


def scan_iac(root, excluded_paths=None):
    """Scan IaC sources under ``root``.

    Returns ``(grants, bindings, identities, meta)`` where ``meta`` has
    ``tf_files``, ``yaml_files``, ``rbac_files``, and ``unparsed_files``.
    Never raises.
    """
    grants, bindings, identities = [], [], []
    meta = {"tf_files": [], "yaml_files": [], "rbac_files": [],
            "unparsed_files": []}
    try:
        tf_files, yaml_files = collect_iac_files(root, excluded_paths)
    except Exception:
        return grants, bindings, identities, meta
    meta["tf_files"] = tf_files
    meta["yaml_files"] = yaml_files
    for rel in tf_files:
        text = _read_capped(root, rel)
        if text is None:
            meta["unparsed_files"].append(rel)
            continue
        try:
            grants.extend(parse_terraform_file(rel, text))
        except Exception:
            meta["unparsed_files"].append(rel)
    for rel in yaml_files:
        text = _read_capped(root, rel)
        if text is None:
            continue
        try:
            file_grants, file_bindings, file_identities = parse_k8s_file(rel, text)
        except Exception:
            meta["unparsed_files"].append(rel)
            continue
        if file_grants or file_bindings or file_identities:
            meta["rbac_files"].append(rel)
        grants.extend(file_grants)
        bindings.extend(file_bindings)
        identities.extend(file_identities)
    return grants, bindings, identities, meta
