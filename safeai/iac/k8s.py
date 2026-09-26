"""Kubernetes RBAC authority extraction (v2.5 IaC evidence, Lane B).

Reads repository YAML documents with RBAC kinds (Role, ClusterRole,
RoleBinding, ClusterRoleBinding, ServiceAccount) via PyYAML and emits
**Grant triples** plus **binding records** and **identity records**.

Fidelity ceiling: only in-repo YAML is read (never the cluster API);
``line`` is a best-effort text search for the object name, since
PyYAML discards positions. Aggregation, wildcards, and non-RBAC
documents are passed through honestly, never resolved.
"""

import yaml

#: RBAC object kinds we extract.
RBAC_KINDS = {
    "Role": "Role",
    "ClusterRole": "ClusterRole",
    "RoleBinding": "RoleBinding",
    "ClusterRoleBinding": "ClusterRoleBinding",
    "ServiceAccount": "ServiceAccount",
}

_MAX_DOCS_PER_FILE = 200


def _best_effort_line(text, name):
    """Line number of the first ``name: <name>`` occurrence, else 1."""
    try:
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("name:"):
                value = stripped[len("name:"):].strip().strip("\"'")
                if value == name:
                    return i
    except Exception:
        pass
    return 1


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def parse_k8s_file(rel_path, text):
    """Extract ``(grants, bindings, identities)`` from one YAML file's text.

    ``rel_path`` is the root-relative forward-slash path. Never raises:
    unparseable or non-RBAC content yields empty lists.
    """
    grants, bindings, identities = [], [], []
    try:
        docs = list(yaml.safe_load_all(text))[:_MAX_DOCS_PER_FILE]
    except Exception:
        return grants, bindings, identities
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        if kind not in RBAC_KINDS:
            continue
        meta = doc.get("metadata") or {}
        name = str(meta.get("name") or "<unnamed>")
        line = _best_effort_line(text, name)
        if kind in ("Role", "ClusterRole"):
            scope = str(meta.get("namespace") or "*") if kind == "Role" else "*"
            for rule in doc.get("rules") or []:
                if not isinstance(rule, dict):
                    continue
                verbs = _as_list(rule.get("verbs"))
                resources = _as_list(rule.get("resources"))
                grants.append({
                    "principal": f"{kind}/{name}",
                    "action": ",".join(verbs) if verbs else "*",
                    "resource": ",".join(resources) if resources else "*",
                    "scope": scope,
                    "source": "kubernetes",
                    "source_file": rel_path,
                    "line": line,
                    "provenance": "repo-iac-observed",
                    "fidelity_notes": [],
                    "family": "kubernetes",
                })
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            ref = doc.get("roleRef") or {}
            role = str(ref.get("name") or "<unknown-role>")
            for subject in doc.get("subjects") or []:
                if not isinstance(subject, dict):
                    continue
                bindings.append({
                    "subject_kind": str(subject.get("kind") or "Unknown"),
                    "subject_name": str(subject.get("name") or "<unnamed>"),
                    "subject_namespace": str(subject.get("namespace") or ""),
                    "role": role,
                    "binding": f"{kind}/{name}",
                    "source_file": rel_path,
                    "line": line,
                })
        elif kind == "ServiceAccount":
            identities.append({
                "name": name,
                "namespace": str(meta.get("namespace") or ""),
                "source_file": rel_path,
                "line": line,
            })
    return grants, bindings, identities
