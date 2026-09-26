"""Tests for the Kubernetes RBAC reader (v2.5 IaC evidence)."""

import os

from safeai.iac.k8s import parse_k8s_file

FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "iac", "kubernetes",
    "representative", "rbac.yaml")


def _read_fixture():
    with open(FIXTURE, encoding="utf-8") as handle:
        return handle.read()


def test_representative_fixture_yields_expected_records():
    grants, bindings, identities = parse_k8s_file("rbac.yaml", _read_fixture())
    assert len(grants) == 1
    grant = grants[0]
    assert grant["principal"] == "Role/agent-reader"
    assert grant["action"] == "get,list"
    assert grant["resource"] == "pods,configmaps"
    assert grant["scope"] == "prod"
    assert grant["provenance"] == "repo-iac-observed"
    assert grant["family"] == "kubernetes"
    assert grant["line"] >= 1
    assert len(bindings) == 1
    binding = bindings[0]
    assert binding["subject_kind"] == "ServiceAccount"
    assert binding["subject_name"] == "agent-sa"
    assert binding["role"] == "agent-reader"
    assert binding["binding"] == "RoleBinding/agent-binding"
    assert len(identities) == 1
    assert identities[0]["name"] == "agent-sa"
    assert identities[0]["namespace"] == "prod"


def test_cluster_scope_uses_wildcard_scope():
    text = (
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n"
        "  name: super\n"
        "rules:\n"
        "- apiGroups: ['*']\n"
        "  resources: ['*']\n"
        "  verbs: ['*']\n"
    )
    grants, _, _ = parse_k8s_file("c.yaml", text)
    assert len(grants) == 1
    assert grants[0]["scope"] == "*"
    assert grants[0]["action"] == "*"
    assert grants[0]["resource"] == "*"


def test_non_rbac_documents_ignored():
    text = (
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: agent\n"
        "spec:\n"
        "  replicas: 2\n"
        "---\n"
        "just a string\n"
        "---\n"
        "42\n"
    )
    assert parse_k8s_file("d.yaml", text) == ([], [], [])


def test_github_workflow_yaml_ignored():
    text = (
        "name: CI\n"
        "on: [push]\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: pytest\n"
    )
    assert parse_k8s_file("ci.yaml", text) == ([], [], [])


def test_malformed_yaml_never_raises():
    assert parse_k8s_file("bad.yaml", ":\t: [\n{{{") == ([], [], [])
    assert parse_k8s_file("empty.yaml", "") == ([], [], [])
    assert parse_k8s_file("null.yaml", "null\n") == ([], [], [])
