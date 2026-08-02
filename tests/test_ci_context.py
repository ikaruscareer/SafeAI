"""CI context detection.

Every test injects an environment dict. Nothing here reads or mutates
the real process environment.
"""

import json

from safeai.kya.ci_context import CONTEXT_FIELDS, detect_ci_context


def test_unknown_outside_ci():
    context = detect_ci_context({})
    assert context["provider"] == "unknown"
    assert all(context[field] is None for field in CONTEXT_FIELDS if field != "provider")


def test_context_always_has_every_field():
    for env in ({}, {"GITHUB_ACTIONS": "true"}, {"GITLAB_CI": "true"}, {"TF_BUILD": "True"}):
        assert set(detect_ci_context(env)) == set(CONTEXT_FIELDS)


def test_github_actions_pull_request(tmp_path):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({
        "pull_request": {"number": 42, "base": {"ref": "main"}, "head": {"ref": "feature"}}
    }), encoding="utf-8")

    context = detect_ci_context({
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "acme/agents",
        "GITHUB_SHA": "abc123",
        "GITHUB_REF": "refs/pull/42/merge",
        "GITHUB_HEAD_REF": "feature",
        "GITHUB_EVENT_PATH": str(event),
    })

    assert context == {
        "provider": "github_actions",
        "branch": "feature",
        "base_ref": "main",
        "commit_sha": "abc123",
        "pr_number": 42,
        "repository": "acme/agents",
    }


def test_github_actions_push_strips_ref_prefix():
    context = detect_ci_context({
        "GITHUB_ACTIONS": "true",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "acme/agents",
    })
    assert context["branch"] == "main"
    assert context["pr_number"] is None


def test_github_pr_number_recovered_from_ref_without_payload():
    context = detect_ci_context({
        "GITHUB_ACTIONS": "true",
        "GITHUB_REF": "refs/pull/7/merge",
    })
    assert context["pr_number"] == 7


def test_github_missing_event_payload_does_not_raise(tmp_path):
    context = detect_ci_context({
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_PATH": str(tmp_path / "absent.json"),
        "GITHUB_BASE_REF": "main",
    })
    assert context["provider"] == "github_actions"
    assert context["base_ref"] == "main"
    assert context["pr_number"] is None


def test_github_malformed_event_payload_does_not_raise(tmp_path):
    event = tmp_path / "event.json"
    event.write_text("{ this is not json", encoding="utf-8")
    context = detect_ci_context({"GITHUB_ACTIONS": "true", "GITHUB_EVENT_PATH": str(event)})
    assert context["provider"] == "github_actions"
    assert context["pr_number"] is None


def test_gitlab_merge_request():
    context = detect_ci_context({
        "GITLAB_CI": "true",
        "CI_PROJECT_PATH": "acme/agents",
        "CI_COMMIT_SHA": "def456",
        "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "feature",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
        "CI_MERGE_REQUEST_IID": "9",
    })
    assert context == {
        "provider": "gitlab_ci",
        "branch": "feature",
        "base_ref": "main",
        "commit_sha": "def456",
        "pr_number": 9,
        "repository": "acme/agents",
    }


def test_gitlab_branch_pipeline_falls_back_to_default_branch():
    context = detect_ci_context({
        "GITLAB_CI": "true",
        "CI_COMMIT_REF_NAME": "topic",
        "CI_DEFAULT_BRANCH": "main",
    })
    assert context["branch"] == "topic"
    assert context["base_ref"] == "main"
    assert context["pr_number"] is None


def test_azure_pipelines_pull_request():
    context = detect_ci_context({
        "TF_BUILD": "True",
        "BUILD_REPOSITORY_NAME": "acme/agents",
        "BUILD_SOURCEVERSION": "aaa111",
        "SYSTEM_PULLREQUEST_SOURCEBRANCH": "refs/heads/feature",
        "SYSTEM_PULLREQUEST_TARGETBRANCH": "refs/heads/main",
        "SYSTEM_PULLREQUEST_PULLREQUESTID": "17",
    })
    assert context == {
        "provider": "azure_pipelines",
        "branch": "feature",
        "base_ref": "main",
        "commit_sha": "aaa111",
        "pr_number": 17,
        "repository": "acme/agents",
    }


def test_non_numeric_pr_number_degrades_to_none():
    context = detect_ci_context({"GITLAB_CI": "true", "CI_MERGE_REQUEST_IID": "not-a-number"})
    assert context["pr_number"] is None


def test_blank_values_are_treated_as_absent():
    context = detect_ci_context({
        "GITHUB_ACTIONS": "true",
        "GITHUB_HEAD_REF": "   ",
        "GITHUB_REF": "refs/heads/main",
    })
    assert context["branch"] == "main"


def test_detection_is_deterministic():
    env = {"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/main"}
    assert detect_ci_context(env) == detect_ci_context(env)
