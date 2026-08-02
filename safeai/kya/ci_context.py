"""Continuous-integration context detection.

SafeAI's PR comment needs to know which branch it is comparing against
and, where available, which pull request it belongs to. That information
lives in provider-specific environment variables.

Three rules govern this module:

* **No network, no shelling out.** Only environment variables and, for
  GitHub Actions, the event payload file that the runner itself wrote.
* **Never raise.** CI metadata is a convenience. A missing variable, an
  unreadable file, or malformed JSON degrades to ``None``; a broken
  runner must never fail a security scan.
* **Injectable environment.** ``detect_ci_context(env=...)`` accepts a
  mapping so tests never mutate real process state.

The returned dictionary always has the same keys, so callers can read
them unconditionally.
"""

import json
import os

#: Every context has these keys, whatever the provider.
CONTEXT_FIELDS = ("provider", "branch", "base_ref", "commit_sha", "pr_number", "repository")

#: Providers this release understands, in detection order.
PROVIDERS = ("github_actions", "gitlab_ci", "azure_pipelines")


def _empty_context(provider="unknown"):
    context = {field: None for field in CONTEXT_FIELDS}
    context["provider"] = provider
    return context


def _clean(value):
    """Return a trimmed string, or ``None`` for empty/absent values."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _strip_ref(value):
    """Reduce a git ref to its short name.

    ``refs/heads/main`` -> ``main``; ``refs/pull/12/merge`` is left alone
    because it is not a branch name and pretending otherwise would be a
    small lie in a security artifact.
    """
    text = _clean(value)
    if text is None:
        return None
    for prefix in ("refs/heads/", "refs/tags/"):
        if text.startswith(prefix):
            return text[len(prefix):]
    return text


def _int_or_none(value):
    text = _clean(value)
    if text is None:
        return None
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _read_event_payload(path):
    """Return the GitHub Actions event payload, or ``None``.

    The payload is written by the runner into the workspace. It is read
    as plain JSON; nothing from it is executed or interpolated.
    """
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _github_context(env):
    context = _empty_context("github_actions")
    context["repository"] = _clean(env.get("GITHUB_REPOSITORY"))
    context["commit_sha"] = _clean(env.get("GITHUB_SHA"))

    # On pull_request events GITHUB_REF is refs/pull/N/merge, so the head
    # branch comes from GITHUB_HEAD_REF instead.
    head_ref = _clean(env.get("GITHUB_HEAD_REF"))
    context["branch"] = head_ref or _strip_ref(env.get("GITHUB_REF"))
    context["base_ref"] = _strip_ref(env.get("GITHUB_BASE_REF"))

    payload = _read_event_payload(_clean(env.get("GITHUB_EVENT_PATH")))
    pull_request = (payload or {}).get("pull_request")
    if isinstance(pull_request, dict):
        context["pr_number"] = _int_or_none(pull_request.get("number"))
        base = pull_request.get("base")
        if context["base_ref"] is None and isinstance(base, dict):
            context["base_ref"] = _strip_ref(base.get("ref"))
        head = pull_request.get("head")
        if context["branch"] is None and isinstance(head, dict):
            context["branch"] = _strip_ref(head.get("ref"))
    if context["pr_number"] is None:
        # refs/pull/12/merge -> 12
        ref = _clean(env.get("GITHUB_REF")) or ""
        parts = ref.split("/")
        if len(parts) >= 3 and parts[0] == "refs" and parts[1] == "pull":
            context["pr_number"] = _int_or_none(parts[2])
    return context


def _gitlab_context(env):
    context = _empty_context("gitlab_ci")
    context["repository"] = _clean(env.get("CI_PROJECT_PATH"))
    context["commit_sha"] = _clean(env.get("CI_COMMIT_SHA"))
    context["branch"] = (
        _clean(env.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"))
        or _clean(env.get("CI_COMMIT_REF_NAME"))
    )
    context["base_ref"] = (
        _clean(env.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"))
        or _clean(env.get("CI_DEFAULT_BRANCH"))
    )
    context["pr_number"] = _int_or_none(env.get("CI_MERGE_REQUEST_IID"))
    return context


def _azure_context(env):
    context = _empty_context("azure_pipelines")
    context["repository"] = _clean(env.get("BUILD_REPOSITORY_NAME"))
    context["commit_sha"] = _clean(env.get("BUILD_SOURCEVERSION"))
    context["branch"] = (
        _strip_ref(env.get("SYSTEM_PULLREQUEST_SOURCEBRANCH"))
        or _strip_ref(env.get("BUILD_SOURCEBRANCH"))
    )
    context["base_ref"] = _strip_ref(env.get("SYSTEM_PULLREQUEST_TARGETBRANCH"))
    context["pr_number"] = _int_or_none(env.get("SYSTEM_PULLREQUEST_PULLREQUESTID"))
    return context


def _is_github(env):
    return _clean(env.get("GITHUB_ACTIONS")) is not None or (
        _clean(env.get("GITHUB_REPOSITORY")) is not None
        and _clean(env.get("GITHUB_RUN_ID")) is not None
    )


def _is_gitlab(env):
    return _clean(env.get("GITLAB_CI")) is not None or _clean(env.get("CI_PROJECT_PATH")) is not None


def _is_azure(env):
    return (
        _clean(env.get("TF_BUILD")) is not None
        or _clean(env.get("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI")) is not None
    )


def detect_ci_context(env=None):
    """Return the CI context for ``env`` (defaults to the real environment).

    The result always contains every key in :data:`CONTEXT_FIELDS`. When
    no supported provider is detected, ``provider`` is ``"unknown"`` and
    every other field is ``None``. This function never raises.
    """
    try:
        environment = os.environ if env is None else env
        if _is_github(environment):
            return _github_context(environment)
        if _is_gitlab(environment):
            return _gitlab_context(environment)
        if _is_azure(environment):
            return _azure_context(environment)
    except Exception:  # pragma: no cover - defensive; CI metadata is optional
        return _empty_context()
    return _empty_context()
