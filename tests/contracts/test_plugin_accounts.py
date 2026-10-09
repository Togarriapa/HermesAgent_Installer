from __future__ import annotations

import pytest

from hermes_installer.components.plugin_accounts import (
    CodexRuntimePin,
    CodexWorkspaceIdentity,
    ComposioAction,
    ComposioProfileScope,
    GitHubAccountScope,
    GitHubOperation,
    GitHubRepository,
    PluginAccountUnavailable,
    require_codex_runtime,
    require_composio_scope,
    require_github_scope,
)


def test_github_repository_scope_separates_read_task_write_and_destructive_authority():
    repo = GitHubRepository("owner", "project")
    scope = GitHubAccountScope(
        "vault://accounts/github/token",
        frozenset({repo}),
        frozenset({GitHubOperation.REPOSITORY_READ}),
        frozenset({GitHubOperation.ISSUE_PULL_REQUEST_WRITE}),
        frozenset({GitHubOperation.ISSUE_PULL_REQUEST_WRITE}),
    )

    assert scope.authority_requirements(repo, GitHubOperation.REPOSITORY_READ) == {"github.read"}
    assert scope.authority_requirements(
        GitHubRepository("other", "project"), GitHubOperation.REPOSITORY_READ
    ) is None
    assert scope.authority_requirements(repo, GitHubOperation.ISSUE_PULL_REQUEST_WRITE) == {
        "github.write", "task.write", "destructive.confirmation"
    }


@pytest.mark.parametrize("value", [
    "ghp_secret_value",
    "https://github.com/owner/project",
    "vault://../outside",
])
def test_github_never_accepts_tokens_or_arbitrary_target_strings(value: str):
    with pytest.raises(ValueError):
        GitHubAccountScope(value, frozenset({GitHubRepository("owner", "project")}),
                           frozenset({GitHubOperation.REPOSITORY_READ}))


def test_composio_requires_profile_local_exact_action_and_confirmed_destructive_action():
    read = ComposioAction("github", "list_repositories")
    delete = ComposioAction("github", "delete_repository")
    scope = ComposioProfileScope(
        "profile-a", "vault://composio/api-key", "vault://composio/connections/profile-a",
        frozenset({read, delete}), frozenset({delete}),
    )

    assert scope.authority_requirements(read) == {"composio.connection", "composio.toolkit"}
    assert scope.authority_requirements(ComposioAction("slack", "send_message")) is None
    assert scope.authority_requirements(delete) == {
        "composio.connection", "composio.toolkit", "destructive.confirmation"
    }
    assert ComposioProfileScope(
        "profile-b", "vault://composio/key-b", "vault://composio/connection-b"
    ).authority_requirements(read) is None


def test_codex_requires_host_pinned_aarch64_cli_and_assigned_workspace_identity():
    workspace = CodexWorkspaceIdentity("task-12", "profile-a", "a" * 64)
    pin = CodexRuntimePin("0.1.0", "linux/aarch64", "b" * 64)
    assert require_codex_runtime(workspace, pin) == (workspace, pin)

    with pytest.raises(ValueError, match="Linux ARM64"):
        CodexRuntimePin("0.1.0", "darwin/arm64", "b" * 64)
    with pytest.raises(ValueError, match="SHA-256"):
        CodexWorkspaceIdentity("task-12", "profile-a", "/tmp/workspace")


@pytest.mark.parametrize("resolver,value", [
    (require_github_scope, True),
    (require_composio_scope, {"toolkits": ["github"]}),
    (require_codex_runtime, (True, True)),
])
def test_missing_host_enrollment_fails_closed(resolver, value):
    with pytest.raises(PluginAccountUnavailable):
        if resolver is require_codex_runtime:
            resolver(*value)
        else:
            resolver(value)
