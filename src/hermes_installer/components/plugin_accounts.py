"""Typed, fail-closed account contracts for the Resources plugins.

The Resources manifests describe scope; they do not contain credentials or
select arbitrary endpoints.  These records validate the protected settings a
host binding must supply.  They deliberately do not implement OAuth, GitHub
HTTP, Composio HTTP, or process execution: those effects belong behind the
root authority broker and the current runtime has not enrolled those brokers.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re


class PluginAccountUnavailable(RuntimeError):
    """The host has not enrolled the account or effect boundary required."""


class GitHubOperation(StrEnum):
    REPOSITORY_READ = "repository-read"
    ISSUE_PULL_REQUEST_READ = "issue-and-pull-request-read"
    WORKFLOW_STATUS_READ = "workflow-and-status-read"
    REPOSITORY_CONTENT_WRITE = "repository-content-write"
    ISSUE_PULL_REQUEST_WRITE = "issue-and-pull-request-write"


@dataclass(frozen=True, slots=True, order=True)
class GitHubRepository:
    owner: str
    name: str

    def __post_init__(self) -> None:
        if not _SLUG.fullmatch(self.owner) or not _SLUG.fullmatch(self.name):
            raise ValueError("GitHub repository must be an exact owner/name slug")

    @property
    def identity(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass(frozen=True, slots=True)
class GitHubAccountScope:
    """Non-secret host-vault reference and exact account/repository ceiling."""

    credential_ref: str
    repositories: frozenset[GitHubRepository]
    read_operations: frozenset[GitHubOperation]
    task_write_operations: frozenset[GitHubOperation] = frozenset()
    destructive_operations: frozenset[GitHubOperation] = frozenset()

    def __post_init__(self) -> None:
        _reference(self.credential_ref)
        if not self.repositories:
            raise ValueError("GitHub account scope requires at least one exact repository")
        if self.read_operations - _GITHUB_READS:
            raise ValueError("GitHub read allowlist contains a non-read operation")
        if self.task_write_operations - _GITHUB_WRITES:
            raise ValueError("GitHub task-write allowlist contains a non-write operation")
        if self.destructive_operations - self.task_write_operations:
            raise ValueError("destructive GitHub operations must also be explicitly task-enabled")

    def authority_requirements(self, repository: GitHubRepository,
                               operation: GitHubOperation) -> frozenset[str] | None:
        """Describe authority required; this is never an authorization decision."""
        if repository not in self.repositories:
            return None
        if operation in self.read_operations:
            return frozenset({"github.read"})
        if operation not in self.task_write_operations:
            return None
        required = {"github.write", "task.write"}
        if operation in self.destructive_operations:
            required.add("destructive.confirmation")
        return frozenset(required)


@dataclass(frozen=True, slots=True, order=True)
class ComposioAction:
    toolkit: str
    action: str

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.toolkit) or not _IDENTIFIER.fullmatch(self.action):
            raise ValueError("Composio toolkit/action must use exact catalog identifiers")


@dataclass(frozen=True, slots=True)
class ComposioProfileScope:
    """A per-profile allowlist and opaque handle to a host-held API secret."""

    profile_id: str
    credential_handle: str
    connection_handle: str
    actions: frozenset[ComposioAction] = frozenset()
    destructive_actions: frozenset[ComposioAction] = frozenset()

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.profile_id):
            raise ValueError("Composio profile identity is invalid")
        _reference(self.credential_handle)
        _reference(self.connection_handle)
        if self.destructive_actions - self.actions:
            raise ValueError("destructive actions must also be explicitly allowlisted")

    def authority_requirements(self, action: ComposioAction) -> frozenset[str] | None:
        """Describe required authority for an allowlisted action without granting it."""
        if action not in self.actions:
            return None
        required = {"composio.connection", "composio.toolkit"}
        if action in self.destructive_actions:
            required.add("destructive.confirmation")
        return frozenset(required)


@dataclass(frozen=True, slots=True)
class CodexWorkspaceIdentity:
    """Host-created workspace identity; callers never provide paths or argv."""

    workspace_id: str
    profile_id: str
    root_identity: str
    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.workspace_id) or not _IDENTIFIER.fullmatch(self.profile_id):
            raise ValueError("Codex workspace/profile identity is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.root_identity):
            raise ValueError("Codex workspace root must be pinned by a SHA-256 identity")


@dataclass(frozen=True, slots=True)
class CodexRuntimePin:
    """Verified host-managed Codex CLI pin, not a caller-selected executable."""

    version: str
    architecture: str
    executable_sha256: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", self.version):
            raise ValueError("Codex CLI version must be pinned")
        if self.architecture != "linux/aarch64":
            raise ValueError("Codex CLI runtime must be pinned for Linux ARM64")
        if not re.fullmatch(r"[0-9a-f]{64}", self.executable_sha256):
            raise ValueError("Codex CLI executable must be pinned by SHA-256")


def require_github_scope(value: object) -> GitHubAccountScope:
    if type(value) is not GitHubAccountScope:
        raise PluginAccountUnavailable(
            "GitHub host-vault reference and exact repository/task-write scope are not enrolled"
        )
    return value


def require_composio_scope(value: object) -> ComposioProfileScope:
    if type(value) is not ComposioProfileScope:
        raise PluginAccountUnavailable(
            "Composio OAuth connection, profile toolkit/action allowlist, or vault handle is not enrolled"
        )
    return value


def require_codex_runtime(workspace: object, pin: object) -> tuple[CodexWorkspaceIdentity, CodexRuntimePin]:
    if type(workspace) is not CodexWorkspaceIdentity or type(pin) is not CodexRuntimePin:
        raise PluginAccountUnavailable(
            "Codex host authentication, assigned workspace, or verified managed ARM64 CLI is not enrolled"
        )
    return workspace, pin


def _reference(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"vault://[a-zA-Z0-9][a-zA-Z0-9._/-]{0,190}", value):
        raise ValueError("credential and connection values must be opaque vault references")


_SLUG = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_GITHUB_READS = frozenset({
    GitHubOperation.REPOSITORY_READ,
    GitHubOperation.ISSUE_PULL_REQUEST_READ,
    GitHubOperation.WORKFLOW_STATUS_READ,
})
_GITHUB_WRITES = frozenset({
    GitHubOperation.REPOSITORY_CONTENT_WRITE,
    GitHubOperation.ISSUE_PULL_REQUEST_WRITE,
})


GITHUB_PLUGIN_VERSION = "1.0.1"
COMPOSIO_PLUGIN_VERSION = "1.0.0"
CODEX_PLUGIN_VERSION = "1.0.1"
