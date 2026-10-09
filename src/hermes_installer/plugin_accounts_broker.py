"""Root-side fixed-effect handlers for the GitHub, Composio and Codex plugins.

The caller supplies a canonical, source-scoped action request. This module
resolves only root-selected enrollment records, validates their immutable
schemas, and dispatches through fixed transports. It never accepts a URL,
shell, executable, credential, recipient, or filesystem path from the caller.
AuthorityService enrollment/registration remains the root daemon's concern.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import sqlite3
import stat
import threading
import time
import uuid
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import quote

from hermes_installer.authority.types import AuthorityDenied, EffectAuthorization, HostContext, canonical_digest
from hermes_installer.network import BoundedNetwork, NetworkError

MAX_PLUGIN_REQUEST = 262_144
MAX_PLUGIN_RESPONSE = 2_097_152
MAX_ACTION_DEADLINE = 30.0

_MANIFESTS = {
    "github": "f08aa0f34d79eb20cf1ad1c65cc0275b6079c374204435730ef14fdab3fa8f6c",
    "composio": "93fe2f7b966a05d43732b66a2340606e44aba5a4dd813a7cc7f71ab40743e885",
    "codex": "7b169020508e4d51367e22bf29a1363ad8a51f24ce1b2b9731ac5fe462942b62",
}
_OPERATIONS = {
    "github": frozenset({"plugin.github.read", "plugin.github.write", "plugin.github.admin"}),
    "composio": frozenset({"plugin.composio.invoke"}),
    "codex": frozenset({"plugin.codex.run"}),
}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_HEX256 = re.compile(r"^[0-9a-f]{64}$")


class PluginEffectDenied(PermissionError):
    """A plugin effect was rejected without leaking credentials or provider data."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PluginActionEnrollment:
    """One root-selected immutable action, target, schema and authority binding."""

    adapter_id: str
    manifest_sha256: str
    handler_artifact_id: str
    handler_sha256: str
    action_id: str
    argument_schema_id: str
    operation: str
    capability: str
    target_id: str
    generation: str
    principal_id: str
    profile_id: str
    recipient: str
    enrollment_id: str
    argument_schema: Mapping[str, Any]
    request_bytes_limit: int = MAX_PLUGIN_REQUEST
    response_bytes_limit: int = MAX_PLUGIN_RESPONSE
    deadline_seconds: float = MAX_ACTION_DEADLINE
    credential_reference_id: str | None = None
    scope_reference_id: str | None = None
    confirmation_policy_id: str | None = None
    idempotency_policy_id: str | None = None
    mutating: bool = False
    verify_after_write: bool = False
    verification_action_id: str | None = None

    def __post_init__(self) -> None:
        if self.adapter_id not in _OPERATIONS:
            raise ValueError("plugin action adapter is not supported")
        if self.manifest_sha256 != _MANIFESTS[self.adapter_id]:
            raise ValueError("plugin action manifest digest differs from the reviewed vendor source")
        for name in ("handler_sha256",):
            if not _HEX256.fullmatch(getattr(self, name)):
                raise ValueError(f"{name} must be a SHA-256 digest")
        for name in ("handler_artifact_id", "action_id", "argument_schema_id", "target_id",
                     "generation", "principal_id", "profile_id", "recipient", "enrollment_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
                raise ValueError(f"plugin action {name} is invalid")
        if self.operation not in _OPERATIONS[self.adapter_id]:
            raise ValueError("plugin action operation is outside the adapter's fixed verbs")
        if self.adapter_id == "codex" and not self.mutating:
            raise ValueError("Codex execution can change its assigned workspace and must use write authority")
        if self.capability != f"plugin:{self.adapter_id}":
            raise ValueError("plugin action capability must be exact and adapter-scoped")
        if (type(self.request_bytes_limit) is not int or not 1 <= self.request_bytes_limit <= MAX_PLUGIN_REQUEST
                or type(self.response_bytes_limit) is not int or not 1 <= self.response_bytes_limit <= MAX_PLUGIN_RESPONSE
                or isinstance(self.deadline_seconds, bool) or not isinstance(self.deadline_seconds, (int, float))
                or not math.isfinite(self.deadline_seconds) or not .1 <= self.deadline_seconds <= MAX_ACTION_DEADLINE):
            raise ValueError("plugin action bounds exceed the global limits")
        if self.mutating and not self.idempotency_policy_id:
            raise ValueError("mutating plugin actions require a protected idempotency policy")
        if self.mutating and not self.verify_after_write and self.adapter_id == "github":
            raise ValueError("GitHub write actions must verify the remote result")
        if self.verify_after_write and not self.verification_action_id:
            raise ValueError("verify-after-write requires a fixed read action ID")
        if not isinstance(self.argument_schema, Mapping):
            raise ValueError("plugin action requires a root-enrolled argument schema")
        schema = _freeze_schema(self.argument_schema)
        _validate_schema_definition(schema)
        object.__setattr__(self, "argument_schema", schema)
        for name in ("credential_reference_id", "scope_reference_id", "confirmation_policy_id",
                     "idempotency_policy_id", "verification_action_id"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not _IDENTIFIER.fullmatch(value)):
                raise ValueError(f"plugin action {name} is invalid")

    @property
    def target(self) -> str:
        return f"plugin:{self.adapter_id}:{self.target_id}:{self.generation}"


@dataclass(frozen=True, slots=True)
class PluginAccountEnrollment:
    """Root-owned adapter account scope; references resolve only in root custody."""

    adapter_id: str
    enrollment_id: str
    principal_id: str
    profile_id: str
    recipient: str
    credential_reference_id: str | None
    credential_scope: str
    account_id: str
    action_ids: frozenset[str]
    repositories: frozenset[str] = frozenset()
    composio_connections: Mapping[str, str] = field(default_factory=dict)
    toolkit_versions: Mapping[str, str] = field(default_factory=dict)
    codex_workspaces: Mapping[str, "CodexWorkspaceBinding"] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.adapter_id not in _OPERATIONS:
            raise ValueError("plugin account adapter is unsupported")
        for name in ("enrollment_id", "principal_id", "profile_id", "recipient", "account_id"):
            if not isinstance(getattr(self, name), str) or not _IDENTIFIER.fullmatch(getattr(self, name)):
                raise ValueError(f"plugin account {name} is invalid")
        if self.adapter_id == "codex":
            if self.credential_reference_id is not None or self.credential_scope:
                raise ValueError("Codex must use host-managed authentication without copied credentials")
        elif (not isinstance(self.credential_reference_id, str) or not _IDENTIFIER.fullmatch(self.credential_reference_id)
              or not isinstance(self.credential_scope, str) or not _IDENTIFIER.fullmatch(self.credential_scope)):
            raise ValueError("account credential must be a protected scoped vault reference")
        if not isinstance(self.action_ids, (set, frozenset)) or not self.action_ids or any(
                not isinstance(item, str) or not _IDENTIFIER.fullmatch(item) for item in self.action_ids):
            raise ValueError("plugin account action allowlist is empty or malformed")
        object.__setattr__(self, "action_ids", frozenset(self.action_ids))
        if not isinstance(self.repositories, (set, frozenset)):
            raise ValueError("GitHub repository scope must be an immutable exact allowlist")
        object.__setattr__(self, "repositories", frozenset(self.repositories))
        if self.adapter_id == "github" and (not self.repositories or any(not _REPO.fullmatch(item) for item in self.repositories)):
            raise ValueError("GitHub enrollment requires exact owner/repository allowlist")
        if self.adapter_id == "composio":
            if not self.composio_connections or not self.toolkit_versions:
                raise ValueError("Composio enrollment requires explicit user connections and pinned toolkit versions")
            if any(not _TOOL_SLUG.fullmatch(slug) or not _OPAQUE_ID.fullmatch(value)
                   for slug, value in self.composio_connections.items()):
                raise ValueError("Composio connection map is invalid")
            if any(not _TOOL_SLUG.fullmatch(slug) or not _TOOL_VERSION.fullmatch(value)
                   for slug, value in self.toolkit_versions.items()):
                raise ValueError("Composio toolkit version map is invalid")
        if self.adapter_id == "codex" and not self.codex_workspaces:
            raise ValueError("Codex enrollment requires exact host-assigned workspaces")
        object.__setattr__(self, "composio_connections", MappingProxyType(dict(self.composio_connections)))
        object.__setattr__(self, "toolkit_versions", MappingProxyType(dict(self.toolkit_versions)))
        object.__setattr__(self, "codex_workspaces", MappingProxyType(dict(self.codex_workspaces)))


@dataclass(frozen=True, slots=True)
class CodexWorkspaceBinding:
    workspace_id: str
    root: Path
    root_identity: str
    writable: bool
    service_profile_id: str

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.workspace_id) or not _IDENTIFIER.fullmatch(self.service_profile_id):
            raise ValueError("Codex workspace IDs are invalid")
        if not isinstance(self.root, Path) or not self.root.is_absolute() or not _HEX256.fullmatch(self.root_identity):
            raise ValueError("Codex workspace requires an enrolled absolute root and SHA-256 identity")
        if type(self.writable) is not bool:
            raise ValueError("Codex workspace write permission must be a protected boolean")


class CredentialVault(Protocol):
    def resolve_reference(self, reference: str, *, peer_uid: int,
                          required_scope: str, principal_id: str) -> str: ...


class HumanConfirmationVerifier(Protocol):
    def consume_plugin_confirmation(self, *, attestation_id: str, context: HostContext,
                                    authorization: EffectAuthorization,
                                    action_id: str, payload_digest: str,
                                    enrollment_id: str, target: str) -> object: ...


class PluginEffectBackend(Protocol):
    def invoke(self, *, enrollment: PluginAccountEnrollment, action: PluginActionEnrollment,
               arguments: Mapping[str, Any], credential: str | None, idempotency_key: str | None,
               timeout: float,
               cancelled: Callable[[], bool]) -> Mapping[str, Any]: ...

    def verify(self, *, enrollment: PluginAccountEnrollment, action: PluginActionEnrollment,
               arguments: Mapping[str, Any], credential: str | None, idempotency_key: str | None,
               response: Mapping[str, Any],
               timeout: float, cancelled: Callable[[], bool]) -> bool: ...


class CodexManagedRunner(Protocol):
    """Root-owned process broker for one enrolled Codex toolchain/workspace."""

    toolchain_lock_sha256: str
    architecture: str

    def run_managed(self, *, workspace: CodexWorkspaceBinding, prompt: str, idempotency_key: str,
                    timeout: float, cancelled: Callable[[], bool]) -> Mapping[str, Any]: ...


class GitHubRESTBackend:
    """Finite GitHub REST actions; host, HTTP verb and route are adapter constants."""

    API = "https://api.github.com"
    def __init__(self, network: BoundedNetwork):
        self.network = network

    def invoke(self, *, enrollment, action, arguments, credential, idempotency_key,
               timeout, cancelled):
        if not credential:
            raise PluginEffectDenied("github.unavailable", "GitHub REST transport or vault credential is unavailable")
        _check_transport_deadline(self.network, timeout)
        repository = arguments.get("repository")
        if not isinstance(repository, str) or repository not in enrollment.repositories or not _REPO.fullmatch(repository):
            raise PluginEffectDenied("github.repository", "repository is outside the root allowlist")
        base = f"{self.API}/repos/{quote(repository, safe='/')}"
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {credential}",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "HermesInstaller-Resources"}
        op = action.action_id
        if op == "repo.get" and action.operation == "plugin.github.read":
            method, path, body = "GET", "", None
        elif op == "issues.list" and action.operation == "plugin.github.read":
            method, path, body = "GET", "/issues?per_page=30&state=open", None
        elif op == "content.get" and action.operation == "plugin.github.read":
            path_value = _github_path(arguments.get("path"))
            method, path, body = "GET", "/contents/" + quote(path_value, safe="/"), None
        elif op == "content.put" and action.operation == "plugin.github.write":
            path_value = _github_path(arguments.get("path"))
            content = arguments.get("content")
            sha = arguments.get("sha")
            if not isinstance(content, str) or len(content.encode("utf-8")) > 700_000:
                raise PluginEffectDenied("github.content", "content is outside the enrolled bound")
            message = arguments.get("message")
            if not isinstance(message, str) or not 1 <= len(message) <= 256:
                raise PluginEffectDenied("github.message", "commit message is outside the enrolled bound")
            # GitHub requires SHA for updates. A missing SHA is allowed only for a new file.
            if sha is not None and (not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha)):
                raise PluginEffectDenied("github.sha", "content update SHA is malformed")
            data = {"message": arguments.get("message"), "content": base64.b64encode(content.encode()).decode("ascii")}
            if sha:
                data["sha"] = sha
            method, path, body = "PUT", "/contents/" + quote(path_value, safe="/"), _canonical_json(data)
        elif op == "issue.create" and action.operation == "plugin.github.write":
            title, issue_body = arguments.get("title"), arguments.get("body", "")
            if not isinstance(title, str) or not 1 <= len(title) <= 256 or not isinstance(issue_body, str) or len(issue_body) > 60_000:
                raise PluginEffectDenied("github.issue", "issue fields exceed the enrolled bounds")
            marker = f"\n\n<!-- hermes-idempotency:{idempotency_key} -->"
            method, path = "POST", "/issues"
            body = _canonical_json({"title": title, "body": issue_body + marker})
        else:
            raise PluginEffectDenied("github.action", "GitHub action is not in the fixed adapter catalog")
        if body is not None:
            headers["Content-Type"] = "application/json"
        # BoundedNetwork rejects redirects and proxies and applies TLS verification.
        try:
            response = self.network.request(base + path, method=method, headers=headers, body=body,
                                            cancelled=cancelled)
        except NetworkError:
            raise PluginEffectDenied("github.unknown", "GitHub request failed or its outcome is unknown") from None
        if response.status not in ({200, 201} if method in {"PUT", "POST"} else {200}):
            raise PluginEffectDenied("github.status", "GitHub returned a non-success response")
        try:
            result = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise PluginEffectDenied("github.response", "GitHub response was invalid JSON") from None
        if not isinstance(result, dict):
            raise PluginEffectDenied("github.response", "GitHub response shape was invalid")
        return result

    def verify(self, *, enrollment, action, arguments, credential, idempotency_key,
               response, timeout, cancelled):
        if not credential:
            return False
        try:
            _check_transport_deadline(self.network, timeout)
        except PluginEffectDenied:
            return False
        repository = arguments.get("repository")
        if repository not in enrollment.repositories or not _REPO.fullmatch(repository):
            return False
        base = f"{self.API}/repos/{quote(repository, safe='/')}"
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {credential}",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "HermesInstaller-Resources"}
        try:
            if action.action_id == "content.put":
                path = _github_path(arguments.get("path"))
                check = self.network.request(base + "/contents/" + quote(path, safe="/"), headers=headers,
                                             cancelled=cancelled)
                value = json.loads(check.body.decode("utf-8")) if check.status == 200 else None
                expected_content = base64.b64encode(arguments["content"].encode()).decode("ascii")
                return isinstance(value, dict) and value.get("content", "").replace("\n", "") == expected_content
            if action.action_id == "issue.create":
                number = response.get("number")
                if type(number) is not int or not 1 <= number <= 2**31 - 1:
                    return False
                check = self.network.request(base + f"/issues/{number}", headers=headers, cancelled=cancelled)
                value = json.loads(check.body.decode("utf-8")) if check.status == 200 else None
                marker = f"<!-- hermes-idempotency:{idempotency_key} -->"
                return (isinstance(value, dict) and value.get("title") == arguments.get("title")
                        and isinstance(value.get("body"), str) and marker in value["body"])
        except (NetworkError, KeyError, ValueError, json.JSONDecodeError):
            return False
        return False


class ComposioToolBackend:
    """Calls only a pre-enrolled Composio tool slug and connected account."""

    API = "https://backend.composio.dev/api/v3.1/tools/execute/"
    def __init__(self, network: BoundedNetwork):
        self.network = network

    def invoke(self, *, enrollment, action, arguments, credential, idempotency_key,
               timeout, cancelled):
        _check_transport_deadline(self.network, timeout)
        slug = action.action_id
        connection = enrollment.composio_connections.get(slug)
        version = enrollment.toolkit_versions.get(slug)
        if (not credential or connection is None or version is None or not _TOOL_SLUG.fullmatch(slug)
                or not _TOOL_VERSION.fullmatch(version)):
            raise PluginEffectDenied("composio.binding", "Composio tool or user connection is not enrolled")
        headers = {"Authorization": f"Bearer {credential}", "Content-Type": "application/json",
                   "Accept": "application/json"}
        body = _canonical_json({"connected_account_id": connection, "version": version,
                                "arguments": arguments})
        try:
            response = self.network.request(self.API + quote(slug, safe=""), method="POST",
                headers=headers, body=body, cancelled=cancelled)
        except NetworkError:
            raise PluginEffectDenied("composio.unknown", "Composio request failed or its outcome is unknown") from None
        if response.status not in {200, 201, 202}:
            raise PluginEffectDenied("composio.status", "Composio returned a non-success response")
        try:
            result = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise PluginEffectDenied("composio.response", "Composio response was invalid JSON") from None
        if not isinstance(result, dict):
            raise PluginEffectDenied("composio.response", "Composio response shape was invalid")
        return result

    def verify(self, *, enrollment, action, arguments, credential, idempotency_key,
               response, timeout, cancelled):
        # Composio actions are catalog-specific; generic execution has no safe
        # generic postcondition. Enrollment must bind a reviewed verifier.
        return False


class CodexManagedRunnerAdapter:
    """Hands a prompt to a host-managed runner; callers never provide argv or paths."""

    def __init__(self, runner: CodexManagedRunner, *, toolchain_lock_sha256: str,
                 architecture: str):
        if (not _HEX256.fullmatch(toolchain_lock_sha256) or architecture != "arm64"
                or getattr(runner, "toolchain_lock_sha256", None) != toolchain_lock_sha256
                or getattr(runner, "architecture", None) != architecture):
            raise ValueError("Codex runner must use the pinned ARM64 host toolchain")
        self.runner = runner
        self.toolchain_lock_sha256 = toolchain_lock_sha256
        self.architecture = architecture

    def invoke(self, *, enrollment, action, arguments, credential, idempotency_key,
               timeout, cancelled):
        if credential is not None or not isinstance(idempotency_key, str) or action.action_id != "run":
            raise PluginEffectDenied("codex.binding", "Codex runner accepts only host-managed task execution")
        workspace_id, prompt = arguments.get("workspace_id"), arguments.get("prompt")
        workspace = enrollment.codex_workspaces.get(workspace_id)
        if (workspace is None or workspace.service_profile_id != enrollment.profile_id
                or not isinstance(prompt, str) or not prompt.strip() or len(prompt.encode()) > 32_768):
            raise PluginEffectDenied("codex.workspace", "Codex task lacks an enrolled workspace or bounded prompt")
        try:
            result = self.runner.run_managed(workspace=workspace, prompt=prompt, idempotency_key=idempotency_key,
                                             timeout=timeout, cancelled=cancelled)
        except Exception:
            raise PluginEffectDenied("codex.failed", "managed Codex task runner failed") from None
        if not isinstance(result, Mapping):
            raise PluginEffectDenied("codex.response", "managed Codex runner returned an invalid result")
        return result

    def verify(self, **_kwargs):
        return False


class IdempotencyLedger(Protocol):
    def claim(self, key: str, request_digest: str, operation_id: str) -> Mapping[str, Any]: ...
    def finish(self, key: str, state: str, receipt: Mapping[str, Any]) -> None: ...


class SQLitePluginEffectLedger:
    """Root-state duplicate ledger. Ambiguous writes are terminal until explicit reconciliation."""

    _STATES = {"pending", "committed", "ambiguous", "read-complete", "failed-before-effect"}

    def __init__(self, path: Path):
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("plugin effect ledger path must be root-selected and absolute")
        parent = path.parent
        if parent.is_symlink() or not parent.is_dir() or stat.S_IMODE(parent.stat().st_mode) & 0o077:
            raise ValueError("plugin effect ledger parent must be an existing private directory")
        if path.is_symlink() or path.exists() and (not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077):
            raise ValueError("plugin effect ledger must be a private regular file")
        self.path = path
        self._lock = threading.RLock()
        with closing(self._connect()) as db:
            db.execute("CREATE TABLE IF NOT EXISTS plugin_effects (key TEXT PRIMARY KEY, digest TEXT NOT NULL, operation_id TEXT NOT NULL, state TEXT NOT NULL, receipt TEXT NOT NULL)")
        path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=3.0, isolation_level=None)
        db.execute("PRAGMA busy_timeout=3000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def claim(self, key: str, request_digest: str, operation_id: str) -> Mapping[str, Any]:
        if not _HEX256.fullmatch(key) or not _HEX256.fullmatch(request_digest) or not _HEX256.fullmatch(operation_id):
            raise PluginEffectDenied("ledger.key", "plugin idempotency binding is invalid")
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                prior = db.execute("SELECT digest, operation_id, state, receipt FROM plugin_effects WHERE key=?", (key,)).fetchone()
                if prior:
                    if prior[0] != request_digest:
                        raise PluginEffectDenied("ledger.digest", "idempotency key is bound to another payload")
                    db.execute("COMMIT")
                    return {"digest": prior[0], "operation_id": prior[1], "state": prior[2], "receipt": json.loads(prior[3])}
                db.execute("INSERT INTO plugin_effects VALUES(?,?,?,'pending','{}')", (key, request_digest, operation_id))
                db.execute("COMMIT")
                return {"digest": request_digest, "operation_id": operation_id, "state": "new", "receipt": {}}
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def finish(self, key: str, state: str, receipt: Mapping[str, Any]) -> None:
        if not _HEX256.fullmatch(key) or state not in self._STATES or not isinstance(receipt, Mapping):
            raise PluginEffectDenied("ledger.transition", "plugin effect ledger transition is malformed")
        safe = _redact(receipt)
        encoded = _canonical_json(safe)
        if len(encoded) > 32_768:
            raise PluginEffectDenied("ledger.receipt", "plugin effect receipt exceeds its bound")
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT state FROM plugin_effects WHERE key=?", (key,)).fetchone()
                allowed = {"pending": {"committed", "ambiguous", "failed-before-effect", "read-complete"},
                           "ambiguous": {"ambiguous", "committed"}, "committed": set(),
                           "read-complete": set(), "failed-before-effect": set()}
                if row is None or state not in allowed.get(row[0], set()):
                    raise PluginEffectDenied("ledger.transition", "plugin effect ledger transition is invalid")
                db.execute("UPDATE plugin_effects SET state=?, receipt=? WHERE key=?", (state, encoded.decode("ascii"), key))
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise


class _ActionHandler:
    def __init__(self, action: PluginActionEnrollment, enrollment: PluginAccountEnrollment,
                 backend: PluginEffectBackend, vault: CredentialVault | None,
                 ledger: IdempotencyLedger, confirmation: HumanConfirmationVerifier | None):
        self.action, self.enrollment = action, enrollment
        self.backend, self.vault, self.ledger, self.confirmation = backend, vault, ledger, confirmation

    def __call__(self, *, context: HostContext, authorization: EffectAuthorization,
                 payload: bytes, timeout: float, peer_pid: int, peer_pidfd: int | None,
                 cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        action, enrollment = self.action, self.enrollment
        request, arguments, idem, attestation = _parse_request(payload, action)
        _verify_grant(context, authorization, action, enrollment, payload, peer_pid, timeout)
        operation_id = uuid.uuid4().hex
        ledger_key = _idempotency_digest(context, action, enrollment, idem, authorization.request_digest) if action.mutating else None
        if action.confirmation_policy_id:
            if self.confirmation is None or attestation is None:
                raise PluginEffectDenied("confirmation.required", "fresh exact-payload confirmation is unavailable")
            digest = canonical_digest(payload)
            if digest != authorization.request_digest:
                raise PluginEffectDenied("confirmation.digest", "confirmation payload digest does not match")
            try:
                grant = self.confirmation.consume_plugin_confirmation(
                    attestation_id=attestation, context=context, authorization=authorization,
                    action_id=action.action_id, payload_digest=digest,
                    enrollment_id=enrollment.enrollment_id, target=action.target)
            except Exception:
                raise PluginEffectDenied("confirmation.denied", "host denied the exact plugin action confirmation") from None
            if grant is None:
                raise PluginEffectDenied("confirmation.denied", "host denied the exact plugin action confirmation")
        if cancelled() or time.monotonic() >= authorization.monotonic_expires_at:
            raise PluginEffectDenied("effect.expired", "plugin effect expired before dispatch")
        credential = None
        if action.adapter_id != "codex":
            try:
                if self.vault is None or enrollment.credential_reference_id is None:
                    raise ValueError("credential reference unavailable")
                credential = self.vault.resolve_reference(
                    enrollment.credential_reference_id, peer_uid=0,
                    required_scope=enrollment.credential_scope, principal_id=enrollment.principal_id)
            except Exception:
                raise PluginEffectDenied("credential.unavailable", "protected plugin credential is unavailable") from None
            if not isinstance(credential, str) or not credential or len(credential) > 16_384 or any(ch in credential for ch in "\x00\r\n"):
                raise PluginEffectDenied("credential.invalid", "protected plugin credential is invalid")
        if action.mutating:
            prior = self.ledger.claim(ledger_key, authorization.request_digest, operation_id)
            state = prior["state"]
            if state != "new":
                wire_state = "ambiguous" if state in {"pending", "ambiguous"} else (
                    "unavailable" if state == "failed-before-effect" else state)
                return _wire_result(prior["operation_id"], wire_state,
                                    prior.get("receipt", {}), verification="reconciliation-required",
                                    resume_action_id=action.verification_action_id)
        if cancelled() or time.monotonic() >= authorization.monotonic_expires_at:
            if action.mutating:
                self.ledger.finish(ledger_key, "failed-before-effect", {"action_id": action.action_id})
            raise PluginEffectDenied("effect.expired", "plugin effect expired before dispatch")
        try:
            result = self.backend.invoke(enrollment=enrollment, action=action, arguments=arguments,
                                         credential=credential, idempotency_key=idem,
                                         timeout=min(timeout, action.deadline_seconds),
                                         cancelled=cancelled)
        except Exception:
            if action.mutating:
                self.ledger.finish(ledger_key, "ambiguous", {"action_id": action.action_id,
                                   "request_digest": authorization.request_digest})
                return _wire_result(operation_id, "ambiguous", {}, verification="unknown-outcome",
                                    resume_action_id=action.verification_action_id)
            raise PluginEffectDenied("backend.failed", "fixed plugin backend failed") from None
        if not isinstance(result, Mapping):
            if action.mutating:
                self.ledger.finish(ledger_key, "ambiguous", {"action_id": action.action_id,
                                   "request_digest": authorization.request_digest})
                return _wire_result(operation_id, "ambiguous", {}, verification="invalid-acknowledgement",
                                    resume_action_id=action.verification_action_id)
            raise PluginEffectDenied("backend.response", "fixed plugin backend returned an invalid result")
        result = _bounded_result(result, action.response_bytes_limit)
        if action.mutating:
            try:
                verified = (self.backend.verify(enrollment=enrollment, action=action, arguments=arguments,
                             credential=credential, idempotency_key=idem, response=result,
                             timeout=min(timeout, action.deadline_seconds), cancelled=cancelled)
                            if action.verify_after_write else False)
            except Exception:
                verified = False
            if verified is not True:
                receipt = {"action_id": action.action_id, "request_digest": authorization.request_digest,
                           "provider_reference": _provider_operation_id(result)}
                self.ledger.finish(ledger_key, "ambiguous", receipt)
                return _wire_result(operation_id, "ambiguous", receipt, verification="not-verified",
                                    resume_action_id=action.verification_action_id)
            receipt = {"action_id": action.action_id, "request_digest": authorization.request_digest,
                       "provider_reference": _provider_operation_id(result), "result": result}
            self.ledger.finish(ledger_key, "committed", receipt)
            return _wire_result(operation_id, "committed", result, verification="verified", resume_action_id=None)
        return _wire_result(operation_id, "read-complete", result, verification="not-applicable", resume_action_id=None)


def build_plugin_effect_handlers(*, actions: Mapping[tuple[str, str], tuple[PluginActionEnrollment, PluginAccountEnrollment]],
                                 backends: Mapping[str, PluginEffectBackend], vault: CredentialVault | None,
                                 ledger: IdempotencyLedger,
                                 confirmation: HumanConfirmationVerifier | None = None
                                 ) -> dict[tuple[str, str], _ActionHandler]:
    """Build root-only fixed-effect handlers for enrolled actions and targets."""
    if not actions or not isinstance(actions, Mapping) or ledger is None:
        return {}
    handlers: dict[tuple[str, str], _ActionHandler] = {}
    seen: set[tuple[str, str, str]] = set()
    for key, pair in actions.items():
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise ValueError("protected plugin action record is malformed")
        action, enrollment = pair
        if not isinstance(action, PluginActionEnrollment) or not isinstance(enrollment, PluginAccountEnrollment):
            raise ValueError("protected plugin action/enrollment types are required")
        if (action.adapter_id != enrollment.adapter_id or action.enrollment_id != enrollment.enrollment_id
                or action.principal_id != enrollment.principal_id or action.profile_id != enrollment.profile_id
                or action.recipient != enrollment.recipient or action.action_id not in enrollment.action_ids
                or key != (action.operation, action.target)):
            raise ValueError("plugin action does not match its selected root enrollment")
        unique = (action.adapter_id, action.enrollment_id, action.action_id)
        if unique in seen:
            raise ValueError("duplicate root plugin action enrollment")
        seen.add(unique)
        backend = backends.get(action.adapter_id)
        if backend is None:
            continue
        handlers[key] = _ActionHandler(action, enrollment, backend, vault, ledger, confirmation)
    return handlers


def _parse_request(payload: bytes, action: PluginActionEnrollment) -> tuple[dict[str, Any], dict[str, Any], str | None, str | None]:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= action.request_bytes_limit:
        raise PluginEffectDenied("request.bounds", "plugin request exceeds its enrolled bound")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise PluginEffectDenied("request.format", "plugin request is not unique-key canonical JSON") from None
    allowed = {"schema", "adapter_id", "action_id", "enrollment_id", "generation", "arguments",
               "idempotency_key", "opaque_confirmation_attestation_id"}
    required = {"schema", "adapter_id", "action_id", "enrollment_id", "generation", "arguments"}
    if (not isinstance(value, dict) or set(value) - allowed or not required <= set(value)
            or value["schema"] != 1 or value["adapter_id"] != action.adapter_id
            or value["action_id"] != action.action_id or value["enrollment_id"] != action.enrollment_id
            or value["generation"] != action.generation):
        raise PluginEffectDenied("request.scope", "plugin request does not match its exact enrollment")
    idem = value.get("idempotency_key")
    attestation = value.get("opaque_confirmation_attestation_id")
    if action.mutating:
        if not isinstance(idem, str) or not _OPAQUE_ID.fullmatch(idem):
            raise PluginEffectDenied("request.idempotency", "mutating plugin request requires an idempotency key")
    elif idem is not None:
        raise PluginEffectDenied("request.idempotency", "read-only plugin request cannot set a write idempotency key")
    if action.confirmation_policy_id:
        if not isinstance(attestation, str) or not _OPAQUE_ID.fullmatch(attestation):
            raise PluginEffectDenied("request.confirmation", "plugin request lacks an opaque confirmation handle")
    elif attestation is not None:
        raise PluginEffectDenied("request.confirmation", "unexpected confirmation handle")
    arguments = value["arguments"]
    _validate_instance(action.argument_schema, arguments, path="arguments")
    normalized = _canonical_json(value)
    if normalized != payload:
        raise PluginEffectDenied("request.canonical", "plugin request must use canonical JSON encoding")
    return value, arguments, idem, attestation


def _verify_grant(context: HostContext, authorization: EffectAuthorization,
                  action: PluginActionEnrollment, enrollment: PluginAccountEnrollment,
                  payload: bytes, peer_pid: int, timeout: float) -> None:
    digest = canonical_digest(payload)
    if (not isinstance(context, HostContext) or not isinstance(authorization, EffectAuthorization)
            or type(peer_pid) is not int or peer_pid <= 0
            or digest != authorization.request_digest or digest != context.final_payload_digest
            or context.final_payload_digest != authorization.final_payload_digest
            or context.principal_id != enrollment.principal_id or context.profile_id != enrollment.profile_id
            or authorization.principal_id != enrollment.principal_id or authorization.profile_id != enrollment.profile_id
            or context.uid != authorization.uid or context.namespace_id != authorization.namespace_id
            or context.trace_id != authorization.trace_id or context.intent_id != authorization.intent_id
            or context.lineage_hash != authorization.lineage_hash
            or action.capability not in context.capabilities or authorization.capability != action.capability
            or action.target != authorization.target or authorization.recipient != enrollment.recipient
            or authorization.operation != action.operation or context.operation != action.operation
            or authorization.enrollment_id != enrollment.enrollment_id
            or authorization.generation != action.generation
            or authorization.retry_index != 0
            or authorization.monotonic_expires_at <= time.monotonic()
            or context.monotonic_expires_at <= time.monotonic()
            or not 0 < timeout <= action.deadline_seconds):
        raise PluginEffectDenied("grant.binding", "plugin grant does not match the fresh exact action")


def _schema_type(schema: Mapping[str, Any]) -> str:
    value = schema.get("type")
    if value not in {"object", "array", "string", "integer", "number", "boolean"}:
        raise ValueError("plugin schema type is unsupported")
    return value


def _validate_schema_definition(schema: Mapping[str, Any], depth: int = 0) -> None:
    if depth > 8 or not isinstance(schema, Mapping):
        raise ValueError("plugin schema nesting exceeds its bound")
    kind = _schema_type(schema)
    common = {"type", "description"}
    if kind == "object":
        if schema.get("additionalProperties", False) is not False:
            raise ValueError("plugin object schemas must forbid additional properties")
        properties = schema.get("properties")
        required = schema.get("required", [])
        if not isinstance(properties, Mapping) or not isinstance(required, (list, tuple)) or len(properties) > 64:
            raise ValueError("plugin object schema is invalid")
        if set(required) - set(properties):
            raise ValueError("plugin schema required fields must be declared")
        if any(not isinstance(key, str) or not _IDENTIFIER.fullmatch(key) for key in properties):
            raise ValueError("plugin schema property name is invalid")
        for child in properties.values():
            _validate_schema_definition(child, depth + 1)
        allowed = common | {"properties", "required", "additionalProperties"}
    elif kind == "array":
        if "items" not in schema:
            raise ValueError("plugin array schemas require an item schema")
        _validate_schema_definition(schema["items"], depth + 1)
        allowed = common | {"items", "minItems", "maxItems"}
    else:
        allowed = common | {"enum", "minLength", "maxLength", "pattern", "minimum", "maximum"}
    if set(schema) - allowed:
        raise ValueError("plugin schema contains unsupported validation keywords")
    for name in ("minLength", "maxLength", "minItems", "maxItems"):
        if name in schema and (type(schema[name]) is not int or schema[name] < 0 or schema[name] > 262144):
            raise ValueError("plugin schema bound is invalid")
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str) or len(schema["pattern"]) > 256:
            raise ValueError("plugin schema regex is invalid")
        re.compile(schema["pattern"])
    if "enum" in schema and (not isinstance(schema["enum"], (list, tuple)) or not schema["enum"] or len(schema["enum"]) > 128):
        raise ValueError("plugin schema enum is invalid")


def _validate_instance(schema: Mapping[str, Any], value: Any, *, path: str) -> None:
    kind = _schema_type(schema)
    if kind == "object":
        properties = schema["properties"]
        required = set(schema.get("required", []))
        if not isinstance(value, Mapping) or set(value) - set(properties) or required - set(value):
            raise PluginEffectDenied("arguments.object", f"{path} has unsupported or missing fields")
        for key, item in value.items():
            _validate_instance(properties[key], item, path=f"{path}.{key}")
        return
    if kind == "array":
        if not isinstance(value, list) or len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 256):
            raise PluginEffectDenied("arguments.array", f"{path} exceeds its enrolled item bounds")
        for index, item in enumerate(value):
            _validate_instance(schema["items"], item, path=f"{path}[{index}]")
        return
    valid = {"string": isinstance(value, str), "integer": type(value) is int,
             "number": type(value) in {int, float} and not isinstance(value, bool) and math.isfinite(value),
             "boolean": type(value) is bool}[kind]
    if not valid:
        raise PluginEffectDenied("arguments.type", f"{path} has the wrong type")
    if kind == "string":
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 65536):
            raise PluginEffectDenied("arguments.length", f"{path} exceeds its enrolled length bounds")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            raise PluginEffectDenied("arguments.pattern", f"{path} does not match its enrolled format")
    if kind in {"integer", "number"}:
        if "minimum" in schema and value < schema["minimum"] or "maximum" in schema and value > schema["maximum"]:
            raise PluginEffectDenied("arguments.range", f"{path} is outside its enrolled numeric range")
    if "enum" in schema and value not in schema["enum"]:
        raise PluginEffectDenied("arguments.enum", f"{path} is outside its enrolled choices")


def _json_value(value: Any, depth: int = 0) -> Any:
    if depth > 12:
        raise PluginEffectDenied("response.depth", "plugin result nesting exceeds its bound")
    if value is None or type(value) in {str, bool, int}:
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    if isinstance(value, (list, tuple)) and len(value) <= 1024:
        return [_json_value(item, depth + 1) for item in value]
    if isinstance(value, Mapping) and len(value) <= 256:
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 256:
                raise PluginEffectDenied("response.shape", "plugin result contains an invalid key")
            if key.casefold() in {"token", "access_token", "refresh_token", "secret", "password", "authorization", "cookie"}:
                continue
            result[key] = _json_value(item, depth + 1)
        return result
    raise PluginEffectDenied("response.shape", "plugin result is outside its JSON bounds")


def _bounded_result(value: Mapping[str, Any], maximum: int) -> dict[str, Any]:
    result = _json_value(value)
    if not isinstance(result, dict) or len(_canonical_json(result)) > maximum:
        raise PluginEffectDenied("response.bounds", "plugin result exceeds its enrolled byte limit")
    return result


def _wire_result(operation_id: str, state: str, result: Mapping[str, Any], *,
                 verification: str, resume_action_id: str | None) -> Mapping[str, Any]:
    if state not in {"committed", "read-complete", "pending", "ambiguous", "unavailable"}:
        raise PluginEffectDenied("response.state", "plugin operation state is invalid")
    response = {"schema": 1, "operation_id": operation_id, "state": state,
                "result": _json_value(result), "verification_status": verification,
                "resume_action_id": resume_action_id}
    if len(_canonical_json(response)) > MAX_PLUGIN_RESPONSE:
        raise PluginEffectDenied("response.bounds", "plugin response exceeds its global bound")
    return response


def _idempotency_digest(context: HostContext, action: PluginActionEnrollment,
                        enrollment: PluginAccountEnrollment, key: str | None,
                        request_digest: str) -> str:
    if key is None:
        raise PluginEffectDenied("request.idempotency", "write attempt lacks idempotency key")
    return canonical_digest({"principal_id": context.principal_id, "adapter_id": action.adapter_id,
        "enrollment_id": enrollment.enrollment_id, "account_id": enrollment.account_id,
        "target": action.target, "generation": action.generation,
        "action_id": action.action_id, "payload_digest": request_digest, "idempotency_key": key})


def _provider_operation_id(result: Mapping[str, Any]) -> str | None:
    for key in ("id", "node_id", "commit_sha", "run_id", "number"):
        value = result.get(key)
        if type(value) in {str, int}:
            text = str(value)
            return text[:256]
    return None


def _redact(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return "[truncated]"
    if isinstance(value, Mapping):
        return {key: "[redacted]" if str(key).casefold() in {"token", "access_token", "refresh_token", "secret", "password", "authorization", "cookie"}
                else _redact(item, depth + 1)
                for key, item in value.items() if isinstance(key, str)}
    if isinstance(value, (list, tuple)):
        return [_redact(item, depth + 1) for item in value[:128]]
    if type(value) in {str, bool, int, float} or value is None:
        return value
    return "[omitted]"


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        raise PluginEffectDenied("json.invalid", "plugin JSON contains an unsupported value") from None


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}$")
_TOOL_SLUG = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_TOOL_VERSION = re.compile(r"^[0-9]{8}_[0-9]{2}$")


def _github_path(value: Any) -> str:
    if (not isinstance(value, str) or not value or len(value) > 512 or value.startswith("/")
            or "\\" in value or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(ord(ch) < 32 for ch in value)):
        raise PluginEffectDenied("github.path", "GitHub content path is outside the fixed repository scope")
    return value


def _freeze_schema(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        raise ValueError("plugin schema nesting exceeds its bound")
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_schema(item, depth + 1) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_schema(item, depth + 1) for item in value)
    return value


def _check_transport_deadline(network: Any, timeout: float) -> None:
    configured = getattr(network, "deadline_seconds", None)
    if configured is not None and (not isinstance(configured, (int, float)) or configured > timeout):
        raise PluginEffectDenied("backend.deadline", "fixed transport exceeds the authorized effect deadline")
