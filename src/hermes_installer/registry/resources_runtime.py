"""Typed runtime bindings for non-profile HermesAgent Resources.

The source catalog can describe capabilities, but it cannot register code,
grant host authority, or activate accounts.  This module turns each declaration
into an explicit runtime binding and provides the shared fixed-effect boundary
used by reviewed native plugin handlers.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence


class ResourceRuntimeError(RuntimeError):
    """Invalid resource identity, runtime binding, or external event."""


@dataclass(frozen=True, slots=True)
class ResourceIdentity:
    resource_id: str
    kind: str
    version: str
    source_path: str
    source_revision: str
    content_digest: str


@dataclass(frozen=True, slots=True)
class ResourceReadiness:
    bundled: bool = True
    validated: bool = True
    materialized: bool = False
    discovered: bool = False
    authenticated: bool = False
    functional: bool = False
    enabled: bool = False
    target_verified: bool = False


@dataclass(frozen=True, slots=True)
class ResourceRuntimeArtifact:
    """Result consumed by NativeRegistry.materialize without granting authority."""

    files: Mapping[str, bytes]
    native_path: str | None
    adapter_id: str | None
    discoverability: str
    invocation: str
    blockers: tuple[str, ...] = ()
    readiness: ResourceReadiness = field(default_factory=ResourceReadiness)


@dataclass(frozen=True, slots=True)
class HermesProfileExecutionTarget:
    """Custody-selected launch inputs for one pinned Hermes profile.

    These values come from protected installer/custody state, never a resource
    manifest. The host broker independently validates the profile target and
    launch envelope before process creation.
    """

    profile_id: str
    executable: Any
    artifact_sha256: str
    artifact_root: Any
    cwd: Any
    data_root: Any
    env_allowlist: Mapping[str, str]
    child_artifact_refs: Mapping[str, str] = field(default_factory=dict)
    max_lifetime_seconds: int = 600
    max_output_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        from pathlib import Path
        from types import MappingProxyType

        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", self.profile_id):
            raise ValueError("selected Hermes profile identity is invalid")
        for name in ("executable", "artifact_root", "cwd", "data_root"):
            value = getattr(self, name)
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"selected Hermes profile {name} must be an absolute Path")
        if not re.fullmatch(r"[0-9a-f]{64}", self.artifact_sha256):
            raise ValueError("selected Hermes executable pin must be a SHA-256 digest")
        if (type(self.max_lifetime_seconds) is not int or not 1 <= self.max_lifetime_seconds <= 600
                or type(self.max_output_bytes) is not int or not 1 <= self.max_output_bytes <= 4 * 1024 * 1024):
            raise ValueError("selected Hermes process bounds are outside supported limits")
        if not isinstance(self.env_allowlist, Mapping) or not isinstance(self.child_artifact_refs, Mapping):
            raise ValueError("selected Hermes launch maps are required")
        env = dict(self.env_allowlist)
        if any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key)
               or not isinstance(value, str) or "\x00" in value for key, value in env.items()):
            raise ValueError("selected Hermes environment allowlist is malformed")
        refs = dict(self.child_artifact_refs)
        for reference, digest in refs.items():
            if (not isinstance(reference, str) or not isinstance(digest, str)
                    or not re.fullmatch(r"artifact:[A-Za-z0-9._-]{1,128}:[0-9a-f]{64}", reference)
                    or reference.rsplit(":", 1)[1] != digest or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise ValueError("selected Hermes child artifact reference is malformed")
        object.__setattr__(self, "env_allowlist", MappingProxyType(env))
        object.__setattr__(self, "child_artifact_refs", MappingProxyType(refs))


class SelectedHermesProfileResolver(Protocol):
    """Resolve only an installed profile selected by the installer runtime."""

    def resolve_profile(self, profile_id: str) -> HermesProfileExecutionTarget | None: ...


class PluginEffectsFacade(Protocol):
    """Root-selected per-action effect dispatcher injected by trusted loader."""

    def invoke(self, adapter_id: str, action_id: str, arguments: Mapping[str, Any],
               idempotency_key: str | None = None,
               opaque_confirmation_attestation_id: str | None = None) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class NativePluginRuntimeContext:
    """Only the trusted installer may construct this context for a plugin.

    ``declared_capabilities`` are display/dispatch names, never grants.  The
    signed invocation lineage comes from Hermes' trusted runtime integration;
    plugin arguments and resource YAML cannot supply it.
    """

    identity: ResourceIdentity
    declared_capabilities: tuple[str, ...]
    authority: "AuthorityClient"
    invocation_contexts: "InvocationContextProvider"
    selected_adapters: "PluginAdapterRegistry"
    mcp_registry: object | None = None
    provider_dispatcher: object | None = None
    local_overlay_store: "ProfileOverlayView | None" = None
    profile_targets: SelectedHermesProfileResolver | None = None
    plugin_effects: PluginEffectsFacade | None = None
    # Opaque per-profile local voice device/session enrollment, selected by
    # the trusted host. It is never read from the Plugin manifest or tool args.
    voice_session_enrollment_id: str | None = None

    def __post_init__(self) -> None:
        value = self.voice_session_enrollment_id
        if value is not None and (
            not isinstance(value, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value)
        ):
            raise ValueError("root-selected voice session enrollment reference is malformed")


class HostContext(Protocol):
    """Signed context type exported by the root-owned authority package."""


class EffectAuthorization(Protocol):
    capability: str
    request_digest: str
    target: str
    recipient: str | None


class BrokeredEffectResponse(Protocol):
    status: int
    body: bytes
    headers: Mapping[str, str]
    receipt_id: str


class AuthorityClient(Protocol):
    def context(self, *, purpose: str, intent: str, operation: str,
                source_contexts: Sequence[HostContext] = (),
                final_payload_digest: str | None = None,
                trace_id: str | None = None, lease_seconds: float = 30.0,
                cancelled: Callable[[], bool] | None = None) -> HostContext: ...

    def authorize_effect(self, context: HostContext, *, capability: str,
                         target: str, recipient: str | None,
                         request_digest: str, retry_index: int = 0,
                         cancelled: Callable[[], bool] | None = None) -> EffectAuthorization: ...

    def verify_effect(self, authorization: EffectAuthorization, context: HostContext, *,
                      capability: str, target: str, recipient: str | None,
                      request_digest: str, retry_index: int = 0,
                      cancelled: Callable[[], bool] | None = None) -> object: ...

    def perform_effect(self, authorization: EffectAuthorization, *, operation: str,
                       payload: bytes, timeout: float,
                       cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse: ...


class InvocationContextProvider(Protocol):
    def __call__(self, *, purpose: str, intent: str) -> tuple[HostContext, ...]: ...


class PluginRegistrationContext(Protocol):
    """Official Hermes PluginContext registration surface used by adapters."""

    def register_tool(self, name: str, toolset: str, schema: dict[str, Any],
                      handler: Callable[..., Any], check_fn: Callable[..., Any] | None = None,
                      requires_env: list[str] | None = None, is_async: bool = False,
                      description: str = "", emoji: str = "", override: bool = False) -> object: ...


class NativePluginImplementation(Protocol):
    def register(self, ctx: PluginRegistrationContext,
                 runtime_context: NativePluginRuntimeContext) -> None: ...


class PluginAdapterRegistry(Protocol):
    def resolve_plugin_adapter(self, adapter_id: str) -> NativePluginImplementation | None: ...


class ReviewedPluginAdapterRegistry:
    """Lazy bridge to the source-reviewed native plugin adapter table."""

    def resolve_plugin_adapter(self, adapter_id: str) -> NativePluginImplementation | None:
        from hermes_installer.components import native_plugins

        resolver = getattr(native_plugins, "resolve_native_plugin_implementation", None)
        if callable(resolver):
            return resolver(adapter_id)
        contract = native_plugins.resolve_native_plugin_adapter(adapter_id)
        if not contract.handler_available:
            return None
        # The reviewed local implementation is present in this component
        # cohort, but older crosswalk snapshots expose only its implementation
        # constant rather than the later resolver function.
        implementation = getattr(native_plugins, "RESOURCE_OVERLAY_STORE_IMPLEMENTATION", None)
        return implementation if adapter_id == "resource-overlay-store" else None


class PluginAdapterUnavailable(ResourceRuntimeError):
    """No reviewed native handler is installed for a declared resource plugin."""


@dataclass(frozen=True, slots=True)
class OverlayValue:
    profile_id: str
    record_id: str
    revision: str
    value: bytes
    deleted: bool = False


class LocalOverlayStore(Protocol):
    def read(self, profile_id: str, record_id: str) -> OverlayValue | None: ...
    def write(self, profile_id: str, record_id: str, value: bytes, *,
              expected_revision: str | None) -> str: ...
    def history(self, profile_id: str, record_id: str) -> tuple[str, ...]: ...
    def delete(self, profile_id: str, record_id: str, *,
               expected_revision: str) -> str: ...


class ProfileOverlayView(Protocol):
    """Profile-pinned view handed to one active Hermes profile only."""

    def read(self, record_id: str) -> OverlayValue | None: ...
    def write(self, record_id: str, value: bytes, *, expected_revision: str | None) -> str: ...
    def history(self, record_id: str) -> tuple[str, ...]: ...
    def delete(self, record_id: str, *, expected_revision: str) -> str: ...


class ResourceOverlayStore:
    """Profile-scoped private overlay with immutable revisions and CAS writes.

    The store touches only its already initialized installer-owned root. Backup,
    encryption and restore remain separate lifecycle capabilities.
    """

    _PROFILE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
    _RECORD = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
    _MAX_VALUE = 1_048_576

    def __init__(self, owned_root: Any, journal: Any):
        marker = owned_root.root / ".hermes-installer-owned"
        if owned_root.root.is_symlink() or marker.is_symlink() or not marker.is_file():
            raise ResourceRuntimeError("overlay root is not initialized and owned")
        if marker.read_bytes() != b"schema=1\n":
            raise ResourceRuntimeError("overlay root ownership marker is invalid")
        self.owned_root = owned_root
        self.journal = journal

    def for_profile(self, profile_id: str) -> ProfileOverlayView:
        if not self._PROFILE.fullmatch(profile_id):
            raise ResourceRuntimeError("overlay profile identity is invalid")
        return _ProfileBoundOverlay(self, profile_id)

    def _key(self, profile_id: str, record_id: str) -> str:
        if not self._PROFILE.fullmatch(profile_id) or not self._RECORD.fullmatch(record_id):
            raise ResourceRuntimeError("overlay profile or record identity is invalid")
        return f"resource-overlay:{profile_id}:{record_id}"

    def _read_json(self, relative: str) -> dict[str, Any] | None:
        import os
        import stat

        path = self.owned_root.path(relative)
        if not path.exists():
            return None
        self._check_private_directory_tree(path.parent)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > self._MAX_VALUE + 4096):
                    raise ResourceRuntimeError("overlay revision file has unsafe ownership or mode")
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    payload = stream.read(self._MAX_VALUE + 4097)
            finally:
                os.close(descriptor)
        except OSError:
            raise ResourceRuntimeError("overlay revision file cannot be read safely") from None
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ResourceRuntimeError("overlay revision file is malformed") from None
        if not isinstance(value, dict):
            raise ResourceRuntimeError("overlay revision file is malformed")
        return value

    def _write_json(self, relative: str, value: Mapping[str, Any]) -> None:
        import os
        import secrets

        path = self.owned_root.path(relative)
        self._ensure_private_directory_tree(path.parent)
        temp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(temp, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, path)
            os.chmod(path, 0o600)
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _check_private_directory(path: Any) -> None:
        import os
        import stat

        try:
            info = path.lstat()
        except OSError:
            raise ResourceRuntimeError("overlay directory cannot be inspected safely") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ResourceRuntimeError("overlay directory has unsafe ownership or permissions")

    def _check_private_directory_tree(self, path: Any) -> None:
        root = self.owned_root.root
        try:
            relative = path.relative_to(root)
        except ValueError:
            raise ResourceRuntimeError("overlay directory escaped its owned root") from None
        current = root
        self._check_private_directory(current)
        for part in relative.parts:
            current = current / part
            self._check_private_directory(current)

    def _ensure_private_directory_tree(self, path: Any) -> None:
        import os
        import stat

        root = self.owned_root.root
        try:
            relative = path.relative_to(root)
        except ValueError:
            raise ResourceRuntimeError("overlay directory escaped its owned root") from None
        current = root
        self._check_private_directory(current)
        for part in relative.parts:
            current = current / part
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            try:
                info = current.lstat()
            except OSError:
                raise ResourceRuntimeError("overlay directory cannot be inspected safely") from None
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise ResourceRuntimeError("overlay directory has unsafe ownership or type")
            if stat.S_IMODE(info.st_mode) & 0o077:
                os.chmod(current, 0o700, follow_symlinks=False)
                self._check_private_directory(current)

    def _write_revision(self, profile_id: str, record_id: str, revision: str,
                        value: Mapping[str, Any]) -> None:
        relative = f"resource-overlays/{profile_id}/{record_id}/revisions/{revision}.json"
        existing = self._read_json(relative)
        if existing is not None:
            if existing != dict(value):
                raise ResourceRuntimeError("overlay revision is immutable and its stored content conflicts")
            return
        self._write_json(relative, value)

    def _current(self, profile_id: str, record_id: str) -> OverlayValue | None:
        pointer = self._read_json(f"resource-overlays/{profile_id}/{record_id}/current.json")
        if pointer is None:
            return None
        revision = pointer.get("revision")
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
            raise ResourceRuntimeError("overlay current pointer is malformed")
        value = self._read_json(f"resource-overlays/{profile_id}/{record_id}/revisions/{revision}.json")
        if (value is None or value.get("profile_id") != profile_id or value.get("record_id") != record_id
                or value.get("revision") != revision or type(value.get("deleted")) is not bool):
            raise ResourceRuntimeError("overlay current revision is missing or mismatched")
        import base64
        try:
            content = base64.b64decode(value.get("value", ""), validate=True)
        except Exception:
            raise ResourceRuntimeError("overlay current revision content is malformed") from None
        if len(content) > self._MAX_VALUE or hashlib.sha256(content + bytes([value["deleted"]])).hexdigest() != revision:
            raise ResourceRuntimeError("overlay current revision digest does not match")
        return OverlayValue(profile_id, record_id, revision, content, value["deleted"])

    def read(self, profile_id: str, record_id: str) -> OverlayValue | None:
        self._key(profile_id, record_id)
        value = self._current(profile_id, record_id)
        return None if value is None or value.deleted else value

    def write(self, profile_id: str, record_id: str, value: bytes, *,
              expected_revision: str | None) -> str:
        from hermes_installer.state import process_lock

        key = self._key(profile_id, record_id)
        if not isinstance(value, bytes) or len(value) > self._MAX_VALUE:
            raise ResourceRuntimeError("overlay value must be bytes no larger than one MiB")
        with process_lock(self.owned_root.path("resource-overlays.lock")):
            current = self._current(profile_id, record_id)
            actual = current.revision if current is not None else None
            if actual != expected_revision:
                raise ResourceRuntimeError("overlay compare-and-swap revision does not match")
            revision = hashlib.sha256(value + b"\0").hexdigest()
            import base64
            self.journal.checkpoint(key, "overlay_write_prepared", {
                "profile_id": profile_id, "record_id": record_id, "revision": revision,
            })
            self._write_revision(profile_id, record_id, revision, {
                "profile_id": profile_id, "record_id": record_id, "revision": revision,
                "deleted": False, "value": base64.b64encode(value).decode("ascii"),
            })
            self._write_json(f"resource-overlays/{profile_id}/{record_id}/current.json", {"revision": revision})
            self.journal.checkpoint(key, "overlay_revision_written", {
                "profile_id": profile_id, "record_id": record_id, "revision": revision,
            })
            return revision

    def history(self, profile_id: str, record_id: str) -> tuple[str, ...]:
        self._key(profile_id, record_id)
        directory = self.owned_root.path(f"resource-overlays/{profile_id}/{record_id}/revisions")
        if not directory.exists():
            return ()
        if directory.is_symlink() or not directory.is_dir():
            raise ResourceRuntimeError("overlay revision directory is unsafe")
        self._check_private_directory_tree(directory)
        revisions = []
        for path in directory.iterdir():
            if path.is_symlink() or not path.is_file() or not re.fullmatch(r"[0-9a-f]{64}\.json", path.name):
                raise ResourceRuntimeError("overlay revision directory contains an unexpected entry")
            revision = path.stem
            value = self._read_json(f"resource-overlays/{profile_id}/{record_id}/revisions/{path.name}")
            if (value is None or value.get("profile_id") != profile_id or value.get("record_id") != record_id
                    or value.get("revision") != revision or type(value.get("deleted")) is not bool):
                raise ResourceRuntimeError("overlay history contains a mismatched revision")
            import base64
            try:
                content = base64.b64decode(value.get("value", ""), validate=True)
            except Exception:
                raise ResourceRuntimeError("overlay history contains malformed content") from None
            if len(content) > self._MAX_VALUE or hashlib.sha256(content + bytes([value["deleted"]])).hexdigest() != revision:
                raise ResourceRuntimeError("overlay history content digest does not match")
            revisions.append(path.stem)
        return tuple(sorted(revisions))

    def delete(self, profile_id: str, record_id: str, *, expected_revision: str) -> str:
        from hermes_installer.state import process_lock

        key = self._key(profile_id, record_id)
        with process_lock(self.owned_root.path("resource-overlays.lock")):
            current = self._current(profile_id, record_id)
            if current is None or current.deleted or current.revision != expected_revision:
                raise ResourceRuntimeError("overlay compare-and-swap revision does not match")
            revision = hashlib.sha256(current.value + b"\1").hexdigest()
            import base64
            self.journal.checkpoint(key, "overlay_delete_prepared", {
                "profile_id": profile_id, "record_id": record_id, "revision": revision,
            })
            self._write_revision(profile_id, record_id, revision, {
                "profile_id": profile_id, "record_id": record_id, "revision": revision,
                "deleted": True, "value": base64.b64encode(current.value).decode("ascii"),
            })
            self._write_json(f"resource-overlays/{profile_id}/{record_id}/current.json", {"revision": revision})
            self.journal.checkpoint(key, "overlay_tombstoned", {
                "profile_id": profile_id, "record_id": record_id, "revision": revision,
            })
            return revision


@dataclass(frozen=True, slots=True)
class _ProfileBoundOverlay:
    store: ResourceOverlayStore
    profile_id: str

    def read(self, record_id: str) -> OverlayValue | None:
        return self.store.read(self.profile_id, record_id)

    def write(self, record_id: str, value: bytes, *, expected_revision: str | None) -> str:
        return self.store.write(self.profile_id, record_id, value, expected_revision=expected_revision)

    def history(self, record_id: str) -> tuple[str, ...]:
        return self.store.history(self.profile_id, record_id)

    def delete(self, record_id: str, *, expected_revision: str) -> str:
        return self.store.delete(self.profile_id, record_id, expected_revision=expected_revision)


def create_native_plugin_handler(adapter_id: str,
                                 runtime_context: NativePluginRuntimeContext) -> Callable[[PluginRegistrationContext], None]:
    """Resolve a reviewed adapter and return the official Hermes ``register(ctx)`` hook."""
    if not isinstance(runtime_context, NativePluginRuntimeContext):
        raise TypeError("trusted NativePluginRuntimeContext is required")
    identity = runtime_context.identity
    if identity.kind != "plugins" or adapter_id != identity.resource_id:
        raise PluginAdapterUnavailable("plugin adapter id does not match the pinned resource identity")
    implementation = runtime_context.selected_adapters.resolve_plugin_adapter(adapter_id)
    if implementation is None:
        raise PluginAdapterUnavailable(
            f"reviewed native handler is unavailable for resource plugin {identity.resource_id}"
        )

    def register(ctx: PluginRegistrationContext) -> None:
        implementation.register(ctx, runtime_context)

    return register


@dataclass(frozen=True, slots=True)
class FixedResourceEffect:
    """One effect registered in protected host policy by the host owner."""

    capability: str
    target: str
    recipient: str | None
    operation: str
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        if not self.capability or not self.target or not self.operation:
            raise ValueError("fixed resource effect needs capability, target and operation")
        if self.operation not in {
            "provider.dispatch", "mcp.request", "mcp.stdio", "memory.request",
            "memory.doctor", "memory.capture", "memory.search", "memory.export",
            "memory.delete", "memory.extract", "memory.embed", "memory.backup",
            "memory.restore", "memory.enqueue", "memory.result", "host.write",
            "alert.deliver", "process.start", "process.status", "process.read",
            "process.write", "process.stop", "artifact.fetch", "package.install",
            "resource.orchestrator.recruit", "resource.cron.run", "resource.channel.route",
            "resource.webhook.deliver",
        }:
            raise ValueError("resource effect operation is not a fixed host verb")
        if not 0 < self.timeout_seconds <= 120:
            raise ValueError("resource effect timeout must be at most 120 seconds")


@dataclass(frozen=True, slots=True)
class SelectedResourceExecution:
    """Root-selected executable resource binding consumed by the root handler.

    The host loader creates these from its protected active-selection ledger,
    not from generated runtime JSON. Resource declarations never set target,
    capability, recipient, delegation or enabled state.
    """

    identity: ResourceIdentity
    generation_digest: str
    effective_spec: Mapping[str, Any]
    capability: str
    target: str
    operation: str
    recipient: str | None
    delegation_id: str
    profile_id: str | None
    enabled: bool

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.generation_digest):
            raise ValueError("selected resource generation must be pinned by SHA-256")
        expected = f"resource:{self.identity.kind}/{self.identity.resource_id}@{self.identity.version}"
        if self.target != expected:
            raise ValueError("selected resource target does not match its immutable identity")
        if not self.capability or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", self.capability):
            raise ValueError("selected resource capability is invalid")
        if self.operation not in {
            "resource.cron.run", "resource.channel.route", "resource.webhook.deliver",
            "resource.orchestrator.recruit",
        }:
            raise ValueError("selected resource operation is not a fixed resource verb")
        expected_operation = {
            "crons": "resource.cron.run", "channels": "resource.channel.route",
            "webhooks": "resource.webhook.deliver", "bundles": "resource.orchestrator.recruit",
        }.get(self.identity.kind)
        if expected_operation != self.operation:
            raise ValueError("selected resource kind does not match its fixed operation")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", self.delegation_id):
            raise ValueError("selected root delegation identity is invalid")
        if self.profile_id is not None and not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", self.profile_id):
            raise ValueError("selected Hermes profile identity is invalid")
        if (self.recipient is not None and (not isinstance(self.recipient, str) or not self.recipient
                                            or len(self.recipient) > 256
                                            or any(ord(char) < 0x20 for char in self.recipient))):
            raise ValueError("selected resource recipient is malformed")
        if type(self.enabled) is not bool or not isinstance(self.effective_spec, Mapping):
            raise ValueError("selected resource enablement and effective specification are malformed")
        # Copy the selected effective body so a mutable input mapping cannot
        # change the root handler's approved action after construction.
        normalized = json.loads(json.dumps(self.effective_spec, sort_keys=True, separators=(",", ":")))
        object.__setattr__(self, "effective_spec", _freeze_json(normalized))


class SelectedResourceResolver(Protocol):
    """Root-owned resolver for enabled, generation-pinned resource selections."""

    def resolve(self, identity: ResourceIdentity) -> SelectedResourceExecution | None: ...


class RootDelegatedEffectService(Protocol):
    """Exact in-process AuthorityService delegation used only by root handlers."""

    def perform_delegated_effect(
        self, parent_authorization: EffectAuthorization, *, delegation_id: str,
        payload: bytes, peer_pid: int, timeout: float,
        cancelled: Callable[[], bool],
    ) -> BrokeredEffectResponse | Mapping[str, Any]: ...


class SelectedResourceRegistry:
    """Validated identity index; production records must come from root custody."""

    __slots__ = ("_rows", "_generation_digest")

    def __init__(self, rows: Sequence[SelectedResourceExecution], *,
                 expected_generation_digest: str | None = None):
        indexed: dict[tuple[str, str, str, str, str], SelectedResourceExecution] = {}
        generations: set[str] = set()
        for row in rows:
            if not isinstance(row, SelectedResourceExecution):
                raise TypeError("selected resource registry accepts only typed enrollment records")
            key = (row.identity.kind, row.identity.resource_id, row.identity.version,
                   row.identity.source_path, row.identity.source_revision)
            if key in indexed:
                raise ValueError("selected resource identity is duplicated")
            indexed[key] = row
            generations.add(row.generation_digest)
        if len(generations) > 1:
            raise ValueError("selected resource registry cannot mix active generations")
        if (expected_generation_digest is not None
                and (not re.fullmatch(r"[0-9a-f]{64}", expected_generation_digest)
                     or generations != {expected_generation_digest})):
            raise ValueError("selected resource registry differs from the protected active generation")
        from types import MappingProxyType

        self._rows = MappingProxyType(indexed)
        self._generation_digest = next(iter(generations), None)

    @property
    def generation_digest(self) -> str | None:
        return self._generation_digest

    @property
    def rows(self) -> tuple[SelectedResourceExecution, ...]:
        return tuple(self._rows.values())

    def resolve(self, identity: ResourceIdentity) -> SelectedResourceExecution | None:
        key = (identity.kind, identity.resource_id, identity.version,
               identity.source_path, identity.source_revision)
        row = self._rows.get(key)
        if row is None or row.identity.content_digest != identity.content_digest:
            return None
        return row


class SelectedResourceUnavailable(ResourceRuntimeError):
    """The selected source item lacks a protected execution target or dependency."""


def _cron_profile_prompt(selected: SelectedResourceExecution,
                         scheduled_for: str,
                         target: HermesProfileExecutionTarget) -> str:
    _validate_cron(selected.effective_spec, expected_source_revision=selected.identity.source_revision)
    action = selected.effective_spec["action"]
    assert isinstance(action, Mapping)
    profile_selector = action.get("profile")
    if (selected.profile_id is None or not isinstance(profile_selector, str)
            or profile_selector.split("@", 1)[0] != selected.profile_id):
        # The installer resolves version selectors into profile_id at selection
        # time. The raw action profile string is not an execution target.
        raise SelectedResourceUnavailable("cron profile target was not resolved from the selected dependency closure")
    mode = action.get("mode")
    if action.get("type") == "installer-resource-candidate-assessment":
        source = action["source"]
        bundle = _verified_installed_resource_bundle(target, source)
        return (
            "Assess only the installer-owned, pinned Resources snapshot at " + str(bundle)
            + f" (source revision {source['revision']}, catalog {source['catalogVersion']}). "
            "Read its declarations and report compatible changes, conflicts, and missing prerequisites. "
            "Do not access the network, install or update packages, change the active generation, "
            "enable a schedule/account, send a message, or modify any files. Include evidence paths "
            "and leave all proposed changes as candidates. Scheduled time: " + scheduled_for
        )
    if mode == "agent-runtime-health-report":
        checks = action.get("checks")
        permitted = {"agent-process", "container-health", "disk-space", "recent-errors", "resource-version"}
        if not isinstance(checks, (list, tuple)) or not checks or len(checks) > len(permitted):
            raise SelectedResourceUnavailable("health report checks are not a bounded reviewed list")
        if any(not isinstance(value, str) or value not in permitted for value in checks):
            raise SelectedResourceUnavailable("health report requested an unreviewed check")
        return (
            "Run a read-only Hermes runtime health report for these checks only: "
            + ", ".join(checks) + ". Do not remediate, change files, or send notifications. "
            "For every finding give the local evidence source and distinguish unavailable probes from healthy results. "
            "Scheduled time: " + scheduled_for
        )
    raise SelectedResourceUnavailable(
        "cron action has no reviewed local Hermes profile-run recipe; enroll exact targets before activation"
    )


def _verified_installed_resource_bundle(
    target: HermesProfileExecutionTarget, source: Mapping[str, Any],
) -> Path:
    """Resolve a complete expanded snapshot against the wheel's pinned bundle.

    The installer package archive is authoritative input; the source checkout's
    ``resources/vendor`` tree is never consulted. The Hermes child can only use
    the expanded copy under its root-enrolled immutable artifact root, so check
    every path, byte and executable mode before placing that path in a prompt.
    A directory containing only the selected cron manifest is not sufficient.
    """
    from hermes_installer.registry.source import RegistrySourceError, load_bundled_source

    try:
        pinned = load_bundled_source()
    except (OSError, ValueError, RegistrySourceError):
        raise SelectedResourceUnavailable("packaged installer Resources archive cannot be verified") from None
    if (source.get("catalogVersion") != pinned.catalog_version
            or source.get("revision") != pinned.revision):
        raise SelectedResourceUnavailable("cron source identity differs from the packaged installer Resources pin")
    raw_path = source.get("path")
    if (not isinstance(raw_path, str) or raw_path.startswith("/")
            or any(part in {"", ".", ".."} for part in raw_path.split("/"))):
        raise SelectedResourceUnavailable("cron Resources bundle path is not a safe relative path")
    try:
        root = target.artifact_root.resolve(strict=True)
        bundle = root.joinpath(*raw_path.split("/")).resolve(strict=True)
        if not bundle.is_relative_to(root) or not bundle.is_dir():
            raise OSError("bundle directory is not contained by artifact root")
        if bundle != root.joinpath(*raw_path.split("/")):
            raise OSError("bundle path contains a symlink")

        observed_files: dict[str, tuple[bytes, int]] = {}
        total_bytes = 0
        for current, directories, names in os.walk(bundle, topdown=True, followlinks=False):
            current_path = Path(current)
            if current_path.is_symlink():
                raise OSError("bundle directory contains a symlink")
            for name in tuple(directories):
                child = current_path / name
                info = child.lstat()
                if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    raise OSError("bundle contains an unsafe directory")
            for name in names:
                file_path = current_path / name
                info = file_path.lstat()
                if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    raise OSError("bundle contains a non-regular file")
                relative = file_path.relative_to(bundle).as_posix()
                content = file_path.read_bytes()
                total_bytes += len(content)
                if total_bytes > 16 * 1024 * 1024:
                    raise OSError("bundle exceeds its pinned expanded-size bound")
                observed_files[relative] = (content, stat.S_IMODE(info.st_mode))
        if set(observed_files) != set(pinned.files):
            raise OSError("bundle file set differs from the packaged pinned snapshot")
        for relative, expected in pinned.files.items():
            content, mode = observed_files[relative]
            if content != expected or mode != pinned.file_modes[relative]:
                raise OSError("bundle bytes or executable mode differ from the packaged pinned snapshot")
    except (OSError, ValueError):
        raise SelectedResourceUnavailable(
            "complete pinned Resources snapshot is not materialized under the selected Hermes artifact root; "
            "stage the verified package-data bundle before enabling this cron"
        ) from None
    return bundle


def _cron_recipe_is_supported(selected: SelectedResourceExecution) -> bool:
    try:
        _validate_cron(selected.effective_spec, expected_source_revision=selected.identity.source_revision)
    except ResourceRuntimeError:
        return False
    action = selected.effective_spec["action"]
    if action.get("type") == "installer-resource-candidate-assessment":
        return action.get("mode") == "candidate-assessment"
    return (action.get("type") == "profile-run"
            and action.get("mode") == "agent-runtime-health-report"
            and "repository" not in action and "ref" not in action)


def build_cron_resource_effect_handler(
    identity: ResourceIdentity,
    *,
    selected_resources: SelectedResourceResolver,
    profile_targets: SelectedHermesProfileResolver,
    authority_service: RootDelegatedEffectService,
) -> Callable[..., Mapping[str, Any]]:
    """Build a root-only cron adapter for one selected resource.

    The parent grant arrives through AuthorityService's fixed handler surface.
    The selected ledger resolves both resource and profile identities; the
    handler accepts no prompt, endpoint, argv, account, or profile override.
    A second one-use child grant is issued by the root service for `process.start`.
    """
    if identity.kind != "crons":
        raise ValueError("cron resource handler requires a cron identity")

    def handle(*, context: HostContext, authorization: EffectAuthorization,
               payload: bytes, timeout: float, peer_pid: int,
               cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        selected = selected_resources.resolve(identity)
        if (selected is None or not selected.enabled or selected.operation != "resource.cron.run"
                or authorization.target != selected.target
                or authorization.capability != selected.capability
                or authorization.recipient != selected.recipient
                or authorization.request_digest != hashlib.sha256(payload).hexdigest()):
            raise SelectedResourceUnavailable("cron is not enabled in the protected selected-resource catalog")
        try:
            request = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ResourceRuntimeError("scheduled invocation payload is malformed") from None
        if not isinstance(request, dict) or set(request) != {"profile_id", "scheduled_for"}:
            raise ResourceRuntimeError("scheduled invocation accepts only its selected profile and schedule instant")
        if request["profile_id"] != selected.profile_id:
            raise ResourceRuntimeError("scheduled invocation profile differs from root selection")
        scheduled_for = request["scheduled_for"]
        if not isinstance(scheduled_for, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})", scheduled_for
        ):
            raise ResourceRuntimeError("scheduled invocation time must be an explicit ISO-8601 instant")
        if not _cron_instant_matches(selected.effective_spec, scheduled_for):
            raise ResourceRuntimeError("scheduled instant does not match the selected cron expression")
        profile_id = selected.profile_id
        if profile_id is None:
            raise SelectedResourceUnavailable("selected cron has no resolved Hermes profile")
        target = profile_targets.resolve_profile(profile_id)
        if target is None or target.profile_id != profile_id:
            raise SelectedResourceUnavailable("selected Hermes profile has no protected custody target")
        prompt = _cron_profile_prompt(selected, scheduled_for, target)
        from hermes_installer.authority import canonical_bytes
        from hermes_installer.authority.client import canonical_profile_target, profile_launch_envelope

        process_target = canonical_profile_target(profile_id, target.executable, target.data_root)
        argv = [str(target.executable.resolve(strict=True)), "-p", profile_id, "-z", prompt]
        launch = profile_launch_envelope(
            target=process_target, profile_id=profile_id, executable=target.executable,
            artifact_sha256=target.artifact_sha256, artifact_root=target.artifact_root,
            cwd=target.cwd, data_root=target.data_root, argv=argv,
            env_allowlist=target.env_allowlist,
            child_artifact_refs=target.child_artifact_refs,
            max_lifetime_seconds=target.max_lifetime_seconds,
            max_output_bytes=target.max_output_bytes, stdin_mode="closed",
        )
        response = authority_service.perform_delegated_effect(
            authorization, delegation_id=selected.delegation_id,
            payload=canonical_bytes(launch), peer_pid=peer_pid,
            timeout=min(timeout, float(target.max_lifetime_seconds)), cancelled=cancelled,
        )
        if isinstance(response, Mapping):
            return response
        return {"status": response.status, "body": response.body,
                "headers": dict(response.headers), "receipt_id": response.receipt_id}

    return handle


def build_selected_resource_effect_handlers(
    *,
    selected_resources: SelectedResourceRegistry,
    profile_targets: SelectedHermesProfileResolver,
    authority_service: RootDelegatedEffectService,
) -> dict[tuple[str, str], Callable[..., Mapping[str, Any]]]:
    """Build concrete handlers for enabled root-selected cron profile runs.

    Call during root `AuthorityService` assembly with selection records read
    from protected host custody. The returned map uses the service's exact
    `(operation, protected target)` key. Unenrolled, disabled, channel, webhook,
    bundle, plugin, and MCP records do not receive an effect handler here.
    """
    handlers: dict[tuple[str, str], Callable[..., Mapping[str, Any]]] = {}
    for selected in selected_resources.rows:
        if (not selected.enabled or selected.identity.kind != "crons"
                or not _cron_recipe_is_supported(selected)):
            continue
        key = (selected.operation, selected.target)
        if key in handlers:
            raise ValueError("multiple selected resources resolve to the same protected effect target")
        handlers[key] = build_cron_resource_effect_handler(
            selected.identity, selected_resources=selected_resources,
            profile_targets=profile_targets, authority_service=authority_service,
        )
    return handlers


def selected_resource_effect_blockers(
    selected_resources: SelectedResourceRegistry,
    *, profile_targets: SelectedHermesProfileResolver | None = None,
) -> Mapping[tuple[str, str], str]:
    """Return exact missing native backends for enabled root-selected records."""
    reasons: dict[tuple[str, str], str] = {}
    for selected in selected_resources.rows:
        if not selected.enabled:
            continue
        key = (selected.operation, selected.target)
        if selected.identity.kind == "crons":
            if not _cron_recipe_is_supported(selected):
                reason = "the selected cron action has no reviewed local Hermes execution recipe"
            elif selected.profile_id is None or profile_targets is None:
                reason = "the selected cron profile lacks a custody-resolved pinned Hermes process target"
            else:
                selected_profile = profile_targets.resolve_profile(selected.profile_id)
                if selected_profile is None:
                    reason = "the selected cron profile lacks a custody-resolved pinned Hermes process target"
                else:
                    action = selected.effective_spec.get("action")
                    if action.get("type") == "installer-resource-candidate-assessment":
                        try:
                            _verified_installed_resource_bundle(selected_profile, action["source"])
                        except SelectedResourceUnavailable as exc:
                            reasons[key] = str(exc)
                            continue
                    # A profile-launch handler is only the effect backend. Until a
                    # root-owned timer producer captures an actual due event and
                    # the job admission path mints a fresh child grant, a selected
                    # cron must not appear operational merely because its target
                    # and launch recipe resolve.
                    reason = (
                        "the protected timer event issuer and fresh resource-job "
                        "child-admission handler are not registered"
                    )
        elif selected.identity.kind == "channels":
            reason = "the official Hermes channel connector and protected account enrollment are unavailable"
        elif selected.identity.kind == "webhooks":
            reason = "the protected ingress listener, secret enrollment, and delegated Hermes route are unavailable"
        elif selected.identity.kind == "bundles":
            reason = "the internal Hermes orchestrator launcher and bounded child-profile delegation are unavailable"
        else:
            reason = "no root-owned effect handler is registered for this selected resource kind"
        reasons[key] = reason
    return reasons


def invoke_fixed_resource_effect(
    context: NativePluginRuntimeContext,
    effect: FixedResourceEffect,
    payload: Mapping[str, Any] | list[Any],
    *,
    intent: str,
    purpose: str = "native-hermes-chat",
    retry_index: int = 0,
    cancelled: Callable[[], bool] | None = None,
) -> BrokeredEffectResponse:
    """Run one reviewed plugin effect through fresh host authority and a fixed verb.

    Resource metadata selects no endpoint or operation.  The reviewed adapter
    supplies ``effect``; the payload is canonicalized and bound to a one-use
    host grant before it reaches the root broker.
    """
    if not isinstance(context, NativePluginRuntimeContext):
        raise TypeError("trusted NativePluginRuntimeContext is required")
    if not isinstance(intent, str) or not intent or len(intent) > 512:
        raise ResourceRuntimeError("resource effect intent is invalid")
    if purpose not in {"native-hermes-chat", "native-hermes-cron", "native-hermes-webhook", "native-hermes-channel"}:
        raise ResourceRuntimeError("resource effect purpose is not a reviewed Hermes execution source")
    if type(retry_index) is not int or not 0 <= retry_index <= 100:
        raise ResourceRuntimeError("resource effect retry index is invalid")
    expected_target = f"resource:{context.identity.kind}/{context.identity.resource_id}@{context.identity.version}"
    if effect.target != expected_target:
        raise ResourceRuntimeError("fixed effect target does not match the selected resource identity")
    if cancelled is not None and cancelled():
        raise ResourceRuntimeError("resource effect was cancelled before authorization")
    # Imported lazily so planning, packaging and offline resource inspection do
    # not require the platform authority service to be installed.
    from hermes_installer.authority import canonical_bytes, canonical_digest

    body = canonical_bytes(payload)
    if len(body) > 4 * 1024 * 1024:
        raise ResourceRuntimeError("resource effect payload exceeds four MiB")
    digest = canonical_digest(body)
    source_contexts = context.invocation_contexts(purpose=purpose, intent=intent)
    if not source_contexts:
        raise ResourceRuntimeError("trusted Hermes invocation lineage is unavailable")
    issued = context.authority.context(
        purpose=purpose, intent=intent, source_contexts=source_contexts,
        trace_id=None, lease_seconds=30.0, cancelled=cancelled,
    )
    grant = context.authority.authorize_effect(
        issued, capability=effect.capability, target=effect.target,
        recipient=effect.recipient, request_digest=digest,
        retry_index=retry_index, cancelled=cancelled,
    )
    context.authority.verify_effect(
        grant, issued, capability=effect.capability, target=effect.target,
        recipient=effect.recipient, request_digest=digest,
        retry_index=retry_index, cancelled=cancelled,
    )
    return context.authority.perform_effect(
        grant, operation=effect.operation, payload=body,
        timeout=effect.timeout_seconds, cancelled=cancelled,
    )


def invoke_scheduled_profile_run(
    context: NativePluginRuntimeContext,
    effect: FixedResourceEffect,
    *,
    profile_id: str,
    scheduled_for: str,
    intent: str,
    retry_index: int = 0,
    cancelled: Callable[[], bool] | None = None,
) -> BrokeredEffectResponse:
    """Submit a scheduled profile run through the root's fixed Hermes adapter.

    A schedule is provenance only. The root adapter must resolve the selected
    profile and independently authorize all work and delivery recipients.
    """
    if context.identity.kind != "crons" or effect.operation != "resource.cron.run":
        raise ResourceRuntimeError("scheduled profiles require a cron identity and fixed resource.cron.run operation")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", profile_id):
        raise ResourceRuntimeError("scheduled profile identity is invalid")
    if not isinstance(scheduled_for, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})", scheduled_for):
        raise ResourceRuntimeError("scheduled invocation time must be an explicit ISO-8601 instant")
    return invoke_fixed_resource_effect(
        context, effect, {"profile_id": profile_id, "scheduled_for": scheduled_for},
        intent=intent, purpose="native-hermes-cron", retry_index=retry_index, cancelled=cancelled,
    )


def invoke_webhook_delivery(
    context: NativePluginRuntimeContext,
    effect: FixedResourceEffect,
    receipt: "WebhookReceipt",
    *,
    intent: str,
    retry_index: int = 0,
    cancelled: Callable[[], bool] | None = None,
) -> BrokeredEffectResponse:
    """Hand an authenticated receipt to the root-owned Hermes ingress adapter."""
    if context.identity.kind != "webhooks" or effect.operation != "resource.webhook.deliver":
        raise ResourceRuntimeError("webhooks require a webhook identity and fixed resource.webhook.deliver operation")
    if receipt.resource_id != context.identity.resource_id:
        raise ResourceRuntimeError("webhook receipt does not match the selected resource")
    import base64

    return invoke_fixed_resource_effect(
        context, effect,
        {"event_id": receipt.event_id, "event_type": receipt.event_type,
         "body_base64": base64.b64encode(receipt.body).decode("ascii"), "body_sha256": receipt.body_sha256,
         "received_at": receipt.received_at},
        intent=intent, purpose="native-hermes-webhook", retry_index=retry_index, cancelled=cancelled,
    )


def invoke_channel_route(
    context: NativePluginRuntimeContext,
    effect: FixedResourceEffect,
    *,
    direction: str,
    conversation_id: str,
    content: str,
    intent: str,
    retry_index: int = 0,
    cancelled: Callable[[], bool] | None = None,
) -> BrokeredEffectResponse:
    """Route one connector event through Hermes with no profile selection input."""
    if context.identity.kind != "channels" or effect.operation != "resource.channel.route":
        raise ResourceRuntimeError("channels require a channel identity and fixed resource.channel.route operation")
    if direction not in {"inbound", "outbound"}:
        raise ResourceRuntimeError("channel direction must be inbound or outbound")
    if not isinstance(conversation_id, str) or not conversation_id or len(conversation_id) > 512:
        raise ResourceRuntimeError("channel conversation identity is invalid")
    if not isinstance(content, str) or len(content.encode("utf-8")) > 1_048_576:
        raise ResourceRuntimeError("channel content is invalid or exceeds one MiB")
    return invoke_fixed_resource_effect(
        context, effect,
        {"direction": direction, "conversation_id": conversation_id,
         "profile_id": "hermes", "content": content},
        intent=intent, purpose="native-hermes-channel", retry_index=retry_index, cancelled=cancelled,
    )


def invoke_internal_bundle_recruitment(
    context: NativePluginRuntimeContext,
    effect: FixedResourceEffect,
    *,
    request_id: str,
    user_request: str,
    resolved_roster: Sequence[str],
    selected_roster: Sequence[str],
    intent: str,
    retry_index: int = 0,
    cancelled: Callable[[], bool] | None = None,
) -> BrokeredEffectResponse:
    """Recruit a bounded subset of the pinned bundle roster via root Hermes.

    The root handler owns protected topology policy, profile-home isolation,
    concurrency/cancellation and correlated aggregation. This function cannot
    launch a worker or bind a channel itself.
    """
    if context.identity.kind != "bundles" or effect.operation != "resource.orchestrator.recruit":
        raise ResourceRuntimeError("bundle recruitment requires a bundle identity and fixed orchestrator verb")
    if not re.fullmatch(r"[0-9a-fA-F-]{16,64}", request_id):
        raise ResourceRuntimeError("bundle request correlation id is invalid")
    if not isinstance(user_request, str) or len(user_request.encode("utf-8")) > 128 * 1024:
        raise ResourceRuntimeError("bundle request is invalid or exceeds 128 KiB")
    if not isinstance(resolved_roster, (list, tuple)) or not isinstance(selected_roster, (list, tuple)):
        raise ResourceRuntimeError("bundle rosters must be bounded profile sequences")
    if any(not isinstance(profile, str) for profile in (*resolved_roster, *selected_roster)):
        raise ResourceRuntimeError("bundle roster contains an invalid profile identity")
    roster = tuple(dict.fromkeys(resolved_roster))
    selected = tuple(dict.fromkeys(selected_roster))
    if not roster or len(roster) > 64 or not selected or len(selected) > 16:
        raise ResourceRuntimeError("bundle recruitment roster is empty or exceeds its concurrency bounds")
    if any(not isinstance(profile, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", profile) for profile in (*roster, *selected)):
        raise ResourceRuntimeError("bundle roster contains an invalid profile identity")
    if not set(selected).issubset(roster):
        raise ResourceRuntimeError("requested specialists are outside the resolved bundle closure")
    return invoke_fixed_resource_effect(
        context, effect,
        {"request_id": request_id, "user_request": user_request,
         "resolved_roster": roster, "selected_roster": selected},
        intent=intent, purpose="native-hermes-chat", retry_index=retry_index, cancelled=cancelled,
    )


_MCP_NEXT_STEPS = {
    "filesystem": "select the assigned workspace and enroll its exact local server target; avoid an unreviewed npx install",
    "github": "select the GitHub account/repository scope, securely enroll the token reference and fixed server target",
    "home-assistant": "select the Home Assistant instance/entities and securely enroll its fixed target and credential reference",
}

_PLUGIN_NEXT_STEP = "install the reviewed native handler for this resource and enroll each fixed effect target in root-owned host policy"
_CHANNEL_NEXT_STEP = "select this channel, bind its native Hermes connector to a securely enrolled account, and verify inbound/outbound routing through Hermes"
_CRON_NEXT_STEP = "select this schedule and enroll its profile-run target, fresh host context and authorized Hermes delivery route"
_WEBHOOK_NEXT_STEP = "enroll a protected local ingress route and secret reference, then verify signed replay-safe delivery through Hermes"


def _safe_identity(resource_id: str, kind: str, version: str, source_path: str,
                   source_revision: str, source_document: Mapping[str, Any]) -> ResourceIdentity:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", resource_id):
        raise ResourceRuntimeError("resource identity is not a safe native name")
    if kind not in {"plugins", "mcps", "bundles", "channels", "crons", "webhooks"}:
        raise ResourceRuntimeError(f"unsupported runtime resource kind: {kind}")
    if not isinstance(source_path, str) or not source_path or source_path.startswith("/") or ".." in source_path.split("/"):
        raise ResourceRuntimeError("resource source path is unsafe")
    if not re.fullmatch(r"[a-fA-F0-9]{40,64}", source_revision):
        raise ResourceRuntimeError("resource source revision is not immutable")
    raw = json.dumps(source_document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return ResourceIdentity(resource_id, kind, version, source_path, source_revision, hashlib.sha256(raw).hexdigest())


def materialize_runtime_resource(
    kind: str,
    resource_id: str,
    version: str,
    source_path: str,
    source_document: Mapping[str, Any],
    effective_spec: Mapping[str, Any],
    source_revision: str,
    catalog_version: str,
) -> ResourceRuntimeArtifact:
    """Describe a native adapter binding and emit its inert, provenance-bound record.

    The record is a registration input, not an activation. It carries no
    credentials and cannot create an authority grant. Account, host and target
    readiness remain independent evidence fields.
    """
    if not isinstance(source_document, Mapping) or not isinstance(effective_spec, Mapping):
        raise ResourceRuntimeError("resource document and effective spec must be mappings")
    identity = _safe_identity(resource_id, kind, version, source_path, source_revision, source_document)
    if not isinstance(catalog_version, str) or not catalog_version:
        raise ResourceRuntimeError("catalog version is required")

    if kind == "bundles":
        imports = effective_spec.get("imports")
        _validate_bundle_declaration(effective_spec)
        if not isinstance(imports, Mapping):
            raise ResourceRuntimeError("bundle imports must be a mapping")
        topology = effective_spec.get("topology")
        is_root = isinstance(topology, Mapping) and bool(topology.get("userEntryPoint"))
        adapter_id = "hermes-installer.root-topology.v1" if is_root else "hermes-installer.internal-orchestrator.bundle.v1"
        native_path = f"orchestrator/{'root' if is_root else 'bundles'}/{resource_id}.json"
        discoverability = "Hermes root topology registry" if is_root else "installer internal orchestrator bundle registry"
        invocation = "single Hermes user entry point; internal orchestrator delegates to Hermes only" if is_root else "Orchestrator.recruit_report with the resolved internal profile roster"
        blockers = (("Root Hermes topology adapter and selected-profile runtime evidence remain pending." if is_root
                     else "Orchestrator registration and selected-profile target evidence remain pending."),)
        registration = {
            "schema": 1, "adapter": adapter_id, "identity": identity.__dict__ if hasattr(identity, "__dict__") else {
                "resource_id": identity.resource_id, "kind": identity.kind, "version": identity.version,
                "source_path": identity.source_path, "source_revision": identity.source_revision,
                "content_digest": identity.content_digest,
            },
            "catalog_version": catalog_version, "imports": dict(imports), "enabled": False,
        }
    elif kind == "crons":
        _validate_cron(effective_spec, expected_source_revision=identity.source_revision)
        adapter_id = "hermes-installer.scheduled-profile-run.v1"
        native_path = f"scheduler/resources/{resource_id}.json"
        discoverability = "installer managed scheduler registry"
        invocation = "fresh root-issued host context, then selected internal profile-run adapter"
        blockers = (_CRON_NEXT_STEP,)
        registration = _registration(identity, adapter_id, catalog_version, effective_spec, enabled=False)
    elif kind == "webhooks":
        _validate_webhook_declaration(effective_spec)
        adapter_id = "hermes-installer.authenticated-webhook.v1"
        native_path = f"ingress/resources/{resource_id}.json"
        discoverability = "installer managed protected ingress registry"
        invocation = "WebhookVerifier then Hermes-routed read-only action with fresh host authorization"
        blockers = (_WEBHOOK_NEXT_STEP,)
        registration = _registration(identity, adapter_id, catalog_version, effective_spec, enabled=False)
    elif kind == "channels":
        _validate_channel_declaration(effective_spec)
        adapter_id = "hermes-installer.native-channel-route.v1"
        native_path = f"channels/resources/{resource_id}.json"
        discoverability = "installer channel registry bound to the official Hermes user channel"
        invocation = "native Hermes inbound and outbound channel connector"
        blockers = (_CHANNEL_NEXT_STEP,)
        registration = _registration(identity, adapter_id, catalog_version, effective_spec, enabled=False)
    elif kind == "mcps":
        adapter_id = "hermes-installer.mcp-connection-registry.v1"
        native_path = f"mcp/resources/{resource_id}.json"
        discoverability = "installer MCPConnectionRegistry selected-resource registry"
        invocation = "bounded MCPConnectionRegistry initialize, discover, selected read, reconnect and close"
        blockers = (_MCP_NEXT_STEPS.get(resource_id, "select this MCP service and enroll its fixed target and account reference"),)
        registration = _registration(identity, adapter_id, catalog_version, effective_spec, enabled=False)
    elif kind == "plugins":
        try:
            from hermes_installer.components.native_plugins import native_plugin_handler_available

            available = native_plugin_handler_available(resource_id)
        except ImportError:
            available = False
        # Handler resolvability is a separate fact from Hermes discovery. The
        # installer-owned PluginContext loader is not packaged yet, so the
        # resource must not be emitted at a path that Hermes could import.
        adapter_id = resource_id if available else None
        native_path = None
        discoverability = ("reviewed register(ctx) implementation exists; trusted Hermes loader is not packaged"
                           if available else "no reviewed native PluginContext handler is installed")
        invocation = ("pending installer-owned PluginContext loader and runtime-context injection"
                      if available else "unavailable until a source-backed register(ctx) handler is installed")
        blockers = (("Package the installer-owned trusted PluginContext loader and verify Hermes discovery/runtime context.",)
                    if available else (f"{_PLUGIN_NEXT_STEP}: {resource_id}.",))
        registration = None
    else:  # guarded by _safe_identity
        raise ResourceRuntimeError(f"unsupported runtime resource kind: {kind}")

    files: dict[str, bytes] = {}
    materialized = False
    if registration is not None:
        path = f"installer-registry/runtime/{kind}/{resource_id}.json"
        files[path] = (json.dumps(registration, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        materialized = True
    return ResourceRuntimeArtifact(
        files=files,
        native_path=native_path,
        adapter_id=adapter_id,
        discoverability=discoverability,
        invocation=invocation,
        blockers=blockers,
        readiness=ResourceReadiness(materialized=materialized),
    )


def _registration(identity: ResourceIdentity, adapter_id: str, catalog_version: str,
                  effective_spec: Mapping[str, Any], *, enabled: bool) -> dict[str, Any]:
    return {
        "schema": 1,
        "adapter": adapter_id,
        "identity": {
            "resource_id": identity.resource_id, "kind": identity.kind,
            "version": identity.version, "source_path": identity.source_path,
            "source_revision": identity.source_revision, "content_digest": identity.content_digest,
        },
        "catalog_version": catalog_version,
        "effective_spec": dict(effective_spec),
        "enabled": enabled,
    }


def _freeze_json(value: Any) -> Any:
    """Recursively freeze normalized JSON values used in root enrollments."""
    from types import MappingProxyType

    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


_CRON_FIELD = re.compile(r"^(?:\*|\d+(?:-\d+)?)(?:/\d+)?(?:,(?:\*|\d+(?:-\d+)?)(?:/\d+)?)*$")
_CRON_LIMITS = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
_HTTP_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _valid_header_name(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 128 and bool(_HTTP_HEADER_NAME.fullmatch(value))


def _validate_cron(spec: Mapping[str, Any], *, expected_source_revision: str | None = None) -> None:
    expression = spec.get("schedule")
    fields = expression.split() if isinstance(expression, str) else []
    if len(fields) != 5:
        raise ResourceRuntimeError("cron schedule must have five fields")
    for field_value, (minimum, maximum) in zip(fields, _CRON_LIMITS, strict=True):
        if not _CRON_FIELD.fullmatch(field_value):
            raise ResourceRuntimeError("cron schedule contains an unsupported field")
        for part in field_value.split(","):
            base, slash, step = part.partition("/")
            if slash and (not step.isdigit() or int(step) < 1 or int(step) > maximum - minimum + 1):
                raise ResourceRuntimeError("cron schedule step is out of range")
            if base == "*":
                continue
            start, dash, end = base.partition("-")
            if not start.isdigit() or dash and (not end.isdigit() or int(start) > int(end)):
                raise ResourceRuntimeError("cron schedule range is invalid")
            if not minimum <= int(start) <= maximum or dash and not minimum <= int(end) <= maximum:
                raise ResourceRuntimeError("cron schedule field is out of range")
    timezone = spec.get("timezone")
    if not isinstance(timezone, str) or not timezone or len(timezone) > 128:
        raise ResourceRuntimeError("cron timezone is required")
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(timezone)
    except Exception:
        raise ResourceRuntimeError("cron timezone is not available on this host") from None
    action = spec.get("action")
    runtime = spec.get("runtime")
    if not isinstance(action, Mapping) or action.get("type") not in {
        "profile-run", "installer-resource-candidate-assessment",
    }:
        raise ResourceRuntimeError("cron action is outside the reviewed native scheduler set")
    if action.get("type") == "installer-resource-candidate-assessment":
        source = action.get("source")
        catalog_version = source.get("catalogVersion") if isinstance(source, Mapping) else None
        if (action.get("mode") != "candidate-assessment" or not isinstance(source, Mapping)
                or source.get("kind") != "installer-bundle"
                or not isinstance(catalog_version, str)
                or source.get("path") != f"resources/vendor/hermes-agent-resources-{catalog_version}"
                or not re.fullmatch(r"[a-fA-F0-9]{40,64}", str(source.get("revision", "")))
                or expected_source_revision is not None
                and source.get("revision", "").lower() != expected_source_revision.lower()
                or "repository" in action or "ref" in action):
            raise ResourceRuntimeError("registry candidate assessment must use the pinned installer bundle only")
    if not isinstance(runtime, Mapping) or runtime.get("engine") != "hermes-cron":
        raise ResourceRuntimeError("cron must declare the Hermes cron engine")
    if runtime.get("profileSelection") != "registry-action-profile":
        raise ResourceRuntimeError("cron profile must come from its reviewed registry action")
    policy = spec.get("policy")
    if not isinstance(policy, Mapping) or policy.get("authorityFromSchedule") != "deny":
        raise ResourceRuntimeError("cron schedules must not create authority")
    if policy.get("staticRecipientListAsAuthority") != "deny":
        raise ResourceRuntimeError("cron static recipients must not create authority")
    requires = spec.get("requires")
    profiles = requires.get("profiles") if isinstance(requires, Mapping) else None
    profile = action.get("profile")
    if not isinstance(profiles, (list, tuple)) or not isinstance(profile, str) or profile not in profiles:
        raise ResourceRuntimeError("cron action profile must be explicitly selected in its dependency closure")


def _cron_instant_matches(spec: Mapping[str, Any], instant: str) -> bool:
    """Check that an explicit instant is a minute selected by the cron rule."""
    from datetime import datetime
    from zoneinfo import ZoneInfo

    try:
        parsed = datetime.fromisoformat(instant.replace("Z", "+00:00"))
        timezone = ZoneInfo(spec["timezone"])
        local = parsed.astimezone(timezone)
    except (KeyError, TypeError, ValueError):
        return False
    if parsed.tzinfo is None or local.second != 0 or local.microsecond != 0:
        return False
    fields = spec["schedule"].split()
    if len(fields) != 5:
        return False
    values = (local.minute, local.hour, local.day, local.month, (local.weekday() + 1) % 7)
    bounds = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
    matches = tuple(
        _cron_field_matches(field, value, minimum, maximum, index == 4)
        for index, (field, value, (minimum, maximum)) in enumerate(zip(fields, values, bounds, strict=True))
    )
    day_of_month_wild = any(part.startswith("*") for part in fields[2].split(","))
    day_of_week_wild = any(part.startswith("*") for part in fields[4].split(","))
    calendar_match = matches[2] and matches[4] if day_of_month_wild or day_of_week_wild else matches[2] or matches[4]
    return matches[0] and matches[1] and matches[3] and calendar_match


def _cron_field_matches(field_value: str, value: int, minimum: int, maximum: int,
                        is_weekday: bool = False) -> bool:
    for part in field_value.split(","):
        base, slash, step_text = part.partition("/")
        step = int(step_text) if slash else 1
        if base == "*":
            start, end = minimum, maximum
        else:
            start_text, dash, end_text = base.partition("-")
            start = int(start_text)
            end = int(end_text) if dash else start
        candidates = (0, 7) if is_weekday and value == 0 else (value,)
        if any(start <= candidate <= end and (candidate - start) % step == 0 for candidate in candidates):
            return True
    return False


def _validate_channel_declaration(spec: Mapping[str, Any]) -> None:
    adapter = spec.get("adapter")
    if adapter not in {"discord", "telegram", "local-audio-assist", "http", "composio-whatsapp-business"}:
        raise ResourceRuntimeError("channel adapter is not in the reviewed native connector set")
    routing = spec.get("routing")
    if not isinstance(routing, Mapping):
        raise ResourceRuntimeError("channel requires an explicit Hermes routing policy")
    if routing.get("inboundProfile") != "hermes" or routing.get("outboundProfile") != "hermes":
        raise ResourceRuntimeError("all user-facing channel traffic must route through Hermes")
    if routing.get("allowDirectProfileSelection") is not False:
        raise ResourceRuntimeError("channels cannot accept direct profile selection")
    policy = spec.get("policy")
    if not isinstance(policy, Mapping) or policy.get("requireHermesGateway") is not True:
        raise ResourceRuntimeError("channel must require the native Hermes gateway")
    if policy.get("rejectNonHermesProfileTarget") is not True:
        raise ResourceRuntimeError("channel must reject non-Hermes profile targets")
    inbound = spec.get("inbound")
    if adapter == "discord" and (not isinstance(inbound, Mapping) or not inbound.get("allowedGuildIds") or policy.get("denyUnknownGuilds") is not True):
        raise ResourceRuntimeError("Discord requires an explicit guild allowlist")
    if adapter == "telegram" and (not isinstance(inbound, Mapping) or not inbound.get("allowedChatIds") or policy.get("denyUnknownChats") is not True):
        raise ResourceRuntimeError("Telegram requires an explicit chat allowlist")
    if adapter == "http":
        listen = spec.get("listen")
        if (not isinstance(listen, Mapping) or listen.get("host") != "127.0.0.1"
                or policy.get("requireUpstreamAuthentication") is not True
                or policy.get("exposeDirectlyToInternet") is not False):
            raise ResourceRuntimeError("HTTP channel must be loopback-only and authenticated behind its gateway")
    if adapter == "local-audio-assist":
        pipeline = spec.get("pipeline")
        if (not isinstance(pipeline, Mapping) or policy.get("localFirst") is not True
                or policy.get("rawAudioRetention") is not False or policy.get("cloudFallback") != "deny"):
            raise ResourceRuntimeError("voice channel must keep audio local and disable raw retention/cloud fallback")
    if adapter == "composio-whatsapp-business":
        integration = spec.get("integration")
        if (not isinstance(inbound, Mapping) or not inbound.get("allowedUserNumbers")
                or not isinstance(integration, Mapping) or integration.get("connection") != "user-authorized"
                or policy.get("businessAccountsOnly") is not True
                or policy.get("proactiveOutbound") != "delegated-template-only"):
            raise ResourceRuntimeError("WhatsApp requires a user-authorized business connection and recipient allowlist")


def _validate_bundle_declaration(spec: Mapping[str, Any]) -> None:
    imports = spec.get("imports")
    if not isinstance(imports, Mapping) or not imports:
        raise ResourceRuntimeError("bundle imports must be a non-empty mapping")
    allowed = {"profiles", "skills", "plugins", "mcps", "bundles", "channels", "crons", "webhooks"}
    if set(imports) - allowed:
        raise ResourceRuntimeError("bundle contains an unsupported import category")
    for category, members in imports.items():
        if not isinstance(members, (list, tuple)) or not members:
            raise ResourceRuntimeError(f"bundle import category {category} must be a non-empty list")
        if any(not isinstance(member, str) or not member or len(member) > 192 for member in members):
            raise ResourceRuntimeError(f"bundle import category {category} contains an invalid selector")
    topology = spec.get("topology")
    if topology is not None:
        if not isinstance(topology, Mapping) or topology.get("userEntryPoint") != "hermes":
            raise ResourceRuntimeError("root topology must name Hermes as its sole user entry point")
        if topology.get("internalCoordinator") != "orchestrator":
            raise ResourceRuntimeError("root topology must name the reviewed internal orchestrator")


def _validate_webhook_declaration(spec: Mapping[str, Any]) -> None:
    path = spec.get("path")
    method = spec.get("method")
    if (not isinstance(path, str) or not path.startswith("/hooks/") or ".." in path.split("/")
            or "\\" in path or "?" in path or "#" in path or any(ord(char) < 0x20 for char in path)):
        raise ResourceRuntimeError("webhook path must remain under the protected /hooks namespace")
    if method != "POST":
        raise ResourceRuntimeError("only POST webhooks are supported")
    auth = spec.get("authentication")
    if not isinstance(auth, Mapping) or auth.get("type") not in {"hmac-sha256", "bearer"}:
        raise ResourceRuntimeError("webhook must declare HMAC-SHA256 or bearer authentication")
    if auth.get("type") == "hmac-sha256" and not _valid_header_name(auth.get("signatureHeader")):
        raise ResourceRuntimeError("webhook signature header name is invalid")
    policy = spec.get("policy")
    if not isinstance(policy, Mapping) or policy.get("authorityFromWebhookReceipt") != "deny":
        raise ResourceRuntimeError("webhook receipts must not create authority")
    action = spec.get("action")
    if not isinstance(action, Mapping) or action.get("type") not in {
        "incident-triage", "repository-change-review", "registry-update-assessment",
    }:
        raise ResourceRuntimeError("webhook action is not in the reviewed read-oriented Hermes ingress set")
    if action.get("mutate") not in (None, False):
        raise ResourceRuntimeError("webhook actions cannot mutate from receipt authority")
    event = spec.get("event")
    if event is not None and (not isinstance(event, Mapping) or not _valid_header_name(event.get("header"))
                              or not isinstance(event.get("allowed"), (list, tuple)) or not event["allowed"]):
        raise ResourceRuntimeError("webhook event types must be explicitly allowlisted")
    replay = spec.get("replayProtection")
    if replay is not None and not isinstance(replay, Mapping):
        raise ResourceRuntimeError("webhook replay protection must be a mapping")
    replay_header = replay.get("deliveryIdHeader") if isinstance(replay, Mapping) else None
    policy_header = policy.get("deliveryIdHeader")
    policy_id_enabled = policy.get("deduplicateByDeliveryId") is True
    body_digest_enabled = isinstance(replay, Mapping) and replay.get("requireEventIdentity") is True
    if (not _valid_header_name(replay_header) and not (policy_id_enabled and _valid_header_name(policy_header))
            and not body_digest_enabled):
        raise ResourceRuntimeError("webhook requires a provider event identity or bounded body deduplication")
    if replay_header is not None and not _valid_header_name(replay_header):
        raise ResourceRuntimeError("webhook delivery identity header is invalid")
    if policy_header is not None and not _valid_header_name(policy_header):
        raise ResourceRuntimeError("webhook policy delivery-ID header is invalid")
    if policy_id_enabled and not _valid_header_name(policy_header):
        raise ResourceRuntimeError("webhook delivery-ID deduplication requires an exact header")
    if policy.get("staticRecipientListAsAuthority") not in (None, "deny"):
        raise ResourceRuntimeError("webhook static recipients cannot create authority")


class ReplayStore(Protocol):
    def claim(self, resource_id: str, event_id: str, expires_at: float) -> bool: ...


class ReplayStoreFull(ResourceRuntimeError):
    """The durable replay ledger is full; delivery must fail closed."""


class SQLiteReplayStore:
    """Bounded, restart-durable webhook replay ledger in a private root directory.

    The caller supplies a host-selected file path beneath a root-owned service
    directory. Resource and event identities are stored only as a
    domain-separated digest. Live entries are never evicted to make room;
    expired rows are pruned atomically with each claim. A full or unavailable
    store raises, so ingress cannot turn a storage failure into a dispatch.
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS replay_claims (
            resource_event_digest TEXT PRIMARY KEY,
            expires_at REAL NOT NULL
        ) WITHOUT ROWID
    """

    def __init__(self, path: Path, *, max_entries: int = 100_000,
                 timeout_seconds: float = 2.0):
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("replay database path must be an absolute Path")
        if type(max_entries) is not int or not 1 <= max_entries <= 1_000_000:
            raise ValueError("replay ledger capacity is outside supported bounds")
        if (type(timeout_seconds) not in (int, float)
                or not 0.05 <= timeout_seconds <= 10.0):
            raise ValueError("replay database timeout is outside supported bounds")
        self.path = path
        self.max_entries = max_entries
        self.timeout_seconds = float(timeout_seconds)
        self._prepare_private_path()
        db = self._connect()
        try:
            db.execute(self._SCHEMA)
        finally:
            db.close()

    def _prepare_private_path(self) -> None:
        parent = self.path.parent
        try:
            parent_stat = parent.lstat()
        except OSError as exc:
            raise ResourceRuntimeError("replay store parent must already exist") from exc
        if (not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode)
                or parent_stat.st_uid != os.geteuid()
                or stat.S_IMODE(parent_stat.st_mode) != 0o700):
            raise ResourceRuntimeError("replay store parent must be private and owned by the service identity")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            fd = None
        except OSError as exc:
            raise ResourceRuntimeError("replay database could not be created safely") from exc
        if fd is not None:
            os.close(fd)
        try:
            info = self.path.lstat()
        except OSError as exc:
            raise ResourceRuntimeError("replay database is unavailable") from exc
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ResourceRuntimeError("replay database must be a private service-owned regular file")
        if stat.S_IMODE(info.st_mode) != 0o600:
            try:
                self.path.chmod(0o600)
            except OSError as exc:
                raise ResourceRuntimeError("replay database permissions could not be restricted") from exc

    def _connect(self) -> sqlite3.Connection:
        db: sqlite3.Connection | None = None
        try:
            db = sqlite3.connect(self.path, timeout=self.timeout_seconds, isolation_level=None)
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.execute(f"PRAGMA busy_timeout={int(self.timeout_seconds * 1000)}")
            return db
        except sqlite3.Error as exc:
            if db is not None:
                db.close()
            raise ResourceRuntimeError("replay ledger is unavailable") from exc

    @staticmethod
    def _claim_digest(resource_id: str, event_id: str) -> str:
        if (not isinstance(resource_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", resource_id)
                or not isinstance(event_id, str) or not event_id or len(event_id) > 256
                or any(ord(char) < 0x20 for char in event_id)):
            raise ResourceRuntimeError("replay claim identity is malformed")
        material = b"hermes-resource-webhook-replay-v1\0" + resource_id.encode() + b"\0" + event_id.encode()
        return hashlib.sha256(material).hexdigest()

    def claim(self, resource_id: str, event_id: str, expires_at: float) -> bool:
        if type(expires_at) not in (int, float) or not float("-inf") < float(expires_at) < float("inf"):
            raise ResourceRuntimeError("replay expiry must be a finite timestamp")
        now = time.time()
        if not now < float(expires_at) <= now + 7 * 86_400:
            raise ResourceRuntimeError("replay expiry must be in the next seven days")
        digest = self._claim_digest(resource_id, event_id)
        db: sqlite3.Connection | None = None
        try:
            db = self._connect()
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM replay_claims WHERE expires_at <= ?", (now,))
            if db.execute("SELECT 1 FROM replay_claims WHERE resource_event_digest=?", (digest,)).fetchone():
                db.rollback()
                return False
            count = db.execute("SELECT count(*) FROM replay_claims").fetchone()[0]
            if count >= self.max_entries:
                db.rollback()
                raise ReplayStoreFull("durable webhook replay ledger is full")
            db.execute("INSERT INTO replay_claims(resource_event_digest, expires_at) VALUES (?, ?)",
                       (digest, float(expires_at)))
            db.commit()
            return True
        except ReplayStoreFull:
            raise
        except sqlite3.Error as exc:
            if db is not None:
                db.rollback()
            raise ResourceRuntimeError("durable webhook replay claim failed closed") from exc
        finally:
            if db is not None:
                db.close()


@dataclass(frozen=True, slots=True)
class WebhookReceipt:
    resource_id: str
    event_id: str
    event_type: str
    body: bytes
    body_sha256: str
    received_at: float


class WebhookVerifier:
    """Authenticate and deduplicate a webhook; receipts never grant authority."""

    def __init__(self, replay_store: ReplayStore, *, max_body_bytes: int = 1_048_576,
                 replay_window_seconds: int = 86_400, now: Callable[[], float] = time.time):
        if not 1 <= max_body_bytes <= 4 * 1024 * 1024:
            raise ValueError("webhook body limit must be at most four MiB")
        if not 1 <= replay_window_seconds <= 7 * 86_400:
            raise ValueError("webhook replay window must be bounded")
        self.replay_store, self.max_body_bytes = replay_store, max_body_bytes
        self.replay_window_seconds, self.now = replay_window_seconds, now

    def verify(self, resource_id: str, spec: Mapping[str, Any], headers: Mapping[str, str],
               body: bytes, secret: bytes) -> WebhookReceipt:
        _validate_webhook_declaration(spec)
        if not isinstance(body, bytes) or len(body) > self.max_body_bytes:
            raise ResourceRuntimeError("webhook body is malformed or exceeds its size limit")
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ResourceRuntimeError("webhook secret reference did not resolve to a strong secret")
        normalized = {str(key).lower(): str(value) for key, value in headers.items()}
        expected_type = (spec.get("validation") or {}).get("contentType", "application/json")
        if not normalized.get("content-type", "").split(";", 1)[0].strip().lower() == expected_type.lower():
            raise ResourceRuntimeError("webhook content type is not allowed")
        try:
            decoded = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ResourceRuntimeError("webhook body is not valid JSON") from None
        if not isinstance(decoded, (dict, list)):
            raise ResourceRuntimeError("webhook JSON root must be an object or array")

        authentication = spec["authentication"]
        auth_type = authentication["type"]
        if auth_type == "hmac-sha256":
            signature_header = authentication.get("signatureHeader")
            signature = normalized.get(str(signature_header).lower()) if isinstance(signature_header, str) else None
            if not isinstance(signature, str) or not re.fullmatch(r"sha256=[0-9a-fA-F]{64}", signature):
                raise ResourceRuntimeError("webhook signature is missing or malformed")
            expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature.lower(), expected):
                raise ResourceRuntimeError("webhook signature verification failed")
        else:
            supplied = normalized.get("authorization", "")
            if not supplied.startswith("Bearer ") or not hmac.compare_digest(supplied[7:].encode(), secret):
                raise ResourceRuntimeError("webhook bearer credential verification failed")

        event = spec.get("event")
        event_type = ""
        if isinstance(event, Mapping):
            event_header = event.get("header")
            event_type = normalized.get(str(event_header).lower(), "") if isinstance(event_header, str) else ""
            allowed = event.get("allowed")
            if isinstance(allowed, (list, tuple)) and event_type not in allowed:
                raise ResourceRuntimeError("webhook event type is not allowed")
        replay = spec.get("replayProtection")
        policy = spec.get("policy")
        delivery_header = replay.get("deliveryIdHeader") if isinstance(replay, Mapping) else None
        if delivery_header is None and isinstance(policy, Mapping):
            delivery_header = policy.get("deliveryIdHeader")
        if isinstance(delivery_header, str):
            event_id = normalized.get(delivery_header.lower(), "")
            if not event_id:
                raise ResourceRuntimeError("configured webhook delivery identity header is missing")
        else:
            event_id = hashlib.sha256(body).hexdigest()
        if not event_id or len(event_id) > 256 or any(ord(c) < 0x20 for c in event_id):
            raise ResourceRuntimeError("webhook delivery identity is missing or invalid")
        received_at = self.now()
        if not self.replay_store.claim(resource_id, event_id, received_at + self.replay_window_seconds):
            raise ResourceRuntimeError("duplicate webhook delivery was rejected")
        return WebhookReceipt(resource_id, event_id, event_type, body,
                              hashlib.sha256(body).hexdigest(), received_at)


def resolve_bundle_roster(bundle: Any, resources: Sequence[Any]) -> tuple[str, ...]:
    """Resolve a bundle's transitive internal profile roster from a pinned closure.

    A primary Hermes topology bundle (which owns user-facing channels) is a
    root registration and cannot be recruited as a specialist roster.
    """
    resource = getattr(bundle, "resource", None)
    if getattr(getattr(resource, "kind", None), "value", None) != "bundles":
        raise ResourceRuntimeError("bundle roster requires a resolved Bundle")
    spec = getattr(bundle, "effective_spec", None) or getattr(resource, "body", None)
    if not isinstance(spec, Mapping):
        raise ResourceRuntimeError("resolved bundle has no effective specification")
    topology = spec.get("topology")
    if isinstance(topology, Mapping) and topology.get("userEntryPoint"):
        raise ResourceRuntimeError("primary Hermes topology bundles cannot be recruited as specialists")
    if isinstance(spec.get("policy"), Mapping) and spec["policy"].get("userFacing") is True:
        raise ResourceRuntimeError("user-facing bundles cannot create direct specialist channels")

    by_identity: dict[str, Any] = {}
    for item in resources:
        item_resource = getattr(item, "resource", None)
        kind = getattr(getattr(item_resource, "kind", None), "value", None)
        name = getattr(item_resource, "id", None)
        version = getattr(item_resource, "version", None)
        if isinstance(kind, str) and isinstance(name, str) and isinstance(version, str):
            by_identity[f"{kind}/{name}@{version}"] = item

    root_resource = resource
    root_key = f"bundles/{root_resource.id}@{root_resource.version}"
    if by_identity.get(root_key) is not bundle:
        raise ResourceRuntimeError("bundle is outside the supplied pinned resolution closure")
    roster: list[str] = []
    visited: set[str] = set()
    active: set[str] = set()

    def walk(item: Any) -> None:
        item_resource = item.resource
        key = f"{item_resource.kind.value}/{item_resource.id}@{item_resource.version}"
        if key in active:
            raise ResourceRuntimeError("resolved bundle graph contains a cycle")
        if key in visited:
            return
        visited.add(key)
        active.add(key)
        for dependency in item.dependencies:
            if not isinstance(dependency, str) or dependency not in by_identity:
                raise ResourceRuntimeError("bundle dependency is missing from the pinned resolution closure")
            child = by_identity[dependency]
            child_kind = child.resource.kind.value
            if child_kind == "profiles":
                if child.resource.id not in roster:
                    roster.append(child.resource.id)
            elif child_kind == "bundles":
                walk(child)
        active.remove(key)

    walk(bundle)
    if not roster:
        raise ResourceRuntimeError("bundle resolves to no internal profiles")
    return tuple(roster)
