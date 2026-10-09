"""Trusted-context memory lifecycle, single capture owner, and fail-closed persistence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Protocol


class MemoryUnavailable(RuntimeError):
    """No verified persistent engine, owner ledger, or trusted route is configured."""


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    id: str
    namespace: str
    profile: str
    source: str
    text: str
    provenance: tuple[str, ...] = ()


class Provider(Protocol):
    name: str
    def backup(self, namespace: str, *, context: Any = None) -> Any: ...
    def restore(self, backup: Any, *, context: Any = None) -> None: ...
    def capture(self, record: MemoryRecord, *, context: Any = None) -> None: ...
    def search(self, namespace: str, query: str, limit: int, *, context: Any = None) -> list[MemoryRecord]: ...
    def export(self, namespace: str, *, context: Any = None) -> list[MemoryRecord]: ...
    def remove(self, namespace: str, record_id: str, *, context: Any = None) -> bool: ...


class OwnerLedger(Protocol):
    def get_owner(self, profile: str) -> str | None: ...
    def set_owner(self, profile: str, name: str | None) -> None: ...


TrustedAuthorizer = Callable[[Any, str, str, str], tuple[bool, str]]


def _namespace(context: Any) -> str | None:
    # HostContext uses namespace_id; legacy signed DispatchContext uses namespace.
    return getattr(context, "namespace_id", getattr(context, "namespace", None))


def _private_or_unknown(context: Any) -> bool:
    value = getattr(context, "sensitivity", "UNKNOWN")
    return getattr(value, "name", str(value)).upper() in {"PRIVATE", "CONFIDENTIAL", "UNKNOWN"}


class MemoryManager:
    """Caller metadata is only a scope assertion; host authority decides effects."""

    def __init__(self, providers: Iterable[Provider], route_allowed=None, *,
                 owner_ledger: OwnerLedger | None = None,
                 trusted_authorizer: TrustedAuthorizer | None = None):
        self.providers = {provider.name: provider for provider in providers}
        self._legacy_route = route_allowed
        self.owner_ledger = owner_ledger
        self.trusted_authorizer = trusted_authorizer

    def _require_runtime(self) -> None:
        if self.owner_ledger is None or self.trusted_authorizer is None:
            raise MemoryUnavailable("memory remains unavailable until durable ownership and host authority are configured")

    def _authorize(self, context: Any, operation: str, profile: str, namespace: str) -> None:
        self._require_runtime()
        if (context is None or getattr(context, "profile_id", None) != profile
                or _namespace(context) != namespace):
            raise PermissionError("signed host profile and namespace context is required")
        allowed, reason = self.trusted_authorizer(context, operation, profile, namespace)
        if not allowed:
            raise PermissionError(reason or "host memory policy denied this operation")

    def select_owner(self, profile: str, name: str | None, *, context: Any = None) -> None:
        self._require_runtime()
        if context is None or getattr(context, "profile_id", None) != profile:
            raise PermissionError("signed host profile context is required to change memory owner")
        if name is not None and name not in self.providers:
            raise MemoryUnavailable(f"memory provider is not installed: {name}")
        allowed, reason = self.trusted_authorizer(context, "memory_owner", profile, _namespace(context) or "")
        if not allowed:
            raise PermissionError(reason or "host memory ownership policy denied this change")
        old = self.owner_ledger.get_owner(profile)
        if old == name:
            return
        previous = self.providers.get(old) if old else None
        selected = self.providers.get(name) if name else None
        if old and previous is None:
            raise MemoryUnavailable(f"persisted memory owner is unavailable: {old}")
        begin = getattr(self.owner_ledger, "begin_transition", None)
        commit = getattr(self.owner_ledger, "commit_transition", None)
        abort = getattr(self.owner_ledger, "abort_transition", None)
        transition_id = begin(profile, old, name) if begin else None
        stopped = False
        started = False
        try:
            if previous is not None:
                flush = getattr(previous, "flush", None)
                stop = getattr(previous, "stop_capture", None)
                if flush:
                    flush(profile)
                if stop:
                    stop(profile)
                stopped = True
            if selected is not None:
                start = getattr(selected, "start_capture", None)
                if start:
                    start(profile, context=context)
                started = True
            if commit:
                commit(profile, transition_id, name)
            else:
                self.owner_ledger.set_owner(profile, name)
        except BaseException:
            if started and selected is not None:
                stop = getattr(selected, "stop_capture", None)
                if stop:
                    try:
                        stop(profile)
                    except Exception:
                        pass
            if stopped and previous is not None:
                start = getattr(previous, "start_capture", None)
                if start:
                    try:
                        start(profile, context=context)
                    except Exception:
                        pass
            if abort:
                abort(profile, transition_id)
            raise

    def ingest(self, record: MemoryRecord, *, context: Any = None,
               generated_by_memory: bool = False) -> None:
        self._authorize(context, "memory_capture", record.profile, record.namespace)
        if generated_by_memory or record.source.startswith("memory:"):
            raise PermissionError("recursive memory ingestion denied")
        owner = self.owner_ledger.get_owner(record.profile)
        provider = self.providers.get(owner) if owner else None
        if provider is None:
            raise MemoryUnavailable("profile has no available persistent capture owner")
        # Provider performs extraction and embedding as separate signed effects.
        provider.capture(record, context=context)

    def search(self, name: str, namespace: str, query: str, limit: int = 10, *,
               context: Any = None) -> list[MemoryRecord]:
        if not 1 <= limit <= 100:
            raise ValueError("limit outside 1..100")
        provider = self.providers.get(name)
        if provider is None:
            raise MemoryUnavailable("memory provider is not installed")
        profile = getattr(context, "profile_id", "")
        self._authorize(context, "memory_retrieval", profile, namespace)
        return [item for item in provider.search(namespace, query, limit, context=context)
                if item.namespace == namespace and item.profile == profile][:limit]

    def export(self, name: str, namespace: str, *, context: Any = None) -> list[MemoryRecord]:
        profile = getattr(context, "profile_id", "")
        self._authorize(context, "memory_export", profile, namespace)
        provider = self.providers.get(name)
        if provider is None:
            raise MemoryUnavailable("memory provider is not installed")
        return [item for item in provider.export(namespace, context=context)
                if item.namespace == namespace and item.profile == profile]

    def backup(self, name: str, namespace: str, *, context: Any = None) -> Any:
        profile = getattr(context, "profile_id", "")
        self._authorize(context, "memory_backup", profile, namespace)
        provider = self.providers.get(name)
        if provider is None:
            raise MemoryUnavailable("memory provider is not installed")
        return provider.backup(namespace, context=context)

    def restore(self, name: str, backup: Any, *, context: Any = None) -> None:
        profile = getattr(context, "profile_id", "")
        namespace = getattr(context, "namespace_id", _namespace(context) or "")
        self._authorize(context, "memory_restore", profile, namespace)
        provider = self.providers.get(name)
        if provider is None:
            raise MemoryUnavailable("memory provider is not installed")
        if getattr(backup, "provider", None) != name:
            raise PermissionError("backup belongs to a different provider")
        provider.restore(backup, context=context)

    def remove(self, name: str, namespace: str, record_id: str, *, context: Any = None) -> bool:
        profile = getattr(context, "profile_id", "")
        self._authorize(context, "memory_delete", profile, namespace)
        provider = self.providers.get(name)
        if provider is None:
            raise MemoryUnavailable("memory provider is not installed")
        visible = self.search(name, namespace, record_id, 100, context=context)
        if not any(item.id == record_id for item in visible):
            return False
        return provider.remove(namespace, record_id, context=context)
