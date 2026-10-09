"""Memory lifecycle gates: durable ownership and trusted dispatch are mandatory."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol
from hermes_installer.policy import DispatchContext

class MemoryUnavailable(RuntimeError):
    """No verified persistent engine or trusted route is configured."""

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
    def capture(self, record: MemoryRecord) -> None: ...
    def search(self, namespace: str, query: str, limit: int) -> list[MemoryRecord]: ...
    def export(self, namespace: str) -> list[MemoryRecord]: ...
    def remove(self, namespace: str, record_id: str) -> bool: ...

class OwnerLedger(Protocol):
    def get_owner(self, profile: str) -> str | None: ...
    def set_owner(self, profile: str, name: str | None) -> None: ...

TrustedAuthorizer = Callable[[DispatchContext, str, str, str], tuple[bool, str]]

class MemoryManager:
    """Never uses caller record.source/provenance as authorization evidence."""
    def __init__(self, providers: Iterable[Provider], route_allowed=None, *,
                 owner_ledger: OwnerLedger | None = None,
                 trusted_authorizer: TrustedAuthorizer | None = None):
        self.providers = {provider.name: provider for provider in providers}
        # route_allowed is kept only so an old caller fails closed rather than silently migrating.
        self._legacy_route = route_allowed
        self.owner_ledger = owner_ledger
        self.trusted_authorizer = trusted_authorizer

    def _require_runtime(self):
        if self.owner_ledger is None or self.trusted_authorizer is None:
            raise MemoryUnavailable("memory engines remain unavailable until durable owner and trusted route adapters are configured")

    def _authorize(self, context: DispatchContext | None, operation: str, profile: str, namespace: str) -> None:
        self._require_runtime()
        if context is None or context.profile_id != profile or getattr(context, "namespace", None) != namespace:
            raise PermissionError("trusted profile and namespace context is required")
        classification = getattr(context, "effective_sensitivity", context.sensitivity)
        if getattr(classification, "name", str(classification)).upper() == "UNKNOWN":
            raise PermissionError("unknown-sensitivity memory operation is denied")
        allowed, reason = self.trusted_authorizer(context, operation, profile, namespace)
        if not allowed:
            raise PermissionError(reason or "host memory policy denied this operation")

    def select_owner(self, profile: str, name: str | None) -> None:
        self._require_runtime()
        if name is not None and name not in self.providers:
            raise MemoryUnavailable(f"memory provider is not installed: {name}")
        old = self.owner_ledger.get_owner(profile)
        if old == name:
            return
        if old:
            provider = self.providers.get(old)
            if provider is None:
                raise MemoryUnavailable(f"persisted memory owner is unavailable: {old}")
            flush = getattr(provider, "flush", None)
            stop = getattr(provider, "stop_capture", None)
            if flush: flush(profile)
            if stop: stop(profile)
        if name is not None:
            start = getattr(self.providers[name], "start_capture", None)
            if start: start(profile)
        self.owner_ledger.set_owner(profile, name)

    def ingest(self, record: MemoryRecord, *, context: DispatchContext | None = None,
               generated_by_memory: bool = False) -> None:
        self._authorize(context, "memory_extraction", record.profile, record.namespace)
        if generated_by_memory:
            raise PermissionError("recursive memory ingestion denied by trusted caller")
        owner = self.owner_ledger.get_owner(record.profile)
        if owner is None or owner not in self.providers:
            raise MemoryUnavailable("profile has no available persistent capture owner")
        self.trusted_authorizer(context, "memory_embedding", record.profile, record.namespace)
        self.providers[owner].capture(record)

    def search(self, name: str, namespace: str, query: str, limit: int = 10, *,
               context: DispatchContext | None = None):
        if not 1 <= limit <= 100:
            raise ValueError("limit outside 1..100")
        if name not in self.providers:
            raise MemoryUnavailable("memory provider is not installed")
        profile = getattr(context, "profile_id", "")
        self._authorize(context, "memory_retrieval", profile, namespace)
        return [record for record in self.providers[name].search(namespace, query, limit)
                if record.namespace == namespace and record.profile == profile][:limit]

    def export(self, name: str, namespace: str, *, context: DispatchContext | None = None):
        profile = getattr(context, "profile_id", "")
        self._authorize(context, "memory_export", profile, namespace)
        if name not in self.providers:
            raise MemoryUnavailable("memory provider is not installed")
        return [record for record in self.providers[name].export(namespace)
                if record.namespace == namespace and record.profile == profile]

    def remove(self, name: str, namespace: str, record_id: str, *, context: DispatchContext | None = None):
        profile = getattr(context, "profile_id", "")
        self._authorize(context, "memory_delete", profile, namespace)
        if name not in self.providers:
            raise MemoryUnavailable("memory provider is not installed")
        visible = self.search(name, namespace, record_id, 100, context=context)
        if not any(record.id == record_id for record in visible):
            return False
        return self.providers[name].remove(namespace, record_id)
