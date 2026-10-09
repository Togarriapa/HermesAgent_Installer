"""Broker-only, pinned memory-provider adapters; no direct network or startup."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .lifecycle import MemoryRecord


class MemoryProviderError(RuntimeError):
    pass


class MemoryBroker(Protocol):
    def context(self, *, purpose: str, intent: str, source_contexts: tuple[Any, ...] = (), trace_id: str | None = None, lease_seconds: int = 30) -> Any: ...
    def authorize_effect(self, context: Any, *, capability: str, target: str, request_digest: str, recipient: str | None = None) -> Any: ...
    def memory_request(self, grant: Any, *, target: str, request_digest: str, payload: bytes, timeout: float, cancelled: Callable[[], bool] | None = None) -> Any: ...


@dataclass(frozen=True, slots=True)
class ProviderStatus:
    provider: str
    available: bool
    detail: str
    service_revision: str | None = None


class BrokerMemoryProvider:
    """Broker resolves each opaque target to a protected pinned service handler."""
    name = ""
    actions = frozenset({"doctor", "capture", "extract", "embed", "search", "export", "delete"})

    def __init__(self, broker: MemoryBroker, *, intent: str = "memory-service", timeout: float = 8.0,
                 cancelled: Callable[[], bool] | None = None):
        if not self.name or not 0 < timeout <= 30:
            raise ValueError("named provider and bounded timeout required")
        self.broker, self.intent, self.timeout = broker, intent, timeout
        self.cancelled = cancelled or (lambda: False)

    def _context(self, purpose: str, source: Any) -> Any:
        if source is None:
            raise PermissionError("fresh host-issued source context is required")
        return self.broker.context(purpose=purpose, intent=self.intent,
            source_contexts=(source,), trace_id=getattr(source, "trace_id", None), lease_seconds=30)

    def _call(self, operation: str, capability: str, payload: dict[str, Any], context: Any) -> dict[str, Any]:
        if operation not in self.actions:
            raise ValueError("unsupported provider operation")
        if context is None:
            raise PermissionError("fresh host-issued memory context is required")
        target = f"memory:{self.name}:{operation}"
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        grant = self.broker.authorize_effect(context, capability=capability, target=target, request_digest=hashlib.sha256(raw).hexdigest())
        response = self.broker.memory_request(grant, target=target,
            request_digest=hashlib.sha256(raw).hexdigest(), payload=raw,
            timeout=self.timeout, cancelled=self.cancelled)
        if not 200 <= int(response.status) < 300:
            raise MemoryProviderError(f"{self.name} {operation} broker operation failed (status {response.status})")
        try:
            result = json.loads(response.body.decode("utf-8"))
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
            raise MemoryProviderError("memory broker returned invalid JSON") from None
        if not isinstance(result, dict):
            raise MemoryProviderError("memory broker response must be an object")
        return result

    def doctor(self, context: Any) -> ProviderStatus:
        result = self._call("doctor", "memory-retrieval", {"schema": 1},
                            self._context("memory-retrieval", context))
        healthy = result.get("healthy") is True
        revision = result.get("revision")
        return ProviderStatus(self.name, healthy, "ready" if healthy else "service unhealthy",
                              revision if isinstance(revision, str) else None)

    def capture(self, record: MemoryRecord, *, context: Any = None) -> None:
        if context is None:
            raise PermissionError("fresh host-issued capture context is required")
        if getattr(context, "profile_id", None) != record.profile or getattr(context, "namespace_id", getattr(context, "namespace", None)) != record.namespace:
            raise PermissionError("record scope does not match signed host context")
        if record.source.startswith("memory:"):
            raise PermissionError("generated memory output cannot be captured recursively")
        record_data = {"id": record.id, "namespace": record.namespace, "profile": record.profile,
                       "source": record.source, "text": record.text, "provenance": list(record.provenance)}
        extracted = self._call("extract", "memory-extraction", {"schema": 1, "record": record_data},
                               self._context("memory-extraction", context))
        facts = extracted.get("facts")
        if not isinstance(facts, list) or not facts:
            raise MemoryProviderError("provider extraction returned no validated facts")
        embedded = self._call("embed", "memory-embedding", {"schema": 1, "facts": facts},
                              self._context("memory-embedding", context))
        vectors = embedded.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(facts):
            raise MemoryProviderError("provider embedding unavailable or invalid")
        self._call("capture", "memory-capture",
            {"schema": 1, "namespace": record.namespace, "profile": record.profile,
             "source": record.source, "record_id": record.id, "facts": facts,
             "embeddings": vectors, "provenance": list(record.provenance)},
            self._context("memory-capture", context))

    def search(self, namespace: str, query: str, limit: int, *, context: Any = None) -> list[MemoryRecord]:
        if not 1 <= limit <= 100:
            raise ValueError("limit outside 1..100")
        if context is None or getattr(context, "namespace_id", getattr(context, "namespace", None)) != namespace:
            raise PermissionError("search namespace does not match signed host context")
        result = self._call("search", "memory-retrieval",
            {"schema": 1, "namespace": namespace, "query": query, "limit": limit},
            self._context("memory-retrieval", context))
        return self._records(result.get("records"), namespace, context)

    def export(self, namespace: str, *, context: Any = None) -> list[MemoryRecord]:
        if context is None or getattr(context, "namespace_id", getattr(context, "namespace", None)) != namespace:
            raise PermissionError("export namespace does not match signed host context")
        result = self._call("export", "memory-export", {"schema": 1, "namespace": namespace},
                            self._context("memory-export", context))
        return self._records(result.get("records"), namespace, context)

    def remove(self, namespace: str, record_id: str, *, context: Any = None) -> bool:
        if context is None or getattr(context, "namespace_id", getattr(context, "namespace", None)) != namespace:
            raise PermissionError("delete namespace does not match signed host context")
        result = self._call("delete", "memory-delete",
            {"schema": 1, "namespace": namespace, "record_id": record_id},
            self._context("memory-delete", context))
        return result.get("deleted") is True

    @staticmethod
    def _records(values: Any, namespace: str, context: Any) -> list[MemoryRecord]:
        if not isinstance(values, list):
            raise MemoryProviderError("memory response has no record list")
        profile = getattr(context, "profile_id", None)
        output = []
        for value in values:
            if not isinstance(value, dict) or value.get("namespace") != namespace or value.get("profile") != profile:
                continue
            if not all(isinstance(value.get(key), str) for key in ("id", "source", "text")):
                continue
            provenance = value.get("provenance", [])
            if not isinstance(provenance, list) or any(not isinstance(item, str) for item in provenance):
                continue
            output.append(MemoryRecord(value["id"], namespace, profile, value["source"],
                                       value["text"], tuple(provenance)))
        return output


class OpenVikingProvider(BrokerMemoryProvider):
    name = "openviking"


class ClaudeMemProvider(BrokerMemoryProvider):
    name = "claude-mem"


class AgentMemoryProvider(BrokerMemoryProvider):
    name = "agentmemory"
