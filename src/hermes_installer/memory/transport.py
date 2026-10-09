"""Disabled legacy memory transport.

SK01 requires a root-owned ``fixed-memory-compound-json-v1`` executor that
owns recipes, response validation, captured identifiers, and step transitions.
This compatibility import remains only to fail closed for old callers; it must
never open a connector or send caller-serialized HTTP bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol


class MemoryTransportUnavailable(RuntimeError):
    """The legacy raw HTTP transport is intentionally not an effect path."""


class MemoryTransportDenied(PermissionError):
    """A legacy caller requested an unsupported memory effect."""


class RootConnectorFactory(Protocol):
    """Compatibility type for callers being migrated to the compound executor."""
    def __call__(self, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class MemoryHTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class MemoryServiceIPC:
    """Fail-closed compatibility surface; no raw HTTP or connector traffic."""

    def __init__(self, enrollments: Mapping[Any, Any], connector_factory: Any, **kwargs: Any):
        self.enrollments = dict(enrollments)
        self.connector_factory = connector_factory

    def request(self, *, context: Any, authorization: Any, service_id: str,
                service_generation: str, provider: str, route_id: str,
                session_id: str, deadline_monotonic: float, payload: bytes,
                timeout: float, peer_pid: int, peer_pidfd: int | None,
                cancelled: Callable[[], bool]) -> MemoryHTTPResponse:
        raise MemoryTransportUnavailable(
            "raw memory HTTP is disabled; fixed compound executor is required")
