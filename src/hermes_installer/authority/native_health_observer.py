"""Root-owned functional health receipt observer for the selected Hermes run.

The resolver callables in this module are in-process root adapters. They must
select/launch an enrolled health operation, resolve event IDs from trusted
registries, and parse the reviewed result schema. This module deliberately has
no RPC method which accepts worker status, stdout, booleans, or event claims.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .types import AuthorityDenied, canonical_digest

_EVENT_KINDS = frozenset({
    "loader-ready", "native-request", "provider-result", "tool-invocation",
    "tool-result", "terminal",
})
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class RootSelectedNativeHealthRun:
    """Current root-selected health process and its immutable enrollment joins.

    ``selected_health_resolver`` returns this only after resolving the opaque
    lifecycle control handle to the committed enrollment transaction and
    starting the fixed root-selected health recipe under custody.
    """

    operation_id: str
    enrollment_id: str
    profile_id: str
    process_generation: str
    service_generation_digest: str
    bootstrap_transaction_handle: str
    committed_enrollment_receipt_id: str
    process_id: str
    process_pid: int
    process_pidfd: int
    process_uid: int
    process_identity: Any
    package_id: str
    compiled_closure_sha256: str
    loaded_package_proof: Any
    fixture_artifact_id: str
    fixture_sha256: str
    health_action_id: str
    result_schema_id: str
    provider_required: bool
    parent_closure_digest: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        for name in ("operation_id", "enrollment_id", "profile_id", "process_generation",
                     "bootstrap_transaction_handle", "committed_enrollment_receipt_id",
                     "process_id", "package_id", "fixture_artifact_id", "health_action_id",
                     "result_schema_id"):
            if not _identifier(getattr(self, name)):
                raise ValueError(f"selected health run {name} is invalid")
        for name in ("service_generation_digest", "compiled_closure_sha256", "fixture_sha256",
                     "parent_closure_digest"):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"selected health run {name} is invalid")
        if (type(self.process_pid) is not int or self.process_pid <= 0
                or type(self.process_pidfd) is not int or self.process_pidfd < 0
                or type(self.process_uid) is not int or self.process_uid <= 0
                or type(self.provider_required) is not bool
                or self.process_identity is None or self.loaded_package_proof is None
                or isinstance(self.expires_monotonic, bool)
                or type(self.expires_monotonic) not in (int, float)
                or not math.isfinite(self.expires_monotonic)):
            raise ValueError("selected health run live process or lease is invalid")


@dataclass(frozen=True, slots=True)
class RootNativeHealthEvent:
    """Typed event returned only by the root event-registry resolver."""

    event_id: str
    event_kind: str
    operation_id: str
    enrollment_id: str
    profile_id: str
    process_generation: str
    service_generation_digest: str
    process_id: str
    process_pid: int
    process_uid: int
    package_id: str
    compiled_closure_sha256: str
    parent_closure_digest: str
    observed_monotonic: float
    expires_monotonic: float
    loader_ready_event_id: str | None = None
    native_request_event_id: str | None = None
    provider_result_event_id: str | None = None
    tool_invocation_event_id: str | None = None
    tool_result_event_id: str | None = None
    terminal_receipt_handle: str | None = None
    result_schema_id: str | None = None
    result_bytes: bytes | None = None
    loaded_proof_id: str | None = None
    action_id: str | None = None
    provider_result_reference: str | None = None
    invocation_handle: str | None = None
    terminal_status: str | None = None
    cleanup_verified: bool = False


@dataclass(frozen=True, slots=True)
class RootNativeHealthReceipt:
    schema: int
    health_receipt_handle: str
    operation_id: str
    enrollment_id: str
    profile_id: str
    process_generation: str
    service_generation_digest: str
    bootstrap_transaction_handle: str
    committed_enrollment_receipt_id: str
    process_id: str
    loader_ready_event_id: str
    native_request_event_id: str
    provider_result_event_id: str | None
    tool_invocation_event_id: str
    tool_result_event_id: str
    terminal_receipt_handle: str
    result_schema_id: str
    result_sha256: str
    parent_closure_digest: str
    status: str
    issued_monotonic: float
    expires_monotonic: float

    def __post_init__(self) -> None:
        if self.schema != 1 or not _OPAQUE.fullmatch(self.health_receipt_handle):
            raise ValueError("native health receipt handle is invalid")
        for name in ("operation_id", "enrollment_id", "profile_id", "process_generation",
                     "bootstrap_transaction_handle", "committed_enrollment_receipt_id", "process_id",
                     "loader_ready_event_id", "native_request_event_id", "tool_invocation_event_id",
                     "tool_result_event_id", "terminal_receipt_handle", "result_schema_id"):
            if not _identifier(getattr(self, name)):
                raise ValueError(f"native health receipt {name} is invalid")
        if self.provider_result_event_id is not None and not _identifier(self.provider_result_event_id):
            raise ValueError("native health provider event ID is invalid")
        for name in ("service_generation_digest", "result_sha256", "parent_closure_digest"):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"native health receipt {name} is invalid")
        if (self.status not in {"passed", "failed", "incomplete"}
                or any(isinstance(value, bool) or type(value) not in (int, float)
                       or not math.isfinite(value)
                       for value in (self.issued_monotonic, self.expires_monotonic))
                or self.expires_monotonic <= self.issued_monotonic):
            raise ValueError("native health receipt status or lease is invalid")


@dataclass(frozen=True, slots=True)
class RootValidatedNativeHealthResult:
    """Reviewed semantic parser output; plain booleans/status strings are rejected."""

    result_schema_id: str
    result_sha256: str
    semantic_outcome: str


@dataclass(slots=True)
class _HealthObservation:
    handle: str
    run: RootSelectedNativeHealthRun
    process_pidfd: int
    loaded_package_proof: Any
    events: dict[str, RootNativeHealthEvent]
    expires_monotonic: float


class RootNativeHealthObserver:
    """Join actual selected loader, request, result, tool, and terminal events."""

    def __init__(self, *, selected_health_resolver: Callable[[str], RootSelectedNativeHealthRun],
                 event_resolver: Callable[[str, str], RootNativeHealthEvent],
                 process_resolver: Callable[..., Any],
                 loaded_package_proof_resolver: Callable[[RootSelectedNativeHealthRun], Any],
                 result_validator: Callable[[str, bytes], Any],
                 selected_run_canceller: Callable[[RootSelectedNativeHealthRun], None],
                 monotonic: Callable[[], float] = time.monotonic):
        if (not all(callable(value) for value in (
                selected_health_resolver, event_resolver, process_resolver,
                loaded_package_proof_resolver, result_validator,
                selected_run_canceller, monotonic))):
            raise ValueError("root native health observation requires concrete root adapters")
        self.selected_health_resolver = selected_health_resolver
        self.event_resolver = event_resolver
        self.process_resolver = process_resolver
        self.loaded_package_proof_resolver = loaded_package_proof_resolver
        self.result_validator = result_validator
        self.selected_run_canceller = selected_run_canceller
        self.monotonic = monotonic
        self._observations: dict[str, _HealthObservation] = {}
        self._receipts: dict[str, RootNativeHealthReceipt] = {}
        self._consumed: set[str] = set()
        self._lock = threading.RLock()

    def begin_selected_health(self, control_handle: str) -> str:
        if not _OPAQUE.fullmatch(control_handle):
            raise AuthorityDenied("native.health.control", "root health control handle is malformed")
        try:
            run = self.selected_health_resolver(control_handle)
        except Exception:
            raise AuthorityDenied("native.health.selection", "selected committed health run is unavailable") from None
        if type(run) is not RootSelectedNativeHealthRun:
            raise AuthorityDenied("native.health.selection", "health resolver did not return the root selected-run DTO")
        now = self.monotonic()
        if now >= run.expires_monotonic:
            self.selected_run_canceller(run)
            raise AuthorityDenied("native.health.expired", "selected health run expired before observation")
        identity = self.process_resolver(
            run.process_pid, run.process_pidfd, profile_id=run.profile_id,
            generation=run.process_generation,
        )
        proof = self.loaded_package_proof_resolver(run)
        if (identity is None or identity != run.process_identity
                or identity.kernel_uid != run.process_uid
                or getattr(proof, "package_id", None) != run.package_id
                or getattr(proof, "compiled_closure_sha256", None) != run.compiled_closure_sha256
                or getattr(proof, "profile_id", None) != run.profile_id
                or getattr(proof, "generation", None) != run.process_generation
                or getattr(proof, "service_generation_digest", None) != run.service_generation_digest):
            self.selected_run_canceller(run)
            raise AuthorityDenied("native.health.closure", "active process or loaded package closure is unavailable")
        try:
            pidfd = os.dup(run.process_pidfd)
        except OSError:
            self.selected_run_canceller(run)
            raise AuthorityDenied("native.health.peer", "health process PIDFD could not be retained") from None
        handle = secrets.token_urlsafe(32)
        observation = _HealthObservation(handle, run, pidfd, proof, {}, run.expires_monotonic)
        with self._lock:
            if handle in self._observations or handle in self._receipts:
                os.close(pidfd)
                self.selected_run_canceller(run)
                raise AuthorityDenied("native.health.handle", "health handle collision")
            self._observations[handle] = observation
        return handle

    def observe_health_event(self, health_observation_handle: str,
                             root_event_record: str) -> None:
        if not _OPAQUE.fullmatch(health_observation_handle) or not _OPAQUE.fullmatch(root_event_record):
            raise AuthorityDenied("native.health.event", "root health event reference is malformed")
        with self._lock:
            observation = self._observations.get(health_observation_handle)
        if observation is None:
            raise AuthorityDenied("native.health.handle", "health observation is unknown or finished")
        run = observation.run
        now = self.monotonic()
        if now >= observation.expires_monotonic:
            self._retire_observation(observation, cancel=True)
            raise AuthorityDenied("native.health.expired", "health observation lease expired")
        try:
            event = self.event_resolver(health_observation_handle, root_event_record)
        except Exception:
            raise AuthorityDenied("native.health.event", "root event registry did not resolve this event") from None
        if type(event) is not RootNativeHealthEvent:
            raise AuthorityDenied("native.health.event", "event registry returned an untyped health record")
        if (event.event_id != root_event_record or event.event_kind not in _EVENT_KINDS
                or event.operation_id != run.operation_id
                or event.enrollment_id != run.enrollment_id
                or event.profile_id != run.profile_id
                or event.process_generation != run.process_generation
                or event.service_generation_digest != run.service_generation_digest
                or event.process_id != run.process_id
                or event.process_pid != run.process_pid or event.process_uid != run.process_uid
                or event.package_id != run.package_id
                or event.compiled_closure_sha256 != run.compiled_closure_sha256
                or event.parent_closure_digest != run.parent_closure_digest
                or type(event.observed_monotonic) not in (int, float)
                or not math.isfinite(event.observed_monotonic)
                or event.observed_monotonic > now
                or type(event.expires_monotonic) not in (int, float)
                or not math.isfinite(event.expires_monotonic)
                or event.expires_monotonic > observation.expires_monotonic
                or event.expires_monotonic <= now):
            raise AuthorityDenied("native.health.event_binding", "health event differs from selected current run")
        if event.event_kind != "terminal":
            current = self.process_resolver(
                run.process_pid, observation.process_pidfd,
                profile_id=run.profile_id, generation=run.process_generation,
            )
            proof = self.loaded_package_proof_resolver(run)
            if current != run.process_identity or proof != observation.loaded_package_proof:
                self._retire_observation(observation, cancel=True)
                raise AuthorityDenied("native.health.peer", "health process or loaded closure changed")
        with self._lock:
            if event.event_id in observation.events:
                raise AuthorityDenied("native.health.replay", "health event was already recorded")
            observation.events[event.event_id] = event

    def finish_selected_health(self, health_observation_handle: str) -> RootNativeHealthReceipt:
        with self._lock:
            observation = self._observations.get(health_observation_handle)
        if observation is None:
            raise AuthorityDenied("native.health.handle", "health observation is unknown or finished")
        run = observation.run
        by_kind: dict[str, RootNativeHealthEvent] = {}
        for event in observation.events.values():
            if event.event_kind in by_kind:
                raise AuthorityDenied("native.health.ambiguous", "health run has duplicate semantic event kinds")
            by_kind[event.event_kind] = event
        required = {"loader-ready", "native-request", "tool-invocation", "tool-result", "terminal"}
        if run.provider_required:
            required.add("provider-result")
        missing = required - set(by_kind)
        if missing:
            raise AuthorityDenied("native.health.incomplete", "selected health run lacks required native events")
        loader = by_kind["loader-ready"]
        request = by_kind["native-request"]
        invocation = by_kind["tool-invocation"]
        tool_result = by_kind["tool-result"]
        terminal = by_kind["terminal"]
        provider = by_kind.get("provider-result")
        if (loader.loader_ready_event_id != loader.event_id
                or loader.loaded_proof_id != getattr(observation.loaded_package_proof, "proof_id", None)
                or request.native_request_event_id != request.event_id
                or invocation.tool_invocation_event_id != invocation.event_id
                or invocation.action_id != run.health_action_id
                or tool_result.tool_result_event_id != tool_result.event_id
                or terminal.terminal_status != "succeeded" or terminal.cleanup_verified is not True
                or not isinstance(terminal.terminal_receipt_handle, str)
                or not _OPAQUE.fullmatch(terminal.terminal_receipt_handle)
                or (provider is not None and provider.provider_result_event_id != provider.event_id)
                or (provider is None and run.provider_required)):
            raise AuthorityDenied("native.health.events", "health event roles or terminal custody proof do not join")
        if (request.provider_result_event_id != (provider.event_id if provider else None)
                or (provider is not None and provider.native_request_event_id != request.event_id)
                or invocation.native_request_event_id != request.event_id
                or invocation.provider_result_reference != (provider.event_id if provider else None)
                or tool_result.tool_invocation_event_id != invocation.event_id):
            raise AuthorityDenied("native.health.lineage", "health request/provider/tool event ancestry does not join")
        if tool_result.invocation_handle != invocation.invocation_handle:
            raise AuthorityDenied("native.health.lineage", "health result is not bound to the selected invocation")
        result_bytes = tool_result.result_bytes
        if (tool_result.result_schema_id != run.result_schema_id
                or not isinstance(result_bytes, bytes) or not 1 <= len(result_bytes) <= 65_536):
            raise AuthorityDenied("native.health.result", "health result is not the selected bounded schema")
        result_digest = hashlib.sha256(result_bytes).hexdigest()
        try:
            validated = self.result_validator(run.result_schema_id, result_bytes)
        except Exception:
            raise AuthorityDenied("native.health.result", "reviewed health result validator rejected bytes") from None
        if (type(validated) is not RootValidatedNativeHealthResult
                or validated.result_schema_id != run.result_schema_id
                or validated.result_sha256 != result_digest
                or validated.semantic_outcome != "passed"):
            raise AuthorityDenied("native.health.semantic", "reviewed health result lacks semantic success")
        now = self.monotonic()
        if (now >= run.expires_monotonic
                or any(event.expires_monotonic <= now for event in observation.events.values())):
            self._retire_observation(observation, cancel=True)
            raise AuthorityDenied("native.health.expired", "health run or one of its events expired before receipt")
        receipt_handle = secrets.token_urlsafe(32)
        receipt = RootNativeHealthReceipt(
            schema=1, health_receipt_handle=receipt_handle,
            operation_id=run.operation_id, enrollment_id=run.enrollment_id,
            profile_id=run.profile_id, process_generation=run.process_generation,
            service_generation_digest=run.service_generation_digest,
            bootstrap_transaction_handle=run.bootstrap_transaction_handle,
            committed_enrollment_receipt_id=run.committed_enrollment_receipt_id,
            process_id=run.process_id,
            loader_ready_event_id=loader.event_id,
            native_request_event_id=request.event_id,
            provider_result_event_id=provider.event_id if provider else None,
            tool_invocation_event_id=invocation.event_id,
            tool_result_event_id=tool_result.event_id,
            terminal_receipt_handle=terminal.terminal_receipt_handle,
            result_schema_id=run.result_schema_id, result_sha256=result_digest,
            parent_closure_digest=run.parent_closure_digest, status="passed",
            issued_monotonic=now,
            expires_monotonic=min(run.expires_monotonic,
                                  *(event.expires_monotonic for event in observation.events.values())),
        )
        with self._lock:
            if self._observations.pop(health_observation_handle, None) is not observation:
                os.close(observation.process_pidfd)
                raise AuthorityDenied("native.health.replay", "health observation changed before finish")
            os.close(observation.process_pidfd)
            self._receipts[receipt_handle] = receipt
        return receipt

    def consume_selected_health_receipt(self, health_receipt_handle: str,
                                        committed_enrollment_receipt_id: str) -> RootNativeHealthReceipt:
        if (not _OPAQUE.fullmatch(health_receipt_handle)
                or not _identifier(committed_enrollment_receipt_id)):
            raise AuthorityDenied("native.health.receipt", "health receipt lookup is malformed")
        with self._lock:
            receipt = self._receipts.get(health_receipt_handle)
            if (receipt is None or receipt.health_receipt_handle in self._consumed
                    or self.monotonic() >= receipt.expires_monotonic
                    or receipt.committed_enrollment_receipt_id != committed_enrollment_receipt_id
                    or receipt.status != "passed"):
                raise AuthorityDenied("native.health.receipt", "health receipt is stale, mismatched, or consumed")
            self._consumed.add(health_receipt_handle)
            return receipt

    def cancel_selected_health(self, health_observation_handle: str) -> None:
        with self._lock:
            observation = self._observations.get(health_observation_handle)
        if observation is not None:
            self._retire_observation(observation, cancel=True)

    def _retire_observation(self, observation: _HealthObservation, *, cancel: bool) -> None:
        with self._lock:
            current = self._observations.pop(observation.handle, None)
        if current is None:
            return
        try:
            os.close(current.process_pidfd)
        except OSError:
            pass
        if cancel:
            try:
                self.selected_run_canceller(current.run)
            except Exception:
                pass


def _identifier(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 256
            and not any(ord(char) < 0x20 for char in value))
