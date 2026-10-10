"""Root-only native input capture for admitted task, health, and desktop ingress.

Every resolver is an in-process adapter backed by the corresponding root
admission/session controller. The worker cannot choose observer IDs, source
kind, payload classification, PID, role, package, or parent lineage.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from .types import AuthorityDenied, HostContext, Sensitivity, canonical_digest

_MAX_INPUT_BYTES = 1_048_576


@dataclass(frozen=True, slots=True)
class RootNativeInputSelection:
    """Root event captured from an admitted controller or authenticated ingress."""

    source_path: str
    observer_enrollment_id: str
    payload_bytes: bytes
    parent_context: HostContext
    parent_receipt_handles: tuple[str, ...]
    peer_pid: int
    peer_pidfd: int
    peer_uid: int
    peer_identity: Any
    profile_id: str
    generation: str
    package_id: str
    compiled_closure_sha256: str
    expires_monotonic: float
    invocation_id: str
    # Root-selected current profile preference. A null value means no private
    # provider egress consent; this is never supplied by the worker.
    private_consent_selection_handle: str | None = None

    def __post_init__(self) -> None:
        if (self.private_consent_selection_handle is not None
                and (not isinstance(self.private_consent_selection_handle, str)
                     or len(self.private_consent_selection_handle) < 32
                     or len(self.private_consent_selection_handle) > 128
                     or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                            for char in self.private_consent_selection_handle))):
            raise ValueError("private consent selection handle is malformed")


@dataclass(frozen=True, slots=True)
class RootNativeInputEvent:
    """Opaque root event record returned to another root-owned component."""

    schema: int
    input_event_id: str
    input_origin_kind: str
    source_receipt_handle: str
    payload_sha256: str
    payload_size_bytes: int
    producer_profile_id: str
    producer_generation: str
    parent_closure_digest: str
    observed_monotonic: float
    expires_monotonic: float
    native_loader_ready_event_id: str | None = None
    private_consent_selection_handle: str | None = None

    def __post_init__(self) -> None:
        if (self.private_consent_selection_handle is not None
                and (not isinstance(self.private_consent_selection_handle, str)
                     or len(self.private_consent_selection_handle) < 32
                     or len(self.private_consent_selection_handle) > 128
                     or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                            for char in self.private_consent_selection_handle))):
            raise ValueError("private consent selection handle is malformed")


class RootNativeInputObserver:
    """Capture exact bytes only after a trusted root adapter proves their origin."""

    def __init__(self, *, service: Any, source_observers: Any,
                 task_input_resolver: Callable[[str, str, Any], RootNativeInputSelection] | None,
                 health_input_resolver: Callable[[str, Any, str], RootNativeInputSelection] | None,
                 desktop_input_resolver: Callable[[str, Any, Any], RootNativeInputSelection] | None,
                 process_resolver: Callable[..., Any],
                 loaded_package_proof_resolver: Callable[..., Any],
                 selected_execution_registry: Any | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
        if (not all(value is None or callable(value) for value in (
                task_input_resolver, health_input_resolver, desktop_input_resolver))
                or not all(callable(value) for value in (
                process_resolver, loaded_package_proof_resolver, monotonic))
                or not callable(getattr(source_observers, "capture_observed_ingress", None))):
            raise ValueError("native input observer requires root session, process, proof, and source adapters")
        self.service = service
        self.source_observers = source_observers
        self.task_input_resolver = task_input_resolver
        self.health_input_resolver = health_input_resolver
        self.desktop_input_resolver = desktop_input_resolver
        self.process_resolver = process_resolver
        self.loaded_package_proof_resolver = loaded_package_proof_resolver
        self.selected_execution_registry = selected_execution_registry
        self.monotonic = monotonic
        self._events: dict[str, RootNativeInputEvent] = {}
        self._task_receipts: dict[str, Any] = {}
        self._lock = threading.RLock()

    @classmethod
    def for_selected_resource_tasks(
        cls, *, service: Any, source_observers: Any,
        selected_execution_registry: Any, process_resolver: Callable[..., Any],
        loaded_package_proof_resolver: Callable[..., Any],
        monotonic: Callable[[], float] = time.monotonic,
    ) -> "RootNativeInputObserver":
        """Build the observer for v46 selected-task ingress only.

        The legacy task/health/desktop resolvers are absent by construction;
        those ingress paths remain unavailable until separately root-selected.
        """
        if (not callable(getattr(selected_execution_registry, "select_resource_task", None))
                or not callable(getattr(selected_execution_registry, "resolve_selected_native_input_target", None))):
            raise ValueError("selected resource-task execution registry is incomplete")
        return cls(
            service=service, source_observers=source_observers,
            task_input_resolver=None, health_input_resolver=None,
            desktop_input_resolver=None, process_resolver=process_resolver,
            loaded_package_proof_resolver=loaded_package_proof_resolver,
            selected_execution_registry=selected_execution_registry,
            monotonic=monotonic,
        )

    def record_selected_task_input(self, *, selected_execution: Any, source: Any,
                                   exact_stdin: bytes, target: Any) -> RootNativeInputEvent:
        """Capture exact admitted stdin for one selected live native execution."""
        from .source_observers import RootSelectedNativeExecution
        from .types import SourceReceipt

        registry = self.selected_execution_registry
        if (type(selected_execution) is not RootSelectedNativeExecution
                or registry is None
                or not callable(getattr(registry, "resolve_current_execution", None))
                or not callable(getattr(registry, "consume_selected_native_input_target", None))
                or not callable(getattr(self.source_observers, "capture_selected_native_ingress", None))
                or selected_execution.kind != "resource-task"
                or not isinstance(exact_stdin, bytes)
                or not 1 <= len(exact_stdin) <= _MAX_INPUT_BYTES
                or target is None):
            self._close_target(target)
            raise AuthorityDenied("native.input.selection", "root selected task input binding is unavailable")
        if registry.resolve_current_execution(selected_execution) is not selected_execution:
            self._close_target(target)
            raise AuthorityDenied("native.input.selection", "selected task execution is no longer current")
        observer = self.source_observers.observers.get(selected_execution.observer_enrollment_id)
        target_identity = getattr(target, "live_peer_identity", None)
        target_proof = getattr(target, "loaded_package_proof", None)
        target_pidfd = getattr(target, "peer_pidfd", None)
        if (observer is None or observer.source_kind != "native-input"
                or observer.package_id != selected_execution.native_package_id
                or observer.profile_id != selected_execution.profile_id
                or observer.generation != selected_execution.generation
                or observer.source_action_id != selected_execution.source_action_id
                or getattr(target, "process_id", None) != selected_execution.process_handle.process_id
                or getattr(target, "profile_id", None) != selected_execution.profile_id
                or getattr(target, "generation", None) != selected_execution.generation
                or getattr(target, "service_generation_digest", None)
                != selected_execution.service_generation_digest
                or getattr(target_identity, "kernel_uid", None) != observer.producer_uid
                or getattr(target_proof, "package_id", None) != selected_execution.native_package_id
                or getattr(target_proof, "compiled_closure_sha256", None) is None
                or getattr(target_proof, "target_peer_identity", None) != target_identity
                or type(target_pidfd) is not int or target_pidfd < 0
                or not isinstance(getattr(source, "signed_receipt_wires", None), tuple)
                or not isinstance(getattr(source, "verified_source_receipt_handles", None), tuple)
                or len(source.signed_receipt_wires) != len(source.verified_source_receipt_handles)
                or not isinstance(getattr(source, "parent_closure_digest", None), str)):
            self._close_target(target)
            raise AuthorityDenied("native.input.binding", "selected task source, target, and observer do not join")
        service = self.source_observers.service
        uid = target_identity.kernel_uid
        try:
            parent_receipts = [SourceReceipt.from_wire(json.loads(wire))
                               for wire in source.signed_receipt_wires]
        except Exception:
            self._close_target(target)
            raise AuthorityDenied("native.input.lineage", "admitted source receipt wires are invalid") from None
        now = self.monotonic()
        lease = min(
            float(selected_execution.expires_monotonic), float(target.expires_monotonic),
            float(source.expires_monotonic), now + 30.0,
        )
        if not now < lease:
            self._close_target(target)
            raise AuthorityDenied("native.input.expired", "selected task input target expired")
        try:
            context_wire = service._issue_context(uid, {
                "purpose": "hermes-native-initial-input",
                "intent": f"resource-task:{selected_execution.execution_handle.admission_id}:{selected_execution.execution_handle.node_id}",
                "trace_id": secrets.token_urlsafe(24),
                "lease_seconds": lease - now,
                "source_contexts": [],
                "source_receipts": [receipt.to_wire() for receipt in parent_receipts],
                "final_payload_digest": canonical_digest(exact_stdin),
                "operation": "native.request.dispatch",
            }, peer_pid=target.peer_pid)
            parent_context = HostContext.from_wire(context_wire)
        except Exception:
            self._close_target(target)
            raise AuthorityDenied("native.input.context", "root could not issue selected initial-input context") from None
        try:
            event_id = None
            try:
                captured_target, target = target, None
                public_selection_handle = getattr(
                    selected_execution, "public_input_permission_selection_handle", None)
                if public_selection_handle is None:
                    source_handle = self.source_observers.capture_selected_native_ingress(
                        observer.observer_enrollment_id,
                        payload_bytes=exact_stdin, parent_context=parent_context,
                        selected_execution=selected_execution, target=captured_target,
                        selection_registry=registry,
                        parent_receipt_handles=source.verified_source_receipt_handles,
                    )
                else:
                    pending = self.source_observers.capture_selected_native_input_for_disclosure(
                        observer.observer_enrollment_id,
                        payload_bytes=exact_stdin, parent_context=parent_context,
                        selected_execution=selected_execution, target=captured_target,
                        selection_registry=registry,
                        parent_receipt_handles=source.verified_source_receipt_handles,
                    )
                    disclosure_registry = getattr(
                        self.source_observers, "_public_input_disclosure_registry", None)
                    if disclosure_registry is None:
                        raise AuthorityDenied(
                            "native.input.public", "root TTY public-input disclosure is not composed")
                    try:
                        disclosure = disclosure_registry.observe_public_input_disclosure(
                            public_selection_handle,
                            pending.retained_observed_input_handle,
                            pending.selected_execution_handle)
                        retained_proof = self.source_observers.resolve_current_retained_selected_input(
                            pending.retained_observed_input_handle,
                            pending.selected_execution_handle)
                        public_proof = self.source_observers.create_public_input_observation(
                            retained_proof, disclosure)
                        source_handle = service.issue_public_input_source(
                            public_proof, selected_execution)
                    except BaseException:
                        cancel_pending = getattr(
                            self.source_observers, "cancel_pending_public_input_disclosure", None)
                        if callable(cancel_pending):
                            cancel_pending(pending.retained_observed_input_handle,
                                           pending.selected_execution_handle)
                        raise
                with service._lock:
                    receipt = service._source_receipt_handles.get(str(source_handle))
                expected_sensitivities = ({Sensitivity.PUBLIC} if public_selection_handle is not None else {
                    Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN})
                if (receipt is None or receipt.sensitivity not in expected_sensitivities
                        or receipt.profile_id != selected_execution.profile_id
                        or receipt.process_generation != selected_execution.generation
                        or receipt.uid != uid
                        or receipt.payload_digest != canonical_digest(exact_stdin)
                        or receipt.parent_lineage_hash != parent_context.lineage_hash
                        or receipt.monotonic_expires_at > lease):
                    raise AuthorityDenied("native.input.receipt", "issued source receipt differs from selected prompt")
                event_id = secrets.token_urlsafe(32)
                event = RootNativeInputEvent(
                    schema=1, input_event_id=event_id,
                    input_origin_kind="root-admitted-task",
                    source_receipt_handle=str(source_handle),
                    payload_sha256=hashlib.sha256(exact_stdin).hexdigest(),
                    payload_size_bytes=len(exact_stdin),
                    producer_profile_id=selected_execution.profile_id,
                    producer_generation=selected_execution.generation,
                    parent_closure_digest=source.parent_closure_digest,
                    observed_monotonic=now,
                    expires_monotonic=min(lease, receipt.monotonic_expires_at),
                    native_loader_ready_event_id=target_proof.loader_ready_event_id,
                    private_consent_selection_handle=(
                        selected_execution.private_consent_selection_handle),
                )
                with self._lock:
                    if event_id in self._events:
                        raise AuthorityDenied("native.input.replay", "root input event handle collided")
                    self._events[event_id] = event
                return event
            except BaseException:
                cancel = getattr(self.source_observers, "cancel_invocation_payload_capsules", None)
                if callable(cancel):
                    cancel(parent_context.grant_id)
                raise
        finally:
            self._close_target(target)

    def retain_task_input_receipt(self, receipt: Any) -> None:
        """Retain an exact receipt object only after its input event is captured."""
        with self._lock:
            events = [event for event in self._events.values()
                      if event.source_receipt_handle == getattr(receipt, "source_receipt_handle", None)
                      and event.payload_sha256 == getattr(receipt, "stdin_sha256", None)
                      and event.payload_size_bytes == getattr(receipt, "stdin_size_bytes", None)
                      and event.producer_generation == getattr(receipt, "process_generation", None)
                      and event.parent_closure_digest == getattr(receipt, "parent_closure_digest", None)]
            if len(events) != 1 or not isinstance(getattr(receipt, "receipt_handle", None), str):
                raise AuthorityDenied("native.input.receipt", "receipt does not match one retained input event")
            if receipt.receipt_handle in self._task_receipts:
                raise AuthorityDenied("native.input.replay", "initial input receipt handle already exists")
            self._task_receipts[receipt.receipt_handle] = receipt

    def resolve_task_input_receipt(self, receipt_handle: str) -> Any:
        with self._lock:
            receipt = self._task_receipts.get(receipt_handle)
            matches = [event for event in self._events.values()
                       if event.source_receipt_handle == getattr(receipt, "source_receipt_handle", None)
                       and event.payload_sha256 == getattr(receipt, "stdin_sha256", None)
                       and event.payload_size_bytes == getattr(receipt, "stdin_size_bytes", None)
                       and event.expires_monotonic > self.monotonic()]
        if receipt is None or len(matches) != 1:
            raise AuthorityDenied("native.input.receipt", "root input receipt is unknown, stale, or consumed")
        if receipt.source_receipt_handle != receipt.producer_context_delivery_handle:
            raise AuthorityDenied("native.input.delivery", "source and delivery handles differ")
        return receipt

    def resolve_event_for_source_handle(self, source_receipt_handle: str) -> RootNativeInputEvent:
        """Resolve one immutable root event without consuming its payload."""
        if not isinstance(source_receipt_handle, str) or not source_receipt_handle:
            raise AuthorityDenied("native.input.event", "source receipt handle is malformed")
        with self._lock:
            matches = [event for event in self._events.values()
                       if event.source_receipt_handle == source_receipt_handle
                       and event.expires_monotonic > self.monotonic()]
        if len(matches) != 1:
            raise AuthorityDenied("native.input.event", "source handle has no unique retained input event")
        return matches[0]

    def discard_task_input_observation(self, *, source_receipt_handle: str,
                                      receipt_handle: str | None = None) -> None:
        """Scrub a captured input if task binding fails before custody writes it."""
        if not isinstance(source_receipt_handle, str) or not source_receipt_handle:
            return
        with self._lock:
            if receipt_handle is not None:
                self._task_receipts.pop(receipt_handle, None)
            for event_id, event in tuple(self._events.items()):
                if event.source_receipt_handle == source_receipt_handle:
                    self._events.pop(event_id, None)
        cancel = getattr(self.source_observers, "cancel_source_payload_capsule", None)
        if callable(cancel):
            try:
                from .source_observers import SourceReceiptHandle
                cancel(SourceReceiptHandle(source_receipt_handle))
            except Exception:
                # Revocation failures leave the coordinator fail-closed; this
                # helper must not mask the original pre-stdin failure.
                pass

    def record_admitted_task_input(self, root_admission_handle: str, node_id: str,
                                   owned_process_handle: Any,
                                   exact_initial_stdin_bytes: bytes) -> RootNativeInputEvent:
        if (not callable(self.task_input_resolver)
                or not _opaque(root_admission_handle) or not _text(node_id)
                or not isinstance(exact_initial_stdin_bytes, bytes)):
            raise AuthorityDenied("native.input.task", "root task input capture is malformed")
        try:
            selected = self.task_input_resolver(
                root_admission_handle, node_id, owned_process_handle)
        except Exception:
            raise AuthorityDenied("native.input.task", "root admitted task input is unavailable") from None
        if (type(selected) is not RootNativeInputSelection
                or selected.source_path != "root-admitted-task"
                or selected.payload_bytes != exact_initial_stdin_bytes):
            raise AuthorityDenied("native.input.task", "task bytes do not equal the root-admitted stdin write")
        return self._capture(selected)

    def record_selected_health_input(self, health_observation_handle: str,
                                     owned_process_handle: Any,
                                     selected_fixture_artifact_id: str) -> RootNativeInputEvent:
        if (not callable(self.health_input_resolver)
                or not _opaque(health_observation_handle) or not _text(selected_fixture_artifact_id)):
            raise AuthorityDenied("native.input.health", "selected health fixture input is malformed")
        try:
            selected = self.health_input_resolver(
                health_observation_handle, owned_process_handle, selected_fixture_artifact_id)
        except Exception:
            raise AuthorityDenied("native.input.health", "root selected health fixture is unavailable") from None
        if (type(selected) is not RootNativeInputSelection
                or selected.source_path != "selected-health-fixture"):
            raise AuthorityDenied("native.input.health", "health resolver returned an unselected input")
        return self._capture(selected)

    def record_authenticated_desktop_input(self, root_remote_session_handle: str,
                                           owned_native_process_handle: Any,
                                           observed_input_event: Any) -> RootNativeInputEvent:
        if (not callable(self.desktop_input_resolver)
                or not _opaque(root_remote_session_handle) or observed_input_event is None):
            raise AuthorityDenied("native.input.desktop", "authenticated desktop input is malformed")
        try:
            selected = self.desktop_input_resolver(
                root_remote_session_handle, owned_native_process_handle, observed_input_event)
        except Exception:
            raise AuthorityDenied("native.input.desktop", "root desktop input/session observation is unavailable") from None
        if (type(selected) is not RootNativeInputSelection
                or selected.source_path != "authenticated-desktop-input"):
            raise AuthorityDenied("native.input.desktop", "desktop resolver returned an unverified origin")
        return self._capture(selected)

    def _capture(self, selected: RootNativeInputSelection) -> RootNativeInputEvent:
        # Resolver-owned PIDFD duplicates transfer to this method on success or
        # failure. Close even when validation fails before the source capture.
        try:
            return self._capture_validated(selected)
        finally:
            try:
                os.close(selected.peer_pidfd)
            except OSError:
                pass

    def _capture_validated(self, selected: RootNativeInputSelection) -> RootNativeInputEvent:
        now = self.monotonic()
        observer = self.source_observers.observers.get(selected.observer_enrollment_id)
        context = selected.parent_context
        payload = selected.payload_bytes
        if (observer is None or observer.source_kind != "native-input"
                or not isinstance(payload, bytes) or not 1 <= len(payload) <= _MAX_INPUT_BYTES
                or not isinstance(context, HostContext)
                or not isinstance(selected.parent_receipt_handles, tuple)
                or len(selected.parent_receipt_handles) > 64
                or len(set(selected.parent_receipt_handles)) != len(selected.parent_receipt_handles)
                or selected.peer_pid <= 0 or selected.peer_pidfd < 0 or selected.peer_uid <= 0
                or (selected.profile_id, selected.generation, selected.peer_uid)
                != (observer.profile_id, observer.generation, observer.producer_uid)
                or context.profile_id != observer.profile_id
                or context.generation != observer.generation
                or context.uid != observer.producer_uid
                or context.native_process_identity != self.service._native_process_identity(
                    selected.peer_pid, selected.peer_uid)
                or selected.package_id != observer.package_id
                or not _sha256(selected.compiled_closure_sha256)
                or type(selected.expires_monotonic) not in (int, float)
                or not math.isfinite(selected.expires_monotonic)
                or selected.expires_monotonic <= now
                or not _text(selected.invocation_id)):
            raise AuthorityDenied("native.input.binding", "root input selection does not match its active observer")
        self.service._verify_context_signature(context)
        self.service._assert_current_context(
            context, self.service._binding(observer.producer_uid), observer.producer_uid,
            peer_pid=selected.peer_pid,
        )
        identity = self.process_resolver(
            selected.peer_pid, selected.peer_pidfd,
            profile_id=selected.profile_id, generation=selected.generation,
        )
        if identity is None or identity != selected.peer_identity or identity.kernel_uid != selected.peer_uid:
            raise AuthorityDenied("native.input.peer", "selected native input producer PIDFD is stale")
        package, _adapter = self.source_observers._resolve_package_role(observer)
        proof = self.source_observers._resolve_loaded_package_proof(
            identity, observer, package, now,
            peer_pid=selected.peer_pid, peer_pidfd=selected.peer_pidfd,
        )
        if (getattr(package, "package_id", None) != selected.package_id
                or getattr(package, "compiled_closure_sha256", None) != selected.compiled_closure_sha256
                or getattr(proof, "package_id", None) != selected.package_id
                or getattr(proof, "compiled_closure_sha256", None) != selected.compiled_closure_sha256
                or getattr(proof, "target_peer_identity", None) != identity
                or getattr(proof, "expires_monotonic", 0) <= now):
            raise AuthorityDenied("native.input.closure", "selected native input lacks its current loaded closure proof")
        if self.monotonic() >= selected.expires_monotonic:
            raise AuthorityDenied("native.input.expired", "root input selection expired before capture")
        try:
            receipt_handle = self.source_observers.capture_observed_ingress(
                observer.observer_enrollment_id,
                payload_bytes=payload,
                parent_context=context,
                peer_pid=selected.peer_pid,
                peer_pidfd=selected.peer_pidfd,
                parent_receipt_handles=selected.parent_receipt_handles,
            )
            self.service._verify_context_signature(context)
            receipt = self.service._source_receipt_handles.get(str(receipt_handle))
            if (receipt is None or receipt.sensitivity not in {
                    Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN}
                    or receipt.profile_id != selected.profile_id
                    or receipt.process_generation != selected.generation
                    or receipt.uid != selected.peer_uid
                    or receipt.payload_digest != canonical_digest(payload)
                    or receipt.monotonic_expires_at > selected.expires_monotonic):
                raise AuthorityDenied("native.input.receipt", "root input receipt does not match captured bytes")
            delivered = self.source_observers.take_source_receipt(
                str(receipt_handle), peer_uid=selected.peer_uid,
                peer_pid=selected.peer_pid, peer_pidfd=selected.peer_pidfd,
            )
            if str(delivered) != str(receipt_handle):
                raise AuthorityDenied("native.input.delivery", "root input receipt delivery changed its handle")
            event = RootNativeInputEvent(
                schema=1, input_event_id=secrets.token_urlsafe(32),
                input_origin_kind=selected.source_path,
                source_receipt_handle=str(receipt_handle),
                payload_sha256=hashlib.sha256(payload).hexdigest(),
                payload_size_bytes=len(payload), producer_profile_id=selected.profile_id,
                producer_generation=selected.generation,
                parent_closure_digest=context.lineage_hash,
                observed_monotonic=now,
                expires_monotonic=min(selected.expires_monotonic, receipt.monotonic_expires_at),
                native_loader_ready_event_id=getattr(proof, "loader_ready_event_id", None),
                private_consent_selection_handle=selected.private_consent_selection_handle,
            )
            with self._lock:
                if any(item.input_event_id == event.input_event_id for item in self._events.values()):
                    raise AuthorityDenied("native.input.replay", "root input event handle collided")
                self._events[event.input_event_id] = event
            return event
        except BaseException:
            cancel = getattr(self.source_observers, "cancel_invocation_payload_capsules", None)
            if callable(cancel):
                cancel(selected.invocation_id)
            raise

    def consume_input_event(self, input_event_id: str, *, peer_uid: int, peer_pid: int,
                            peer_pidfd: int) -> RootNativeInputEvent:
        if (not _opaque(input_event_id) or type(peer_uid) is not int or peer_uid <= 0
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0):
            raise AuthorityDenied("native.input.event", "native input event lookup is malformed")
        with self._lock:
            event = self._events.pop(input_event_id, None)
        if event is None or self.monotonic() >= event.expires_monotonic:
            raise AuthorityDenied("native.input.event", "native input event is unknown, stale, or consumed")
        try:
            with self.service._lock:
                receipt = self.service._source_receipt_handles.get(event.source_receipt_handle)
            if receipt is None:
                raise KeyError(event.source_receipt_handle)
            producer = self.source_observers.resolve_live_source_producer(
                receipt.receipt_id,
                profile_id=event.producer_profile_id,
                generation=event.producer_generation,
                native_process_identity=receipt.native_process_identity,
                expires_monotonic=receipt.monotonic_expires_at,
            )
            try:
                live = self.process_resolver(peer_pid, peer_pidfd,
                                             profile_id=event.producer_profile_id,
                                             generation=event.producer_generation)
                if (peer_uid != producer.uid or peer_pid != producer.pid
                        or live is None or live != producer.identity):
                    raise AuthorityDenied("native.input.peer", "input event belongs to another process")
            finally:
                os.close(producer.pidfd)
            return event
        except KeyError:
            raise AuthorityDenied("native.input.receipt", "input source receipt is no longer retained") from None


def _opaque(value: Any) -> bool:
    return isinstance(value, str) and 32 <= len(value) <= 128


def _text(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 256 and "\x00" not in value


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)
