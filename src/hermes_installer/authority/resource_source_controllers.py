"""Protected role and event registry for root-owned Resources dispatchers.

Root scheduler, webhook ingress, and channel ingress are execution controllers,
not historical event producers.  This module keeps their active role rows and
one-use event records separate from ``SourceObserverRegistry``.  A role row is
not executable proof by itself: resolving a controller requires the current
daemon-unit/PIDFD and loaded-role proof from root custody.
"""
from __future__ import annotations

import math
import json
import re
import secrets
import threading
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .types import AuthorityDenied
from .root_controller_custody import RootControllerRoleEnrollment as _CustodyRoleEnrollment
from .root_controller_custody import RootControllerRoleCatalog

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UNIT = re.compile(r"[A-Za-z0-9_.@:-]{1,255}\.service\Z")
_KINDS = frozenset({"root-scheduler", "root-webhook", "root-channel"})
_OPERATIONS_BY_KIND = {
    "root-scheduler": frozenset({"resource.cron.run", "resource.bundle.node.run"}),
    "root-webhook": frozenset({"resource.webhook.run", "resource.bundle.node.run"}),
    "root-channel": frozenset({"resource.channel.run", "resource.bundle.node.run"}),
}
_ROLE_FIELDS = frozenset({
    "id", "controller_kind", "daemon_unit_id", "daemon_executable_artifact_id",
    "daemon_executable_sha256", "role_module_artifact_id", "role_module_sha256",
    "controller_generation", "source_observer_enrollment_ids",
    "allowed_backend_enrollment_ids", "allowed_operations", "max_lease_seconds",
})
_MAX_ROOT_EVENT_COUNT = 256
_MAX_ROOT_EVENT_BYTES = 8 * 1024 * 1024
_MAX_ROOT_EVENT_IDS_PER_EPOCH = 100_000
_MAX_EVENT_LEASE_SECONDS = 600


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _string_set(value: Any, *, maximum: int = 128) -> frozenset[str]:
    if (not isinstance(value, (list, tuple)) or not 1 <= len(value) <= maximum
            or any(not _identifier(item) for item in value)
            or len(set(value)) != len(value)):
        raise ValueError
    return frozenset(value)


def _event_fields_from_payload(payload: bytes) -> Mapping[str, Any]:
    """Derive recipe fields from authenticated canonical JSON, never caller labels."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        decoded = json.loads(payload, object_pairs_hook=pairs,
                             parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        raise AuthorityDenied("resource.event", "observed event is not unambiguous JSON") from None
    if not isinstance(decoded, dict) or len(decoded) > 64:
        raise AuthorityDenied("resource.event", "observed event fields are outside the supported object bound")
    return MappingProxyType(decoded)


RootControllerRoleEnrollment = _CustodyRoleEnrollment


def parse_root_controller_role_records(records: Any, *, generation_digest: str) -> RootControllerRoleCatalog:
    """Parse only the exact digest-bound v23 ``resource_controller_roles`` rows."""
    if not isinstance(records, (list, tuple)) or len(records) > 64:
        raise AuthorityDenied("resource.controller_catalog", "root controller role catalog is malformed")
    try:
        if any(not isinstance(row, Mapping) or set(row) != _ROLE_FIELDS for row in records):
            raise ValueError
        catalog = RootControllerRoleCatalog(records, generation_digest=generation_digest)
        if any(not set(role.allowed_operations) <= _OPERATIONS_BY_KIND[role.controller_kind]
               for role in catalog.rows):
            raise ValueError
        return catalog
    except (KeyError, TypeError, ValueError, AuthorityDenied):
        raise AuthorityDenied("resource.controller_catalog", "root controller role row is invalid") from None


@dataclass(frozen=True, slots=True)
class RootResourceEventHandle:
    """Opaque in-process identifier for one root-verified resource ingress."""

    handle: str
    event_id: str
    resource_id: str
    resource_generation: str
    source_kind: str
    source_observer_enrollment_id: str
    source_receipt_ids: tuple[str, ...] = field(repr=False)
    parent_closure_digest: str
    payload_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    authority_epoch: str

    def __post_init__(self) -> None:
        for name in ("handle", "event_id", "resource_id", "resource_generation",
                     "source_observer_enrollment_id", "authority_epoch"):
            if not _identifier(getattr(self, name)):
                raise ValueError(f"root resource event {name} is invalid")
        if (self.source_kind not in {"schedule-event", "webhook-event", "native-input"}
                or not self.source_receipt_ids
                or any(not _identifier(item) for item in self.source_receipt_ids)
                or len(set(self.source_receipt_ids)) != len(self.source_receipt_ids)
                or not _SHA256.fullmatch(self.parent_closure_digest)
                or not _SHA256.fullmatch(self.payload_sha256)
                or any(isinstance(item, bool) or not isinstance(item, (int, float))
                       or not math.isfinite(item) for item in (self.issued_monotonic, self.expires_monotonic))
                or self.expires_monotonic <= self.issued_monotonic):
            raise ValueError("root resource event binding is malformed")


@dataclass(frozen=True, slots=True)
class RootResourceJobContextRequest:
    """Service-private request derived solely from a retained root event."""

    root_event: RootResourceEventHandle = field(repr=False)
    event_payload: bytes = field(repr=False)
    event_fields: Mapping[str, Any] = field(repr=False)
    parent_context: Any = field(repr=False)
    parent_receipts: tuple[Any, ...] = field(repr=False)
    resource_enrollment: Any = field(repr=False)
    node: Any = field(repr=False)
    backend: Any = field(repr=False)
    controller: Any = field(repr=False)
    operation: str
    canonical_payload_sha256: str
    service_generation_digest: str
    authority_epoch: str
    issuer_token: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class RootResourceContextReservation:
    """Validated root-local snapshot consumed once by the event context issuer."""

    request: RootResourceJobContextRequest = field(repr=False)
    record: Any = field(repr=False)
    enrollment: Any = field(repr=False)
    node: Any = field(repr=False)
    backend: Any = field(repr=False)
    role: RootControllerRoleEnrollment
    controller_proof: Any = field(repr=False)


@dataclass(frozen=True, slots=True)
class RootControllerEventBinding:
    """Fully joined event, job, source, backend, and active daemon role."""

    role: RootControllerRoleEnrollment
    event: RootResourceEventHandle
    resource_enrollment: Any = field(repr=False)
    node: Any = field(repr=False)
    backend: Any = field(repr=False)
    source_observer: Any = field(repr=False)
    service_generation_digest: str
    authority_epoch: str
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class _RootEventRecord:
    handle: RootResourceEventHandle
    parent_context: Any = field(repr=False)
    parent_receipts: tuple[Any, ...] = field(repr=False)
    payload: bytes = field(repr=False)
    event_fields: Mapping[str, Any] = field(repr=False)
    selected_spec: Mapping[str, Any] = field(repr=False)
    parent_results: Mapping[str, Any] = field(repr=False)

    def __post_init__(self) -> None:
        from types import MappingProxyType
        object.__setattr__(self, "event_fields", MappingProxyType(dict(self.event_fields)))
        object.__setattr__(self, "selected_spec", MappingProxyType(dict(self.selected_spec)))
        object.__setattr__(self, "parent_results", MappingProxyType(dict(self.parent_results)))


class RootResourceControllerRegistry:
    """Per-authority-epoch root dispatcher registry.

    Construction is intentionally gated on the custody object implementing
    the concrete ``resolve_role`` API.  This prevents catalog metadata or a
    callback that merely returns a PID from being treated as controller proof.
    Event producers add records through the typed root-ingress methods below;
    no method is exported over AuthorityClient RPC.
    """

    def __init__(self, *, service: Any, roles: RootControllerRoleCatalog,
                 job_enrollments: Mapping[tuple[str, str], Any], source_observers: Any,
                 selected_specs: Mapping[tuple[str, str], Mapping[str, Any]],
                 custody_resolver: Any):
        from .service import AuthorityService
        if not isinstance(service, AuthorityService):
            raise ValueError("root authority service is required")
        if not isinstance(roles, RootControllerRoleCatalog):
            raise ValueError("typed active root controller roles are required")
        if (not isinstance(job_enrollments, Mapping) or source_observers is None
                or not isinstance(selected_specs, Mapping)
                or any(not isinstance(key, tuple) or len(key) != 2
                       or not isinstance(value, Mapping) for key, value in selected_specs.items())):
            raise ValueError("active resource jobs and source observer registry are required")
        if (getattr(custody_resolver, "resolve_for_event", None) is None
                or not callable(custody_resolver.resolve_for_event)):
            raise ValueError("root daemon unit and loaded role custody is unavailable")
        digest = service.service_generation_digest
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError("active service generation digest is required")
        if roles.generation_digest != digest:
            raise ValueError("root controller catalog is not from the active service generation")
        self.service = service
        self.roles = MappingProxyType({role.id: role for role in roles.rows})
        self.job_enrollments = MappingProxyType(dict(job_enrollments))
        self.source_observers = source_observers
        self.selected_specs = MappingProxyType({key: MappingProxyType(dict(value))
                                                for key, value in selected_specs.items()})
        self.custody_resolver = custody_resolver
        self.authority_epoch = service.authority_epoch
        self.service_generation_digest = digest
        self._lock = threading.RLock()
        self._events: dict[str, _RootEventRecord] = {}
        self._used: set[tuple[str, str]] = set()
        self._pending_context_requests: dict[int, RootResourceJobContextRequest] = {}
        self._event_ids_seen: set[tuple[str, str, str]] = set()
        self._ingress_token = object()
        self._context_issuer_token = object()
        self._event_bytes = 0

    def _select_role(self, *, observer_id: str, controller_kind: str,
                     backend_id: str, operation: str) -> RootControllerRoleEnrollment:
        matches = [role for role in self.roles.values()
                   if role.controller_kind == controller_kind
                   and observer_id in role.source_observer_enrollment_ids
                   and backend_id in role.allowed_backend_enrollment_ids
                   and operation in role.allowed_operations]
        if len(matches) != 1:
            raise AuthorityDenied("resource.controller", "selected root controller role is missing or ambiguous")
        return matches[0]

    def _profile_binding(self, enrollment: Any) -> Any:
        matches = [binding for binding in self.service.bindings_by_uid.values()
                   if binding.profile_id == enrollment.profile_id
                   and binding.principal_id == enrollment.principal_id]
        if len(matches) != 1:
            raise AuthorityDenied("resource.subject", "selected profile principal binding is missing or ambiguous")
        return matches[0]

    def resolve_for_event(self, root_event_handle: RootResourceEventHandle,
                          node_id: str) -> Any:
        """Resolve a fresh current daemon PIDFD for this event and selected node.

        The custody owner supplies `resolve_role(role, expected_generation, ttl)`
        and `revalidate_role(proof, role, expected_generation)`; neither uses
        caller-selected PID identity. The returned DTO is a one-use PIDFD copy.
        """
        from hermes_installer.registry.resource_jobs import RootTaskController
        record, enrollment, node, backend = self._resolve_event_node(root_event_handle, node_id)
        event = record.handle
        kind = {"schedule-event": "root-scheduler", "webhook-event": "root-webhook",
                "native-input": "root-channel"}.get(event.source_kind)
        if kind is None:
            raise AuthorityDenied("resource.controller", "selected resource kind has no root controller")
        role = self._select_role(observer_id=event.source_observer_enrollment_id,
                                 controller_kind=kind, backend_id=backend.backend_id,
                                 operation=node.effect)
        if event.authority_epoch != self.service.authority_epoch:
            raise AuthorityDenied("resource.controller", "root event belongs to another service epoch")
        proof = self.custody_resolver.resolve_for_event(event.handle, node_id)
        revalidate = getattr(proof, "revalidate", None)
        if (proof is None or getattr(proof, "row", None) != role
                or getattr(proof, "generation_digest", None) != self.service_generation_digest
                or getattr(proof, "expires_monotonic", 0) > event.expires_monotonic
                or not callable(revalidate) or revalidate() is not True):
            close = getattr(proof, "close", None)
            if callable(close):
                close()
            raise AuthorityDenied("resource.controller", "selected root controller role proof is stale")
        duplicate_pidfd = getattr(proof, "duplicate_pidfd", None)
        if not callable(duplicate_pidfd):
            close = getattr(proof, "close", None)
            if callable(close):
                close()
            raise AuthorityDenied("resource.controller", "root controller proof has no live PIDFD")
        try:
            duplicate = duplicate_pidfd()
            if type(duplicate) is not int or duplicate < 0:
                raise AuthorityDenied("resource.controller", "custody returned an invalid PIDFD duplicate")
            proof_row = proof.row
            return RootTaskController(
                schema=1, controller_handle=secrets.token_urlsafe(32),
                controller_kind=role.controller_kind,
                controller_role_artifact_id=proof_row.role_module_artifact_id,
                controller_role_sha256=proof_row.role_module_sha256,
                pid=proof.pid, pidfd=duplicate, uid=proof.uid, identity=proof.identity,
                controller_profile_id=None,
                controller_generation=role.controller_generation,
                source_receipt_id=None,
                subject_principal_id=enrollment.principal_id,
                subject_profile_id=enrollment.profile_id,
                subject_namespace_id=self._profile_binding(enrollment).namespace_id,
                service_generation_digest=self.service_generation_digest,
                expires_monotonic=min(event.expires_monotonic, proof.expires_monotonic),
            )
        except Exception:
            try:
                import os
                os.close(duplicate)
            except (OSError, UnboundLocalError):
                pass
            raise
        finally:
            close = getattr(proof, "close", None)
            if callable(close):
                close()

    def controller_binding_for_event(self, root_event_handle: RootResourceEventHandle | str,
                                     node_id: str) -> RootControllerEventBinding:
        """Custody resolver callback; returns the exact protected join it must prove."""
        if isinstance(root_event_handle, str):
            with self._lock:
                record = next((item for item in self._events.values()
                               if item.handle.handle == root_event_handle), None)
            if record is None:
                raise AuthorityDenied("resource.event", "root event handle is unknown or consumed")
            root_event_handle = record.handle
        record, enrollment, node, backend = self._resolve_event_node(root_event_handle, node_id)
        event = record.handle
        kind = self._source_controller_kind(event.source_kind)
        role = self._select_role(observer_id=event.source_observer_enrollment_id,
                                 controller_kind=kind, backend_id=backend.backend_id,
                                 operation=node.effect)
        observer = self.source_observers.observers[event.source_observer_enrollment_id]
        expiry = min(event.expires_monotonic,
                     self.service.monotonic() + role.max_lease_seconds)
        return RootControllerEventBinding(
            role=role, event=event, resource_enrollment=enrollment,
            node=node, backend=backend, source_observer=observer,
            service_generation_digest=self.service_generation_digest,
            authority_epoch=self.service.authority_epoch,
            expires_monotonic=expiry,
        )

    def register_verified_event(self, *, resource_id: str, generation: str,
                                source_kind: str, source_observer_enrollment_id: str,
                                payload: bytes,
                                parent_context: Any,
                                parent_receipts: tuple[Any, ...],
                                _issuer: object) -> RootResourceEventHandle:
        """Internal finalizer for ingress adapters after signature/freshness/replay checks.

        `_issuer` must be the exact private producer token held by the concrete
        root ingress adapters. In the absence of a selected producer adapter
        event, this method is not a worker-accessible admission path.
        """
        token = getattr(self, "_ingress_token", None)
        if token is None or _issuer is not token:
            raise AuthorityDenied("resource.event", "event was not verified by an installed root ingress")
        key = (resource_id, generation)
        enrollment = self.job_enrollments.get(key)
        if (enrollment is None or enrollment.selected_enabled is not True
                or source_kind not in enrollment.source_policy
                or source_observer_enrollment_id != enrollment.observer_enrollment_id
                or not isinstance(payload, bytes) or not 1 <= len(payload) <= enrollment.max_payload_bytes
                or not isinstance(parent_receipts, tuple) or not parent_receipts or len(parent_receipts) > 64):
            raise AuthorityDenied("resource.event", "verified event does not join the active selected resource")
        selected_spec = self.selected_specs.get(key)
        if selected_spec is None:
            raise AuthorityDenied("resource.event", "root selected source specification is unavailable")
        observer = getattr(self.source_observers, "observers", {}).get(source_observer_enrollment_id)
        if (observer is None or observer.source_kind != source_kind
                or observer.profile_id != enrollment.profile_id
                or observer.principal_id != enrollment.principal_id
                or observer.channel_id != enrollment.source_issuer_channel_id
                or observer.generation != enrollment.profile_generation):
            raise AuthorityDenied("resource.event", "event observer differs from the active selected enrollment")
        now = self.service.monotonic()
        from .types import HostContext, SourceReceipt, canonical_digest
        if (not isinstance(parent_context, HostContext)
                or tuple(parent_context.source_receipts) != parent_receipts):
            raise AuthorityDenied("resource.event", "event parent is not the complete signed receipt closure")
        principal_binding = self._profile_binding(enrollment)
        if (principal_binding.principal_id != enrollment.principal_id
                or parent_context.profile_id != enrollment.profile_id
                or parent_context.principal_id != enrollment.principal_id
                or parent_context.namespace_id != principal_binding.namespace_id):
            raise AuthorityDenied("resource.event", "root event subject differs from active selected profile")
        try:
            self.service._verify_context_signature(parent_context)
            self.service._assert_current_context(parent_context, principal_binding, principal_binding.uid)
            for receipt in parent_receipts:
                if not isinstance(receipt, SourceReceipt):
                    raise ValueError
                self.service._verify_source_receipt(receipt, principal_binding)
            receipt_ids = {receipt.receipt_id for receipt in parent_receipts}
            if (len(receipt_ids) != len(parent_receipts)
                    or any(not set(receipt.parent_receipt_ids) <= receipt_ids for receipt in parent_receipts)):
                raise ValueError
        except Exception:
            raise AuthorityDenied("resource.event", "event parent receipt closure failed verification") from None
        expected_kind = {"crons": "schedule-event", "webhooks": "webhook-event",
                         "channels": "native-input"}.get(enrollment.kind)
        source_receipt = next((receipt for receipt in parent_receipts
                               if receipt.source_kind == source_kind
                               and receipt.origin_id.startswith(observer.origin_id + ":")
                               and receipt.origin_id.count(":") ==
                                   observer.origin_id.count(":") + 1), None)
        observer_origin = observer.origin_id
        event_prefix = observer_origin + ":"
        event_id = (source_receipt.origin_id[len(event_prefix):]
                    if source_receipt is not None else "")
        if (expected_kind != source_kind or source_receipt is None
                or not _identifier(event_id)
                or source_receipt.payload_digest != canonical_digest(payload)
                or source_receipt.profile_id != enrollment.profile_id
                or source_receipt.principal_id != enrollment.principal_id
                or source_receipt.process_generation != enrollment.profile_generation):
            raise AuthorityDenied("resource.event", "signed source receipt does not bind the verified event")
        receipt_by_id = {receipt.receipt_id: receipt for receipt in parent_receipts}
        reachable: set[str] = set()
        pending = [source_receipt.receipt_id]
        while pending:
            receipt_id = pending.pop()
            if receipt_id in reachable:
                continue
            reachable.add(receipt_id)
            pending.extend(receipt_by_id[receipt_id].parent_receipt_ids)
        if reachable != receipt_ids:
            raise AuthorityDenied("resource.event", "parent closure contains receipts outside the source ancestry")
        issued_monotonic = source_receipt.issued_at_monotonic
        expires_monotonic = min(source_receipt.monotonic_expires_at,
                                parent_context.monotonic_expires_at,
                                now + _MAX_EVENT_LEASE_SECONDS)
        if (isinstance(issued_monotonic, bool) or not isinstance(issued_monotonic, (int, float))
                or not math.isfinite(issued_monotonic) or issued_monotonic > now
                or isinstance(expires_monotonic, bool) or not isinstance(expires_monotonic, (int, float))
                or not math.isfinite(expires_monotonic) or expires_monotonic <= now):
            raise AuthorityDenied("resource.event", "verified event lease is stale or unbounded")
        closure_digest = canonical_digest(sorted(
            (receipt.receipt_id, canonical_digest(receipt.claims())) for receipt in parent_receipts))
        event_fields = _event_fields_from_payload(payload)
        handle = RootResourceEventHandle(
            handle=secrets.token_urlsafe(32), event_id=event_id,
            resource_id=resource_id, resource_generation=generation,
            source_kind=source_kind,
            source_observer_enrollment_id=source_observer_enrollment_id,
            source_receipt_ids=tuple(sorted(receipt_ids)),
            parent_closure_digest=closure_digest,
            payload_sha256=canonical_digest(payload), issued_monotonic=float(issued_monotonic),
            expires_monotonic=float(expires_monotonic), authority_epoch=self.authority_epoch,
        )
        with self._lock:
            self._prune_locked(now)
            if handle.handle in self._events or any(
                    item.handle.event_id == event_id and item.handle.resource_id == resource_id
                    and item.handle.resource_generation == generation for item in self._events.values()
            ) or (resource_id, generation, event_id) in self._event_ids_seen:
                raise AuthorityDenied("resource.event_replay", "root event was already admitted")
            if len(self._event_ids_seen) >= _MAX_ROOT_EVENT_IDS_PER_EPOCH:
                raise AuthorityDenied("resource.event_capacity", "root event epoch reached its replay bound")
            if (len(self._events) >= _MAX_ROOT_EVENT_COUNT
                    or self._event_bytes + len(payload) > _MAX_ROOT_EVENT_BYTES):
                raise AuthorityDenied("resource.event_capacity", "bounded root event store is full")
            self._events[handle.handle] = _RootEventRecord(
                handle, parent_context, parent_receipts, bytes(payload), event_fields,
                dict(selected_spec), {})
            self._event_ids_seen.add((resource_id, generation, event_id))
            self._event_bytes += len(payload)
        return handle

    def issue_resource_job_context(self, root_event_handle: RootResourceEventHandle,
                                   node_id: str, operation: str,
                                   canonical_payload_sha256: str) -> tuple[Any, Any]:
        """Ask AuthorityService to mint a fresh reduced child grant for a root event."""
        record, enrollment, node, backend = self._resolve_event_node(root_event_handle, node_id)
        if (operation != node.effect or operation != backend.operation
                or operation not in _OPERATIONS_BY_KIND[self._source_controller_kind(record.handle.source_kind)]
                or not isinstance(canonical_payload_sha256, str)
                or not _SHA256.fullmatch(canonical_payload_sha256)):
            raise AuthorityDenied("resource.context", "event does not authorize the selected operation")
        recipe = enrollment.body_recipes.get(node.body_recipe_id)
        if recipe is None:
            raise AuthorityDenied("resource.context", "selected resource body recipe is unavailable")
        try:
            body = recipe.render(
                backend=backend, scope_bindings=enrollment.scope_bindings,
                validators=enrollment.validators, event_fields=record.event_fields,
                parent_results={
                    node_id: fields for node_id, value in record.parent_results.items()
                    if isinstance(value, tuple) and len(value) == 2
                    for receipt_id, fields in (value,)
                    if receipt_id in {item.receipt_id for item in record.parent_context.source_receipts}
                },
            )
        except Exception:
            raise AuthorityDenied("resource.context", "selected resource body could not be rendered") from None
        from .types import canonical_digest
        digest = canonical_digest(body)
        if digest != canonical_payload_sha256:
            raise AuthorityDenied("resource.context", "payload digest differs from root-rendered selected recipe")
        controller = self.resolve_for_event(root_event_handle, node_id)
        role = self._select_role(observer_id=record.handle.source_observer_enrollment_id,
                                 controller_kind=self._source_controller_kind(record.handle.source_kind),
                                 backend_id=backend.backend_id, operation=node.effect)
        request = RootResourceJobContextRequest(
            root_event=record.handle, event_payload=record.payload,
            event_fields=record.event_fields, parent_context=record.parent_context,
            parent_receipts=record.parent_receipts, resource_enrollment=enrollment,
            node=node, backend=backend, controller=controller,
            operation=operation, canonical_payload_sha256=digest,
            service_generation_digest=self.service_generation_digest,
            authority_epoch=self.service.authority_epoch,
            issuer_token=self._context_issuer_token,
        )
        use_key = (record.handle.handle, node_id)
        with self._lock:
            if use_key in self._used:
                import os
                os.close(controller.pidfd)
                raise AuthorityDenied("resource.context", "root event node context was already issued")
            # Reserve before calling authority so concurrent/reentrant attempts
            # cannot duplicate a grant. Failure remains consumed by design.
            self._used.add(use_key)
            if len(self._pending_context_requests) >= _MAX_ROOT_EVENT_COUNT:
                import os
                os.close(controller.pidfd)
                raise AuthorityDenied("resource.context", "root context request capacity is full")
            self._pending_context_requests[id(request)] = request
        issuer = getattr(self.service, "issue_resource_job_context", None)
        if not callable(issuer):
            with self._lock:
                self._pending_context_requests.pop(id(request), None)
            import os
            os.close(controller.pidfd)
            raise AuthorityDenied("resource.context", "root event context issuer is unavailable")
        try:
            result = issuer(request)
            if (not isinstance(result, tuple) or len(result) != 2):
                raise AuthorityDenied("resource.context", "root event issuer returned an invalid grant pair")
            return result
        finally:
            with self._lock:
                self._pending_context_requests.pop(id(request), None)
            import os
            try:
                os.close(controller.pidfd)
            except OSError:
                pass

    def consume_context_request(
        self, request: RootResourceJobContextRequest,
    ) -> RootResourceContextReservation | None:
        """Consume an exact instance-minted request before the service signs it."""
        if not isinstance(request, RootResourceJobContextRequest):
            return None
        with self._lock:
            if (request.issuer_token is not self._context_issuer_token
                    or self._pending_context_requests.pop(id(request), None) is not request):
                return None
        try:
            from .types import canonical_digest
            if (request.authority_epoch != self.service.authority_epoch
                    or request.service_generation_digest != self.service.service_generation_digest
                    or request.root_event.authority_epoch != self.service.authority_epoch
                    or request.controller.service_generation_digest != request.service_generation_digest
                    or request.controller.controller_kind != self._source_controller_kind(
                        request.root_event.source_kind)):
                return None
            record, enrollment, node, backend = self._resolve_event_node(
                request.root_event, request.node.node_id)
            if (record.handle is not request.root_event
                    or record.payload != request.event_payload
                    or record.event_fields != request.event_fields
                    or record.parent_context is not request.parent_context
                    or record.parent_receipts != request.parent_receipts
                    or enrollment != request.resource_enrollment
                    or node != request.node or backend != request.backend
                    or self.selected_specs.get((enrollment.resource_id, enrollment.generation))
                       != record.selected_spec):
                return None
            role = self._select_role(
                observer_id=record.handle.source_observer_enrollment_id,
                controller_kind=self._source_controller_kind(record.handle.source_kind),
                backend_id=backend.backend_id, operation=node.effect)
            if (request.controller.controller_role_artifact_id != role.role_module_artifact_id
                    or request.controller.controller_role_sha256 != role.role_module_sha256
                    or request.controller.controller_generation != role.controller_generation
                    or request.operation != node.effect):
                return None
            recipe = enrollment.body_recipes.get(node.body_recipe_id)
            if recipe is None:
                return None
            parent_result_fields = {
                parent_node_id: fields
                for parent_node_id, value in record.parent_results.items()
                if isinstance(value, tuple) and len(value) == 2
                for receipt_id, fields in (value,)
                if receipt_id in {item.receipt_id for item in record.parent_context.source_receipts}
            }
            body = recipe.render(
                backend=backend, scope_bindings=enrollment.scope_bindings,
                validators=enrollment.validators, event_fields=record.event_fields,
                parent_results=parent_result_fields,
            )
            if (canonical_digest(body) != request.canonical_payload_sha256
                    or request.controller.expires_monotonic <= self.service.monotonic()
                    or (record.handle.handle, node.node_id) not in self._used):
                return None
            return RootResourceContextReservation(
                request=request, record=record, enrollment=enrollment, node=node,
                backend=backend, role=role, controller_proof=request.controller)
        except Exception:
            return None

    @staticmethod
    def _source_controller_kind(source_kind: str) -> str:
        value = {"schedule-event": "root-scheduler", "webhook-event": "root-webhook",
                 "native-input": "root-channel"}.get(source_kind)
        if value is None:
            raise AuthorityDenied("resource.controller", "source kind has no root controller role")
        return value

    def _resolve_event_node(self, handle: RootResourceEventHandle,
                            node_id: str) -> tuple[_RootEventRecord, Any, Any, Any]:
        if not isinstance(handle, RootResourceEventHandle) or not _identifier(node_id):
            raise AuthorityDenied("resource.event", "root event handle or node is invalid")
        now = self.service.monotonic()
        with self._lock:
            record = self._events.get(handle.handle)
            if record is None or record.handle is not handle:
                raise AuthorityDenied("resource.event", "root event handle is unknown or consumed")
            if (handle.authority_epoch != self.service.authority_epoch
                    or handle.expires_monotonic <= now):
                self._drop_event_locked(handle.handle)
                raise AuthorityDenied("resource.event", "root event expired or belongs to another daemon epoch")
        enrollment = self.job_enrollments.get((handle.resource_id, handle.resource_generation))
        if (enrollment is None or enrollment.selected_enabled is not True
                or not getattr(enrollment, "node_map", None)):
            raise AuthorityDenied("resource.event", "selected resource generation is no longer active")
        node = enrollment.node_map.get(node_id)
        backend = enrollment.backends.get(node.backend_enrollment_id) if node is not None else None
        if (node is None or backend is None
                or node.action_id not in enrollment.approved_action_ids
                or node.effect != backend.operation or node.target != backend.target_id
                or node.recipient != backend.recipient
                or node.action_id not in backend.approved_action_ids):
            raise AuthorityDenied("resource.event", "event does not authorize this selected node")
        self._select_role(observer_id=handle.source_observer_enrollment_id,
                          controller_kind=self._source_controller_kind(handle.source_kind),
                          backend_id=backend.backend_id, operation=node.effect)
        observer = getattr(self.source_observers, "observers", {}).get(handle.source_observer_enrollment_id)
        if (observer is None or getattr(observer, "source_kind", None) != handle.source_kind
                or getattr(observer, "channel_id", None) != enrollment.source_issuer_channel_id
                or getattr(observer, "profile_id", None) != enrollment.profile_id):
            raise AuthorityDenied("resource.event", "event observer is outside the active selected source catalog")
        return record, enrollment, node, backend

    def cancel_event(self, handle: RootResourceEventHandle) -> None:
        """Revoke one in-memory event and release its retained payload immediately."""
        if not isinstance(handle, RootResourceEventHandle):
            raise AuthorityDenied("resource.event", "root event handle is invalid")
        with self._lock:
            record = self._events.get(handle.handle)
            if record is None or record.handle is not handle:
                raise AuthorityDenied("resource.event", "root event handle is unknown")
            self._drop_event_locked(handle.handle)

    def revoke_generation(self, resource_id: str, generation: str) -> int:
        """Remove events for a superseded selected resource generation."""
        if not _identifier(resource_id) or not _SHA256.fullmatch(generation):
            raise AuthorityDenied("resource.event", "resource revocation identity is invalid")
        with self._lock:
            handles = [key for key, value in self._events.items()
                       if value.handle.resource_id == resource_id
                       and value.handle.resource_generation == generation]
            for key in handles:
                self._drop_event_locked(key)
            return len(handles)

    def prune(self) -> int:
        with self._lock:
            return self._prune_locked(self.service.monotonic())

    def close(self) -> None:
        with self._lock:
            self._events.clear()
            self._event_bytes = 0
            self._used.clear()
            self._pending_context_requests.clear()
            self._event_ids_seen.clear()

    def _prune_locked(self, now: float) -> int:
        expired = [key for key, record in self._events.items()
                   if record.handle.expires_monotonic <= now
                   or record.handle.authority_epoch != self.service.authority_epoch]
        for key in expired:
            self._drop_event_locked(key)
        return len(expired)

    def _drop_event_locked(self, key: str) -> None:
        record = self._events.pop(key, None)
        if record is not None:
            self._event_bytes = max(0, self._event_bytes - len(record.payload))
        self._used = {item for item in self._used if item[0] != key}
