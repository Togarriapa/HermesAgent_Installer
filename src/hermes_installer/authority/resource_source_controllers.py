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

from .types import AuthorityDenied, Sensitivity, canonical_digest
from .root_controller_custody import RootControllerRoleEnrollment as _CustodyRoleEnrollment
from .root_controller_custody import RootControllerRoleCatalog

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OPAQUE_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
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
_INGRESS_CAPTURE_SCHEMA_ID = "resource-ingress-capture-v1"
_INGRESS_CAPTURE_SCHEMA_SHA256 = "0a0c8d71b58cbc04d65309003a65701b0dfb1e57a9931c5a96356f5c647609b1"
_INGRESS_ENVELOPE_FIELDS = frozenset({
    "schema", "kind", "resource_id", "resource_generation", "profile_id",
    "controller_proof_handle", "raw_observation_handle", "raw_payload_sha256",
    "event_data", "observed_monotonic", "replay_key_sha256",
})


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


def _validate_ingress_envelope(
    payload: bytes, *, expected_kind: str, expected_resource_id: str,
    expected_generation: str, expected_profile_id: str,
    expected_controller_handle: str | None, expected_raw_handle: str | None,
    expected_raw_sha256: str | None, expected_replay_sha256: str | None,
    expected_observed: float | None, expected_event_data: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    """Validate the exact canonical root envelope against retained raw proof."""
    from .types import canonical_bytes
    if (not isinstance(payload, bytes) or not 1 <= len(payload) <= 1_048_576
            or expected_event_data is None):
        raise AuthorityDenied("resource.ingress", "canonical ingress envelope is outside its bound")
    try:
        decoded = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=lambda pairs: _unique_json_pairs(pairs),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite number")),
        )
    except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
        raise AuthorityDenied("resource.ingress", "canonical ingress envelope is malformed") from None
    key_count = [0]
    if not _bounded_event_json(decoded, depth=0, key_count=key_count):
        raise AuthorityDenied("resource.ingress", "canonical ingress envelope exceeds JSON bounds")
    if (not isinstance(decoded, dict) or set(decoded) != _INGRESS_ENVELOPE_FIELDS
            or canonical_bytes(decoded) != payload
            or decoded.get("schema") != 1
            or decoded.get("kind") != expected_kind
            or decoded.get("resource_id") != expected_resource_id
            or decoded.get("resource_generation") != expected_generation
            or decoded.get("profile_id") != expected_profile_id
            or decoded.get("controller_proof_handle") != expected_controller_handle
            or decoded.get("raw_observation_handle") != expected_raw_handle
            or decoded.get("raw_payload_sha256") != expected_raw_sha256
            or decoded.get("replay_key_sha256") != expected_replay_sha256
            or decoded.get("event_data") != dict(expected_event_data)
            or isinstance(decoded.get("observed_monotonic"), bool)
            or not isinstance(decoded.get("observed_monotonic"), (int, float))
            or not math.isfinite(decoded["observed_monotonic"])
            or decoded["observed_monotonic"] != expected_observed):
        raise AuthorityDenied("resource.ingress", "canonical ingress envelope differs from selected raw observation")
    return MappingProxyType(dict(decoded))


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _bounded_event_json(value: Any, *, depth: int, key_count: list[int]) -> bool:
    if depth > 32:
        return False
    if isinstance(value, dict):
        key_count[0] += len(value)
        return (key_count[0] <= 4096
                and all(isinstance(key, str)
                        and _bounded_event_json(item, depth=depth + 1, key_count=key_count)
                        for key, item in value.items()))
    if isinstance(value, list):
        return len(value) <= 4096 and all(
            _bounded_event_json(item, depth=depth + 1, key_count=key_count) for item in value)
    if isinstance(value, float):
        return math.isfinite(value)
    return value is None or type(value) in {str, int, bool}


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
    admission_handle: Any = field(default=None, repr=False, compare=False)
    node_result_closure_handle: str | None = None


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
    admission_handle: Any = field(default=None, repr=False)
    node_result_closure: Any = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class RootResourceEventIssuerCapability:
    """Per-registry capability passed only to the attached root event issuer."""

    _token: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class RootResourceSourceEventProof:
    """Opaque producer event presented to the attached root context issuer."""

    producer_handle: str
    event_id: str
    resource_id: str
    resource_generation: str
    source_observer_enrollment_id: str
    source_kind: str
    payload: bytes = field(repr=False)
    verified_provenance: object = field(repr=False, compare=False)
    issuer_token: object = field(repr=False, compare=False)
    raw_observation_handle: str | None = None
    raw_payload_sha256: str | None = None
    replay_key_sha256: str | None = None
    observed_monotonic: float | None = None
    controller_proof_handle: str | None = None
    capture_schema_id: str | None = None
    capture_schema_sha256: str | None = None

    def __post_init__(self) -> None:
        for name in ("producer_handle", "event_id", "resource_id", "resource_generation",
                     "source_observer_enrollment_id"):
            if not _identifier(getattr(self, name)):
                raise ValueError(f"root source event {name} is invalid")
        if not _OPAQUE_HANDLE.fullmatch(self.producer_handle) or not _OPAQUE_HANDLE.fullmatch(self.event_id):
            raise ValueError("root source event producer and event handles must be opaque random IDs")
        if (self.source_kind not in {"schedule-event", "webhook-event", "native-input"}
                or not isinstance(self.payload, bytes) or not self.payload
                or isinstance(self.verified_provenance, (str, bytes, bool, int, float, dict, list, tuple))
                or isinstance(self.issuer_token, (str, bytes, bool, int, float, dict, list, tuple))):
            raise ValueError("root source event proof is malformed")
        if any(value is not None for value in (
                self.raw_observation_handle, self.raw_payload_sha256, self.replay_key_sha256,
                self.observed_monotonic, self.controller_proof_handle,
                self.capture_schema_id, self.capture_schema_sha256)):
            if (not isinstance(self.raw_observation_handle, str)
                    or not _OPAQUE_HANDLE.fullmatch(self.raw_observation_handle)
                    or self.raw_payload_sha256 != hashlib.sha256(self.payload).hexdigest()
                    or not isinstance(self.replay_key_sha256, str)
                    or not _SHA256.fullmatch(self.replay_key_sha256)
                    or isinstance(self.observed_monotonic, bool)
                    or not isinstance(self.observed_monotonic, (int, float))
                    or not math.isfinite(self.observed_monotonic)
                    or self.observed_monotonic < 0
                    or not isinstance(self.controller_proof_handle, str)
                    or not _OPAQUE_HANDLE.fullmatch(self.controller_proof_handle)
                    or self.capture_schema_id != _INGRESS_CAPTURE_SCHEMA_ID
                    or self.capture_schema_sha256 != _INGRESS_CAPTURE_SCHEMA_SHA256):
                raise ValueError("root source raw-observation binding is malformed")

    @property
    def observer_enrollment_id(self) -> str:
        return self.source_observer_enrollment_id


@dataclass(frozen=True, slots=True)
class RootResourceIssuedSourceEvent:
    """Signed root source context and complete receipt closure from the issuer."""

    source_context: Any = field(repr=False)
    receipt: Any = field(repr=False)
    parent_receipts: tuple[Any, ...] = field(repr=False)
    payload: bytes = field(repr=False)
    producer_handle: str
    event_id: str
    resource_id: str
    resource_generation: str
    source_observer_enrollment_id: str
    source_kind: str
    controller_role_id: str
    controller_proof: Any = field(repr=False)
    raw_observation_handle: str | None = None
    raw_payload: bytes | None = field(default=None, repr=False)
    raw_payload_sha256: str | None = None
    replay_key_sha256: str | None = None
    observed_monotonic: float | None = None
    event_data: Mapping[str, Any] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        for name in ("producer_handle", "event_id", "resource_id", "resource_generation",
                     "source_observer_enrollment_id", "controller_role_id"):
            if not _identifier(getattr(self, name)):
                raise ValueError(f"issued root source event {name} is invalid")
        if (not _OPAQUE_HANDLE.fullmatch(self.producer_handle)
                or not _OPAQUE_HANDLE.fullmatch(self.event_id)
                or self.source_kind not in {"schedule-event", "webhook-event", "native-input"}
                or not isinstance(self.payload, bytes) or not self.payload
                or not isinstance(self.parent_receipts, tuple)):
            raise ValueError("issued root source event is malformed")
        if self.raw_observation_handle is not None:
            if (not _OPAQUE_HANDLE.fullmatch(self.raw_observation_handle)
                    or not isinstance(self.raw_payload, bytes) or not self.raw_payload
                    or self.raw_payload_sha256 != hashlib.sha256(self.raw_payload).hexdigest()
                    or not isinstance(self.replay_key_sha256, str)
                    or not _SHA256.fullmatch(self.replay_key_sha256)
                    or isinstance(self.observed_monotonic, bool)
                    or not isinstance(self.observed_monotonic, (int, float))
                    or not math.isfinite(self.observed_monotonic)
                    or not isinstance(self.event_data, Mapping)):
                raise ValueError("issued root raw-observation binding is malformed")

    @property
    def observer_enrollment_id(self) -> str:
        return self.source_observer_enrollment_id


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
    raw_payload: bytes | None = field(default=None, repr=False)
    raw_observation_handle: str | None = None
    raw_payload_sha256: str | None = None
    replay_key_sha256: str | None = None
    observed_monotonic: float | None = None

    def __post_init__(self) -> None:
        from types import MappingProxyType
        object.__setattr__(self, "event_fields", MappingProxyType(dict(self.event_fields)))
        object.__setattr__(self, "selected_spec", MappingProxyType(dict(self.selected_spec)))
        object.__setattr__(self, "parent_results", MappingProxyType(dict(self.parent_results)))
        if self.raw_payload is not None:
            object.__setattr__(self, "raw_payload", bytes(self.raw_payload))


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
        self._replay_keys_seen: set[tuple[str, str, str]] = set()
        self._ingress_token = object()
        self._context_issuer_token = object()
        self._event_issuer: Any = None
        self._event_issuer_capability: RootResourceEventIssuerCapability | None = None
        # Initial ingress must establish the actual root controller before an
        # event (and therefore before any source receipt) exists.  Keep the
        # custody proof in this instance until the issuer consumes the exact
        # producer observation.  The handle is opaque and never worker-visible.
        self._ingress_proofs: dict[str, tuple[Any, Any, Any, Any, Any]] = {}
        self._event_bytes = 0
        self._resource_job_authority: Any = None
        self._event_admissions: dict[str, Any] = {}

    def resolve_selected_ingress_controller(
        self, controller_role_id: str, selected_source_issuer_id: str,
        selected_backend_id: str,
    ) -> Any:
        """Reserve current root custody for an enrolled ingress before event mint.

        The IDs are root assembly selections, not HTTP/worker fields.  Custody
        independently resolves the systemd unit, PIDFD, executable and loaded
        role module; this registry checks that its returned proof joins the
        selected resource, observer, backend and active generation exactly.
        """
        from .root_controller_custody import RootIngressControllerProof

        if not all(_identifier(value) for value in (
                controller_role_id, selected_source_issuer_id, selected_backend_id)):
            raise AuthorityDenied("resource.ingress", "selected ingress binding is malformed")
        with self._lock:
            if (self.service.authority_epoch != self.authority_epoch
                    or self.service.service_generation_digest != self.service_generation_digest):
                raise AuthorityDenied("resource.ingress", "selected ingress generation or epoch is stale")
            role = self.roles.get(controller_role_id)
            if role is None:
                raise AuthorityDenied("resource.ingress", "selected ingress role is unavailable")
            enrollments = [enrollment for enrollment in self.job_enrollments.values()
                           if getattr(enrollment, "source_issuer_channel_id", None) == selected_source_issuer_id
                           and getattr(enrollment, "selected_enabled", False) is True
                           and selected_backend_id in getattr(enrollment, "backends", {})]
            if len(enrollments) != 1:
                raise AuthorityDenied("resource.ingress", "selected ingress resource/backend join is missing or ambiguous")
            enrollment = enrollments[0]
            observer_id = getattr(enrollment, "observer_enrollment_id", None)
            observer = getattr(self.source_observers, "observers", {}).get(observer_id)
            if observer is None:
                raise AuthorityDenied("resource.ingress", "selected ingress observer enrollment is unavailable")
            source_kind = {"crons": "schedule-event", "webhooks": "webhook-event",
                           "channels": "native-input"}.get(enrollment.kind)
            expected_controller = self._source_controller_kind(source_kind) if source_kind else None
            backend = enrollment.backends[selected_backend_id]
            expected_operation = {"crons": "resource.cron.run", "webhooks": "resource.webhook.run",
                                  "channels": "resource.channel.run"}.get(enrollment.kind)
            if (role.controller_kind != expected_controller
                    or observer_id not in role.source_observer_enrollment_ids
                    or selected_backend_id not in role.allowed_backend_enrollment_ids
                    or expected_operation not in role.allowed_operations
                    or getattr(observer, "source_kind", None) != source_kind
                    or getattr(observer, "profile_id", None) != enrollment.profile_id
                    or getattr(observer, "principal_id", None) != enrollment.principal_id
                    or getattr(observer, "generation", None) != enrollment.profile_generation
                    or getattr(observer, "channel_id", None) != enrollment.source_issuer_channel_id
                    or getattr(backend, "observer_enrollment_id", observer_id) != observer_id
                    or getattr(backend, "source_issuer_channel_id", selected_source_issuer_id)
                    != selected_source_issuer_id
                    or getattr(backend, "backend_id", None) != selected_backend_id):
                raise AuthorityDenied("resource.ingress", "selected ingress role/observer/backend join is invalid")
            resolver = getattr(self.custody_resolver, "resolve_selected_ingress_controller", None)
            if not callable(resolver):
                raise AuthorityDenied("resource.ingress", "pre-event root ingress custody is unavailable")
            try:
                proof = resolver(controller_role_id, selected_source_issuer_id, selected_backend_id)
            except Exception:
                raise AuthorityDenied("resource.ingress", "selected ingress controller custody is unavailable") from None
            try:
                if (type(proof) is not RootIngressControllerProof
                        or proof.controller_role_id != role.id
                        or proof.controller_kind != role.controller_kind
                        or proof.controller_generation != role.controller_generation
                        or proof.source_issuer_id != selected_source_issuer_id
                        or proof.backend_enrollment_id != selected_backend_id
                        or proof.resource_generation != enrollment.generation
                        or proof.service_generation_digest != self.service_generation_digest
                        or proof.authority_epoch != self.authority_epoch
                        or proof.uid != 0
                        or type(proof.pid) is not int or proof.pid <= 0
                        or type(proof.pidfd) is not int or proof.pidfd < 0
                        or getattr(proof, "live_peer_identity", None) is None
                        or proof.role_artifact_id != role.role_module_artifact_id
                        or proof.role_artifact_sha256 != role.role_module_sha256
                        or not _identifier(proof.proof_handle)
                        or not _OPAQUE_HANDLE.fullmatch(proof.proof_handle)
                        or not _identifier(proof.selected_ingress_binding_id)
                        or not callable(getattr(proof, "revalidate", None))
                        or proof.revalidate() is not True
                        or proof.expires_monotonic <= self.service.monotonic()
                        or proof.expires_monotonic > self.service.monotonic() + role.max_lease_seconds):
                    raise AuthorityDenied("resource.ingress", "selected ingress proof does not match active custody")
                handle = proof.proof_handle
                if handle in self._ingress_proofs:
                    raise AuthorityDenied("resource.ingress", "selected ingress proof handle was replayed")
                self._ingress_proofs[handle] = (proof, role, enrollment, observer, backend)
                return proof
            except BaseException:
                release = getattr(self.custody_resolver, "release_ingress_proof", None)
                if callable(release):
                    try:
                        release(getattr(proof, "proof_handle", ""))
                    except Exception:
                        pass
                close = getattr(proof, "close", None)
                if callable(close):
                    close()
                raise

    def capture_selected_ingress(
        self, proof_handle: str, root_observed_input_record: RootResourceSourceEventProof,
    ) -> RootResourceEventHandle:
        """Consume one retained custody proof and one sealed producer event.

        Producer-specific validation stays in the attached event issuer.  It
        receives the actual retained PIDFD/module proof, never a caller-supplied
        identity or ordinary ``HostContext``.
        """
        with self._lock:
            retained = self._ingress_proofs.pop(proof_handle, None)
            issuer = self._event_issuer
            capability = self._event_issuer_capability
            if (retained is None or issuer is None or capability is None
                    or not isinstance(root_observed_input_record, RootResourceSourceEventProof)):
                raise AuthorityDenied("resource.ingress", "root ingress proof or producer observation is unavailable")
        proof, role, enrollment, observer, backend = retained
        release = getattr(self.custody_resolver, "release_ingress_proof", None)
        try:
            if (proof_handle != proof.proof_handle
                    or root_observed_input_record.resource_id != enrollment.resource_id
                    or root_observed_input_record.resource_generation != enrollment.generation
                    or root_observed_input_record.source_observer_enrollment_id != observer.observer_enrollment_id
                    or root_observed_input_record.source_kind != observer.source_kind
                    or root_observed_input_record.source_kind not in enrollment.source_policy
                    or len(root_observed_input_record.payload) > enrollment.max_payload_bytes
                    or root_observed_input_record.raw_payload_sha256
                       != hashlib.sha256(root_observed_input_record.payload).hexdigest()
                    or root_observed_input_record.controller_proof_handle != proof_handle
                    or root_observed_input_record.capture_schema_id != _INGRESS_CAPTURE_SCHEMA_ID
                    or root_observed_input_record.capture_schema_sha256 != _INGRESS_CAPTURE_SCHEMA_SHA256
                    or self.selected_specs.get((enrollment.resource_id, enrollment.generation)) is None
                    or root_observed_input_record.issuer_token is not capability._token
                    or self.service.authority_epoch != self.authority_epoch
                    or self.service.service_generation_digest != self.service_generation_digest
                    or not callable(getattr(proof, "revalidate", None))
                    or proof.revalidate() is not True):
                raise AuthorityDenied("resource.ingress", "root ingress proof or selected source changed")
            capture = getattr(issuer, "capture_selected_ingress", None)
            if not callable(capture):
                raise AuthorityDenied("resource.ingress", "root source event issuer has no ingress capture callpoint")
            event_data = self.resolve_validated_source_event_data(
                root_observed_input_record, capability)
            try:
                issued = capture(proof, root_observed_input_record, capability)
            except Exception:
                raise AuthorityDenied("resource.ingress", "root source event capture failed") from None
            return self._finalize_issued_event(
                root_observed_input_record, issued, role,
                expected=(enrollment, observer, backend, proof), event_data=event_data,
            )
        finally:
            if callable(release):
                try:
                    release(proof_handle)
                except Exception:
                    pass
            close = getattr(proof, "close", None)
            if callable(close):
                close()

    def resolve_validated_source_event_data(
        self, proof: RootResourceSourceEventProof, capability: RootResourceEventIssuerCapability,
    ) -> Mapping[str, Any]:
        """Resolve schema-validated event fields from the exact retained issuer proof.

        This deliberately never reads event data from the producer DTO. The
        attached issuer must resolve and validate its own retained raw ingress
        record; only that immutable root result may feed event/body recipes.
        """
        if type(proof) is not RootResourceSourceEventProof:
            raise AuthorityDenied("resource.ingress", "root source proof is invalid")
        with self._lock:
            issuer = self._event_issuer
            if (issuer is None or capability is not self._event_issuer_capability
                    or proof.issuer_token is not capability._token):
                raise AuthorityDenied("resource.ingress", "root event issuer capability is invalid")
        enrollment = self.job_enrollments.get((proof.resource_id, proof.resource_generation))
        observer = getattr(self.source_observers, "observers", {}).get(
            proof.source_observer_enrollment_id)
        resolver = getattr(issuer, "resolve_validated_source_event_data", None)
        if (enrollment is None or observer is None
                or enrollment.selected_enabled is not True
                or proof.source_kind not in enrollment.source_policy
                or observer.source_kind != proof.source_kind
                or observer.capture_schema_id != _INGRESS_CAPTURE_SCHEMA_ID
                or proof.capture_schema_id != _INGRESS_CAPTURE_SCHEMA_ID
                or proof.capture_schema_sha256 != _INGRESS_CAPTURE_SCHEMA_SHA256
                or not callable(resolver)):
            raise AuthorityDenied("resource.ingress", "selected ingress schema or validator is unavailable")
        try:
            event_data = resolver(proof, capability)
        except Exception:
            raise AuthorityDenied("resource.ingress", "retained raw ingress did not validate") from None
        if (not isinstance(event_data, Mapping)
                or type(event_data) is dict):
            raise AuthorityDenied("resource.ingress", "source validator did not return immutable event fields")
        try:
            frozen = MappingProxyType(dict(event_data))
            encoded = json.dumps(dict(frozen), sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise AuthorityDenied("resource.ingress", "validated event fields are not bounded JSON") from None
        if len(encoded) > 1_048_576:
            raise AuthorityDenied("resource.ingress", "validated event fields exceed the selected bound")
        return frozen

    def _finalize_issued_event(
        self, producer_record: RootResourceSourceEventProof,
        issued: RootResourceIssuedSourceEvent,
        expected_role: RootControllerRoleEnrollment, *, expected: tuple[Any, Any, Any, Any],
        event_data: Mapping[str, Any] | None = None,
    ) -> RootResourceEventHandle:
        """Validate and retain one source event signed by the attached issuer."""
        if not isinstance(issued, RootResourceIssuedSourceEvent):
            raise AuthorityDenied("resource.event_issuer", "root source issuer returned an invalid event")
        if (issued.producer_handle != producer_record.producer_handle
                or issued.event_id != producer_record.event_id
                or issued.resource_id != producer_record.resource_id
                or issued.resource_generation != producer_record.resource_generation
                or issued.source_observer_enrollment_id != producer_record.source_observer_enrollment_id
                or issued.source_kind != producer_record.source_kind
                or issued.raw_observation_handle != producer_record.raw_observation_handle
                or issued.raw_payload != producer_record.payload
                or issued.raw_payload_sha256 != producer_record.raw_payload_sha256
                or issued.replay_key_sha256 != producer_record.replay_key_sha256
                or issued.observed_monotonic != producer_record.observed_monotonic
                or not isinstance(issued.event_data, Mapping)
                or event_data is None
                or dict(issued.event_data) != dict(event_data)):
            raise AuthorityDenied("resource.event_issuer", "signed source event differs from producer provenance")
        envelope = _validate_ingress_envelope(
            issued.payload, expected_kind={"schedule-event": "schedule-event",
                                           "webhook-event": "webhook-event",
                                           "native-input": "channel-event"}[issued.source_kind],
            expected_resource_id=issued.resource_id,
            expected_generation=issued.resource_generation,
            expected_profile_id=getattr(expected[0], "profile_id", ""),
            expected_controller_handle=producer_record.controller_proof_handle,
            expected_raw_handle=producer_record.raw_observation_handle,
            expected_raw_sha256=producer_record.raw_payload_sha256,
            expected_replay_sha256=producer_record.replay_key_sha256,
            expected_observed=producer_record.observed_monotonic,
            expected_event_data=event_data,
        )
        enrollment, observer, backend, controller_proof = expected
        from .types import HostContext, SourceReceipt
        if (not isinstance(issued.source_context, HostContext)
                or not isinstance(issued.receipt, SourceReceipt)
                or not isinstance(issued.parent_receipts, tuple)
                or issued.receipt not in issued.source_context.source_receipts
                or tuple(issued.source_context.source_receipts) != issued.parent_receipts):
            raise AuthorityDenied("resource.event_issuer", "issuer omitted the signed complete source closure")
        current_enrollment = self.job_enrollments.get((issued.resource_id, issued.resource_generation))
        current_observer = getattr(self.source_observers, "observers", {}).get(
            issued.source_observer_enrollment_id)
        if (current_enrollment is not enrollment or current_observer is not observer
                or current_enrollment.selected_enabled is not True
                or current_enrollment.generation != issued.resource_generation
                or issued.observer_enrollment_id != observer.observer_enrollment_id
                or observer.source_kind != issued.source_kind
                or observer.profile_id != enrollment.profile_id
                or observer.principal_id != enrollment.principal_id
                or observer.generation != enrollment.profile_generation
                or observer.channel_id != enrollment.source_issuer_channel_id
                or getattr(backend, "backend_id", None) not in expected_role.allowed_backend_enrollment_ids):
            raise AuthorityDenied("resource.event_issuer", "source event differs from current protected selection")
        expected_origin = f"{observer.origin_id}:{issued.event_id}"
        if (issued.receipt.source_kind != observer.source_kind
                or issued.receipt.origin_id != expected_origin
                or issued.receipt.payload_digest != hashlib.sha256(issued.payload).hexdigest()
                or issued.receipt.sensitivity is not Sensitivity.PRIVATE
                or issued.source_context.profile_id != enrollment.profile_id
                or issued.source_context.principal_id != enrollment.principal_id
                or issued.source_context.final_payload_digest != canonical_digest(issued.payload)
                or issued.source_context.generation != observer.generation
                or issued.source_context.enrollment_id != observer.enrollment_id
                or issued.receipt not in issued.parent_receipts
                or len({item.receipt_id for item in issued.parent_receipts}) != len(issued.parent_receipts)
                or issued.receipt.monotonic_expires_at <= self.service.monotonic()
                or issued.source_context.monotonic_expires_at <= self.service.monotonic()):
            raise AuthorityDenied("resource.event_issuer", "source receipt or signed context does not bind exact event")
        custody = issued.controller_proof
        try:
            # Initial ingress custody is the pre-event proof itself.  Do not
            # silently substitute an event-resolved PID or a second producer
            # callback after the source receipt has been minted.
            if (issued.controller_role_id != expected_role.id
                    or custody is not controller_proof
                    or getattr(custody, "controller_role_id", None) != expected_role.id
                    or getattr(custody, "service_generation_digest", None)
                    != self.service_generation_digest
                    or getattr(custody, "uid", None) != 0
                    or getattr(custody, "expires_monotonic", 0) > min(
                        issued.receipt.monotonic_expires_at,
                        issued.source_context.monotonic_expires_at)
                    or not callable(getattr(custody, "revalidate", None))
                    or custody.revalidate() is not True):
                raise AuthorityDenied("resource.event_issuer", "source ingress custody is stale or mismatched")
            handle = self._register_verified_event(
                resource_id=issued.resource_id,
                generation=issued.resource_generation,
                source_kind=issued.source_kind,
                source_observer_enrollment_id=issued.source_observer_enrollment_id,
                payload=issued.payload,
                parent_context=issued.source_context,
                parent_receipts=issued.parent_receipts,
                event_fields=envelope["event_data"],
                raw_payload=issued.raw_payload,
                raw_observation_handle=issued.raw_observation_handle,
                raw_payload_sha256=issued.raw_payload_sha256,
                replay_key_sha256=issued.replay_key_sha256,
                observed_monotonic=issued.observed_monotonic,
                _issuer=self._ingress_token,
            )
        finally:
            # The ingress caller owns cleanup here; capture_selected_ingress
            # releases the retained resolver handle after this finalizer.
            pass
        if handle.event_id != producer_record.event_id:
            self.cancel_event(handle)
            raise AuthorityDenied("resource.event_issuer", "root receipt event ID differs from producer proof")
        return handle

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

    def _select_source_role(self, enrollment: Any, observer_id: str,
                            source_kind: str) -> RootControllerRoleEnrollment:
        controller_kind = self._source_controller_kind(source_kind)
        operation = {"schedule-event": "resource.cron.run",
                     "webhook-event": "resource.webhook.run",
                     "native-input": "resource.channel.run"}[source_kind]
        backends = getattr(enrollment, "backends", {})
        if not isinstance(backends, Mapping) or not backends:
            backend = getattr(enrollment, "backend", None)
            backends = ({backend.backend_id: backend} if backend is not None else {})
        backend_ids = set(backends)
        matches = [role for role in self.roles.values()
                   if role.controller_kind == controller_kind
                   and observer_id in role.source_observer_enrollment_ids
                   and operation in role.allowed_operations
                   and backend_ids.intersection(role.allowed_backend_enrollment_ids)]
        if len(matches) != 1:
            raise AuthorityDenied("resource.controller", "source controller role is missing or ambiguous")
        return matches[0]

    def _profile_binding(self, enrollment: Any) -> Any:
        matches = [binding for binding in self.service.bindings_by_uid.values()
                   if binding.profile_id == enrollment.profile_id
                   and binding.principal_id == enrollment.principal_id]
        if len(matches) != 1:
            raise AuthorityDenied("resource.subject", "selected profile principal binding is missing or ambiguous")
        return matches[0]

    def attach_event_issuer(self, issuer: Any) -> RootResourceEventIssuerCapability:
        """Attach the sole root source-event issuer and return its private capability."""
        if issuer is None or not callable(getattr(issuer, "issue_source_event", None)):
            raise ValueError("typed root source-event issuer is required")
        with self._lock:
            if self._event_issuer is not None:
                raise AuthorityDenied("resource.event_issuer", "root source-event issuer is already attached")
            self._event_issuer = issuer
            capability = RootResourceEventIssuerCapability(object())
            self._event_issuer_capability = capability
            return capability

    def attach_resource_job_authority(self, authority: Any) -> None:
        """Attach the exact root durable job authority used for event admission/results."""
        with self._lock:
            if self._resource_job_authority is not None:
                raise AuthorityDenied("resource.admission", "resource job authority is already attached")
            if (authority is None
                    or not callable(getattr(authority, "is_root_admission_current", None))
                    or not callable(getattr(authority, "resolve_node_result_closure", None))
                    or not callable(getattr(authority, "resolve_node_result_values", None))):
                raise ValueError("typed root resource job authority is required")
            self._resource_job_authority = authority

    def bind_admitted_job(self, event_handle: RootResourceEventHandle, admission: Any) -> None:
        """Bind one exact durable root admission object to its retained event."""
        with self._lock:
            record = self._events.get(getattr(event_handle, "handle", ""))
            authority = self._resource_job_authority
            if (record is None or record.handle is not event_handle or authority is None
                    or not callable(getattr(authority, "is_root_admission_current", None))):
                raise AuthorityDenied("resource.admission", "root event or job authority is unavailable")
            if (getattr(admission, "resource_id", None) != event_handle.resource_id
                    or getattr(admission, "generation", None) != event_handle.resource_generation
                    or authority.is_root_admission_current(event_handle, admission) is not True
                    or event_handle.handle in self._event_admissions):
                raise AuthorityDenied("resource.admission", "admission is stale, mismatched, or already bound")
            self._event_admissions[event_handle.handle] = admission

    def resolve_retained_event(self, event_handle: RootResourceEventHandle) -> _RootEventRecord:
        """Return the exact live root event record to same-process authorities.

        The returned immutable row is not a worker DTO and cannot recreate an
        event: every caller must present the exact opaque handle object retained
        by this registry, and the service epoch/lease is checked on each lookup.
        """
        if not isinstance(event_handle, RootResourceEventHandle):
            raise AuthorityDenied("resource.event", "root event handle is invalid")
        with self._lock:
            self._prune_locked(self.service.monotonic())
            record = self._events.get(event_handle.handle)
            if (record is None or record.handle is not event_handle
                    or event_handle.authority_epoch != self.service.authority_epoch
                    or event_handle.expires_monotonic <= self.service.monotonic()):
                raise AuthorityDenied("resource.event", "root event record is stale or unknown")
            return record

    def register_issued_event(self, proof: RootResourceSourceEventProof, *,
                              issuer: Any) -> RootResourceEventHandle:
        """Consume a producer proof through the attached issuer and retain its signed event."""
        with self._lock:
            capability = self._event_issuer_capability
            if (issuer is not self._event_issuer or capability is None
                    or not isinstance(proof, RootResourceSourceEventProof)
                    or proof.issuer_token is not capability._token):
                raise AuthorityDenied("resource.event_issuer", "source event issuer or capability is invalid")
        enrollment = self.job_enrollments.get((proof.resource_id, proof.resource_generation))
        observer = getattr(self.source_observers, "observers", {}).get(
            proof.source_observer_enrollment_id)
        expected_source_kind = {"crons": "schedule-event", "webhooks": "webhook-event",
                                "channels": "native-input"}.get(
                                    getattr(enrollment, "kind", None))
        if (enrollment is None or enrollment.selected_enabled is not True
                or proof.source_kind != expected_source_kind
                or proof.source_kind not in enrollment.source_policy
                or len(proof.payload) > enrollment.max_payload_bytes
                or observer is None
                or observer.source_kind != proof.source_kind
                or observer.profile_id != enrollment.profile_id
                or observer.principal_id != enrollment.principal_id
                or observer.generation != enrollment.profile_generation
                or observer.channel_id != enrollment.source_issuer_channel_id
                or self.selected_specs.get((proof.resource_id, proof.resource_generation)) is None):
            raise AuthorityDenied("resource.event_issuer", "producer proof is outside active resource selection")
        expected_role = self._select_source_role(
            enrollment, proof.source_observer_enrollment_id, proof.source_kind)
        try:
            # The attached issuer consumes the producer proof exactly once
            # inside this call, validates its opaque provenance, then returns
            # the signed root context and complete source-receipt closure.
            issued = issuer.issue_source_event(proof, capability)
        except Exception:
            raise AuthorityDenied("resource.event_issuer", "root source event could not be signed") from None
        if not isinstance(issued, RootResourceIssuedSourceEvent):
            raise AuthorityDenied("resource.event_issuer", "root source issuer returned an invalid event")
        if (issued.producer_handle != proof.producer_handle
                or issued.event_id != proof.event_id
                or issued.resource_id != proof.resource_id
                or issued.resource_generation != proof.resource_generation
                or issued.source_observer_enrollment_id != proof.source_observer_enrollment_id
                or issued.source_kind != proof.source_kind
                or issued.payload != proof.payload):
            raise AuthorityDenied("resource.event_issuer", "signed source event differs from producer provenance")
        from .types import HostContext, SourceReceipt
        if (not isinstance(issued.source_context, HostContext)
                or not isinstance(issued.receipt, SourceReceipt)
                or not isinstance(issued.parent_receipts, tuple)
                or issued.receipt not in issued.source_context.source_receipts
                or tuple(issued.source_context.source_receipts) != issued.parent_receipts):
            raise AuthorityDenied("resource.event_issuer", "issuer omitted the signed complete source closure")
        enrollment = self.job_enrollments.get((issued.resource_id, issued.resource_generation))
        observer = getattr(self.source_observers, "observers", {}).get(
            issued.source_observer_enrollment_id)
        if (enrollment is None or observer is None
                or observer.observer_enrollment_id != issued.observer_enrollment_id
                or observer.source_kind != issued.source_kind
                or observer.profile_id != enrollment.profile_id
                or observer.principal_id != enrollment.principal_id
                or observer.generation != enrollment.profile_generation
                or observer.channel_id != enrollment.source_issuer_channel_id):
            raise AuthorityDenied("resource.event_issuer", "source event differs from current protected selection")
        role = self._select_source_role(
            enrollment, issued.source_observer_enrollment_id, issued.source_kind)
        if role != expected_role:
            raise AuthorityDenied("resource.event_issuer", "active source controller role changed during issuance")
        custody = issued.controller_proof
        try:
            from .root_controller_custody import RootControllerRoleCustody
            if (not isinstance(custody, RootControllerRoleCustody)
                    or issued.controller_role_id != role.id
                    or custody.row != role
                    or custody.generation_digest != self.service_generation_digest
                    or custody.expires_monotonic > min(
                        issued.receipt.monotonic_expires_at,
                        issued.source_context.monotonic_expires_at)
                    or custody.revalidate() is not True):
                raise AuthorityDenied("resource.event_issuer", "source producer custody is stale or mismatched")
            handle = self._register_verified_event(
                resource_id=issued.resource_id,
                generation=issued.resource_generation,
                source_kind=issued.source_kind,
                source_observer_enrollment_id=issued.source_observer_enrollment_id,
                payload=issued.payload,
                parent_context=issued.source_context,
                parent_receipts=issued.parent_receipts,
                _issuer=self._ingress_token,
            )
        finally:
            close = getattr(custody, "close", None)
            if callable(close):
                close()
        if handle.event_id != proof.event_id:
            self.cancel_event(handle)
            raise AuthorityDenied("resource.event_issuer", "root receipt event ID differs from producer proof")
        return handle

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

    def _register_verified_event(self, *, resource_id: str, generation: str,
                                source_kind: str, source_observer_enrollment_id: str,
                                payload: bytes,
                                parent_context: Any,
                                parent_receipts: tuple[Any, ...],
                                _issuer: object,
                                event_fields: Mapping[str, Any] | None = None,
                                raw_payload: bytes | None = None,
                                raw_observation_handle: str | None = None,
                                raw_payload_sha256: str | None = None,
                                replay_key_sha256: str | None = None,
                                observed_monotonic: float | None = None) -> RootResourceEventHandle:
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
                or len(payload) > 1_048_576
                or not isinstance(parent_receipts, tuple) or not parent_receipts or len(parent_receipts) > 64):
            raise AuthorityDenied("resource.event", "verified event does not join the active selected resource")
        if raw_payload is not None:
            if (not isinstance(raw_payload, bytes) or not 1 <= len(raw_payload) <= 1_048_576
                    or not isinstance(raw_observation_handle, str)
                    or not _OPAQUE_HANDLE.fullmatch(raw_observation_handle)
                    or raw_payload_sha256 != hashlib.sha256(raw_payload).hexdigest()
                    or not isinstance(replay_key_sha256, str)
                    or not _SHA256.fullmatch(replay_key_sha256)
                    or isinstance(observed_monotonic, bool)
                    or not isinstance(observed_monotonic, (int, float))
                    or not math.isfinite(observed_monotonic)
                    or observed_monotonic < 0):
                raise AuthorityDenied("resource.event", "root raw observation capsule is malformed")
        elif any(value is not None for value in (
                raw_observation_handle, raw_payload_sha256, replay_key_sha256, observed_monotonic)):
            raise AuthorityDenied("resource.event", "raw event capsule fields are incomplete")
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
        if event_fields is None:
            event_fields = _event_fields_from_payload(payload)
        elif not isinstance(event_fields, Mapping):
            raise AuthorityDenied("resource.event", "root event fields are not schema validated")
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
            replay_identity = ((resource_id, generation, replay_key_sha256)
                               if replay_key_sha256 is not None else None)
            if replay_identity is not None and replay_identity in self._replay_keys_seen:
                raise AuthorityDenied("resource.event_replay", "root source replay key was already admitted")
            retained_size = len(payload) + (len(raw_payload) if raw_payload is not None else 0)
            if (len(self._events) >= _MAX_ROOT_EVENT_COUNT
                    or self._event_bytes + retained_size > _MAX_ROOT_EVENT_BYTES):
                raise AuthorityDenied("resource.event_capacity", "bounded root event store is full")
            self._events[handle.handle] = _RootEventRecord(
                handle, parent_context, parent_receipts, bytes(payload), event_fields,
                dict(selected_spec), {}, raw_payload, raw_observation_handle,
                raw_payload_sha256, replay_key_sha256, observed_monotonic)
            self._event_ids_seen.add((resource_id, generation, event_id))
            if replay_identity is not None:
                self._replay_keys_seen.add(replay_identity)
            self._event_bytes += retained_size
        return handle

    def issue_resource_job_context(self, root_event_handle: RootResourceEventHandle,
                                   node_id: str, operation: str,
                                   canonical_payload_sha256: str, *,
                                   node_result_closure_handle: str | None = None) -> tuple[Any, Any]:
        """Ask AuthorityService to mint a fresh reduced child grant for a root event."""
        record, enrollment, node, backend = self._resolve_event_node(root_event_handle, node_id)
        with self._lock:
            admission = self._event_admissions.get(root_event_handle.handle)
            job_authority = self._resource_job_authority
        if (admission is None or job_authority is None
                or job_authority.is_root_admission_current(root_event_handle, admission) is not True):
            raise AuthorityDenied("resource.admission", "root event has no current durable job admission")
        node_result_closure = None
        if node.depends_on:
            if (not isinstance(node_result_closure_handle, str)
                    or _OPAQUE_HANDLE.fullmatch(node_result_closure_handle) is None):
                raise AuthorityDenied("resource.result_closure", "dependent node requires a root result closure")
            try:
                node_result_closure = job_authority.resolve_node_result_closure(
                    root_event_handle, admission, node_id)
            except Exception:
                raise AuthorityDenied("resource.result_closure", "root node result closure is unavailable") from None
            if getattr(node_result_closure, "closure_handle", None) != node_result_closure_handle:
                raise AuthorityDenied("resource.result_closure", "result closure handle does not match selected node")
            try:
                parent_results = job_authority.resolve_node_result_values(node_result_closure)
            except Exception:
                raise AuthorityDenied("resource.result_closure", "root node result values are stale") from None
        else:
            if node_result_closure_handle is not None:
                raise AuthorityDenied("resource.result_closure", "initial node cannot accept a result closure")
            parent_results = {}
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
                parent_results=parent_results,
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
            admission_handle=admission,
            node_result_closure_handle=node_result_closure_handle,
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
            admission = self._event_admissions.get(request.root_event.handle)
            job_authority = self._resource_job_authority
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
            if (admission is None or request.admission_handle is not admission
                    or job_authority is None
                    or job_authority.is_root_admission_current(request.root_event, admission) is not True):
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
            if node.depends_on:
                if not isinstance(request.node_result_closure_handle, str):
                    return None
                closure = job_authority.resolve_node_result_closure(
                    request.root_event, admission, node.node_id)
                if getattr(closure, "closure_handle", None) != request.node_result_closure_handle:
                    return None
                parent_result_fields = job_authority.resolve_node_result_values(closure)
            else:
                if request.node_result_closure_handle is not None:
                    return None
                parent_result_fields = {}
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
                backend=backend, role=role, controller_proof=request.controller,
                admission_handle=admission,
                node_result_closure=(closure if node.depends_on else None))
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
            self._replay_keys_seen.clear()
            self._event_admissions.clear()

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
            self._event_bytes = max(0, self._event_bytes - len(record.payload)
                                    - (len(record.raw_payload) if record.raw_payload is not None else 0))
        self._event_admissions.pop(key, None)
        self._used = {item for item in self._used if item[0] != key}
