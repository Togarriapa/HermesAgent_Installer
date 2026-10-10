"""Root-only issuance for selected Resources event effects (RB-T08).

The root event registry owns ingress provenance and the one-use request
capability.  This module consumes that capability, independently verifies the
signed source closure and current subject/effect bindings, then signs a fresh
reduced context and one-use effect grant with the active AuthorityService key.

No RPC or serializable proof is defined here.  Worker-provided labels,
``HostContext`` objects, receipts, timer values, HMAC results, and channel IDs
cannot enter this issuer.
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
import dataclasses
import re
from dataclasses import replace
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .types import AuthorityDenied, EffectAuthorization, HostContext, Sensitivity, canonical_digest
from .resource_source_controllers import (
    RootResourceIssuedSourceEvent, RootResourceSourceEventProof,
)

_SOURCE_KIND_BY_RESOURCE = {
    "crons": "schedule-event",
    "webhooks": "webhook-event",
    "channels": "native-input",
}
_MAX_EVENT_BYTES = 4 * 1024 * 1024
_MAX_RECEIPTS = 64
_INGRESS_CAPTURE_SCHEMA_ID = "resource-ingress-capture-v1"
_INGRESS_CAPTURE_SCHEMA_SHA256 = "0a0c8d71b58cbc04d65309003a65701b0dfb1e57a9931c5a96356f5c647609b1"
_MAX_CAPTURE_BYTES = 1_048_576
_RAW_OBSERVATION_SEAL = object()
_OPAQUE_ID = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_PROTOCOL_SCHEMAS = {
    "resource-cron-tick-v1": "7b7292435e8f3cd8010e1be3d678b0eabe6199b4a047782221e91073b02be53a",
    "resource-github-push-v1": "3b27135572adf4392f85b0f37a8dcce0e18dbac2aba811462416807c5e4733c8",
    "resource-registry-update-notice-v1": "01bdc4055a7675038feb5d61bbf36e345315543e3008d22e0e1c4815edb2c278",
    "channel-http-observed-event-v1": "7626756c12b9020248423114e0df294fc7c2c5c74def36e535244de81bd4452c",
    "channel-audio-observed-event-v1": "cfbd9c9a41299293776666201298e4cdf3be388e91ec7c8ff05d2931520965fb",
}


class _FrozenJSONDict(dict):
    """JSON-encoder-compatible nested immutable object for MappingProxy roots."""

    def __init__(self, values: Mapping[str, Any]):
        dict.__init__(self, values)

    def _deny(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("validated event data is immutable")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _deny


@dataclasses.dataclass(frozen=True, slots=True, init=False)
class RootValidatedRawObservation:
    """Private typed result returned by one selected root producer seam."""

    raw_observation_handle: str
    raw_payload: bytes = dataclasses.field(repr=False)
    event_id: str
    replay_key_sha256: str
    observed_monotonic: float
    event_data: Mapping[str, Any] = dataclasses.field(repr=False)
    _seal: object = dataclasses.field(repr=False, compare=False)

    @classmethod
    def _from_issuer(cls, seal: object, *, raw_observation_handle: str,
                     raw_payload: bytes, event_id: str, replay_key_sha256: str,
                     observed_monotonic: float, event_data: Mapping[str, Any]):
        if seal is not _RAW_OBSERVATION_SEAL:
            raise TypeError("root validated observations are issuer-created")
        value = object.__new__(cls)
        for name, item in (("raw_observation_handle", raw_observation_handle),
                           ("raw_payload", raw_payload), ("event_id", event_id),
                           ("replay_key_sha256", replay_key_sha256),
                           ("observed_monotonic", observed_monotonic),
                           ("event_data", event_data), ("_seal", seal)):
            object.__setattr__(value, name, item)
        value.__post_init__()
        return value

    def __post_init__(self) -> None:
        if (not isinstance(self.raw_observation_handle, str)
                or not _OPAQUE_ID.fullmatch(self.raw_observation_handle)
                or not isinstance(self.raw_payload, bytes)
                or not 1 <= len(self.raw_payload) <= _MAX_CAPTURE_BYTES
                or not isinstance(self.event_id, str) or not _OPAQUE_ID.fullmatch(self.event_id)
                or not isinstance(self.replay_key_sha256, str)
                or len(self.replay_key_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.replay_key_sha256)
                or isinstance(self.observed_monotonic, bool)
                or not isinstance(self.observed_monotonic, (int, float))
                or not math.isfinite(self.observed_monotonic)
                or self.observed_monotonic < 0
                or self._seal is not _RAW_OBSERVATION_SEAL
                or not isinstance(self.event_data, Mapping)
                or isinstance(self.event_data, dict)):
            raise ValueError("selected root raw observation is malformed")


class _SourceProducerBinding:
    __slots__ = ("producer", "capability", "source_kind", "observer_id",
                 "selected_binding", "protocol_schema_id", "protocol_schema_sha256")

    def __init__(self, producer: object, capability: object, source_kind: str,
                 observer_id: str,
                 selected_binding: object | None = None,
                 protocol_schema_id: str | None = None,
                 protocol_schema_sha256: str | None = None):
        self.producer, self.capability = producer, capability
        self.source_kind, self.observer_id = source_kind, observer_id
        self.selected_binding = selected_binding
        self.protocol_schema_id = protocol_schema_id
        self.protocol_schema_sha256 = protocol_schema_sha256


class ResourceEventContextIssuer:
    """Issue resource effect authority only for one registered root event/node.

    ``selected_generation`` and ``current_consent_revision`` are root-owned
    live readers.  They are required because immutable enrollment rows alone
    do not prove that the resource remains selected or consented at issuance.
    """

    def __init__(self, *, service: Any, controller_registry: Any,
                 selected_generation: Callable[[str], str],
                 current_consent_revision: Callable[[str], str],
                 monotonic: Callable[[], float] | None = None,
                 selected_protocol_schema: Callable[[str, str, str, str], tuple[str, str]] | None = None):
        from .service import AuthorityService
        from .resource_source_controllers import RootResourceControllerRegistry

        if not isinstance(service, AuthorityService):
            raise ValueError("active AuthorityService is required")
        if (not isinstance(controller_registry, RootResourceControllerRegistry)
                or controller_registry.service is not service):
            raise ValueError("the service-owned root resource controller registry is required")
        if not callable(selected_generation) or not callable(current_consent_revision):
            raise ValueError("live resource-selection and consent readers are required")
        self.service = service
        self.controller_registry = controller_registry
        self.selected_generation = selected_generation
        self.current_consent_revision = current_consent_revision
        if selected_protocol_schema is not None and not callable(selected_protocol_schema):
            raise ValueError("selected protocol schema resolver must be callable")
        self.selected_protocol_schema = selected_protocol_schema
        self.monotonic = monotonic or service.monotonic
        self._producer_lock = __import__("threading").RLock()
        self._producer_bindings: dict[int, _SourceProducerBinding] = {}
        self._source_proofs: dict[int, tuple[Any, ...]] = {}
        try:
            self._registry_capability = controller_registry.attach_event_issuer(self)
        except Exception as exc:
            raise ValueError("root resource registry refused its sole event issuer") from exc

    def prepare_source_parent_context(self, capability: object,
                                      controller_proof: Any, *,
                                      source_payload: bytes) -> HostContext:
        """Issue a short-lived parent context for a selected ingress receipt.

        The producer capability and live PIDFD custody proof are both required;
        no context claims, receipt fields, or payload digest are caller-selected;
        the exact bounded bytes are supplied by the root listener that owns the
        authenticated request/capture observation.
        """
        from .root_controller_custody import RootIngressControllerProof
        with self._producer_lock:
            producer = next((row for row in self._producer_bindings.values()
                             if row.capability is capability), None)
        if (producer is None or producer.selected_binding is None
                or not isinstance(source_payload, bytes)
                or not 1 <= len(source_payload) <= _MAX_CAPTURE_BYTES
                or type(controller_proof) is not RootIngressControllerProof
                or controller_proof._resolver is not self.controller_registry.custody_resolver
                or not self._is_retained_controller_proof(controller_proof)
                or controller_proof.revalidate() is not True):
            raise AuthorityDenied("resource.source", "selected ingress receipt authority is unavailable")
        selected = producer.selected_binding
        if (controller_proof.controller_role_id != selected.role.id
                or controller_proof.source_issuer_id != selected.source_issuer.issuer_channel_id
                or controller_proof.backend_enrollment_id != selected.backend.backend_id
                or controller_proof.resource_generation != selected.resource_generation
                or controller_proof.selected_ingress_binding_id != selected.selected_ingress_binding_id
                or controller_proof.authority_epoch != self.service.authority_epoch
                or controller_proof.service_generation_digest != self.service.service_generation_digest
                or controller_proof.expires_monotonic > selected.expires_monotonic):
            raise AuthorityDenied("resource.source", "selected ingress receipt binding changed")
        enrollment = self._selected_enrollment(selected, producer)
        internal_source = type("_SelectedSource", (), {})()
        internal_source.resource_id = enrollment.resource_id
        internal_source.resource_generation = enrollment.generation
        internal_source.event_id = "receipt-" + secrets.token_urlsafe(24)
        internal_source.producer_handle = "producer-" + secrets.token_urlsafe(24)
        internal_source.source_observer_enrollment_id = producer.observer_id
        internal_source.source_kind = producer.source_kind
        internal_source.payload = source_payload
        parent, _proof, _role, _enrollment, _observer = self._source_parent_context(
            internal_source, controller_proof)
        return parent

    def register_selected_source_producer(self, producer: object, *,
                                          selected_ingress_binding: Any) -> object:
        """Attach one concrete producer to a protected selected-ingress row.

        This path has no caller-supplied boolean validator.  The selected
        binding is a root resolver snapshot, and the producer must consume its
        own exact pending observation at the accepted transport/timer seam.
        """
        from .root_controller_custody import RootSelectedIngressBinding
        if (type(selected_ingress_binding) is not RootSelectedIngressBinding
                or not callable(getattr(producer, "consume_verified_raw_observation", None))):
            raise ValueError("a typed selected ingress binding and concrete producer are required")
        observer = selected_ingress_binding.source_observer
        source_kind = getattr(observer, "source_kind", None)
        observer_id = getattr(observer, "observer_enrollment_id", None)
        resource_id = selected_ingress_binding.backend.resource_id
        generation = selected_ingress_binding.resource_generation
        issuer_id = selected_ingress_binding.source_issuer.issuer_channel_id
        if source_kind == "schedule-event":
            protocol_schema_id = "resource-cron-tick-v1"
            protocol_schema_sha256 = _PROTOCOL_SCHEMAS[protocol_schema_id]
        elif self.selected_protocol_schema is not None:
            try:
                protocol_schema_id, protocol_schema_sha256 = self.selected_protocol_schema(
                    resource_id, generation, issuer_id, source_kind)
            except Exception:
                raise ValueError("selected protocol schema could not be resolved") from None
        else:
            protocol_schema_id = protocol_schema_sha256 = None
        expected_protocol = protocol_schema_id
        if (source_kind not in _SOURCE_KIND_BY_RESOURCE.values()
                or not isinstance(observer_id, str) or not observer_id
                or getattr(observer, "capture_schema_id", None) != _INGRESS_CAPTURE_SCHEMA_ID
                or getattr(selected_ingress_binding.source_issuer, "capture_schema_id", None)
                   != _INGRESS_CAPTURE_SCHEMA_ID
                or expected_protocol not in _PROTOCOL_SCHEMAS
                or protocol_schema_sha256 != _PROTOCOL_SCHEMAS[expected_protocol]):
            raise ValueError("selected ingress source kind or pinned protocol schema is unavailable")
        from .root_controller_custody import RootControllerRoleResolver
        selected_resolver = getattr(
            self.controller_registry.custody_resolver,
            "_selected_ingress_binding_resolver", None,
        )
        try:
            current_binding = selected_resolver(
                selected_ingress_binding.role.id,
                selected_ingress_binding.source_issuer.issuer_channel_id,
                selected_ingress_binding.backend.backend_id,
            ) if callable(selected_resolver) else None
        except Exception:
            current_binding = None
        if current_binding != selected_ingress_binding:
            raise ValueError("ingress binding is not the current root-selected row")
        RootControllerRoleResolver._ingress_join(
            selected_ingress_binding, selected_ingress_binding.role.id,
            selected_ingress_binding.source_issuer.issuer_channel_id,
            selected_ingress_binding.backend.backend_id)
        key = id(producer)
        with self._producer_lock:
            if key in self._producer_bindings:
                raise ValueError("source producer is already attached")
            capability = object()
            self._producer_bindings[key] = _SourceProducerBinding(
                producer, capability, source_kind, observer_id,
                selected_binding=selected_ingress_binding,
                protocol_schema_id=protocol_schema_id,
                protocol_schema_sha256=protocol_schema_sha256)
            return capability

    def mint_selected_source_proof(self, capability: object, *,
                                   controller_proof: Any,
                                   raw_observation: object) -> RootResourceSourceEventProof:
        """Consume a concrete producer observation and bind it to live custody."""
        from .root_controller_custody import RootIngressControllerProof
        with self._producer_lock:
            match = next((item for item in self._producer_bindings.values()
                          if item.capability is capability), None)
            if match is None or match.selected_binding is None:
                raise AuthorityDenied("resource.source", "selected source producer is not registered")
            selected = match.selected_binding
            if (type(controller_proof) is not RootIngressControllerProof
                    or controller_proof._resolver is not self.controller_registry.custody_resolver
                    or not self._is_retained_controller_proof(controller_proof)
                    or controller_proof.revalidate() is not True
                    or controller_proof.controller_role_id != selected.role.id
                    or controller_proof.source_issuer_id != selected.source_issuer.issuer_channel_id
                or controller_proof.backend_enrollment_id != selected.backend.backend_id
                or controller_proof.resource_generation != selected.resource_generation
                or controller_proof.service_generation_digest != selected.service_generation_digest
                or controller_proof.authority_epoch != selected.authority_epoch
                or controller_proof.expires_monotonic > selected.expires_monotonic
                or controller_proof.selected_ingress_binding_id != selected.selected_ingress_binding_id):
                raise AuthorityDenied("resource.controller", "selected ingress custody is stale or mismatched")
            enrollment = self._selected_enrollment(selected, match)
            consume = getattr(match.producer, "consume_verified_raw_observation", None)
            try:
                producer_record = consume(raw_observation, controller_proof)
            except Exception:
                raise AuthorityDenied("resource.source", "selected source observation was not verified") from None
            try:
                event_data = self._freeze_json(producer_record.event_data)
                observation = RootValidatedRawObservation._from_issuer(
                    _RAW_OBSERVATION_SEAL,
                    raw_observation_handle=producer_record.raw_observation_handle,
                    raw_payload=producer_record.raw_payload,
                    event_id=producer_record.event_id,
                    replay_key_sha256=producer_record.replay_key_sha256,
                    observed_monotonic=producer_record.observed_monotonic,
                    event_data=event_data,
                )
            except Exception:
                raise AuthorityDenied("resource.source", "producer returned malformed one-use evidence") from None
            self._validate_raw_observation(observation, controller_proof, selected, match)
            proof = RootResourceSourceEventProof(
                producer_handle="producer-" + secrets.token_urlsafe(24),
                event_id=observation.event_id,
                resource_id=enrollment.resource_id,
                resource_generation=enrollment.generation,
                source_observer_enrollment_id=match.observer_id,
                source_kind=match.source_kind,
                payload=observation.raw_payload,
                verified_provenance=raw_observation,
                issuer_token=self._registry_capability._token,
                raw_observation_handle=observation.raw_observation_handle,
                raw_payload_sha256=hashlib.sha256(observation.raw_payload).hexdigest(),
                replay_key_sha256=observation.replay_key_sha256,
                observed_monotonic=observation.observed_monotonic,
                controller_proof_handle=controller_proof.proof_handle,
                capture_schema_id=_INGRESS_CAPTURE_SCHEMA_ID,
                capture_schema_sha256=_INGRESS_CAPTURE_SCHEMA_SHA256,
            )
            self._source_proofs[id(proof)] = (proof, match, observation, controller_proof)
            return proof

    def _selected_enrollment(self, selected: Any, producer: _SourceProducerBinding) -> Any:
        backend = selected.backend
        enrollment = self.controller_registry.job_enrollments.get(
            (backend.resource_id, selected.resource_generation))
        if enrollment is None or enrollment.selected_enabled is not True:
            raise AuthorityDenied("resource.selection", "selected ingress resource is unavailable")
        if (enrollment.observer_enrollment_id != producer.observer_id
                or producer.source_kind not in enrollment.source_policy
                or _SOURCE_KIND_BY_RESOURCE.get(enrollment.kind) != producer.source_kind
                or enrollment.generation != selected.resource_generation
                or enrollment.profile_id != backend.profile_id
                or enrollment.principal_id != backend.principal_id):
            raise AuthorityDenied("resource.selection", "selected ingress enrollment changed")
        self._require_live_selection(enrollment)
        return enrollment

    def _is_retained_controller_proof(self, proof: Any) -> bool:
        rows = getattr(self.controller_registry.custody_resolver, "_ingress_proofs", {})
        retained = rows.get(getattr(proof, "proof_handle", None))
        return retained is not None and getattr(retained, "proof", None) is proof

    def _validate_raw_observation(self, observation: RootValidatedRawObservation,
                                  controller_proof: Any, selected: Any,
                                  producer: _SourceProducerBinding) -> None:
        payload = observation.raw_payload
        now = self.monotonic()
        if (not 1 <= len(payload) <= _MAX_CAPTURE_BYTES
                or not math.isfinite(now)
                or self._is_retained_controller_proof(controller_proof) is not True
                or controller_proof.revalidate() is not True
                or controller_proof.controller_role_id != selected.role.id
                or controller_proof.source_issuer_id != selected.source_issuer.issuer_channel_id
                or controller_proof.backend_enrollment_id != selected.backend.backend_id
                or controller_proof.resource_generation != selected.resource_generation
                or controller_proof.service_generation_digest != selected.service_generation_digest
                or controller_proof.authority_epoch != selected.authority_epoch
                or observation.observed_monotonic < controller_proof.issued_monotonic
                or observation.observed_monotonic > min(now, controller_proof.expires_monotonic)
                or len(observation.event_id) < 32
                or not observation.raw_observation_handle
                or not isinstance(observation.event_data, Mapping)
                or type(observation.event_data) is dict):
            raise AuthorityDenied("resource.source", "selected raw observation is malformed or stale")
        self._validate_json_value(observation.event_data)
        self._validate_protocol_event_data(observation, selected, producer)

    def _validate_protocol_event_data(self, observation: RootValidatedRawObservation,
                                      selected: Any, producer: _SourceProducerBinding) -> None:
        data = observation.event_data
        schema = producer.protocol_schema_id
        if producer.protocol_schema_sha256 != _PROTOCOL_SCHEMAS.get(schema):
            raise AuthorityDenied("resource.event", "selected protocol schema is not pinned")
        if schema != "resource-cron-tick-v1":
            resolver = self.selected_protocol_schema
            try:
                current_schema = resolver(
                    selected.backend.resource_id, selected.resource_generation,
                    selected.source_issuer.issuer_channel_id, producer.source_kind,
                ) if callable(resolver) else None
            except Exception:
                current_schema = None
            if current_schema != (schema, producer.protocol_schema_sha256):
                raise AuthorityDenied("resource.event", "selected protocol schema changed")
        if schema == "resource-cron-tick-v1":
            expected = {"schedule_enrollment_id", "scheduled_time_unix", "due_time_unix",
                        "fired_time_unix", "event_id", "occurrence_sequence",
                        "action_graph_sha256"}
            if (set(data) != expected
                    or data.get("event_id") != observation.event_id
                    or data.get("scheduled_time_unix") != data.get("due_time_unix")
                    or type(data.get("occurrence_sequence")) is not int
                    or data["occurrence_sequence"] < 1
                    or not re.fullmatch(r"[0-9a-f]{64}", str(data.get("action_graph_sha256", "")))
                    or any(type(data.get(name)) is not int or data[name] < 0
                           for name in ("scheduled_time_unix", "due_time_unix", "fired_time_unix"))):
                raise AuthorityDenied("resource.event", "cron tick differs from its selected schema")
            replay_key = canonical_digest({
                "resource_id": selected.backend.resource_id,
                "resource_generation": selected.resource_generation,
                "schedule_enrollment_id": data["schedule_enrollment_id"],
                "scheduled_time_unix": data["scheduled_time_unix"],
            })
            if replay_key != observation.replay_key_sha256:
                raise AuthorityDenied("resource.event", "cron occurrence replay key changed")
        elif schema == "resource-github-push-v1":
            repository = data.get("repository")
            selected_repo_id = getattr(selected.backend, "github_repository_id", None)
            selected_repo_name = getattr(selected.backend, "github_repository_full_name", None)
            if (not {"ref", "before", "after", "repository"} <= set(data)
                    or not isinstance(repository, Mapping)
                    or type(repository.get("id")) is not int or repository["id"] < 1
                    or not isinstance(repository.get("full_name"), str)
                    or not repository["full_name"]
                    or type(selected_repo_id) is not int
                    or selected_repo_id != repository["id"]
                    or selected_repo_name != repository["full_name"]):
                raise AuthorityDenied("resource.event", "GitHub push differs from its selected schema")
        elif schema == "resource-registry-update-notice-v1":
            selected_repository = getattr(selected.backend, "resources_repository", None)
            if (set(data) != {"repository", "branch", "commit"}
                    or data.get("branch") != "main"
                    or not isinstance(data.get("repository"), str)
                    or selected_repository != data.get("repository")
                    or not re.fullmatch(r"[0-9a-f]{40}", str(data.get("commit", "")))):
                raise AuthorityDenied("resource.event", "registry notice differs from its selected schema")
        elif schema == "channel-http-observed-event-v1":
            if (producer.source_kind != "native-input"
                    or set(data) != {"text", "session_id", "request_id", "subject_id",
                                     "raw_body_sha256", "raw_body_size_bytes"}
                    or not isinstance(data.get("text"), str)
                    or not 1 <= len(data["text"]) <= 65536
                    or any(not isinstance(data.get(name), str) or not 1 <= len(data[name]) <= 256
                           for name in ("session_id", "request_id", "subject_id"))
                    or not isinstance(data.get("raw_body_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", data["raw_body_sha256"])
                    or type(data.get("raw_body_size_bytes")) is not int
                    or not 1 <= data["raw_body_size_bytes"] <= 262144):
                raise AuthorityDenied("resource.event", "HTTP channel event differs from its selected schema")
            replay_key = canonical_digest({
                "session_id": data["session_id"], "request_id": data["request_id"],
                "body_sha256": data["raw_body_sha256"],
            })
            if replay_key != observation.replay_key_sha256:
                raise AuthorityDenied("resource.event", "HTTP request replay key changed")
        elif schema == "channel-audio-observed-event-v1":
            if (producer.source_kind != "native-input"
                    or set(data) != {"session_id", "capture_id", "audio_artifact_receipt_handle",
                                     "audio_sha256", "audio_size_bytes", "format",
                                     "sample_rate_hz", "duration_milliseconds"}
                    or any(not isinstance(data.get(name), str) or not 1 <= len(data[name]) <= 256
                           for name in ("session_id", "capture_id", "audio_artifact_receipt_handle"))
                    or not isinstance(data.get("audio_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", data["audio_sha256"])
                    or type(data.get("audio_size_bytes")) is not int
                    or not 1 <= data["audio_size_bytes"] <= 33554432
                    or data.get("format") != "pcm-s16le-mono"
                    or type(data.get("sample_rate_hz")) is not int or data["sample_rate_hz"] != 16000
                    or type(data.get("duration_milliseconds")) is not int
                    or not 1 <= data["duration_milliseconds"] <= 60000):
                raise AuthorityDenied("resource.event", "audio channel event differs from its selected schema")
            replay_key = canonical_digest({
                "session_id": data["session_id"], "capture_id": data["capture_id"],
                "audio_sha256": data["audio_sha256"],
            })
            if replay_key != observation.replay_key_sha256:
                raise AuthorityDenied("resource.event", "audio capture replay key changed")
        else:
            raise AuthorityDenied("resource.event", "selected protocol schema has no root validator")

    @classmethod
    def _validate_json_value(cls, value: Any, *, depth: int = 0, count: list[int] | None = None) -> None:
        if count is None:
            count = [0]
        if depth > 32:
            raise AuthorityDenied("resource.event", "event data exceeds the schema depth limit")
        if isinstance(value, Mapping):
            for key, item in value.items():
                count[0] += 1
                if count[0] > 4096 or not isinstance(key, str):
                    raise AuthorityDenied("resource.event", "event data exceeds schema limits")
                cls._validate_json_value(item, depth=depth + 1, count=count)
        elif isinstance(value, (tuple, list)):
            for item in value:
                count[0] += 1
                if count[0] > 4096:
                    raise AuthorityDenied("resource.event", "event data exceeds schema limits")
                cls._validate_json_value(item, depth=depth + 1, count=count)
        elif value is None or type(value) in (str, int, bool):
            return
        elif type(value) is float and math.isfinite(value):
            return
        else:
            raise AuthorityDenied("resource.event", "event data is not strict JSON")

    @classmethod
    def _freeze_json(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            # The outer object is a MappingProxy so the root registry can
            # distinguish it from caller dictionaries. Nested FrozenJSONDict
            # values stay JSON-encoder compatible while blocking mutation.
            nested = {key: cls._freeze_json(item) for key, item in value.items()}
            return MappingProxyType(nested)
        if isinstance(value, (tuple, list)):
            return tuple(cls._freeze_json(item) for item in value)
        return value

    def resolve_validated_source_event_data(
            self, proof: RootResourceSourceEventProof, capability: object) -> Mapping[str, Any]:
        """Resolve schema-approved fields from the exact retained root producer result."""
        if (type(proof) is not RootResourceSourceEventProof
                or capability is not self._registry_capability
                or proof.issuer_token is not self._registry_capability._token):
            raise AuthorityDenied("resource.source", "root event issuer capability is invalid")
        with self._producer_lock:
            retained = self._source_proofs.get(id(proof))
            if retained is None or retained[0] is not proof or len(retained) != 4:
                raise AuthorityDenied("resource.source", "raw source observation is stale or consumed")
            _, producer, observation, controller = retained
            self._validate_raw_observation(observation, controller, producer.selected_binding, producer)
            if (proof.payload != observation.raw_payload
                    or proof.raw_payload_sha256 != hashlib.sha256(observation.raw_payload).hexdigest()
                    or proof.raw_observation_handle != observation.raw_observation_handle
                    or proof.replay_key_sha256 != observation.replay_key_sha256
                    or proof.event_id != observation.event_id
                    or proof.controller_proof_handle != controller.proof_handle):
                raise AuthorityDenied("resource.source", "retained raw source observation changed")
            return observation.event_data

    def discard_source_proof(self, proof: RootResourceSourceEventProof) -> bool:
        """Drop only this issuer's exact unconsumed proof after custody setup fails.

        This is intentionally identity- and token-scoped. It cannot cancel a
        reconstructed dataclass or another producer's pending observation.
        Once capture begins, ``capture_selected_ingress`` consumes the proof.
        """
        if (type(proof) is not RootResourceSourceEventProof
                or proof.issuer_token is not self._registry_capability._token):
            return False
        with self._producer_lock:
            retained = self._source_proofs.get(id(proof))
            if retained is None or retained[0] is not proof:
                return False
            del self._source_proofs[id(proof)]
            producer = retained[1].producer
            release = getattr(producer, "release_verified_raw_observation", None)
            observer = getattr(producer, "observer", None)
        if callable(release):
            try:
                release(proof.verified_provenance)
            except Exception:
                pass
        else:
            consume = getattr(observer, "consume", None)
            if callable(consume):
                try:
                    consume(proof.verified_provenance)
                except Exception:
                    pass
        return True

    def issue_source_event(self, proof: RootResourceSourceEventProof,
                           registry_capability: object) -> RootResourceIssuedSourceEvent:
        """Reject pre-v36 issuance that lacks the registry's retained custody proof."""
        raise AuthorityDenied("resource.source", "initial ingress custody proof is required")

    def capture_selected_ingress(self, controller_proof: Any,
                                 root_observed_input_record: RootResourceSourceEventProof,
                                 registry_capability: object) -> RootResourceIssuedSourceEvent:
        """Consume source input together with registry-reserved live ingress custody."""
        from .resource_source_controllers import RootResourceEventIssuerCapability
        if (type(root_observed_input_record) is not RootResourceSourceEventProof
                or type(registry_capability) is not RootResourceEventIssuerCapability
                or registry_capability is not self._registry_capability):
            raise AuthorityDenied("resource.source", "root source proof or registry capability is invalid")
        with self._producer_lock:
            retained = self._source_proofs.pop(id(root_observed_input_record), None)
            binding = retained[1] if retained is not None else None
        proof = root_observed_input_record
        if (retained is None or len(retained) != 4 or retained[0] is not proof
                or proof.issuer_token is not self._registry_capability._token
                or binding is None or retained[3] is not controller_proof):
            raise AuthorityDenied("resource.source", "root source proof is stale or already consumed")
        producer_observer = getattr(binding.producer, "observer", None)
        consume = getattr(producer_observer, "consume", None)
        release = getattr(binding.producer, "release_verified_raw_observation", None)
        try:
            return self._capture_consumed_source(proof, binding, controller_proof, retained[2])
        finally:
            if callable(release):
                try:
                    release(proof.verified_provenance)
                except Exception:
                    pass
            elif callable(consume):
                try:
                    consume(proof.verified_provenance)
                except Exception:
                    pass

    def _capture_consumed_source(self, proof: RootResourceSourceEventProof,
                                 binding: _SourceProducerBinding,
                                 controller_proof: Any,
                                 observation: RootValidatedRawObservation) -> RootResourceIssuedSourceEvent:
        self._validate_raw_observation(observation, controller_proof, binding.selected_binding, binding)
        if (proof.payload != observation.raw_payload
                or proof.raw_payload_sha256 != hashlib.sha256(observation.raw_payload).hexdigest()
                or proof.raw_observation_handle != observation.raw_observation_handle
                or proof.replay_key_sha256 != observation.replay_key_sha256
                or proof.event_id != observation.event_id
                or proof.controller_proof_handle != controller_proof.proof_handle):
            raise AuthorityDenied("resource.source", "source raw observation binding changed")
        parent_context, role_proof, role, enrollment, observer = self._source_parent_context(
            proof, controller_proof)
        parent_receipts = self._resolve_parent_receipts(proof, binding, enrollment, parent_context)
        event_data = observation.event_data
        envelope = {
            "schema": 1,
            "kind": {"native-input": "channel-event", "schedule-event": "schedule-event",
                     "webhook-event": "webhook-event"}[proof.source_kind],
            "resource_id": enrollment.resource_id,
            "resource_generation": enrollment.generation,
            "profile_id": enrollment.profile_id,
            "controller_proof_handle": controller_proof.proof_handle,
            "raw_observation_handle": observation.raw_observation_handle,
            "raw_payload_sha256": hashlib.sha256(observation.raw_payload).hexdigest(),
            "event_data": self._thaw_json(event_data),
            "observed_monotonic": observation.observed_monotonic,
            "replay_key_sha256": observation.replay_key_sha256,
        }
        canonical_payload = json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(canonical_payload) > _MAX_CAPTURE_BYTES:
            raise AuthorityDenied("resource.event", "canonical event envelope exceeds selected limit")
        if parent_receipts:
            parent_context = replace(parent_context, source_receipts=parent_receipts,
                                     monotonic_expires_at=min(
                                         parent_context.monotonic_expires_at,
                                         *(item.monotonic_expires_at for item in parent_receipts)),
                                     signature="pending")
            parent_context = HostContext.from_wire(self.service._signed_context(
                parent_context, self.service._sign(parent_context.claims())))
        parent_context = replace(parent_context, final_payload_digest=canonical_digest(canonical_payload),
                                 signature="pending")
        parent_context = HostContext.from_wire(self.service._signed_context(
            parent_context, self.service._sign(parent_context.claims())))
        receipt = self.service.issue_source_receipt(
            parent_context, source_kind=proof.source_kind,
            origin_id=f"{observer.origin_id}:{proof.event_id}", payload=canonical_payload,
            ttl_seconds=min(300, max(1, int(role_proof.expires_monotonic - self.monotonic()))),
        )
        complete_receipts = tuple(sorted((*parent_receipts, receipt),
                                         key=lambda item: item.receipt_id))
        event_context = replace(
            parent_context, source_receipts=complete_receipts,
            monotonic_expires_at=min(parent_context.monotonic_expires_at,
                                     receipt.monotonic_expires_at),
            nonce=secrets.token_urlsafe(24), grant_id=secrets.token_urlsafe(24),
            signature="pending", final_payload_digest=canonical_digest(canonical_payload),
        )
        signed = self.service._signed_context(event_context,
                                             self.service._sign(event_context.claims()))
        source_context = HostContext.from_wire(signed)
        self.service._verify_context_signature(source_context)
        self.service._verify_source_receipt(receipt, self.controller_registry._profile_binding(enrollment))
        return RootResourceIssuedSourceEvent(
            source_context=source_context, receipt=receipt,
            parent_receipts=complete_receipts,
            payload=canonical_payload,
            producer_handle=proof.producer_handle, event_id=proof.event_id,
            resource_id=proof.resource_id,
            resource_generation=proof.resource_generation,
            source_observer_enrollment_id=proof.source_observer_enrollment_id,
            source_kind=proof.source_kind, controller_role_id=role.id,
            controller_proof=role_proof,
            raw_observation_handle=observation.raw_observation_handle,
            raw_payload=observation.raw_payload,
            raw_payload_sha256=hashlib.sha256(observation.raw_payload).hexdigest(),
            replay_key_sha256=observation.replay_key_sha256,
            observed_monotonic=observation.observed_monotonic,
            event_data=event_data,
        )

    @classmethod
    def _thaw_json(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {key: cls._thaw_json(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [cls._thaw_json(item) for item in value]
        return value

    def _resolve_parent_receipts(self, proof: RootResourceSourceEventProof,
                                 producer: _SourceProducerBinding,
                                 enrollment: Any, parent_context: HostContext) -> tuple[Any, ...]:
        """Resolve native proof receipt handles through its exact root observer.

        Receipt handles never enter the public event DTO. The registered adapter
        must expose its concrete root observer, which consumes those handles once
        and resolves them to real service-signed receipts.
        """
        observer = getattr(producer.producer, "observer", None)
        consume = getattr(observer, "consume_source_receipts", None)
        if getattr(producer, "protocol_schema_id", None) in {
                "channel-http-observed-event-v1", "channel-audio-observed-event-v1"}:
            # v94 HTTP JWT/session and audio consent/device/capture handles are
            # actual root-retained ingress proofs, not SourceReceipt DTOs. The
            # exact typed producer re-reads that same proof from its selected
            # observer at capture time; a valid first-ingress chain is empty.
            try:
                from hermes_installer.components.plugin_channel_provenance import (
                    AuthenticatedHttpIngressProducer, ObservedChannelIngress,
                    SelectedAudioIngressProducer,
                )
                if (type(producer.producer) not in {
                        AuthenticatedHttpIngressProducer, SelectedAudioIngressProducer}
                        or type(proof.verified_provenance) is not ObservedChannelIngress
                        or not callable(consume)):
                    raise ValueError("wrong producer proof type")
                producer.producer._validate(proof.verified_provenance.proof)
                receipts = consume(proof.verified_provenance)
            except Exception:
                raise AuthorityDenied(
                    "resource.source", "selected HTTP/audio root proof is stale or unavailable") from None
            if not isinstance(receipts, tuple):
                raise AuthorityDenied("resource.source", "native source receipt closure is malformed")
        elif not callable(consume):
            return ()
        else:
            try:
                receipts = consume(proof.verified_provenance)
            except Exception:
                raise AuthorityDenied("resource.source", "native source receipt closure is stale or unavailable") from None
        from .types import SourceReceipt
        if (not isinstance(receipts, tuple) or len(receipts) > _MAX_RECEIPTS
                or any(type(item) is not SourceReceipt for item in receipts)):
            raise AuthorityDenied("resource.source", "native source receipt closure is malformed")
        if not receipts:
            return ()
        by_id = {item.receipt_id: item for item in receipts}
        if len(by_id) != len(receipts):
            raise AuthorityDenied("resource.source", "native source receipt closure has duplicates")
        allowed_kinds = getattr(
            self.controller_registry.source_observers.observers.get(
                enrollment.observer_enrollment_id), "allowed_parent_source_kinds", frozenset())
        for receipt in receipts:
            try:
                self.service._verify_source_receipt(
                    receipt, self.controller_registry._profile_binding(enrollment))
            except Exception:
                raise AuthorityDenied("resource.source", "native source parent receipt signature is invalid") from None
            if (receipt.source_kind not in allowed_kinds
                    or receipt.profile_id != enrollment.profile_id
                    or receipt.principal_id != enrollment.principal_id
                    or receipt.namespace_id != parent_context.namespace_id
                    or receipt.uid != parent_context.uid
                    or receipt.process_generation != self.service.profile_generations.get(
                        enrollment.profile_id, "unversioned")
                    or receipt.monotonic_expires_at <= self.monotonic()):
                raise AuthorityDenied("resource.source", "native source parent receipt is outside the active selection")
            if any(parent_id not in by_id for parent_id in receipt.parent_receipt_ids):
                raise AuthorityDenied("resource.source", "native source parent receipt closure is incomplete")
        referenced = {parent_id for item in receipts for parent_id in item.parent_receipt_ids}
        reachable: set[str] = set()
        pending = list(set(by_id) - referenced)
        while pending:
            receipt_id = pending.pop()
            if receipt_id in reachable:
                continue
            row = by_id.get(receipt_id)
            if row is None:
                raise AuthorityDenied("resource.source", "native source parent closure is incomplete")
            reachable.add(receipt_id)
            pending.extend(row.parent_receipt_ids)
        if reachable != set(by_id):
            raise AuthorityDenied("resource.source", "native source parent closure contains unrelated receipts")
        return tuple(sorted(receipts, key=lambda item: item.receipt_id))

    def _source_parent_context(self, proof: RootResourceSourceEventProof,
                               controller_proof: Any) -> tuple[Any, Any, Any, Any, Any]:
        """Resolve selected enrollment and live controller role before first receipt mint."""
        registry = self.controller_registry
        enrollment = registry.job_enrollments.get((proof.resource_id, proof.resource_generation))
        observer = registry.source_observers.observers.get(proof.source_observer_enrollment_id)
        spec = registry.selected_specs.get((proof.resource_id, proof.resource_generation))
        if (enrollment is None or observer is None or spec is None
                or enrollment.selected_enabled is not True
                or enrollment.generation != proof.resource_generation
                or enrollment.observer_enrollment_id != proof.source_observer_enrollment_id
                or proof.source_kind not in enrollment.source_policy
                or _SOURCE_KIND_BY_RESOURCE.get(enrollment.kind) != proof.source_kind
                or enrollment.profile_id != observer.profile_id
                or enrollment.principal_id != observer.principal_id
                or enrollment.profile_generation != observer.generation
                or enrollment.source_issuer_channel_id != observer.channel_id
                or not isinstance(enrollment.consent_revision, str)
                or not enrollment.consent_revision):
            raise AuthorityDenied("resource.source", "resource source is not currently selected")
        self._require_live_selection(enrollment)
        binding = registry._profile_binding(enrollment)
        role = registry._select_source_role(
            enrollment, proof.source_observer_enrollment_id, proof.source_kind)
        role_proof = self._controller_custody_from_ingress_proof(controller_proof)
        from .root_controller_custody import (
            RootControllerProcessIdentity, RootControllerRoleResolver,
            RootIngressControllerProof,
        )
        if (type(role_proof) is not RootIngressControllerProof
                or role_proof._resolver is not registry.custody_resolver
                or type(role_proof.schema) is not int or role_proof.schema != 1
                or role_proof.controller_role_id != role.id
                or role_proof.controller_kind != role.controller_kind
                or role_proof.controller_generation != role.controller_generation
                or role_proof.source_issuer_id != enrollment.source_issuer_channel_id
                or role_proof.resource_generation != enrollment.generation
                or role_proof.backend_enrollment_id not in role.allowed_backend_enrollment_ids
                or role_proof.authority_epoch != self.service.authority_epoch
                or role_proof.service_generation_digest != self.service.service_generation_digest
                or role_proof.role_artifact_id != role.role_module_artifact_id
                or role_proof.role_artifact_sha256 != role.role_module_sha256
                or not isinstance(role_proof.namespace_id, str)
                or not role_proof.namespace_id
                or type(role_proof.live_peer_identity) is not RootControllerProcessIdentity
                or role_proof.live_peer_identity.pid != role_proof.pid
                or role_proof.live_peer_identity.uid != 0
                or role_proof.live_peer_identity.daemon_unit_id != role.daemon_unit_id
                or role_proof.live_peer_identity.executable_artifact_id != role.daemon_executable_artifact_id
                or role_proof.live_peer_identity.executable_sha256 != role.daemon_executable_sha256
                or role_proof.namespace_id != RootControllerRoleResolver._namespace_binding_id(
                    role_proof.live_peer_identity)
                or type(role_proof.uid) is not int or role_proof.uid != 0
                or type(role_proof.pid) is not int or role_proof.pid <= 0
                or type(role_proof.pidfd) is not int or role_proof.pidfd < 0
                or not role_proof.proof_handle or not role_proof.selected_ingress_binding_id
                or not callable(getattr(role_proof, "revalidate", None))
                or role_proof.revalidate() is not True
                or type(role_proof.issued_monotonic) not in (int, float)
                or not math.isfinite(role_proof.issued_monotonic)
                or type(role_proof.expires_monotonic) not in (int, float)
                or not math.isfinite(role_proof.expires_monotonic)
                or role_proof.issued_monotonic > self.monotonic()
                or role_proof.expires_monotonic <= self.monotonic()
                or role_proof.expires_monotonic > self.monotonic() + role.max_lease_seconds):
            raise AuthorityDenied("resource.controller", "root source controller custody is stale")
        now = self.monotonic()
        if not math.isfinite(now) or role_proof.expires_monotonic <= now:
            raise AuthorityDenied("resource.controller", "root source controller lease expired")
        expiry = min(now + role.max_lease_seconds, role_proof.expires_monotonic,
                     now + 300.0)
        parent = HostContext(
            principal_id=binding.principal_id, profile_id=binding.profile_id,
            namespace_id=binding.namespace_id, uid=binding.uid,
            purpose=f"resource-source:{proof.resource_id}"[:128],
            intent_id=canonical_digest({"resource_id": proof.resource_id,
                                        "event_id": proof.event_id,
                                        "payload_sha256": canonical_digest(proof.payload)}),
            trace_id=secrets.token_urlsafe(24), sensitivity=Sensitivity.PRIVATE,
            lineage_hash=canonical_digest({
                "source_kind": proof.source_kind, "producer": proof.producer_handle,
                "resource_id": proof.resource_id, "generation": proof.resource_generation,
                "observer": proof.source_observer_enrollment_id,
                "service_generation_digest": self.service.service_generation_digest,
            }), policy_revision=self.service._policy_revision(),
            capabilities=binding.capabilities, issued_at_monotonic=now,
            monotonic_expires_at=expiry, nonce=secrets.token_urlsafe(24),
            grant_id=secrets.token_urlsafe(24), signature="pending",
            final_payload_digest=canonical_digest(proof.payload),
            enrollment_id=canonical_digest({"uid": binding.uid,
                "principal_id": binding.principal_id, "profile_id": binding.profile_id,
                "namespace_id": binding.namespace_id,
                "generation": self.service.profile_generations.get(binding.profile_id, "unversioned"),
                "authority_epoch": self.service.authority_epoch}),
            generation=self.service.profile_generations.get(binding.profile_id, "unversioned"),
            operation="resource.job.admit",
            native_process_identity=(f"{role.daemon_unit_id}:{role_proof.pid}:"
                                     f"{role_proof.live_peer_identity.start_time_ticks}:"
                                     f"{role.daemon_executable_sha256}:{role_proof.role_artifact_sha256}:"
                                     f"{role_proof.namespace_id}"),
        )
        parent = HostContext.from_wire(self.service._signed_context(parent,
                                         self.service._sign(parent.claims())))
        return parent, role_proof, role, enrollment, observer

    def _controller_custody_from_ingress_proof(self, ingress_proof: Any) -> Any:
        """Extract only the registry-retained custody object behind v36 proof."""
        from .root_controller_custody import RootIngressControllerProof
        if type(ingress_proof) is not RootIngressControllerProof:
            raise AuthorityDenied("resource.controller", "selected ingress proof type is invalid")
        return ingress_proof

    def issue(self, request: Any) -> tuple[HostContext, EffectAuthorization]:
        """Consume one registry-minted request and sign its exact selected effect."""
        from .resource_source_controllers import RootResourceJobContextRequest

        if type(request) is not RootResourceJobContextRequest:
            raise AuthorityDenied("resource.context", "only the root registry request type is accepted")
        registry = self.controller_registry
        # Atomically consumes the registry's per-instance request capability.
        # The returned reservation contains the exact retained event and the
        # root-created controller DTO; a reconstructed dataclass is rejected.
        try:
            reservation = registry.consume_context_request(request)
        except Exception:
            raise AuthorityDenied("resource.context", "root event request is stale or already consumed") from None
        if reservation is None or getattr(reservation, "request", None) is not request:
            raise AuthorityDenied("resource.context", "root event request capability is invalid")

        controller = reservation.controller_proof
        return self._issue_reserved(request, reservation, controller)

    def _issue_reserved(self, request: Any, reservation: Any,
                        controller: Any) -> tuple[HostContext, EffectAuthorization]:
        service = self.service
        registry = self.controller_registry
        record = reservation.record
        enrollment = reservation.enrollment
        node = reservation.node
        backend = reservation.backend
        role = reservation.role
        event = record.handle
        now = self.monotonic()

        if (service.authority_epoch != request.authority_epoch
                or service.service_generation_digest != request.service_generation_digest
                or registry.authority_epoch != service.authority_epoch
                or registry.service_generation_digest != service.service_generation_digest
                or event.authority_epoch != service.authority_epoch
                or controller.service_generation_digest != service.service_generation_digest
                or not math.isfinite(now) or event.expires_monotonic <= now):
            raise AuthorityDenied("resource.context", "root event authority epoch or lease is stale")
        if (request.root_event is not event or request.resource_enrollment is not enrollment
                or request.node is not node or request.backend is not backend
                or request.controller is not controller
                or request.operation != node.effect or request.operation != backend.operation
                or node.target != backend.target_id or node.recipient != backend.recipient
                or node.action_id not in enrollment.approved_action_ids
                or node.action_id not in backend.approved_action_ids
                or node.backend_enrollment_id != backend.backend_id
                or enrollment.selected_enabled is not True
                or event.resource_id != enrollment.resource_id
                or event.resource_generation != enrollment.generation
                or event.source_observer_enrollment_id != enrollment.observer_enrollment_id
                or event.source_kind not in enrollment.source_policy
                or _SOURCE_KIND_BY_RESOURCE.get(enrollment.kind) != event.source_kind):
            raise AuthorityDenied("resource.context", "event, node, backend, or source selection changed")

        self._require_live_selection(enrollment)
        binding = registry._profile_binding(enrollment)
        if (binding.profile_id != enrollment.profile_id
                or binding.principal_id != enrollment.principal_id
                or binding.namespace_id != controller.subject_namespace_id
                or binding.principal_id != controller.subject_principal_id
                or binding.profile_id != controller.subject_profile_id
                or service.profile_generations.get(binding.profile_id) != enrollment.profile_generation
                or controller.controller_kind != registry._source_controller_kind(event.source_kind)
                or controller.controller_generation != role.controller_generation
                or controller.controller_role_artifact_id != role.role_module_artifact_id
                or controller.controller_role_sha256 != role.role_module_sha256
                or controller.expires_monotonic <= now
                or controller.expires_monotonic > event.expires_monotonic):
            raise AuthorityDenied("resource.context", "root controller or subject profile binding changed")

        self._revalidate_controller(event, request.node.node_id, role, controller)
        context, receipts = self._verify_source_closure(record, enrollment, binding, now)
        job_authority = getattr(service, "resource_job_authority", None)
        admission = reservation.admission_handle
        current_admission = getattr(job_authority, "is_root_admission_current", None)
        if (job_authority is None or admission is None or admission is not request.admission_handle
                or not callable(current_admission)
                or current_admission(event, admission) is not True):
            raise AuthorityDenied("resource.admission", "current root job admission is unavailable")
        if node.depends_on:
            if not isinstance(request.node_result_closure_handle, str):
                raise AuthorityDenied("resource.result_closure", "dependent node lacks its root result closure")
            resolve_closure = getattr(job_authority, "resolve_node_result_closure", None)
            resolve_values = getattr(job_authority, "resolve_node_result_values", None)
            if not callable(resolve_closure) or not callable(resolve_values):
                raise AuthorityDenied("resource.result_closure", "root result closure resolver is unavailable")
            try:
                result_closure = resolve_closure(event, admission, node.node_id)
                parent_results = resolve_values(result_closure)
            except Exception:
                raise AuthorityDenied("resource.result_closure", "root result closure is stale or incomplete") from None
            if (result_closure is not reservation.node_result_closure
                    or getattr(result_closure, "closure_handle", None)
                       != request.node_result_closure_handle
                    or getattr(result_closure, "event_handle", None) != event.handle
                    or getattr(result_closure, "node_id", None) != node.node_id
                    or not isinstance(parent_results, Mapping)
                    or set(parent_results) != set(node.depends_on)):
                raise AuthorityDenied("resource.result_closure", "result closure does not match selected DAG parents")
            result_closure_digest = getattr(result_closure, "parent_closure_digest", None)
            if not isinstance(result_closure_digest, str) or len(result_closure_digest) != 64:
                raise AuthorityDenied("resource.result_closure", "result closure digest is malformed")
        else:
            if (request.node_result_closure_handle is not None
                    or reservation.node_result_closure is not None):
                raise AuthorityDenied("resource.result_closure", "initial DAG node carries unexpected result authority")
            parent_results = {}
            result_closure_digest = canonical_digest([])
        payload = record.payload
        if (not isinstance(payload, bytes) or not 1 <= len(payload) <= _MAX_EVENT_BYTES
                or hashlib.sha256(payload).hexdigest() != event.payload_sha256
                or canonical_digest(payload) != event.payload_sha256
                or canonical_digest(sorted((item.receipt_id, canonical_digest(item.claims()))
                                           for item in receipts)) != event.parent_closure_digest):
            raise AuthorityDenied("resource.context", "retained event bytes or signed source closure changed")
        self._require_canonical_event(payload)

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
            raise AuthorityDenied("resource.context", "selected body recipe no longer resolves") from None
        digest = canonical_digest(body)
        if (digest != request.canonical_payload_sha256
                or len(body) > backend.maximum_request_bytes):
            raise AuthorityDenied("resource.context", "canonical effect bytes differ from the selected recipe")

        rule = service.rules.get(("hermes-resource-runtime", node.effect, node.target))
        if (rule is None or (rule.operation, rule.target) not in service.handlers
                or rule.recipient != node.recipient
                or node.effect != request.operation
                or node.target != backend.target_id):
            raise AuthorityDenied("resource.context", "selected resource effect route is unavailable")

        # Parent receipts are consumed once at source admission.  Every child
        # effect gets a fresh one-use grant whose signed lineage commits the
        # complete verified closure, so a DAG cannot replay source receipts.
        lineage = canonical_digest({
            "parent_lineage_hash": context.lineage_hash,
            "source_closure": sorted((item.receipt_id, canonical_digest(item.claims()))
                                      for item in receipts),
            "event_handle": event.handle,
            "event_payload_sha256": event.payload_sha256,
            "event_parent_closure_digest": event.parent_closure_digest,
            "result_closure_digest": result_closure_digest,
            "result_closure_handle": request.node_result_closure_handle,
            "resource_id": enrollment.resource_id,
            "resource_generation": enrollment.generation,
            "consent_revision": enrollment.consent_revision,
            "approved_dag_sha256": reservation.record.selected_spec.get("approved_dag_sha256"),
            "node_id": node.node_id,
            "action_id": node.action_id,
            "backend_id": backend.backend_id,
            "backend_sha256": backend.handler_sha256,
            "scope_binding_id": backend.scope_binding_id,
            "operation": node.effect,
            "target": node.target,
            "recipient": node.recipient,
            "canonical_payload_sha256": digest,
            "service_generation_digest": service.service_generation_digest,
        })
        source_order = (Sensitivity.PUBLIC, Sensitivity.PRIVATE,
                        Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN)
        sensitivity = max((context.sensitivity, *(item.sensitivity for item in receipts)),
                          key=source_order.index)
        expiry = min(
            event.expires_monotonic, controller.expires_monotonic,
            context.monotonic_expires_at,
            *(item.monotonic_expires_at for item in receipts),
            now + float(role.max_lease_seconds),
        )
        if expiry <= now:
            raise AuthorityDenied("resource.context", "source or controller lease expired before issuance")
        generation = service.profile_generations[binding.profile_id]
        intent_id = canonical_digest({
            "event_id": event.event_id, "resource_id": enrollment.resource_id,
            "resource_generation": enrollment.generation, "node_id": node.node_id,
            "operation": node.effect, "payload_sha256": digest,
        })
        fresh = HostContext(
            principal_id=binding.principal_id, profile_id=binding.profile_id,
            namespace_id=binding.namespace_id, uid=binding.uid,
            purpose=f"resource-event:{enrollment.resource_id}:{node.action_id}"[:128],
            intent_id=intent_id, trace_id=secrets.token_urlsafe(24),
            sensitivity=sensitivity, lineage_hash=lineage,
            policy_revision=service._policy_revision(), capabilities=binding.capabilities,
            issued_at_monotonic=now, monotonic_expires_at=expiry,
            nonce=secrets.token_urlsafe(24), grant_id=secrets.token_urlsafe(24),
            signature="pending", source_receipts=(), final_payload_digest=digest,
            enrollment_id=canonical_digest({
                "uid": binding.uid, "principal_id": binding.principal_id,
                "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
                "generation": generation, "authority_epoch": service.authority_epoch,
            }), generation=generation, operation=node.effect,
            native_process_identity=None,
        )
        signed_wire = service._signed_context(fresh, service._sign(fresh.claims()))
        grant_wire = service._authorize_effect(binding.uid, {
            "context": signed_wire, "capability": rule.capability,
            "target": rule.target, "recipient": rule.recipient,
            "request_digest": digest, "retry_index": 0,
        })
        signed_context = HostContext.from_wire(signed_wire)
        grant = EffectAuthorization.from_wire(grant_wire)
        service._verify_context_signature(signed_context)
        service._verify_grant_signature(grant)
        service._assert_current_context(signed_context, binding, binding.uid)
        from .service import _context_digest
        if (grant.context_digest != _context_digest(signed_context)
                or grant.request_digest != digest or grant.operation != node.effect
                or grant.target != node.target or grant.recipient != node.recipient
                or grant.source_receipts or signed_context.source_receipts):
            raise AuthorityDenied("resource.context", "service returned a mismatched root effect grant")
        return signed_context, grant

    def _require_live_selection(self, enrollment: Any) -> None:
        try:
            selected = self.selected_generation(enrollment.resource_id)
            consent = self.current_consent_revision(enrollment.resource_id)
        except Exception:
            raise AuthorityDenied("resource.selection", "current resource selection or consent is unavailable") from None
        if selected != enrollment.generation or consent != enrollment.consent_revision:
            raise AuthorityDenied("resource.selection", "resource selection or consent revision changed")

    def _verify_source_closure(self, record: Any, enrollment: Any,
                               binding: Any, now: float) -> tuple[HostContext, tuple[Any, ...]]:
        service = self.service
        context = record.parent_context
        receipts = record.parent_receipts
        if (not isinstance(context, HostContext) or not isinstance(receipts, tuple)
                or not 1 <= len(receipts) <= _MAX_RECEIPTS
                or context.source_receipts != receipts
                or context.profile_id != enrollment.profile_id
                or context.principal_id != enrollment.principal_id
                or context.uid != binding.uid or context.namespace_id != binding.namespace_id):
            raise AuthorityDenied("resource.source", "root event source context or complete closure is invalid")
        try:
            service._verify_context_signature(context)
            service._assert_current_context(context, binding, binding.uid)
            for receipt in receipts:
                service._verify_source_receipt(receipt, binding)
        except Exception:
            raise AuthorityDenied("resource.source", "source context or receipt signature is stale") from None
        receipt_by_id = {item.receipt_id: item for item in receipts}
        if len(receipt_by_id) != len(receipts):
            raise AuthorityDenied("resource.source", "source closure contains duplicate receipts")
        source_kind = _SOURCE_KIND_BY_RESOURCE.get(enrollment.kind)
        observer = self.controller_registry.source_observers.observers.get(
            enrollment.observer_enrollment_id)
        expected_origin = f"{observer.origin_id}:{record.handle.event_id}" if observer else ""
        primary = [item for item in receipts
                   if item.source_kind == source_kind and item.origin_id == expected_origin
                   and item.payload_digest == canonical_digest(record.payload)]
        if (len(primary) != 1 or primary[0].receipt_id not in record.handle.source_receipt_ids
                or tuple(sorted(receipt_by_id)) != tuple(sorted(record.handle.source_receipt_ids))):
            raise AuthorityDenied("resource.source", "event receipt does not bind the selected source bytes")
        if any(item.source_kind not in observer.allowed_parent_source_kinds
               for item in receipts if item.receipt_id != primary[0].receipt_id):
            raise AuthorityDenied("resource.source", "source parent kind is outside the selected observer closure")
        reachable: set[str] = set()
        pending = [primary[0].receipt_id]
        while pending:
            receipt_id = pending.pop()
            if receipt_id in reachable:
                continue
            receipt = receipt_by_id.get(receipt_id)
            if receipt is None:
                raise AuthorityDenied("resource.source", "source parent closure is incomplete")
            reachable.add(receipt_id)
            pending.extend(receipt.parent_receipt_ids)
        if reachable != set(receipt_by_id):
            raise AuthorityDenied("resource.source", "source closure contains unrelated receipts")
        if (any(item.monotonic_expires_at <= now for item in receipts)
                or context.monotonic_expires_at <= now
                or min(item.monotonic_expires_at for item in receipts) < record.handle.expires_monotonic):
            raise AuthorityDenied("resource.source", "source closure lease is expired or inconsistent")
        return context, receipts

    def _revalidate_controller(self, event: Any, node_id: str,
                               role: Any, controller: Any) -> None:
        resolver = self.controller_registry.custody_resolver
        proof = None
        try:
            proof = resolver.resolve_for_event(event.handle, node_id)
            revalidate = getattr(proof, "revalidate", None)
            if (proof is None or getattr(proof, "row", None) != role
                    or getattr(proof, "generation_digest", None) != self.service.service_generation_digest
                    or not callable(revalidate) or revalidate() is not True
                    or proof.pid != controller.pid or proof.uid != controller.uid
                    or proof.identity != controller.identity):
                raise AuthorityDenied("resource.controller", "live root controller changed before issuance")
            loaded = getattr(proof, "loaded_role_proof", None)
            if loaded is None and not getattr(proof, "loaded_role_verified", False):
                raise AuthorityDenied("resource.controller", "loaded root role proof is unavailable")
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("resource.controller", "live root controller is unavailable") from None
        finally:
            close = getattr(proof, "close", None)
            if callable(close):
                close()

    @staticmethod
    def _require_canonical_event(payload: bytes) -> None:
        def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result
        try:
            parsed = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_pairs,
                                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
            canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            raise AuthorityDenied("resource.event", "event bytes are not strict JSON") from None
        if not isinstance(parsed, dict) or canonical != payload:
            raise AuthorityDenied("resource.event", "event bytes are not canonical selected JSON")
