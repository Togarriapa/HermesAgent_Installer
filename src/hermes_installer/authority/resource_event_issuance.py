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
from dataclasses import replace
from typing import Any, Callable

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


class _SourceProducerBinding:
    __slots__ = ("producer", "capability", "source_kind", "observer_id", "validator")

    def __init__(self, producer: object, capability: object, source_kind: str,
                 observer_id: str, validator: Callable[[object], bool]):
        self.producer, self.capability = producer, capability
        self.source_kind, self.observer_id, self.validator = source_kind, observer_id, validator


class ResourceEventContextIssuer:
    """Issue resource effect authority only for one registered root event/node.

    ``selected_generation`` and ``current_consent_revision`` are root-owned
    live readers.  They are required because immutable enrollment rows alone
    do not prove that the resource remains selected or consented at issuance.
    """

    def __init__(self, *, service: Any, controller_registry: Any,
                 selected_generation: Callable[[str], str],
                 current_consent_revision: Callable[[str], str],
                 monotonic: Callable[[], float] | None = None):
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
        self.monotonic = monotonic or service.monotonic
        self._producer_lock = __import__("threading").RLock()
        self._producer_bindings: dict[int, _SourceProducerBinding] = {}
        self._source_proofs: dict[int, tuple[RootResourceSourceEventProof, _SourceProducerBinding]] = {}
        try:
            self._registry_capability = controller_registry.attach_event_issuer(self)
        except Exception as exc:
            raise ValueError("root resource registry refused its sole event issuer") from exc

    def register_source_producer(self, producer: object, *, source_kind: str,
                                 observer_enrollment_id: str,
                                 validate_provenance: Callable[[object], bool]) -> object:
        """Root-assembly-only one-time binding for a concrete native source adapter."""
        if (producer is None or source_kind not in _SOURCE_KIND_BY_RESOURCE.values()
                or not isinstance(observer_enrollment_id, str) or not observer_enrollment_id
                or not callable(validate_provenance)):
            raise ValueError("an enrolled root source producer and validator are required")
        key = id(producer)
        with self._producer_lock:
            if key in self._producer_bindings:
                raise ValueError("source producer is already attached")
            capability = object()
            self._producer_bindings[key] = _SourceProducerBinding(
                producer, capability, source_kind, observer_enrollment_id,
                validate_provenance)
            return capability

    def mint_source_proof(self, capability: object, *, event_id: str,
                          resource_id: str, resource_generation: str,
                          source_observer_enrollment_id: str, payload: bytes,
                          provenance: object) -> RootResourceSourceEventProof:
        """Create an opaque one-use proof at a trusted producer's native seam."""
        with self._producer_lock:
            match = next((item for item in self._producer_bindings.values()
                          if item.capability is capability), None)
            if (match is None or source_observer_enrollment_id != match.observer_id
                    or not match.validator(provenance)):
                raise AuthorityDenied("resource.source", "native source producer rejected the observation")
            proof = RootResourceSourceEventProof(
                producer_handle="producer-" + secrets.token_urlsafe(24),
                event_id=event_id,
                resource_id=resource_id, resource_generation=resource_generation,
                source_observer_enrollment_id=source_observer_enrollment_id,
                source_kind=match.source_kind,
                payload=payload, verified_provenance=provenance,
                issuer_token=self._registry_capability._token,
            )
            self._source_proofs[id(proof)] = (proof, match)
            return proof

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
        if (retained is None or retained[0] is not proof
                or proof.issuer_token is not self._registry_capability._token
                or binding is None):
            raise AuthorityDenied("resource.source", "root source proof is stale or already consumed")
        producer_observer = getattr(binding.producer, "observer", None)
        consume = getattr(producer_observer, "consume", None)
        try:
            return self._capture_consumed_source(proof, binding, controller_proof)
        finally:
            if callable(consume):
                try:
                    consume(proof.verified_provenance)
                except Exception:
                    pass

    def _capture_consumed_source(self, proof: RootResourceSourceEventProof,
                                 binding: _SourceProducerBinding,
                                 controller_proof: Any) -> RootResourceIssuedSourceEvent:
        self._validate_initial_source(proof, binding)
        parent_context, role_proof, role, enrollment, observer = self._source_parent_context(
            proof, controller_proof)
        parent_receipts = self._resolve_parent_receipts(proof, binding, enrollment, parent_context)
        if parent_receipts:
            parent_context = replace(parent_context, source_receipts=parent_receipts,
                                     monotonic_expires_at=min(
                                         parent_context.monotonic_expires_at,
                                         *(item.monotonic_expires_at for item in parent_receipts)),
                                     signature="pending")
            parent_context = HostContext.from_wire(self.service._signed_context(
                parent_context, self.service._sign(parent_context.claims())))
        receipt = self.service.issue_source_receipt(
            parent_context, source_kind=proof.source_kind,
            origin_id=f"{observer.origin_id}:{proof.event_id}", payload=proof.payload,
            ttl_seconds=min(300, max(1, int(role_proof.expires_monotonic - self.monotonic()))),
        )
        complete_receipts = tuple(sorted((*parent_receipts, receipt),
                                         key=lambda item: item.receipt_id))
        event_context = replace(
            parent_context, source_receipts=complete_receipts,
            monotonic_expires_at=min(parent_context.monotonic_expires_at,
                                     receipt.monotonic_expires_at),
            nonce=secrets.token_urlsafe(24), grant_id=secrets.token_urlsafe(24),
            signature="pending", final_payload_digest=canonical_digest(proof.payload),
        )
        signed = self.service._signed_context(event_context,
                                             self.service._sign(event_context.claims()))
        source_context = HostContext.from_wire(signed)
        self.service._verify_context_signature(source_context)
        self.service._verify_source_receipt(receipt, self.controller_registry._profile_binding(enrollment))
        return RootResourceIssuedSourceEvent(
            source_context=source_context, receipt=receipt,
            parent_receipts=complete_receipts,
            producer_handle=proof.producer_handle, event_id=proof.event_id,
            resource_id=proof.resource_id,
            resource_generation=proof.resource_generation,
            source_observer_enrollment_id=proof.source_observer_enrollment_id,
            source_kind=proof.source_kind, controller_role_id=role.id,
            controller_proof=role_proof,
        )

    def _validate_initial_source(self, proof: RootResourceSourceEventProof,
                                 producer: _SourceProducerBinding) -> None:
        if (proof.issuer_token is not self._registry_capability._token
                or not isinstance(proof.payload, bytes) or not 1 <= len(proof.payload) <= _MAX_EVENT_BYTES
                or not all(isinstance(getattr(proof, name), str) and getattr(proof, name)
                           for name in ("event_id", "resource_id", "resource_generation",
                                        "producer_handle"))
                or proof.source_kind != producer.source_kind
                or proof.source_observer_enrollment_id != producer.observer_id
                or not producer.validator(proof.verified_provenance)):
            raise AuthorityDenied("resource.source", "source provenance or selected source bytes changed")
        self._require_canonical_event(proof.payload)

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
        if not callable(consume):
            return ()
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
                parent_results={
                    parent_node_id: fields
                    for parent_node_id, item in record.parent_results.items()
                    if isinstance(item, tuple) and len(item) == 2
                    for receipt_id, fields in (item,)
                    if receipt_id in {receipt.receipt_id for receipt in receipts}
                },
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
