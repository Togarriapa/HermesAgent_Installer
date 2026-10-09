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
    __slots__ = ("producer", "capability", "source_kind", "observer_id", "validator",
                 "resolve_controller")

    def __init__(self, producer: object, capability: object, source_kind: str,
                 observer_id: str, validator: Callable[[object], bool],
                 resolve_controller: Callable[..., Any]):
        self.producer, self.capability = producer, capability
        self.source_kind, self.observer_id, self.validator = source_kind, observer_id, validator
        self.resolve_controller = resolve_controller


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
                                 validate_provenance: Callable[[object], bool],
                                 resolve_controller: Callable[..., Any]) -> object:
        """Root-assembly-only one-time binding for a concrete native source adapter."""
        if (producer is None or source_kind not in _SOURCE_KIND_BY_RESOURCE.values()
                or not isinstance(observer_enrollment_id, str) or not observer_enrollment_id
                or not callable(validate_provenance) or not callable(resolve_controller)):
            raise ValueError("an enrolled root source producer, validator, and custody resolver are required")
        key = id(producer)
        with self._producer_lock:
            if key in self._producer_bindings:
                raise ValueError("source producer is already attached")
            capability = object()
            self._producer_bindings[key] = _SourceProducerBinding(
                producer, capability, source_kind, observer_enrollment_id,
                validate_provenance, resolve_controller)
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
        """Consume producer evidence and mint original source context and receipt.

        The registry capability is checked by the attached root registry before
        it calls this method; producer proof identity and validation are checked
        here.  The registry subsequently verifies the complete signed closure.
        """
        from .resource_source_controllers import RootResourceEventIssuerCapability
        if (type(proof) is not RootResourceSourceEventProof
                or type(registry_capability) is not RootResourceEventIssuerCapability
                or registry_capability is not self._registry_capability):
            raise AuthorityDenied("resource.source", "root source proof type is invalid")
        with self._producer_lock:
            retained = self._source_proofs.pop(id(proof), None)
            binding = retained[1] if retained is not None else None
        if (retained is None or retained[0] is not proof
                or proof.issuer_token is not self._registry_capability._token
                or binding is None):
            raise AuthorityDenied("resource.source", "root source proof is stale or already consumed")
        self._validate_initial_source(proof, binding)
        parent_context, role_proof, role, enrollment, observer = self._source_parent_context(proof, binding)
        try:
            receipt = self.service.issue_source_receipt(
                parent_context, source_kind=proof.source_kind,
                origin_id=f"{observer.origin_id}:{proof.event_id}", payload=proof.payload,
                ttl_seconds=min(300, max(1, int(role_proof.expires_monotonic - self.monotonic()))),
            )
            event_context = replace(
                parent_context, source_receipts=(receipt,),
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
                parent_receipts=(receipt,), payload=proof.payload,
                producer_handle=proof.producer_handle, event_id=proof.event_id,
                resource_id=proof.resource_id,
                resource_generation=proof.resource_generation,
                source_observer_enrollment_id=proof.source_observer_enrollment_id,
                source_kind=proof.source_kind, controller_role_id=role.id,
                controller_proof=role_proof,
            )
        except BaseException:
            role_proof.close()
            raise

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

    def _source_parent_context(self, proof: RootResourceSourceEventProof,
                               producer: _SourceProducerBinding) -> tuple[Any, Any, Any, Any]:
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
        try:
            role_proof = producer.resolve_controller(role, enrollment, observer, spec)
        except Exception:
            raise AuthorityDenied("resource.controller", "root source controller custody is unavailable") from None
        from .root_controller_custody import RootControllerRoleCustody
        if (type(role_proof) is not RootControllerRoleCustody
                or getattr(role_proof, "row", None) != role
                or getattr(role_proof, "generation_digest", None) != self.service.service_generation_digest
                or getattr(role_proof, "loaded_role_proof", None) is None
                or getattr(getattr(role_proof, "identity", None), "daemon_unit_id", None)
                != role.daemon_unit_id
                or not callable(getattr(role_proof, "revalidate", None))
                or role_proof.revalidate() is not True
                or getattr(role_proof, "uid", None) != 0):
            close = getattr(role_proof, "close", None)
            if callable(close): close()
            raise AuthorityDenied("resource.controller", "root source controller custody is stale")
        now = self.monotonic()
        if not math.isfinite(now) or role_proof.expires_monotonic <= now:
            role_proof.close()
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
            native_process_identity=f"{role_proof.identity.daemon_unit_id}:{role_proof.pid}:{role_proof.identity.start_time_ticks}",
        )
        parent = HostContext.from_wire(self.service._signed_context(parent,
                                         self.service._sign(parent.claims())))
        return parent, role_proof, role, enrollment, observer

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
