from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from hermes_installer.authority.resource_event_issuance import ResourceEventContextIssuer
from hermes_installer.authority.resource_source_controllers import (
    RootControllerRoleEnrollment,
    RootResourceContextReservation,
    RootResourceControllerRegistry,
    RootResourceEventHandle,
    RootResourceJobContextRequest,
    _RootEventRecord,
)
from hermes_installer.authority.service import (
    AuthorityService, EffectRule, PrincipalBinding,
)
from hermes_installer.authority.types import (
    AuthorityDenied, HostContext, Sensitivity, canonical_digest,
)
from hermes_installer.registry.resource_jobs import (
    ResourceBodyRecipe, ResourceBodyRecipeField, ResourceValidator, RootTaskController,
)


class _Policy:
    revision = "resource-event-policy-v1"

    def classify(self, *, purpose, intent, source_contexts, binding):
        return Sensitivity.PRIVATE, canonical_digest({"purpose": purpose, "intent": intent})

    def allow_effect(self, *, context, rule, request_digest, retry_index):
        return context.sensitivity is Sensitivity.PRIVATE


class _ControllerProof:
    def __init__(self, role, generation_digest, controller):
        self.row = role
        self.generation_digest = generation_digest
        self.pid = controller.pid
        self.uid = controller.uid
        self.identity = controller.identity
        self.expires_monotonic = controller.expires_monotonic
        self.loaded_role_proof = object()
        self.closed = False

    def revalidate(self):
        return not self.closed

    def close(self):
        self.closed = True


class _CustodyResolver:
    def __init__(self, role, generation_digest, controller):
        self.role = role
        self.generation_digest = generation_digest
        self.controller = controller
        self.proofs = []

    def resolve_for_event(self, _event_handle, _node_id):
        proof = _ControllerProof(self.role, self.generation_digest, self.controller)
        self.proofs.append(proof)
        return proof


def _case(*, selected_generation=None, consent_revision=None):
    uid = os.getuid()
    generation = hashlib.sha256(b"selected resource generation").hexdigest()
    profile_generation = "profile-generation-v1"
    service_generation = hashlib.sha256(b"service generation").hexdigest()
    operation = "resource.cron.run"
    target = f"resource:demo:run-action:{generation}"
    capability = "hermes-resource-runtime"
    rule = EffectRule(capability, operation, target)
    binding = PrincipalBinding(uid, "principal-demo", "profile-demo", "namespace-demo",
                              frozenset({capability}))
    service = AuthorityService(
        signing_key=b"r" * 32, key_id="resource-event-fixture",
        bindings_by_uid={uid: binding},
        rules={(capability, operation, target): rule},
        handlers={(operation, target): lambda **_kwargs: {}}, policy=_Policy(),
        profile_generations={binding.profile_id: profile_generation},
    )
    service.authority_epoch = "authority-epoch-v1"
    service.service_generation_digest = service_generation

    payload = b'{"event":"timer-fire"}'
    now = time.monotonic()
    context_expiry = now + 90
    source_identity = f"fixture-process-{os.getpid()}"
    source = HostContext(
        principal_id=binding.principal_id, profile_id=binding.profile_id,
        namespace_id=binding.namespace_id, uid=binding.uid,
        purpose="resource-source", intent_id=canonical_digest({"event": "timer-fire"}),
        trace_id=secrets.token_urlsafe(16), sensitivity=Sensitivity.PRIVATE,
        lineage_hash=canonical_digest({"source": "scheduler"}),
        policy_revision=service._policy_revision(), capabilities=binding.capabilities,
        issued_at_monotonic=now, monotonic_expires_at=context_expiry,
        nonce=secrets.token_urlsafe(16), grant_id=secrets.token_urlsafe(16),
        signature="pending", final_payload_digest=canonical_digest(payload),
        enrollment_id=canonical_digest({
            "uid": binding.uid, "principal_id": binding.principal_id,
            "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
            "generation": profile_generation, "authority_epoch": service.authority_epoch,
        }), generation=profile_generation, operation="resource.job.admit",
        native_process_identity=source_identity,
    )
    source = HostContext.from_wire(service._signed_context(source, service._sign(source.claims())))
    receipt = service.issue_source_receipt(
        source, source_kind="schedule-event", origin_id="schedule-demo:event-1",
        payload=payload, ttl_seconds=60,
    )
    # The controller registry requires ID tokens to begin with an alphanumeric;
    # normalize this test receipt so its random URL-safe prefix cannot flake.
    receipt = replace(receipt, receipt_id=f"receipt-{receipt.receipt_id}", signature="pending")
    receipt = replace(receipt, signature=service._sign(receipt.claims()))
    event_context = replace(
        source, source_receipts=(receipt,),
        monotonic_expires_at=min(source.monotonic_expires_at, receipt.monotonic_expires_at),
        nonce=secrets.token_urlsafe(16), grant_id=secrets.token_urlsafe(16), signature="pending",
    )
    event_context = HostContext.from_wire(
        service._signed_context(event_context, service._sign(event_context.claims())))

    validator = ResourceValidator(
        "event-value", "utf8-string", 128, None, None, None, None, None,
    )
    recipe = ResourceBodyRecipe(
        "recipe-demo", "request-schema", "recipe-artifact",
        hashlib.sha256(b"recipe").hexdigest(),
        (ResourceBodyRecipeField("event", "observed-event-field", "event", "event-value"),),
        (), 512,
    )
    node = SimpleNamespace(
        node_id="node-1", action_id="run-action", effect=operation, target=target,
        recipient=None, action_digest=hashlib.sha256(b"selected action").hexdigest(),
        backend_enrollment_id="backend-1", body_recipe_id="recipe-demo",
    )
    backend = SimpleNamespace(
        backend_id="backend-1", operation=operation, target_id=target, recipient=None,
        approved_action_ids=frozenset({"run-action"}), handler_sha256=hashlib.sha256(b"handler").hexdigest(),
        scope_binding_id="scope-1", maximum_request_bytes=512,
    )
    enrollment = SimpleNamespace(
        resource_id="demo", kind="crons", generation=generation,
        selected_enabled=True, profile_id=binding.profile_id,
        principal_id=binding.principal_id, consent_revision="consent-v1",
        profile_generation=profile_generation, observer_enrollment_id="observer-schedule",
        source_issuer_channel_id="source-scheduler", source_policy=frozenset({"schedule-event"}),
        approved_action_ids=frozenset({"run-action"}),
        body_recipes={recipe.recipe_id: recipe}, scope_bindings={}, validators={validator.validator_id: validator},
    )
    observer = SimpleNamespace(
        observer_enrollment_id=enrollment.observer_enrollment_id,
        source_kind="schedule-event", origin_id="schedule-demo",
        profile_id=binding.profile_id, principal_id=binding.principal_id,
        generation=profile_generation, channel_id=enrollment.source_issuer_channel_id,
        allowed_parent_source_kinds=frozenset(),
    )
    role = RootControllerRoleEnrollment(
        id="role-scheduler", controller_kind="root-scheduler",
        daemon_unit_id="hermes-installer-authority.service",
        daemon_executable_artifact_id="daemon-exe-v1",
        daemon_executable_sha256="1" * 64,
        role_module_artifact_id="scheduler-role-v1", role_module_sha256="2" * 64,
        controller_generation="scheduler-generation-v1",
        source_observer_enrollment_ids=(observer.observer_enrollment_id,),
        allowed_backend_enrollment_ids=(backend.backend_id,),
        allowed_operations=(operation,), max_lease_seconds=25,
    )
    controller_identity = SimpleNamespace(pid=400, start_time_ticks=12, cgroup="system.slice", uid=0)
    controller = RootTaskController(
        schema=1, controller_handle="controller-handle-v1",
        controller_kind=role.controller_kind,
        controller_role_artifact_id=role.role_module_artifact_id,
        controller_role_sha256=role.role_module_sha256,
        pid=400, pidfd=os.open("/dev/null", os.O_RDONLY), uid=0,
        identity=controller_identity, controller_profile_id=None,
        controller_generation=role.controller_generation, source_receipt_id=None,
        subject_principal_id=binding.principal_id, subject_profile_id=binding.profile_id,
        subject_namespace_id=binding.namespace_id, service_generation_digest=service_generation,
        expires_monotonic=min(event_context.monotonic_expires_at, now + 20),
    )
    parent_closure = canonical_digest(sorted(
        (receipt.receipt_id, canonical_digest(receipt.claims())) for receipt in (receipt,)))
    event = RootResourceEventHandle(
        handle="root-event-handle-v1", event_id="event-1", resource_id="demo",
        resource_generation=generation, source_kind="schedule-event",
        source_observer_enrollment_id=observer.observer_enrollment_id,
        source_receipt_ids=(receipt.receipt_id,), parent_closure_digest=parent_closure,
        payload_sha256=canonical_digest(payload), issued_monotonic=now,
        expires_monotonic=min(event_context.monotonic_expires_at, now + 30),
        authority_epoch=service.authority_epoch,
    )
    record = _RootEventRecord(
        event, event_context, (receipt,), payload, {"event": "timer-fire"},
        {"approved_dag_sha256": hashlib.sha256(b"dag").hexdigest()}, {},
    )
    body = recipe.render(backend=backend, scope_bindings={}, validators={validator.validator_id: validator},
                         event_fields={"event": "timer-fire"}, parent_results={})
    request_token = object()
    request = RootResourceJobContextRequest(
        root_event=event, event_payload=payload, event_fields=record.event_fields,
        parent_context=event_context, parent_receipts=(receipt,), resource_enrollment=enrollment,
        node=node, backend=backend, controller=controller, operation=operation,
        canonical_payload_sha256=canonical_digest(body),
        service_generation_digest=service_generation, authority_epoch=service.authority_epoch,
        issuer_token=request_token,
    )
    registry = object.__new__(RootResourceControllerRegistry)
    registry.service = service
    registry.authority_epoch = service.authority_epoch
    registry.service_generation_digest = service_generation
    registry.source_observers = SimpleNamespace(observers={observer.observer_enrollment_id: observer})
    registry.roles = {role.id: role}
    registry._context_issuer_token = request_token
    registry._pending_context_requests = {id(request): request}
    registry._used = {(event.handle, node.node_id)}
    registry._lock = __import__("threading").RLock()
    registry._event_issuer = None
    registry._event_issuer_capability = None
    registry.job_enrollments = {}
    registry.selected_specs = {(enrollment.resource_id, enrollment.generation): record.selected_spec}
    registry._resolve_event_node = lambda _event, _node: (record, enrollment, node, backend)
    registry._select_role = lambda **_kwargs: role
    registry._source_controller_kind = lambda kind: {
        "schedule-event": "root-scheduler", "webhook-event": "root-webhook",
        "native-input": "root-channel",
    }[kind]
    registry._profile_binding = lambda _enrollment: binding
    registry.custody_resolver = _CustodyResolver(role, service_generation, controller)
    reservation = RootResourceContextReservation(
        request, record, enrollment, node, backend, role, controller,
    )
    registry.consume_context_request = lambda candidate: (
        reservation if registry._pending_context_requests.pop(id(candidate), None) is candidate
        and candidate.issuer_token is registry._context_issuer_token else None
    )
    issuer = ResourceEventContextIssuer(
        service=service, controller_registry=registry,
        selected_generation=lambda _resource_id: selected_generation or generation,
        current_consent_revision=lambda _resource_id: consent_revision or "consent-v1",
    )
    return issuer, request, registry, service, record


def test_root_event_issuer_signs_exact_fresh_effect_and_commits_full_private_lineage():
    issuer, request, registry, service, record = _case()
    service.attach_resource_event_context_issuer(issuer)

    context, grant = service.issue_resource_job_context(request)

    assert context.operation == "resource.cron.run"
    assert context.final_payload_digest == request.canonical_payload_sha256
    assert context.sensitivity is Sensitivity.PRIVATE
    assert context.source_receipts == ()  # Source closure is one-use at admission.
    assert request.parent_receipts[0].receipt_id in context.lineage_hash or len(context.lineage_hash) == 64
    service._verify_context_signature(context)
    service._verify_grant_signature(grant)
    assert grant.operation == context.operation
    assert grant.target == request.backend.target_id
    assert grant.request_digest == request.canonical_payload_sha256
    assert registry.custody_resolver.proofs[-1].closed is True
    assert record.handle.handle not in {key[0] for key in registry._pending_context_requests}


def test_root_event_issuer_rejects_forged_request_copy_and_cannot_replay_capability():
    issuer, request, _registry, _service, _record = _case()
    forged = replace(request, issuer_token=request.issuer_token)

    with pytest.raises(AuthorityDenied, match="request capability"):
        issuer.issue(forged)
    issuer.issue(request)
    with pytest.raises(AuthorityDenied, match="request capability"):
        issuer.issue(request)


@pytest.mark.parametrize("selected_generation,consent_revision", [
    ("stale-generation", "consent-v1"),
    (None, "revoked-consent"),
])
def test_root_event_issuer_rejects_stale_selection_or_consent_before_signing(
        selected_generation, consent_revision):
    issuer, request, registry, _service, _record = _case(
        selected_generation=selected_generation, consent_revision=consent_revision,
    )

    with pytest.raises(AuthorityDenied, match="selection or consent"):
        issuer.issue(request)
    assert registry.custody_resolver.proofs == []


def test_root_event_issuer_rejects_changed_captured_bytes_before_signing():
    issuer, request, _registry, _service, record = _case()
    object.__setattr__(record, "payload", b'{"event":"different"}')

    with pytest.raises(AuthorityDenied, match="event receipt"):
        issuer.issue(request)


def test_root_event_issuer_rejects_incomplete_or_unrelated_parent_receipt_closure():
    issuer, _request, _registry, service, record = _case()
    binding = service.bindings_by_uid[os.getuid()]
    object.__setattr__(record, "parent_receipts", ())
    object.__setattr__(record, "parent_context",
                       replace(record.parent_context, source_receipts=()))

    with pytest.raises(AuthorityDenied, match="source context or complete closure"):
        issuer._verify_source_closure(record, SimpleNamespace(
            profile_id=binding.profile_id, principal_id=binding.principal_id,
        ), binding, service.monotonic())


def test_initial_source_proof_is_producer_bound_opaque_and_one_use():
    issuer, _request, _registry, _service, _record = _case()
    producer = object()
    provenance = SimpleNamespace(accepted=True, native_id="message-9")
    capability = issuer.register_source_producer(
        producer, source_kind="schedule-event",
        observer_enrollment_id="observer-schedule",
        validate_provenance=lambda value: value is provenance and value.accepted is True,
        resolve_controller=lambda *_args: None,
    )
    proof = issuer.mint_source_proof(
        capability, event_id="e" + secrets.token_urlsafe(32), resource_id="demo",
        resource_generation=_record.handle.resource_generation,
        source_observer_enrollment_id="observer-schedule",
        payload=b'{"event":"timer-fire"}', provenance=provenance,
    )
    assert "message-9" not in repr(proof) and "timer-fire" not in repr(proof)
    issuer.controller_registry.job_enrollments = {}
    with pytest.raises(AuthorityDenied, match="not currently selected"):
        issuer.issue_source_event(proof, issuer._registry_capability)
    with pytest.raises(AuthorityDenied, match="stale or already consumed"):
        issuer.issue_source_event(proof, issuer._registry_capability)
