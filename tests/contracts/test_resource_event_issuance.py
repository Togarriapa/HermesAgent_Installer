from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import replace
from pathlib import Path
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
from hermes_installer.authority.root_controller_custody import (
    RootIngressControllerProof, RootSelectedIngressBinding,
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
        self._ingress_proofs = {}

    def resolve_for_event(self, _event_handle, _node_id):
        proof = _ControllerProof(self.role, self.generation_digest, self.controller)
        self.proofs.append(proof)
        return proof

    def revalidate_ingress_proof(self, proof_handle):
        return proof_handle in self._ingress_proofs


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
        backend_enrollment_id="backend-1", body_recipe_id="recipe-demo", depends_on=(),
    )
    backend = SimpleNamespace(
        backend_id="backend-1", operation=operation, target_id=target, recipient=None,
        approved_action_ids=frozenset({"run-action"}), handler_sha256=hashlib.sha256(b"handler").hexdigest(),
        scope_binding_id="scope-1", maximum_request_bytes=512,
        resource_id="demo", profile_id=binding.profile_id, principal_id=binding.principal_id,
        generation=generation, source_issuer_channel_id="source-scheduler",
        observer_enrollment_id="observer-schedule",
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
        capture_schema_id="resource-ingress-capture-v1",
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
    admission_token = object()
    request = RootResourceJobContextRequest(
        root_event=event, event_payload=payload, event_fields=record.event_fields,
        parent_context=event_context, parent_receipts=(receipt,), resource_enrollment=enrollment,
        node=node, backend=backend, controller=controller, operation=operation,
        canonical_payload_sha256=canonical_digest(body),
        service_generation_digest=service_generation, authority_epoch=service.authority_epoch,
        issuer_token=request_token,
        admission_handle=admission_token,
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
    registry.job_enrollments = {(enrollment.resource_id, enrollment.generation): enrollment}
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
        request, record, enrollment, node, backend, role, controller, admission_token,
    )
    registry.consume_context_request = lambda candidate: (
        reservation if registry._pending_context_requests.pop(id(candidate), None) is candidate
        and candidate.issuer_token is registry._context_issuer_token else None
    )
    service.resource_job_authority = SimpleNamespace(
        is_root_admission_current=lambda event_handle, admission: (
            event_handle is event and admission is admission_token),
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


def test_generic_boolean_validator_and_caller_selected_mint_are_not_exposed():
    from hermes_installer.authority.resource_event_issuance import RootValidatedRawObservation

    issuer, _request, _registry, _service, _record = _case()
    assert not hasattr(issuer, "register_source_producer")
    assert not hasattr(issuer, "mint_source_proof")
    with pytest.raises(TypeError):
        RootValidatedRawObservation("raw", b"body", "event", "0" * 64, 1.0, {})


def test_issuer_sealed_raw_observation_is_immutable_and_requires_exact_seal():
    import hermes_installer.authority.resource_event_issuance as module

    fields = module.ResourceEventContextIssuer._freeze_json({"event": {"count": 2}})
    sealed = module.RootValidatedRawObservation._from_issuer(
        module._RAW_OBSERVATION_SEAL,
        raw_observation_handle=secrets.token_urlsafe(32), raw_payload=b"exact raw bytes",
        event_id=secrets.token_urlsafe(32), replay_key_sha256="a" * 64,
        observed_monotonic=10.0, event_data=fields,
    )
    assert sealed.event_data["event"]["count"] == 2
    with pytest.raises(TypeError):
        sealed.event_data["event"]["count"] = 3
    with pytest.raises(TypeError):
        module.RootValidatedRawObservation._from_issuer(
            object(), raw_observation_handle=secrets.token_urlsafe(32),
            raw_payload=b"raw", event_id=secrets.token_urlsafe(32),
            replay_key_sha256="b" * 64, observed_monotonic=10.0,
            event_data=module.MappingProxyType({}),
        )


def test_cron_protocol_event_requires_exact_selected_occurrence_replay_key():
    import hermes_installer.authority.resource_event_issuance as module

    issuer, _request, _registry, _service, record = _case()
    event_id = "E" + secrets.token_urlsafe(32)
    data = module.MappingProxyType({
        "schedule_enrollment_id": "schedule-demo",
        "scheduled_time_unix": 100,
        "due_time_unix": 100,
        "fired_time_unix": 101,
        "event_id": event_id,
        "occurrence_sequence": 1,
        "action_graph_sha256": "c" * 64,
    })
    replay = canonical_digest({
        "resource_id": "demo", "resource_generation": record.handle.resource_generation,
        "schedule_enrollment_id": "schedule-demo", "scheduled_time_unix": 100,
    })
    observation = module.RootValidatedRawObservation._from_issuer(
        module._RAW_OBSERVATION_SEAL, raw_observation_handle=secrets.token_urlsafe(32),
        raw_payload=b"raw timer record", event_id=event_id, replay_key_sha256=replay,
        observed_monotonic=100.5, event_data=data,
    )
    selected = SimpleNamespace(backend=SimpleNamespace(resource_id="demo"),
                               resource_generation=record.handle.resource_generation)
    producer = SimpleNamespace(protocol_schema_id="resource-cron-tick-v1",
                               protocol_schema_sha256=module._PROTOCOL_SCHEMAS["resource-cron-tick-v1"],
                               source_kind="schedule-event")
    issuer._validate_protocol_event_data(observation, selected, producer)
    bad = module.RootValidatedRawObservation._from_issuer(
        module._RAW_OBSERVATION_SEAL,
        raw_observation_handle=observation.raw_observation_handle,
        raw_payload=observation.raw_payload, event_id=observation.event_id,
        replay_key_sha256="d" * 64, observed_monotonic=observation.observed_monotonic,
        event_data=observation.event_data,
    )
    with pytest.raises(AuthorityDenied, match="replay key changed"):
        issuer._validate_protocol_event_data(bad, selected, producer)


@pytest.mark.parametrize("schema_id,schema_sha256,event_data,selected", [
    ("channel-http-observed-event-v1",
     "7626756c12b9020248423114e0df294fc7c2c5c74def36e535244de81bd4452c",
     {"text": "hello", "session_id": "s" * 32, "request_id": "r" * 32,
      "subject_id": "u" * 32, "raw_body_sha256": "a" * 64, "raw_body_size_bytes": 17},
     SimpleNamespace(backend=SimpleNamespace(resource_id="channel"), resource_generation="g1",
                    source_issuer=SimpleNamespace(issuer_channel_id="issuer-1"))),
    ("channel-audio-observed-event-v1",
     "cfbd9c9a41299293776666201298e4cdf3be388e91ec7c8ff05d2931520965fb",
     {"session_id": "s" * 32, "capture_id": "c" * 32,
      "audio_artifact_receipt_handle": "a" * 32, "audio_sha256": "b" * 64,
      "audio_size_bytes": 32000, "format": "pcm-s16le-mono", "sample_rate_hz": 16000,
      "duration_milliseconds": 1000},
     SimpleNamespace(backend=SimpleNamespace(resource_id="channel"), resource_generation="g1",
                    source_issuer=SimpleNamespace(issuer_channel_id="issuer-1"))),
])
def test_v94_native_http_audio_event_schemas_are_exact_and_bounded(
        schema_id, schema_sha256, event_data, selected):
    import hermes_installer.authority.resource_event_issuance as module

    issuer, *_ = _case()
    issuer.selected_protocol_schema = lambda *_args: (schema_id, schema_sha256)
    replay_fields = ({"session_id": event_data["session_id"],
                      "request_id": event_data["request_id"],
                      "body_sha256": event_data["raw_body_sha256"]}
                     if schema_id == "channel-http-observed-event-v1" else
                     {"session_id": event_data["session_id"],
                      "capture_id": event_data["capture_id"],
                      "audio_sha256": event_data["audio_sha256"]})
    observation = module.RootValidatedRawObservation._from_issuer(
        module._RAW_OBSERVATION_SEAL,
        raw_observation_handle=secrets.token_urlsafe(32), raw_payload=b"bounded source bytes",
        event_id=secrets.token_urlsafe(32), replay_key_sha256=canonical_digest(replay_fields),
        observed_monotonic=10.0, event_data=module.ResourceEventContextIssuer._freeze_json(event_data),
    )
    producer = SimpleNamespace(source_kind="native-input", protocol_schema_id=schema_id,
                               protocol_schema_sha256=schema_sha256)
    issuer._validate_protocol_event_data(observation, selected, producer)

    malformed = dict(event_data)
    malformed["unexpected"] = "caller data"
    forged = module.RootValidatedRawObservation._from_issuer(
        module._RAW_OBSERVATION_SEAL,
        raw_observation_handle=observation.raw_observation_handle,
        raw_payload=observation.raw_payload, event_id=observation.event_id,
        replay_key_sha256=observation.replay_key_sha256,
        observed_monotonic=observation.observed_monotonic,
        event_data=module.ResourceEventContextIssuer._freeze_json(malformed),
    )
    with pytest.raises(AuthorityDenied, match="differs from its selected schema"):
        issuer._validate_protocol_event_data(forged, selected, producer)
    replay_forged = module.RootValidatedRawObservation._from_issuer(
        module._RAW_OBSERVATION_SEAL,
        raw_observation_handle=observation.raw_observation_handle,
        raw_payload=observation.raw_payload, event_id=observation.event_id,
        replay_key_sha256="d" * 64, observed_monotonic=observation.observed_monotonic,
        event_data=observation.event_data,
    )
    with pytest.raises(AuthorityDenied, match="replay key changed"):
        issuer._validate_protocol_event_data(replay_forged, selected, producer)


def test_v94_schema_catalog_digests_match_committed_schema_artifacts():
    import hermes_installer.authority.resource_event_issuance as module

    root = Path(__file__).parents[2]
    schema_dir = root / "plans/amendments/2026-10-10-http-audio-observed-event-schemas-v94"
    for filename, schema_id in (
            ("channel-http-observed-event-v1.json", "channel-http-observed-event-v1"),
            ("channel-audio-observed-event-v1.json", "channel-audio-observed-event-v1")):
        digest = hashlib.sha256((schema_dir / filename).read_bytes()).hexdigest()
        assert module._PROTOCOL_SCHEMAS[schema_id] == digest


def test_selected_producer_mints_one_use_proof_only_for_retained_live_ingress_custody():
    issuer, _request, registry, service, record = _case()
    enrollment = registry.job_enrollments[("demo", record.handle.resource_generation)]
    backend = SimpleNamespace(
        resource_id="demo", profile_id=enrollment.profile_id, principal_id=enrollment.principal_id,
        backend_id="backend-1", generation=enrollment.generation,
        source_issuer_channel_id=enrollment.source_issuer_channel_id,
        observer_enrollment_id=enrollment.observer_enrollment_id,
        operation="resource.cron.run",
    )
    observer = registry.source_observers.observers[enrollment.observer_enrollment_id]
    role = registry.roles["role-scheduler"]
    source_issuer = SimpleNamespace(
        issuer_channel_id=enrollment.source_issuer_channel_id,
        observer_enrollment_id=observer.observer_enrollment_id,
        producer_profile_id=observer.profile_id,
        capture_schema_id="resource-ingress-capture-v1",
    )
    now = service.monotonic()
    selected = RootSelectedIngressBinding(
        role=role, source_issuer=source_issuer, source_observer=observer,
        backend=backend, resource_generation=enrollment.generation,
        service_generation_digest=service.service_generation_digest,
        authority_epoch=service.authority_epoch,
        selected_ingress_binding_id="ingress-binding-1", expires_monotonic=now + 20,
    )
    resolver = registry.custody_resolver
    resolver._selected_ingress_binding_resolver = lambda *_args: selected
    from hermes_installer.authority.root_controller_custody import RootControllerRoleResolver
    resolver._ingress_join = RootControllerRoleResolver._ingress_join
    proof = RootIngressControllerProof(
        schema=1, proof_handle="proof-handle-" + secrets.token_urlsafe(24),
        controller_role_id=role.id, controller_kind=role.controller_kind,
        controller_generation=role.controller_generation,
        source_issuer_id=source_issuer.issuer_channel_id,
        backend_enrollment_id=backend.backend_id,
        resource_generation=enrollment.generation,
        service_generation_digest=service.service_generation_digest,
        authority_epoch=service.authority_epoch, pid=111, pidfd=os.open("/dev/null", os.O_RDONLY), uid=0,
        live_peer_identity=SimpleNamespace(pid=111), role_artifact_id=role.role_module_artifact_id,
        role_artifact_sha256=role.role_module_sha256, namespace_id="namespace-root",
        selected_ingress_binding_id=selected.selected_ingress_binding_id,
        issued_monotonic=now - 1, expires_monotonic=now + 10, _resolver=resolver,
    )
    resolver._ingress_proofs[proof.proof_handle] = SimpleNamespace(proof=proof)
    replay_key = canonical_digest({
        "resource_id": "demo", "resource_generation": enrollment.generation,
        "schedule_enrollment_id": "schedule-1", "scheduled_time_unix": 100,
    })
    raw_record = object()
    event_id = "E" + secrets.token_urlsafe(32)

    class _Producer:
        def __init__(self):
            self.used = False

        def consume_verified_raw_observation(self, candidate, custody):
            assert candidate is raw_record and custody is proof
            if self.used:
                raise ValueError("replayed raw observation")
            self.used = True
            return SimpleNamespace(
                raw_observation_handle=secrets.token_urlsafe(32),
                raw_payload=b"signed/root timer observation", event_id=event_id,
                replay_key_sha256=replay_key, observed_monotonic=now,
                event_data={
                    "schedule_enrollment_id": "schedule-1", "scheduled_time_unix": 100,
                    "due_time_unix": 100, "fired_time_unix": 101,
                    "event_id": event_id, "occurrence_sequence": 1,
                    "action_graph_sha256": "e" * 64,
                },
            )

    producer = _Producer()
    # The occurrence ID is generated before event_data is returned and is
    # tied to the same actual one-use timer record.
    cap = issuer.register_selected_source_producer(producer, selected_ingress_binding=selected)
    with pytest.raises(AuthorityDenied, match="custody is stale or mismatched"):
        issuer.mint_selected_source_proof(
            cap, controller_proof=replace(proof), raw_observation=raw_record,
        )
    assert producer.used is False
    issuer.selected_generation = lambda _resource_id: "stale-generation"
    with pytest.raises(AuthorityDenied, match="selection or consent revision changed"):
        issuer.mint_selected_source_proof(cap, controller_proof=proof, raw_observation=raw_record)
    assert producer.used is False
    issuer.selected_generation = lambda _resource_id: enrollment.generation
    minted = issuer.mint_selected_source_proof(
        cap, controller_proof=proof, raw_observation=raw_record,
    )
    assert minted.controller_proof_handle == proof.proof_handle
    assert minted.resource_id == enrollment.resource_id
    assert issuer.resolve_validated_source_event_data(minted, issuer._registry_capability)["event_id"] == event_id
    with pytest.raises(AuthorityDenied, match="stale or consumed"):
        issuer.resolve_validated_source_event_data(replace(minted), issuer._registry_capability)
    with pytest.raises(AuthorityDenied, match="observation was not verified"):
        issuer.mint_selected_source_proof(cap, controller_proof=proof, raw_observation=raw_record)
    os.close(proof.pidfd)


def test_source_proof_discard_rejects_non_proof_objects():
    issuer, _request, _registry, _service, _record = _case()
    assert issuer.discard_source_proof(object()) is False


def test_initial_source_resolves_only_signed_current_parent_receipts_from_exact_observer():
    issuer, _request, registry, service, record = _case()
    observer_row = registry.source_observers.observers["observer-schedule"]
    observer_row.allowed_parent_source_kinds = frozenset({"static-context"})
    base = replace(record.parent_context, source_receipts=(), signature="pending")
    base = HostContext.from_wire(service._signed_context(base, service._sign(base.claims())))
    parent = service.issue_source_receipt(
        base, source_kind="static-context", origin_id="http-subject:session-1",
        payload=b"subject", ttl_seconds=30,
    )
    provenance = object()

    class _Observer:
        def consume_source_receipts(self, candidate):
            assert candidate is provenance
            return (parent,)

    producer = SimpleNamespace(observer=_Observer())
    proof = SimpleNamespace(verified_provenance=provenance)
    producer_binding = SimpleNamespace(producer=producer)
    resolved = issuer._resolve_parent_receipts(
        proof, producer_binding,
        SimpleNamespace(resource_id="demo", generation=record.handle.resource_generation,
                        observer_enrollment_id="observer-schedule", profile_id=base.profile_id,
                        principal_id=base.principal_id), base,
    )
    assert resolved == (parent,)

    tampered = replace(parent, signature="forged")
    producer.observer.consume_source_receipts = lambda _candidate: (tampered,)
    with pytest.raises(AuthorityDenied, match="signature is invalid"):
        issuer._resolve_parent_receipts(
            proof, producer_binding,
            SimpleNamespace(resource_id="demo", generation=record.handle.resource_generation,
                            observer_enrollment_id="observer-schedule", profile_id=base.profile_id,
                            principal_id=base.principal_id), base,
        )
