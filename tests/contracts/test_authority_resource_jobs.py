from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

from hermes_installer.authority.resource_jobs import index_resource_job_records
from hermes_installer.registry.resource_jobs import (
    ResourceBackendEnrollment,
    ResourceBodyRecipe,
    ResourceBodyRecipeField,
    ResourceCredentialBinding,
    ResourceJobEnrollment,
    ResourceJobNode,
    ResourceScopeBinding,
    ResourceValidator,
)


def test_resource_credential_binding_preserves_full_manifest_placeholder():
    binding = ResourceCredentialBinding(
        "${GITHUB_WEBHOOK_SECRET}", "credential-github-hook", "webhook-hmac-verify",
    )
    assert binding.source_placeholder == "${GITHUB_WEBHOOK_SECRET}"
    with pytest.raises(Exception):
        ResourceCredentialBinding("${github-secret}", "credential-github-hook", "webhook-hmac-verify")

_EXECUTION_BINDING = {
    "process_enrollment_id": "process-profile",
    "process_generation": "process-generation",
    "operation_id": "hermes-resource-profile-task-v1",
    "native_package_id": "package-1",
    "native_package_generation": "service-generation",
    "child_operation": "process.start",
    "child_target_id": "process:profile:chat",
    "child_capability": "hermes-profile-invoke",
    "task_body_recipe_id": "task-recipe",
    "task_request_schema_id": "hermes-resource-profile-query-v1",
}


def _fixture():
    generation = hashlib.sha256(b"resource-generation").hexdigest()
    handler_digest = hashlib.sha256(b"pinned-handler").hexdigest()
    recipe = ResourceBodyRecipe(
        "recipe", "request-schema", "recipe-artifact", handler_digest,
        (ResourceBodyRecipeField("action", "literal", "run", "run-action"),), {}, 512,
    )
    task_recipe = ResourceBodyRecipe(
        "task-recipe", "hermes-resource-profile-query-v1", "task-recipe-artifact", handler_digest,
        (ResourceBodyRecipeField("prompt", "literal", "perform the selected action", "task-prompt"),),
        (), 1024,
    )
    node = ResourceJobNode(
        "node-1", "run-action", "resource.cron.run",
        f"resource:demo:run-action:{generation}", None, recipe.template_payload(),
        request_schema_id="request-schema", body_recipe_id="recipe",
        backend_enrollment_id="backend-1", result_schema_id="result-schema",
        scope_binding_id="scope-binding",
    )
    backend = ResourceBackendEnrollment(
        "backend-1", "demo", "profile-1", "principal-1", generation, "consent-1",
        "source-channel", "observer-1", "package-1", "service-generation",
        "handler-artifact", handler_digest, frozenset({"run-action"}),
        "resource.cron.run", node.target, None, frozenset(), "request-schema",
        "result-schema", "recipe", "scope-binding", 1024, 2048, 30, "service-generation",
        _EXECUTION_BINDING,
    )
    scope_record = ResourceScopeBinding(
        "scope-binding", "demo", "profile-1", "principal-1", generation,
        "service-generation", "backend-1", {}, frozenset(), None,
    )
    validator_record = ResourceValidator(
        "run-action", "enum", None, None, None, ("run",), None, None,
    )
    task_validator = ResourceValidator(
        "task-prompt", "utf8-string", 262_144, None, None, None, None, None,
    )
    enrollment = ResourceJobEnrollment(
        "demo", "crons", generation, True, "profile-1", "principal-1", "consent-1",
        frozenset({"run-action"}), frozenset({node.target}), frozenset(),
        frozenset({"schedule-event"}), "schedule-1", (node,), 1, 1, 30, 2048, 10,
        enrollment_id="profile-enrollment-1", source_issuer_channel_id="source-channel",
        observer_enrollment_id="observer-1",
        body_recipes={"recipe": recipe, "task-recipe": task_recipe},
        backends={"backend-1": backend}, profile_generation="service-generation",
        scope_bindings={"scope-binding": scope_record},
        validators={"run-action": validator_record, "task-prompt": task_validator},
    )
    raw_backend = {
        "id": "backend-1", "resource_id": "demo", "profile_id": "profile-1",
        "principal_id": "principal-1", "generation": generation,
        "consent_revision": "consent-1", "source_issuer_channel_id": "source-channel",
        "observer_enrollment_id": "observer-1", "native_package_id": "package-1",
        "native_package_generation": "service-generation", "handler_artifact_id": "handler-artifact",
        "handler_sha256": handler_digest, "approved_action_ids": ["run-action"],
        "operation": "resource.cron.run", "target_id": node.target, "recipient": None,
        "credential_reference_ids": [], "request_schema_id": "request-schema",
        "result_schema_id": "result-schema", "body_recipe_id": "recipe",
        "scope_binding_id": "scope-binding", "maximum_request_bytes": 1024,
        "maximum_response_bytes": 2048, "maximum_seconds": 30,
        "profile_generation": "service-generation",
        "execution_binding": _EXECUTION_BINDING,
        "credential_bindings": [],
    }
    raw_recipe = {
        "id": "recipe", "schema_id": "request-schema", "source_artifact_id": "recipe-artifact",
        "source_sha256": handler_digest,
        "output_fields": [{"name": "action", "source": "literal", "value": "run",
                           "validator_id": "run-action"}],
        "scope_bindings": [], "maximum_bytes": 512,
    }
    raw_task_recipe = {
        "id": "task-recipe", "schema_id": "hermes-resource-profile-query-v1",
        "source_artifact_id": "task-recipe-artifact", "source_sha256": handler_digest,
        "output_fields": [{"name": "prompt", "source": "literal",
                           "value": "perform the selected action", "validator_id": "task-prompt"}],
        "scope_bindings": [], "maximum_bytes": 1024,
    }
    scope = {
        "id": "scope-binding", "resource_id": "demo", "profile_id": "profile-1",
        "principal_id": "principal-1", "resource_generation": generation,
        "profile_generation": "service-generation", "backend_enrollment_id": "backend-1",
        "fixed_fields": {}, "credential_reference_ids": [], "recipient": None,
    }
    validator = {
        "id": "run-action", "kind": "enum", "maximum_bytes": None,
        "minimum": None, "maximum": None, "allowed_values": ["run"],
        "schema_artifact_id": None, "schema_sha256": None,
    }
    raw_task_validator = {
        "id": "task-prompt", "kind": "utf8-string", "maximum_bytes": 262144,
        "minimum": None, "maximum": None, "allowed_values": None,
        "schema_artifact_id": None, "schema_sha256": None,
    }
    row = {
        "resource_id": "demo", "kind": "crons", "selected_enabled": True,
        "profile_id": "profile-1", "principal_id": "principal-1", "generation": generation,
        "consent_revision": "consent-1", "approved_action_ids": ["run-action"],
        "fixed_target_ids": [node.target], "credential_reference_ids": [],
        "recipient_scope": [], "source_policy": ["schedule-event"],
        "schedule_or_route_id": "schedule-1", "max_children": 1, "max_concurrency": 1,
        "max_runtime_seconds": 30, "max_payload_bytes": 2048, "max_replay_entries": 10,
        "enrollment_id": "profile-enrollment-1", "source_issuer_channel_id": "source-channel",
        "observer_enrollment_id": "observer-1",
        "approved_dag": {"dag_sha256": enrollment.dag_sha256, "nodes": [{
            "node_id": node.node_id, "resource_id": "demo", "action_id": node.action_id,
            "operation": node.effect, "target_id": node.target, "recipient": node.recipient,
            "request_schema_id": node.request_schema_id, "body_recipe_id": node.body_recipe_id,
            "depends_on": [], "maximum_attempts": 1,
            "backend_enrollment_id": node.backend_enrollment_id,
            "result_schema_id": node.result_schema_id, "scope_binding_id": node.scope_binding_id,
        }]},
    }
    source_issuer = SimpleNamespace(
        issuer_channel_id="source-channel", observer_enrollment_id="observer-1",
        generation="service-generation", producer_profile_id="profile-1",
        capture_schema_id="event-schema", source_action_ids=("root-timer-event",),
    )
    observer = SimpleNamespace(
        observer_enrollment_id="observer-1", channel_id="source-channel", profile_id="profile-1",
        principal_id="principal-1", generation="service-generation", source_kind="schedule-event",
        origin_id="schedule-1", capture_schema_id="event-schema",
        source_action_id="root-timer-event",
    )
    return (row, raw_backend, [raw_recipe, raw_task_recipe], scope,
            [validator, raw_task_validator], source_issuer, observer, enrollment)


def test_protected_resource_job_index_requires_exact_active_source_backend_and_recipe_joins():
    from hermes_installer.authority.resource_jobs import (
        parse_resource_backend_records,
        parse_resource_body_recipes,
        parse_resource_scope_binding_records,
        parse_resource_validator_records,
    )

    row, raw_backend, raw_recipes, raw_scope, raw_validators, issuer, observer, expected = _fixture()
    backends = parse_resource_backend_records([raw_backend])
    recipes = parse_resource_body_recipes(raw_recipes)
    scopes = parse_resource_scope_binding_records([raw_scope])
    validators = parse_resource_validator_records(raw_validators)
    result = index_resource_job_records(
        [row], backend_enrollments=backends, body_recipes=recipes,
        scope_bindings=scopes, validators=validators,
        source_issuers=(issuer,), source_observers={"observer-1": observer},
    )
    assert result[("demo", expected.generation)].backends == expected.backends

    wrong_observer = SimpleNamespace(**{**observer.__dict__, "channel_id": "another-channel"})
    assert not index_resource_job_records(
        [row], backend_enrollments=backends, body_recipes=recipes,
        scope_bindings=scopes, validators=validators,
        source_issuers={"source-channel": issuer}, source_observers={"observer-1": wrong_observer},
    )


def test_root_process_receipt_binds_task_attempt_and_full_lineage():
    import pytest

    from hermes_installer.authority.resource_jobs import (
        RootResourceProcessReceipt, parse_resource_backend_records,
    )
    from hermes_installer.authority.types import AuthorityDenied

    _, raw_backend, *_ = _fixture()
    backend = parse_resource_backend_records([raw_backend])["backend-1"]
    payload = b'{"prompt":"perform the selected action"}'
    closure = hashlib.sha256(b"complete-parent-closure").hexdigest()
    wire = {
        "schema": 1, "job_id": "job-1", "node_id": "node-1",
        "backend_enrollment_id": "backend-1", "process_id": "process-1",
        "process_generation": "process-generation",
        "native_package_generation": "service-generation",
        "task_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "parent_closure_digest": closure, "terminal_receipt_handle": "terminal-1",
        "result_capsule_handle": "result-1", "expires_monotonic": 40.0,
    }
    receipt = RootResourceProcessReceipt.from_wire(wire)
    receipt.assert_bound(job_id="job-1", node_id="node-1", backend=backend, payload=payload,
                         parent_closure_digest=closure, now=10.0, job_expires_monotonic=50.0)
    with pytest.raises(AuthorityDenied, match="does not bind this selected task"):
        receipt.assert_bound(job_id="job-1", node_id="other-node", backend=backend, payload=payload,
                             parent_closure_digest=closure, now=10.0, job_expires_monotonic=50.0)


def test_protected_resource_job_index_rejects_wrong_observer_origin_or_action():
    row, raw_backend, raw_recipes, raw_scope, raw_validators, issuer, observer, _ = _fixture()
    from hermes_installer.authority.resource_jobs import (
        parse_resource_backend_records, parse_resource_body_recipes,
        parse_resource_scope_binding_records, parse_resource_validator_records,
    )

    kwargs = {
        "backend_enrollments": parse_resource_backend_records([raw_backend]),
        "body_recipes": parse_resource_body_recipes(raw_recipes),
        "scope_bindings": parse_resource_scope_binding_records([raw_scope]),
        "validators": parse_resource_validator_records(raw_validators),
        "source_issuers": (issuer,),
    }
    wrong_origin = SimpleNamespace(**{**observer.__dict__, "origin_id": "another-schedule"})
    assert not index_resource_job_records([row], **kwargs, source_observers=(wrong_origin,))
    wrong_action = SimpleNamespace(**{**observer.__dict__, "source_action_id": "unselected-action"})
    assert not index_resource_job_records([row], **kwargs, source_observers=(wrong_action,))


def test_root_selected_task_dispatch_consumes_one_ledger_bound_handle(tmp_path):
    import json
    import time

    from hermes_installer.authority.resource_jobs import (
        ResourceJobAuthority, RootResourceProcessReceipt,
    )
    from hermes_installer.authority.service import AuthorityService
    from hermes_installer.authority.types import (
        AuthorityDenied, HostContext, Sensitivity, SourceReceipt, canonical_digest,
    )
    from hermes_installer.registry.resource_backends import ResourceProfileTaskAdapter
    from hermes_installer.registry.resource_jobs import ResourceJobLedger

    row, _raw_backend, _recipes, _scope, _validators, _issuer, _observer, enrollment = _fixture()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    data.chmod(0o700)
    ledger = ResourceJobLedger(data / "jobs.sqlite")
    now = time.monotonic
    admission = ledger.admit_job(
        enrollment, event_id="observed-event-123", verified_source_receipt_ids=("source-receipt-1",),
        current_generation=enrollment.generation, ttl_seconds=30,
        parent_lineage_hash=hashlib.sha256(b"source lineage").hexdigest(),
        parent_sensitivity="private",
    )
    child = ledger.admit_child(
        admission, enrollment, node_id="node-1",
        parent_result_receipt_ids=(), current_generation=enrollment.generation,
    )

    service = object.__new__(AuthorityService)
    service.monotonic = now
    service.profile_generations = {"profile-1": "service-generation"}
    task_adapter = object.__new__(ResourceProfileTaskAdapter)
    backend = enrollment.backends["backend-1"]
    binding = backend.execution_binding
    task_adapter.selection = SimpleNamespace(
        resource_backend_id=backend.backend_id, resource_generation=enrollment.generation,
        profile_id=backend.profile_id, profile_generation=backend.profile_generation,
        native_package_id=backend.native_package_id,
        native_package_generation=backend.native_package_generation,
        process_enrollment_id=binding["process_enrollment_id"],
        process_generation=binding["process_generation"], operation_id=binding["operation_id"],
        process_start_target=binding["child_target_id"], child_capability=binding["child_capability"],
        task_body_recipe_id=binding["task_body_recipe_id"],
        task_request_schema_id=binding["task_request_schema_id"],
    )
    task_adapter.node_id = "node-1"
    task_adapter.launcher = service
    observed_handles = []
    observed_sources = []
    observed_tasks = []
    authority = None

    def launcher(handle, node_id):
        observed_handles.append(handle)
        authority.consume_task_handle(handle, node_id)
        observed_sources.append(authority.resolve_admitted_task_source(handle, node_id))
        observed_tasks.append(authority.resolve_admitted_task(handle, node_id))
        with pytest.raises(AuthorityDenied, match="one-use"):
            authority.resolve_admitted_task_source(handle, node_id)
        controller = authority.resolve_admitted_task_controller(handle, node_id)
        assert controller.pid == 1234 and controller.controller_kind == "worker"
        assert controller.subject_principal_id == enrollment.principal_id
        assert controller.service_generation_digest == service.service_generation_digest
        os.close(controller.pidfd)
        with pytest.raises(AuthorityDenied, match="forged, stale, or consumed"):
            authority.resolve_admitted_task_parent_context(handle, node_id, "caller-selected-context")
        parent = authority.resolve_admitted_task_parent_context(
            handle, node_id, observed_sources[-1].source_context_handle,
        )
        assert parent is parent_context
        with pytest.raises(AuthorityDenied, match="forged, stale, or consumed"):
            authority.resolve_admitted_task_parent_context(
                handle, node_id, observed_sources[-1].source_context_handle,
            )
        task = observed_tasks[-1]
        selection = {
            "schema": 1, "enrollment_id": task.process_enrollment_id,
            "generation": task.process_generation, "operation_id": task.operation_id,
            "parameters": {}, "admission_handle": handle.handle_id,
            "node_id": task.node_id, "task_payload_sha256": task.task_payload_sha256,
            "stdin_sha256": task.stdin_sha256, "stdin_size_bytes": task.stdin_size_bytes,
        }
        selection_bytes = json.dumps(selection, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode("ascii")
        assert authority.is_admitted_task_current(task, selection_bytes)
        assert authority.is_task_admission_current(task)
        assert not authority.is_admitted_task_current(replace(task), selection_bytes)
        assert not authority.is_task_admission_current(replace(task))
        stale_selection = dict(selection, admission_handle="forged-handle")
        stale_bytes = json.dumps(stale_selection, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True).encode("ascii")
        assert not authority.is_admitted_task_current(task, stale_bytes)
        original_clock = service.monotonic
        service.monotonic = lambda: handle.expires_monotonic + 1
        assert not authority.is_admitted_task_current(task, selection_bytes)
        service.monotonic = original_clock
        authority.start_task_handle(handle, node_id)
        return RootResourceProcessReceipt(
            job_id=handle.job_id, node_id=handle.node_id,
            backend_enrollment_id=handle.backend_enrollment_id, process_id="process-1",
            process_generation=handle.process_generation,
            native_package_generation=handle.native_package_generation,
            task_payload_sha256=handle.task_payload_sha256,
            parent_closure_digest=handle.parent_closure_digest,
            terminal_receipt_handle="terminal-1", result_capsule_handle="capsule-1",
            expires_monotonic=min(admission.expires_monotonic, now() + 20),
        )

    service.launch_resource_profile_task = launcher
    capsule_digest_resolved = []
    service.consume_resource_task_completion = lambda _receipt, *, cancelled: (
        pytest.fail("result capsule was consumed before its digest was resolved")
        if not capsule_digest_resolved else {
            "status": 200, "body": b'{"ok":true}', "headers": {"content-type": "application/json"},
            "receipt_id": "root-result-receipt", "result_fields": {"ok": True},
        }
    )
    service.resource_task_runner = SimpleNamespace(
        resolve_result_capsule_sha256=lambda _receipt: (
            capsule_digest_resolved.append(True) or hashlib.sha256(b'{"ok":true}').hexdigest()
        ),
    )
    authority = ResourceJobAuthority(
        service=service, enrollments={("demo", enrollment.generation): enrollment},
        ledger=ledger, selected_generation=lambda _resource: enrollment.generation,
        profile_task_adapters={("backend-1", "node-1"): task_adapter},
    )
    assert authority.handlers() == {}  # no service launcher/receipt consumer, no admission route
    service.resource_job_authority = authority
    service.rules = {
        ("hermes-resource-runtime", "resource.job.admit", authority._job_target(enrollment)):
            SimpleNamespace(recipient=None),
        ("hermes-resource-runtime", "resource.job.child.admit",
         authority._child_target(enrollment, enrollment.nodes[0])):
            SimpleNamespace(recipient=None),
    }
    service.handlers = {}
    registrations = authority.handlers()
    assert set(registrations) == {
        ("resource.job.admit", authority._job_target(enrollment)),
        ("resource.job.child.admit", authority._child_target(enrollment, enrollment.nodes[0])),
    }
    lineage = hashlib.sha256(b"source lineage").hexdigest()
    source_receipt = SourceReceipt(
        receipt_id="source-receipt-1", issuer_id="source-issuer", source_kind="schedule-event",
        principal_id=enrollment.principal_id, profile_id=enrollment.profile_id,
        namespace_id="namespace-1", uid=501, origin_id="schedule-1",
        process_generation=enrollment.profile_generation,
        payload_digest=hashlib.sha256(b"observed payload").hexdigest(),
        sensitivity=Sensitivity.PRIVATE, parent_lineage_hash=lineage,
        policy_revision="policy-1", recipient_ceiling=frozenset(),
        issued_at_monotonic=now(), monotonic_expires_at=now() + 30,
        signature="source-signature", enrollment_id="source-enrollment",
        native_process_identity="native-process", parent_receipt_ids=(), nonce="source-nonce",
    )
    import os

    class FixtureSourceObservers:
        def resolve_live_source_producer(self, receipt_id, *, profile_id, generation,
                                         native_process_identity, expires_monotonic):
            assert (receipt_id, profile_id, generation, native_process_identity) == (
                source_receipt.receipt_id, source_receipt.profile_id,
                source_receipt.process_generation, source_receipt.native_process_identity,
            )
            return SimpleNamespace(
                receipt_id=receipt_id, pid=1234, pidfd=os.open("/dev/null", os.O_RDONLY),
                uid=source_receipt.uid, profile_id=profile_id, generation=generation,
                expires_monotonic=expires_monotonic, authority_epoch="test-epoch",
                observer_enrollment_id="observer-1", source_action_id="source-action",
                channel_id="schedule-1",
                identity=SimpleNamespace(native_process_identity=native_process_identity),
                loaded_package_proof=SimpleNamespace(
                    role_artifact_id="native-role-artifact",
                    role_sha256=hashlib.sha256(b"native-role").hexdigest(),
                ),
            )

    service._source_receipt_handles = {"opaque-root-receipt-handle-00000001": source_receipt}
    service.source_observer_registry = FixtureSourceObservers()
    service.service_generation_digest = hashlib.sha256(b"service-generation").hexdigest()
    parent_context = HostContext(
        principal_id=enrollment.principal_id, profile_id=enrollment.profile_id,
        namespace_id="namespace-1", uid=501, purpose="resource-job-test", intent_id="intent-1",
        trace_id="trace-1", sensitivity=Sensitivity.PRIVATE, lineage_hash=lineage,
        policy_revision="policy-1", capabilities=frozenset({"hermes-resource-runtime"}),
        issued_at_monotonic=now(), monotonic_expires_at=now() + 30,
        nonce="context-nonce", grant_id="context-grant", signature="context-signature",
        source_receipts=(source_receipt,), generation="service-generation",
        operation="resource.job.admit",
    )
    service.authority_epoch = "test-epoch"
    service._verify_context_signature = lambda _context: None
    service._verify_source_receipt = lambda _receipt, _binding: None
    service._binding = lambda uid: SimpleNamespace(
        uid=uid, profile_id=enrollment.profile_id, principal_id=enrollment.principal_id,
        namespace_id="namespace-1",
    )
    service._assert_current_context = lambda _context, _binding, _uid: None
    service.selected_operation_resolver = lambda enrollment_id, generation, operation, operation_id: SimpleNamespace(
        operation=operation, operation_id=operation_id,
        target=binding["child_target_id"], enrollment_id=enrollment_id,
        generation=generation, profile_id=enrollment.profile_id,
        principal_id=enrollment.principal_id,
    )
    source_capsule_lineage = {
        "receipt_id": "source-receipt-1", "observer_enrollment_id": "observer-1",
        "event_record_id": "event-record-1", "invocation_id": "invocation-1",
        "source_kind": "schedule-event", "channel_id": "schedule-1",
        "source_action_id": "source-action", "profile_id": enrollment.profile_id,
        "principal_id": enrollment.principal_id, "namespace_id": "namespace-1",
        "generation": enrollment.profile_generation,
        "payload_sha256": hashlib.sha256(b"observed payload").hexdigest(),
        "parent_receipt_ids": (), "parent_closure_digest": canonical_digest(()),
        "issued_monotonic": now(), "expires_monotonic": now() + 30,
    }
    authority._event_fields_by_job[admission.job_id] = (bytearray(b"{}"), admission.expires_monotonic)
    authority._source_closures_by_job[admission.job_id] = (
        parent_context, (source_receipt,), source_capsule_lineage, admission.expires_monotonic)
    event = authority._event(admission.job_id, enrollment)
    result = authority._launch_profile_task(child, event, enrollment.backends["backend-1"], 30.0, lambda: False)
    assert result["receipt_id"] == "root-result-receipt"
    assert len(observed_handles) == 1
    assert observed_handles[0].attempt_index == 0
    assert observed_handles[0].task_payload == b'{"prompt":"perform the selected action"}'
    source = observed_sources[0]
    assert source.source_context_handle
    assert source.verified_source_receipt_handles == ("opaque-root-receipt-handle-00000001",)
    assert source.signed_receipt_wires == (json.dumps(
        source_receipt.to_wire(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8"),)
    assert source.lineage_hash == lineage
    assert source.sensitivity is Sensitivity.PRIVATE
    assert source.controller_binding_handle
    assert source.parent_closure_digest == observed_handles[0].parent_closure_digest
    assert observed_tasks[0].admission_id == observed_handles[0].child_admission_id
    assert observed_tasks[0].task_payload_sha256 == observed_handles[0].task_payload_sha256
    assert observed_tasks[0].task_payload_bytes == observed_handles[0].task_payload
    assert observed_tasks[0].stdin_sha256 == hashlib.sha256(b"perform the selected action").hexdigest()
    assert observed_tasks[0].stdin_size_bytes == len(b"perform the selected action")
    assert observed_tasks[0].source_context_handle == source.source_context_handle
    assert "task_payload" not in observed_tasks[0].__dataclass_fields__
    with pytest.raises(AuthorityDenied, match="forged, replayed, or consumed"):
        authority.consume_task_handle(observed_handles[0], "node-1")
    with pytest.raises(AuthorityDenied, match="consumed root handle"):
        authority.resolve_admitted_task_source(observed_handles[0], "node-1")


def test_root_event_admission_requires_exact_registry_handle_and_persists_once(tmp_path):
    import os
    import threading
    import time

    from hermes_installer.authority.resource_jobs import ResourceJobAuthority
    from hermes_installer.authority.resource_source_controllers import RootResourceEventHandle
    from hermes_installer.authority.types import (
        AuthorityDenied, HostContext, Sensitivity, SourceReceipt, canonical_digest,
    )
    from hermes_installer.registry.resource_jobs import ResourceJobLedger

    _row, _backend, _recipes, _scope, _validators, _issuer_row, _observer, enrollment = _fixture()
    now = time.monotonic
    lineage = hashlib.sha256(b"root lineage").hexdigest()
    payload = b'{"event_data":{"schedule_enrollment_id":"schedule-1"}}'
    receipt = SourceReceipt(
        receipt_id="root-receipt-1", issuer_id="observer-1", source_kind="schedule-event",
        principal_id=enrollment.principal_id, profile_id=enrollment.profile_id,
        namespace_id="namespace-1", uid=501, origin_id="schedule-1:event-1",
        process_generation=enrollment.profile_generation,
        payload_digest=hashlib.sha256(payload).hexdigest(), sensitivity=Sensitivity.PRIVATE,
        parent_lineage_hash=lineage, policy_revision="policy-1", recipient_ceiling=frozenset(),
        issued_at_monotonic=now(), monotonic_expires_at=now() + 30,
        signature="test-signature", enrollment_id="source-enrollment",
        native_process_identity="source-process", parent_receipt_ids=(), nonce="source-nonce",
    )
    context = HostContext(
        principal_id=enrollment.principal_id, profile_id=enrollment.profile_id,
        namespace_id="namespace-1", uid=501, purpose="resource-event", intent_id="event-intent",
        trace_id="event-trace", sensitivity=Sensitivity.PRIVATE, lineage_hash=lineage,
        policy_revision="policy-1", capabilities=frozenset({"hermes-resource-runtime"}),
        issued_at_monotonic=now(), monotonic_expires_at=now() + 30,
        nonce="context-nonce", grant_id="context-grant", signature="test-signature",
        source_receipts=(receipt,), final_payload_digest=canonical_digest(payload),
        generation=enrollment.profile_generation,
    )
    receipt_closure = canonical_digest(sorted(((receipt.receipt_id,
                                                canonical_digest(receipt.claims())),)))
    handle = RootResourceEventHandle(
        handle="opaque-root-event-handle", event_id="event-1", resource_id="demo",
        resource_generation=enrollment.generation, source_kind="schedule-event",
        source_observer_enrollment_id="observer-1", source_receipt_ids=(receipt.receipt_id,),
        parent_closure_digest=receipt_closure, payload_sha256=canonical_digest(payload),
        issued_monotonic=now(), expires_monotonic=now() + 30, authority_epoch="epoch-1",
    )
    record = SimpleNamespace(handle=handle, payload=payload, event_fields={"event_data": {
        "schedule_enrollment_id": "schedule-1"}}, parent_context=context,
        parent_receipts=(receipt,))
    controller_registry = SimpleNamespace(
        _resolve_event_node=lambda candidate, _node: (
            (record, enrollment, enrollment.nodes[0], enrollment.backends["backend-1"])
            if candidate is handle else (_ for _ in ()).throw(ValueError("not exact handle"))),
        _profile_binding=lambda _enrollment: object(),
        resolve_for_event=lambda _candidate, _node: SimpleNamespace(
            controller_kind="root-scheduler", uid=0, service_generation_digest=service.service_generation_digest,
            pidfd=os.open("/dev/null", os.O_RDONLY)),
    )
    issuer = SimpleNamespace(
        service=None,
        controller_registry=controller_registry,
        _require_live_selection=lambda _enrollment: None,
        _verify_source_closure=lambda _record, _enrollment, _binding, _now: (context, (receipt,)),
    )
    service = SimpleNamespace(
        monotonic=now, authority_epoch="epoch-1",
        service_generation_digest=hashlib.sha256(b"service").hexdigest(),
        profile_generations={enrollment.profile_id: enrollment.profile_generation},
        _verify_context_signature=lambda _context: None,
        _verify_source_receipt=lambda _receipt, _binding: None,
        _binding=lambda uid: SimpleNamespace(uid=uid),
        _assert_current_context=lambda _context, _binding, _uid: None,
    )
    issuer.service = service
    service.resource_event_context_issuer = issuer
    private = tmp_path / "private-store"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    ledger = ResourceJobLedger(private / "jobs.sqlite")
    authority = object.__new__(ResourceJobAuthority)
    authority.service = service
    authority.enrollments = {("demo", enrollment.generation): enrollment}
    authority.ledger = ledger
    authority.selected_generation = lambda _resource: enrollment.generation
    authority._event_lock = threading.RLock()
    authority._event_fields_by_job = {}
    authority._source_closures_by_job = {}
    authority._result_fields_by_job = {}
    authority._result_fields_expiry = {}
    authority._event_field_reservations = {}
    authority._event_field_bytes = 0
    authority._root_event_admissions = {}
    authority._root_admission_objects = {}
    authority._root_event_by_job = {}
    authority._root_source_context_by_job = {}
    authority._root_job_handles = {}
    authority._result_capsules_by_job = {}
    authority._root_result_closures = {}

    forged = replace(handle, event_id="forged-event")
    with pytest.raises(AuthorityDenied, match="stale or not selected"):
        authority.admit_root_resource_event(forged, timeout=20)
    admission = authority.admit_root_resource_event(handle, timeout=20)
    assert admission.resource_id == "demo"
    assert admission.generation == enrollment.generation
    assert authority._root_event_admissions[handle.handle] == (handle, admission)
    retained = authority._source_closures_by_job[admission.job_id]
    assert retained[0] is context and retained[1] == (receipt,)
    with pytest.raises(AuthorityDenied, match="already admitted"):
        authority.admit_root_resource_event(handle, timeout=20)
    with pytest.raises(AuthorityDenied, match="already admitted"):
        authority.admit_root_resource_event(forged, timeout=20)
