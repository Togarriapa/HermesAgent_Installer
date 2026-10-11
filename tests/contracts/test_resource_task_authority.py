from __future__ import annotations

import pytest
import hashlib
import json
from types import SimpleNamespace

from hermes_installer.authority.resource_task_authority import (
    RootResourceTaskAuthority,
    RootResourceTaskContext,
)
from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
from hermes_installer.authority.types import AuthorityDenied, Sensitivity


class _Policy:
    revision = "resource-task-policy"

    def allow_effect(self, *, context, rule, request_digest, retry_index):
        return True


def _service() -> AuthorityService:
    binding = PrincipalBinding(501, "principal:task", "profile:task", "namespace:task",
                               frozenset({"hermes-profile-invoke"}))
    rule = EffectRule("hermes-profile-invoke", "process.start", "process:task")
    return AuthorityService(
        signing_key=b"r" * 32, key_id="resource-task-test",
        bindings_by_uid={501: binding},
        rules={(rule.capability, rule.operation, rule.target): rule}, handlers={},
        policy=_Policy(), profile_generations={"profile:task": "generation:1"},
        service_generation_digest="a" * 64, monotonic=lambda: 2.0,
    )


def test_resource_task_context_signature_uses_its_own_domain():
    service = _service()
    fields = {
        "schema": 1, "context_id": "x" * 43, "admission_handle": "h" * 43,
        "admission_kind": "resource-child-task", "controller_proof_sha256": "b" * 64,
        "selected_principal_id": "principal:task", "selected_profile_id": "profile:task",
        "selected_generation": "generation:1", "selected_namespace_identity": "namespace:task",
        "selected_subject_uid": 501, "selected_subject_gid": 501,
        "service_generation_digest": "a" * 64, "role": "resource-profile-task",
        "action": "start", "enrollment_id": "process-enrollment:task",
        "operation_id": "hermes-resource-profile-task-v1", "operation": "process.start",
        "capability": "hermes-profile-invoke", "target": "process:task",
        "source_closure_sha256": "c" * 64, "sensitivity": Sensitivity.PRIVATE.value,
        "recipient": None, "policy_revision": "policy:task", "authority_epoch": "epoch:task",
        "issued_monotonic": 1.0, "expires_monotonic": 10.0, "nonce": "d" * 64,
        "job_handle": "h" * 43, "node_id": "node:task", "child_admission_id": "j" * 43,
        "retry_index": 0, "task_payload_sha256": "e" * 64, "stdin_sha256": "f" * 64,
        "stdin_size_bytes": 5,
    }
    context = RootResourceTaskContext(
        **{**fields, "sensitivity": Sensitivity.PRIVATE},
        signature=service._sign_root_selected("root-resource-task-context-v1", fields),
    )
    issuer = RootResourceTaskAuthority(service, object(), object())
    issuer._verify("root-resource-task-context-v1", context.claims(), context.signature)
    with pytest.raises(AuthorityDenied):
        issuer._verify("root-selected-service-context-v1", context.claims(), context.signature)


def test_resource_task_context_rejects_public_source_and_oversized_lease():
    service = _service()
    claims = {
        "schema": 1, "context_id": "x" * 43, "admission_handle": "h" * 43,
        "admission_kind": "resource-child-task", "controller_proof_sha256": "b" * 64,
        "selected_principal_id": "principal:task", "selected_profile_id": "profile:task",
        "selected_generation": "generation:1", "selected_namespace_identity": "namespace:task",
        "selected_subject_uid": 501, "selected_subject_gid": 501,
        "service_generation_digest": "a" * 64, "role": "resource-profile-task",
        "action": "start", "enrollment_id": "process-enrollment:task",
        "operation_id": "hermes-resource-profile-task-v1", "operation": "process.start",
        "capability": "hermes-profile-invoke", "target": "process:task",
        "source_closure_sha256": "c" * 64, "sensitivity": Sensitivity.PUBLIC,
        "recipient": None, "policy_revision": "policy:task", "authority_epoch": "epoch:task",
        "issued_monotonic": 1.0, "expires_monotonic": 40.0, "nonce": "d" * 64,
        "job_handle": "h" * 43, "node_id": "node:task", "child_admission_id": "j" * 43,
        "retry_index": 0, "task_payload_sha256": "e" * 64, "stdin_sha256": "f" * 64,
        "stdin_size_bytes": 5,
    }
    signature = service._sign_root_selected("root-resource-task-context-v1", {
        **{key: value.value if isinstance(value, Sensitivity) else value for key, value in claims.items()}
    })
    with pytest.raises(AuthorityDenied):
        RootResourceTaskContext(**claims, signature=signature)


def test_root_resource_task_start_is_consumed_once_and_bound_to_exact_input():
    from hermes_installer.authority.resource_task_authority import RootResourceTaskAuthority
    from hermes_installer.registry.resource_jobs import (
        ResourceChildAdmission, RootAdmittedTask, RootAdmittedTaskSource,
        RootResourceJobAdmissionHandle, RootTaskController,
    )
    from hermes_installer.registry.resource_backends import SelectedResourceProfileTask

    prompt = "hello"
    task_payload = json.dumps({"prompt": prompt}, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
    stdin = prompt.encode("utf-8")
    task = RootAdmittedTask(
        schema=1, admission_id="child-admission", job_id="job-task", node_id="node-task",
        backend_enrollment_id="backend-task", resource_generation="resource-gen",
        process_enrollment_id="process-enrollment:task", process_generation="generation:1",
        native_package_id="package:task", native_package_generation="package-gen",
        operation_id="hermes-resource-profile-task-v1", task_body_recipe_id="body:task",
        task_request_schema_id="schema:task", task_payload_sha256=hashlib.sha256(task_payload).hexdigest(),
        task_payload_bytes=task_payload, stdin_sha256=hashlib.sha256(stdin).hexdigest(),
        stdin_size_bytes=len(stdin), parent_closure_digest="c" * 64,
        deadline_monotonic=9.0, source_context_handle="source-context-handle-1234567890123456",
    )
    handle = RootResourceJobAdmissionHandle(
        handle_id="h" * 43, job_id=task.job_id, node_id=task.node_id,
        child_admission_id="j" * 43, attempt_index=0, backend_enrollment_id="backend-task",
        resource_generation="resource-gen", profile_id="profile:task", profile_generation="generation:1",
        native_package_id="package:task", native_package_generation="package-gen",
        process_enrollment_id="process-enrollment:task", process_generation="generation:1",
        operation_id=task.operation_id, child_target_id="process:task",
        child_capability="hermes-profile-invoke", task_body_recipe_id="body:task",
        task_request_schema_id="schema:task", task_payload=task_payload,
        task_payload_sha256=task.task_payload_sha256, parent_closure_digest="c" * 64,
        expires_monotonic=8.0,
    )
    source = RootAdmittedTaskSource(
        source_context_handle=task.source_context_handle,
        verified_source_receipt_handles=("r" * 43,), signed_receipt_wires=(b"{}",),
        sensitivity=Sensitivity.PRIVATE, lineage_hash="d" * 64, recipient_ceiling=(),
        principal_id="principal:task", profile_id="profile:task", namespace_id="namespace:task",
        parent_closure_digest="c" * 64, controller_binding_handle="controller:task",
        expires_monotonic=8.0,
    )
    child = ResourceChildAdmission(
        admission_id="j" * 43, job_id=task.job_id, resource_id="resource:task",
        generation="resource-gen", node_id=task.node_id, retry_index=0, action_id="action:task",
        effect="resource.cron.run", target="resource:task", recipient=None,
        canonical_payload_sha256="e" * 64, payload=b"{}", source_receipt_ids=("r" * 43,),
        parent_result_receipt_ids=(),
    )
    controller = RootTaskController(
        schema=1, controller_handle="controller:task", controller_kind="root-scheduler",
        controller_role_artifact_id="role:task", controller_role_sha256="f" * 64,
        pid=42, pidfd=0, uid=0, identity="pidfd-identity", controller_profile_id=None,
        controller_generation="controller-gen", source_receipt_id=None,
        subject_principal_id="principal:task", subject_profile_id="profile:task",
        subject_namespace_id="namespace:task", service_generation_digest="a" * 64,
        expires_monotonic=8.0,
    )
    profile = SimpleNamespace(profile_id="profile:task", generation="generation:1",
                              enrollment_id="process-enrollment:task", owner_uid=501,
                              owner_gid=501, principal_id="principal:task",
                              operation_targets={"process.start": "process:task"})
    execution = SelectedResourceProfileTask(
        resource_backend_id="backend-task", resource_id="resource:task",
        resource_generation="resource-gen", profile_id="profile:task", principal_id="principal:task",
        profile_generation="generation:1", process_enrollment_id="process-enrollment:task",
        process_generation="generation:1", operation_id=task.operation_id,
        process_start_target="process:task", native_package_id="package:task",
        native_package_generation="package-gen", task_body_recipe_id="body:task",
        task_request_schema_id="schema:task", process_operation=object(), launch_recipe=object(),
        native_package=object(), task_body_recipe=object(), source_profile_id="hermes",
        home_binding_id="m" * 64,
    )

    class _HomeBindingIssuer:
        def __init__(self):
            self._binding_seal = object()

        def verify_current(self, binding, selection):
            return binding is selected_home_binding and selection is execution

    home_issuer = _HomeBindingIssuer()
    selected_home_binding = object.__new__(__import__(
        "hermes_installer.authority.native_profile_task_homes",
        fromlist=["RootSelectedResourceTaskHomeBinding"],
    ).RootSelectedResourceTaskHomeBinding)
    object.__setattr__(selected_home_binding, "_issuer", home_issuer)
    object.__setattr__(selected_home_binding, "_seal", home_issuer._binding_seal)
    object.__setattr__(selected_home_binding, "source_profile_id", "hermes")
    object.__setattr__(selected_home_binding, "home_binding_id", "m" * 64)
    object.__setattr__(selected_home_binding, "binding_handle", "home-binding-handle")
    object.__setattr__(selected_home_binding, "binding_sha256", "b" * 64)
    class Jobs:
        def resolve_task_child_admission(self, got, node):
            assert got is handle and node == task.node_id
            return child
        def verify_admitted_root_task_controller(self, got, got_task, got_source, got_controller):
            return got is handle and got_task is task and got_source is source and got_controller is controller
        def is_admitted_task_current(self, got, payload=None):
            return got is task and (payload is None or payload == expected_payload)
        def is_admitted_task_controller_current(self, got, node, got_controller):
            return got is handle and node == task.node_id and got_controller is controller

    service = _service()
    service.process_effect_handler = SimpleNamespace(profiles={"profile:task": profile})
    service.selected_operation_resolver = lambda enrollment, generation, operation, operation_id: SimpleNamespace(
        target="process:task", profile_id="profile:task", generation="generation:1",
        enrollment_id="process-enrollment:task")
    jobs = Jobs()
    authority = RootResourceTaskAuthority(service, jobs, object())
    service_generation = service.service_generation_digest
    expected_payload = authority.selection_payload(handle, task, execution, profile,
                                                    selected_home_binding)
    grant = authority.issue_root_resource_task_start(
        child, source, task, execution, task_handle=handle, controller=controller,
        selected_home_binding=selected_home_binding,
    )
    proof = authority.consume_root_resource_task_start(
        grant, child, source, task, expected_payload, task_handle=handle,
    )
    assert authority.verify_consumed_start(
        proof, expected_payload, task_admission=task, selected_profile=profile,
    )
    with pytest.raises(AuthorityDenied):
        authority.consume_root_resource_task_start(
            grant, child, source, task, expected_payload, task_handle=handle,
        )
    assert service.service_generation_digest == service_generation
