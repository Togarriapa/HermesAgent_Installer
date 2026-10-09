from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch
import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from hermes_installer.artifacts import ArtifactCatalog, ArtifactSpec

from hermes_installer.registry.resource_backends import (
    HERMES_RESOURCE_PROFILE_TASK_OPERATION,
    PINNED_HERMES_REVISION,
    RESOURCE_PROFILE_TASK_HANDLER_ARTIFACT_ID,
    ResourceProfileTaskUnavailable,
    resource_profile_task_handler_sha256,
    resolve_resource_profile_task,
    ResourceProfileTaskAdapter,
    build_resource_profile_task_adapters,
    RootArtifactValidator,
    HERMES_TASK_TEXT_RESULT_SCHEMA_ID,
    HERMES_TASK_TEXT_RESULT_VALIDATOR_ID,
    HERMES_TASK_TEXT_RESULT_ARTIFACT_ID,
    HERMES_TASK_TEXT_RESULT_SCHEMA_SHA256,
)
from hermes_installer.registry.resource_jobs import (
    ResourceBackendEnrollment,
    ResourceBodyRecipe,
    ResourceBodyRecipeField,
    ResourceJobEnrollment,
    ResourceJobNode,
    ResourceScopeBinding,
    ResourceValidator,
    RootResourceJobAdmissionHandle,
)


_EXECUTION_BINDING = {
    "process_enrollment_id": "process-enrollment",
    "process_generation": "process-generation",
    "operation_id": HERMES_RESOURCE_PROFILE_TASK_OPERATION,
    "native_package_id": "native-package",
    "native_package_generation": "package-generation",
    "child_operation": "process.start",
    "child_target_id": "hermes-profile-invoke:process-enrollment",
    "child_capability": "hermes-profile-invoke",
    "task_body_recipe_id": "task-prompt-recipe",
    "task_request_schema_id": "hermes-profile-query-v1",
}


class _ProtectedBindings:
    def __init__(self, *, target: str | None = None, package_generation: str = "package-generation",
                 package_revision: str = PINNED_HERMES_REVISION, argv: tuple[str, ...] | None = None):
        selected_target = target or _EXECUTION_BINDING["child_target_id"]
        self.operation = SimpleNamespace(
            operation="process.start", operation_id=HERMES_RESOURCE_PROFILE_TASK_OPERATION,
            target=selected_target, enrollment_id="process-enrollment",
            generation="process-generation", profile_id="selected-profile",
            principal_id="selected-principal", service_uid=2000,
        )
        self.recipe = SimpleNamespace(
            parameter_schema=SimpleNamespace(schema_id="process-params"),
            recipe=SimpleNamespace(
                parameter_schema_id="process-params", stdin_mode="bounded-typed-bytes",
                argv_recipe=tuple({"literal": value} for value in (argv or (
                    "-m", "hermes_cli.main", "chat", "--query-file", "-", "--oneshot", "--quiet",
                ))),
            ),
            operation_id=HERMES_RESOURCE_PROFILE_TASK_OPERATION,
            process_start_target=selected_target,
        )
        self.package = SimpleNamespace(
            profile_id="selected-profile", generation=package_generation,
            package_id="native-package", source_revision=package_revision,
        )
        self.enrollment_catalog = self

    def resolve_selected_operation(self, enrollment_id, generation, operation, operation_id):
        self.assertions = (enrollment_id, generation, operation, operation_id)
        return self.operation

    def resolve_launch_recipe(self, enrollment_id, generation, operation_id):
        return self.recipe

    def resolve_native_package(self, package_id, generation):
        return self.package


def _selected(*, target: str | None = None, package_generation: str = "package-generation",
              package_revision: str = PINNED_HERMES_REVISION, argv: tuple[str, ...] | None = None):
    backend = ResourceBackendEnrollment(
        backend_id="backend-1", resource_id="daily", profile_id="selected-profile",
        principal_id="selected-principal", generation="resource-generation",
        consent_revision="consent-1", source_issuer_channel_id="source-issuer",
        observer_enrollment_id="observer-1", native_package_id="native-package",
        native_package_generation="package-generation",
        handler_artifact_id=RESOURCE_PROFILE_TASK_HANDLER_ARTIFACT_ID,
        handler_sha256=resource_profile_task_handler_sha256(),
        approved_action_ids=frozenset({"run"}), operation="resource.cron.run",
        target_id="resource:daily:run:resource-generation", recipient=None,
        credential_reference_ids=frozenset(), request_schema_id="outer-request-v1",
        result_schema_id="outer-result-v1", body_recipe_id="outer-recipe",
        scope_binding_id="scope-1", maximum_request_bytes=262_144,
        maximum_response_bytes=1024 * 1024, maximum_seconds=30,
        profile_generation="profile-generation", execution_binding=_EXECUTION_BINDING,
    )
    recipe = ResourceBodyRecipe(
        recipe_id="task-prompt-recipe", schema_id="hermes-profile-query-v1",
        source_artifact_id="task-recipe-artifact", source_sha256="a" * 64,
        output_fields=(ResourceBodyRecipeField("prompt", "literal", "review the event", "prompt-text"),),
        scope_bindings=(), maximum_bytes=262_144,
    )
    validator = ResourceValidator(
        "prompt-text", "utf8-string", 262_144, None, None, None, None, None,
    )
    bindings = _ProtectedBindings(target=target, package_generation=package_generation,
                                  package_revision=package_revision, argv=argv)
    selection = resolve_resource_profile_task(
        backend, recipe, protected_bindings=bindings, validators={"prompt-text": validator},
    )
    return selection, backend, recipe, validator, bindings


class ResourceProfileBackendTests(unittest.TestCase):
    def test_resolves_exact_protected_process_package_and_task_recipe(self):
        selection, _, _, _, bindings = _selected()
        self.assertEqual(selection.operation_id, HERMES_RESOURCE_PROFILE_TASK_OPERATION)
        self.assertEqual(selection.process_start_target, _EXECUTION_BINDING["child_target_id"])
        self.assertEqual(selection.native_package_generation, "package-generation")
        self.assertEqual(selection.task_body_recipe_id, "task-prompt-recipe")
        self.assertEqual(bindings.assertions, (
            "process-enrollment", "process-generation", "process.start",
            HERMES_RESOURCE_PROFILE_TASK_OPERATION,
        ))

    def test_rejects_wrong_selected_process_target(self):
        with self.assertRaisesRegex(ResourceProfileTaskUnavailable, "does not join"):
            _selected(target="hermes-profile-invoke:other")

    def test_rejects_native_package_generation_or_source_drift(self):
        with self.assertRaisesRegex(ResourceProfileTaskUnavailable, "native package"):
            _selected(package_generation="stale-package-generation")
        with self.assertRaisesRegex(ResourceProfileTaskUnavailable, "pinned Hermes"):
            _selected(package_revision="1" * 40)

    def test_rejects_argv_prompt_or_non_stdin_task_recipe(self):
        with self.assertRaisesRegex(ResourceProfileTaskUnavailable, "pinned Hermes stdin"):
            _selected(argv=("--profile", "worker", "-m", "hermes_cli.main", "chat",
                            "--query-file", "-", "--oneshot", "--quiet"))

    def test_handler_identity_is_bound_to_this_adapter_source(self):
        self.assertRegex(resource_profile_task_handler_sha256(), r"^[0-9a-f]{64}$")

    def test_selected_text_result_requires_active_backend_and_actual_pinned_artifact(self):
        schema_bytes = (
            b'{"additional_fields":false,"fields":[{"max_utf8_bytes":1048000,'
            b'"min_utf8_bytes":1,"name":"text","required":true,"type":"string"},'
            b'{"name":"stdout_sha256","required":true,"type":"sha256"},'
            b'{"maximum":1048000,"minimum":1,"name":"stdout_size_bytes",'
            b'"required":true,"type":"integer"}],"id":"hermes-task-text-result-v1",'
            b'"max_bytes":1048576,"schema":1,"type":"object"}'
        )
        self.assertEqual(hashlib.sha256(schema_bytes).hexdigest(), HERMES_TASK_TEXT_RESULT_SCHEMA_SHA256)
        backend = ResourceBackendEnrollment(
            backend_id="result-backend", resource_id="daily", profile_id="selected-profile",
            principal_id="selected-principal", generation="a" * 64,
            consent_revision="consent-1", source_issuer_channel_id="source-issuer",
            observer_enrollment_id="observer-1", native_package_id="native-package",
            native_package_generation="package-generation",
            handler_artifact_id="handler", handler_sha256="b" * 64,
            approved_action_ids=frozenset({"run"}), operation="resource.cron.run",
            target_id="resource:daily:run:generation", recipient=None,
            credential_reference_ids=frozenset(), request_schema_id="request-v1",
            result_schema_id=HERMES_TASK_TEXT_RESULT_SCHEMA_ID, body_recipe_id="recipe",
            scope_binding_id="scope", maximum_request_bytes=4096,
            maximum_response_bytes=1_048_576, maximum_seconds=30,
        )
        validator = ResourceValidator(
            HERMES_TASK_TEXT_RESULT_VALIDATOR_ID, "bounded-json", 262_144,
            None, None, None, HERMES_TASK_TEXT_RESULT_ARTIFACT_ID,
            HERMES_TASK_TEXT_RESULT_SCHEMA_SHA256,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "staging"
            root.mkdir(mode=0o700)
            path = root / "objects" / HERMES_TASK_TEXT_RESULT_ARTIFACT_ID / HERMES_TASK_TEXT_RESULT_SCHEMA_SHA256
            path.mkdir(parents=True, mode=0o700)
            schema_path = path / "schema.json"
            schema_path.write_bytes(schema_bytes)
            schema_path.chmod(0o444)
            catalog = ArtifactCatalog.from_records((ArtifactSpec(
                artifact_id=HERMES_TASK_TEXT_RESULT_ARTIFACT_ID, version="1.0.0",
                sha256=HERMES_TASK_TEXT_RESULT_SCHEMA_SHA256,
                source_url="https://schemas.example.invalid/hermes-task-text-result-v1.json",
                max_bytes=65_536, size_bytes=len(schema_bytes), filename="schema.json",
            ),))
            selected = RootArtifactValidator(
                backend_enrollments={backend.backend_id: backend},
                validators={validator.validator_id: validator}, artifact_catalog=catalog,
                staging_root=root, expected_uid=os.getuid(),
            ).resolve_selected_result(
                backend.backend_id, HERMES_TASK_TEXT_RESULT_SCHEMA_ID, backend.generation,
            )
            result = selected.validate_stdout(b"Hermes finished\n")
            self.assertEqual(result["text"], "Hermes finished\n")
            self.assertEqual(result["stdout_size_bytes"], len(b"Hermes finished\n"))
            self.assertEqual(result["stdout_sha256"], hashlib.sha256(b"Hermes finished\n").hexdigest())
            with self.assertRaises(ResourceProfileTaskUnavailable):
                selected.validate_stdout(b"bad\x00output")
            with self.assertRaises(ResourceProfileTaskUnavailable):
                RootArtifactValidator(
                    backend_enrollments={backend.backend_id: backend}, validators={},
                    artifact_catalog=catalog, staging_root=root, expected_uid=os.getuid(),
                ).resolve_selected_result(backend.backend_id, "unreviewed-json", backend.generation)

    def test_composition_builds_immutable_adapter_map_from_exact_selected_joins(self):
        from hermes_installer.authority.service import AuthorityService

        from dataclasses import replace

        _, backend, task_recipe, validator, bindings = _selected()
        generation = hashlib.sha256(b"resource-generation").hexdigest()
        backend = replace(backend, generation=generation)
        outer_recipe = ResourceBodyRecipe(
            recipe_id="outer-recipe", schema_id="outer-request-v1",
            source_artifact_id="outer-source", source_sha256="c" * 64,
            output_fields=(ResourceBodyRecipeField("event", "literal", "selected", "event-text"),),
            scope_bindings=(), maximum_bytes=1024,
        )
        event_validator = ResourceValidator("event-text", "utf8-string", 128, None, None, None, None, None)
        scope = ResourceScopeBinding(
            scope_binding_id="scope-1", resource_id="daily", profile_id="selected-profile",
            principal_id="selected-principal", resource_generation=generation,
            profile_generation="profile-generation", backend_enrollment_id="backend-1",
            fixed_fields={}, credential_reference_ids=frozenset(), recipient=None,
        )
        node = ResourceJobNode(
            node_id="run-node", action_id="run", effect=backend.operation,
            target=backend.target_id, recipient=None, payload=outer_recipe.template_payload(),
            request_schema_id=backend.request_schema_id, body_recipe_id=outer_recipe.recipe_id,
            backend_enrollment_id=backend.backend_id, result_schema_id=backend.result_schema_id,
            scope_binding_id=backend.scope_binding_id,
        )
        enrollment = ResourceJobEnrollment(
            resource_id="daily", kind="crons", generation=generation,
            selected_enabled=True, profile_id=backend.profile_id, principal_id=backend.principal_id,
            consent_revision=backend.consent_revision, approved_action_ids=frozenset({"run"}),
            fixed_target_ids=frozenset({backend.target_id}), recipient_scope=frozenset(),
            source_policy=frozenset({"static-context"}), schedule_or_route_id="daily-run",
            nodes=(node,), max_children=2, max_concurrency=1, max_runtime_seconds=60,
            max_payload_bytes=4096, max_replay_entries=10, enrollment_id="job-enrollment",
            source_issuer_channel_id=backend.source_issuer_channel_id,
            observer_enrollment_id=backend.observer_enrollment_id,
            backend_enrollment_id=backend.backend_id, profile_generation=backend.profile_generation,
            backends={backend.backend_id: backend}, body_recipes={
                outer_recipe.recipe_id: outer_recipe, task_recipe.recipe_id: task_recipe,
            }, scope_bindings={scope.scope_binding_id: scope},
            validators={validator.validator_id: validator, event_validator.validator_id: event_validator},
        )
        service = object.__new__(AuthorityService)
        with patch.object(AuthorityService, "launch_resource_profile_task", create=True):
            adapters = build_resource_profile_task_adapters(
                {(enrollment.resource_id, enrollment.generation): enrollment},
                protected_bindings=bindings, authority_service=service,
            )
        self.assertEqual(tuple(adapters), (("backend-1", "run-node"),))
        self.assertIsInstance(adapters[("backend-1", "run-node")], ResourceProfileTaskAdapter)
        with self.assertRaises(TypeError):
            adapters[("forged", "node")] = object()

    def test_adapter_forwards_only_exact_live_root_admission_handle(self):
        from hermes_installer.authority.service import AuthorityService

        selection, backend, _, _, _ = _selected()
        payload = b'{"prompt":"review the event"}'
        handle = RootResourceJobAdmissionHandle(
            handle_id="handle-1", job_id="job-1", node_id="node-1",
            child_admission_id="attempt-1", attempt_index=0,
            backend_enrollment_id=backend.backend_id,
            resource_generation=backend.generation, profile_id=backend.profile_id,
            profile_generation=backend.profile_generation,
            native_package_id=backend.native_package_id,
            native_package_generation=backend.native_package_generation,
            process_enrollment_id=_EXECUTION_BINDING["process_enrollment_id"],
            process_generation=_EXECUTION_BINDING["process_generation"],
            operation_id=HERMES_RESOURCE_PROFILE_TASK_OPERATION,
            child_target_id=_EXECUTION_BINDING["child_target_id"],
            child_capability=_EXECUTION_BINDING["child_capability"],
            task_body_recipe_id=_EXECUTION_BINDING["task_body_recipe_id"],
            task_request_schema_id=_EXECUTION_BINDING["task_request_schema_id"],
            task_payload=payload, task_payload_sha256=hashlib.sha256(payload).hexdigest(),
            parent_closure_digest="b" * 64, expires_monotonic=time.monotonic() + 60,
        )
        launcher = object.__new__(AuthorityService)
        with patch.object(AuthorityService, "launch_resource_profile_task", create=True,
                          return_value={"started": True}) as launch:
            adapter = ResourceProfileTaskAdapter(selection, node_id="node-1", launcher=launcher)
            self.assertEqual(adapter.launch_resource_profile_task(handle, "node-1"), {"started": True})
            launch.assert_called_once_with(handle, "node-1")

    def test_adapter_rejects_mismatched_or_expired_root_handle_before_authority(self):
        from dataclasses import replace
        from hermes_installer.authority.service import AuthorityService

        selection, backend, _, _, _ = _selected()
        payload = b'{"prompt":"review the event"}'
        base = RootResourceJobAdmissionHandle(
            handle_id="handle-1", job_id="job-1", node_id="node-1",
            child_admission_id="attempt-1", attempt_index=0,
            backend_enrollment_id=backend.backend_id,
            resource_generation=backend.generation, profile_id=backend.profile_id,
            profile_generation=backend.profile_generation,
            native_package_id=backend.native_package_id,
            native_package_generation=backend.native_package_generation,
            process_enrollment_id=_EXECUTION_BINDING["process_enrollment_id"],
            process_generation=_EXECUTION_BINDING["process_generation"],
            operation_id=HERMES_RESOURCE_PROFILE_TASK_OPERATION,
            child_target_id=_EXECUTION_BINDING["child_target_id"],
            child_capability=_EXECUTION_BINDING["child_capability"],
            task_body_recipe_id=_EXECUTION_BINDING["task_body_recipe_id"],
            task_request_schema_id=_EXECUTION_BINDING["task_request_schema_id"],
            task_payload=payload, task_payload_sha256=hashlib.sha256(payload).hexdigest(),
            parent_closure_digest="b" * 64, expires_monotonic=time.monotonic() + 60,
        )
        launcher = object.__new__(AuthorityService)
        with patch.object(AuthorityService, "launch_resource_profile_task", create=True) as launch:
            adapter = ResourceProfileTaskAdapter(selection, node_id="node-1", launcher=launcher)
            for bad in (replace(base, backend_enrollment_id="other-backend"),
                        replace(base, process_generation="stale-generation"),
                        replace(base, expires_monotonic=time.monotonic() - 1)):
                with self.assertRaises(ResourceProfileTaskUnavailable):
                    adapter.launch_resource_profile_task(bad, "node-1")
            launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
