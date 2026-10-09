from __future__ import annotations

from types import SimpleNamespace
import unittest

from hermes_installer.registry.resource_backends import (
    HERMES_RESOURCE_PROFILE_TASK_OPERATION,
    PINNED_HERMES_REVISION,
    RESOURCE_PROFILE_TASK_HANDLER_ARTIFACT_ID,
    ResourceProfileTaskUnavailable,
    resource_profile_task_handler_sha256,
    resolve_resource_profile_task,
)
from hermes_installer.registry.resource_jobs import (
    ResourceBackendEnrollment,
    ResourceBodyRecipe,
    ResourceBodyRecipeField,
    ResourceValidator,
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


if __name__ == "__main__":
    unittest.main()
