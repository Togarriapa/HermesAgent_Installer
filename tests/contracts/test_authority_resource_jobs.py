from __future__ import annotations

import hashlib
from types import SimpleNamespace

from hermes_installer.authority.resource_jobs import index_resource_job_records
from hermes_installer.registry.resource_jobs import (
    ResourceBackendEnrollment,
    ResourceBodyRecipe,
    ResourceBodyRecipeField,
    ResourceJobEnrollment,
    ResourceJobNode,
    ResourceScopeBinding,
    ResourceValidator,
)

_EXECUTION_BINDING = {
    "process_enrollment_id": "process-profile",
    "process_generation": "process-generation",
    "operation_id": "hermes-resource-profile-task-v1",
    "native_package_id": "package-1",
    "native_package_generation": "service-generation",
    "child_operation": "process.start",
    "child_target_id": "process:profile:chat",
    "child_capability": "hermes-process-runtime",
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
    enrollment = ResourceJobEnrollment(
        "demo", "crons", generation, True, "profile-1", "principal-1", "consent-1",
        frozenset({"run-action"}), frozenset({node.target}), frozenset(),
        frozenset({"schedule-event"}), "schedule-1", (node,), 1, 1, 30, 2048, 10,
        enrollment_id="profile-enrollment-1", source_issuer_channel_id="source-channel",
        observer_enrollment_id="observer-1", body_recipes={"recipe": recipe},
        backends={"backend-1": backend}, profile_generation="service-generation",
        scope_bindings={"scope-binding": scope_record},
        validators={"run-action": validator_record},
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
    }
    raw_recipe = {
        "id": "recipe", "schema_id": "request-schema", "source_artifact_id": "recipe-artifact",
        "source_sha256": handler_digest,
        "output_fields": [{"name": "action", "source": "literal", "value": "run",
                           "validator_id": "run-action"}],
        "scope_bindings": [], "maximum_bytes": 512,
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
    )
    return row, raw_backend, raw_recipe, scope, validator, source_issuer, observer, enrollment


def test_protected_resource_job_index_requires_exact_active_source_backend_and_recipe_joins():
    from hermes_installer.authority.resource_jobs import (
        parse_resource_backend_records,
        parse_resource_body_recipes,
        parse_resource_scope_binding_records,
        parse_resource_validator_records,
    )

    row, raw_backend, raw_recipe, raw_scope, raw_validator, issuer, observer, expected = _fixture()
    backends = parse_resource_backend_records([raw_backend])
    recipes = parse_resource_body_recipes([raw_recipe])
    scopes = parse_resource_scope_binding_records([raw_scope])
    validators = parse_resource_validator_records([raw_validator])
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
