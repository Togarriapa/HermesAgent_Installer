"""Root authority handlers for selected Resources jobs (RB07 / RB-T08).

The handler factory is intentionally opt-in: it accepts only typed records
already returned by the root protected-generation loader. It never interprets
worker resource IDs, receipt IDs, action graphs, URLs, or credentials as
enrollment. Every child is dispatched through the service's exact protected
``(capability, operation, target)`` rule with a newly minted one-use grant.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import secrets
import threading
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from hermes_installer.registry.resource_jobs import (
    ResourceChildAdmission,
    ResourceCredentialBinding,
    ResourceBackendEnrollment,
    ResourceBodyRecipe,
    ResourceBodyRecipeField,
    ResourceBodyRecipeScope,
    ResourceJobAdmission,
    ResourceJobDenied,
    ResourceJobEnrollment,
    ResourceJobLedger,
    ResourceJobNode,
    RootAdmittedTask,
    RootAdmittedTaskSource,
    _ident,
    RootResourceJobAdmissionHandle,
    RootResourceNodeResultClosure,
    RootTaskController,
    ResourceScopeBinding,
    ResourceValidator,
)
from .service import AuthorityService, EffectAuthorization
from .types import AuthorityDenied, HostContext, Sensitivity, canonical_digest

_RESOURCE_EFFECT_BY_KIND = {
    "crons": "resource.cron.run",
    "webhooks": "resource.webhook.run",
    "channels": "resource.channel.run",
    "bundles": "resource.bundle.node.run",
}
_HEX64 = __import__("re").compile(r"[0-9a-f]{64}\Z")
_SOURCE_KIND_BY_KIND = {
    "crons": "schedule-event",
    "webhooks": "webhook-event",
    "channels": "native-input",
}
_CAPABILITY = "hermes-resource-runtime"

_BACKEND_FIELDS = {
    "id", "resource_id", "profile_id", "principal_id", "generation", "consent_revision",
    "source_issuer_channel_id", "observer_enrollment_id", "native_package_id",
    "native_package_generation", "handler_artifact_id", "handler_sha256",
    "approved_action_ids", "operation", "target_id", "recipient",
    "credential_reference_ids", "request_schema_id", "result_schema_id", "body_recipe_id",
    "scope_binding_id", "maximum_request_bytes", "maximum_response_bytes", "maximum_seconds",
    "profile_generation", "execution_binding",
    "credential_bindings",
}
_BODY_RECIPE_FIELDS = {
    "id", "schema_id", "source_artifact_id", "source_sha256", "output_fields",
    "scope_bindings", "maximum_bytes",
}
_SCOPE_BINDING_FIELDS = {
    "id", "resource_id", "profile_id", "principal_id", "resource_generation",
    "profile_generation", "backend_enrollment_id", "fixed_fields",
    "credential_reference_ids", "recipient",
}
_RESOURCE_VALIDATOR_FIELDS = {
    "id", "kind", "maximum_bytes", "minimum", "maximum", "allowed_values",
    "schema_artifact_id", "schema_sha256",
}


def parse_resource_backend_records(records: Any) -> Mapping[str, ResourceBackendEnrollment]:
    """Parse the digest-bound active service-generation backend rows."""
    if not isinstance(records, (list, tuple)) or len(records) > 692:
        raise AuthorityDenied("resource.backend", "protected backend catalog is malformed")
    result: dict[str, ResourceBackendEnrollment] = {}
    for raw in records:
        if not isinstance(raw, Mapping) or set(raw) != _BACKEND_FIELDS:
            raise AuthorityDenied("resource.backend", "protected backend row fields are invalid")
        try:
            if (not isinstance(raw["approved_action_ids"], list)
                    or any(not isinstance(item, str) for item in raw["approved_action_ids"])
                    or not isinstance(raw["credential_reference_ids"], list)
                    or any(not isinstance(item, str) for item in raw["credential_reference_ids"])
                    or not isinstance(raw["credential_bindings"], list)
                    or len(raw["credential_bindings"]) > 16
                    or any(not isinstance(item, Mapping)
                           or set(item) != {"source_placeholder", "credential_reference_id", "usage"}
                           for item in raw["credential_bindings"])):
                raise ValueError
            backend = ResourceBackendEnrollment(
                backend_id=raw["id"], resource_id=raw["resource_id"],
                profile_id=raw["profile_id"], principal_id=raw["principal_id"],
                generation=raw["generation"], consent_revision=raw["consent_revision"],
                source_issuer_channel_id=raw["source_issuer_channel_id"],
                observer_enrollment_id=raw["observer_enrollment_id"],
                native_package_id=raw["native_package_id"],
                native_package_generation=raw["native_package_generation"],
                handler_artifact_id=raw["handler_artifact_id"],
                handler_sha256=raw["handler_sha256"],
                approved_action_ids=frozenset(raw["approved_action_ids"]),
                operation=raw["operation"], target_id=raw["target_id"],
                recipient=raw["recipient"],
                credential_reference_ids=frozenset(raw["credential_reference_ids"]),
                request_schema_id=raw["request_schema_id"],
                result_schema_id=raw["result_schema_id"],
                body_recipe_id=raw["body_recipe_id"],
                scope_binding_id=raw["scope_binding_id"],
                maximum_request_bytes=raw["maximum_request_bytes"],
                maximum_response_bytes=raw["maximum_response_bytes"],
                maximum_seconds=raw["maximum_seconds"],
                profile_generation=raw["profile_generation"],
                execution_binding=raw["execution_binding"],
                credential_bindings=tuple(ResourceCredentialBinding(**item)
                                           for item in raw["credential_bindings"]),
            )
        except (TypeError, ValueError, ResourceJobDenied):
            raise AuthorityDenied("resource.backend", "protected backend row is invalid") from None
        if backend.backend_id in result:
            raise AuthorityDenied("resource.backend", "protected backend ID is duplicated")
        result[backend.backend_id] = backend
    return MappingProxyType(result)


def parse_resource_body_recipes(records: Any) -> Mapping[str, ResourceBodyRecipe]:
    """Parse immutable body recipes without treating recipes as executable code."""
    if not isinstance(records, (list, tuple)) or len(records) > 4096:
        raise AuthorityDenied("resource.recipe", "protected body recipe catalog is malformed")
    result: dict[str, ResourceBodyRecipe] = {}
    for raw in records:
        if not isinstance(raw, Mapping) or set(raw) != _BODY_RECIPE_FIELDS:
            raise AuthorityDenied("resource.recipe", "protected body recipe fields are invalid")
        outputs = raw["output_fields"]
        scopes = raw["scope_bindings"]
        if (not isinstance(outputs, list) or not isinstance(scopes, list)
                or any(not isinstance(item, Mapping)
                       or set(item) != {"name", "source", "value", "validator_id"}
                       for item in outputs)
                or any(not isinstance(item, Mapping)
                       or set(item) != {"name", "scope_binding_id", "field", "validator_id"}
                       for item in scopes)):
            raise AuthorityDenied("resource.recipe", "protected body recipe contents are malformed")
        try:
            recipe = ResourceBodyRecipe(
                recipe_id=raw["id"], schema_id=raw["schema_id"],
                source_artifact_id=raw["source_artifact_id"], source_sha256=raw["source_sha256"],
                output_fields=tuple(ResourceBodyRecipeField(
                    item["name"], item["source"], item["value"], item["validator_id"]
                ) for item in outputs),
                scope_bindings=tuple(ResourceBodyRecipeScope(
                    item["name"], item["scope_binding_id"], item["field"], item["validator_id"]
                ) for item in scopes), maximum_bytes=raw["maximum_bytes"],
            )
        except (TypeError, ValueError, ResourceJobDenied):
            raise AuthorityDenied("resource.recipe", "protected body recipe is invalid") from None
        if recipe.recipe_id in result:
            raise AuthorityDenied("resource.recipe", "protected body recipe ID is duplicated")
        result[recipe.recipe_id] = recipe
    return MappingProxyType(result)


def parse_resource_scope_binding_records(records: Any) -> Mapping[str, ResourceScopeBinding]:
    """Parse exact active scope rows; never resolve credentials from their IDs."""
    if not isinstance(records, (list, tuple)) or len(records) > 4096:
        raise AuthorityDenied("resource.scope", "protected scope catalog is malformed")
    result: dict[str, ResourceScopeBinding] = {}
    for raw in records:
        if not isinstance(raw, Mapping) or set(raw) != _SCOPE_BINDING_FIELDS:
            raise AuthorityDenied("resource.scope", "protected scope row fields are invalid")
        try:
            if (not isinstance(raw["fixed_fields"], Mapping)
                    or not isinstance(raw["credential_reference_ids"], list)
                    or any(not isinstance(item, str) for item in raw["credential_reference_ids"])):
                raise ValueError
            scope = ResourceScopeBinding(
                scope_binding_id=raw["id"], resource_id=raw["resource_id"],
                profile_id=raw["profile_id"], principal_id=raw["principal_id"],
                resource_generation=raw["resource_generation"],
                profile_generation=raw["profile_generation"],
                backend_enrollment_id=raw["backend_enrollment_id"],
                fixed_fields=raw["fixed_fields"],
                credential_reference_ids=frozenset(raw["credential_reference_ids"]),
                recipient=raw["recipient"],
            )
        except (TypeError, ValueError, ResourceJobDenied):
            raise AuthorityDenied("resource.scope", "protected scope row is invalid") from None
        if scope.scope_binding_id in result:
            raise AuthorityDenied("resource.scope", "protected scope ID is duplicated")
        result[scope.scope_binding_id] = scope
    return MappingProxyType(result)


def parse_resource_validator_records(records: Any) -> Mapping[str, ResourceValidator]:
    """Parse the closed validator catalog; strict JSON schema artifacts remain a root join."""
    if not isinstance(records, (list, tuple)) or len(records) > 4096:
        raise AuthorityDenied("resource.validator", "protected validator catalog is malformed")
    result: dict[str, ResourceValidator] = {}
    for raw in records:
        if not isinstance(raw, Mapping) or set(raw) != _RESOURCE_VALIDATOR_FIELDS:
            raise AuthorityDenied("resource.validator", "protected validator row fields are invalid")
        try:
            allowed = raw["allowed_values"]
            if allowed is not None and not isinstance(allowed, list):
                raise ValueError
            validator = ResourceValidator(
                validator_id=raw["id"], kind=raw["kind"],
                maximum_bytes=raw["maximum_bytes"], minimum=raw["minimum"],
                maximum=raw["maximum"],
                allowed_values=tuple(allowed) if allowed is not None else None,
                schema_artifact_id=raw["schema_artifact_id"],
                schema_sha256=raw["schema_sha256"],
            )
        except (TypeError, ValueError, ResourceJobDenied):
            raise AuthorityDenied("resource.validator", "protected validator row is invalid") from None
        if validator.validator_id in result:
            raise AuthorityDenied("resource.validator", "protected validator ID is duplicated")
        result[validator.validator_id] = validator
    return MappingProxyType(result)


def resource_job_enrollment_from_record(
        record: Mapping[str, Any], *, backend_enrollments: Mapping[str, ResourceBackendEnrollment],
        body_recipes: Mapping[str, ResourceBodyRecipe],
        scope_bindings: Mapping[str, ResourceScopeBinding],
        validators: Mapping[str, ResourceValidator]) -> ResourceJobEnrollment:
    """Parse one exact root-protected RB07 selected-job record."""
    fields = {
        "resource_id", "kind", "selected_enabled", "profile_id", "principal_id",
        "generation", "consent_revision", "approved_action_ids", "fixed_target_ids",
        "credential_reference_ids", "recipient_scope", "source_policy",
        "schedule_or_route_id", "max_children", "max_concurrency",
        "max_runtime_seconds", "max_payload_bytes", "max_replay_entries", "enrollment_id",
        "source_issuer_channel_id", "observer_enrollment_id",
        "approved_dag",
    }
    if not isinstance(record, Mapping) or set(record) != fields:
        raise AuthorityDenied("resource.enrollment", "protected resource job record fields are invalid")
    approved_dag = record["approved_dag"]
    if (not isinstance(approved_dag, Mapping) or set(approved_dag) != {"dag_sha256", "nodes"}
            or not isinstance(approved_dag["nodes"], list)):
        raise AuthorityDenied("resource.enrollment", "selected DAG digest record is malformed")
    raw_nodes = approved_dag["nodes"]
    if not isinstance(raw_nodes, list) or not raw_nodes or len(raw_nodes) > 256:
        raise AuthorityDenied("resource.enrollment", "protected resource job DAG is empty or oversized")
    nodes: list[ResourceJobNode] = []
    for raw in raw_nodes:
        if not isinstance(raw, Mapping) or set(raw) != {
            "node_id", "resource_id", "action_id", "operation", "target_id", "recipient",
            "request_schema_id", "body_recipe_id", "depends_on", "maximum_attempts",
            "backend_enrollment_id", "result_schema_id", "scope_binding_id",
        }:
            raise AuthorityDenied("resource.enrollment", "protected resource job node fields are invalid")
        try:
            if raw["resource_id"] != record["resource_id"]:
                raise ValueError
            recipe = raw["body_recipe_id"]
            recipe_record = body_recipes.get(recipe)
            if not isinstance(recipe_record, ResourceBodyRecipe):
                raise ValueError
            payload = recipe_record.template_payload()
            dependencies = raw["depends_on"]
            if not isinstance(dependencies, list):
                raise ValueError
            nodes.append(ResourceJobNode(
                node_id=raw["node_id"], action_id=raw["action_id"], effect=raw["operation"],
                target=raw["target_id"], recipient=raw["recipient"], payload=payload,
                depends_on=tuple(dependencies), maximum_attempts=raw["maximum_attempts"],
                request_schema_id=raw["request_schema_id"], body_recipe_id=recipe,
                backend_enrollment_id=raw["backend_enrollment_id"],
                result_schema_id=raw["result_schema_id"],
                scope_binding_id=raw["scope_binding_id"],
            ))
        except (TypeError, ValueError, ResourceJobDenied):
            raise AuthorityDenied("resource.enrollment", "protected resource job node is invalid") from None
    backend_ids = {node.backend_enrollment_id for node in nodes}
    if not backend_ids <= set(backend_enrollments):
        raise AuthorityDenied("resource.enrollment", "selected DAG node backend is absent")
    profile_generations = {backend_enrollments[item].profile_generation for item in backend_ids}
    if len(profile_generations) != 1:
        raise AuthorityDenied("resource.enrollment", "selected DAG spans service profile generations")
    required_recipe_ids = {node.body_recipe_id for node in nodes}
    for backend_id in backend_ids:
        binding = backend_enrollments[backend_id].execution_binding
        if binding is not None:
            required_recipe_ids.add(binding["task_body_recipe_id"])
    if not required_recipe_ids <= set(body_recipes):
        raise AuthorityDenied("resource.enrollment", "selected node or task body recipe is absent")
    try:
        for name in ("approved_action_ids", "fixed_target_ids", "credential_reference_ids",
                     "recipient_scope", "source_policy"):
            if not isinstance(record[name], list) or any(not isinstance(item, str) for item in record[name]):
                raise ValueError
        if not isinstance(record["approved_dag"]["dag_sha256"], str):
            raise ValueError
        enrollment = ResourceJobEnrollment(
            resource_id=record["resource_id"], kind=record["kind"],
            generation=record["generation"], selected_enabled=record["selected_enabled"],
            profile_id=record["profile_id"], principal_id=record["principal_id"],
            consent_revision=record["consent_revision"],
            approved_action_ids=frozenset(record["approved_action_ids"]),
            fixed_target_ids=frozenset(record["fixed_target_ids"]),
            recipient_scope=frozenset(record["recipient_scope"]),
            source_policy=frozenset(record["source_policy"]),
            schedule_or_route_id=record["schedule_or_route_id"], nodes=tuple(nodes),
            max_children=record["max_children"], max_concurrency=record["max_concurrency"],
            max_runtime_seconds=record["max_runtime_seconds"],
            max_payload_bytes=record["max_payload_bytes"],
            max_replay_entries=record["max_replay_entries"],
            enrollment_id=record["enrollment_id"],
            source_issuer_channel_id=record["source_issuer_channel_id"],
            observer_enrollment_id=record["observer_enrollment_id"],
            backend_enrollment_id="",
            credential_reference_ids=frozenset(record["credential_reference_ids"]),
            backend=None,
            body_recipes={recipe_id: body_recipes[recipe_id] for recipe_id in required_recipe_ids},
            backends={node.backend_enrollment_id: backend_enrollments[node.backend_enrollment_id]
                      for node in nodes},
            profile_generation=next(iter(profile_generations)),
            scope_bindings={backend.scope_binding_id: scope_bindings[backend.scope_binding_id]
                            for backend in (backend_enrollments[item] for item in backend_ids)},
                validators={validator_id: validators[validator_id] for recipe in
                        (body_recipes[recipe_id] for recipe_id in required_recipe_ids)
                        for validator_id in ({field.validator_id for field in recipe.output_fields}
                                             | {field.validator_id for field in recipe.scope_bindings})
                        if validator_id in validators},
        )
    except (TypeError, ValueError, ResourceJobDenied):
        raise AuthorityDenied("resource.enrollment", "protected resource job enrollment is invalid") from None
    expected_effect = _RESOURCE_EFFECT_BY_KIND[enrollment.kind]
    for node in enrollment.nodes:
        expected_target = f"resource:{enrollment.resource_id}:{node.action_id}:{enrollment.generation}"
        if node.effect != expected_effect or node.target != expected_target:
            raise AuthorityDenied("resource.enrollment", "resource node is outside its fixed action route")
    if approved_dag["dag_sha256"] != enrollment.dag_sha256:
        raise AuthorityDenied("resource.enrollment", "approved DAG digest does not match its canonical nodes")
    return enrollment


def index_resource_job_records(
        records: Any, *, backend_enrollments: Mapping[str, ResourceBackendEnrollment],
        body_recipes: Mapping[str, ResourceBodyRecipe],
        scope_bindings: Mapping[str, ResourceScopeBinding],
        validators: Mapping[str, ResourceValidator], source_issuers: Any,
        source_observers: Any) -> Mapping[tuple[str, str], ResourceJobEnrollment]:
    """Build an immutable index from strictly joined root digest-verified records.

    Rows without an exact active backend, source issuer, and root observer join
    are omitted, so unavailable resources cannot enter handler registration.
    """
    if not isinstance(records, (list, tuple)) or len(records) > 692:
        raise AuthorityDenied("resource.enrollment", "protected resource job catalog is malformed")
    source_issuers = _index_catalog(source_issuers, "issuer_channel_id", "source issuer")
    source_observers = _index_catalog(source_observers, "observer_enrollment_id", "source observer")
    result: dict[tuple[str, str], ResourceJobEnrollment] = {}
    for raw in records:
        try:
            enrollment = resource_job_enrollment_from_record(
                raw, backend_enrollments=backend_enrollments, body_recipes=body_recipes,
                scope_bindings=scope_bindings, validators=validators)
            issuer = source_issuers.get(enrollment.source_issuer_channel_id)
            observer = source_observers.get(enrollment.observer_enrollment_id)
            backends = tuple(enrollment.backends.values())
            if (issuer is None or observer is None or not backends
                    or getattr(issuer, "issuer_channel_id", None) != enrollment.source_issuer_channel_id
                    or getattr(issuer, "observer_enrollment_id", None) != enrollment.observer_enrollment_id
                    or getattr(issuer, "generation", None) != enrollment.profile_generation
                    or getattr(issuer, "producer_profile_id", None) != enrollment.profile_id
                    or getattr(observer, "observer_enrollment_id", None) != enrollment.observer_enrollment_id
                    or getattr(observer, "channel_id", None) != enrollment.source_issuer_channel_id
                    or getattr(observer, "profile_id", None) != enrollment.profile_id
                    or getattr(observer, "principal_id", None) != enrollment.principal_id
                    or getattr(observer, "generation", None) != enrollment.profile_generation
                    or getattr(observer, "origin_id", None) != enrollment.schedule_or_route_id
                    or getattr(observer, "capture_schema_id", None) != getattr(issuer, "capture_schema_id", None)
                    or getattr(observer, "source_action_id", None) not in getattr(issuer, "source_action_ids", ())
                    or getattr(observer, "source_kind", None) not in enrollment.source_policy
                    or any(backend.profile_generation != enrollment.profile_generation
                           for backend in backends)):
                continue
            enrollment = replace(
                enrollment,
                source_capture_schema_id=getattr(issuer, "capture_schema_id", ""),
                source_action_ids=frozenset(getattr(issuer, "source_action_ids", ())),
                source_parent_channels=frozenset(getattr(issuer, "allowed_parent_channels", ())),
            )
        except (AuthorityDenied, KeyError, TypeError, ValueError):
            # A single malformed/unjoined resource is unavailable without
            # invalidating unrelated digest-verified enrollments.
            continue
        key = (enrollment.resource_id, enrollment.generation)
        if key in result:
            raise AuthorityDenied("resource.enrollment", "resource job generation is duplicated")
        result[key] = enrollment
    return MappingProxyType(result)


def _index_catalog(records: Any, key_field: str, name: str) -> Mapping[str, Any]:
    """Accept the loader's immutable row tuple or an already keyed root catalog."""
    if isinstance(records, Mapping):
        return records
    if not isinstance(records, (tuple, list)) or len(records) > 4096:
        raise AuthorityDenied("resource.enrollment", f"protected {name} catalog is malformed")
    indexed: dict[str, Any] = {}
    for record in records:
        key = getattr(record, key_field, None)
        if not isinstance(key, str) or not key or key in indexed:
            raise AuthorityDenied("resource.enrollment", f"protected {name} catalog has invalid identities")
        indexed[key] = record
    return MappingProxyType(indexed)


@dataclass(frozen=True, slots=True)
class _JobEvent:
    enrollment: ResourceJobEnrollment
    admission: ResourceJobAdmission
    source_receipt_ids: tuple[str, ...]
    sensitivity: Sensitivity
    lineage_hash: str
    event_fields: Mapping[str, Any]
    parent_results: Mapping[str, tuple[str, Mapping[str, Any]]]
    parent_context: HostContext
    source_receipts: tuple[Any, ...]
    source_capsule_lineage: Mapping[str, Any]

    def __post_init__(self) -> None:
        if (not isinstance(self.source_receipt_ids, tuple)
                or not isinstance(self.source_receipts, tuple)
                or self.parent_context.source_receipts != self.source_receipts
                or tuple(sorted(item.receipt_id for item in self.source_receipts))
                != tuple(sorted(self.source_receipt_ids))
                or not isinstance(self.parent_context, HostContext)):
            raise AuthorityDenied("resource.source", "retained job event source closure is invalid")
        object.__setattr__(self, "event_fields", _freeze_mapping(self.event_fields))
        object.__setattr__(self, "parent_results", _freeze_parent_results(self.parent_results))
        object.__setattr__(self, "source_capsule_lineage", _freeze_mapping(self.source_capsule_lineage))


@dataclass(frozen=True, slots=True)
class _RootResultCapsuleBinding:
    """Authority-retained binding from one completed DAG node to its capsule."""

    node_id: str
    admission_id: str
    receipt_id: str
    capsule_handle: str
    capsule_sha256: str
    backend_enrollment_id: str
    resource_generation: str
    service_generation_digest: str
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class RootResourceProcessReceipt:
    """Validated wire receipt from the root-only profile task launcher.

    This DTO does not prove a task completed. The terminal and result-capsule
    handles must still be resolved by the root-owned process/result services.
    """

    job_id: str
    node_id: str
    backend_enrollment_id: str
    process_id: str
    process_generation: str
    native_package_generation: str
    task_payload_sha256: str
    parent_closure_digest: str
    terminal_receipt_handle: str
    result_capsule_handle: str
    expires_monotonic: float

    @classmethod
    def from_wire(cls, value: Any) -> "RootResourceProcessReceipt":
        fields = {
            "schema", "job_id", "node_id", "backend_enrollment_id", "process_id",
            "process_generation", "native_package_generation", "task_payload_sha256",
            "parent_closure_digest", "terminal_receipt_handle", "result_capsule_handle",
            "expires_monotonic",
        }
        if (not isinstance(value, Mapping) or set(value) != fields
                or type(value["schema"]) is not int or value["schema"] != 1):
            raise AuthorityDenied("resource.process_receipt", "root process receipt fields are invalid")
        try:
            receipt = cls(**{key: value[key] for key in fields - {"schema"}})
        except (TypeError, ValueError):
            raise AuthorityDenied("resource.process_receipt", "root process receipt is malformed") from None
        for name in ("job_id", "node_id", "backend_enrollment_id", "process_id",
                     "process_generation", "native_package_generation",
                     "terminal_receipt_handle", "result_capsule_handle"):
            if not isinstance(getattr(receipt, name), str) or not getattr(receipt, name):
                raise AuthorityDenied("resource.process_receipt", "root process receipt identity is invalid")
        for name in ("task_payload_sha256", "parent_closure_digest"):
            digest = getattr(receipt, name)
            if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise AuthorityDenied("resource.process_receipt", "root process receipt digest is invalid")
        if (isinstance(receipt.expires_monotonic, bool)
                or not isinstance(receipt.expires_monotonic, (int, float))
                or not math.isfinite(receipt.expires_monotonic)):
            raise AuthorityDenied("resource.process_receipt", "root process receipt expiry is invalid")
        return receipt

    def assert_bound(self, *, job_id: str, node_id: str, backend: ResourceBackendEnrollment,
                     payload: bytes, parent_closure_digest: str, now: float,
                     job_expires_monotonic: float) -> None:
        if (self.job_id != job_id or self.node_id != node_id
                or self.backend_enrollment_id != backend.backend_id
                or backend.execution_binding is None
                or self.process_generation != backend.execution_binding["process_generation"]
                or self.native_package_generation != backend.native_package_generation
                or self.task_payload_sha256 != hashlib.sha256(payload).hexdigest()
                or self.parent_closure_digest != parent_closure_digest
                or not now < self.expires_monotonic <= job_expires_monotonic):
            raise AuthorityDenied("resource.process_receipt", "root process receipt does not bind this selected task")


class ResourceJobAuthority:
    """Concrete fixed admission and child-effect handlers for root assembly.

    The constructor requires an ``AuthorityService`` and ``ResourceJobLedger``
    created by root assembly. The service verifies signatures and consumes the
    caller's source receipts before invoking these handlers. Thus receipt IDs
    below are extracted only from that verified authorization, never from a
    ``WebhookReceipt`` or worker-supplied receipt list.
    """

    def __init__(self, *, service: AuthorityService,
                 enrollments: Mapping[tuple[str, str], ResourceJobEnrollment],
                 ledger: ResourceJobLedger,
                 selected_generation: Callable[[str], str] | None = None,
                 profile_task_adapters: Mapping[tuple[str, str], Any] | None = None,
                 capability: str = _CAPABILITY):
        if not isinstance(service, AuthorityService) or not isinstance(ledger, ResourceJobLedger):
            raise ValueError("root authority service and private resource job ledger are required")
        if not callable(selected_generation):
            raise ValueError("a root protected selected-generation resolver is required")
        if not isinstance(enrollments, Mapping) or any(
                key != (value.resource_id, value.generation)
                or not isinstance(value, ResourceJobEnrollment)
                for key, value in enrollments.items()):
            raise ValueError("root-selected immutable resource enrollments are required")
        if capability != _CAPABILITY:
            raise ValueError("resource job capability is fixed")
        self.service = service
        self.enrollments = MappingProxyType(dict(enrollments))
        self.ledger = ledger
        self.selected_generation = selected_generation
        adapters = dict(profile_task_adapters or {})
        if adapters:
            try:
                from hermes_installer.registry.resource_backends import ResourceProfileTaskAdapter
            except ImportError:
                raise ValueError("fixed Hermes resource profile-task adapter is unavailable") from None
            if any(not isinstance(key, tuple) or len(key) != 2
                   or not all(isinstance(part, str) and part for part in key)
                   or not isinstance(value, ResourceProfileTaskAdapter)
                   for key, value in adapters.items()):
                raise ValueError("root selected profile-task adapter map is malformed")
        self.profile_task_adapters = MappingProxyType(adapters)
        self._task_handle_lock = threading.RLock()
        self._task_handles: dict[str, tuple[Any, ResourceChildAdmission, ResourceJobEnrollment, _JobEvent]] = {}
        self._running_task_handles: dict[str, tuple[Any, ResourceChildAdmission, ResourceJobEnrollment, _JobEvent]] = {}
        self._resolved_task_dtos: dict[str, RootAdmittedTask] = {}
        self._source_resolved_handles: set[str] = set()
        self._source_context_handles: dict[str, str] = {}
        self._task_controller_bindings: dict[str, tuple[str, Any]] = {}
        self._controller_resolved_handles: set[str] = set()
        self._resolved_controller_evidence: dict[str, tuple[Any, ...]] = {}
        self._parent_context_resolved_handles: set[str] = set()
        self._event_lock = threading.RLock()
        self._event_fields_by_job: dict[str, tuple[bytearray, float]] = {}
        self._source_closures_by_job: dict[str, tuple[HostContext, tuple[Any, ...], Mapping[str, Any], float]] = {}
        self._result_fields_by_job: dict[str, dict[str, tuple[str, bytearray]]] = {}
        self._result_fields_expiry: dict[str, float] = {}
        self._result_capsules_by_job: dict[str, dict[str, _RootResultCapsuleBinding]] = {}
        self._root_result_closures: dict[str, tuple[RootResourceNodeResultClosure,
                                                    Mapping[str, Mapping[str, Any]]]] = {}
        self._root_job_handles: dict[str, str] = {}
        self._event_field_reservations: dict[str, bytearray] = {}
        self._event_field_bytes = 0
        # Root ingress admission is intentionally separate from the worker
        # resource.job.admit RPC. These maps bind the exact registry-minted
        # event and returned admission objects; neither IDs nor DTO contents
        # alone are bearer authority.
        self._root_event_admissions: dict[str, tuple[Any, ResourceJobAdmission]] = {}
        self._root_admission_objects: dict[str, ResourceJobAdmission] = {}
        self._root_event_by_job: dict[str, Any] = {}
        self._root_source_context_by_job: dict[str, str] = {}
        self._root_task_controller_tokens: dict[str, str] = {}

    def admit_root_resource_event(
        self, root_event_handle: Any, *, timeout: float = 30.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> ResourceJobAdmission:
        """Durably admit one already captured, root-verified resource event.

        This is an in-process producer API. It accepts only the exact opaque
        handle retained by this AuthorityService's root controller registry;
        workers cannot call it over RPC or supply event fields, receipt IDs,
        resource identity, controller evidence, or a DAG.
        """
        from .resource_source_controllers import RootResourceEventHandle

        if (type(root_event_handle) is not RootResourceEventHandle
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0.1 <= timeout <= 600
                or not callable(cancelled)):
            raise AuthorityDenied("resource.event", "root resource event admission request is malformed")
        issuer = getattr(self.service, "resource_event_context_issuer", None)
        controller_registry = getattr(issuer, "controller_registry", None)
        if controller_registry is None or getattr(issuer, "service", None) is not self.service:
            raise AuthorityDenied("resource.event", "root resource event registry is unavailable")
        # Attach only this exact job authority to the same root event registry
        # that authenticated the capture. Runtime composition may have done
        # this already; an unrelated authority is never replaced.
        attach_jobs = getattr(controller_registry, "attach_resource_job_authority", None)
        if not callable(attach_jobs):
            raise AuthorityDenied("resource.admission", "root event registry has no job-authority binding")
        bound_jobs = getattr(controller_registry, "_resource_job_authority", None)
        if bound_jobs is None:
            try:
                attach_jobs(self)
            except Exception:
                # A concurrent exact attachment is harmless; a different
                # authority or an invalid interface is not.
                if getattr(controller_registry, "_resource_job_authority", None) is not self:
                    raise AuthorityDenied("resource.admission", "root job authority attachment failed") from None
        elif bound_jobs is not self:
            raise AuthorityDenied("resource.admission", "another root job authority owns this event registry")
        key = (root_event_handle.resource_id, root_event_handle.resource_generation)
        enrollment = self.enrollments.get(key)
        if enrollment is None:
            raise AuthorityDenied("resource.selection", "root event is outside the active job enrollment")
        with self._event_lock:
            self._prune_root_admissions_locked(self.service.monotonic())
            prior = self._root_event_admissions.get(root_event_handle.handle)
            if prior is not None:
                raise AuthorityDenied("resource.event_replay", "root event was already admitted")
            if len(self._root_event_admissions) >= min(4096, self.ledger.max_jobs):
                raise AuthorityDenied("resource.capacity", "root admission handle store is full")

        # Resolve through the owning controller registry, which checks object
        # identity, event epoch/deadline, selected source role, observer,
        # resource generation, backend, and node membership.
        try:
            first_node = enrollment.nodes[0]
            record, selected, _node, _backend = controller_registry._resolve_event_node(
                root_event_handle, first_node.node_id)
        except Exception:
            raise AuthorityDenied("resource.event", "root event is stale or not selected") from None
        if selected is not enrollment:
            raise AuthorityDenied("resource.selection", "event and job authorities selected different generations")
        if cancelled():
            raise AuthorityDenied("resource.event", "root event was cancelled before admission")

        # The event issuer rechecks current consent, signed HostContext,
        # complete source receipt signatures/closure and source-origin joins.
        # Never derive these facts from the worker admission handler.
        try:
            issuer._require_live_selection(enrollment)
            context, receipts = issuer._verify_source_closure(
                record, enrollment, controller_registry._profile_binding(enrollment),
                self.service.monotonic(),
            )
            self.service._verify_context_signature(context)
            binding = self.service._binding(context.uid)
            self.service._assert_current_context(context, binding, context.uid)
            for receipt in receipts:
                self.service._verify_source_receipt(receipt, binding)
        except Exception:
            raise AuthorityDenied("resource.source", "root event source closure or consent is stale") from None
        expected_ids = tuple(sorted(receipt.receipt_id for receipt in receipts))
        closure_digest = canonical_digest(sorted(
            (receipt.receipt_id, canonical_digest(receipt.claims())) for receipt in receipts
        ))
        if (context.source_receipts != receipts
                or expected_ids != tuple(sorted(root_event_handle.source_receipt_ids))
                or context.source_receipts != record.parent_receipts
                or record.handle is not root_event_handle
                or canonical_digest(record.payload) != root_event_handle.payload_sha256
                or closure_digest != root_event_handle.parent_closure_digest
                or context.profile_id != enrollment.profile_id
                or context.principal_id != enrollment.principal_id
                or context.generation != enrollment.profile_generation):
            raise AuthorityDenied("resource.source", "root event payload or authenticated closure changed")

        # Revalidate live controller custody before the durable state change.
        # The duplicated PIDFD is immediately closed; per-node issuer calls
        # acquire their own fresh lease later.
        import os
        controller = None
        try:
            controller = controller_registry.resolve_for_event(
                root_event_handle, first_node.node_id)
            if (controller.controller_kind not in {"root-scheduler", "root-webhook", "root-channel"}
                    or controller.uid != 0
                    or controller.service_generation_digest != getattr(
                        self.service, "service_generation_digest", None)):
                raise AuthorityDenied("resource.controller", "root ingress controller lease is invalid")
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("resource.controller", "root ingress controller is stale") from None
        finally:
            if controller is not None:
                try:
                    os.close(controller.pidfd)
                except OSError:
                    pass

        now = self.service.monotonic()
        current_generation = self._resource_generation(enrollment)
        if current_generation != root_event_handle.resource_generation:
            raise AuthorityDenied("resource.selection", "resource generation changed before admission")
        deadline = min(
            [root_event_handle.expires_monotonic, context.monotonic_expires_at]
            + [receipt.monotonic_expires_at for receipt in receipts]
        )
        remaining = deadline - now
        ttl = min(enrollment.max_runtime_seconds, max(1, int(timeout)), int(remaining))
        if remaining < 1 or ttl < 1:
            raise AuthorityDenied("resource.source", "root event has no usable execution lease")

        # Root-authenticated source fields are derived only from the retained
        # event record. Bounded reservation prevents memory exhaustion while
        # admission commits; the SQLite event key makes retry/replay durable.
        reservation = self._reserve_event_fields(record.event_fields)
        try:
            admission = self.ledger.admit_job(
                enrollment, event_id=root_event_handle.event_id,
                verified_source_receipt_ids=expected_ids,
                current_generation=current_generation, ttl_seconds=ttl,
                parent_lineage_hash=context.lineage_hash,
                parent_sensitivity=context.sensitivity.value,
            )
        except ResourceJobDenied as exc:
            self._discard_event_field_reservation(reservation)
            raise AuthorityDenied("resource.admission", str(exc)) from None
        except Exception:
            self._discard_event_field_reservation(reservation)
            raise

        lineage = MappingProxyType({
            "root_event_handle": root_event_handle.handle,
            "event_id": root_event_handle.event_id,
            "source_kind": root_event_handle.source_kind,
            "observer_enrollment_id": root_event_handle.source_observer_enrollment_id,
            "payload_sha256": root_event_handle.payload_sha256,
            "parent_closure_digest": root_event_handle.parent_closure_digest,
            "parent_receipt_ids": expected_ids,
            "issued_monotonic": root_event_handle.issued_monotonic,
            "expires_monotonic": root_event_handle.expires_monotonic,
        })
        self._promote_event_fields(
            reservation, admission.job_id, admission.expires_monotonic,
            source_closure=(context, tuple(receipts), lineage, admission.expires_monotonic),
        )
        with self._event_lock:
            if root_event_handle.handle in self._root_event_admissions:
                # This should be prevented by the ledger's unique event key;
                # fail closed if in-memory state disagrees after a race.
                self._discard_job_event_fields(admission.job_id)
                raise AuthorityDenied("resource.event_replay", "root event admission was already retained")
            self._root_event_admissions[root_event_handle.handle] = (root_event_handle, admission)
            self._root_admission_objects[admission.job_id] = admission
            self._root_event_by_job[admission.job_id] = root_event_handle
            self._root_source_context_by_job[admission.job_id] = secrets.token_urlsafe(32)
            self._root_job_handles[admission.job_id] = secrets.token_urlsafe(32)
        bind_job = getattr(controller_registry, "bind_admitted_job", None)
        try:
            if not callable(bind_job):
                raise AuthorityDenied("resource.admission", "root event registry cannot bind durable admission")
            bind_job(root_event_handle, admission)
        except Exception:
            self.ledger.cancel_job(admission.job_id, current_generation=enrollment.generation)
            self._discard_job_event_fields(admission.job_id)
            raise AuthorityDenied("resource.admission", "root durable admission could not bind to its event") from None
        if cancelled() or self._resource_generation(enrollment) != enrollment.generation:
            self.ledger.cancel_job(admission.job_id, current_generation=enrollment.generation)
            self._discard_job_event_fields(admission.job_id)
            raise AuthorityDenied("resource.event", "root event was revoked immediately after admission")
        return admission

    def _prune_root_admissions_locked(self, now: float) -> None:
        """Drop expired in-memory dispatch authority without pruning ledger replay rows."""
        for handle_id, (handle, admission) in tuple(self._root_event_admissions.items()):
            if admission.expires_monotonic <= now or handle.authority_epoch != self.service.authority_epoch:
                self._root_event_admissions.pop(handle_id, None)
                self._root_admission_objects.pop(admission.job_id, None)
                self._root_event_by_job.pop(admission.job_id, None)
                self._root_source_context_by_job.pop(admission.job_id, None)
                self._root_job_handles.pop(admission.job_id, None)

    def is_root_admission_current(self, root_event_handle: Any, admission: Any) -> bool:
        """Revalidate the exact event/admission pair before any root DAG step."""
        from .resource_source_controllers import RootResourceEventHandle
        if (type(root_event_handle) is not RootResourceEventHandle
                or not isinstance(admission, ResourceJobAdmission)):
            return False
        with self._event_lock:
            self._prune_root_admissions_locked(self.service.monotonic())
            bound = self._root_event_admissions.get(root_event_handle.handle)
            if (bound is None or bound[0] is not root_event_handle or bound[1] is not admission
                    or self._root_admission_objects.get(admission.job_id) is not admission
                    or self._root_event_by_job.get(admission.job_id) is not root_event_handle):
                return False
        enrollment = self.enrollments.get((admission.resource_id, admission.generation))
        issuer = getattr(self.service, "resource_event_context_issuer", None)
        registry = getattr(issuer, "controller_registry", None)
        if (enrollment is None or registry is None or admission.expires_monotonic <= self.service.monotonic()
                or root_event_handle.authority_epoch != getattr(self.service, "authority_epoch", None)
                or getattr(issuer, "service", None) is not self.service
                or self._resource_generation(enrollment) != enrollment.generation
                or not self.ledger.is_job_active(admission.job_id, current_generation=enrollment.generation)):
            return False
        try:
            record, selected, node, _backend = registry._resolve_event_node(
                root_event_handle, enrollment.nodes[0].node_id)
            if selected is not enrollment:
                return False
            issuer._require_live_selection(enrollment)
            context, receipts = issuer._verify_source_closure(
                record, enrollment, registry._profile_binding(enrollment), self.service.monotonic())
            self.service._verify_context_signature(context)
            binding = self.service._binding(context.uid)
            self.service._assert_current_context(context, binding, context.uid)
            for receipt in receipts:
                self.service._verify_source_receipt(receipt, binding)
            controller = registry.resolve_for_event(root_event_handle, node.node_id)
        except Exception:
            return False
        try:
            retained = self._source_closures_by_job.get(admission.job_id)
            return bool(
                record.handle is root_event_handle and context.source_receipts == receipts
                and receipts == record.parent_receipts
                and retained is not None and retained[0] is context and retained[1] == receipts
                and retained[3] > self.service.monotonic()
                and context.profile_id == enrollment.profile_id
                and context.principal_id == enrollment.principal_id
                and controller.uid == 0 and controller.controller_profile_id is None
                and controller.controller_kind in {"root-scheduler", "root-webhook", "root-channel"}
                and controller.service_generation_digest == self.service.service_generation_digest
                and controller.expires_monotonic > self.service.monotonic()
            )
        finally:
            try:
                os.close(controller.pidfd)
            except OSError:
                pass

    def resolve_node_result_closure(
        self, root_event_handle: Any, admission: ResourceJobAdmission, node_id: str,
    ) -> RootResourceNodeResultClosure:
        """Issue one immutable v66 closure from completed, retained result capsules."""
        from .resource_source_controllers import RootResourceEventHandle
        if (type(root_event_handle) is not RootResourceEventHandle
                or not isinstance(admission, ResourceJobAdmission)
                or not isinstance(node_id, str)):
            raise AuthorityDenied("resource.result_closure", "root node result closure request is malformed")
        if not self.is_root_admission_current(root_event_handle, admission):
            raise AuthorityDenied("resource.result_closure", "root event admission is stale or unbound")
        enrollment = self.enrollments[(admission.resource_id, admission.generation)]
        node = enrollment.node_map.get(node_id)
        if node is None:
            raise AuthorityDenied("resource.result_closure", "requested node is outside the admitted DAG")
        now = self.service.monotonic()
        current_generation = self._resource_generation(enrollment)
        values = self._load_parent_results(admission.job_id)
        capsule_rows = self._result_capsules_by_job.get(admission.job_id, {})
        result_handles: list[str] = []
        result_digests: list[str] = []
        expiries = [admission.expires_monotonic, root_event_handle.expires_monotonic]
        for prerequisite in sorted(node.depends_on):
            try:
                completed_id, attempt, receipts = self.ledger.completed_node_result_receipts(
                    admission.job_id, prerequisite, current_generation=current_generation)
            except ResourceJobDenied as exc:
                raise AuthorityDenied("resource.result_closure", str(exc)) from None
            row = capsule_rows.get(prerequisite)
            stored = values.get(prerequisite)
            if (row is None or stored is None or row.admission_id != completed_id
                    or row.node_id != prerequisite or row.resource_generation != enrollment.generation
                    or row.service_generation_digest != self.service.service_generation_digest
                    or row.expires_monotonic <= now or stored[0] not in receipts
                    or row.receipt_id != stored[0]):
                raise AuthorityDenied("resource.result_closure", "completed prerequisite lacks its actual validated capsule")
            result_handles.append(row.capsule_handle)
            result_digests.append(row.capsule_sha256)
            expiries.append(row.expires_monotonic)
        expires = min(expiries)
        if expires <= now:
            raise AuthorityDenied("resource.result_closure", "selected result closure has expired")
        parent_digest = canonical_digest({
            "event": root_event_handle.handle,
            "event_parent_closure": root_event_handle.parent_closure_digest,
            "job": admission.job_id, "dag": admission.approved_dag_sha256,
            "node": node_id, "prerequisites": sorted(node.depends_on),
            "capsules": list(zip(result_handles, result_digests)),
            "resource_generation": enrollment.generation,
            "service_generation_digest": self.service.service_generation_digest,
            "consent_revision": enrollment.consent_revision,
        })
        closure = RootResourceNodeResultClosure(
            schema=1, closure_handle=secrets.token_urlsafe(32),
            event_handle=root_event_handle.handle, admission_handle=admission.job_id,
            node_id=node_id, job_handle=self._root_job_handles[admission.job_id],
            resource_generation=enrollment.generation,
            service_generation_digest=self.service.service_generation_digest,
            prerequisite_node_ids=tuple(sorted(node.depends_on)),
            result_capsule_handles=tuple(result_handles),
            result_capsule_sha256s=tuple(result_digests),
            parent_closure_digest=parent_digest, issued_monotonic=now,
            expires_monotonic=expires,
        )
        selected_values = MappingProxyType({
            key: values[key][1] for key in sorted(node.depends_on)
        })
        with self._event_lock:
            if len(self._root_result_closures) >= 1024:
                raise AuthorityDenied("resource.capacity", "root result closure registry is full")
            self._root_result_closures[closure.closure_handle] = (closure, selected_values)
        return closure

    def resolve_node_result_values(
        self, closure: RootResourceNodeResultClosure,
    ) -> Mapping[str, Mapping[str, Any]]:
        """Revalidate a closure and resolve only its root-retained result fields."""
        if not isinstance(closure, RootResourceNodeResultClosure):
            raise AuthorityDenied("resource.result_closure", "result closure handle is invalid")
        with self._event_lock:
            row = self._root_result_closures.get(closure.closure_handle)
            if row is None or row[0] is not closure:
                raise AuthorityDenied("resource.result_closure", "result closure is forged or already expired")
        bound = self._root_event_admissions.get(closure.event_handle)
        if bound is None or bound[1].job_id != closure.admission_handle:
            raise AuthorityDenied("resource.result_closure", "result closure no longer has its admitted job")
        current = self.resolve_node_result_closure(bound[0], bound[1], closure.node_id)
        try:
            if (current.prerequisite_node_ids != closure.prerequisite_node_ids
                    or current.result_capsule_handles != closure.result_capsule_handles
                    or current.result_capsule_sha256s != closure.result_capsule_sha256s
                    or current.parent_closure_digest != closure.parent_closure_digest
                    or current.service_generation_digest != closure.service_generation_digest
                    or current.resource_generation != closure.resource_generation
                    or current.expires_monotonic < closure.expires_monotonic):
                raise AuthorityDenied("resource.result_closure", "result closure changed after issuance")
        finally:
            with self._event_lock:
                self._root_result_closures.pop(current.closure_handle, None)
        with self._event_lock:
            retained = self._root_result_closures.get(closure.closure_handle)
            if retained is None or retained[0] is not closure:
                raise AuthorityDenied("resource.result_closure", "result closure expired during resolution")
            return retained[1]

    def handlers(self) -> Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]:
        """Return exact protected handler registrations; absent joins stay absent."""
        handlers: dict[tuple[str, str], Callable[..., Mapping[str, Any]]] = {}
        for enrollment in self.enrollments.values():
            expected_recipes = {node.body_recipe_id for node in enrollment.nodes}
            for backend in enrollment.backends.values():
                if backend.execution_binding is not None:
                    expected_recipes.add(backend.execution_binding["task_body_recipe_id"])
            if (set(enrollment.backends) != {node.backend_enrollment_id for node in enrollment.nodes}
                    or set(enrollment.body_recipes) != expected_recipes):
                # Metadata-only jobs are never routable. The root assembly
                # must supply a fully joined backend and all fixed recipes.
                continue
            if any(backend.execution_binding is not None
                   and (backend.backend_id, node.node_id) not in self.profile_task_adapters
                   for node in enrollment.nodes
                   for backend in (enrollment.backends[node.backend_enrollment_id],)):
                continue
            if (any(backend.execution_binding is not None for backend in enrollment.backends.values())
                    and (getattr(self.service, "resource_job_authority", None) is not self
                         or not callable(getattr(self.service, "launch_resource_profile_task", None))
                         or not callable(getattr(self.service, "consume_resource_task_completion", None)))):
                # A selected task backend requires both the service launcher
                # and its terminal/result capsule consumer before admission is
                # routable. Do not admit a job that can never complete safely.
                continue
            job_target = self._job_target(enrollment)
            self._require_rule("resource.job.admit", job_target, None, require_handler=False)
            handlers[("resource.job.admit", job_target)] = self._admit_handler(enrollment)
            for node in enrollment.nodes:
                child_target = self._child_target(enrollment, node)
                self._require_rule("resource.job.child.admit", child_target, node.recipient,
                                   require_handler=False)
                backend = enrollment.backends[node.backend_enrollment_id]
                if (node.effect != backend.operation or node.target != backend.target_id
                        or node.recipient != backend.recipient
                        or node.action_id not in backend.approved_action_ids
                        or node.request_schema_id != backend.request_schema_id
                        or node.body_recipe_id != backend.body_recipe_id):
                    raise AuthorityDenied("resource.unavailable", "selected node is outside its protected backend")
                if backend.execution_binding is None:
                    self._require_rule(node.effect, node.target, node.recipient, require_handler=True)
                    effect_handler = self.service.handlers.get((node.effect, node.target))
                    if (getattr(effect_handler, "resource_backend_enrollment_id", None) != backend.backend_id
                            or getattr(effect_handler, "handler_artifact_id", None) != backend.handler_artifact_id
                            or getattr(effect_handler, "handler_sha256", None) != backend.handler_sha256):
                        raise AuthorityDenied("resource.unavailable", "selected backend handler is not artifact-bound")
                elif (backend.execution_binding["operation_id"] != "hermes-resource-profile-task-v1"
                      or (backend.backend_id, node.node_id) not in self.profile_task_adapters):
                    # A metadata row never becomes an effect handler by itself.
                    handlers.pop(("resource.job.admit", job_target), None)
                    continue
                key = ("resource.job.child.admit", child_target)
                if key in handlers:
                    raise AuthorityDenied("resource.enrollment", "resource child route is duplicated")
                handlers[key] = self._child_handler(enrollment, node)
        return MappingProxyType(handlers)

    def _require_rule(self, operation: str, target: str, recipient: str | None,
                      *, capability: str = _CAPABILITY, require_handler: bool) -> None:
        rule = self.service.rules.get((capability, operation, target))
        if (rule is None or rule.recipient != recipient
                or require_handler and (operation, target) not in self.service.handlers):
            raise AuthorityDenied("resource.unavailable", "protected resource job effect route is not fully enrolled")

    @staticmethod
    def _job_target(enrollment: ResourceJobEnrollment) -> str:
        return f"resource-job:{enrollment.resource_id}:{enrollment.generation}"

    @staticmethod
    def _child_target(enrollment: ResourceJobEnrollment, node: ResourceJobNode) -> str:
        return f"resource-child:{enrollment.resource_id}:{node.node_id}:{enrollment.generation}"

    def _admit_handler(self, enrollment: ResourceJobEnrollment) -> Callable[..., Mapping[str, Any]]:
        def handle(*, context: HostContext, authorization: EffectAuthorization, payload: bytes,
                   timeout: float, peer_pid: int, peer_pidfd: int | None,
                   cancelled: Callable[[], bool]) -> Mapping[str, Any]:
            request = _payload(payload, {"schema", "resource_id", "generation", "event_id",
                                         "source_receipt_ids", "intent_id", "trace_id"})
            if (request["schema"] != 1 or request["resource_id"] != enrollment.resource_id
                    or request["generation"] != enrollment.generation
                    or request["intent_id"] != authorization.intent_id
                    or request["trace_id"] != authorization.trace_id):
                raise AuthorityDenied("resource.admission", "job request does not match its signed selected context")
            self._assert_selected_context(context, authorization, enrollment, "resource.job.admit")
            receipts = authorization.source_receipts
            if (not isinstance(request["source_receipt_ids"], list)
                    or any(not isinstance(item, str) for item in request["source_receipt_ids"])
                    or not receipts or len(receipts) != len(request["source_receipt_ids"])
                    or tuple(sorted(item.receipt_id for item in receipts))
                    != tuple(sorted(request["source_receipt_ids"]))):
                raise AuthorityDenied("resource.source", "job source closure differs from the consumed signed receipt set")
            selected_fields, capsule = self._consume_selected_event_capsule(
                enrollment, context=context, authorization=authorization,
                peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                receipts=receipts, requested_event_id=request["event_id"],
            )
            capsule_lineage = _capsule_lineage(capsule)
            reservation = self._reserve_event_fields(selected_fields)
            try:
                current_generation = self._resource_generation(enrollment)
                now = self.service.monotonic()
                source_deadline = min(
                    [context.monotonic_expires_at, capsule.expires_monotonic]
                    + [receipt.monotonic_expires_at for receipt in receipts]
                )
                remaining = source_deadline - now
                if remaining < 1.0:
                    raise AuthorityDenied("resource.source", "verified source closure has no usable job lease")
                ttl_seconds = min(enrollment.max_runtime_seconds, max(1, int(timeout)), int(remaining))
                admission = self.ledger.admit_job(
                    enrollment, event_id=request["event_id"],
                    verified_source_receipt_ids=tuple(item.receipt_id for item in receipts),
                    current_generation=current_generation,
                    ttl_seconds=ttl_seconds,
                    parent_lineage_hash=authorization.lineage_hash,
                    parent_sensitivity=authorization.sensitivity.value,
                )
            except Exception:
                self._discard_event_field_reservation(reservation)
                raise
            self._promote_event_fields(
                reservation, admission.job_id, admission.expires_monotonic,
                source_closure=(context, tuple(receipts), capsule_lineage, admission.expires_monotonic),
            )
            body = _canonical({
                "schema": 1, "job_id": admission.job_id, "resource_id": enrollment.resource_id,
                "generation": enrollment.generation, "approved_dag_sha256": admission.approved_dag_sha256,
                "expires_monotonic": admission.expires_monotonic,
                "max_concurrency": admission.max_concurrency,
                "child_admission_ids": dict(admission.child_admission_ids),
            })
            return {"status": 202, "body": body, "headers": {"content-type": "application/json"},
                    "receipt_id": admission.job_id}
        return handle

    def _child_handler(self, enrollment: ResourceJobEnrollment,
                       node: ResourceJobNode) -> Callable[..., Mapping[str, Any]]:
        def handle(*, context: HostContext, authorization: EffectAuthorization, payload: bytes,
                   timeout: float, peer_pid: int, peer_pidfd: int | None,
                   cancelled: Callable[[], bool]) -> Mapping[str, Any]:
            request = _payload(payload, {"schema", "job_id", "child_admission_id", "generation",
                                         "node_id", "canonical_payload_sha256", "parent_result_receipt_ids"})
            if (request["schema"] != 1 or request["generation"] != enrollment.generation
                    or request["node_id"] != node.node_id
                    or request["canonical_payload_sha256"] != node.payload_sha256):
                raise AuthorityDenied("resource.child", "child request differs from the fixed selected DAG node")
            self._assert_selected_context(context, authorization, enrollment, "resource.job.child.admit")
            if context.source_receipts or authorization.source_receipts:
                raise AuthorityDenied("resource.source", "child admission cannot add or replay source receipts")
            event = self._event(request["job_id"], enrollment)
            current_generation = self._resource_generation(enrollment)
            # Failed pre-effect mint attempts may receive one bounded fresh
            # admission. Effect-started attempts are terminal and never auto
            # replayed, because their external outcome may be ambiguous.
            child = self.ledger.claim_child(
                event.admission, enrollment, node_id=node.node_id,
                child_admission_id=request["child_admission_id"],
                parent_result_receipt_ids=request["parent_result_receipt_ids"],
                current_generation=current_generation,
            )
            _check_job_cancelled(cancelled, self.ledger, child, current_generation)
            try:
                response = self.invoke_resource_backend(child, event, timeout, cancelled)
            except Exception:
                try:
                    self.ledger.fail_child_admission(
                        child, current_generation=self._resource_generation(enrollment))
                except ResourceJobDenied:
                    # If execution had started, retain terminal failure and
                    # never retry an ambiguous side effect.
                    try:
                        self.ledger.finish_child(
                            child, result_receipt_ids=(), success=False,
                            current_generation=self._resource_generation(enrollment))
                    except ResourceJobDenied:
                        pass
                raise
            successful = 200 <= response["status"] < 400
            stored_result = False
            if successful and "result_fields" in response:
                self._store_result_fields(child, response["receipt_id"], response["result_fields"],
                                          expires=event.admission.expires_monotonic,
                                          maximum_bytes=enrollment.backends[node.backend_enrollment_id].maximum_response_bytes)
                stored_result = True
            try:
                self.ledger.finish_child(child, result_receipt_ids=(response["receipt_id"],),
                                         success=successful,
                                         current_generation=self._resource_generation(enrollment))
            except Exception:
                if stored_result:
                    self._discard_result_fields(child.job_id, child.node_id)
                raise
            if not self.ledger.is_job_active(
                    child.job_id, current_generation=self._resource_generation(enrollment)):
                self._discard_job_event_fields(child.job_id)
            if not successful:
                response = {**response, "headers": {**response["headers"],
                                                     "x-resource-child-admission-id": child.admission_id}}
            return response
        return handle

    def invoke_resource_backend(self, child: ResourceChildAdmission, event: _JobEvent,
                                timeout: float, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        """Invoke one exact root-selected backend under a fresh child grant.

        This is a private root call point, never an RPC. It intentionally
        performs one ledger-selected node only; the worker cannot choose a
        backend, action, recipient, target, or request body.
        """
        enrollment = event.enrollment
        node = enrollment.node_map.get(child.node_id)
        backend = enrollment.backends.get(node.backend_enrollment_id) if node else None
        recipe = enrollment.body_recipes.get(node.body_recipe_id) if node else None
        if (not isinstance(backend, ResourceBackendEnrollment)
                or node is None or recipe is None
                or child.action_id != node.action_id or child.effect != backend.operation
                or child.target != backend.target_id or child.recipient != backend.recipient
                or node.action_id not in backend.approved_action_ids
                or node.request_schema_id != backend.request_schema_id
                or node.body_recipe_id != backend.body_recipe_id):
            raise AuthorityDenied("resource.backend", "child does not resolve to its protected backend")
        try:
            request_body = recipe.render(
                backend=backend, scope_bindings=enrollment.scope_bindings,
                validators=enrollment.validators, event_fields=event.event_fields,
                parent_results={node_id: fields for node_id, (receipt_id, fields)
                                in event.parent_results.items()
                                if receipt_id in child.parent_result_receipt_ids},
            )
        except ResourceJobDenied:
            raise AuthorityDenied("resource.backend", "dynamic body recipe resolver is unavailable") from None
        if len(request_body) > backend.maximum_request_bytes:
            raise AuthorityDenied("resource.backend", "rendered request exceeds protected backend bounds")
        if backend.execution_binding is not None:
            return self._launch_profile_task(child, event, backend, timeout, cancelled)
        binding = next((item for item in self.service.bindings_by_uid.values()
                        if item.profile_id == enrollment.profile_id), None)
        if (binding is None or binding.principal_id != enrollment.principal_id
                or _CAPABILITY not in binding.capabilities):
            raise AuthorityDenied("resource.child", "selected child process identity or capability is unavailable")
        rule = self.service.rules.get((_CAPABILITY, child.effect, child.target))
        handler = self.service.handlers.get((child.effect, child.target))
        if rule is None or handler is None or rule.recipient != child.recipient:
            raise AuthorityDenied("resource.child", "fixed selected child executor is not installed")
        if (getattr(handler, "resource_backend_enrollment_id", None) != backend.backend_id
                or getattr(handler, "handler_artifact_id", None) != backend.handler_artifact_id
                or getattr(handler, "handler_sha256", None) != backend.handler_sha256):
            raise AuthorityDenied("resource.backend", "backend implementation artifact is not selected")
        generation = self.service.profile_generations.get(binding.profile_id, "unversioned")
        now = self.service.monotonic()
        expiry = min(event.admission.expires_monotonic, now + max(1.0, min(timeout, 30.0)))
        if expiry <= now:
            raise AuthorityDenied("resource.child", "resource child deadline expired")
        payload_digest = canonical_digest(request_body)
        lineage = canonical_digest({
            "parent_lineage": event.lineage_hash, "source_receipts": sorted(event.source_receipt_ids),
            "job_id": child.job_id, "node_id": child.node_id,
            "attempt": child.retry_index,
            "parent_result_receipts": list(child.parent_result_receipt_ids),
        })
        child_context = HostContext(
            principal_id=binding.principal_id, profile_id=binding.profile_id,
            namespace_id=binding.namespace_id, uid=binding.uid,
            purpose=f"resource-job:{enrollment.resource_id}:{child.action_id}"[:128],
            intent_id=canonical_digest({"job": child.job_id, "admission": child.admission_id,
                                        "action": child.action_id}),
            trace_id=secrets.token_urlsafe(24), sensitivity=event.sensitivity,
            lineage_hash=lineage, policy_revision=self.service._policy_revision(),
            capabilities=binding.capabilities, issued_at_monotonic=now,
            monotonic_expires_at=expiry, nonce=secrets.token_urlsafe(24),
            grant_id=secrets.token_urlsafe(24), signature="pending", source_receipts=(),
            final_payload_digest=payload_digest,
            enrollment_id=canonical_digest({"uid": binding.uid, "principal_id": binding.principal_id,
                                            "profile_id": binding.profile_id,
                                            "namespace_id": binding.namespace_id,
                                            "generation": generation,
                                            "authority_epoch": self.service.authority_epoch}),
            generation=generation, operation=child.effect,
            native_process_identity=None,
        )
        signed_context = self.service._signed_context(child_context, self.service._sign(child_context.claims()))
        grant = self.service._authorize_effect(binding.uid, {
            "context": signed_context, "capability": _CAPABILITY, "target": child.target,
            "recipient": child.recipient, "request_digest": payload_digest,
            "retry_index": child.retry_index,
        })
        self.ledger.start_child(child, current_generation=enrollment.generation)
        body = {
            "authorization": grant, "operation": child.effect,
            "payload": base64.b64encode(request_body).decode("ascii"),
            "timeout": min(timeout, backend.maximum_seconds, max(0.1, expiry - self.service.monotonic())),
        }
        response = self.service._perform_effect(
            binding.uid, os.getpid(), body,
            cancelled=lambda: cancelled() or not self.ledger.is_active(
                child, current_generation=self._resource_generation(enrollment)),
            enforce_peer_identity=False,
        )
        response_body = base64.b64decode(response["body"], validate=True)
        if len(response_body) > backend.maximum_response_bytes:
            raise AuthorityDenied("resource.backend", "backend response exceeds the protected byte limit")
        return {"status": response["status"], "body": response_body,
                "headers": response["headers"], "receipt_id": response["receipt_id"]}

    def _launch_profile_task(self, child: ResourceChildAdmission, event: _JobEvent,
                             backend: ResourceBackendEnrollment, timeout: float,
                             cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        """Invoke only the fixed root-selected Hermes profile-task adapter."""
        binding = backend.execution_binding
        node = event.enrollment.node_map.get(child.node_id)
        if binding is None or node is None:
            raise AuthorityDenied("resource.backend", "selected profile-task binding is unavailable")
        adapter = self.profile_task_adapters.get((backend.backend_id, node.node_id))
        if adapter is None or getattr(getattr(adapter, "selection", None), "resource_backend_id", None) != backend.backend_id:
            raise AuthorityDenied("resource.backend", "fixed selected profile-task adapter is unavailable")
        task_recipe = event.enrollment.body_recipes.get(binding["task_body_recipe_id"])
        if not isinstance(task_recipe, ResourceBodyRecipe):
            raise AuthorityDenied("resource.backend", "selected task body recipe is unavailable")
        try:
            task_payload = task_recipe.render(
                backend=backend, scope_bindings=event.enrollment.scope_bindings,
                validators=event.enrollment.validators, event_fields=event.event_fields,
                parent_results={node_id: fields for node_id, (receipt_id, fields)
                                in event.parent_results.items()
                                if receipt_id in child.parent_result_receipt_ids},
            )
        except ResourceJobDenied:
            raise AuthorityDenied("resource.backend", "selected profile task input is unavailable") from None
        if len(task_payload) > min(262_144, backend.maximum_request_bytes):
            raise AuthorityDenied("resource.backend", "selected task input exceeds its protected bound")
        now = self.service.monotonic()
        expires = min(event.admission.expires_monotonic,
                      now + max(1.0, min(float(timeout), backend.maximum_seconds)))
        if expires <= now:
            raise AuthorityDenied("resource.child", "selected task lease is expired")
        closure = _admitted_source_closure_digest(event, child, node, backend)
        handle = RootResourceJobAdmissionHandle(
            handle_id=secrets.token_urlsafe(32), job_id=child.job_id, node_id=node.node_id,
            child_admission_id=child.admission_id, attempt_index=child.retry_index,
            backend_enrollment_id=backend.backend_id,
            resource_generation=event.enrollment.generation,
            profile_id=backend.profile_id, profile_generation=backend.profile_generation,
            native_package_id=backend.native_package_id,
            native_package_generation=backend.native_package_generation,
            process_enrollment_id=binding["process_enrollment_id"],
            process_generation=binding["process_generation"], operation_id=binding["operation_id"],
            child_target_id=binding["child_target_id"], child_capability=binding["child_capability"],
            task_body_recipe_id=binding["task_body_recipe_id"],
            task_request_schema_id=binding["task_request_schema_id"], task_payload=task_payload,
            task_payload_sha256=hashlib.sha256(task_payload).hexdigest(),
            parent_closure_digest=closure, expires_monotonic=expires,
        )
        if (cancelled() or not self.ledger.is_child_admitted(
                child, current_generation=self._resource_generation(event.enrollment))):
            raise AuthorityDenied("resource.child", "selected profile-task attempt was cancelled before launch")
        with self._task_handle_lock:
            if handle.handle_id in self._task_handles or len(self._task_handles) >= 256:
                raise AuthorityDenied("resource.capacity", "root profile-task admission handle store is full")
            self._task_handles[handle.handle_id] = (handle, child, event.enrollment, event)
            self._source_context_handles[handle.handle_id] = (
                self._root_source_context_by_job.get(child.job_id) or secrets.token_urlsafe(32)
            )
        try:
            response = adapter.launch_resource_profile_task(handle, node.node_id)
            with self._task_handle_lock:
                consumed = self._running_task_handles.get(handle.handle_id)
            if (consumed is None or consumed[0] is not handle
                    or not self.ledger.is_active(child,
                        current_generation=self._resource_generation(event.enrollment))):
                raise AuthorityDenied("resource.process_task", "root launcher did not consume the one-use job handle")
            if not isinstance(response, RootResourceProcessReceipt):
                raise AuthorityDenied("resource.process_receipt", "root launcher did not return a typed process receipt")
            response.assert_bound(
                job_id=child.job_id, node_id=node.node_id, backend=backend, payload=task_payload,
                parent_closure_digest=closure, now=self.service.monotonic(),
                job_expires_monotonic=event.admission.expires_monotonic,
            )
            # Receipt creation alone does not establish clean terminal completion
            # or result-capsule validity. The AuthorityService owns that join.
            completion = getattr(self.service, "consume_resource_task_completion", None)
            if not callable(completion):
                raise AuthorityDenied("resource.result", "root terminal/result capsule consumer is unavailable")
            # Resolve the digest while the runner still retains the exact
            # unconsumed capsule. Completion consumes that capsule, so querying
            # its digest afterward would either fail or create a replay seam.
            task_runner = getattr(self.service, "resource_task_runner", None)
            capsule_digest_resolver = getattr(task_runner, "resolve_result_capsule_sha256", None)
            if not callable(capsule_digest_resolver):
                raise AuthorityDenied("resource.result", "root result capsule digest resolver is unavailable")
            capsule_digest = capsule_digest_resolver(response)
            if not isinstance(capsule_digest, str) or not _HEX64.fullmatch(capsule_digest):
                raise AuthorityDenied("resource.result", "root result capsule digest is malformed")
            result = completion(response, cancelled=cancelled)
            if not isinstance(result, Mapping) or set(result) != {
                    "status", "body", "headers", "receipt_id", "result_fields"}:
                raise AuthorityDenied("resource.result", "root task completion result has an invalid shape")
            if (type(result["status"]) is not int or not isinstance(result["body"], bytes)
                    or not isinstance(result["headers"], Mapping) or not isinstance(result["receipt_id"], str)
                    or not result["receipt_id"] or not isinstance(result["result_fields"], Mapping)
                    or len(result["body"]) > backend.maximum_response_bytes):
                raise AuthorityDenied("resource.result", "root task completion result exceeds its schema")
            result_value = dict(result)
            result_value["result_fields"] = MappingProxyType(dict(result["result_fields"]))
            self._retain_task_result_capsule(
                child, event, backend, response, result_value, capsule_digest,
            )
            return result_value
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("resource.result", "root task result capsule failed validation") from None
        finally:
            with self._task_handle_lock:
                self._task_handles.pop(handle.handle_id, None)
                self._running_task_handles.pop(handle.handle_id, None)
                self._resolved_task_dtos.pop(handle.handle_id, None)
                self._source_resolved_handles.discard(handle.handle_id)
                self._source_context_handles.pop(handle.handle_id, None)
                self._controller_resolved_handles.discard(handle.handle_id)
                self._resolved_controller_evidence.pop(handle.handle_id, None)
                self._parent_context_resolved_handles.discard(handle.handle_id)
                controller = self._task_controller_bindings.pop(handle.handle_id, None)
            if controller is not None:
                try:
                    os.close(controller[1].pidfd)
                except OSError:
                    pass

    def consume_task_handle(self, handle: Any, node_id: str) -> RootResourceJobAdmissionHandle:
        """Consume exactly the issued root token before AuthorityService launches it."""
        if not isinstance(handle, RootResourceJobAdmissionHandle) or node_id != handle.node_id:
            raise AuthorityDenied("resource.process_task", "root task handle is not selected for this node")
        with self._task_handle_lock:
            registered = self._task_handles.pop(handle.handle_id, None)
        if registered is None or registered[0] is not handle:
            raise AuthorityDenied("resource.process_task", "root task handle was forged, replayed, or consumed")
        _, child, enrollment, event = registered
        backend = enrollment.backends.get(handle.backend_enrollment_id)
        binding = backend.execution_binding if backend is not None else None
        if (backend is None or binding is None or child.admission_id != handle.child_admission_id
                or child.job_id != handle.job_id or child.node_id != handle.node_id
                or child.retry_index != handle.attempt_index
                or enrollment.generation != handle.resource_generation
                or backend.profile_id != handle.profile_id
                or backend.profile_generation != handle.profile_generation
                or backend.native_package_id != handle.native_package_id
                or backend.native_package_generation != handle.native_package_generation
                or binding["process_enrollment_id"] != handle.process_enrollment_id
                or binding["process_generation"] != handle.process_generation
                or binding["operation_id"] != handle.operation_id
                or binding["child_target_id"] != handle.child_target_id
                or binding["child_capability"] != handle.child_capability
                or binding["task_body_recipe_id"] != handle.task_body_recipe_id
                or binding["task_request_schema_id"] != handle.task_request_schema_id
                or self.service.monotonic() >= handle.expires_monotonic
                or not self.ledger.is_child_admitted(child,
                    current_generation=self._resource_generation(enrollment))):
            raise AuthorityDenied("resource.process_task", "root task handle is stale or outside its admitted node")
        with self._task_handle_lock:
            if handle.handle_id in self._running_task_handles:
                raise AuthorityDenied("resource.process_task", "root task handle is already running")
            self._running_task_handles[handle.handle_id] = registered
        return handle

    def resolve_task_child_admission(
        self, handle: Any, node_id: str,
    ) -> ResourceChildAdmission:
        """Resolve the exact active ledger child for the root task grant issuer.

        This is an in-process authority seam. It accepts only the identical
        consumed task handle retained in ``_running_task_handles``; the child
        admission is returned from that retained tuple, never reconstructed
        from task/source DTO fields. The service calls it again at grant
        consumption, so revocation or a stale retry cannot reuse the proof.
        """
        if (not isinstance(handle, RootResourceJobAdmissionHandle)
                or not isinstance(node_id, str) or node_id != handle.node_id):
            raise AuthorityDenied("resource.child", "task child admission lookup is malformed")
        with self._task_handle_lock:
            registered = self._running_task_handles.get(handle.handle_id)
            if (registered is None or len(registered) != 4
                    or registered[0] is not handle):
                raise AuthorityDenied("resource.child", "task child admission requires the exact consumed handle")
        _handle, child, enrollment, event = registered
        backend = enrollment.backends.get(handle.backend_enrollment_id)
        binding = backend.execution_binding if backend is not None else None
        node = enrollment.node_map.get(node_id)
        current_generation = self._resource_generation(enrollment)
        now = self.service.monotonic()
        if (backend is None or binding is None or node is None
                or event.enrollment is not enrollment
                or event.admission.job_id != child.job_id
                or child.node_id != node_id or child.job_id != handle.job_id
                or child.admission_id != handle.child_admission_id
                or child.retry_index != handle.attempt_index
                or enrollment.generation != handle.resource_generation
                or backend.resource_id != enrollment.resource_id
                or backend.generation != enrollment.generation
                or backend.consent_revision != enrollment.consent_revision
                or backend.profile_id != enrollment.profile_id
                or backend.principal_id != enrollment.principal_id
                or binding["process_enrollment_id"] != handle.process_enrollment_id
                or binding["process_generation"] != handle.process_generation
                or binding["operation_id"] != handle.operation_id
                or binding["child_target_id"] != handle.child_target_id
                or binding["child_capability"] != handle.child_capability
                or binding["task_body_recipe_id"] != handle.task_body_recipe_id
                or binding["task_request_schema_id"] != handle.task_request_schema_id
                or current_generation != enrollment.generation
                or self.service.profile_generations.get(enrollment.profile_id)
                   != event.parent_context.generation
                or now >= min(handle.expires_monotonic, event.admission.expires_monotonic)
                or handle.parent_closure_digest != _admitted_source_closure_digest(
                    event, child, node, backend)
                or not self.ledger.is_child_admitted(child, current_generation=current_generation)):
            raise AuthorityDenied("resource.child", "task child admission is stale or outside its selected job")
        root_event = self._root_event_by_job.get(child.job_id)
        if root_event is not None:
            with self._event_lock:
                root_row = self._root_event_admissions.get(root_event.handle)
            if (root_row is None or root_row[0] is not root_event
                    or root_row[1] is not event.admission
                    or not self.is_root_admission_current(root_event, event.admission)):
                raise AuthorityDenied("resource.child", "root event admission is no longer current")
        return child

    def resolve_admitted_task_source(self, handle: Any, node_id: str) -> RootAdmittedTaskSource:
        """Resolve the original verified source closure for an actively consumed handle.

        This is an in-process AuthorityService seam. It accepts only the exact
        token instance currently held in the running registry; wire fields or
        reconstructed digests cannot retrieve source context.
        """
        if not isinstance(handle, RootResourceJobAdmissionHandle) or node_id != handle.node_id:
            raise AuthorityDenied("resource.source", "task source lookup is not bound to the selected node")
        with self._task_handle_lock:
            registered = self._running_task_handles.get(handle.handle_id)
            if registered is None or registered[0] is not handle or len(registered) != 4:
                raise AuthorityDenied("resource.source", "task source lookup requires a consumed root handle")
            if handle.handle_id in self._source_resolved_handles:
                raise AuthorityDenied("resource.source", "task source closure is one-use")
            self._source_resolved_handles.add(handle.handle_id)
        _handle, child, enrollment, event = registered
        backend = enrollment.backends.get(handle.backend_enrollment_id)
        binding = backend.execution_binding if backend is not None else None
        now = self.service.monotonic()
        generation = self._resource_generation(enrollment)
        node = enrollment.node_map.get(child.node_id)
        expected_closure = (_admitted_source_closure_digest(event, child, node, backend)
                            if node is not None and backend is not None else "")
        if (backend is None or binding is None or event.enrollment is not enrollment
                or event.admission.job_id != child.job_id or child.node_id != node_id
                or child.admission_id != handle.child_admission_id
                or child.retry_index != handle.attempt_index
                or generation != handle.resource_generation
                or backend.resource_id != enrollment.resource_id
                or backend.generation != enrollment.generation
                or backend.consent_revision != enrollment.consent_revision
                or backend.profile_id != enrollment.profile_id
                or backend.principal_id != enrollment.principal_id
                or self.service.profile_generations.get(enrollment.profile_id)
                != event.parent_context.generation
                or now >= handle.expires_monotonic
                or not self.ledger.is_child_admitted(child, current_generation=generation)
                or handle.parent_closure_digest != expected_closure
                or not event.source_receipts
                or tuple(sorted(item.receipt_id for item in event.source_receipts))
                != tuple(sorted(event.source_receipt_ids))):
            raise AuthorityDenied("resource.source", "task source closure is stale or unbound")
        if (binding["process_enrollment_id"] != handle.process_enrollment_id
                or binding["process_generation"] != handle.process_generation
                or binding["native_package_id"] != handle.native_package_id
                or binding["native_package_generation"] != handle.native_package_generation
                or binding["task_body_recipe_id"] != handle.task_body_recipe_id
                or binding["task_request_schema_id"] != handle.task_request_schema_id):
            raise AuthorityDenied("resource.source", "task source selection changed after admission")
        capsule = event.source_capsule_lineage
        # Resolve the private context capability and exact signed receipt
        # handles before splitting root-owned ingress from worker-observed
        # events.  Both paths consume the same retained, signature-bearing
        # closure; only the authority that validates the producer differs.
        receipt_handle_map = getattr(self.service, "_source_receipt_handles", None)
        if not isinstance(receipt_handle_map, Mapping):
            raise AuthorityDenied("resource.source", "root source receipt handle registry is unavailable")
        opaque_receipt_handles: list[str] = []
        signed_wires: list[bytes] = []
        for receipt in event.source_receipts:
            matches = [key for key, candidate in receipt_handle_map.items()
                       if candidate is receipt or candidate.receipt_id == receipt.receipt_id]
            if len(matches) != 1:
                raise AuthorityDenied("resource.source", "signed source receipt handle is unavailable or ambiguous")
            opaque_receipt_handles.append(str(matches[0]))
            signed_wires.append(_canonical(receipt.to_wire()))
        context_handle = self._source_context_handles.get(handle.handle_id)
        if not isinstance(context_handle, str) or not context_handle:
            raise AuthorityDenied("resource.source", "root source context handle is unavailable")
        # Root timer/webhook/channel events have a different trusted producer
        # identity from worker-captured native events. Bind the same complete
        # retained source context/receipt closure, but do not try to reinterpret
        # the root event as a worker SourceObserverRegistry receipt.
        root_event_handle = self._root_event_by_job.get(child.job_id)
        if (root_event_handle is not None
                and capsule.get("root_event_handle") == root_event_handle.handle):
            return self._resolve_root_admitted_task_source(
                handle, child, enrollment, event, context_handle,
                opaque_receipt_handles, signed_wires,
            )
        source_receipt = next((item for item in event.source_receipts
                               if item.receipt_id == capsule.get("receipt_id")), None)
        parent_receipt_ids = tuple(capsule.get("parent_receipt_ids", ()))
        if (source_receipt is None
                or source_receipt.source_kind != capsule.get("source_kind")
                or source_receipt.payload_digest != capsule.get("payload_sha256")
                or set(parent_receipt_ids) != set(event.source_receipt_ids) - {source_receipt.receipt_id}
                or capsule.get("parent_closure_digest") != canonical_digest(parent_receipt_ids)
                or capsule.get("profile_id") != enrollment.profile_id
                or capsule.get("principal_id") != enrollment.principal_id
                or capsule.get("generation") != backend.profile_generation
                or backend.consent_revision != enrollment.consent_revision
                or self.service.profile_generations.get(enrollment.profile_id)
                != event.parent_context.generation):
            raise AuthorityDenied("resource.source", "root source receipt lineage no longer validates")
        if (event.parent_context.profile_id != enrollment.profile_id
                or event.parent_context.principal_id != enrollment.principal_id
                or event.parent_context.sensitivity != event.sensitivity):
            raise AuthorityDenied("resource.source", "original parent context no longer matches its selected job")
        result_fields = MappingProxyType({
            node_id: fields for node_id, (receipt_id, fields) in event.parent_results.items()
            if receipt_id in child.parent_result_receipt_ids
        })
        if set(child.parent_result_receipt_ids) != {
                receipt_id for receipt_id, _fields in event.parent_results.values()
                if receipt_id in child.parent_result_receipt_ids}:
            raise AuthorityDenied("resource.source", "declared predecessor result closure is incomplete")
        observers = getattr(self.service, "source_observer_registry", None)
        resolver = getattr(observers, "resolve_live_source_producer", None)
        capsule = event.source_capsule_lineage
        source_receipt = next((item for item in event.source_receipts
                               if item.receipt_id == capsule.get("receipt_id")), None)
        if source_receipt is None or not callable(resolver):
            raise AuthorityDenied("resource.controller", "live root source producer resolver is unavailable")
        try:
            producer = resolver(
                source_receipt.receipt_id, profile_id=source_receipt.profile_id,
                generation=source_receipt.process_generation,
                native_process_identity=source_receipt.native_process_identity,
                expires_monotonic=source_receipt.monotonic_expires_at,
            )
        except Exception:
            raise AuthorityDenied("resource.controller", "selected source producer is no longer live") from None
        producer_fields = (
            "receipt_id", "pid", "pidfd", "uid", "profile_id", "generation",
            "expires_monotonic", "authority_epoch", "observer_enrollment_id",
            "source_action_id", "channel_id", "identity", "loaded_package_proof",
        )
        if (any(not hasattr(producer, name) for name in producer_fields)
                or producer.receipt_id != source_receipt.receipt_id
                or producer.profile_id != source_receipt.profile_id
                or producer.generation != source_receipt.process_generation
                or producer.expires_monotonic != source_receipt.monotonic_expires_at
                or type(producer.pid) is not int or type(producer.pidfd) is not int
                or type(producer.uid) is not int):
            close = getattr(producer, "pidfd", None)
            if type(close) is int:
                try:
                    os.close(close)
                except OSError:
                    pass
            raise AuthorityDenied("resource.controller", "live source producer evidence is malformed")
        controller_handle = secrets.token_urlsafe(32)
        with self._task_handle_lock:
            registered = self._running_task_handles.get(handle.handle_id)
            if registered is None or registered[0] is not handle:
                try:
                    os.close(producer.pidfd)
                except OSError:
                    pass
                raise AuthorityDenied("resource.controller", "task controller lookup lost its consumed handle")
            self._task_controller_bindings[handle.handle_id] = (controller_handle, producer)
        task_body = json.loads(handle.task_payload.decode("utf-8"))
        stdin = task_body["prompt"].encode("utf-8")
        task = RootAdmittedTask(
            schema=1, admission_id=child.admission_id, job_id=child.job_id,
            node_id=child.node_id, backend_enrollment_id=backend.backend_id,
            resource_generation=enrollment.generation,
            process_enrollment_id=handle.process_enrollment_id,
            process_generation=handle.process_generation,
            native_package_id=backend.native_package_id,
            native_package_generation=backend.native_package_generation,
            operation_id=handle.operation_id, task_body_recipe_id=handle.task_body_recipe_id,
            task_request_schema_id=handle.task_request_schema_id,
            task_payload_sha256=handle.task_payload_sha256,
            task_payload_bytes=handle.task_payload,
            stdin_sha256=hashlib.sha256(stdin).hexdigest(), stdin_size_bytes=len(stdin),
            parent_closure_digest=handle.parent_closure_digest,
            deadline_monotonic=handle.expires_monotonic, source_context_handle=context_handle,
        )
        recipient_ceiling = set(event.source_receipts[0].recipient_ceiling)
        for receipt in event.source_receipts[1:]:
            recipient_ceiling.intersection_update(receipt.recipient_ceiling)
        return RootAdmittedTaskSource(
            source_context_handle=context_handle,
            verified_source_receipt_handles=tuple(opaque_receipt_handles),
            signed_receipt_wires=tuple(signed_wires), lineage_hash=event.lineage_hash,
            sensitivity=event.sensitivity, recipient_ceiling=tuple(sorted(recipient_ceiling)),
            principal_id=enrollment.principal_id, profile_id=enrollment.profile_id,
            namespace_id=event.parent_context.namespace_id,
            parent_closure_digest=handle.parent_closure_digest,
            controller_binding_handle=controller_handle,
            expires_monotonic=min(handle.expires_monotonic,
                                  *(receipt.monotonic_expires_at for receipt in event.source_receipts)),
        )

    def _resolve_root_admitted_task_source(
        self, handle: RootResourceJobAdmissionHandle, child: ResourceChildAdmission,
        enrollment: ResourceJobEnrollment, event: _JobEvent, context_handle: str,
        receipt_handles: Sequence[str], signed_wires: Sequence[bytes],
    ) -> RootAdmittedTaskSource:
        root_event = self._root_event_by_job.get(child.job_id)
        issuer = getattr(self.service, "resource_event_context_issuer", None)
        registry = getattr(issuer, "controller_registry", None)
        if (root_event is None or event.source_capsule_lineage.get("root_event_handle") != root_event.handle
                or registry is None or getattr(issuer, "service", None) is not self.service
                or len(receipt_handles) != len(event.source_receipts)
                or len(signed_wires) != len(event.source_receipts)):
            raise AuthorityDenied("resource.source", "root task source registry binding is unavailable")
        try:
            record, selected, _node, _backend = registry._resolve_event_node(root_event, child.node_id)
            issuer._require_live_selection(enrollment)
            context, receipts = issuer._verify_source_closure(
                record, enrollment, registry._profile_binding(enrollment), self.service.monotonic())
            self.service._verify_context_signature(context)
            binding = self.service._binding(context.uid)
            self.service._assert_current_context(context, binding, context.uid)
            for receipt in receipts:
                self.service._verify_source_receipt(receipt, binding)
        except Exception:
            raise AuthorityDenied("resource.source", "root task source closure is stale") from None
        if (selected is not enrollment or record.handle is not root_event
                or context is not event.parent_context or receipts != event.source_receipts
                or tuple(sorted(item.receipt_id for item in receipts)) != event.source_receipt_ids
                or context.source_receipts != receipts
                or context.lineage_hash != event.lineage_hash
                or context.sensitivity != event.sensitivity
                or self.service.monotonic() >= min(handle.expires_monotonic,
                                                    root_event.expires_monotonic,
                                                    *(item.monotonic_expires_at for item in receipts))):
            raise AuthorityDenied("resource.source", "root task source identity, closure, or lease changed")
        with self._task_handle_lock:
            if (self._running_task_handles.get(handle.handle_id, (None,))[0] is not handle
                    or handle.handle_id in self._root_task_controller_tokens):
                raise AuthorityDenied("resource.controller", "root task controller token is already resolved")
            controller_token = secrets.token_urlsafe(32)
            self._root_task_controller_tokens[handle.handle_id] = controller_token
        recipient_ceiling = set(receipts[0].recipient_ceiling)
        for receipt in receipts[1:]:
            recipient_ceiling.intersection_update(receipt.recipient_ceiling)
        return RootAdmittedTaskSource(
            source_context_handle=context_handle,
            verified_source_receipt_handles=tuple(receipt_handles),
            signed_receipt_wires=tuple(signed_wires), sensitivity=event.sensitivity,
            lineage_hash=event.lineage_hash, recipient_ceiling=tuple(sorted(recipient_ceiling)),
            principal_id=enrollment.principal_id, profile_id=enrollment.profile_id,
            namespace_id=context.namespace_id, parent_closure_digest=handle.parent_closure_digest,
            controller_binding_handle=controller_token,
            expires_monotonic=min(handle.expires_monotonic, root_event.expires_monotonic,
                                  context.monotonic_expires_at,
                                  *(item.monotonic_expires_at for item in receipts)),
        )

    def resolve_admitted_task_controller(self, handle: Any, node_id: str) -> RootTaskController:
        """Return one root-resolved live source producer PIDFD for a consumed node."""
        if not isinstance(handle, RootResourceJobAdmissionHandle) or node_id != handle.node_id:
            raise AuthorityDenied("resource.controller", "task controller is not bound to this selected node")
        with self._task_handle_lock:
            registered = self._running_task_handles.get(handle.handle_id)
            controller_token = self._root_task_controller_tokens.get(handle.handle_id)
            root_event = (self._root_event_by_job.get(handle.job_id)
                          if registered is not None and registered[0] is handle else None)
            if root_event is not None:
                self._root_task_controller_tokens.pop(handle.handle_id, None)
        if root_event is not None:
            source_event = registered[3].source_capsule_lineage.get("root_event_handle")
            issuer = getattr(self.service, "resource_event_context_issuer", None)
            registry = getattr(issuer, "controller_registry", None)
            if (source_event != root_event.handle or not isinstance(controller_token, str)
                    or registry is None or self.service.monotonic() >= handle.expires_monotonic):
                raise AuthorityDenied("resource.controller", "root task controller event binding is stale")
            controller = None
            try:
                controller = registry.resolve_for_event(root_event, node_id)
                if (controller.controller_kind not in {"root-scheduler", "root-webhook", "root-channel"}
                        or controller.uid != 0 or controller.controller_profile_id is not None
                        or controller.source_receipt_id is not None
                        or controller.subject_profile_id != registered[2].profile_id
                        or controller.subject_principal_id != registered[2].principal_id
                        or controller.service_generation_digest
                        != getattr(self.service, "service_generation_digest", None)
                        or controller.expires_monotonic <= self.service.monotonic()):
                    raise AuthorityDenied("resource.controller", "root task controller proof is not selected")
                from dataclasses import replace
                controller = replace(controller, controller_handle=controller_token)
                with self._task_handle_lock:
                    if (self._running_task_handles.get(handle.handle_id, (None,))[0] is not handle
                            or handle.handle_id in self._controller_resolved_handles):
                        raise AuthorityDenied("resource.controller", "root task controller was replayed")
                    self._controller_resolved_handles.add(handle.handle_id)
                    self._resolved_controller_evidence[handle.handle_id] = (
                        controller_token, root_event.handle, controller.identity, controller.pid,
                        controller.uid, controller.controller_kind,
                        controller.controller_role_artifact_id, controller.controller_role_sha256,
                        controller.controller_generation, controller.expires_monotonic,
                        controller.service_generation_digest, self.service.authority_epoch,
                    )
                return controller
            except Exception:
                if controller is not None:
                    try:
                        os.close(controller.pidfd)
                    except OSError:
                        pass
                raise AuthorityDenied("resource.controller", "root task controller is stale or unavailable") from None
        with self._task_handle_lock:
            bound = self._task_controller_bindings.pop(handle.handle_id, None)
        if (registered is None or registered[0] is not handle or bound is None
                or not self.service.monotonic() < handle.expires_monotonic):
            raise AuthorityDenied("resource.controller", "task controller binding is stale or already consumed")
        controller_handle, producer = bound
        source_context_handle = self._source_context_handles.get(handle.handle_id)
        if (not isinstance(source_context_handle, str)
                or not source_context_handle
                or producer.receipt_id not in {item.receipt_id for item in registered[3].source_receipts}):
            try:
                os.close(producer.pidfd)
            except OSError:
                pass
            raise AuthorityDenied("resource.controller", "task controller binding changed after admission")
        source_receipt = next(item for item in registered[3].source_receipts
                              if item.receipt_id == producer.receipt_id)
        proof = producer.loaded_package_proof
        role_artifact_id = getattr(proof, "role_artifact_id", None)
        role_sha256 = getattr(proof, "role_sha256", None)
        service_generation_digest = getattr(self.service, "service_generation_digest", None)
        if (not isinstance(role_artifact_id, str) or not isinstance(role_sha256, str)
                or not isinstance(service_generation_digest, str)
                or not _HEX64.fullmatch(service_generation_digest)):
            try:
                os.close(producer.pidfd)
            except OSError:
                pass
            raise AuthorityDenied("resource.controller", "selected controller role proof is incomplete")
        enrollment = registered[2]
        controller_dto = RootTaskController(
            schema=1, controller_handle=controller_handle, controller_kind="worker",
            controller_role_artifact_id=role_artifact_id,
            controller_role_sha256=role_sha256, pid=producer.pid, pidfd=producer.pidfd,
            uid=producer.uid, identity=producer.identity,
            controller_profile_id=producer.profile_id,
            controller_generation=producer.generation, source_receipt_id=source_receipt.receipt_id,
            subject_principal_id=enrollment.principal_id,
            subject_profile_id=enrollment.profile_id,
            subject_namespace_id=registered[3].parent_context.namespace_id,
            service_generation_digest=service_generation_digest,
            expires_monotonic=producer.expires_monotonic,
        )
        with self._task_handle_lock:
            self._controller_resolved_handles.add(handle.handle_id)
            self._resolved_controller_evidence[handle.handle_id] = (
                controller_handle, source_receipt.receipt_id, producer.identity,
                producer.uid, producer.profile_id, producer.generation,
                producer.expires_monotonic, role_artifact_id, role_sha256,
                service_generation_digest, producer.authority_epoch,
            )
        return controller_dto

    def verify_admitted_root_task_controller(
        self, handle: Any, task: Any, source: Any, controller: Any,
    ) -> bool:
        """Revalidate a root role PIDFD against the exact consumed resource task.

        This is the only service-side proof accepted for root-* controllers.
        It resolves current custody again from the retained event registry and
        compares that proof to the one-use duplicate handed to the runner.
        """
        from .resource_source_controllers import RootResourceEventHandle
        if (not isinstance(handle, RootResourceJobAdmissionHandle)
                or not isinstance(task, RootAdmittedTask)
                or not isinstance(source, RootAdmittedTaskSource)
                or not isinstance(controller, RootTaskController)
                or task.node_id != handle.node_id
                or controller.controller_kind not in {"root-scheduler", "root-webhook", "root-channel"}
                or controller.uid != 0 or controller.controller_profile_id is not None
                or controller.source_receipt_id is not None):
            return False
        with self._task_handle_lock:
            registered = self._running_task_handles.get(handle.handle_id)
            evidence = self._resolved_controller_evidence.get(handle.handle_id)
            expected_context = self._source_context_handles.get(handle.handle_id)
        root_event = self._root_event_by_job.get(handle.job_id)
        if (registered is None or registered[0] is not handle or len(registered) != 4
                or handle.handle_id not in self._controller_resolved_handles
                or evidence is None or evidence[0] != controller.controller_handle
                or root_event is None or evidence[1] != root_event.handle
                or source.controller_binding_handle != controller.controller_handle
                or source.source_context_handle != expected_context
                or source.parent_closure_digest != handle.parent_closure_digest
                or source.expires_monotonic <= self.service.monotonic()
                or task.deadline_monotonic <= self.service.monotonic()
                or handle.expires_monotonic <= self.service.monotonic()):
            return False
        _token, child, enrollment, event = registered
        issuer = getattr(self.service, "resource_event_context_issuer", None)
        registry = getattr(issuer, "controller_registry", None)
        if (not isinstance(root_event, RootResourceEventHandle)
                or event.source_capsule_lineage.get("root_event_handle") != root_event.handle
                or not self.ledger.is_child_admitted(
                    child, current_generation=self._resource_generation(enrollment))
                or not callable(getattr(issuer, "_require_live_selection", None))
                or registry is None):
            return False
        try:
            issuer._require_live_selection(enrollment)
            record, selected, _node, _backend = registry._resolve_event_node(root_event, task.node_id)
            context, receipts = issuer._verify_source_closure(
                record, enrollment, registry._profile_binding(enrollment), self.service.monotonic())
            self.service._verify_context_signature(context)
            binding = self.service._binding(context.uid)
            self.service._assert_current_context(context, binding, context.uid)
            for receipt in receipts:
                self.service._verify_source_receipt(receipt, binding)
            current = registry.resolve_for_event(root_event, task.node_id)
        except Exception:
            return False
        try:
            return bool(
                selected is enrollment and record.handle is root_event
                and context is event.parent_context and receipts == event.source_receipts
                and current.controller_kind == controller.controller_kind
                and current.controller_role_artifact_id == controller.controller_role_artifact_id
                and current.controller_role_sha256 == controller.controller_role_sha256
                and current.pid == controller.pid and current.uid == controller.uid
                and current.identity == controller.identity
                and current.controller_generation == controller.controller_generation
                and current.service_generation_digest == controller.service_generation_digest
                and current.expires_monotonic >= controller.expires_monotonic
                and current.service_generation_digest == getattr(
                    self.service, "service_generation_digest", None)
                and tuple(sorted(item.receipt_id for item in receipts))
                    == tuple(sorted(event.source_receipt_ids))
                and context.source_receipts == receipts
            )
        finally:
            try:
                os.close(current.pidfd)
            except OSError:
                pass

    def is_admitted_task_controller_current(
        self, handle: Any, node_id: str, controller: Any,
    ) -> bool:
        """Repeatably verify root controller custody without consuming its PIDFD."""
        if (not isinstance(handle, RootResourceJobAdmissionHandle)
                or handle.node_id != node_id or not isinstance(controller, RootTaskController)
                or controller.controller_kind not in {"root-scheduler", "root-webhook", "root-channel"}
                or controller.uid != 0 or controller.controller_profile_id is not None
                or controller.source_receipt_id is not None):
            return False
        with self._task_handle_lock:
            registered = self._running_task_handles.get(handle.handle_id)
            evidence = self._resolved_controller_evidence.get(handle.handle_id)
        root_event = self._root_event_by_job.get(handle.job_id)
        if (registered is None or registered[0] is not handle or len(registered) != 4
                or evidence is None or evidence[0] != controller.controller_handle
                or root_event is None or evidence[1] != root_event.handle
                or handle.handle_id not in self._controller_resolved_handles
                or not self.ledger.is_child_admitted(
                    registered[1], current_generation=self._resource_generation(registered[2]))
                or controller.expires_monotonic <= self.service.monotonic()):
            return False
        event = registered[3]
        issuer = getattr(self.service, "resource_event_context_issuer", None)
        registry = getattr(issuer, "controller_registry", None)
        if registry is None or event.source_capsule_lineage.get("root_event_handle") != root_event.handle:
            return False
        try:
            issuer._require_live_selection(registered[2])
            record, selected, _node, _backend = registry._resolve_event_node(root_event, node_id)
            context, receipts = issuer._verify_source_closure(
                record, registered[2], registry._profile_binding(registered[2]),
                self.service.monotonic())
            self.service._verify_context_signature(context)
            binding = self.service._binding(context.uid)
            self.service._assert_current_context(context, binding, context.uid)
            for receipt in receipts:
                self.service._verify_source_receipt(receipt, binding)
            current = registry.resolve_for_event(root_event, node_id)
        except Exception:
            return False
        try:
            return bool(
                selected is registered[2] and record.handle is root_event
                and context is event.parent_context and receipts == event.source_receipts
                and current.controller_kind == controller.controller_kind
                and current.controller_role_artifact_id == controller.controller_role_artifact_id
                and current.controller_role_sha256 == controller.controller_role_sha256
                and current.pid == controller.pid and current.uid == controller.uid
                and current.identity == controller.identity
                and current.controller_generation == controller.controller_generation
                and current.service_generation_digest == controller.service_generation_digest
                and current.service_generation_digest == self.service.service_generation_digest
                and current.expires_monotonic >= controller.expires_monotonic
            )
        finally:
            try:
                os.close(current.pidfd)
            except OSError:
                pass

    def resolve_admitted_task_parent_context(
        self, handle: Any, node_id: str, source_context_handle: str,
    ) -> HostContext:
        """Return the original signed parent context to the root issuer once.

        The returned context is source material, not a child grant. The
        AuthorityService must issue a fresh ``process.start`` context/grant
        with empty ``source_receipts`` (the parent receipts were already
        consumed by event admission) and must bind its lineage hash to the
        freshly revalidated full source-closure digest.
        """
        if (not isinstance(handle, RootResourceJobAdmissionHandle) or node_id != handle.node_id
                or not isinstance(source_context_handle, str)):
            raise AuthorityDenied("resource.source", "task parent context lookup is malformed")
        with self._task_handle_lock:
            registered = self._running_task_handles.get(handle.handle_id)
            expected_handle = self._source_context_handles.get(handle.handle_id)
            if (registered is None or registered[0] is not handle
                    or expected_handle != source_context_handle
                    or handle.handle_id not in self._source_resolved_handles
                    or handle.handle_id not in self._controller_resolved_handles
                    or handle.handle_id not in self._resolved_controller_evidence
                    or handle.handle_id in self._parent_context_resolved_handles):
                raise AuthorityDenied("resource.source", "task parent context is forged, stale, or consumed")
            self._parent_context_resolved_handles.add(handle.handle_id)
        _token, child, enrollment, event = registered
        backend = enrollment.backends.get(handle.backend_enrollment_id)
        binding = backend.execution_binding if backend is not None else None
        now = self.service.monotonic()
        current_generation = self._resource_generation(enrollment)
        node = enrollment.node_map.get(node_id)
        if (backend is None or binding is None or node is None
                or event.enrollment is not enrollment or event.admission.job_id != child.job_id
                or child.node_id != node_id or child.admission_id != handle.child_admission_id
                or child.retry_index != handle.attempt_index
                or current_generation != handle.resource_generation
                or backend.resource_id != enrollment.resource_id
                or backend.generation != enrollment.generation
                or backend.consent_revision != enrollment.consent_revision
                or backend.profile_id != enrollment.profile_id
                or backend.principal_id != enrollment.principal_id
                or self.service.profile_generations.get(enrollment.profile_id)
                   != event.parent_context.generation
                or now >= min(handle.expires_monotonic, event.admission.expires_monotonic)
                or not self.ledger.is_child_admitted(child, current_generation=current_generation)
                or handle.parent_closure_digest != _admitted_source_closure_digest(
                    event, child, node, backend)):
            raise AuthorityDenied("resource.source", "task parent context is stale or outside its selected job")
        root_event = self._root_event_by_job.get(child.job_id)
        if (root_event is not None
                and event.source_capsule_lineage.get("root_event_handle") == root_event.handle):
            issuer = getattr(self.service, "resource_event_context_issuer", None)
            registry = getattr(issuer, "controller_registry", None)
            evidence = self._resolved_controller_evidence.get(handle.handle_id)
            if registry is None or evidence is None or evidence[1] != root_event.handle:
                raise AuthorityDenied("resource.controller", "root event controller evidence is unavailable")
            try:
                issuer._require_live_selection(enrollment)
                record, selected, _node, _backend = registry._resolve_event_node(root_event, node_id)
                context, receipts = issuer._verify_source_closure(
                    record, enrollment, registry._profile_binding(enrollment), now)
                self.service._verify_context_signature(context)
                parent_binding = self.service._binding(context.uid)
                self.service._assert_current_context(context, parent_binding, context.uid)
                for receipt in receipts:
                    self.service._verify_source_receipt(receipt, parent_binding)
                controller = registry.resolve_for_event(root_event, node_id)
            except Exception:
                raise AuthorityDenied("resource.source", "root task parent closure is stale") from None
            try:
                if (selected is not enrollment or record.handle is not root_event
                        or context is not event.parent_context or receipts != event.source_receipts
                        or not context.native_process_identity
                        or context.sensitivity != event.sensitivity
                        or tuple(sorted(item.receipt_id for item in receipts))
                           != tuple(sorted(event.source_receipt_ids))
                        or controller.uid != 0
                        or controller.controller_kind not in {
                            "root-scheduler", "root-webhook", "root-channel"}
                        or controller.pid != evidence[3] or controller.uid != evidence[4]
                        or controller.controller_kind != evidence[5]
                        or controller.controller_role_artifact_id != evidence[6]
                        or controller.controller_role_sha256 != evidence[7]
                        or controller.controller_generation != evidence[8]
                        or controller.service_generation_digest != evidence[10]
                        or controller.expires_monotonic < evidence[9]):
                    raise AuthorityDenied("resource.controller", "root controller or source closure changed")
            finally:
                try:
                    os.close(controller.pidfd)
                except OSError:
                    pass
            retained = self._source_closures_by_job.get(child.job_id)
            if (retained is None or retained[0] is not context or retained[1] != receipts
                    or retained[3] <= now):
                raise AuthorityDenied("resource.source", "root authenticated source closure expired")
            return context
        if (binding["process_enrollment_id"] != handle.process_enrollment_id
                or binding["process_generation"] != handle.process_generation
                or binding["native_package_id"] != handle.native_package_id
                or binding["native_package_generation"] != handle.native_package_generation
                or binding["operation_id"] != handle.operation_id
                or binding["child_target_id"] != handle.child_target_id
                or binding["child_capability"] != handle.child_capability
                or binding["task_body_recipe_id"] != handle.task_body_recipe_id
                or binding["task_request_schema_id"] != handle.task_request_schema_id):
            raise AuthorityDenied("resource.selection", "process-start selection changed after task admission")
        resolver = getattr(self.service, "selected_operation_resolver", None)
        if not callable(resolver):
            raise AuthorityDenied("resource.selection", "root selected process operation resolver is unavailable")
        try:
            operation = resolver(
                handle.process_enrollment_id, handle.process_generation,
                "process.start", handle.operation_id,
            )
        except Exception:
            raise AuthorityDenied("resource.selection", "selected process-start operation is unavailable") from None
        if (getattr(operation, "operation", None) != "process.start"
                or getattr(operation, "operation_id", None) != handle.operation_id
                or getattr(operation, "target", None) != handle.child_target_id
                or getattr(operation, "enrollment_id", None) != handle.process_enrollment_id
                or getattr(operation, "generation", None) != handle.process_generation
                or getattr(operation, "profile_id", None) != enrollment.profile_id
                or getattr(operation, "principal_id", None) != enrollment.principal_id):
            raise AuthorityDenied("resource.selection", "selected process operation is outside the job principal")
        context = event.parent_context
        try:
            self.service._verify_context_signature(context)
            parent_binding = self.service._binding(context.uid)
            self.service._assert_current_context(context, parent_binding, context.uid)
            for receipt in event.source_receipts:
                self.service._verify_source_receipt(receipt, parent_binding)
        except Exception:
            raise AuthorityDenied("resource.source", "original signed parent context is no longer current") from None
        if (context.profile_id != enrollment.profile_id
                or context.principal_id != enrollment.principal_id
                or context.namespace_id == ""
                or context.sensitivity != event.sensitivity
                or tuple(sorted(item.receipt_id for item in context.source_receipts))
                   != tuple(sorted(event.source_receipt_ids))
                or context.source_receipts != event.source_receipts
                or tuple(sorted(item.receipt_id for item in event.source_receipts))
                   != tuple(sorted(event.source_receipt_ids))):
            raise AuthorityDenied("resource.source", "original source context or receipt closure changed")
        with self._event_lock:
            retained = self._source_closures_by_job.get(child.job_id)
        if (retained is None or retained[0] is not context
                or retained[1] != event.source_receipts
                or retained[2] != event.source_capsule_lineage
                or retained[3] <= now):
            raise AuthorityDenied("resource.source", "retained authenticated source closure expired or changed")
        evidence = self._resolved_controller_evidence.get(handle.handle_id)
        if (evidence is None or evidence[1] not in event.source_receipt_ids
                or evidence[3] != context.uid or evidence[4] != enrollment.profile_id
                or evidence[5] != context.generation or evidence[6] <= now
                or evidence[10] != getattr(self.service, "authority_epoch", None)):
            raise AuthorityDenied("resource.controller", "resolved task controller is stale or outside source closure")
        observer_registry = getattr(self.service, "source_observer_registry", None)
        producer_resolver = getattr(observer_registry, "resolve_live_source_producer", None)
        receipt = next((item for item in event.source_receipts if item.receipt_id == evidence[1]), None)
        if receipt is None or not callable(producer_resolver):
            raise AuthorityDenied("resource.controller", "live source controller proof is unavailable")
        try:
            live = producer_resolver(
                receipt.receipt_id, profile_id=receipt.profile_id,
                generation=receipt.process_generation,
                native_process_identity=receipt.native_process_identity,
                expires_monotonic=receipt.monotonic_expires_at,
            )
        except Exception:
            raise AuthorityDenied("resource.controller", "task source controller is no longer current") from None
        try:
            proof = live.loaded_package_proof
            if (live.receipt_id != receipt.receipt_id or live.identity != evidence[2]
                    or live.uid != evidence[3] or live.profile_id != evidence[4]
                    or live.generation != evidence[5] or live.expires_monotonic != evidence[6]
                    or getattr(proof, "role_artifact_id", None) != evidence[7]
                    or getattr(proof, "role_sha256", None) != evidence[8]
                    or live.authority_epoch != evidence[10]
                    or live.expires_monotonic <= now):
                raise AuthorityDenied("resource.controller", "task controller identity changed after resolution")
        finally:
            try:
                os.close(live.pidfd)
            except OSError:
                pass
        return context

    def resolve_admitted_task(self, handle: Any, node_id: str) -> RootAdmittedTask:
        """Project the exact neutral task DTO after source and handle validation."""
        if not isinstance(handle, RootResourceJobAdmissionHandle) or node_id != handle.node_id:
            raise AuthorityDenied("resource.process_task", "admitted task is not bound to the selected node")
        with self._task_handle_lock:
            registered = self._running_task_handles.get(handle.handle_id)
            context_handle = self._source_context_handles.get(handle.handle_id)
            source_resolved = handle.handle_id in self._source_resolved_handles
        if (registered is None or registered[0] is not handle or not source_resolved
                or not isinstance(context_handle, str) or self.task_handle_cancelled(handle, node_id)):
            raise AuthorityDenied("resource.process_task", "admitted task source or handle is not current")
        _token, child, enrollment, _event = registered
        backend = enrollment.backends.get(handle.backend_enrollment_id)
        binding = backend.execution_binding if backend is not None else None
        if (backend is None or binding is None or child.admission_id != handle.child_admission_id
                or child.retry_index != handle.attempt_index
                or enrollment.generation != handle.resource_generation
                or binding["process_enrollment_id"] != handle.process_enrollment_id
                or binding["process_generation"] != handle.process_generation
                or binding["native_package_id"] != handle.native_package_id
                or binding["native_package_generation"] != handle.native_package_generation
                or binding["operation_id"] != handle.operation_id
                or binding["task_body_recipe_id"] != handle.task_body_recipe_id
                or binding["task_request_schema_id"] != handle.task_request_schema_id):
            raise AuthorityDenied("resource.process_task", "admitted task selection changed after consume")
        value = json.loads(handle.task_payload.decode("utf-8"))
        stdin = value["prompt"].encode("utf-8")
        task = RootAdmittedTask(
            schema=1, admission_id=child.admission_id, job_id=child.job_id,
            node_id=child.node_id, backend_enrollment_id=backend.backend_id,
            resource_generation=enrollment.generation,
            process_enrollment_id=handle.process_enrollment_id,
            process_generation=handle.process_generation,
            native_package_id=backend.native_package_id,
            native_package_generation=backend.native_package_generation,
            operation_id=handle.operation_id, task_body_recipe_id=handle.task_body_recipe_id,
            task_request_schema_id=handle.task_request_schema_id,
            task_payload_sha256=handle.task_payload_sha256,
            task_payload_bytes=handle.task_payload,
            stdin_sha256=hashlib.sha256(stdin).hexdigest(), stdin_size_bytes=len(stdin),
            parent_closure_digest=handle.parent_closure_digest,
            deadline_monotonic=handle.expires_monotonic, source_context_handle=context_handle,
        )
        with self._task_handle_lock:
            current = self._running_task_handles.get(handle.handle_id)
            if (current is None or current[0] is not handle
                    or handle.handle_id in self._resolved_task_dtos):
                raise AuthorityDenied("resource.process_task", "admitted task DTO was already resolved or released")
            self._resolved_task_dtos[handle.handle_id] = task
        return task

    def start_task_handle(self, handle: Any, node_id: str) -> None:
        """Move the claimed child to running immediately before process.start bytes."""
        if not isinstance(handle, RootResourceJobAdmissionHandle) or node_id != handle.node_id:
            raise AuthorityDenied("resource.process_task", "root task start identity is invalid")
        with self._task_handle_lock:
            registered = self._running_task_handles.get(handle.handle_id)
        if registered is None or registered[0] is not handle:
            raise AuthorityDenied("resource.process_task", "root task handle is not consumed")
        _handle, child, enrollment, _event = registered
        if self.task_handle_cancelled(handle, node_id):
            raise AuthorityDenied("resource.process_task", "root task was cancelled before process start")
        try:
            self.ledger.start_child(child, current_generation=self._resource_generation(enrollment))
        except ResourceJobDenied:
            raise AuthorityDenied("resource.process_task", "root child attempt cannot start") from None

    def is_admitted_task_current(self, task: Any, selection_payload: bytes | None = None) -> bool:
        """Custody guard for the task token and, when supplied, exact launch envelope."""
        if (not isinstance(task, RootAdmittedTask)
                or selection_payload is not None and not isinstance(selection_payload, bytes)):
            return False
        envelope = None
        if selection_payload is not None:
            try:
                envelope = json.loads(selection_payload.decode("ascii"))
                if (not isinstance(envelope, dict)
                        or set(envelope) != {
                            "schema", "enrollment_id", "generation", "operation_id", "parameters",
                            "admission_handle", "node_id", "task_payload_sha256", "stdin_sha256",
                            "stdin_size_bytes", "source_profile_id", "home_binding_id",
                            "home_binding_handle", "home_binding_sha256",
                        }
                        or _canonical(envelope) != selection_payload
                        or envelope["schema"] != 1
                        or envelope["enrollment_id"] != task.process_enrollment_id
                        or envelope["generation"] != task.process_generation
                        or envelope["operation_id"] != task.operation_id
                        or envelope["parameters"] != {}
                        or envelope["node_id"] != task.node_id
                        or envelope["task_payload_sha256"] != task.task_payload_sha256
                        or envelope["stdin_sha256"] != task.stdin_sha256
                        or envelope["stdin_size_bytes"] != task.stdin_size_bytes):
                    return False
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                return False

        with self._task_handle_lock:
            candidates = [row for row in self._running_task_handles.values()
                          if row[1].admission_id == task.admission_id
                          and row[1].job_id == task.job_id
                          and row[1].node_id == task.node_id]
            if len(candidates) != 1:
                return False
            handle, child, enrollment, event = candidates[0]
            if (self._resolved_task_dtos.get(handle.handle_id) is not task
                    or envelope is not None and envelope["admission_handle"] != handle.handle_id
                    or self._source_context_handles.get(handle.handle_id) != task.source_context_handle
                    or handle.handle_id not in self._source_resolved_handles
                    or handle.handle_id not in self._controller_resolved_handles
                    or handle.handle_id not in self._parent_context_resolved_handles):
                return False
        try:
            now = self.service.monotonic()
            backend = enrollment.backends.get(task.backend_enrollment_id)
            node = enrollment.node_map.get(task.node_id)
            current_generation = self._resource_generation(enrollment)
            if (backend is None or node is None or event.enrollment is not enrollment
                    or task.admission_id != child.admission_id or task.job_id != child.job_id
                    or task.node_id != child.node_id or child.retry_index != handle.attempt_index
                    or task.resource_generation != enrollment.generation
                    or task.process_enrollment_id != handle.process_enrollment_id
                    or task.process_generation != handle.process_generation
                    or task.native_package_id != backend.native_package_id
                    or task.native_package_generation != backend.native_package_generation
                    or task.operation_id != handle.operation_id
                    or task.task_body_recipe_id != handle.task_body_recipe_id
                    or task.task_request_schema_id != handle.task_request_schema_id
                    or task.task_payload_bytes != handle.task_payload
                    or task.task_payload_sha256 != handle.task_payload_sha256
                    or task.stdin_sha256 != hashlib.sha256(
                        json.loads(handle.task_payload.decode("utf-8"))["prompt"].encode("utf-8")
                    ).hexdigest()
                    or task.stdin_size_bytes != len(
                        json.loads(handle.task_payload.decode("utf-8"))["prompt"].encode("utf-8")
                    )
                    or task.parent_closure_digest != handle.parent_closure_digest
                    or task.deadline_monotonic != handle.expires_monotonic
                    or now >= min(handle.expires_monotonic, event.admission.expires_monotonic)
                    or handle.parent_closure_digest != _admitted_source_closure_digest(
                        event, child, node, backend)
                    or current_generation != enrollment.generation
                    or backend.consent_revision != enrollment.consent_revision
                    or backend.profile_id != enrollment.profile_id
                    or backend.principal_id != enrollment.principal_id
                    or envelope is not None and (
                        not isinstance(backend.execution_binding, Mapping)
                        or envelope["source_profile_id"] != backend.execution_binding.get("source_profile_id")
                        or envelope["home_binding_id"] != backend.execution_binding.get("home_binding_id")
                        or not isinstance(envelope["home_binding_handle"], str)
                        or not envelope["home_binding_handle"]
                        or not isinstance(envelope["home_binding_sha256"], str)
                        or not re.fullmatch(r"[0-9a-f]{64}", envelope["home_binding_sha256"])
                    )
                    or self.service.profile_generations.get(enrollment.profile_id)
                       != event.parent_context.generation
                    or not self.ledger.is_job_active(child.job_id, current_generation=current_generation)
                    or not (self.ledger.is_child_admitted(child, current_generation=current_generation)
                            or self.ledger.is_active(child, current_generation=current_generation))):
                return False
            with self._event_lock:
                retained = self._source_closures_by_job.get(child.job_id)
            if (retained is None or retained[0] is not event.parent_context
                    or retained[1] != event.source_receipts
                    or retained[2] != event.source_capsule_lineage
                    or retained[3] <= now):
                return False
            self.service._verify_context_signature(event.parent_context)
            parent_binding = self.service._binding(event.parent_context.uid)
            self.service._assert_current_context(event.parent_context, parent_binding,
                                                 event.parent_context.uid)
            if event.parent_context.source_receipts != event.source_receipts:
                return False
            for receipt in event.source_receipts:
                self.service._verify_source_receipt(receipt, parent_binding)
            evidence = self._resolved_controller_evidence.get(handle.handle_id)
            observers = getattr(self.service, "source_observer_registry", None)
            resolver = getattr(observers, "resolve_live_source_producer", None)
            source_receipt = next((item for item in event.source_receipts
                                   if evidence is not None and item.receipt_id == evidence[1]), None)
            if evidence is None or source_receipt is None or not callable(resolver):
                return False
            live = resolver(
                source_receipt.receipt_id, profile_id=source_receipt.profile_id,
                generation=source_receipt.process_generation,
                native_process_identity=source_receipt.native_process_identity,
                expires_monotonic=source_receipt.monotonic_expires_at,
            )
            try:
                return bool(
                    live.receipt_id == source_receipt.receipt_id
                    and live.identity == evidence[2] and live.uid == evidence[3]
                    and live.profile_id == evidence[4] and live.generation == evidence[5]
                    and live.expires_monotonic == evidence[6] and live.expires_monotonic > now
                    and live.authority_epoch == evidence[10]
                    and evidence[10] == getattr(self.service, "authority_epoch", None)
                )
            finally:
                os.close(live.pidfd)
        except Exception:
            return False

    def is_task_admission_current(self, task: Any) -> bool:
        """One-argument callback for managed task custody; custody validates its envelope."""
        return self.is_admitted_task_current(task)

    def task_handle_cancelled(self, handle: Any, node_id: str) -> bool:
        """Root launcher poll hook; stale, revoked, or unknown tokens cancel."""
        if not isinstance(handle, RootResourceJobAdmissionHandle) or node_id != handle.node_id:
            return True
        with self._task_handle_lock:
            registered = self._running_task_handles.get(handle.handle_id)
        if registered is None or registered[0] is not handle:
            return True
        _, child, enrollment, _event = registered
        try:
            generation = self._resource_generation(enrollment)
            job_active = self.ledger.is_job_active(child.job_id, current_generation=generation)
            cancelled = (self.service.monotonic() >= handle.expires_monotonic
                         or not job_active
                         or not (self.ledger.is_child_admitted(child, current_generation=generation)
                                 or self.ledger.is_active(child, current_generation=generation)))
            if not job_active:
                self._discard_job_event_fields(child.job_id)
            return cancelled
        except Exception:
            self._discard_job_event_fields(child.job_id)
            return True

    def release_task_handle(self, handle: Any, node_id: str) -> None:
        """Drop root-local task handle state after terminal/result reconciliation."""
        if not isinstance(handle, RootResourceJobAdmissionHandle) or node_id != handle.node_id:
            raise AuthorityDenied("resource.process_task", "root task handle release identity is invalid")
        with self._task_handle_lock:
            registered = self._running_task_handles.pop(handle.handle_id, None)
            self._resolved_task_dtos.pop(handle.handle_id, None)
            self._source_resolved_handles.discard(handle.handle_id)
            self._source_context_handles.pop(handle.handle_id, None)
            self._controller_resolved_handles.discard(handle.handle_id)
            self._resolved_controller_evidence.pop(handle.handle_id, None)
            self._parent_context_resolved_handles.discard(handle.handle_id)
            controller = self._task_controller_bindings.pop(handle.handle_id, None)
        if controller is not None:
            try:
                os.close(controller[1].pidfd)
            except OSError:
                pass
        if registered is None or registered[0] is not handle:
            raise AuthorityDenied("resource.process_task", "root task handle is not actively owned")

    def _store_result_fields(self, child: ResourceChildAdmission, receipt_id: str,
                             fields: Mapping[str, Any], *, expires: float,
                             maximum_bytes: int) -> None:
        if not isinstance(fields, Mapping) or len(fields) > 64:
            raise AuthorityDenied("resource.result", "selected result fields are malformed")
        payload = bytearray(_canonical(dict(fields)))
        if (type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 2 * 1024 * 1024
                or len(payload) > maximum_bytes):
            payload[:] = b"\x00" * len(payload)
            raise AuthorityDenied("resource.result", "selected result fields exceed their bound")
        try:
            _ident(receipt_id, "root result receipt id")
        except ResourceJobDenied:
            payload[:] = b"\x00" * len(payload)
            raise AuthorityDenied("resource.result", "root result receipt identity is invalid") from None
        with self._event_lock:
            self._prune_event_fields_locked(self.service.monotonic())
            rows = self._result_fields_by_job.setdefault(child.job_id, {})
            if (child.node_id in rows or self._event_field_bytes + len(payload) > 8 * 1024 * 1024):
                payload[:] = b"\x00" * len(payload)
                raise AuthorityDenied("resource.capacity", "root result-field store is full or duplicated")
            rows[child.node_id] = (receipt_id, payload)
            self._result_fields_expiry[child.job_id] = expires
            self._event_field_bytes += len(payload)

    def _retain_task_result_capsule(
        self, child: ResourceChildAdmission, event: _JobEvent,
        backend: ResourceBackendEnrollment, receipt: RootResourceProcessReceipt,
        result: Mapping[str, Any], capsule_sha256: str,
    ) -> None:
        """Bind only the runner-validated capsule to this exact child attempt."""
        if (not isinstance(receipt, RootResourceProcessReceipt)
                or not isinstance(result, Mapping)
                or receipt.job_id != child.job_id or receipt.node_id != child.node_id
                or receipt.backend_enrollment_id != backend.backend_id
                or not _HEX64.fullmatch(capsule_sha256)
                or result.get("receipt_id") is None
                or not isinstance(result.get("receipt_id"), str)
                or not isinstance(result.get("body"), bytes)):
            raise AuthorityDenied("resource.result", "validated task capsule does not bind its child attempt")
        binding = _RootResultCapsuleBinding(
            node_id=child.node_id, admission_id=child.admission_id,
            receipt_id=result["receipt_id"], capsule_handle=receipt.result_capsule_handle,
            capsule_sha256=capsule_sha256, backend_enrollment_id=backend.backend_id,
            resource_generation=event.enrollment.generation,
            service_generation_digest=self.service.service_generation_digest or "",
            expires_monotonic=min(receipt.expires_monotonic, event.admission.expires_monotonic),
        )
        if (not _HEX64.fullmatch(binding.service_generation_digest)
                or binding.expires_monotonic <= self.service.monotonic()):
            raise AuthorityDenied("resource.result", "validated task result capsule lease is stale")
        with self._event_lock:
            rows = self._result_capsules_by_job.setdefault(child.job_id, {})
            if child.node_id in rows or sum(len(value) for value in self._result_capsules_by_job.values()) >= 1024:
                raise AuthorityDenied("resource.capacity", "root task result capsule registry is full or duplicated")
            rows[child.node_id] = binding

    def _load_parent_results(self, job_id: str) -> Mapping[str, tuple[str, Mapping[str, Any]]]:
        with self._event_lock:
            self._prune_event_fields_locked(self.service.monotonic())
            result: dict[str, tuple[str, Mapping[str, Any]]] = {}
            for node_id, (receipt_id, payload) in self._result_fields_by_job.get(job_id, {}).items():
                try:
                    fields = json.loads(bytes(payload).decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise AuthorityDenied("resource.result", "root result-field capsule is corrupt") from None
                if not isinstance(fields, dict):
                    raise AuthorityDenied("resource.result", "root result-field capsule has invalid shape")
                result[node_id] = (receipt_id, MappingProxyType(fields))
            return MappingProxyType(result)

    def _discard_result_fields(self, job_id: str, node_id: str) -> None:
        with self._event_lock:
            rows = self._result_fields_by_job.get(job_id)
            row = rows.pop(node_id, None) if rows is not None else None
            if row is not None:
                self._event_field_bytes -= len(row[1])
                row[1][:] = b"\x00" * len(row[1])
            if rows == {}:
                self._result_fields_by_job.pop(job_id, None)
                self._result_fields_expiry.pop(job_id, None)
            capsules = self._result_capsules_by_job.get(job_id)
            if capsules is not None:
                capsules.pop(node_id, None)
                if not capsules:
                    self._result_capsules_by_job.pop(job_id, None)

    def _consume_selected_event_capsule(
            self, enrollment: ResourceJobEnrollment, *, context: HostContext,
            authorization: EffectAuthorization, peer_pid: int, peer_pidfd: int | None,
            receipts: Sequence[Any], requested_event_id: str) -> tuple[Mapping[str, Any], Any]:
        """Consume one selected root capsule and retain only validated recipe fields."""
        registry = getattr(self.service, "source_observer_registry", None)
        observers = getattr(registry, "observers", None)
        observer = observers.get(enrollment.observer_enrollment_id) if isinstance(observers, Mapping) else None
        if (observer is None or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0):
            raise AuthorityDenied("resource.source", "root observer capsule registry or live peer is unavailable")
        expected_kind = _SOURCE_KIND_BY_KIND.get(enrollment.kind)
        primary = [receipt for receipt in receipts
                   if receipt.profile_id == enrollment.profile_id
                   and receipt.principal_id == enrollment.principal_id
                   and receipt.uid == authorization.uid
                   and (expected_kind is None or receipt.source_kind == expected_kind)
                   and receipt.source_kind in enrollment.source_policy
                   and receipt.origin_id == f"{observer.origin_id}:{requested_event_id}"]
        if len(primary) != 1:
            raise AuthorityDenied("resource.source", "one exact signed root-observed source receipt is required")
        source_receipt = primary[0]
        if any(node.recipient is not None and node.recipient not in source_receipt.recipient_ceiling
               for node in enrollment.nodes):
            raise AuthorityDenied("resource.source", "observed source recipient ceiling is too narrow")
        receipt_ids = {item.receipt_id for item in receipts}
        if len(receipt_ids) != len(receipts):
            raise AuthorityDenied("resource.source", "signed source closure repeats a receipt")
        if any(item.source_kind not in observer.allowed_parent_source_kinds
               for item in receipts if item.receipt_id != source_receipt.receipt_id):
            raise AuthorityDenied("resource.source", "source parent kind is outside the selected observer closure")
        try:
            handle = registry.lookup_source_handle(
                source_receipt.receipt_id, signed_context=context, peer_uid=authorization.uid,
                peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            )
            capsule = registry.consume_source_payload_capsule(
                handle, signed_context=context, peer_uid=authorization.uid,
                peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            )
        except Exception:
            raise AuthorityDenied("resource.source", "root source payload capsule is unavailable or already consumed") from None
        if (capsule.receipt_id != source_receipt.receipt_id
                or capsule.observer_enrollment_id != enrollment.observer_enrollment_id
                or capsule.event_record_id != requested_event_id
                or capsule.source_kind not in enrollment.source_policy
                or expected_kind is not None and capsule.source_kind != expected_kind
                or capsule.channel_id != enrollment.source_issuer_channel_id
                or capsule.capture_schema_id != enrollment.source_capture_schema_id
                or capsule.source_action_id not in enrollment.source_action_ids
                or capsule.profile_id != enrollment.profile_id
                or capsule.principal_id != enrollment.principal_id
                or capsule.generation != enrollment.profile_generation
                or observer.source_action_id != capsule.source_action_id
                or observer.capture_schema_id != capsule.capture_schema_id
                or set(capsule.parent_receipt_ids) != receipt_ids - {source_receipt.receipt_id}
                or capsule.parent_closure_digest != canonical_digest(capsule.parent_receipt_ids)
                or hashlib.sha256(capsule.payload_bytes).hexdigest() != capsule.payload_sha256
                or len(capsule.payload_bytes) > enrollment.max_payload_bytes):
            raise AuthorityDenied("resource.source", "captured source capsule does not join the selected generation")
        try:
            content = json.loads(capsule.payload_bytes.decode("utf-8"))
            if not isinstance(content, dict) or _canonical(content) != capsule.payload_bytes:
                raise ValueError
            selected: dict[str, Any] = {}
            for recipe in enrollment.body_recipes.values():
                for field in recipe.output_fields:
                    if field.source != "observed-event-field":
                        continue
                    name = field.value
                    if name not in content:
                        raise ResourceJobDenied("selected event field is missing from its captured schema")
                    validator = enrollment.validators[field.validator_id]
                    value = validator.validate_scalar(content[name])
                    if name in selected and selected[name] != value:
                        raise ResourceJobDenied("event field has incompatible selected validators")
                    selected[name] = value
            selected_payload = _canonical(selected)
            if len(selected_payload) > enrollment.max_payload_bytes:
                raise ResourceJobDenied("selected event fields exceed the job payload bound")
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, ResourceJobDenied):
            raise AuthorityDenied("resource.source", "captured event bytes fail selected field validation") from None
        return MappingProxyType(selected), capsule

    def _reserve_event_fields(self, values: Mapping[str, Any]) -> str:
        payload = bytearray(_canonical(dict(values)))
        now = self.service.monotonic()
        with self._event_lock:
            self._prune_event_fields_locked(now)
            if (len(self._event_fields_by_job) + len(self._event_field_reservations) >= 1024
                    or self._event_field_bytes + len(payload) > 8 * 1024 * 1024):
                payload[:] = b"\x00" * len(payload)
                raise AuthorityDenied("resource.capacity", "root selected event-field store is full")
            token = secrets.token_urlsafe(32)
            self._event_field_reservations[token] = payload
            self._event_field_bytes += len(payload)
            return token

    def _promote_event_fields(
        self, token: str, job_id: str, expires: float, *,
        source_closure: tuple[HostContext, tuple[Any, ...], Mapping[str, Any], float],
    ) -> None:
        with self._event_lock:
            payload = self._event_field_reservations.pop(token, None)
            if (payload is None or job_id in self._event_fields_by_job
                    or job_id in self._source_closures_by_job
                    or not isinstance(source_closure[0], HostContext)
                    or source_closure[3] != expires):
                if payload is not None:
                    self._event_field_bytes -= len(payload)
                    payload[:] = b"\x00" * len(payload)
                raise AuthorityDenied("resource.capacity", "root event-field admission reservation is stale")
            self._event_fields_by_job[job_id] = (payload, expires)
            self._source_closures_by_job[job_id] = source_closure

    def _discard_event_field_reservation(self, token: str) -> None:
        with self._event_lock:
            payload = self._event_field_reservations.pop(token, None)
            if payload is not None:
                self._event_field_bytes -= len(payload)
                payload[:] = b"\x00" * len(payload)

    def _discard_job_event_fields(self, job_id: str) -> None:
        with self._event_lock:
            self._source_closures_by_job.pop(job_id, None)
            row = self._event_fields_by_job.pop(job_id, None)
            if row is not None:
                self._event_field_bytes -= len(row[0])
                row[0][:] = b"\x00" * len(row[0])
            results = self._result_fields_by_job.pop(job_id, {})
            for _receipt_id, payload in results.values():
                self._event_field_bytes -= len(payload)
                payload[:] = b"\x00" * len(payload)
            self._result_fields_expiry.pop(job_id, None)
            self._result_capsules_by_job.pop(job_id, None)
            for key, (closure, _values) in tuple(self._root_result_closures.items()):
                if closure.admission_handle == job_id:
                    self._root_result_closures.pop(key, None)

    def _prune_event_fields_locked(self, now: float) -> None:
        for job_id, (payload, expires) in tuple(self._event_fields_by_job.items()):
            if expires <= now:
                self._event_fields_by_job.pop(job_id, None)
                self._event_field_bytes -= len(payload)
                payload[:] = b"\x00" * len(payload)
        for job_id, (_context, _receipts, _capsule, expires) in tuple(self._source_closures_by_job.items()):
            if expires <= now:
                self._source_closures_by_job.pop(job_id, None)
        for job_id, expires in tuple(self._result_fields_expiry.items()):
            if expires <= now:
                results = self._result_fields_by_job.pop(job_id, {})
                self._result_fields_expiry.pop(job_id, None)
                for _receipt_id, payload in results.values():
                    self._event_field_bytes -= len(payload)
                    payload[:] = b"\x00" * len(payload)
        for job_id, rows in tuple(self._result_capsules_by_job.items()):
            kept = {node_id: row for node_id, row in rows.items() if row.expires_monotonic > now}
            if kept:
                self._result_capsules_by_job[job_id] = kept
            else:
                self._result_capsules_by_job.pop(job_id, None)
        for key, (closure, _values) in tuple(self._root_result_closures.items()):
            if closure.expires_monotonic <= now:
                self._root_result_closures.pop(key, None)

    def _load_event_fields(self, job_id: str) -> Mapping[str, Any]:
        now = self.service.monotonic()
        with self._event_lock:
            self._prune_event_fields_locked(now)
            row = self._event_fields_by_job.get(job_id)
            if row is None:
                raise AuthorityDenied("resource.source", "root event fields expired or are unavailable")
            try:
                value = json.loads(bytes(row[0]).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._discard_job_event_fields(job_id)
                raise AuthorityDenied("resource.source", "root event-field capsule is corrupt") from None
            if not isinstance(value, dict):
                self._discard_job_event_fields(job_id)
                raise AuthorityDenied("resource.source", "root event-field capsule has invalid shape")
            return MappingProxyType(value)

    def _assert_selected_context(self, context: HostContext, authorization: EffectAuthorization,
                                 enrollment: ResourceJobEnrollment, operation: str) -> None:
        if (context.profile_id != enrollment.profile_id or context.principal_id != enrollment.principal_id
                or context.uid != authorization.uid
                or context.operation != operation
                or authorization.profile_id != enrollment.profile_id
                or authorization.principal_id != enrollment.principal_id
                or authorization.operation != operation
                or authorization.capability != _CAPABILITY
                or authorization.generation != self.service.profile_generations.get(enrollment.profile_id)
                or context.generation != authorization.generation):
            raise AuthorityDenied("resource.selection", "resource job caller is outside the current selected profile")
        if context.source_receipts != authorization.source_receipts:
            raise AuthorityDenied("resource.source", "job context and effect source closure differ")

    def _resource_generation(self, enrollment: ResourceJobEnrollment) -> str:
        # Every admission, retry, and cancellation callback re-reads the
        # protected selected snapshot. The profile generation on HostContext
        # is a separate binding and cannot substitute for resource selection.
        try:
            current = self.selected_generation(enrollment.resource_id)
        except Exception:
            raise AuthorityDenied("resource.selection", "current selected resource generation is unavailable") from None
        if not isinstance(current, str) or not current:
            raise AuthorityDenied("resource.selection", "current selected resource generation is unavailable")
        if current != enrollment.generation:
            self.ledger.revoke_generation(enrollment.resource_id, enrollment.generation)
        return current

    def _event(self, job_id: str, enrollment: ResourceJobEnrollment) -> _JobEvent:
        try:
            admission = self.ledger.load_admission(job_id, enrollment=enrollment)
            receipts, lineage, sensitivity = self.ledger.job_provenance(job_id, enrollment=enrollment)
            event_fields = self._load_event_fields(job_id)
            parent_results = self._load_parent_results(job_id)
            with self._event_lock:
                source_closure = self._source_closures_by_job.get(job_id)
            if source_closure is None or source_closure[3] <= self.service.monotonic():
                raise ResourceJobDenied("verified source closure expired or was not retained")
            parent_context, source_receipts, capsule_lineage, _expires = source_closure
            if (tuple(sorted(item.receipt_id for item in parent_context.source_receipts))
                    != tuple(sorted(receipts))
                    or tuple(sorted(item.receipt_id for item in source_receipts))
                    != tuple(sorted(receipts))):
                raise ResourceJobDenied("retained parent source closure differs from the durable job admission")
            event = _JobEvent(
                enrollment, admission, receipts, Sensitivity(sensitivity), lineage,
                _freeze_mapping(event_fields), _freeze_parent_results(parent_results),
                parent_context, source_receipts, capsule_lineage,
            )
        except (ResourceJobDenied, ValueError):
            raise AuthorityDenied("resource.job", "job is outside the selected resource generation") from None
        if not self.ledger.is_job_active(job_id, current_generation=self._resource_generation(enrollment)):
            self._discard_job_event_fields(job_id)
            raise AuthorityDenied("resource.job", "resource job is cancelled or expired")
        return event


def _payload(payload: bytes, fields: set[str]) -> dict[str, Any]:
    if not isinstance(payload, bytes) or len(payload) > 1_048_576:
        raise AuthorityDenied("resource.request", "resource job payload exceeds its bound")
    try:
        value = json.loads(payload.decode("utf-8"))
        if (not isinstance(value, dict) or set(value) != fields
                or json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                              allow_nan=False).encode("utf-8") != payload):
            raise ValueError
        return value
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, TypeError):
        raise AuthorityDenied("resource.request", "resource job payload is not the exact canonical schema") from None


def _capsule_lineage(capsule: Any) -> Mapping[str, Any]:
    """Retain only immutable provenance metadata; the capsule payload is scrubbed upstream."""
    names = (
        "receipt_id", "observer_enrollment_id", "event_record_id", "invocation_id",
        "source_kind", "channel_id", "capture_schema_id", "source_action_id",
        "profile_id", "principal_id", "namespace_id", "generation", "payload_sha256", "parent_receipt_ids",
        "parent_closure_digest", "issued_monotonic", "expires_monotonic",
    )
    values = {name: getattr(capsule, name, None) for name in names}
    text_fields = set(names) - {"parent_receipt_ids", "issued_monotonic", "expires_monotonic"}
    if (any(not isinstance(values[name], str) or not values[name] for name in text_fields)
            or not isinstance(values["parent_receipt_ids"], tuple)
            or not _HEX64.fullmatch(values["payload_sha256"])
            or not _HEX64.fullmatch(values["parent_closure_digest"])):
        raise AuthorityDenied("resource.source", "verified source capsule provenance is incomplete")
    values["parent_receipt_ids"] = tuple(values["parent_receipt_ids"])
    return MappingProxyType(values)


def _admitted_source_closure_digest(event: _JobEvent, child: ResourceChildAdmission,
                                    node: ResourceJobNode,
                                    backend: ResourceBackendEnrollment) -> str:
    """Bind task launch to the complete root-held event and selected closure."""
    context = event.parent_context
    source_receipts = sorted((receipt.to_wire() for receipt in event.source_receipts),
                             key=lambda row: row["receipt_id"])
    parent_results = [
        {"node_id": node_id, "receipt_id": receipt_id,
         "fields_sha256": hashlib.sha256(_canonical(_plain(fields))).hexdigest()}
        for node_id, (receipt_id, fields) in sorted(event.parent_results.items())
    ]
    return canonical_digest({
        "job_id": child.job_id, "node_id": child.node_id,
        "child_admission_id": child.admission_id, "attempt": child.retry_index,
        "action_id": node.action_id, "effect": node.effect, "target": node.target,
        "recipient": node.recipient, "request_schema_id": node.request_schema_id,
        "body_recipe_id": node.body_recipe_id,
        "resource_id": event.enrollment.resource_id,
        "resource_generation": event.enrollment.generation,
        "consent_revision": event.enrollment.consent_revision,
        "approved_dag_sha256": event.admission.approved_dag_sha256,
        "profile_id": backend.profile_id, "profile_generation": backend.profile_generation,
        "principal_id": event.enrollment.principal_id,
        "native_package_id": backend.native_package_id,
        "native_package_generation": backend.native_package_generation,
        "process_enrollment_id": backend.execution_binding["process_enrollment_id"],
        "process_generation": backend.execution_binding["process_generation"],
        "task_body_recipe_id": backend.execution_binding["task_body_recipe_id"],
        "task_request_schema_id": backend.execution_binding["task_request_schema_id"],
        "scope_binding_ids": sorted(binding.scope_binding_id
                                      for binding in event.enrollment.scope_bindings.values()),
        "parent_context": context.to_wire(),
        "source_receipts": source_receipts,
        "source_capsule_lineage": _plain(event.source_capsule_lineage),
        "event_fields_sha256": hashlib.sha256(_canonical(_plain(event.event_fields))).hexdigest(),
        "parent_result_receipt_ids": list(child.parent_result_receipt_ids),
        "parent_results": parent_results,
        "lineage_hash": event.lineage_hash,
        "sensitivity": event.sensitivity.value,
    })


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze_json(item) for item in value)
    return value


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})


def _freeze_parent_results(value: Mapping[str, tuple[str, Mapping[str, Any]]]
                           ) -> Mapping[str, tuple[str, Mapping[str, Any]]]:
    return MappingProxyType({node_id: (receipt_id, _freeze_mapping(fields))
                             for node_id, (receipt_id, fields) in value.items()})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _check_job_cancelled(cancelled: Callable[[], bool], ledger: ResourceJobLedger,
                         child: ResourceChildAdmission, generation: str) -> None:
    if cancelled() or not ledger.is_active(child, current_generation=generation):
        raise AuthorityDenied("resource.child", "resource child is cancelled before dispatch")
