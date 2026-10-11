"""Root-owned durable admission ledger for selected Resources jobs.

This module stores bounded immutable DAG jobs and gives each child attempt a
single-use admission. It deliberately does not mint authority contexts or
effect grants: the protected AuthorityService must verify the signed event
receipts and issue a fresh child grant after ``admit_child`` succeeds.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import os
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from .resources_runtime import ResourceRuntimeError


class ResourceJobDenied(ResourceRuntimeError):
    """A resource job or child transition failed its protected bounds."""


_ID = re.compile(r"[A-Za-z0-9_.:@/-]{1,256}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_EFFECTS = frozenset({
    "resource.cron.run", "resource.webhook.run", "resource.channel.run",
    "resource.bundle.node.run",
})
_SOURCE_KINDS = frozenset({"schedule-event", "webhook-event", "native-input",
                           "static-context", "tool-result", "provider-result",
                           "memory-record"})


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        raise ResourceJobDenied("job payload is not canonical JSON") from None


def _ident(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ResourceJobDenied(f"{label} is invalid")
    return value


def _freeze_json(value: Any) -> Any:
    """Copy protected JSON recipe values into immutable containers."""
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ResourceJobDenied("body recipe contains a non-string object key")
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    if value is None or type(value) in {str, int, float, bool}:
        if type(value) is float and not __import__("math").isfinite(value):
            raise ResourceJobDenied("body recipe contains a non-finite number")
        return value
    raise ResourceJobDenied("body recipe value is not JSON data")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class ResourceBodyRecipeField:
    name: str
    source: str
    value: Any
    validator_id: str

    def __post_init__(self) -> None:
        _ident(self.name, "body recipe field name")
        _ident(self.validator_id, "body recipe validator id")
        if self.source not in {"literal", "observed-event-field", "owned-parent-result-field"}:
            raise ResourceJobDenied("body recipe source is not protected")
        object.__setattr__(self, "value", _freeze_json(self.value))
        if self.source == "observed-event-field":
            _ident(self.value, "observed event field key")
        elif self.source == "owned-parent-result-field":
            if (not isinstance(self.value, Mapping) or set(self.value) != {"node_id", "field"}):
                raise ResourceJobDenied("owned parent result selector must name one node and field")
            _ident(self.value["node_id"], "owned parent result node ID")
            _ident(self.value["field"], "owned parent result field key")


@dataclass(frozen=True, slots=True)
class ResourceBodyRecipeScope:
    name: str
    scope_binding_id: str
    field: str
    validator_id: str

    def __post_init__(self) -> None:
        for name in ("name", "scope_binding_id", "field", "validator_id"):
            _ident(getattr(self, name), f"body recipe scope {name}")


@dataclass(frozen=True, slots=True)
class ResourceScopeBinding:
    scope_binding_id: str
    resource_id: str
    profile_id: str
    principal_id: str
    resource_generation: str
    profile_generation: str
    backend_enrollment_id: str
    fixed_fields: Mapping[str, Any]
    credential_reference_ids: frozenset[str]
    recipient: str | None

    def __post_init__(self) -> None:
        for name in ("scope_binding_id", "resource_id", "profile_id", "principal_id",
                     "resource_generation", "profile_generation", "backend_enrollment_id"):
            _ident(getattr(self, name), name)
        if self.recipient is not None:
            _ident(self.recipient, "scope recipient")
        if not isinstance(self.fixed_fields, Mapping) or len(self.fixed_fields) > 64:
            raise ResourceJobDenied("scope fixed fields are malformed")
        frozen = {}
        for name, value in self.fixed_fields.items():
            _ident(name, "scope field name")
            frozen[name] = _freeze_json(value)
        object.__setattr__(self, "fixed_fields", MappingProxyType(frozen))
        if not isinstance(self.credential_reference_ids, (set, frozenset)):
            raise ResourceJobDenied("scope credential references must be a protected set")
        object.__setattr__(self, "credential_reference_ids",
                           frozenset(_ident(value, "scope credential reference")
                                     for value in self.credential_reference_ids))


@dataclass(frozen=True, slots=True)
class ResourceValidator:
    validator_id: str
    kind: str
    maximum_bytes: int | None
    minimum: int | None
    maximum: int | None
    allowed_values: tuple[Any, ...] | None
    schema_artifact_id: str | None
    schema_sha256: str | None

    def __post_init__(self) -> None:
        _ident(self.validator_id, "validator id")
        if self.kind not in {"utf8-string", "opaque-id", "integer", "boolean", "enum", "bounded-json"}:
            raise ResourceJobDenied("validator kind is not in the protected closed set")
        if self.kind in {"utf8-string", "opaque-id", "bounded-json"}:
            if type(self.maximum_bytes) is not int or not 1 <= self.maximum_bytes <= 262_144:
                raise ResourceJobDenied("validator byte bound is invalid")
        elif self.maximum_bytes is not None:
            raise ResourceJobDenied("validator has an inapplicable byte bound")
        if self.kind == "integer":
            if (type(self.minimum) is not int or type(self.maximum) is not int
                    or self.minimum > self.maximum):
                raise ResourceJobDenied("integer validator bounds are invalid")
        elif self.minimum is not None or self.maximum is not None:
            raise ResourceJobDenied("validator has inapplicable integer bounds")
        if self.kind == "enum":
            if (not isinstance(self.allowed_values, tuple) or not 1 <= len(self.allowed_values) <= 128
                    or any(type(value) not in {str, int, bool} for value in self.allowed_values)
                    or len({(type(value), value) for value in self.allowed_values}) != len(self.allowed_values)):
                raise ResourceJobDenied("enum validator values are invalid")
        elif self.allowed_values is not None:
            raise ResourceJobDenied("validator has inapplicable enum values")
        if self.kind == "bounded-json":
            if (not isinstance(self.schema_artifact_id, str)
                    or not isinstance(self.schema_sha256, str)
                    or not _DIGEST.fullmatch(self.schema_sha256)):
                raise ResourceJobDenied("bounded JSON validator needs a pinned schema artifact")
        elif self.schema_artifact_id is not None or self.schema_sha256 is not None:
            raise ResourceJobDenied("validator has inapplicable schema artifact fields")

    def validate_scalar(self, value: Any) -> Any:
        if self.kind == "utf8-string":
            if (not isinstance(value, str) or not value
                    or len(value.encode("utf-8")) > self.maximum_bytes):
                raise ResourceJobDenied("value failed the protected UTF-8 string validator")
        elif self.kind == "opaque-id":
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
                raise ResourceJobDenied("value failed the protected opaque ID validator")
        elif self.kind == "integer":
            if type(value) is not int or not self.minimum <= value <= self.maximum:
                raise ResourceJobDenied("value failed the protected integer validator")
        elif self.kind == "boolean":
            if type(value) is not bool:
                raise ResourceJobDenied("value failed the protected boolean validator")
        elif self.kind == "enum":
            if not any(type(value) is type(item) and value == item for item in self.allowed_values):
                raise ResourceJobDenied("value failed the protected enum validator")
        elif self.kind == "bounded-json":
            rendered = _canonical(value)
            if len(rendered) > self.maximum_bytes:
                raise ResourceJobDenied("value exceeds the protected JSON byte bound")
            _validate_json_depth(value, max_depth=16)
            # A digest pin alone is not schema validation. Until root assembly
            # supplies the selected artifact's strict validator, do not accept
            # structured caller/event data under this validator kind.
            raise ResourceJobDenied("strict bounded JSON schema artifact validator is unavailable")
        return _thaw_json(_freeze_json(value))


def _validate_json_depth(value: Any, *, max_depth: int) -> None:
    stack = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ResourceJobDenied("JSON value exceeds the protected nesting depth")
        if isinstance(current, Mapping):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (tuple, list)):
            stack.extend((item, depth + 1) for item in current)


@dataclass(frozen=True, slots=True)
class ResourceBodyRecipe:
    recipe_id: str
    schema_id: str
    source_artifact_id: str
    source_sha256: str
    output_fields: tuple[ResourceBodyRecipeField, ...]
    scope_bindings: tuple[ResourceBodyRecipeScope, ...]
    maximum_bytes: int

    def __post_init__(self) -> None:
        for name in ("recipe_id", "schema_id", "source_artifact_id"):
            _ident(getattr(self, name), name)
        if not _DIGEST.fullmatch(self.source_sha256):
            raise ResourceJobDenied("body recipe source digest is invalid")
        if (not isinstance(self.output_fields, tuple) or not 1 <= len(self.output_fields) <= 64
                or any(not isinstance(field, ResourceBodyRecipeField) for field in self.output_fields)
                or len({field.name for field in self.output_fields}) != len(self.output_fields)):
            raise ResourceJobDenied("body recipe output fields are malformed")
        raw_scopes = self.scope_bindings
        if isinstance(raw_scopes, Mapping) and not raw_scopes:
            raw_scopes = ()
        if (not isinstance(raw_scopes, tuple) or len(raw_scopes) > 64
                or any(not isinstance(item, ResourceBodyRecipeScope) for item in raw_scopes)
                or len({item.name for item in raw_scopes}) != len(raw_scopes)
                or {item.name for item in raw_scopes} & {item.name for item in self.output_fields}):
            raise ResourceJobDenied("body recipe scope bindings are malformed")
        object.__setattr__(self, "scope_bindings", tuple(raw_scopes))
        if type(self.maximum_bytes) is not int or not 1 <= self.maximum_bytes <= 256 * 1024:
            raise ResourceJobDenied("body recipe size bound is invalid")

    def render_literals(self) -> bytes:
        """Render only recipes that need no event/result or account-scope data."""
        if self.scope_bindings or any(field.source != "literal" for field in self.output_fields):
            raise ResourceJobDenied("body recipe needs protected event, result, or scope values")
        rendered = _canonical({field.name: _thaw_json(field.value) for field in self.output_fields})
        if len(rendered) > self.maximum_bytes:
            raise ResourceJobDenied("rendered body recipe exceeds its protected byte bound")
        return rendered

    def template_payload(self) -> bytes:
        """Stable DAG commitment; the actual request is rendered only at root."""
        return _canonical({"body_recipe_id": self.recipe_id, "schema_id": self.schema_id})

    def render(self, *, backend: "ResourceBackendEnrollment | None" = None,
               scope_bindings: Mapping[str, ResourceScopeBinding] | None = None,
               validators: Mapping[str, ResourceValidator],
               event_fields: Mapping[str, Any] | None = None,
               parent_results: Mapping[str, Mapping[str, Any]] | None = None) -> bytes:
        scopes = dict(scope_bindings or {})
        event = event_fields or {}
        results = parent_results or {}
        body: dict[str, Any] = {}
        for scope in self.scope_bindings:
            binding = scopes.get(scope.scope_binding_id)
            validator = validators.get(scope.validator_id)
            if (binding is None or validator is None or backend is None
                    or binding.backend_enrollment_id != backend.backend_id
                    or binding.scope_binding_id != backend.scope_binding_id
                    or scope.field not in binding.fixed_fields):
                raise ResourceJobDenied("body recipe scope binding or validator is unavailable")
            body[scope.name] = validator.validate_scalar(
                _thaw_json(binding.fixed_fields[scope.field]))
        for output in self.output_fields:
            validator = validators.get(output.validator_id)
            if validator is None:
                raise ResourceJobDenied("body recipe validator is unavailable")
            if output.source == "literal":
                value = _thaw_json(output.value)
            elif output.source == "observed-event-field":
                if output.value not in event:
                    raise ResourceJobDenied("selected event field is absent")
                value = event[output.value]
            else:
                selector = _thaw_json(output.value)
                previous = results.get(selector["node_id"])
                if not isinstance(previous, Mapping) or selector["field"] not in previous:
                    raise ResourceJobDenied("selected predecessor result field is unavailable")
                value = previous[selector["field"]]
            if output.name in body:
                raise ResourceJobDenied("body recipe cannot replace a scope-selected field")
            body[output.name] = validator.validate_scalar(value)
        rendered = _canonical(body)
        if len(rendered) > self.maximum_bytes:
            raise ResourceJobDenied("rendered body recipe exceeds its protected byte bound")
        return rendered


@dataclass(frozen=True, slots=True)
class ResourceCredentialBinding:
    """Exact protected mapping from a reviewed request placeholder to a vault ref."""

    source_placeholder: str
    credential_reference_id: str
    usage: str

    def __post_init__(self) -> None:
        # Preserve the exact selected manifest token. Environment-style
        # placeholders are data labels only: they never become environment
        # variable names or an implicit vault lookup.
        if (not isinstance(self.source_placeholder, str)
                or not (re.fullmatch(r"\$\{[A-Z][A-Z0-9_]{0,127}\}", self.source_placeholder)
                        or _ID.fullmatch(self.source_placeholder))):
            raise ResourceJobDenied("credential source placeholder is invalid")
        _ident(self.credential_reference_id, "credential reference")
        if self.usage not in {"webhook-hmac-verify", "channel-account", "backend-account"}:
            raise ResourceJobDenied("credential binding usage is outside the protected closed set")


@dataclass(frozen=True, slots=True)
class ResourceBackendEnrollment:
    backend_id: str
    resource_id: str
    profile_id: str
    principal_id: str
    generation: str
    consent_revision: str
    source_issuer_channel_id: str
    observer_enrollment_id: str
    native_package_id: str
    native_package_generation: str
    handler_artifact_id: str
    handler_sha256: str
    approved_action_ids: frozenset[str]
    operation: str
    target_id: str
    recipient: str | None
    credential_reference_ids: frozenset[str]
    request_schema_id: str
    result_schema_id: str
    body_recipe_id: str
    scope_binding_id: str
    maximum_request_bytes: int
    maximum_response_bytes: int
    maximum_seconds: int
    profile_generation: str = ""
    execution_binding: Mapping[str, Any] | None = None
    credential_bindings: tuple[ResourceCredentialBinding, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "backend_id", "resource_id", "profile_id", "principal_id", "generation",
            "consent_revision", "source_issuer_channel_id", "observer_enrollment_id",
            "native_package_id", "native_package_generation", "handler_artifact_id",
            "operation", "target_id", "request_schema_id", "result_schema_id",
            "body_recipe_id", "scope_binding_id",
        ):
            _ident(getattr(self, name), name)
        if self.profile_generation:
            _ident(self.profile_generation, "backend profile generation")
        if self.execution_binding is not None:
            fields = {
                "process_enrollment_id", "process_generation", "operation_id",
                "native_package_id", "native_package_generation", "child_operation",
                "child_target_id", "child_capability", "task_body_recipe_id",
                "task_request_schema_id", "source_profile_id", "home_binding_id",
            }
            binding = self.execution_binding
            if not isinstance(binding, Mapping) or set(binding) != fields:
                raise ResourceJobDenied("backend process execution binding is malformed")
            frozen_binding = {}
            for key, value in binding.items():
                _ident(value, f"backend execution {key}")
                frozen_binding[key] = value
            if (not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", frozen_binding["source_profile_id"])
                    or not re.fullmatch(r"[0-9a-f]{64}", frozen_binding["home_binding_id"])):
                raise ResourceJobDenied("backend execution source-home identity is malformed")
            if (frozen_binding["operation_id"] != "hermes-resource-profile-task-v1"
                    or frozen_binding["child_operation"] != "process.start"
                    or frozen_binding["native_package_id"] != self.native_package_id
                    or frozen_binding["native_package_generation"] != self.native_package_generation):
                raise ResourceJobDenied("backend process execution binding does not join its selected row")
            object.__setattr__(self, "execution_binding", MappingProxyType(frozen_binding))
        if not _DIGEST.fullmatch(self.handler_sha256):
            raise ResourceJobDenied("resource backend handler digest is invalid")
        if self.recipient is not None:
            _ident(self.recipient, "resource backend recipient")
        for name in ("approved_action_ids", "credential_reference_ids"):
            values = getattr(self, name)
            if not isinstance(values, (set, frozenset)):
                raise ResourceJobDenied(f"resource backend {name} must be a protected set")
            object.__setattr__(self, name, frozenset(_ident(value, name) for value in values))
        bindings = self.credential_bindings
        if (not isinstance(bindings, (tuple, list)) or len(bindings) > 16
                or any(not isinstance(item, ResourceCredentialBinding) for item in bindings)
                or len({item.source_placeholder for item in bindings}) != len(bindings)
                or any(item.credential_reference_id not in self.credential_reference_ids
                       for item in bindings)):
            raise ResourceJobDenied("resource backend credential bindings are invalid")
        object.__setattr__(self, "credential_bindings", tuple(bindings))
        if not self.approved_action_ids:
            raise ResourceJobDenied("resource backend has no approved actions")
        for name, maximum in (("maximum_request_bytes", 256 * 1024),
                              ("maximum_response_bytes", 2 * 1024 * 1024),
                              ("maximum_seconds", 600)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ResourceJobDenied(f"resource backend {name} is outside protected bounds")


@dataclass(frozen=True, slots=True)
class ResourceJobNode:
    """One reviewed immutable graph action and its exact child effect binding."""

    node_id: str
    action_id: str
    effect: str
    target: str
    recipient: str | None
    payload: bytes
    depends_on: tuple[str, ...] = ()
    maximum_attempts: int = 1
    request_schema_id: str = ""
    body_recipe_id: str = ""
    backend_enrollment_id: str = ""
    result_schema_id: str = ""
    scope_binding_id: str = ""

    def __post_init__(self) -> None:
        _ident(self.node_id, "node id")
        _ident(self.action_id, "action id")
        if self.effect not in _EFFECTS:
            raise ResourceJobDenied("child effect is not an enrolled resource operation")
        _ident(self.target, "child target")
        if self.recipient is not None:
            _ident(self.recipient, "child recipient")
        if not isinstance(self.payload, bytes) or not 1 <= len(self.payload) <= 1_048_576:
            raise ResourceJobDenied("child payload exceeds the enrolled bound")
        try:
            parsed = json.loads(self.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ResourceJobDenied("child payload must be canonical JSON") from None
        if _canonical(parsed) != self.payload:
            raise ResourceJobDenied("child payload must be canonical JSON")
        if not isinstance(self.depends_on, tuple) or any(not isinstance(item, str) for item in self.depends_on):
            raise ResourceJobDenied("child dependencies are malformed")
        object.__setattr__(self, "depends_on", tuple(self.depends_on))
        if type(self.maximum_attempts) is not int or not 1 <= self.maximum_attempts <= 10:
            raise ResourceJobDenied("child retry count is outside the protected bound")
        if self.request_schema_id:
            _ident(self.request_schema_id, "request schema id")
        for name in ("body_recipe_id", "backend_enrollment_id", "result_schema_id", "scope_binding_id"):
            value = getattr(self, name)
            if value:
                _ident(value, name)

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


@dataclass(frozen=True, slots=True)
class ResourceJobEnrollment:
    """Protected root enrollment; callers never supply or mutate these fields."""

    resource_id: str
    kind: str
    generation: str
    selected_enabled: bool
    profile_id: str
    principal_id: str
    consent_revision: str
    approved_action_ids: frozenset[str]
    fixed_target_ids: frozenset[str]
    recipient_scope: frozenset[str]
    source_policy: frozenset[str]
    schedule_or_route_id: str
    nodes: tuple[ResourceJobNode, ...]
    max_children: int
    max_concurrency: int
    max_runtime_seconds: int
    max_payload_bytes: int
    max_replay_entries: int
    enrollment_id: str = ""
    source_issuer_channel_id: str = ""
    observer_enrollment_id: str = ""
    backend_enrollment_id: str = ""
    credential_reference_ids: frozenset[str] = frozenset()
    backend: ResourceBackendEnrollment | None = None
    body_recipes: Mapping[str, ResourceBodyRecipe] = field(default_factory=dict)
    source_capture_schema_id: str = ""
    source_action_ids: frozenset[str] = frozenset()
    backends: Mapping[str, ResourceBackendEnrollment] = field(default_factory=dict)
    profile_generation: str = ""
    scope_bindings: Mapping[str, ResourceScopeBinding] = field(default_factory=dict)
    validators: Mapping[str, ResourceValidator] = field(default_factory=dict)
    source_parent_channels: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        for key in ("resource_id", "kind", "profile_id", "principal_id", "consent_revision", "schedule_or_route_id"):
            _ident(getattr(self, key), key)
        for key in ("enrollment_id", "source_issuer_channel_id", "observer_enrollment_id", "backend_enrollment_id"):
            value = getattr(self, key)
            if value:
                _ident(value, key)
        if self.source_capture_schema_id:
            _ident(self.source_capture_schema_id, "source capture schema id")
        if self.profile_generation:
            _ident(self.profile_generation, "service profile generation")
        if not isinstance(self.source_action_ids, (set, frozenset)):
            raise ResourceJobDenied("source action IDs must be a protected set")
        object.__setattr__(self, "source_action_ids",
                           frozenset(_ident(item, "source action ID") for item in self.source_action_ids))
        if not isinstance(self.source_parent_channels, (set, frozenset)):
            raise ResourceJobDenied("source parent channels must be a protected set")
        object.__setattr__(self, "source_parent_channels",
                           frozenset(_ident(item, "source parent channel")
                                     for item in self.source_parent_channels))
        if not isinstance(self.credential_reference_ids, (set, frozenset)):
            raise ResourceJobDenied("credential references must be a protected set")
        object.__setattr__(self, "credential_reference_ids",
                           frozenset(_ident(item, "credential reference id")
                                     for item in self.credential_reference_ids))
        if not _DIGEST.fullmatch(self.generation):
            raise ResourceJobDenied("resource generation must be a SHA-256 digest")
        if self.kind not in {"crons", "webhooks", "channels", "bundles"}:
            raise ResourceJobDenied("resource kind cannot start a protected job")
        if type(self.selected_enabled) is not bool or not self.selected_enabled:
            raise ResourceJobDenied("resource is not selected and enabled")
        for name in ("approved_action_ids", "fixed_target_ids", "recipient_scope", "source_policy"):
            values = getattr(self, name)
            if not isinstance(values, (set, frozenset)) or any(not isinstance(item, str) for item in values):
                raise ResourceJobDenied(f"{name} must be a set of fixed identifiers")
            frozen = frozenset(_ident(item, name) for item in values)
            object.__setattr__(self, name, frozen)
        if not self.source_policy or not self.source_policy <= _SOURCE_KINDS:
            raise ResourceJobDenied("source policy contains an unavailable event kind")
        for name, maximum in (("max_children", 256), ("max_concurrency", 64),
                              ("max_runtime_seconds", 86_400), ("max_payload_bytes", 4_194_304),
                              ("max_replay_entries", 1_000_000)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ResourceJobDenied(f"{name} is outside supported bounds")
        if (not isinstance(self.nodes, tuple) or not self.nodes
                or any(not isinstance(node, ResourceJobNode) for node in self.nodes)
                or len(self.nodes) > self.max_children):
            raise ResourceJobDenied("approved DAG exceeds the enrolled child limit")
        if sum(node.maximum_attempts for node in self.nodes) > self.max_children:
            raise ResourceJobDenied("approved DAG retry allowances exceed the child-attempt quota")
        if self.backend is not None:
            backend = self.backend
            if (not isinstance(backend, ResourceBackendEnrollment)
                    or backend.backend_id != self.backend_enrollment_id
                    or backend.resource_id != self.resource_id
                    or backend.profile_id != self.profile_id
                    or backend.principal_id != self.principal_id
                    or backend.generation != self.generation
                    or backend.consent_revision != self.consent_revision
                    or backend.source_issuer_channel_id != self.source_issuer_channel_id
                    or backend.observer_enrollment_id != self.observer_enrollment_id
                    or not {node.action_id for node in self.nodes} <= backend.approved_action_ids
                    or any(node.effect != backend.operation or node.target != backend.target_id
                           or node.recipient != backend.recipient
                           or node.request_schema_id != backend.request_schema_id
                           or node.body_recipe_id != backend.body_recipe_id
                           or len(node.payload) > backend.maximum_request_bytes
                           for node in self.nodes)
                    or not backend.credential_reference_ids <= self.credential_reference_ids
                    ):
                raise ResourceJobDenied("selected backend does not exactly join the protected job and DAG")
        elif self.backend_enrollment_id:
            # Direct ledger fixtures can omit backend details. A root handler
            # factory must reject this incomplete selection before exposing a
            # route.
            pass
        if not isinstance(self.backends, Mapping):
            raise ResourceJobDenied("per-node resource backend index is malformed")
        backend_rows = dict(self.backends)
        if any(key != item.backend_id or not isinstance(item, ResourceBackendEnrollment)
               for key, item in backend_rows.items()):
            raise ResourceJobDenied("per-node resource backend index is malformed")
        if backend_rows:
            if set(backend_rows) != {node.backend_enrollment_id for node in self.nodes}:
                raise ResourceJobDenied("per-node backend rows do not exactly cover the approved DAG")
            for node in self.nodes:
                backend = backend_rows[node.backend_enrollment_id]
                if (backend.resource_id != self.resource_id or backend.profile_id != self.profile_id
                        or backend.principal_id != self.principal_id or backend.generation != self.generation
                        or backend.consent_revision != self.consent_revision
                        or backend.source_issuer_channel_id != self.source_issuer_channel_id
                        or backend.observer_enrollment_id != self.observer_enrollment_id
                        or backend.profile_generation != self.profile_generation
                        or node.action_id not in backend.approved_action_ids
                        or node.effect != backend.operation or node.target != backend.target_id
                        or node.recipient != backend.recipient
                        or node.request_schema_id != backend.request_schema_id
                        or node.result_schema_id != backend.result_schema_id
                        or node.body_recipe_id != backend.body_recipe_id
                        or node.scope_binding_id != backend.scope_binding_id
                        or node.backend_enrollment_id != backend.backend_id
                        or len(node.payload) > backend.maximum_request_bytes
                        or not backend.credential_reference_ids <= self.credential_reference_ids):
                    raise ResourceJobDenied("node does not exactly join its per-node protected backend")
        object.__setattr__(self, "backends", MappingProxyType(backend_rows))
        if not isinstance(self.body_recipes, Mapping):
            raise ResourceJobDenied("selected body recipe index is malformed")
        recipes = dict(self.body_recipes)
        if any(key != recipe.recipe_id or not isinstance(recipe, ResourceBodyRecipe)
               for key, recipe in recipes.items()):
            raise ResourceJobDenied("selected body recipe index is malformed")
        required_recipe_ids = {node.body_recipe_id for node in self.nodes}
        for backend in backend_rows.values():
            if backend.execution_binding is not None:
                required_recipe_ids.add(backend.execution_binding["task_body_recipe_id"])
        if recipes and set(recipes) != required_recipe_ids:
            raise ResourceJobDenied("selected body recipes do not exactly cover node and task recipes")
        for node in self.nodes:
            recipe = recipes.get(node.body_recipe_id)
            if recipe is not None and (recipe.schema_id != node.request_schema_id
                                       or recipe.template_payload() != node.payload):
                raise ResourceJobDenied("node payload differs from its protected body recipe template")
        object.__setattr__(self, "body_recipes", MappingProxyType(recipes))
        if not isinstance(self.scope_bindings, Mapping) or not isinstance(self.validators, Mapping):
            raise ResourceJobDenied("selected scope or validator catalog is malformed")
        scopes = dict(self.scope_bindings)
        validators = dict(self.validators)
        if any(key != scope.scope_binding_id or not isinstance(scope, ResourceScopeBinding)
               for key, scope in scopes.items()):
            raise ResourceJobDenied("selected scope catalog is malformed")
        if any(key != validator.validator_id or not isinstance(validator, ResourceValidator)
               for key, validator in validators.items()):
            raise ResourceJobDenied("selected validator catalog is malformed")
        for backend in backend_rows.values():
            scope = scopes.get(backend.scope_binding_id)
            if (scope is None or scope.resource_id != backend.resource_id
                    or scope.profile_id != backend.profile_id
                    or scope.principal_id != backend.principal_id
                    or scope.resource_generation != backend.generation
                    or scope.profile_generation != backend.profile_generation
                    or scope.backend_enrollment_id != backend.backend_id
                    or scope.recipient != backend.recipient
                    or scope.credential_reference_ids != backend.credential_reference_ids):
                raise ResourceJobDenied("selected backend has no exactly joined protected scope binding")
        for recipe in recipes.values():
            for field in recipe.output_fields:
                if field.validator_id not in validators:
                    raise ResourceJobDenied("body recipe validator is absent from selected catalog")
            for field in recipe.scope_bindings:
                scope = scopes.get(field.scope_binding_id)
                if (scope is None or field.validator_id not in validators
                        or field.field not in scope.fixed_fields):
                    raise ResourceJobDenied("body recipe scope or validator is absent from selected catalog")
        for node in self.nodes:
            recipe = recipes.get(node.body_recipe_id)
            backend = backend_rows.get(node.backend_enrollment_id)
            if recipe is not None and backend is not None and any(
                    field.scope_binding_id != backend.scope_binding_id
                    for field in recipe.scope_bindings):
                raise ResourceJobDenied("body recipe scope does not exactly bind its node backend")
            binding = backend.execution_binding if backend is not None else None
            task_recipe = recipes.get(binding["task_body_recipe_id"]) if binding is not None else None
            if binding is not None and (task_recipe is None
                                        or task_recipe.schema_id != binding["task_request_schema_id"]
                                        or any(field.scope_binding_id != backend.scope_binding_id
                                               for field in task_recipe.scope_bindings)):
                raise ResourceJobDenied("profile task recipe does not exactly join its backend execution binding")
        object.__setattr__(self, "scope_bindings", MappingProxyType(scopes))
        object.__setattr__(self, "validators", MappingProxyType(validators))
        if sum(len(node.payload) for node in self.nodes) > self.max_payload_bytes:
            raise ResourceJobDenied("aggregate approved DAG payload exceeds the enrolled bound")
        if len({node.node_id for node in self.nodes}) != len(self.nodes):
            raise ResourceJobDenied("approved DAG contains duplicate node identities")
        action_ids = {node.action_id for node in self.nodes}
        targets = {node.target for node in self.nodes}
        if not action_ids <= self.approved_action_ids or not targets <= self.fixed_target_ids:
            raise ResourceJobDenied("approved DAG exceeds selected action or target scope")
        if any(node.recipient is not None and node.recipient not in self.recipient_scope for node in self.nodes):
            raise ResourceJobDenied("approved DAG exceeds selected recipient scope")
        _validate_dag(self.nodes)

    @property
    def dag_sha256(self) -> str:
        body = [{"node_id": n.node_id, "resource_id": self.resource_id,
                "action_id": n.action_id, "operation": n.effect, "target_id": n.target,
                "recipient": n.recipient, "request_schema_id": n.request_schema_id,
                 "body_recipe_id": n.body_recipe_id, "depends_on": list(n.depends_on),
                 "backend_enrollment_id": n.backend_enrollment_id,
                 "result_schema_id": n.result_schema_id, "scope_binding_id": n.scope_binding_id,
                 "maximum_attempts": n.maximum_attempts}
                for n in sorted(self.nodes, key=lambda item: item.node_id)]
        return hashlib.sha256(_canonical(body)).hexdigest()

    @property
    def node_map(self) -> Mapping[str, ResourceJobNode]:
        return MappingProxyType({node.node_id: node for node in self.nodes})


def _validate_dag(nodes: Sequence[ResourceJobNode]) -> None:
    by_id = {node.node_id: node for node in nodes}
    if any(len(node.depends_on) > len(nodes) or len(set(node.depends_on)) != len(node.depends_on)
           or any(dep not in by_id or dep == node.node_id for dep in node.depends_on)
           for node in nodes):
        raise ResourceJobDenied("approved DAG has invalid prerequisites")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in visiting:
            raise ResourceJobDenied("approved DAG contains a cycle")
        if node_id in visited:
            return
        visiting.add(node_id)
        for dependency in by_id[node_id].depends_on:
            visit(dependency)
        visiting.remove(node_id)
        visited.add(node_id)

    for node_id in by_id:
        visit(node_id)


@dataclass(frozen=True, slots=True)
class ResourceJobAdmission:
    job_id: str
    resource_id: str
    generation: str
    approved_dag_sha256: str
    expires_monotonic: float
    max_concurrency: int
    child_admission_ids: Mapping[str, str]

    def __post_init__(self) -> None:
        if not isinstance(self.child_admission_ids, Mapping):
            raise ResourceJobDenied("child admission map is malformed")
        copied = {_ident(key, "node id"): _ident(value, "child admission id")
                  for key, value in self.child_admission_ids.items()}
        object.__setattr__(self, "child_admission_ids", MappingProxyType(copied))


@dataclass(frozen=True, slots=True)
class RootResourceNodeResultClosure:
    """One registry-issued snapshot of completed prerequisite result capsules.

    This immutable DTO carries only opaque root handles and digests. Result
    fields remain in ResourceJobAuthority's private capsule index and are
    resolved again at the context-issuance boundary.
    """

    schema: int
    closure_handle: str
    event_handle: str
    admission_handle: str
    node_id: str
    job_handle: str
    resource_generation: str
    service_generation_digest: str
    prerequisite_node_ids: tuple[str, ...]
    result_capsule_handles: tuple[str, ...]
    result_capsule_sha256s: tuple[str, ...]
    parent_closure_digest: str
    issued_monotonic: float
    expires_monotonic: float

    def __post_init__(self) -> None:
        if type(self.schema) is not int or self.schema != 1:
            raise ResourceJobDenied("root result closure schema is invalid")
        for name in ("closure_handle", "event_handle", "admission_handle", "node_id", "job_handle",
                     "resource_generation"):
            _ident(getattr(self, name), f"root result closure {name}")
        for name in ("service_generation_digest", "parent_closure_digest"):
            if not isinstance(getattr(self, name), str) or not _DIGEST.fullmatch(getattr(self, name)):
                raise ResourceJobDenied("root result closure digest is invalid")
        if (not isinstance(self.prerequisite_node_ids, tuple)
                or len(set(self.prerequisite_node_ids)) != len(self.prerequisite_node_ids)
                or any(not isinstance(item, str) or not _ID.fullmatch(item)
                       for item in self.prerequisite_node_ids)
                or not isinstance(self.result_capsule_handles, tuple)
                or not isinstance(self.result_capsule_sha256s, tuple)
                or len(self.result_capsule_handles) != len(self.result_capsule_sha256s)
                or len(self.result_capsule_handles) != len(self.prerequisite_node_ids)
                or any(not isinstance(item, str) or not _ID.fullmatch(item)
                       for item in self.result_capsule_handles)
                or any(not isinstance(item, str) or not _DIGEST.fullmatch(item)
                       for item in self.result_capsule_sha256s)):
            raise ResourceJobDenied("root result closure capsule list is malformed")
        if (any(isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) for value in
                (self.issued_monotonic, self.expires_monotonic))
                or self.issued_monotonic <= 0 or self.expires_monotonic <= self.issued_monotonic):
            raise ResourceJobDenied("root result closure lease is invalid")


@dataclass(frozen=True, slots=True)
class RootResourceJobAdmissionHandle:
    """Root-only one-attempt handle used to launch a selected Hermes task.

    Instances are minted by ResourceJobAuthority after a durable child claim
    and passed only between root in-process services. This DTO has no wire
    encoder and is not a worker bearer credential.
    """

    handle_id: str
    job_id: str
    node_id: str
    child_admission_id: str
    attempt_index: int
    backend_enrollment_id: str
    resource_generation: str
    profile_id: str
    profile_generation: str
    native_package_id: str
    native_package_generation: str
    process_enrollment_id: str
    process_generation: str
    operation_id: str
    child_target_id: str
    child_capability: str
    task_body_recipe_id: str
    task_request_schema_id: str
    task_payload: bytes = field(repr=False)
    task_payload_sha256: str
    parent_closure_digest: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        for name in (
            "handle_id", "job_id", "node_id", "child_admission_id", "backend_enrollment_id",
            "resource_generation", "profile_id", "profile_generation", "native_package_id",
            "native_package_generation", "process_enrollment_id", "process_generation",
            "operation_id", "child_target_id", "child_capability", "task_body_recipe_id",
            "task_request_schema_id",
        ):
            _ident(getattr(self, name), f"root task handle {name}")
        if (type(self.attempt_index) is not int or not 0 <= self.attempt_index <= 9
                or self.operation_id != "hermes-resource-profile-task-v1"):
            raise ResourceJobDenied("root task handle operation or attempt is invalid")
        if (not isinstance(self.task_payload, bytes) or not 1 <= len(self.task_payload) <= 262_144
                or hashlib.sha256(self.task_payload).hexdigest() != self.task_payload_sha256
                or not _DIGEST.fullmatch(self.parent_closure_digest)):
            raise ResourceJobDenied("root task handle payload or closure digest is invalid")
        try:
            value = json.loads(self.task_payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ResourceJobDenied("root task handle payload is malformed") from None
        if (not isinstance(value, dict) or set(value) != {"prompt"}
                or not isinstance(value["prompt"], str) or not value["prompt"]
                or _canonical(value) != self.task_payload):
            raise ResourceJobDenied("root task handle payload is not the fixed prompt schema")
        if (isinstance(self.expires_monotonic, bool)
                or not isinstance(self.expires_monotonic, (int, float))
                or not __import__("math").isfinite(self.expires_monotonic)
                or self.expires_monotonic <= 0):
            raise ResourceJobDenied("root task handle lease is invalid")


@dataclass(frozen=True, slots=True)
class RootAdmittedTask:
    """Neutral immutable task snapshot from the protected RB-T08 contract.

    It is metadata, never a bearer grant. ``source_context_handle`` resolves
    only in the issuing root authority's private registry.
    """

    schema: int
    admission_id: str
    job_id: str
    node_id: str
    backend_enrollment_id: str
    resource_generation: str
    process_enrollment_id: str
    process_generation: str
    native_package_id: str
    native_package_generation: str
    operation_id: str
    task_body_recipe_id: str
    task_request_schema_id: str
    task_payload_sha256: str
    task_payload_bytes: bytes = field(repr=False)
    stdin_sha256: str
    stdin_size_bytes: int
    parent_closure_digest: str
    deadline_monotonic: float
    source_context_handle: str

    def __post_init__(self) -> None:
        if type(self.schema) is not int or self.schema != 1:
            raise ResourceJobDenied("root admitted task schema is invalid")
        for name in ("admission_id", "job_id", "node_id", "backend_enrollment_id",
                     "resource_generation", "process_enrollment_id", "process_generation",
                     "native_package_id", "native_package_generation", "operation_id",
                     "task_body_recipe_id", "task_request_schema_id", "source_context_handle"):
            _ident(getattr(self, name), f"root admitted task {name}")
        for name in ("task_payload_sha256", "stdin_sha256", "parent_closure_digest"):
            if not isinstance(getattr(self, name), str) or not _DIGEST.fullmatch(getattr(self, name)):
                raise ResourceJobDenied("root admitted task digest is invalid")
        if (type(self.stdin_size_bytes) is not int or not 1 <= self.stdin_size_bytes <= 262_144
                or isinstance(self.deadline_monotonic, bool)
                or not isinstance(self.deadline_monotonic, (int, float))
                or not __import__("math").isfinite(self.deadline_monotonic)):
            raise ResourceJobDenied("root admitted task bounds are invalid")
        if (not isinstance(self.task_payload_bytes, bytes)
                or not 1 <= len(self.task_payload_bytes) <= 262_144
                or hashlib.sha256(self.task_payload_bytes).hexdigest() != self.task_payload_sha256):
            raise ResourceJobDenied("root admitted task payload digest is invalid")
        try:
            value = json.loads(self.task_payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ResourceJobDenied("root admitted task payload is malformed") from None
        if (not isinstance(value, dict) or set(value) != {"prompt"}
                or not isinstance(value["prompt"], str) or not value["prompt"]
                or _canonical(value) != self.task_payload_bytes
                or hashlib.sha256(value["prompt"].encode("utf-8")).hexdigest() != self.stdin_sha256
                or len(value["prompt"].encode("utf-8")) != self.stdin_size_bytes):
            raise ResourceJobDenied("root admitted task payload does not match its selected stdin")


@dataclass(frozen=True, slots=True)
class RootTaskInitialInputReceipt:
    """Root-recorded delivery of the exact admitted prompt to a selected producer."""

    schema: int
    receipt_handle: str
    task_handle: str
    admission_id: str
    node_id: str
    process_id: str
    process_generation: str
    selected_execution_handle: str
    source_receipt_handle: str
    producer_context_delivery_handle: str
    native_loader_ready_event_id: str
    stdin_sha256: str
    stdin_size_bytes: int
    parent_closure_digest: str
    service_generation_digest: str
    resource_generation: str
    issued_monotonic: float
    expires_monotonic: float

    def __post_init__(self) -> None:
        opaque = ("receipt_handle", "task_handle", "selected_execution_handle",
                  "source_receipt_handle", "producer_context_delivery_handle",
                  "native_loader_ready_event_id")
        identities = ("admission_id", "node_id", "process_id", "process_generation",
                      "resource_generation")
        digests = ("stdin_sha256", "parent_closure_digest", "service_generation_digest")
        if (type(self.schema) is not int or self.schema != 1
                or any(not isinstance(getattr(self, name), str)
                       or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", getattr(self, name))
                       for name in opaque)
                or any(not isinstance(getattr(self, name), str)
                       or not _ID.fullmatch(getattr(self, name)) for name in identities)
                or any(not _DIGEST.fullmatch(getattr(self, name)) for name in digests)
                or type(self.stdin_size_bytes) is not int or not 1 <= self.stdin_size_bytes <= 262_144
                or any(isinstance(value, bool) or not isinstance(value, (int, float))
                       or not math.isfinite(value)
                       for value in (self.issued_monotonic, self.expires_monotonic))
                or not self.issued_monotonic < self.expires_monotonic):
            raise ResourceJobDenied("root task initial input receipt is malformed")


@dataclass(frozen=True, slots=True)
class RootTaskNativeExecutionReceipt:
    """Immutable companion binding actual native events to one task terminal."""

    schema: int
    native_execution_receipt_handle: str
    task_handle: str
    process_id: str
    process_generation: str
    native_package_generation: str
    loader_ready_event_id: str
    initial_input_event_id: str
    native_request_event_ids: tuple[str, ...]
    native_result_event_ids: tuple[str, ...]
    required_tool_result_event_ids: tuple[str, ...]
    parent_closure_digest: str
    task_payload_sha256: str
    terminal_receipt_handle: str
    observed_monotonic: float

    def __post_init__(self) -> None:
        opaque_fields = ("native_execution_receipt_handle", "task_handle",
                         "loader_ready_event_id", "initial_input_event_id",
                         "terminal_receipt_handle")
        event_fields = ("native_request_event_ids", "native_result_event_ids",
                        "required_tool_result_event_ids")
        if (type(self.schema) is not int or self.schema != 1
                or any(not isinstance(getattr(self, name), str)
                       or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", getattr(self, name))
                       for name in opaque_fields)
                or any(not isinstance(getattr(self, name), str) or not getattr(self, name)
                       for name in ("process_id", "process_generation", "native_package_generation"))
                or not _DIGEST.fullmatch(self.parent_closure_digest)
                or not _DIGEST.fullmatch(self.task_payload_sha256)
                or any(not isinstance(getattr(self, name), tuple)
                       or len(getattr(self, name)) > 256
                       or any(not isinstance(item, str)
                              or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", item)
                              for item in getattr(self, name))
                       or len(set(getattr(self, name))) != len(getattr(self, name))
                       for name in event_fields)
                or isinstance(self.observed_monotonic, bool)
                or not isinstance(self.observed_monotonic, (int, float))
                or not math.isfinite(self.observed_monotonic)):
            raise ResourceJobDenied("root native execution receipt is malformed")


@dataclass(frozen=True, slots=True)
class RootTaskStdinWriteReceipt:
    """Custody proof that the exact admitted stdin frame reached EOF once."""

    schema: int
    receipt_handle: str
    task_handle: str
    process_id: str
    process_generation: str
    initial_input_receipt_handle: str
    stdin_sha256: str
    stdin_size_bytes: int
    sequence: int
    write_complete: bool
    drained: bool
    stdin_closed: bool
    service_generation_digest: str
    issued_monotonic: float
    expires_monotonic: float

    def __post_init__(self) -> None:
        opaque_fields = ("receipt_handle", "task_handle", "process_id",
                         "initial_input_receipt_handle")
        if (type(self.schema) is not int or self.schema != 1
                or any(not isinstance(getattr(self, name), str)
                       or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", getattr(self, name))
                       for name in opaque_fields)
                or not isinstance(self.process_generation, str)
                or not _ID.fullmatch(self.process_generation)
                or not _DIGEST.fullmatch(self.stdin_sha256)
                or type(self.stdin_size_bytes) is not int
                or not 1 <= self.stdin_size_bytes <= 262_144
                or type(self.sequence) is not int or self.sequence != 0
                or self.write_complete is not True or self.drained is not True
                or self.stdin_closed is not True
                or not _DIGEST.fullmatch(self.service_generation_digest)
                or any(isinstance(value, bool) or not isinstance(value, (int, float))
                       or not math.isfinite(value)
                       for value in (self.issued_monotonic, self.expires_monotonic))
                or not self.issued_monotonic < self.expires_monotonic):
            raise ResourceJobDenied("root task stdin write receipt is malformed")


@dataclass(frozen=True, slots=True)
class RootAdmittedTaskSource:
    """Neutral DTO for a root-verified source closure; never a worker grant."""

    source_context_handle: str
    verified_source_receipt_handles: tuple[str, ...]
    signed_receipt_wires: tuple[bytes, ...] = field(repr=False)
    sensitivity: Any = field(repr=False)
    lineage_hash: str
    recipient_ceiling: tuple[str, ...]
    principal_id: str
    profile_id: str
    namespace_id: str
    parent_closure_digest: str
    controller_binding_handle: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        for name in ("source_context_handle", "principal_id", "profile_id", "namespace_id",
                     "controller_binding_handle"):
            _ident(getattr(self, name), f"root admitted source {name}")
        for name in ("lineage_hash", "parent_closure_digest"):
            if not _DIGEST.fullmatch(getattr(self, name)):
                raise ResourceJobDenied("root admitted source digest is invalid")
        if (not isinstance(self.verified_source_receipt_handles, tuple)
                or not self.verified_source_receipt_handles
                or any(not isinstance(value, str) or not 32 <= len(value) <= 128
                       for value in self.verified_source_receipt_handles)
                or not isinstance(self.signed_receipt_wires, tuple)
                or len(self.verified_source_receipt_handles) != len(self.signed_receipt_wires)
                or any(not isinstance(value, bytes) or not value for value in self.signed_receipt_wires)
                or getattr(self.sensitivity, "value", None) not in {"public", "private", "unknown"}
                or not isinstance(self.recipient_ceiling, tuple)
                or any(not isinstance(value, str) or not value for value in self.recipient_ceiling)
                or isinstance(self.expires_monotonic, bool)
                or not isinstance(self.expires_monotonic, (int, float))
                or not __import__("math").isfinite(self.expires_monotonic)):
            raise ResourceJobDenied("root admitted source closure fields are invalid")


@dataclass(frozen=True, slots=True)
class RootTaskController:
    """Root-created, non-wire controller proof with a caller-owned PIDFD."""

    schema: int
    controller_handle: str
    controller_kind: str
    controller_role_artifact_id: str
    controller_role_sha256: str
    pid: int
    pidfd: int
    uid: int
    identity: Any = field(repr=False, compare=False)
    controller_profile_id: str | None
    controller_generation: str
    source_receipt_id: str | None
    subject_principal_id: str
    subject_profile_id: str
    subject_namespace_id: str
    service_generation_digest: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if type(self.schema) is not int or self.schema != 1:
            raise ResourceJobDenied("root task controller schema is invalid")
        for name in ("controller_handle", "controller_role_artifact_id", "controller_generation",
                     "subject_principal_id", "subject_profile_id", "subject_namespace_id"):
            _ident(getattr(self, name), f"root task controller {name}")
        if (self.controller_kind not in {"worker", "root-scheduler", "root-webhook", "root-channel"}
                or not isinstance(self.controller_role_sha256, str)
                or not _DIGEST.fullmatch(self.controller_role_sha256)
                or type(self.pid) is not int or self.pid <= 0
                or type(self.pidfd) is not int or self.pidfd < 0
                or type(self.uid) is not int or self.uid < 0
                or self.controller_profile_id is not None
                   and (not isinstance(self.controller_profile_id, str) or not self.controller_profile_id)
                or self.source_receipt_id is not None
                   and (not isinstance(self.source_receipt_id, str) or not self.source_receipt_id)
                or not _DIGEST.fullmatch(self.service_generation_digest)
                or isinstance(self.expires_monotonic, bool)
                or not isinstance(self.expires_monotonic, (int, float))
                or not __import__("math").isfinite(self.expires_monotonic)):
            raise ResourceJobDenied("root task controller identity is invalid")


@dataclass(frozen=True, slots=True)
class ResourceChildAdmission:
    """Single-use bounded claim; it is not itself a HostContext or effect grant."""

    admission_id: str
    job_id: str
    resource_id: str
    generation: str
    node_id: str
    retry_index: int
    action_id: str
    effect: str
    target: str
    recipient: str | None
    canonical_payload_sha256: str
    payload: bytes
    source_receipt_ids: tuple[str, ...]
    parent_result_receipt_ids: tuple[str, ...]


class ResourceJobLedger:
    """Atomic, restart-durable job and per-child-attempt state machine.

    Construct under the protected root service directory. ``verified_event``
    must be a result of the root AuthorityService validating a signed source
    receipt; a plugin receipt, event ID, or caller boolean is not accepted by
    this API.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS jobs (
      job_id TEXT PRIMARY KEY, resource_id TEXT NOT NULL, generation TEXT NOT NULL,
      event_key TEXT NOT NULL, source_receipts TEXT NOT NULL, dag_json TEXT NOT NULL,
      dag_sha256 TEXT NOT NULL, expires REAL NOT NULL,
      max_concurrency INTEGER NOT NULL, status TEXT NOT NULL,
      parent_lineage_hash TEXT NOT NULL, parent_sensitivity TEXT NOT NULL
    ) WITHOUT ROWID;
    CREATE UNIQUE INDEX IF NOT EXISTS jobs_event_once ON jobs(resource_id,generation,event_key);
    CREATE TABLE IF NOT EXISTS children (
      admission_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, node_id TEXT NOT NULL,
      attempt INTEGER NOT NULL, status TEXT NOT NULL, result_receipts TEXT NOT NULL,
      UNIQUE(job_id,node_id,attempt), FOREIGN KEY(job_id) REFERENCES jobs(job_id)
    ) WITHOUT ROWID;
    """

    def __init__(self, path: Path, *, max_jobs: int = 100_000,
                 timeout_seconds: float = 2.0, monotonic: Callable[[], float] = time.monotonic):
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("resource job database path must be absolute")
        if type(max_jobs) is not int or not 1 <= max_jobs <= 1_000_000:
            raise ValueError("resource job capacity is outside supported bounds")
        if not 0.05 <= timeout_seconds <= 10.0:
            raise ValueError("resource job database timeout is outside supported bounds")
        self.path, self.max_jobs = path, max_jobs
        self.timeout_seconds, self.monotonic = float(timeout_seconds), monotonic
        self._prepare()
        db = self._connect()
        try:
            db.executescript(self._SCHEMA)
            columns = {row[1] for row in db.execute("PRAGMA table_info(jobs)")}
            if "parent_lineage_hash" not in columns:
                db.execute("ALTER TABLE jobs ADD COLUMN parent_lineage_hash TEXT NOT NULL DEFAULT '" + ("0" * 64) + "'")
            if "parent_sensitivity" not in columns:
                db.execute("ALTER TABLE jobs ADD COLUMN parent_sensitivity TEXT NOT NULL DEFAULT 'unknown'")
            # Monotonic expiries are meaningful only within this authority
            # process epoch. After a daemon restart, invalidate all active
            # leases and their effect cancellation handles before accepting
            # another admission.
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE children SET status='cancelled' WHERE status IN ('pending','admitted','running')")
            db.execute("UPDATE jobs SET status='cancelled' WHERE status='running'")
            db.commit()
        finally:
            db.close()

    def _prepare(self) -> None:
        parent = self.path.parent
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ResourceJobDenied("resource job store parent must be private and root-service-owned")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            fd = None
        if fd is not None:
            os.close(fd)
        file_info = self.path.lstat()
        if (not stat.S_ISREG(file_info.st_mode) or stat.S_ISLNK(file_info.st_mode)
                or file_info.st_uid != os.geteuid() or file_info.st_nlink != 1
                or stat.S_IMODE(file_info.st_mode) != 0o600):
            raise ResourceJobDenied("resource job database must be a private service-owned regular file")

    def _connect(self) -> sqlite3.Connection:
        try:
            db = sqlite3.connect(self.path, timeout=self.timeout_seconds, isolation_level=None)
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.execute(f"PRAGMA busy_timeout={int(self.timeout_seconds * 1000)}")
            return db
        except sqlite3.Error as exc:
            raise ResourceJobDenied("resource job ledger is unavailable") from exc

    @staticmethod
    def _event_key(event_id: str, receipt_ids: Sequence[str]) -> str:
        _ident(event_id, "event id")
        if not isinstance(receipt_ids, (tuple, list)) or not receipt_ids or len(receipt_ids) > 64:
            raise ResourceJobDenied("root-verified source receipts are required")
        normalized = sorted({_ident(item, "source receipt id") for item in receipt_ids})
        if len(normalized) != len(receipt_ids):
            raise ResourceJobDenied("duplicate source receipts are not allowed")
        # Replay identity is the root-generated event ID. Including receipt
        # IDs here would permit a second admission if the same event were
        # wrapped in a newly issued signed receipt.
        return hashlib.sha256(_canonical({"event_id": event_id})).hexdigest()

    def admit_job(self, enrollment: ResourceJobEnrollment, *, event_id: str,
                  verified_source_receipt_ids: Sequence[str], current_generation: str,
                  ttl_seconds: int, parent_lineage_hash: str,
                  parent_sensitivity: str) -> ResourceJobAdmission:
        """Consume one root-authenticated event and create bounded child slots.

        Caller data is limited to the event identity and opaque receipt IDs.
        The route/schedule issuer supplies the trusted enrollment and receipt
        IDs only after AuthorityService verified their signatures and lineage.
        """
        if not isinstance(enrollment, ResourceJobEnrollment):
            raise ResourceJobDenied("protected selected resource enrollment is required")
        if current_generation != enrollment.generation:
            raise ResourceJobDenied("selected resource generation is stale")
        if not _DIGEST.fullmatch(parent_lineage_hash):
            raise ResourceJobDenied("root context lineage is invalid")
        if parent_sensitivity not in {"public", "private", "confidential", "unknown"}:
            raise ResourceJobDenied("root context sensitivity is invalid")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= enrollment.max_runtime_seconds:
            raise ResourceJobDenied("job deadline exceeds its root-enrolled runtime")
        source_kinds = {"crons": {"schedule-event"}, "webhooks": {"webhook-event"},
                        "channels": {"native-input"}}.get(
                            enrollment.kind, set(enrollment.source_policy))
        if not source_kinds or not source_kinds <= enrollment.source_policy:
            raise ResourceJobDenied("event source kind is not selected by root policy")
        event_key = self._event_key(event_id, verified_source_receipt_ids)
        now = self.monotonic()
        job_id = secrets.token_urlsafe(24)
        ids = {node.node_id: secrets.token_urlsafe(24) for node in enrollment.nodes}
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM jobs WHERE resource_id=? AND generation=? AND event_key=?",
                          (enrollment.resource_id, enrollment.generation, event_key)).fetchone():
                raise ResourceJobDenied("resource event was already admitted")
            count = db.execute("SELECT count(*) FROM jobs").fetchone()[0]
            resource_count = db.execute("SELECT count(*) FROM jobs WHERE resource_id=?",
                                        (enrollment.resource_id,)).fetchone()[0]
            if count >= self.max_jobs or resource_count >= enrollment.max_replay_entries:
                raise ResourceJobDenied("resource job ledger is full")
            dag_json = _canonical({node.node_id: list(node.depends_on) for node in enrollment.nodes}).decode()
            db.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       (job_id, enrollment.resource_id, enrollment.generation, event_key,
                        _canonical(sorted(verified_source_receipt_ids)).decode(),
                        dag_json, enrollment.dag_sha256, now + ttl_seconds,
                        enrollment.max_concurrency, "running", parent_lineage_hash,
                        parent_sensitivity))
            db.executemany("INSERT INTO children VALUES (?,?,?,0,'pending','[]')",
                           ((ids[node.node_id], job_id, node.node_id) for node in enrollment.nodes))
            db.commit()
        except ResourceJobDenied:
            db.rollback()
            raise
        except sqlite3.Error as exc:
            db.rollback()
            raise ResourceJobDenied("resource job admission failed closed") from exc
        finally:
            db.close()
        return ResourceJobAdmission(job_id, enrollment.resource_id, enrollment.generation,
                                    enrollment.dag_sha256, now + ttl_seconds,
                                    enrollment.max_concurrency, ids)

    def job_provenance(self, job_id: str, *, enrollment: ResourceJobEnrollment
                       ) -> tuple[tuple[str, ...], str, str]:
        """Read persisted source ancestry for restart-safe root execution."""
        _ident(job_id, "job id")
        db = self._connect()
        try:
            row = db.execute(
                "SELECT resource_id,generation,source_receipts,parent_lineage_hash,parent_sensitivity "
                "FROM jobs WHERE job_id=?", (job_id,),
            ).fetchone()
            if row is None or row[0] != enrollment.resource_id or row[1] != enrollment.generation:
                raise ResourceJobDenied("job is outside the selected resource generation")
            receipts = json.loads(row[2])
            if not isinstance(receipts, list) or not receipts or any(not isinstance(item, str) for item in receipts):
                raise ResourceJobDenied("persisted signed source receipt closure is malformed")
            if not _DIGEST.fullmatch(row[3]) or row[4] not in {"public", "private", "confidential", "unknown"}:
                raise ResourceJobDenied("persisted job lineage is malformed")
            return tuple(receipts), row[3], row[4]
        except sqlite3.Error as exc:
            raise ResourceJobDenied("resource job provenance lookup failed closed") from exc
        finally:
            db.close()

    def load_admission(self, job_id: str, *, enrollment: ResourceJobEnrollment
                       ) -> ResourceJobAdmission:
        """Rebuild a bounded public admission view from root-persisted state."""
        _ident(job_id, "job id")
        db = self._connect()
        try:
            row = db.execute(
                "SELECT resource_id,generation,dag_sha256,expires,max_concurrency,status "
                "FROM jobs WHERE job_id=?", (job_id,),
            ).fetchone()
            if (row is None or row[0] != enrollment.resource_id or row[1] != enrollment.generation
                    or row[2] != enrollment.dag_sha256 or row[5] != "running"):
                raise ResourceJobDenied("job is expired, revoked, or outside the selected DAG")
            initial = dict(db.execute(
                "SELECT node_id,admission_id FROM children WHERE job_id=? AND attempt=0", (job_id,)))
            if set(initial) != set(enrollment.node_map):
                raise ResourceJobDenied("persisted child admissions do not match the selected DAG")
            return ResourceJobAdmission(job_id, row[0], row[1], row[2], row[3], row[4], initial)
        except sqlite3.Error as exc:
            raise ResourceJobDenied("resource job admission lookup failed closed") from exc
        finally:
            db.close()

    def claim_child(self, admission: ResourceJobAdmission, enrollment: ResourceJobEnrollment, *,
                    node_id: str, child_admission_id: str,
                    parent_result_receipt_ids: Sequence[str],
                    current_generation: str) -> ResourceChildAdmission:
        """Consume one initial or retry admission, minting fresh retry IDs.

        A repeated request can only retry the latest failed attempt. The new
        ID is allocated and claimed in the same root call; every attempt then
        reaches child authority issuance with its own retry index and nonce.
        """
        _ident(child_admission_id, "child admission id")
        node_id = _ident(node_id, "node id")
        node = enrollment.node_map.get(node_id)
        if node is None:
            raise ResourceJobDenied("child identity is outside the admitted DAG")
        parents = tuple(sorted({_ident(item, "parent result receipt id") for item in parent_result_receipt_ids}))
        if len(parents) != len(parent_result_receipt_ids) or len(parents) > 64:
            raise ResourceJobDenied("parent result receipt lineage is malformed")
        db = self._connect()
        try:
            row = db.execute(
                "SELECT attempt,status FROM children WHERE admission_id=? AND job_id=? AND node_id=?",
                (child_admission_id, admission.job_id, node_id),
            ).fetchone()
            latest = db.execute(
                "SELECT admission_id,attempt,status FROM children WHERE job_id=? AND node_id=? "
                "ORDER BY attempt DESC LIMIT 1", (admission.job_id, node_id),
            ).fetchone()
        except sqlite3.Error as exc:
            raise ResourceJobDenied("child retry lookup failed closed") from exc
        finally:
            db.close()
        if row is None:
            raise ResourceJobDenied("child admission identifier is outside this job")
        if row[1] == "pending" and admission.child_admission_ids.get(node_id) == child_admission_id:
            return self.admit_child(
                admission, enrollment, node_id=node_id,
                parent_result_receipt_ids=parents,
                current_generation=current_generation,
            )
        if row[1] == "denied":
            if latest is None or latest[0] != child_admission_id or latest[2] != "denied":
                raise ResourceJobDenied("only the latest pre-effect denied child attempt may be retried")
            source_ids, _lineage, _sensitivity = self.job_provenance(
                admission.job_id, enrollment=enrollment)
            failed = ResourceChildAdmission(
                child_admission_id, admission.job_id, enrollment.resource_id,
                enrollment.generation, node.node_id, row[0], node.action_id, node.effect,
                node.target, node.recipient, node.payload_sha256, node.payload,
                source_ids, parents,
            )
            try:
                return self.retry_child(
                    admission, failed, enrollment,
                    parent_result_receipt_ids=parents,
                    current_generation=current_generation,
                )
            except ResourceJobDenied as exc:
                if "attempt quota is exhausted" in str(exc) or "child-attempt quota is exhausted" in str(exc):
                    self.fail_node(admission.job_id, node.node_id)
                raise
        raise ResourceJobDenied("child admission was already consumed or is not retryable")

    def is_job_active(self, job_id: str, *, current_generation: str) -> bool:
        _ident(job_id, "job id")
        if not _DIGEST.fullmatch(current_generation):
            return False
        db = self._connect()
        try:
            row = db.execute("SELECT generation,expires,status FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            return bool(row and row[0] == current_generation and row[1] > self.monotonic()
                        and row[2] == "running")
        finally:
            db.close()

    def completed_node_result_receipts(
        self, job_id: str, node_id: str, *, current_generation: str,
    ) -> tuple[str, int, tuple[str, ...]]:
        """Return only the latest terminal-complete node's durable receipt set."""
        _ident(job_id, "job id")
        node_id = _ident(node_id, "node id")
        if not _DIGEST.fullmatch(current_generation):
            raise ResourceJobDenied("resource generation is unavailable")
        db = self._connect()
        try:
            row = db.execute(
                "SELECT c.admission_id,c.attempt,c.status,c.result_receipts,j.generation,j.expires,j.status "
                "FROM children AS c JOIN jobs AS j ON j.job_id=c.job_id "
                "WHERE c.job_id=? AND c.node_id=? ORDER BY c.attempt DESC LIMIT 1",
                (job_id, node_id),
            ).fetchone()
            now = self.monotonic()
            if (row is None or row[2] != "complete" or row[4] != current_generation
                    or row[5] <= now or row[6] != "running"):
                raise ResourceJobDenied("node result is not a current completed job child")
            receipts = json.loads(row[3])
            if (not isinstance(receipts, list) or not receipts or len(receipts) > 64
                    or any(not isinstance(item, str) or not item for item in receipts)
                    or len(set(receipts)) != len(receipts)):
                raise ResourceJobDenied("completed node result receipts are malformed")
            return row[0], row[1], tuple(receipts)
        except ResourceJobDenied:
            raise
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ResourceJobDenied("completed node result lookup failed closed") from exc
        finally:
            db.close()

    def admit_child(self, admission: ResourceJobAdmission, enrollment: ResourceJobEnrollment, *,
                    node_id: str, parent_result_receipt_ids: Sequence[str],
                    current_generation: str) -> ResourceChildAdmission:
        """Atomically claim a ready child; authority then mints a fresh grant."""
        if (not isinstance(admission, ResourceJobAdmission)
                or not isinstance(enrollment, ResourceJobEnrollment)
                or admission.resource_id != enrollment.resource_id
                or admission.generation != enrollment.generation
                or admission.approved_dag_sha256 != enrollment.dag_sha256):
            raise ResourceJobDenied("job admission does not match the selected immutable DAG")
        if current_generation != enrollment.generation:
            self.revoke_generation(enrollment.resource_id, enrollment.generation)
            raise ResourceJobDenied("resource generation was revoked")
        node = enrollment.node_map.get(_ident(node_id, "node id"))
        admission_id = admission.child_admission_ids.get(node_id)
        if node is None or admission_id is None:
            raise ResourceJobDenied("child identity is outside the admitted DAG")
        parents = tuple(sorted({_ident(item, "parent result receipt id") for item in parent_result_receipt_ids}))
        if len(parents) != len(parent_result_receipt_ids) or len(parents) > 64:
            raise ResourceJobDenied("parent result receipt lineage is malformed")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            job = db.execute("SELECT resource_id,generation,source_receipts,dag_json,dag_sha256,expires,max_concurrency,status FROM jobs WHERE job_id=?",
                             (admission.job_id,)).fetchone()
            now = self.monotonic()
            if (job is None or job[0] != enrollment.resource_id or job[1] != current_generation
                    or job[4] != enrollment.dag_sha256 or job[5] <= now or job[7] != "running"
                    or admission.expires_monotonic <= now):
                raise ResourceJobDenied("job is expired, revoked, or no longer current")
            rows: dict[str, tuple[str, list[str]]] = {}
            for row in db.execute("SELECT node_id,attempt,status,result_receipts FROM children WHERE job_id=? ORDER BY attempt",
                                  (admission.job_id,)):
                rows[row[0]] = (row[2], json.loads(row[3]))
            if any(rows.get(dep, (None, []))[0] != "complete" for dep in node.depends_on):
                raise ResourceJobDenied("child prerequisites are not complete")
            required_parents = tuple(sorted({receipt for dep in node.depends_on for receipt in rows[dep][1]}))
            if parents != required_parents:
                raise ResourceJobDenied("child lineage does not contain the exact completed parent receipts")
            active = db.execute("SELECT count(*) FROM children WHERE job_id=? AND status IN ('admitted','running')",
                                (admission.job_id,)).fetchone()[0]
            if active >= job[6]:
                raise ResourceJobDenied("resource job concurrency limit is reached")
            attempt_row = db.execute("SELECT attempt FROM children WHERE admission_id=? AND job_id=? AND node_id=? AND status='pending'",
                                     (admission_id, admission.job_id, node_id)).fetchone()
            cur = db.execute("UPDATE children SET status='admitted' WHERE admission_id=? AND job_id=? AND node_id=? AND status='pending'",
                             (admission_id, admission.job_id, node_id))
            if cur.rowcount != 1:
                raise ResourceJobDenied("child admission was already consumed")
            db.commit()
        except ResourceJobDenied:
            db.rollback()
            raise
        except sqlite3.Error as exc:
            db.rollback()
            raise ResourceJobDenied("child admission failed closed") from exc
        finally:
            db.close()
        return ResourceChildAdmission(admission_id, admission.job_id, enrollment.resource_id,
                                      enrollment.generation, node.node_id, attempt_row[0], node.action_id,
                                      node.effect, node.target, node.recipient, node.payload_sha256,
                                      node.payload, tuple(json.loads(job[2])), parents)

    def start_child(self, child: ResourceChildAdmission, *, current_generation: str) -> None:
        if current_generation != child.generation:
            self.revoke_generation(child.resource_id, child.generation)
            raise ResourceJobDenied("resource generation was revoked before child effect")
        self._transition(child, "admitted", "running", receipts=())

    def fail_child_admission(self, child: ResourceChildAdmission, *, current_generation: str) -> None:
        """Fail a pre-effect attempt when context/grant minting is denied."""
        if current_generation != child.generation:
            self.revoke_generation(child.resource_id, child.generation)
            raise ResourceJobDenied("resource generation was revoked before child dispatch")
        self._transition(child, "admitted", "denied", receipts=())

    def finish_child(self, child: ResourceChildAdmission, *, result_receipt_ids: Sequence[str],
                     success: bool, current_generation: str) -> None:
        if type(success) is not bool or current_generation != child.generation:
            self.revoke_generation(child.resource_id, child.generation)
            raise ResourceJobDenied("child result arrived after generation revocation")
        receipts = tuple(sorted({_ident(item, "result receipt id") for item in result_receipt_ids}))
        if success and not receipts:
            raise ResourceJobDenied("successful child must preserve its root-issued result receipt")
        self._transition(child, "running", "complete" if success else "failed", receipts=receipts)
        if success:
            self._finish_job_if_terminal(child.job_id)
        else:
            self.fail_node(child.job_id, child.node_id)

    def retry_child(self, admission: ResourceJobAdmission, failed_attempt: ResourceChildAdmission,
                    enrollment: ResourceJobEnrollment, *, parent_result_receipt_ids: Sequence[str],
                    current_generation: str) -> ResourceChildAdmission:
        """Admit a fresh bounded attempt with a new one-use grant opportunity.

        The aggregate job child cap bounds retries; every retry gets a distinct
        admission ID and incremented root-derived retry index. Caller/model
        supplied retry indexes are not accepted.
        """
        if (failed_attempt.job_id != admission.job_id or failed_attempt.generation != enrollment.generation
                or failed_attempt.resource_id != enrollment.resource_id
                or admission.approved_dag_sha256 != enrollment.dag_sha256):
            raise ResourceJobDenied("retry is outside the selected job and immutable DAG")
        if current_generation != enrollment.generation:
            self.revoke_generation(enrollment.resource_id, enrollment.generation)
            raise ResourceJobDenied("resource generation was revoked")
        node = enrollment.node_map.get(failed_attempt.node_id)
        if node is None:
            raise ResourceJobDenied("retry node is outside the approved DAG")
        parents = tuple(sorted({_ident(item, "parent result receipt id") for item in parent_result_receipt_ids}))
        if len(parents) != len(parent_result_receipt_ids) or len(parents) > 64:
            raise ResourceJobDenied("parent result receipt lineage is malformed")
        new_id = secrets.token_urlsafe(24)
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            job = db.execute("SELECT resource_id,generation,source_receipts,dag_json,dag_sha256,expires,max_concurrency,status FROM jobs WHERE job_id=?",
                             (admission.job_id,)).fetchone()
            now = self.monotonic()
            if (job is None or job[0] != enrollment.resource_id or job[1] != current_generation
                    or job[4] != enrollment.dag_sha256 or job[5] <= now or job[7] != "running"):
                raise ResourceJobDenied("job is expired, revoked, or no longer current")
            prior = db.execute("SELECT attempt,status FROM children WHERE admission_id=? AND job_id=? AND node_id=?",
                               (failed_attempt.admission_id, admission.job_id, node.node_id)).fetchone()
            if prior is None or prior[0] != failed_attempt.retry_index or prior[1] != "denied":
                raise ResourceJobDenied("only a pre-effect denied child attempt may be retried")
            if prior[0] + 1 >= node.maximum_attempts:
                raise ResourceJobDenied("child attempt quota is exhausted")
            count = db.execute("SELECT count(*) FROM children WHERE job_id=?", (admission.job_id,)).fetchone()[0]
            if count >= enrollment.max_children:
                raise ResourceJobDenied("resource job child-attempt quota is exhausted")
            rows: dict[str, tuple[str, list[str]]] = {}
            for row in db.execute("SELECT node_id,attempt,status,result_receipts FROM children WHERE job_id=? ORDER BY attempt",
                                  (admission.job_id,)):
                rows[row[0]] = (row[2], json.loads(row[3]))
            if any(rows.get(dep, (None, []))[0] != "complete" for dep in node.depends_on):
                raise ResourceJobDenied("retry prerequisites are not complete")
            expected = tuple(sorted({receipt for dep in node.depends_on for receipt in rows[dep][1]}))
            if parents != expected:
                raise ResourceJobDenied("retry lineage does not contain exact parent receipts")
            active = db.execute("SELECT count(*) FROM children WHERE job_id=? AND status IN ('admitted','running')",
                                (admission.job_id,)).fetchone()[0]
            if active >= job[6]:
                raise ResourceJobDenied("resource job concurrency limit is reached")
            next_attempt = prior[0] + 1
            db.execute("INSERT INTO children VALUES (?,?,?,?,'admitted','[]')",
                       (new_id, admission.job_id, node.node_id, next_attempt))
            db.commit()
        except ResourceJobDenied:
            db.rollback()
            raise
        except sqlite3.Error as exc:
            db.rollback()
            raise ResourceJobDenied("fresh child retry admission failed closed") from exc
        finally:
            db.close()
        return ResourceChildAdmission(new_id, admission.job_id, enrollment.resource_id,
                                      enrollment.generation, node.node_id, next_attempt,
                                      node.action_id, node.effect, node.target, node.recipient,
                                      node.payload_sha256, node.payload, tuple(json.loads(job[2])), parents)

    def fail_node(self, job_id: str, node_id: str) -> None:
        """Close a failed node after its bounded retry policy is exhausted."""
        _ident(job_id, "job id")
        self._cancel_descendants(job_id, _ident(node_id, "node id"))
        self._finish_job_if_terminal(job_id)

    def _transition(self, child: ResourceChildAdmission, before: str, after: str,
                    *, receipts: Sequence[str]) -> None:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            job = db.execute("SELECT expires,status FROM jobs WHERE job_id=?", (child.job_id,)).fetchone()
            if job is None or job[0] <= self.monotonic() or job[1] != "running":
                raise ResourceJobDenied("job expired or stopped before child transition")
            cursor = db.execute("UPDATE children SET status=?,result_receipts=? WHERE admission_id=? AND job_id=? AND node_id=? AND status=?",
                                (after, _canonical(list(receipts)).decode(), child.admission_id,
                                 child.job_id, child.node_id, before))
            if cursor.rowcount != 1:
                raise ResourceJobDenied("child attempt transition is stale or already consumed")
            db.commit()
        except ResourceJobDenied:
            db.rollback()
            raise
        except sqlite3.Error as exc:
            db.rollback()
            raise ResourceJobDenied("child state update failed closed") from exc
        finally:
            db.close()

    def _cancel_descendants(self, job_id: str, failed_node: str) -> None:
        """Cancel only transitive dependents, including any active owned work."""
        db = self._connect()
        try:
            graph = db.execute("SELECT dag_json FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if graph is None:
                raise ResourceJobDenied("job disappeared before descendant cancellation")
            dependencies = json.loads(graph[0])
            cancelled = {failed_node}
            changed = True
            while changed:
                changed = False
                for node_id, parents in dependencies.items():
                    if node_id not in cancelled and any(parent in cancelled for parent in parents):
                        cancelled.add(node_id)
                        changed = True
            descendants = cancelled - {failed_node}
            if descendants:
                placeholders = ",".join("?" for _ in descendants)
                db.execute(f"UPDATE children SET status='cancelled' WHERE job_id=? AND node_id IN ({placeholders}) AND status IN ('pending','admitted','running')",
                           (job_id, *sorted(descendants)))
        finally:
            db.close()

    def is_active(self, child: ResourceChildAdmission, *, current_generation: str) -> bool:
        """Fresh cancellation/deadline check suitable for the broker callback."""
        if current_generation != child.generation:
            return False
        db = self._connect()
        try:
            row = db.execute("SELECT j.generation,j.expires,j.status,c.status FROM jobs j JOIN children c ON c.job_id=j.job_id WHERE j.job_id=? AND c.admission_id=?",
                             (child.job_id, child.admission_id)).fetchone()
            return bool(row and row[0] == current_generation and row[1] > self.monotonic()
                        and row[2] == "running" and row[3] == "running")
        finally:
            db.close()

    def is_child_admitted(self, child: ResourceChildAdmission, *, current_generation: str) -> bool:
        """Check a claimed child before its first effect has started."""
        if current_generation != child.generation:
            return False
        db = self._connect()
        try:
            row = db.execute(
                "SELECT j.generation,j.expires,j.status,c.status FROM jobs j "
                "JOIN children c ON c.job_id=j.job_id WHERE j.job_id=? AND c.admission_id=?",
                (child.job_id, child.admission_id),
            ).fetchone()
            return bool(row and row[0] == current_generation and row[1] > self.monotonic()
                        and row[2] == "running" and row[3] == "admitted")
        finally:
            db.close()

    def _finish_job_if_terminal(self, job_id: str) -> None:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            states: dict[str, str] = {}
            for node_id, attempt, status in db.execute(
                    "SELECT node_id,attempt,status FROM children WHERE job_id=? ORDER BY attempt", (job_id,)):
                states[node_id] = status
            pending = sum(state in {"pending", "admitted", "running"} for state in states.values())
            if pending == 0:
                failed = sum(state in {"failed", "denied", "cancelled"} for state in states.values())
                db.execute("UPDATE jobs SET status=? WHERE job_id=? AND status='running'",
                           ("failed" if failed else "complete", job_id))
            db.commit()
        finally:
            db.close()

    def revoke_generation(self, resource_id: str, generation: str) -> int:
        _ident(resource_id, "resource id")
        if not _DIGEST.fullmatch(generation):
            raise ResourceJobDenied("resource generation is invalid")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE children SET status='cancelled' WHERE status IN ('pending','admitted','running') AND job_id IN (SELECT job_id FROM jobs WHERE resource_id=? AND generation=?)",
                       (resource_id, generation))
            cursor = db.execute("UPDATE jobs SET status='cancelled' WHERE resource_id=? AND generation=? AND status='running'",
                                (resource_id, generation))
            count = cursor.rowcount
            db.commit()
            return count
        except sqlite3.Error as exc:
            db.rollback()
            raise ResourceJobDenied("generation revocation failed closed") from exc
        finally:
            db.close()

    def cancel_job(self, job_id: str, *, current_generation: str) -> bool:
        """Cancel one root admission and all of its uncompleted children atomically."""
        _ident(job_id, "job id")
        if not isinstance(current_generation, str) or not current_generation:
            raise ResourceJobDenied("current resource generation is invalid")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT generation,status FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if row is None or row[0] != current_generation:
                db.rollback()
                return False
            db.execute(
                "UPDATE children SET status='cancelled' WHERE job_id=? AND status IN ('pending','admitted','running')",
                (job_id,),
            )
            cursor = db.execute("UPDATE jobs SET status='cancelled' WHERE job_id=? AND status='running'",
                                (job_id,))
            db.commit()
            return cursor.rowcount == 1
        except sqlite3.Error as exc:
            db.rollback()
            raise ResourceJobDenied("job cancellation failed closed") from exc
        finally:
            db.close()
