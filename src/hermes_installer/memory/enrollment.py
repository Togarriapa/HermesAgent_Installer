"""Strict source-pinned memory service enrollment and finite route catalogs.

Protected enrollment records are the only source of service identity, listener
port, namespace, auth reference, and ownership generation. This module never
discovers or guesses a loopback port and never accepts caller-supplied routes.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
import re
from typing import Any, Mapping

from .compound import MemoryRecipeDenied, MemoryRecipeUnavailable, MemoryRouteRecipe


SOURCE_PINS = {
    "openviking": "e7b2e974b1fb97cd8c6087ff013181ddfec94f77",
    "claude-mem": "fa8ab09f06aa05f958c5225cf3756ce52a3ebb96",
    "agentmemory": "df3d4a83b966d8d415cb9180d5a4724b07f729dc",
}

# Route IDs and request paths are checked against the pinned provider source.
# A route record may tighten limits but may never change method/path.
@dataclass(frozen=True, slots=True)
class RouteStep:
    method: str
    path: str
    body: str = "json"
    response: str = "json"


def _route(method: str, path: str, *, body: str = "json") -> RouteStep:
    return RouteStep(method, path, body)


ROUTES: dict[str, dict[str, dict[str, RouteStep]]] = {
    "openviking": {
        "default": {
            "openviking-ready": _route("GET", "/ready", body="none"),
            "openviking-find": _route("POST", "/api/v1/search/find"),
            # This route is a broker-owned recipe. The adapter performs create,
            # message append, then the enrolled commit/extract step in order.
            "openviking-session-capture": _route("POST", "/api/v1/sessions", body="recipe"),
        }
    },
    "claude-mem": {
        "server-v1-sqlite": {
            "claude-sqlite-ready": _route("GET", "/healthz", body="none"),
            "claude-sqlite-search": _route("POST", "/v1/search"),
            "claude-sqlite-capture": _route("POST", "/v1/memories"),
        },
        "server-v1-postgres": {
            "claude-postgres-ready": _route("GET", "/healthz", body="none"),
            "claude-postgres-search": _route("POST", "/v1/search"),
            "claude-postgres-capture": _route("POST", "/v1/memories"),
            "claude-postgres-delete": _route("DELETE", "/v1/memories/{owned_id}", body="none"),
        },
        "worker-observation": {
            "claude-worker-capture": _route("POST", "/api/memory/save"),
            "claude-worker-search-get": _route("GET", "/api/search", body="query"),
            "claude-worker-search-post": _route("POST", "/api/mem-search"),
            "claude-worker-delete": _route("DELETE", "/api/observation/{owned_id}", body="none"),
        },
    },
    "agentmemory": {
        "default": {
            "agentmemory-ready": _route("GET", "/agentmemory/livez", body="none"),
            "agentmemory-search": _route("POST", "/agentmemory/smart-search"),
            "agentmemory-capture": _route("POST", "/agentmemory/remember"),
            "agentmemory-delete": _route("POST", "/agentmemory/forget"),
            "agentmemory-export": _route("GET", "/agentmemory/export", body="none"),
            "agentmemory-backup": _route("GET", "/agentmemory/export", body="none"),
            "agentmemory-restore": _route("POST", "/agentmemory/import"),
        }
    },
}

ROOT_MEMORY_FIELDS = frozenset({
    "target_id", "provider", "backend_variant", "profile_id", "principal_id",
    "service_enrollment_id", "source_revision", "service_generation",
    "namespace_identity", "literal_loopback_port", "fixed_route_map",
    "data_root_id", "authority_state_root_id", "auth_reference_id", "fixed_project_account_user_scope",
    "memory_owner_generation", "private_extraction_embedding_routes",
    "background_consent_revision", "limits", "lifecycle_binding",
})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


class MemoryEnrollmentError(ValueError):
    """Protected memory enrollment is incomplete or differs from its pinned catalog."""


@dataclass(frozen=True, slots=True)
class MemoryLifecycleBinding:
    """Digest-covered selected start/readiness recipe for one service generation."""

    service_enrollment_id: str
    service_generation: str
    start_operation_id: str
    start_parameter_schema_id: str
    prestart_receipt_handles: tuple[str, ...]
    readiness_route_id: str
    readiness_schema_id: str
    restart_policy: str
    maximum_restart_attempts: int
    original_deadline_seconds: int

    @classmethod
    def from_protected_record(cls, value: Mapping[str, Any], *, provider: str,
                              backend_variant: str, service_enrollment_id: str,
                              service_generation: str,
                              fixed_route_map: Mapping[str, MemoryRouteRecipe]
                              ) -> "MemoryLifecycleBinding":
        fields = {
            "service_enrollment_id", "service_generation", "start_operation_id",
            "start_parameter_schema_id", "prestart_receipt_handles", "readiness_route_id",
            "readiness_schema_id", "restart_policy", "maximum_restart_attempts",
            "original_deadline_seconds",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise MemoryEnrollmentError("memory lifecycle binding fields differ from SK-T01")
        if (value["service_enrollment_id"] != service_enrollment_id
                or value["service_generation"] != service_generation):
            raise MemoryEnrollmentError("memory lifecycle binding differs from selected service generation")
        if value["start_parameter_schema_id"] != "no-caller-parameters-v1":
            raise MemoryEnrollmentError("memory startup parameters must use the protected empty schema")

        expected_start = {
            ("openviking", "default"): "memory-openviking-serve-v1",
            ("agentmemory", "default"): "memory-agentmemory-serve-v1",
            ("claude-mem", "worker-observation"): "memory-claude-mem-worker-observation-serve-v1",
            ("claude-mem", "server-v1-sqlite"): "memory-claude-mem-server-v1-sqlite-serve-v1",
            ("claude-mem", "server-v1-postgres"): "memory-claude-mem-server-v1-postgres-serve-v1",
        }.get((provider, backend_variant))
        if expected_start is None or value["start_operation_id"] != expected_start:
            raise MemoryEnrollmentError("memory startup operation differs from the pinned provider variant")

        expected_ready = {
            ("openviking", "default"): "openviking-ready",
            ("agentmemory", "default"): "agentmemory-ready",
            ("claude-mem", "server-v1-sqlite"): "claude-sqlite-ready",
            ("claude-mem", "server-v1-postgres"): "claude-postgres-ready",
        }.get((provider, backend_variant))
        readiness_route_id = value["readiness_route_id"]
        recipe = fixed_route_map.get(readiness_route_id) if isinstance(readiness_route_id, str) else None
        if (expected_ready is None or readiness_route_id != expected_ready or recipe is None
                or value["readiness_schema_id"] != recipe.result_schema_id):
            raise MemoryEnrollmentError("memory readiness route/schema is not source-pinned for the selected variant")

        receipts = value["prestart_receipt_handles"]
        if (not isinstance(receipts, (tuple, list)) or not receipts
                or any(not isinstance(handle, str) or not _ID.fullmatch(handle) for handle in receipts)
                or len(set(receipts)) != len(receipts)):
            raise MemoryEnrollmentError("memory startup requires distinct protected prestart receipts")
        restart_policy = value["restart_policy"]
        retries = value["maximum_restart_attempts"]
        if restart_policy not in {"manual-owned-restart", "bounded-owned-restart"}:
            raise MemoryEnrollmentError("memory restart policy is not a fixed owned policy")
        if type(retries) is not int or not 0 <= retries <= 3:
            raise MemoryEnrollmentError("memory restart attempts exceed the bounded lifecycle policy")
        if restart_policy == "manual-owned-restart" and retries != 0:
            raise MemoryEnrollmentError("manual memory restart policy cannot authorize automatic retries")
        deadline = value["original_deadline_seconds"]
        if type(deadline) is not int or not 1 <= deadline <= 600:
            raise MemoryEnrollmentError("memory lifecycle deadline exceeds the fixed bound")
        return cls(
            service_enrollment_id=service_enrollment_id,
            service_generation=service_generation,
            start_operation_id=expected_start,
            start_parameter_schema_id="no-caller-parameters-v1",
            prestart_receipt_handles=tuple(receipts),
            readiness_route_id=readiness_route_id,
            readiness_schema_id=recipe.result_schema_id,
            restart_policy=restart_policy,
            maximum_restart_attempts=retries,
            original_deadline_seconds=deadline,
        )


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise MemoryEnrollmentError(f"protected {label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class MemoryServiceEnrollment:
    target_id: str
    provider: str
    backend_variant: str
    profile_id: str
    principal_id: str
    service_enrollment_id: str
    source_revision: str
    service_generation: str
    namespace_identity: str
    literal_loopback_port: int
    fixed_route_map: Mapping[str, MemoryRouteRecipe]
    data_root_id: str
    auth_reference_id: str
    fixed_project_account_user_scope: Mapping[str, str]
    authority_state_root_id: str
    memory_owner_generation: int
    private_extraction_embedding_routes: Mapping[str, str]
    background_consent_revision: str
    limits: Mapping[str, int]
    lifecycle_binding: MemoryLifecycleBinding | None = None

    @classmethod
    def from_protected_record(cls, record: Mapping[str, Any]) -> "MemoryServiceEnrollment":
        if not isinstance(record, Mapping) or set(record) != ROOT_MEMORY_FIELDS:
            raise MemoryEnrollmentError("protected memory record fields do not match SK01 schema")
        provider = record["provider"]
        if provider not in SOURCE_PINS:
            raise MemoryEnrollmentError("memory provider is not in the pinned catalog")
        variant = record["backend_variant"]
        if not isinstance(variant, str) or variant not in ROUTES[provider]:
            raise MemoryEnrollmentError("backend variant is missing or unsupported")
        profile = _id(record["profile_id"], "profile ID")
        if record["target_id"] != f"memory-{provider}:{profile}":
            raise MemoryEnrollmentError("connector target ID is not the enrolled provider/profile identity")
        if record["source_revision"] != SOURCE_PINS[provider]:
            raise MemoryEnrollmentError("memory source revision differs from the reviewed pin")
        for field in ("principal_id", "service_enrollment_id", "namespace_identity",
                      "data_root_id", "authority_state_root_id", "auth_reference_id",
                      "background_consent_revision"):
            _id(record[field], field)
        generation = record["service_generation"]
        if not isinstance(generation, str) or not _ID.fullmatch(generation):
            raise MemoryEnrollmentError("opaque root-issued service generation is required")
        if type(record["memory_owner_generation"]) is not int or record["memory_owner_generation"] < 1:
            raise MemoryEnrollmentError("positive memory owner generation is required")
        port = record["literal_loopback_port"]
        if type(port) is not int or not 1024 <= port <= 65535:
            raise MemoryEnrollmentError("literal configured listener port is required")
        pinned_port = {"openviking": 1933, "agentmemory": 3111}.get(provider)
        if pinned_port is not None and port != pinned_port:
            raise MemoryEnrollmentError("service listener port differs from the reviewed provider configuration")

        raw_routes = record["fixed_route_map"]
        if not isinstance(raw_routes, Mapping) or not raw_routes:
            raise MemoryEnrollmentError("protected compound fixed route map is required")
        if any(not isinstance(route_id, str) or route_id not in ROUTES[provider][variant]
               for route_id in raw_routes):
            raise MemoryEnrollmentError("enrolled route is outside the pinned provider/variant catalog")
        limits = record["limits"]
        if not isinstance(limits, Mapping):
            raise MemoryEnrollmentError("route bounds are required before parsing compound recipes")
        routes: dict[str, MemoryRouteRecipe] = {}
        for route_id, raw in raw_routes.items():
            try:
                parsed = MemoryRouteRecipe.from_protected_record(
                    route_id, raw, backend_variant=variant, limits=limits)
            except (MemoryRecipeDenied, MemoryRecipeUnavailable, ValueError) as exc:
                raise MemoryEnrollmentError(
                    f"route {route_id} lacks a complete pinned compound serializer/validator: {exc}") from None
            route_scope = parsed.scope_bindings
            if (route_scope["profile_id"] != profile
                    or route_scope["service_generation"] != generation
                    or route_scope["memory_owner_generation"] != record["memory_owner_generation"]
                    or route_scope["credential_reference_id"] != record["auth_reference_id"]):
                raise MemoryEnrollmentError("route scope differs from the protected service enrollment")
            routes[route_id] = parsed

        scope = record["fixed_project_account_user_scope"]
        if not isinstance(scope, Mapping) or set(scope) != {"project_id", "account_id", "user_id"}:
            raise MemoryEnrollmentError("root-forced project/account/user scope is required")
        scope_values = {key: _id(value, f"scope {key}") for key, value in scope.items()}
        if scope_values["user_id"] != profile:
            raise MemoryEnrollmentError("provider user scope must bind to the enrolled profile")
        for parsed in routes.values():
            route_scope = parsed.scope_bindings
            if (route_scope["backend_project_ref"] != scope_values["project_id"]
                    or route_scope["backend_agent_ref"] != scope_values["user_id"]):
                raise MemoryEnrollmentError("route provider scope differs from root-forced enrollment scope")

        private_routes = record["private_extraction_embedding_routes"]
        if not isinstance(private_routes, Mapping) or set(private_routes) != {"extract", "embed"}:
            raise MemoryEnrollmentError("both private extraction and embedding route identities are required")
        private_route_values = {key: _id(value, f"private {key} route") for key, value in private_routes.items()}

        expected_limits = {"request_bytes", "response_bytes", "result_limit",
                           "operation_timeout_seconds", "whole_compound_timeout_seconds"}
        if not isinstance(limits, Mapping) or set(limits) != expected_limits:
            raise MemoryEnrollmentError("memory service limits are incomplete")
        maxima = {"request_bytes": 262144, "response_bytes": 2097152, "result_limit": 100,
                  "operation_timeout_seconds": 15, "whole_compound_timeout_seconds": 60}
        checked_limits: dict[str, int] = {}
        for key, maximum in maxima.items():
            value = limits[key]
            if type(value) is not int or not 1 <= value <= maximum:
                raise MemoryEnrollmentError(f"memory {key} exceeds the approved connector bound")
            checked_limits[key] = value

        lifecycle_record = record["lifecycle_binding"]
        if lifecycle_record is None:
            lifecycle_binding = None
        else:
            lifecycle_binding = MemoryLifecycleBinding.from_protected_record(
                lifecycle_record, provider=provider, backend_variant=variant,
                service_enrollment_id=record["service_enrollment_id"],
                service_generation=generation, fixed_route_map=routes)

        return cls(
            target_id=f"memory-{provider}:{profile}", provider=provider,
            backend_variant=variant, profile_id=profile,
            principal_id=record["principal_id"],
            service_enrollment_id=record["service_enrollment_id"],
            source_revision=record["source_revision"],
            service_generation=generation,
            namespace_identity=record["namespace_identity"],
            literal_loopback_port=port, fixed_route_map=routes,
             data_root_id=record["data_root_id"],
             auth_reference_id=record["auth_reference_id"],
            fixed_project_account_user_scope=scope_values,
            authority_state_root_id=record["authority_state_root_id"],
            memory_owner_generation=record["memory_owner_generation"],
            private_extraction_embedding_routes=private_route_values,
            background_consent_revision=record["background_consent_revision"],
            limits=checked_limits,
            lifecycle_binding=lifecycle_binding,
        )
