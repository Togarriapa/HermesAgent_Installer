"""Strict source-pinned memory service enrollment and finite route catalogs.

Protected enrollment records are the only source of service identity, listener
port, namespace, auth reference, and ownership generation. This module never
discovers or guesses a loopback port and never accepts caller-supplied routes.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping


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
    "data_root_id", "auth_reference_id", "fixed_project_account_user_scope",
    "memory_owner_generation", "private_extraction_embedding_routes",
    "background_consent_revision", "limits",
})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


class MemoryEnrollmentError(ValueError):
    """Protected memory enrollment is incomplete or differs from its pinned catalog."""


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
    fixed_route_map: Mapping[str, RouteStep]
    data_root_id: str
    auth_reference_id: str
    fixed_project_account_user_scope: Mapping[str, str]
    memory_owner_generation: int
    private_extraction_embedding_routes: Mapping[str, str]
    background_consent_revision: str
    limits: Mapping[str, int]

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
                      "data_root_id", "auth_reference_id", "background_consent_revision"):
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
        if not isinstance(raw_routes, Mapping):
            raise MemoryEnrollmentError("protected fixed route map is required")
        catalog = ROUTES[provider][variant]
        routes: dict[str, RouteStep] = {}
        for route_id, raw in raw_routes.items():
            if route_id not in catalog or not isinstance(raw, Mapping) or set(raw) != {"method", "path", "body"}:
                raise MemoryEnrollmentError("enrolled route is outside the pinned provider/variant catalog")
            expected = catalog[route_id]
            if (raw["method"], raw["path"], raw["body"]) != (
                    expected.method, expected.path, expected.body):
                raise MemoryEnrollmentError("enrolled route method/path/body differs from pinned source")
            routes[route_id] = expected
        if not routes:
            raise MemoryEnrollmentError("at least one exact approved route is required")

        scope = record["fixed_project_account_user_scope"]
        if not isinstance(scope, Mapping) or set(scope) != {"project_id", "account_id", "user_id"}:
            raise MemoryEnrollmentError("root-forced project/account/user scope is required")
        scope_values = {key: _id(value, f"scope {key}") for key, value in scope.items()}
        if scope_values["user_id"] != profile:
            raise MemoryEnrollmentError("provider user scope must bind to the enrolled profile")

        private_routes = record["private_extraction_embedding_routes"]
        if not isinstance(private_routes, Mapping) or set(private_routes) != {"extract", "embed"}:
            raise MemoryEnrollmentError("both private extraction and embedding route identities are required")
        private_route_values = {key: _id(value, f"private {key} route") for key, value in private_routes.items()}

        limits = record["limits"]
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

        return cls(
            target_id=f"memory-{provider}:{profile}", provider=provider,
            backend_variant=variant, profile_id=profile,
            principal_id=record["principal_id"],
            service_enrollment_id=record["service_enrollment_id"],
            source_revision=record["source_revision"],
            service_generation=generation,
            namespace_identity=record["namespace_identity"],
            literal_loopback_port=port, fixed_route_map=routes,
            data_root_id=record["data_root_id"], auth_reference_id=record["auth_reference_id"],
            fixed_project_account_user_scope=scope_values,
            memory_owner_generation=record["memory_owner_generation"],
            private_extraction_embedding_routes=private_route_values,
            background_consent_revision=record["background_consent_revision"],
            limits=checked_limits,
        )
