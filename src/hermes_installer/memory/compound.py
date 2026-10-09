"""Typed, root-only request recipes for SK01 fixed memory compounds.

This module deliberately contains no socket, URL, or credential-reading code.
The root ServiceConnector uses the returned fixed request to perform the already
authorized service effect. Worker payloads are content/query objects, never HTTP.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Mapping, Sequence


class MemoryRecipeDenied(PermissionError):
    """A request is outside the immutable source-pinned memory recipe."""


class MemoryRecipeUnavailable(RuntimeError):
    """No reviewed serializer/validator is installed for this selected route."""


@dataclass(frozen=True, slots=True)
class MemoryServiceRequest:
    method: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    credential_reference_id: str


@dataclass(frozen=True, slots=True)
class MemoryStepOutcome:
    result: Mapping[str, Any]
    captures: Mapping[str, str]


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_ALLOWED_METHODS = frozenset({"GET", "POST", "DELETE"})
_MAX_BODY = 256 * 1024
_MAX_TEXT = 65536

# These route identities and templates are verified against the pinned source
# catalog. Claude-mem body/result validators are intentionally omitted until
# each backend variant has a reviewed request and semantic result schema.
_FIXED_PATHS: dict[str, tuple[str, str]] = {
    "agentmemory-search": ("POST", "/agentmemory/smart-search"),
    "agentmemory-capture": ("POST", "/agentmemory/remember"),
    "agentmemory-delete": ("POST", "/agentmemory/forget"),
    "agentmemory-export": ("GET", "/agentmemory/export"),
    "agentmemory-backup": ("GET", "/agentmemory/export"),
    "agentmemory-restore": ("POST", "/agentmemory/import"),
    "agentmemory-ready": ("GET", "/agentmemory/livez"),
    "openviking-find": ("POST", "/api/v1/search/find"),
    "openviking-session-capture": ("POST", "/api/v1/sessions"),
    "openviking-ready": ("GET", "/ready"),
}


def canonical_json(value: Mapping[str, Any], maximum: int = _MAX_BODY) -> bytes:
    if not isinstance(value, Mapping):
        raise ValueError("memory request body must be an object")
    try:
        result = json.dumps(dict(value), sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        raise ValueError("memory request body is not canonical JSON data") from None
    if len(result) > maximum:
        raise ValueError("memory request body exceeds the enrolled limit")
    return result


def _nonempty_text(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{name} is empty or exceeds its bound")
    return value


def _positive_limit(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 100:
        raise ValueError("memory result limit must be an integer from 1 through 100")
    return value


def _opaque(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise MemoryRecipeDenied(f"root enrollment has an invalid {name}")
    return value


def _path_for(step: Mapping[str, Any], captures: Mapping[str, str]) -> str:
    path = step.get("path_template")
    if not isinstance(path, str) or not path.startswith("/") or "//" in path or "?" in path or "#" in path:
        raise MemoryRecipeDenied("protected route path is malformed")
    if path == "/api/v1/sessions/{root-captured-owned-session-id}/messages" or path == "/api/v1/sessions/{root-captured-owned-session-id}/{root-selected-commit-or-extract}":
        session_id = _opaque(captures.get("session_id"), "captured session ID")
        suffix = "messages" if path.endswith("/messages") else _opaque(
            captures.get("finalize_action"), "root-selected finalize action")
        if suffix not in {"messages", "commit", "extract"}:
            raise MemoryRecipeDenied("finalize action is outside the enrolled recipe")
        return path.replace("{root-captured-owned-session-id}", session_id).replace(
            "{root-selected-commit-or-extract}", suffix)
    if "{" in path or "}" in path:
        raise MemoryRecipeDenied("route path contains an unrecognized root token")
    return path


def build_memory_request(*, provider: str, route_id: str, recipe: Mapping[str, Any],
                         step: Mapping[str, Any], body: Mapping[str, Any],
                         scope_bindings: Mapping[str, Any],
                         captures: Mapping[str, str] | None = None,
                         maximum_bytes: int = _MAX_BODY) -> MemoryServiceRequest:
    """Serialize one source-pinned recipe step; called only inside root custody.

    The route and step mappings come from strict root enrollment. The body is
    the canonical protocol envelope's typed body, never raw worker HTTP.
    """
    if not isinstance(recipe, Mapping) or not isinstance(step, Mapping):
        raise MemoryRecipeDenied("protected route recipe is missing")
    if not isinstance(scope_bindings, Mapping):
        raise MemoryRecipeDenied("protected scope bindings are missing")
    expected = _FIXED_PATHS.get(route_id)
    method = step.get("method")
    if expected is None or method not in _ALLOWED_METHODS:
        raise MemoryRecipeUnavailable("selected route has no reviewed fixed serializer")
    expected_method, expected_path = expected
    path_template = step.get("path_template")
    allowed_paths = {expected_path}
    if route_id == "openviking-session-capture":
        allowed_paths = {
            "/api/v1/sessions",
            "/api/v1/sessions/{root-captured-owned-session-id}/messages",
            "/api/v1/sessions/{root-captured-owned-session-id}/{root-selected-commit-or-extract}",
        }
    if method != expected_method or path_template not in allowed_paths:
        raise MemoryRecipeDenied("protected method or path differs from source-pinned route")
    body_recipe = step.get("body_recipe_id")
    captures = dict(captures or {})
    forced = {
        "project": _opaque(scope_bindings.get("backend_project_ref"), "project scope"),
        "agentId": _opaque(scope_bindings.get("backend_agent_ref"), "agent scope"),
    }
    if provider == "agentmemory" and route_id == "agentmemory-search" and body_recipe == "agentmemory-search-owned-v1":
        if set(body) != {"query", "limit"}:
            raise MemoryRecipeDenied("AgentMemory search accepts only query and limit")
        query = _nonempty_text(body["query"], "query", 16384)
        payload = {"query": query, "limit": _positive_limit(body["limit"]), **forced}
    elif provider == "agentmemory" and route_id == "agentmemory-capture" and body_recipe == "agentmemory-remember-owned-v1":
        if set(body) != {"content"}:
            raise MemoryRecipeDenied("AgentMemory capture accepts only content")
        payload = {"content": _nonempty_text(body["content"], "content", _MAX_TEXT), **forced}
    elif provider == "openviking" and route_id == "openviking-find" and body_recipe == "openviking-find-owned-v1":
        if set(body) != {"query", "limit"}:
            raise MemoryRecipeDenied("OpenViking find accepts only query and limit")
        target_uri = scope_bindings.get("backend_project_ref")
        target_uri = _nonempty_text(target_uri, "root target URI", 2048)
        payload = {"query": _nonempty_text(body["query"], "query", 16384),
                   "limit": _positive_limit(body["limit"]), "target_uri": target_uri,
                   "telemetry": False}
    elif provider == "openviking" and route_id == "openviking-session-capture":
        # Session create/append/finalize bodies differ by step and require source
        # response schemas. The executor rejects unknown IDs instead of turning
        # the outer body into arbitrary HTTP or choosing commit/extract itself.
        if body_recipe not in {
            "openviking-create-owned-session-v1",
            "openviking-append-captured-event-v1",
            "openviking-finalize-private-v1",
        }:
            raise MemoryRecipeUnavailable("OpenViking compound step recipe is not enrolled")
        raise MemoryRecipeUnavailable("OpenViking capture step serializer awaits pinned request validators")
    else:
        raise MemoryRecipeUnavailable("selected provider/action body recipe has no reviewed serializer")

    resolved_path = _path_for(step, captures)
    credential = _opaque(recipe.get("credential_reference_id"), "vault credential reference")
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= _MAX_BODY:
        raise MemoryRecipeDenied("enrolled request limit is invalid")
    encoded = canonical_json(payload, maximum_bytes)
    return MemoryServiceRequest(
        method=method, path=resolved_path,
        headers=(("accept", "application/json"), ("content-type", "application/json")),
        body=encoded, credential_reference_id=credential,
    )


def validate_compound_envelope(data: bytes, *, maximum_bytes: int = _MAX_BODY) -> dict[str, Any]:
    """Validate the canonical fixed-memory-compound-json-v1 worker envelope."""
    if not isinstance(data, bytes) or not 1 <= len(data) <= maximum_bytes:
        raise ValueError("memory compound envelope exceeds its enrolled bound")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("memory compound envelope is invalid JSON") from None
    required = {"schema", "handle_id", "generation", "sequence", "compound_job_handle", "step_id", "body"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("memory compound envelope fields differ from schema 1")
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise ValueError("memory compound envelope schema must be 1")
    for key in ("handle_id", "generation", "compound_job_handle", "step_id"):
        _opaque(value[key], key)
    if type(value["sequence"]) is not int or value["sequence"] < 1:
        raise ValueError("memory compound sequence must be positive")
    if not isinstance(value["body"], dict):
        raise ValueError("memory compound body must be a typed object")
    if canonical_json(value) != data:
        raise ValueError("memory compound envelope must be canonical JSON")
    return value


def validate_step_outcome(*, route_id: str, step_id: str, status: int,
                          value: Any) -> MemoryStepOutcome:
    """Validate only known response families and root-captured identifiers."""
    if type(status) is not int or not 200 <= status < 300 or not isinstance(value, dict):
        raise MemoryRecipeUnavailable("memory service response is not a successful JSON object")
    if route_id == "openviking-session-capture":
        if step_id == "create":
            if value.get("status") != "ok" or not isinstance(value.get("result"), dict):
                raise MemoryRecipeUnavailable("OpenViking create response failed source schema")
            session_id = value["result"].get("session_id")
            session_id = _opaque(session_id, "OpenViking created session ID")
            return MemoryStepOutcome({"status": "ok"}, {"session_id": session_id})
        if step_id in {"append", "finalize"}:
            if value.get("status") != "ok":
                raise MemoryRecipeUnavailable("OpenViking session step did not report success")
            return MemoryStepOutcome({"status": "ok"}, {})
    if route_id.startswith("agentmemory-"):
        # Pinned REST routes forward function payloads from the upstream
        # memory engine. Until the selected result shape has its own reviewed
        # schema artifact, do not convert arbitrary JSON into success.
        raise MemoryRecipeUnavailable("AgentMemory semantic result validator is not installed")
    if route_id == "openviking-find":
        if value.get("status") != "ok" or not isinstance(value.get("result"), dict):
            raise MemoryRecipeUnavailable("OpenViking find response failed source schema")
        return MemoryStepOutcome(value["result"], {})
    raise MemoryRecipeUnavailable("selected route has no semantic response validator")
