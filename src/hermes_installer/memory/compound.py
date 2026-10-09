"""Typed, root-only request recipes for SK01 fixed memory compounds.

This module deliberately contains no socket, URL, or credential-reading code.
The root ServiceConnector uses the returned fixed request to perform the already
authorized service effect. Worker payloads are content/query objects, never HTTP.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
from typing import Any, Mapping, Sequence
from types import MappingProxyType


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
                         trusted_event: Mapping[str, Any] | None = None,
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
        # The provider project reference is opaque enrollment metadata, not
        # an OpenViking URI. Until the protected resolver supplies a validated
        # root-owned viking:// target, do not serialize a guessed search scope.
        raise MemoryRecipeUnavailable(
            "root-owned OpenViking target URI resolver is not enrolled")
    elif provider == "openviking" and route_id == "openviking-session-capture":
        if body_recipe == "openviking-create-owned-session-v1":
            if body:
                raise MemoryRecipeDenied("OpenViking create accepts no caller-selected session fields")
            new_session = _opaque(captures.get("new_session_id"),
                                  "root-generated OpenViking session ID")
            payload = {"session_id": new_session, "auto_commit_policy": None,
                       "telemetry": False}
        elif body_recipe == "openviking-append-captured-event-v1":
            if set(body) != {"content"} or not isinstance(trusted_event, Mapping):
                raise MemoryRecipeDenied("append requires one content field and a root-captured event")
            event_fields = {"content", "role", "peer_id", "created_at", "turn_id",
                            "message_kind", "source_message_ids"}
            if set(trusted_event) - event_fields:
                raise MemoryRecipeDenied("root event contains fields outside the fixed append recipe")
            content = _nonempty_text(body["content"], "content", _MAX_TEXT)
            if content != trusted_event.get("content"):
                raise MemoryRecipeDenied("append content differs from root-captured source bytes")
            role = trusted_event.get("role")
            if role not in {"user", "assistant"}:
                raise MemoryRecipeDenied("captured role is not an allowed native conversation role")
            payload = {"role": role, "content": content, "telemetry": False}
            peer = trusted_event.get("peer_id")
            if peer is not None:
                payload["peer_id"] = _opaque(peer, "captured peer ID")
            message_kind = trusted_event.get("message_kind")
            if message_kind is not None:
                if message_kind not in {"user_query", "assistant_step", "tool_transport", "checkpoint"}:
                    raise MemoryRecipeDenied("captured message kind is not supported")
                payload["message_kind"] = message_kind
            for key in ("created_at", "turn_id"):
                value = trusted_event.get(key)
                if value is not None:
                    payload[key] = _nonempty_text(value, f"captured {key}", 128)
            source_ids = trusted_event.get("source_message_ids")
            if source_ids is not None:
                if (not isinstance(source_ids, (list, tuple)) or len(source_ids) > 100
                        or any(not isinstance(item, str) or not _ID.fullmatch(item)
                               for item in source_ids)):
                    raise MemoryRecipeDenied("captured source message IDs are invalid")
                payload["source_message_ids"] = list(source_ids)
        elif body_recipe == "openviking-finalize-private-v1":
            if body:
                raise MemoryRecipeDenied("finalize accepts no caller-selected operation fields")
            action = _opaque(captures.get("finalize_action"), "root-selected finalize action")
            if action not in {"commit", "extract"}:
                raise MemoryRecipeDenied("finalize action is outside the fixed recipe")
            if scope_bindings.get("private_provider_route_ref") is None:
                raise MemoryRecipeUnavailable("private extraction route is not enrolled")
            payload = {} if action == "extract" else {"keep_recent_count": 0, "telemetry": False}
        else:
            raise MemoryRecipeUnavailable("OpenViking session recipe is not enrolled")
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
                          value: Any, expected_session_id: str | None = None) -> MemoryStepOutcome:
    """Validate only known response families and root-captured identifiers."""
    if type(status) is not int or not 200 <= status < 300 or not isinstance(value, dict):
        raise MemoryRecipeUnavailable("memory service response is not a successful JSON object")
    if route_id == "openviking-session-capture":
        if step_id == "create":
            result = value.get("result")
            if value.get("status") != "ok" or not isinstance(result, dict):
                raise MemoryRecipeUnavailable("OpenViking create response failed source schema")
            session_id = _opaque(result.get("session_id"), "OpenViking created session ID")
            if expected_session_id is not None and session_id != expected_session_id:
                raise MemoryRecipeDenied("OpenViking returned a different session than root requested")
            return MemoryStepOutcome({"status": "ok"}, {"session_id": session_id})
        if step_id == "append":
            result = value.get("result")
            if value.get("status") != "ok" or not isinstance(result, dict):
                raise MemoryRecipeUnavailable("OpenViking append response failed source schema")
            session_id = _opaque(result.get("session_id"), "OpenViking append session ID")
            if expected_session_id is None or session_id != expected_session_id:
                raise MemoryRecipeDenied("OpenViking append response crossed the captured session")
            for key in ("message_count", "pending_tokens"):
                if type(result.get(key)) is not int or result[key] < 0:
                    raise MemoryRecipeUnavailable("OpenViking append response counters are invalid")
            return MemoryStepOutcome({"status": "ok"}, {})
        if step_id == "finalize":
            if value.get("status") != "ok" or not isinstance(value.get("result"), dict):
                raise MemoryRecipeUnavailable("OpenViking finalize response failed source schema")
            return MemoryStepOutcome({"status": "ok"}, {})
    if route_id == "agentmemory-search" and step_id == "search":
        if value.get("mode") != "compact":
            raise MemoryRecipeUnavailable("AgentMemory search returned an unsupported mode")
        rows = value.get("results")
        if not isinstance(rows, list) or len(rows) > 100:
            raise MemoryRecipeUnavailable("AgentMemory compact result list is invalid")
        records = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                    "obsId", "sessionId", "title", "type", "score", "timestamp"}:
                raise MemoryRecipeUnavailable("AgentMemory compact result fields differ from pin")
            record_id = _opaque(row["obsId"], "AgentMemory observation ID")
            _opaque(row["sessionId"], "AgentMemory source session ID")
            title = _nonempty_text(row["title"], "AgentMemory result title", 8192)
            if not isinstance(row["type"], str) or not row["type"] or len(row["type"]) > 64:
                raise MemoryRecipeUnavailable("AgentMemory observation type is invalid")
            score = row["score"]
            if type(score) not in (int, float) or not math.isfinite(score):
                raise MemoryRecipeUnavailable("AgentMemory search score is invalid")
            if not isinstance(row["timestamp"], str) or len(row["timestamp"]) > 64:
                raise MemoryRecipeUnavailable("AgentMemory timestamp is invalid")
            records.append({"id": record_id, "source": "agentmemory", "text": title})
        if "lessons" in value and not isinstance(value["lessons"], list):
            raise MemoryRecipeUnavailable("AgentMemory lesson results are invalid")
        return MemoryStepOutcome({"records": records}, {})
    if route_id == "agentmemory-capture" and step_id == "capture":
        memory = value.get("memory")
        if value.get("success") is not True or not isinstance(memory, dict):
            raise MemoryRecipeUnavailable("AgentMemory remember response failed source schema")
        try:
            memory_id = _opaque(memory.get("id"), "AgentMemory created memory ID")
        except MemoryRecipeDenied:
            # A service response is untrusted data, not an enrollment record.
            # Malformed IDs make this result unusable; they do not imply that
            # protected root configuration itself is invalid.
            raise MemoryRecipeUnavailable("AgentMemory remember result has an invalid ID") from None
        title = memory.get("title")
        if title is not None and (not isinstance(title, str) or len(title.encode("utf-8")) > 8192):
            raise MemoryRecipeUnavailable("AgentMemory created memory title is invalid")
        return MemoryStepOutcome({"success": True, "id": memory_id}, {"memory_id": memory_id})
    if route_id == "openviking-find":
        raise MemoryRecipeUnavailable(
            "OpenViking find result validator is not enrolled for the selected source schema")
    raise MemoryRecipeUnavailable("selected route has no semantic response validator")


@dataclass(frozen=True, slots=True)
class MemoryRouteStep:
    step_id: str
    method: str
    path_template: str
    body_recipe_id: str
    response_schema_id: str
    capture_fields: tuple[str, ...]
    next_step_id: str | None


@dataclass(frozen=True, slots=True)
class MemoryRouteRecipe:
    approved_route_id: str
    backend_variant: str
    steps: tuple[MemoryRouteStep, ...]
    request_schema_id: str
    result_schema_id: str
    scope_bindings: Mapping[str, Any]
    credential_reference_id: str
    maximum_seconds: int
    maximum_bytes: int

    @classmethod
    def from_protected_record(cls, route_id: str, raw: Mapping[str, Any], *,
                              backend_variant: str, limits: Mapping[str, int]) -> "MemoryRouteRecipe":
        required = {
            "approved_route_id", "backend_variant", "steps", "request_schema_id",
            "result_schema_id", "scope_bindings", "credential_reference_id",
            "maximum_seconds", "maximum_bytes",
        }
        if not isinstance(raw, Mapping) or set(raw) != required:
            raise MemoryRecipeDenied("protected route fields differ from SK01")
        if raw["approved_route_id"] != route_id or raw["backend_variant"] != backend_variant:
            raise MemoryRecipeDenied("route ID or backend variant differs from enrollment")
        if type(raw["maximum_seconds"]) is not int or type(raw["maximum_bytes"]) is not int:
            raise MemoryRecipeDenied("route limits must be integers")
        if (not 1 <= raw["maximum_seconds"] <= min(60, limits.get("whole_compound_timeout_seconds", 0))
                or not 1 <= raw["maximum_bytes"] <= min(_MAX_BODY, limits.get("request_bytes", 0))):
            raise MemoryRecipeDenied("route limits exceed enrollment")
        credential = _opaque(raw["credential_reference_id"], "vault credential reference")
        scope = raw["scope_bindings"]
        scope_keys = {"profile_id", "service_generation", "memory_owner_generation",
                      "backend_project_ref", "backend_agent_ref", "backend_session_ref",
                      "private_provider_route_ref", "credential_reference_id"}
        if not isinstance(scope, Mapping) or set(scope) != scope_keys:
            raise MemoryRecipeDenied("root-bound scope schema is incomplete")
        for key in ("profile_id", "service_generation", "backend_project_ref",
                    "backend_agent_ref", "credential_reference_id"):
            _opaque(scope[key], key)
        if scope["credential_reference_id"] != credential:
            raise MemoryRecipeDenied("route and scope vault references differ")
        if type(scope["memory_owner_generation"]) is not int or scope["memory_owner_generation"] < 1:
            raise MemoryRecipeDenied("owner generation must be positive")
        for key in ("backend_session_ref", "private_provider_route_ref"):
            value = scope[key]
            if value is not None:
                _opaque(value, key)
        raw_steps = raw["steps"]
        if not isinstance(raw_steps, (list, tuple)) or not 1 <= len(raw_steps) <= 16:
            raise MemoryRecipeDenied("route must contain one through sixteen ordered steps")
        steps = []
        for item in raw_steps:
            fields = {"step_id", "method", "path_template", "body_recipe_id",
                      "response_schema_id", "capture_fields", "next_step_id"}
            if not isinstance(item, Mapping) or set(item) != fields:
                raise MemoryRecipeDenied("step fields differ from SK01")
            step_id = _opaque(item["step_id"], "step ID")
            method, path = item["method"], item["path_template"]
            if method not in _ALLOWED_METHODS or not isinstance(path, str) or not path.startswith("/"):
                raise MemoryRecipeDenied("step method or path is invalid")
            body_id = _opaque(item["body_recipe_id"], "body recipe ID")
            response_id = _opaque(item["response_schema_id"], "response schema ID")
            captures = item["capture_fields"]
            if not isinstance(captures, (list, tuple)) or any(
                not isinstance(value, str) or not _ID.fullmatch(value) for value in captures
            ):
                raise MemoryRecipeDenied("step capture field list is invalid")
            next_id = item["next_step_id"]
            if next_id is not None:
                _opaque(next_id, "next step ID")
            steps.append(MemoryRouteStep(step_id, method, path, body_id, response_id,
                                         tuple(captures), next_id))
        if len({item.step_id for item in steps}) != len(steps):
            raise MemoryRecipeDenied("step IDs must be unique")
        for i, item in enumerate(steps):
            expected_next = steps[i + 1].step_id if i + 1 < len(steps) else None
            if item.next_step_id != expected_next:
                raise MemoryRecipeDenied("steps are not a closed ordered sequence")
        # This exact subset has complete request-body serializers and pinned
        # route schemas. Other provider variants stay unavailable until their
        # own semantic request/response validators are implemented.
        catalog = {
            "agentmemory-search": ("default", "agentmemory-search-request-v1",
                "agentmemory-search-result-v1",
                (("search", "POST", "/agentmemory/smart-search",
                  "agentmemory-search-owned-v1", "agentmemory-search-result-v1", (), None),)),
            "agentmemory-capture": ("default", "agentmemory-capture-request-v1",
                "agentmemory-remember-result-v1",
                (("capture", "POST", "/agentmemory/remember",
                  "agentmemory-remember-owned-v1", "agentmemory-remember-result-v1", (), None),)),
            "openviking-find": ("default", "openviking-find-request-v1",
                "openviking-find-result-v1",
                (("find", "POST", "/api/v1/search/find",
                  "openviking-find-owned-v1", "openviking-find-result-v1", (), None),)),
            "openviking-session-capture": ("default", "openviking-capture-event-v1",
                "openviking-capture-result-v1",
                (("create", "POST", "/api/v1/sessions",
                  "openviking-create-owned-session-v1", "openviking-create-result-v1",
                  ("session_id",), "append"),
                 ("append", "POST", "/api/v1/sessions/{root-captured-owned-session-id}/messages",
                  "openviking-append-captured-event-v1", "openviking-append-result-v1",
                  (), "finalize"),
                 ("finalize", "POST", "/api/v1/sessions/{root-captured-owned-session-id}/{root-selected-commit-or-extract}",
                  "openviking-finalize-private-v1", "openviking-finalize-result-v1",
                  (), None)),),
        }
        expected = catalog.get(route_id)
        if expected is None:
            raise MemoryRecipeUnavailable("route has no complete reviewed serializer")
        expected_variant, request_id, result_id, step_rows = expected
        actual = tuple((item.step_id, item.method, item.path_template, item.body_recipe_id,
                        item.response_schema_id, item.capture_fields, item.next_step_id)
                       for item in steps)
        if (backend_variant != expected_variant or raw["request_schema_id"] != request_id
                or raw["result_schema_id"] != result_id or actual != step_rows):
            raise MemoryRecipeDenied("route recipe differs from the pinned schema catalog")
        return cls(route_id, backend_variant, tuple(steps), request_id, result_id,
                   MappingProxyType(dict(scope)), credential,
                   raw["maximum_seconds"], raw["maximum_bytes"])
