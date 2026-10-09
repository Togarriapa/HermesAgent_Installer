"""Fixed, read-only public registry effects for reviewed Hermes plugins.

The caller can choose bounded search fields or an opaque record identity, but
never a URL, method, host, HTTP header, or network policy.  The host handler
catalog below binds each exact service ID to its official public origin and
small route set.  Public responses remain untrusted source data.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import quote, urlencode

from hermes_installer.network import BoundedNetwork, NetworkError

MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 2 * 1_048_576
MAX_DEADLINE_SECONDS = 9.0
MAX_QUERY_BYTES = 256
MAX_PAGE_SIZE = 30
MAX_PAGES = 3
_CAPABILITIES = {
    "registry:modelcontextprotocol": "registry-read",
    "registry:agent37": "registry-agent37-read",
}
_RECIPIENTS = {
    "registry:modelcontextprotocol": "https://registry.modelcontextprotocol.io",
    "registry:agent37": "https://www.agent37.com",
}


class PublicRegistryDenied(PermissionError):
    """A public registry call failed a fixed service, grant, or response rule."""


def canonical_registry_payload(payload: Mapping[str, Any]) -> bytes:
    """Encode the same deterministic JSON representation used for effect digests."""
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise PublicRegistryDenied("registry request is not canonical JSON") from None


def _json_payload(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_REQUEST_BYTES:
        raise PublicRegistryDenied("registry request exceeds its byte limit")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise PublicRegistryDenied("registry request is not valid JSON") from None
    if (not isinstance(value, dict) or set(value) != {"schema", "query", "limit", "cursor"}
            or value.get("schema") != 1 or type(value.get("schema")) is not int):
        raise PublicRegistryDenied("registry request does not match schema 1")
    if canonical_registry_payload(value) != payload:
        raise PublicRegistryDenied("registry request is not canonically encoded")
    query = value.get("query")
    if not isinstance(query, dict) or len(query) > 7:
        raise PublicRegistryDenied("registry query must be a bounded object")
    if len(canonical_registry_payload(query)) > MAX_QUERY_BYTES:
        raise PublicRegistryDenied("registry query exceeds the reviewed 256-byte limit")
    limit = value.get("limit")
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
        raise PublicRegistryDenied("registry page limit is invalid")
    cursor = value.get("cursor")
    if cursor is not None and (not isinstance(cursor, str) or len(cursor) > 1024
                               or any(ord(char) < 32 for char in cursor)):
        raise PublicRegistryDenied("registry pagination cursor is invalid")
    return value


def _validate_grant(context: object, authorization: object, *, target: str,
                    recipient: str, capability: str, payload: bytes,
                    timeout: float, peer_pid: int, cancelled: Callable[[], bool]) -> float:
    if not callable(cancelled) or cancelled():
        raise PublicRegistryDenied("registry request was cancelled")
    digest = hashlib.sha256(payload).hexdigest()
    sensitivity = getattr(context, "sensitivity", None)
    if not isinstance(sensitivity, str):
        sensitivity = getattr(sensitivity, "value", None)
    if (getattr(context, "purpose", None) != "native-hermes-chat"
            or sensitivity != "public"
            or capability not in getattr(context, "capabilities", frozenset())
            or getattr(authorization, "target", None) != target
            or getattr(authorization, "recipient", None) != recipient
            or getattr(authorization, "capability", None) != capability
            or getattr(authorization, "request_digest", None) != digest
            or getattr(authorization, "purpose", None) != getattr(context, "purpose", None)):
        raise PublicRegistryDenied("registry effect grant does not match its public read request")
    retry_index = getattr(authorization, "retry_index", None)
    if retry_index != 0:
        raise PublicRegistryDenied("public registry reads do not permit retries")
    for name in ("principal_id", "profile_id", "namespace_id", "uid", "intent_id",
                 "trace_id", "policy_revision", "lineage_hash"):
        value = getattr(context, name, None)
        if value in (None, "") or value != getattr(authorization, name, None):
            raise PublicRegistryDenied("registry grant is not bound to the current host context")
    deadline = getattr(authorization, "monotonic_expires_at", None)
    context_deadline = getattr(context, "monotonic_expires_at", None)
    now = time.monotonic()
    if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
            or isinstance(context_deadline, bool) or not isinstance(context_deadline, (int, float))
            or not math.isfinite(deadline) or not math.isfinite(context_deadline)
            or deadline <= now or context_deadline <= now or deadline > context_deadline
            or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0
            or type(peer_pid) is not int or peer_pid <= 0):
        raise PublicRegistryDenied("registry grant or request deadline is invalid")
    if getattr(authorization, "retry_index", None) != 0:
        raise PublicRegistryDenied("public registry reads do not permit retries")
    remaining = min(MAX_DEADLINE_SECONDS, float(timeout), deadline - now, context_deadline - now)
    if cancelled() or remaining <= 0:
        raise PublicRegistryDenied("registry request expired before dispatch")
    return remaining


@dataclass(frozen=True, slots=True)
class _RegistryHandler:
    target: str
    recipient: str
    capability: str

    def __call__(self, *, context: object, authorization: object, payload: bytes,
                 timeout: float, peer_pid: int,
                 cancelled: Callable[[], bool]) -> dict[str, Any]:
        if self.target not in _CAPABILITIES or _RECIPIENTS[self.target] != self.recipient:
            raise PublicRegistryDenied("public registry enrollment does not match the compiled catalog")
        if _CAPABILITIES[self.target] != self.capability:
            raise PublicRegistryDenied("public registry capability does not match the compiled catalog")
        remaining = _validate_grant(context, authorization, target=self.target,
                                    recipient=self.recipient, capability=self.capability,
                                    payload=payload, timeout=timeout, peer_pid=peer_pid,
                                    cancelled=cancelled)
        request = _json_payload(payload)
        deadline = min(time.monotonic() + MAX_DEADLINE_SECONDS,
                       getattr(authorization, "monotonic_expires_at"),
                       getattr(context, "monotonic_expires_at"),
                       time.monotonic() + remaining)
        current = dict(request)
        aggregate: list[Any] = []
        final_metadata: dict[str, Any] = {}
        projected: Any = None
        page_count = 0
        while page_count < MAX_PAGES:
            left = deadline - time.monotonic()
            if cancelled() or left <= 0:
                raise PublicRegistryDenied("registry read exceeded its whole-operation deadline")
            url = (_mcp_registry_url(current) if self.target == "registry:modelcontextprotocol"
                   else _agent37_url(current))
            try:
                network = BoundedNetwork(
                    deadline_seconds=left, socket_timeout=min(3.0, left),
                    max_response_bytes=MAX_RESPONSE_BYTES,
                )
                response = network.request(url, method="GET",
                                           headers={"Accept": "application/json"},
                                           body=None, cancelled=cancelled)
            except (NetworkError, OSError, TimeoutError, ValueError):
                raise PublicRegistryDenied("fixed public registry request failed within its bounds") from None
            if (type(response.status) is not int or response.status != 200
                    or not isinstance(response.body, bytes) or len(response.body) > MAX_RESPONSE_BYTES
                    or not isinstance(response.headers, Mapping)):
                raise PublicRegistryDenied("public registry returned an invalid or oversized response")
            content_type = response.headers.get("Content-Type", response.headers.get("content-type", ""))
            if not isinstance(content_type, str) or "application/json" not in content_type.casefold():
                raise PublicRegistryDenied("public registry response is not JSON")
            try:
                parsed = json.loads(response.body)
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                raise PublicRegistryDenied("public registry response is malformed JSON") from None
            if not isinstance(parsed, dict):
                raise PublicRegistryDenied("public registry response has an unexpected shape")
            page_count += 1
            if self.target == "registry:modelcontextprotocol":
                entries, final_metadata = _project_mcp_page(parsed, current)
                aggregate.extend(entries)
                next_cursor = final_metadata.get("nextCursor")
                is_search = current["query"].get("name") is None
                is_history = (current["query"].get("name") is not None
                              and current["query"].get("version") is None)
                if is_history:
                    projected = {"servers": entries, "metadata": final_metadata,
                                 "pageCount": page_count}
                    break
                if (not is_search or not next_cursor or page_count == MAX_PAGES):
                    projected = ({"servers": aggregate, "metadata": final_metadata,
                                  "pageCount": page_count} if is_search else entries[0])
                    break
                current["cursor"] = next_cursor
            else:
                page = _strip_agent37_content(parsed, request=current)
                if "id" in current["query"]:
                    projected = page
                    break
                aggregate.extend(page["hits"])
                total = page["totalHits"]
                next_offset = page["offset"] + page["limit"]
                final_metadata = {"totalHits": total, "limit": page["limit"],
                                  "offset": page["offset"]}
                if (next_offset >= total or len(page["hits"]) < page["limit"]
                        or page_count == MAX_PAGES):
                    projected = {"hits": aggregate, "totalHits": total,
                                 "limit": request["limit"],
                                 "offset": int(request["cursor"] or "0"),
                                 "pageCount": page_count,
                                 "sourceContentTrust": "untrusted-public-metadata"}
                    break
                current["cursor"] = str(next_offset)
        if projected is None:
            raise PublicRegistryDenied("registry pagination produced no bounded result")
        if cancelled() or time.monotonic() >= deadline:
            raise PublicRegistryDenied("registry response arrived after its grant expired")
        body = canonical_registry_payload(projected)
        if len(body) > MAX_RESPONSE_BYTES:
            raise PublicRegistryDenied("public registry response exceeds the encoded byte limit")
        return {
            "status": response.status,
            "body": body,
            "headers": {"Content-Type": "application/json"},
            "receipt_id": "registry-read-" + secrets.token_urlsafe(24),
        }


def _text(query: Mapping[str, Any], name: str, *, required: bool = False,
          maximum: int = 256) -> str | None:
    value = query.get(name)
    if value is None and not required:
        return None
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(char) < 32 for char in value)):
        raise PublicRegistryDenied(f"registry query field {name} is invalid")
    return value.strip()


def _mcp_registry_url(request: Mapping[str, Any]) -> str:
    query = request["query"]
    allowed = {"search", "version", "name"}
    if set(query) - allowed:
        raise PublicRegistryDenied("MCP Registry query contains an unsupported filter")
    limit = request["limit"]
    cursor = request["cursor"]
    if limit > MAX_PAGE_SIZE:
        raise PublicRegistryDenied("MCP Registry page limit exceeds 30")
    name = _text(query, "name", maximum=200)
    search = _text(query, "search", maximum=200)
    version = _text(query, "version", maximum=128)
    params: dict[str, str] = {}
    if name is None:
        if "version" in query and version != "latest":
            raise PublicRegistryDenied("MCP Registry list supports only version=latest")
        if search is not None:
            params["search"] = search
        if version is not None:
            params["version"] = version
        params["limit"] = str(limit)
        if cursor is not None:
            params["cursor"] = cursor
        path = "/v0.1/servers"
    else:
        if search is not None:
            raise PublicRegistryDenied("MCP Registry detail cannot combine name and search")
        if cursor is not None:
            raise PublicRegistryDenied("MCP Registry version routes do not support pagination")
        encoded_name = quote(name, safe="")
        if version is None:
            path = f"/v0.1/servers/{encoded_name}/versions"
        else:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}|latest", version):
                raise PublicRegistryDenied("MCP Registry version selector is invalid")
            path = f"/v0.1/servers/{encoded_name}/versions/{quote(version, safe='')}"
        # The official versions and version-detail routes have no pagination
        # parameters; do not send ignored or undocumented query fields.
    query_string = urlencode(params)
    return f"https://registry.modelcontextprotocol.io{path}" + (f"?{query_string}" if query_string else "")


_AGENT37_ID = re.compile(r"^[0-9a-f]{32}$")


def _agent37_url(request: Mapping[str, Any]) -> str:
    query = request["query"]
    allowed = {"search", "id", "owner", "repo", "sort", "min_stars", "recent"}
    if set(query) - allowed:
        raise PublicRegistryDenied("Agent37 query contains an unsupported filter")
    skill_id = _text(query, "id", maximum=32)
    if skill_id is not None:
        if not _AGENT37_ID.fullmatch(skill_id) or set(query) != {"id"}:
            raise PublicRegistryDenied("Agent37 detail needs one exact returned skill ID")
        return f"https://www.agent37.com/api/skills/{skill_id}"
    search = _text(query, "search", required=True, maximum=160)
    params = {
        "query": search,
        "limit": str(min(request["limit"], 30)),
        "offset": request["cursor"] or "0",
    }
    if not re.fullmatch(r"(?:0|[1-9]\d{0,5})", params["offset"]):
        raise PublicRegistryDenied("Agent37 page cursor is invalid")
    for name, api_name, maximum in (("owner", "owner", 128), ("repo", "repo", 256)):
        value = _text(query, name, maximum=maximum)
        if value is not None:
            params[api_name] = value
    sort = _text(query, "sort", maximum=16)
    if sort is not None:
        if sort not in {"relevance", "updated"}:
            raise PublicRegistryDenied("Agent37 sort order is invalid")
        params["sort"] = sort
    min_stars = query.get("min_stars")
    if min_stars is not None:
        if type(min_stars) is not int or min_stars != 10:
            raise PublicRegistryDenied("Agent37 supports only the reviewed minimum-star filter")
        params["minStars"] = "10"
    recent = query.get("recent")
    if recent is not None:
        if recent is not True:
            raise PublicRegistryDenied("Agent37 recent filter must be true")
        params["recentlyUpdated"] = "30"
    return "https://www.agent37.com/api/skills/search?" + urlencode(params)


_AGENT37_METADATA_FIELDS = frozenset({
    "id", "name", "description", "source", "githubOwner", "githubRepoName",
    "githubRepoFullName", "githubStars", "githubForks", "githubUrl", "branch",
    "filePath", "repoLastPushedAt", "repoUpdatedAt", "lastSyncedAt", "syncStatus",
})


_MCP_SERVER_FIELDS = frozenset({
    "name", "description", "title", "version", "websiteUrl", "$schema",
})


def _project_mcp_server(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PublicRegistryDenied("MCP Registry entry lacks a server object")
    server = value.get("server", value)
    if not isinstance(server, dict):
        raise PublicRegistryDenied("MCP Registry entry has an invalid server object")
    name = server.get("name")
    if not isinstance(name, str) or not 1 <= len(name) <= 200:
        raise PublicRegistryDenied("MCP Registry entry lacks a bounded server identity")
    projected: dict[str, Any] = {}
    for key in _MCP_SERVER_FIELDS:
        item = server.get(key)
        if item is None:
            continue
        if not isinstance(item, str) or len(item) > 4096:
            raise PublicRegistryDenied("MCP Registry metadata field exceeds its scalar size limit")
        projected[key] = item
    repository = server.get("repository")
    if repository is not None:
        if not isinstance(repository, dict):
            raise PublicRegistryDenied("MCP Registry repository metadata has an invalid shape")
        safe_repository = {}
        for key in ("url", "source", "id", "subfolder"):
            item = repository.get(key)
            if item is None:
                continue
            if not isinstance(item, str) or len(item) > 2048:
                raise PublicRegistryDenied("MCP Registry repository field exceeds its size limit")
            safe_repository[key] = item
        projected["repository"] = safe_repository
    return {"server": projected}


def _project_mcp_page(value: Mapping[str, Any], request: Mapping[str, Any]
                      ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    query = request["query"]
    if "servers" in value:
        entries = value["servers"]
        max_entries = (90 if query.get("name") is not None and query.get("version") is None
                       else request["limit"])
        if not isinstance(entries, list) or len(entries) > max_entries:
            raise PublicRegistryDenied("MCP Registry page exceeds the requested entry bound")
        metadata = value.get("metadata", {})
        if not isinstance(metadata, dict):
            raise PublicRegistryDenied("MCP Registry pagination metadata is malformed")
        next_cursor = metadata.get("nextCursor")
        if next_cursor is not None and (not isinstance(next_cursor, str) or len(next_cursor) > 1024
                                        or any(ord(char) < 32 for char in next_cursor)):
            raise PublicRegistryDenied("MCP Registry returned an invalid pagination cursor")
        count = metadata.get("count")
        if count is not None and (type(count) is not int or count < 0 or count > max_entries):
            raise PublicRegistryDenied("MCP Registry page count is invalid")
        safe_metadata = {}
        if "nextCursor" in metadata:
            safe_metadata["nextCursor"] = next_cursor
        if count is not None:
            safe_metadata["count"] = count
        projected = [_project_mcp_server(item) for item in entries]
        if query.get("name") is not None:
            for item in projected:
                server = item["server"]
                if server.get("name") != query["name"]:
                    raise PublicRegistryDenied("MCP Registry history contains another server identity")
                if query.get("version") is not None and server.get("version") != query["version"]:
                    raise PublicRegistryDenied("MCP Registry version detail does not match the request")
        return projected, safe_metadata
    if query.get("name") is None:
        raise PublicRegistryDenied("MCP Registry list result lacks its bounded server page")
    detail = _project_mcp_server(value)
    server = detail["server"]
    if server.get("name") != query["name"]:
        raise PublicRegistryDenied("MCP Registry detail identity does not match the requested server")
    version = query.get("version")
    if version is not None and server.get("version") != version:
        raise PublicRegistryDenied("MCP Registry detail version does not match the request")
    return [detail], {}


def _strip_agent37_content(value: dict[str, Any] | list[Any], *,
                           request: Mapping[str, Any]) -> dict[str, Any] | list[Any]:
    """Keep only bounded discovery metadata; skill instructions remain unrequested."""
    if isinstance(value, list):
        raise PublicRegistryDenied("Agent37 returned a list where its API promises an object")
    hits = value.get("hits")
    if isinstance(hits, list):
        if len(hits) > 30:
            raise PublicRegistryDenied("Agent37 returned more than one fixed page")
        safe_hits = []
        for hit in hits:
            if not isinstance(hit, dict) or not isinstance(hit.get("id"), str) or not _AGENT37_ID.fullmatch(hit["id"]):
                raise PublicRegistryDenied("Agent37 result lacks a reviewed opaque skill ID")
            safe_hits.append(_safe_metadata(hit))
        total = value.get("totalHits")
        limit = value.get("limit")
        offset = value.get("offset")
        if (type(total) is not int or total < 0 or type(limit) is not int or not 1 <= limit <= 30
                or type(offset) is not int or offset < 0):
            raise PublicRegistryDenied("Agent37 result count is invalid")
        expected_offset = int(request["cursor"] or "0")
        if limit != request["limit"] or offset != expected_offset:
            raise PublicRegistryDenied("Agent37 page does not match the requested offset and limit")
        return {"hits": safe_hits, "totalHits": total,
                "limit": limit, "offset": offset,
                "sourceContentTrust": "untrusted-public-metadata"}
    requested_id = request["query"].get("id")
    if (not isinstance(requested_id, str) or value.get("id") != requested_id
            or not _AGENT37_ID.fullmatch(requested_id)):
        raise PublicRegistryDenied("Agent37 detail response lacks the requested skill identity")
    return _safe_metadata(value) | {
        "sourceContentTrust": "untrusted-public-metadata",
    }


def _safe_metadata(value: Mapping[str, Any]) -> dict[str, Any]:
    """Retain only scalar public metadata; never pass nested source payloads."""
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key not in _AGENT37_METADATA_FIELDS:
            continue
        if isinstance(item, str):
            if len(item) > 4096:
                raise PublicRegistryDenied("Agent37 metadata field exceeds its size limit")
            result[key] = item
        elif item is None or type(item) in {int, bool}:
            result[key] = item
        else:
            raise PublicRegistryDenied("Agent37 metadata field has an unsupported nested shape")
    return result


def build_registry_handlers() -> Mapping[tuple[str, str], _RegistryHandler]:
    """Compile only two fixed GET handlers; host rules separately enroll them.

    The returned map is intended for the installer-owned AuthorityService
    handler registry. An empty/denied authority rule still blocks every call.
    """
    return {
        ("registry.read", target): _RegistryHandler(
            target=target, recipient=_RECIPIENTS[target],
            capability=_CAPABILITIES[target],
        )
        for target in _CAPABILITIES
    }


def invoke_public_registry_read(runtime_context: object, *, service_id: str,
                                query: Mapping[str, Any], limit: int = 20,
                                cursor: str | None = None, action_id: str,
                                invocation_arguments: Mapping[str, Any],
                                intent: str) -> dict[str, Any]:
    """Use a fresh host context and one-use grant for a fixed public registry."""
    plugin_for_service = {
        "registry:modelcontextprotocol": "mcp-registry",
        "registry:agent37": "agent37-discovery",
    }
    actions_for_service = {
        "registry:modelcontextprotocol": frozenset({
            "discover-servers", "inspect-server-metadata", "inspect-versions",
        }),
        "registry:agent37": frozenset({
            "discover-skill-candidates", "inspect-public-metadata",
        }),
    }
    capability = _CAPABILITIES.get(service_id)
    if (capability is None or service_id not in plugin_for_service
            or action_id not in actions_for_service[service_id]
            or getattr(getattr(runtime_context, "identity", None), "kind", None) != "plugins"
            or getattr(runtime_context.identity, "resource_id", None) != plugin_for_service[service_id]):
        raise PublicRegistryDenied("registry service does not match the selected Plugin source identity")
    if (not isinstance(query, Mapping) or not isinstance(invocation_arguments, Mapping)
            or type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE):
        raise PublicRegistryDenied("public registry query bounds are invalid")
    payload_object = {"schema": 1, "query": dict(query), "limit": limit, "cursor": cursor}
    body = canonical_registry_payload(payload_object)
    if len(body) > MAX_REQUEST_BYTES or len(canonical_registry_payload(query)) > MAX_QUERY_BYTES:
        raise PublicRegistryDenied("registry request exceeds its byte limit")
    _json_payload(body)
    authority = getattr(runtime_context, "authority", None)
    invocation_contexts = getattr(runtime_context, "invocation_contexts", None)
    if authority is None or not callable(invocation_contexts):
        raise PublicRegistryDenied("root-owned public registry authority is unavailable")
    intent = intent.strip() if isinstance(intent, str) else ""
    if not intent or len(intent) > 512:
        raise PublicRegistryDenied("registry read intent is invalid")
    from hermes_installer.components.plugin_effects import (
        PluginEffectUnavailable,
        root_invocation_source_receipt_handles,
    )
    arguments_digest = hashlib.sha256(canonical_registry_payload(invocation_arguments)).hexdigest()
    try:
        source_receipt_handles = root_invocation_source_receipt_handles(
            invocation_contexts, adapter_id=plugin_for_service[service_id],
            action_id=action_id, arguments_sha256=arguments_digest,
            purpose="native-hermes-chat", intent=intent,
        )
    except (PluginEffectUnavailable, TypeError, ValueError):
        raise PublicRegistryDenied("trusted Hermes invocation lineage is unavailable") from None
    target = service_id
    recipient = _RECIPIENTS[target]
    request_digest = hashlib.sha256(body).hexdigest()
    context = authority.context(
        purpose="native-hermes-chat", intent=intent, operation="registry.read",
        source_receipt_handles=source_receipt_handles,
        final_payload_digest=request_digest, lease_seconds=30.0,
    )
    grant = authority.authorize_effect(context, capability=capability, target=target,
                                       recipient=recipient, request_digest=request_digest,
                                       retry_index=0)
    authority.verify_effect(grant, context, capability=capability, target=target,
                            recipient=recipient, request_digest=request_digest,
                            retry_index=0)
    response = authority.perform_effect(grant, operation="registry.read", payload=body,
                                        timeout=MAX_DEADLINE_SECONDS)
    if type(getattr(response, "status", None)) is not int or response.status != 200:
        raise PublicRegistryDenied("public registry read did not return HTTP 200")
    response_body = getattr(response, "body", None)
    if not isinstance(response_body, bytes) or len(response_body) > MAX_RESPONSE_BYTES:
        raise PublicRegistryDenied("public registry returned an invalid or oversized response")
    try:
        result = json.loads(response_body)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise PublicRegistryDenied("public registry broker returned malformed JSON") from None
    if not isinstance(result, (dict, list)):
        raise PublicRegistryDenied("public registry broker returned an invalid JSON shape")
    return {"service_id": service_id, "trust": "untrusted-public-source", "result": result}
