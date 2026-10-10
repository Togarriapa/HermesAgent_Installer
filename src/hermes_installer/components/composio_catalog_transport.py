"""Root-only fixed HTTPS transport for authenticated Composio catalog reads.

The setup authority creates one-use grants from a current root setup session.
This module accepts no caller URL, method, header, or raw credential. It pins
the Composio v3.1 trigger catalog and records every actual response through
the authority's immutable source-receipt sink before returning parsed data.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode

from hermes_installer.network import BoundedNetwork


COMPOSIO_ORIGIN = "https://backend.composio.dev"
COMPOSIO_TOOLKIT_VERSION = "20260721_00"
COMPOSIO_COLLECTION_PATH = "/api/v3.1/triggers_types"
COMPOSIO_CATALOG_POLICY_ID = "installer-composio-whatsapp-catalog-read-policy-v1"
COMPOSIO_CATALOG_POLICY_ARTIFACT_PATH = (
    "plans/amendments/2026-10-10-prepared-base-reader-release-manifest-v63/"
    "composio-whatsapp-catalog-read-policy-v1.json"
)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_DEADLINE_SECONDS = 30.0
MAX_CURSOR_BYTES = 1024
_SLUG = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_VERSION_QUERY = {"whatsapp": COMPOSIO_TOOLKIT_VERSION}

_POLICY = {
    "credential_scope": "composio-project-catalog-read",
    "detail_prefix": COMPOSIO_COLLECTION_PATH + "/",
    "id": COMPOSIO_CATALOG_POLICY_ID,
    "list_path": COMPOSIO_COLLECTION_PATH,
    "max_lease_seconds": 30,
    "max_page_items": 50,
    "max_pages": 10,
    "max_response_bytes": MAX_RESPONSE_BYTES,
    "max_total_items": 500,
    "methods": ["GET"],
    "operation": "composio.whatsapp.catalog.read",
    "origin": COMPOSIO_ORIGIN,
    "redirects": "deny",
    "schema": 1,
    "toolkit_slug": "whatsapp",
    "version_source": "selected-channel-pinned-version",
    "writes": "deny",
}
COMPOSIO_CATALOG_POLICY_SHA256 = hashlib.sha256(
    json.dumps(_POLICY, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
).hexdigest()


class ComposioCatalogTransportDenied(PermissionError):
    """A root catalog read failed its current grant, fixed request or receipt rule."""


@dataclass(frozen=True, slots=True)
class ComposioCatalogResponse(Mapping[str, Any]):
    """Parsed response plus one root exchange receipt for its paired bytes."""

    document: Mapping[str, Any]
    exchange_receipt_handle: str
    http_status: int

    def __getitem__(self, key: str) -> Any:
        return self.document[key]

    def __iter__(self):
        return iter(self.document)

    def __len__(self) -> int:
        return len(self.document)


class _ComposioSetupAuthority(Protocol):
    def authorize_catalog_get(self, authorization_handle: str, *,
                              trigger_slug: str | None = None) -> object: ...
    def resolve_project_credential(self, grant: object) -> str: ...
    def record_catalog_exchange(self, grant: object, *, http_status: int,
                                response_body: bytes) -> str: ...


class _Network(Protocol):
    def request(self, url: str, *, method: str, headers: Mapping[str, str],
                body: bytes | None = None, timeout_seconds: float,
                max_response_bytes: int) -> Any: ...


class _BoundedComposioNetwork:
    """Per-request hard deadline and response cap over the shared HTTPS primitive."""

    def request(self, url: str, *, method: str, headers: Mapping[str, str],
                body: bytes | None = None, timeout_seconds: float,
                max_response_bytes: int):
        deadline = min(MAX_DEADLINE_SECONDS, float(timeout_seconds))
        if not 0.1 <= deadline <= MAX_DEADLINE_SECONDS:
            raise ValueError("invalid Composio request deadline")
        network = BoundedNetwork(
            deadline_seconds=deadline,
            socket_timeout=min(10.0, deadline),
            max_response_bytes=min(MAX_RESPONSE_BYTES, max_response_bytes))
        return network.request(url, method=method, headers=headers, body=body)


def _query_string(query: Mapping[str, Any]) -> str:
    """Encode only the documented bracket-notation Composio query form."""
    if not isinstance(query, Mapping):
        raise ComposioCatalogTransportDenied("catalog query must be an object")
    allowed = {"toolkit_slugs", "toolkit_versions", "limit", "cursor"}
    if not set(query).issubset(allowed):
        raise ComposioCatalogTransportDenied("catalog query contains an unreviewed field")
    pairs: list[tuple[str, str]] = []
    if "toolkit_slugs" in query:
        if query["toolkit_slugs"] != ["whatsapp"]:
            raise ComposioCatalogTransportDenied("catalog toolkit selection is not the pinned WhatsApp toolkit")
        pairs.append(("toolkit_slugs", "whatsapp"))
    if query.get("toolkit_versions") != _VERSION_QUERY:
        raise ComposioCatalogTransportDenied("catalog toolkit version is not the exact manifest pin")
    pairs.append(("toolkit_versions[whatsapp]", COMPOSIO_TOOLKIT_VERSION))
    if "limit" in query:
        limit = query["limit"]
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ComposioCatalogTransportDenied("catalog page size is outside its reviewed bound")
        pairs.append(("limit", str(limit)))
    if "cursor" in query:
        cursor = query["cursor"]
        if (not isinstance(cursor, str) or not 1 <= len(cursor) <= MAX_CURSOR_BYTES
                or any(ord(char) < 0x20 for char in cursor)):
            raise ComposioCatalogTransportDenied("catalog pagination cursor is invalid")
        pairs.append(("cursor", cursor))
    if set(query) == {"toolkit_versions"}:
        return urlencode(pairs)
    if not ("toolkit_slugs" in query and "limit" in query):
        # The detail lookup has a deliberately smaller query.
        raise ComposioCatalogTransportDenied("catalog query is incomplete")
    return urlencode(pairs)


class RootComposioCatalogTransport:
    """Authenticated fixed Composio catalog reader for a root setup authority.

    The authorization handle can only be minted from a current root setup
    session and principal-selection receipt. This class is for root setup code;
    worker-facing code receives only the resulting discovery artifact.
    """

    def __init__(self, authority: _ComposioSetupAuthority, authorization: object,
                 *, network: _Network | None = None, monotonic=time.monotonic):
        if not callable(getattr(authority, "authorize_catalog_get", None)):
            raise ValueError("root Composio catalog setup authority is required")
        if not callable(getattr(authority, "resolve_project_credential", None)):
            raise ValueError("root project-bound credential resolver is required")
        if not callable(getattr(authority, "record_catalog_exchange", None)):
            raise ValueError("root immutable catalog source-receipt sink is required")
        authorization_handle = getattr(authorization, "authorization_handle", None)
        reference = getattr(authorization, "credential_reference_id", None)
        if not isinstance(authorization_handle, str) or not authorization_handle:
            raise ValueError("opaque root catalog authorization is required")
        if (getattr(authorization, "operation", None) != "composio.whatsapp.catalog.read"
                or getattr(authorization, "target", None)
                != f"composio:whatsapp:catalog:{COMPOSIO_TOOLKIT_VERSION}"
                or getattr(authorization, "toolkit_version", None) != COMPOSIO_TOOLKIT_VERSION
                or getattr(authorization, "request_policy_artifact_id", None) != COMPOSIO_CATALOG_POLICY_ID
                or getattr(authorization, "request_policy_sha256", None) != COMPOSIO_CATALOG_POLICY_SHA256
                or not isinstance(reference, str) or not reference):
            raise ValueError("root authorization does not match the selected catalog policy")
        if not callable(monotonic):
            raise ValueError("monotonic clock is required")
        self._authority = authority
        self._authorization_handle = authorization_handle
        self._network = network
        self._monotonic = monotonic
        self._started = monotonic()
        self._selected_credential_reference_id = reference
        self._listed_slugs: set[str] = set()
        self._pages = 0
        self._rows = 0
        self._expected_cursor: str | None = None
        self._seen_cursors: set[str] = set()
        self._catalog_complete = False
        self._seen_slugs: set[str] = set()

    def get_json(self, *, path: str, query: Mapping[str, Any],
                 credential_reference_id: str, usage: str,
                 max_response_bytes: int, timeout_seconds: float) -> ComposioCatalogResponse:
        """Perform exactly one authority-granted catalog GET and receipt it."""
        if (usage != "composio-trigger-discovery"
                or credential_reference_id != self._selected_credential_reference_id
                or type(max_response_bytes) is not int or not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES
                or isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
            raise ComposioCatalogTransportDenied("catalog request is outside the root setup bounds")
        query_string = _query_string(query)
        elapsed = self._monotonic() - self._started
        remaining = min(MAX_DEADLINE_SECONDS - elapsed, float(timeout_seconds))
        if remaining <= 0:
            raise ComposioCatalogTransportDenied("root Composio catalog authorization expired")

        slug: str | None = None
        cursor: str | None = None
        if path == COMPOSIO_COLLECTION_PATH:
            if (set(query) - {"toolkit_slugs", "toolkit_versions", "limit", "cursor"}
                    or "toolkit_slugs" not in query or "limit" not in query):
                raise ComposioCatalogTransportDenied("catalog collection request is malformed")
            if self._pages >= 10:
                raise ComposioCatalogTransportDenied("catalog page bound exceeded")
            supplied_cursor = query.get("cursor")
            if supplied_cursor != self._expected_cursor:
                raise ComposioCatalogTransportDenied("catalog cursor is not the next root-observed page")
            if self._catalog_complete:
                raise ComposioCatalogTransportDenied("catalog pagination is already complete")
            self._pages += 1
            grant = self._authority.authorize_catalog_get(self._authorization_handle)
        elif path.startswith(COMPOSIO_COLLECTION_PATH + "/"):
            slug = path.removeprefix(COMPOSIO_COLLECTION_PATH + "/")
            if not _SLUG.fullmatch(slug) or slug not in self._listed_slugs:
                raise ComposioCatalogTransportDenied("detail slug was not returned by this authorized catalog")
            if set(query) != {"toolkit_versions"}:
                raise ComposioCatalogTransportDenied("catalog detail request is malformed")
            if not self._catalog_complete:
                raise ComposioCatalogTransportDenied("catalog detail is unavailable until listing is complete")
            grant = self._authority.authorize_catalog_get(
                self._authorization_handle, trigger_slug=slug)
        else:
            raise ComposioCatalogTransportDenied("catalog path is outside the fixed Composio endpoint")

        grant_path = getattr(grant, "path", None)
        grant_origin = getattr(grant, "origin", None)
        grant_method = getattr(grant, "method", None)
        grant_version = getattr(grant, "toolkit_version", None)
        grant_policy = getattr(grant, "request_policy_sha256", None)
        grant_policy_id = getattr(grant, "request_policy_artifact_id", None)
        grant_deadline = getattr(grant, "expires_monotonic", None)
        if (grant_path != path or grant_origin != COMPOSIO_ORIGIN or grant_method != "GET"
                or grant_version != COMPOSIO_TOOLKIT_VERSION
                or grant_policy_id != COMPOSIO_CATALOG_POLICY_ID
                or grant_policy != COMPOSIO_CATALOG_POLICY_SHA256
                or isinstance(grant_deadline, bool) or not isinstance(grant_deadline, (int, float))
                or not math.isfinite(grant_deadline) or grant_deadline <= self._monotonic()):
            raise ComposioCatalogTransportDenied("root catalog grant does not match the fixed reader policy")
        if getattr(grant, "query", None) != dict(query):
            raise ComposioCatalogTransportDenied("request query does not match the root one-use grant")
        url = f"{COMPOSIO_ORIGIN}{path}?{query_string}"
        credential = self._authority.resolve_project_credential(grant)
        if not isinstance(credential, str) or not credential or any(c in credential for c in "\r\n\x00"):
            raise ComposioCatalogTransportDenied("root project credential could not be resolved")
        request_budget = min(remaining, grant_deadline - self._monotonic())
        if request_budget < 0.1:
            raise ComposioCatalogTransportDenied("root catalog request expired before dispatch")
        try:
            network = self._network or _BoundedComposioNetwork()
            response = network.request(
                url, method="GET", headers={"x-api-key": credential, "accept": "application/json"},
                body=None, timeout_seconds=request_budget, max_response_bytes=max_response_bytes)
        except Exception:
            raise ComposioCatalogTransportDenied("authenticated Composio catalog request failed") from None
        finally:
            # Drop the local reference immediately after the bounded request.
            del credential
        status, body = getattr(response, "status", None), getattr(response, "body", None)
        if type(status) is not int or not isinstance(body, bytes) or len(body) > max_response_bytes:
            raise ComposioCatalogTransportDenied("Composio catalog response exceeded its bound")
        try:
            exchange_handle = self._authority.record_catalog_exchange(
                grant, http_status=status, response_body=body)
        except Exception:
            raise ComposioCatalogTransportDenied("root could not retain catalog source receipts") from None
        # Receipt every HTTP response, including 401/4xx/5xx, before exposing
        # any body. A failed status is never parsed as an authenticated schema.
        if status != 200:
            raise ComposioCatalogTransportDenied("Composio catalog did not return HTTP 200")
        try:
            document = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise ComposioCatalogTransportDenied("Composio catalog returned malformed JSON") from None
        if not isinstance(document, dict):
            raise ComposioCatalogTransportDenied("Composio catalog response is not a JSON object")
        if path == COMPOSIO_COLLECTION_PATH:
            items = document.get("items")
            if not isinstance(items, list) or len(items) > 50:
                raise ComposioCatalogTransportDenied("Composio catalog page is malformed")
            self._rows += len(items)
            if self._rows > 500:
                raise ComposioCatalogTransportDenied("Composio catalog row bound exceeded")
            next_cursor = document.get("next_cursor")
            if next_cursor in (None, ""):
                self._expected_cursor = None
                self._catalog_complete = True
            elif (not isinstance(next_cursor, str) or len(next_cursor) > MAX_CURSOR_BYTES
                  or any(ord(c) < 0x20 for c in next_cursor) or next_cursor in self._seen_cursors
                  or self._pages >= 10):
                raise ComposioCatalogTransportDenied("Composio catalog cursor is invalid or exceeds bounds")
            else:
                self._seen_cursors.add(next_cursor)
                self._expected_cursor = next_cursor
            for item in items:
                toolkit = item.get("toolkit") if isinstance(item, Mapping) else None
                slug_value = item.get("slug") if isinstance(item, Mapping) else None
                if (isinstance(toolkit, Mapping) and toolkit.get("slug") == "whatsapp"
                        and isinstance(slug_value, str) and _SLUG.fullmatch(slug_value)
                        and item.get("version") == COMPOSIO_TOOLKIT_VERSION):
                    if slug_value in self._seen_slugs:
                        raise ComposioCatalogTransportDenied("Composio catalog contains a duplicate trigger slug")
                    self._seen_slugs.add(slug_value)
                    self._listed_slugs.add(slug_value)
        if not isinstance(exchange_handle, str) or not exchange_handle:
            raise ComposioCatalogTransportDenied("root source receipt handles are invalid")
        return ComposioCatalogResponse(document, exchange_handle, status)


class RootComposioCatalogReader:
    """Setup call point that joins a selected root session to fixed reads.

    This facade intentionally exposes only list and inspect operations. It
    cannot create a Composio trigger/account or activate inbound delivery.
    """

    def __init__(self, authority: Any, authorization: object,
                 *, network: _Network | None = None, monotonic=time.monotonic):
        from .composio_trigger_setup import ComposioWhatsAppTriggerDiscovery

        self._transport = RootComposioCatalogTransport(
            authority, authorization, network=network, monotonic=monotonic)
        self._discovery = ComposioWhatsAppTriggerDiscovery(
            self._transport,
            credential_reference_id=getattr(authorization, "credential_reference_id"),
            toolkit_version=COMPOSIO_TOOLKIT_VERSION,
            monotonic=monotonic)

    @classmethod
    def from_root_setup(cls, authority: Any, session_handle: object, *,
                        project_id: str, project_api_key_reference: str,
                        principal_selection_receipt_handle: str,
                        network: _Network | None = None,
                        monotonic=time.monotonic) -> "RootComposioCatalogReader":
        authorize = getattr(authority, "authorize_whatsapp_catalog_read", None)
        if not callable(authorize):
            raise ComposioCatalogTransportDenied("root Composio setup selection authority is unavailable")
        try:
            authorization = authorize(
                session_handle, project_id=project_id,
                project_api_key_reference=project_api_key_reference,
                principal_selection_receipt_handle=principal_selection_receipt_handle,
                toolkit_version=COMPOSIO_TOOLKIT_VERSION)
        except Exception:
            raise ComposioCatalogTransportDenied(
                "current root setup session cannot authorize the Composio catalog read") from None
        return cls(authority, authorization, network=network, monotonic=monotonic)

    def list_types(self):
        """Return source-discovered types; these are not configured resources."""
        return self._discovery.discover()

    def inspect_returned_type(self, selected_slug: str):
        """Re-list and re-fetch only a slug returned by the current catalog."""
        return self._discovery.select(selected_slug)
