"""Bounded, version-pinned Composio trigger discovery for selected resources.

This module discovers a trigger schema during setup. It does not activate an
account, create a trigger, receive an event, or confer runtime authority. The
HTTP port is root-owned and must resolve the opaque credential reference from
the protected vault, pin the official Composio origin, verify TLS, disallow
redirects, and enforce response/time limits.

Composio API contract references (reviewed 2026-10-09):
* https://docs.composio.dev/reference/api-reference/triggers/getTriggersTypes
* https://docs.composio.dev/reference/api-reference/triggers/getTriggersTypesBySlug
* https://docs.composio.dev/docs/setting-up-triggers/subscribing-to-events
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import time
from collections.abc import Mapping
from typing import Any, Protocol

from .composio_catalog_transport import (
    COMPOSIO_CATALOG_POLICY_ID, COMPOSIO_CATALOG_POLICY_SHA256,
)


class ComposioTriggerSetupUnavailable(RuntimeError):
    """Authenticated, version-pinned trigger discovery is not available."""


_API_ROOT = "/api/v3.1/triggers_types"
_VERSION = re.compile(r"[0-9]{8}_[0-9]{2}\Z")
_SLUG = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
_MAX_PAGES = 10
_MAX_ROWS = 500
_MAX_PAGE_SIZE = 50
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_SCHEMA_BYTES = 256 * 1024
_MAX_DEADLINE_SECONDS = 30.0


class RootComposioGet(Protocol):
    """Fixed-origin root broker GET port; never accepts a URL or raw secret."""

    def get_json(self, *, path: str, query: Mapping[str, Any],
                 credential_reference_id: str, usage: str,
                 max_response_bytes: int, timeout_seconds: float) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class ComposioTriggerType:
    slug: str
    name: str
    description: str
    trigger_type: str
    toolkit_slug: str
    toolkit_version: str
    config_schema: Mapping[str, Any]
    payload_schema: Mapping[str, Any]
    requires_webhook_endpoint_setup: bool | None
    schema_sha256: str


@dataclass(frozen=True, slots=True)
class ComposioTriggerCatalogReceipt:
    """Evidence of a live authenticated schema discovery, not readiness."""

    toolkit_version: str
    selected_slug: str
    schema_sha256: str
    catalog_sha256: str
    source_exchange_receipt_handles: tuple[str, ...] = ()
    request_policy_artifact_id: str = COMPOSIO_CATALOG_POLICY_ID
    request_policy_sha256: str = COMPOSIO_CATALOG_POLICY_SHA256
    source: str = "composio-v3.1-authenticated-trigger-catalog"
    status: str = "discovered-not-configured"


def _json_bytes(value: object, *, maximum: int) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise ComposioTriggerSetupUnavailable("Composio schema is not bounded finite JSON") from None
    if len(encoded) > maximum:
        raise ComposioTriggerSetupUnavailable("Composio schema exceeds the setup response bound")
    return encoded


def _sha(value: object, *, maximum: int = _MAX_SCHEMA_BYTES) -> str:
    return hashlib.sha256(_json_bytes(value, maximum=maximum)).hexdigest()


def _required_text(value: object, pattern: re.Pattern[str], what: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ComposioTriggerSetupUnavailable(f"Composio {what} is invalid")
    return value


def _parse_trigger(row: object, *, toolkit_version: str) -> ComposioTriggerType:
    if not isinstance(row, Mapping):
        raise ComposioTriggerSetupUnavailable("Composio returned a malformed trigger schema")
    slug = _required_text(row.get("slug"), _SLUG, "trigger slug")
    toolkit = row.get("toolkit")
    if not isinstance(toolkit, Mapping) or toolkit.get("slug") != "whatsapp":
        raise ComposioTriggerSetupUnavailable("Composio trigger is not from the WhatsApp toolkit")
    version = _required_text(row.get("version"), _VERSION, "toolkit version")
    if version != toolkit_version:
        raise ComposioTriggerSetupUnavailable("Composio returned a trigger for a different toolkit version")
    name, description = row.get("name"), row.get("description")
    if (not isinstance(name, str) or not name or len(name) > 512
            or not isinstance(description, str) or len(description) > 4096):
        raise ComposioTriggerSetupUnavailable("Composio trigger metadata is invalid")
    trigger_type = row.get("type")
    if trigger_type not in {"webhook", "poll"}:
        raise ComposioTriggerSetupUnavailable("Composio trigger transport type is unsupported")
    config, payload = row.get("config"), row.get("payload")
    if not isinstance(config, Mapping) or not isinstance(payload, Mapping):
        raise ComposioTriggerSetupUnavailable("Composio trigger configuration or payload schema is missing")
    instructions = row.get("instructions")
    if instructions is not None and (not isinstance(instructions, str) or len(instructions) > 8192):
        raise ComposioTriggerSetupUnavailable("Composio trigger instructions are invalid")
    schema_projection = {
        "slug": slug, "name": name, "description": description,
        "instructions": instructions,
        "type": trigger_type, "toolkit": {"slug": "whatsapp", "version": version},
        "config": config, "payload": payload,
        "requires_webhook_endpoint_setup": row.get("requires_webhook_endpoint_setup"),
    }
    digest = _sha(schema_projection)
    requires_webhook = row.get("requires_webhook_endpoint_setup")
    if requires_webhook is not None and type(requires_webhook) is not bool:
        raise ComposioTriggerSetupUnavailable("Composio webhook requirement field is invalid")
    return ComposioTriggerType(slug, name, description, trigger_type, "whatsapp", version,
                               dict(config), dict(payload), requires_webhook, digest)


class ComposioWhatsAppTriggerDiscovery:
    """Discover and re-fetch one user-selected trigger from the exact manifest pin."""

    def __init__(self, broker: RootComposioGet, *, credential_reference_id: str,
                 toolkit_version: str, monotonic: Any = time.monotonic):
        if not callable(getattr(broker, "get_json", None)):
            raise ValueError("root fixed-origin Composio GET broker is required")
        if not isinstance(credential_reference_id, str) or not _REF.fullmatch(credential_reference_id):
            raise ValueError("protected Composio project credential reference is required")
        if not isinstance(toolkit_version, str) or not _VERSION.fullmatch(toolkit_version):
            raise ValueError("exact pinned Composio WhatsApp toolkit version is required")
        if not callable(monotonic):
            raise ValueError("monotonic deadline source is required")
        self._broker = broker
        self._credential_reference_id = credential_reference_id
        self._toolkit_version = toolkit_version
        self._monotonic = monotonic
        self._source_receipts: list[str] = []

    def _get_json(self, *, path: str, query: Mapping[str, Any], deadline: float) -> Mapping[str, Any]:
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise ComposioTriggerSetupUnavailable("Composio trigger discovery exceeded its 30-second deadline")
        try:
            result = self._broker.get_json(
                path=path, query=query,
                credential_reference_id=self._credential_reference_id,
                usage="composio-trigger-discovery",
                max_response_bytes=_MAX_RESPONSE_BYTES,
                timeout_seconds=min(_MAX_DEADLINE_SECONDS, remaining))
            exchange_handle = getattr(result, "exchange_receipt_handle", None)
            if exchange_handle is not None:
                if (not isinstance(exchange_handle, str) or not exchange_handle
                        or exchange_handle in self._source_receipts):
                    raise ComposioTriggerSetupUnavailable(
                        "root Composio exchange receipt handle is invalid or replayed")
                self._source_receipts.append(exchange_handle)
            return result
        except ComposioTriggerSetupUnavailable:
            raise
        except Exception:
            raise ComposioTriggerSetupUnavailable(
                "authenticated Composio trigger discovery failed; account remains unconfigured") from None

    def discover(self) -> tuple[ComposioTriggerType, ...]:
        """Read all pages at the exact toolkit version, without guessing a slug."""
        return self._discover(deadline=self._monotonic() + _MAX_DEADLINE_SECONDS)

    def _discover(self, *, deadline: float) -> tuple[ComposioTriggerType, ...]:
        cursor: str | None = None
        rows: list[ComposioTriggerType] = []
        seen_cursors: set[str] = set()
        for _ in range(_MAX_PAGES):
            query: dict[str, Any] = {
                "toolkit_slugs": ["whatsapp"],
                "toolkit_versions": {"whatsapp": self._toolkit_version},
                "limit": _MAX_PAGE_SIZE,
            }
            if cursor is not None:
                query["cursor"] = cursor
            page = self._get_json(path=_API_ROOT, query=query, deadline=deadline)
            _json_bytes(page, maximum=_MAX_RESPONSE_BYTES)
            items = page.get("items") if isinstance(page, Mapping) else None
            if not isinstance(items, list) or len(items) > _MAX_PAGE_SIZE:
                raise ComposioTriggerSetupUnavailable("Composio trigger catalog page is malformed")
            for item in items:
                parsed = _parse_trigger(item, toolkit_version=self._toolkit_version)
                rows.append(parsed)
                if len(rows) > _MAX_ROWS:
                    raise ComposioTriggerSetupUnavailable("Composio trigger catalog exceeds its bound")
            next_cursor = page.get("next_cursor")
            if next_cursor is None or next_cursor == "":
                break
            if (not isinstance(next_cursor, str) or len(next_cursor) > 1024
                    or next_cursor in seen_cursors):
                raise ComposioTriggerSetupUnavailable("Composio trigger pagination cursor is invalid")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise ComposioTriggerSetupUnavailable("Composio trigger catalog exceeded the page bound")
        if len({item.slug for item in rows}) != len(rows):
            raise ComposioTriggerSetupUnavailable("Composio trigger catalog contains duplicate slugs")
        # This call only returns discovered catalog rows; webhook selection is
        # deliberately not inferred from a manifest display label.
        return tuple(rows)

    def select(self, selected_slug: str) -> tuple[ComposioTriggerType, ComposioTriggerCatalogReceipt]:
        """Confirm a displayed catalog choice against a fresh exact-version GET."""
        selected_slug = _required_text(selected_slug, _SLUG, "selected trigger slug")
        self._source_receipts = []
        deadline = self._monotonic() + _MAX_DEADLINE_SECONDS
        catalog = self._discover(deadline=deadline)
        selected = next((item for item in catalog if item.slug == selected_slug), None)
        if selected is None:
            raise ComposioTriggerSetupUnavailable("selected trigger is not in the pinned WhatsApp catalog")
        raw = self._get_json(
            path=f"{_API_ROOT}/{selected_slug}",
            query={"toolkit_versions": {"whatsapp": self._toolkit_version}},
            deadline=deadline)
        _json_bytes(raw, maximum=_MAX_RESPONSE_BYTES)
        confirmed = _parse_trigger(raw, toolkit_version=self._toolkit_version)
        if confirmed.slug != selected.slug or confirmed.schema_sha256 != selected.schema_sha256:
            raise ComposioTriggerSetupUnavailable("Composio trigger schema changed during setup; rediscover")
        exchange_handles = tuple(self._source_receipts)
        catalog_digest = _sha({
            "rows": [(item.slug, item.schema_sha256) for item in catalog],
            "source_exchange_receipt_handles": exchange_handles,
        }, maximum=_MAX_RESPONSE_BYTES)
        receipt = ComposioTriggerCatalogReceipt(
            toolkit_version=self._toolkit_version, selected_slug=selected.slug,
            schema_sha256=selected.schema_sha256, catalog_sha256=catalog_digest,
            source_exchange_receipt_handles=exchange_handles)
        return confirmed, receipt
