"""Fixed owner-ingress Google Calendar read adapter for the root Inspector.

This path is separate from model-origin NativeMCPDispatcher calls. It accepts
only the one current Access owner, a root-registered connection/calendar, and
the literal Google Calendar ``list_events`` HTTPS method. Registration stores
opaque credential references only; bearer material stays inside this module.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import math
import os
import re
import secrets
import socket
import ssl
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..authority.enrollment import RootCredentialVault

UTC = timezone.utc
GOOGLE_CALENDAR_ENDPOINT = "https://calendarmcp.googleapis.com/mcp/v1"
GOOGLE_CALENDAR_SERVICE = "google-calendar"
GOOGLE_LIST_EVENTS_TOOL = "list_events"
CALENDAR_INVOCATION_CLASS = "owner-ui-calendar-read"
CALENDAR_REGISTRATION_PATH = Path("/var/lib/hermes-installer/core-runtime/calendar-connections.json")
MAX_REGISTRATIONS = 16
MAX_CALENDARS = 64
MAX_EVENTS = 100
MAX_WINDOW = timedelta(days=31)
MAX_JSON_BYTES = 1_048_576
MAX_RESULT_BYTES = 262_144
MAX_CALL_SECONDS = 5.0
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SEAL = object()
_REG_FIELDS = frozenset({
    "schema", "owner_subject_sha256", "connection_id", "generation_sha256",
    "connection_generation_sha256", "source_binding_sha256",
    "provider_principal_id", "credential_consumer_uid",
    "credential_ref", "credential_scope", "endpoint", "tool_name",
    "input_schema_sha256", "output_schema_sha256", "invocation_class",
    "calendars", "selected_calendar_ref", "provider_identity_label",
    "owner_ui_consent", "native_binding_id",
    "mcp_generation",
})
_CALENDAR_FIELDS = frozenset({"calendar_ref", "calendar_id", "label"})
_CONSENT_FIELDS = frozenset({"schema", "owner_subject_sha256", "action", "confirmed_at",
                             "core_generation", "connection_generation_sha256",
                             "source_binding_sha256", "canonical_arguments_sha256"})


class OwnerCalendarUnavailable(RuntimeError):
    """Calendar read is not currently available; text is deliberately generic."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8", "strict")


def _json(raw: bytes, *, maximum: int = MAX_JSON_BYTES) -> Any:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= maximum:
        raise OwnerCalendarUnavailable("Calendar source response exceeded its bound")
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs,
                          parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except Exception:
        raise OwnerCalendarUnavailable("Calendar source response was malformed") from None


def _valid_calendar_id(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 256
            and all(0x21 <= ord(char) <= 0x7e for char in value)
            and "\r" not in value and "\n" not in value)


def _validate_registration(record: Any) -> dict[str, Any]:
    if not isinstance(record, Mapping) or set(record) != _REG_FIELDS:
        raise OwnerCalendarUnavailable("Calendar connection registration is unavailable")
    row = dict(record)
    if (type(row["schema"]) is not int or row["schema"] != 1
            or not _HASH.fullmatch(str(row["owner_subject_sha256"]))
            or not _ID.fullmatch(row["connection_id"])
            or not _HASH.fullmatch(str(row["generation_sha256"]))
            or not _HASH.fullmatch(str(row["connection_generation_sha256"]))
            or not _HASH.fullmatch(str(row["source_binding_sha256"]))
            or not _ID.fullmatch(row["provider_principal_id"])
            or type(row["credential_consumer_uid"]) is not int
            or row["credential_consumer_uid"] <= 0
            or not isinstance(row["credential_ref"], str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", row["credential_ref"])
            or row["credential_scope"] != "mcp:google-calendar:read"
            or row["endpoint"] != GOOGLE_CALENDAR_ENDPOINT
            or row["tool_name"] != GOOGLE_LIST_EVENTS_TOOL
            or not _HASH.fullmatch(str(row["input_schema_sha256"]))
            or not _HASH.fullmatch(str(row["output_schema_sha256"]))
            or row["invocation_class"] != CALENDAR_INVOCATION_CLASS
            or not _ID.fullmatch(row["native_binding_id"])
            or not _ID.fullmatch(row["mcp_generation"])
            or not isinstance(row["calendars"], list)
            or not 1 <= len(row["calendars"]) <= MAX_CALENDARS
            or not isinstance(row["selected_calendar_ref"], str)
            or not _OPAQUE.fullmatch(row["selected_calendar_ref"])):
        raise OwnerCalendarUnavailable("Calendar connection registration is unavailable")
    seen_refs: set[str] = set()
    seen_ids: set[str] = set()
    clean = []
    for value in row["calendars"]:
        if (not isinstance(value, Mapping) or set(value) != _CALENDAR_FIELDS
                or not isinstance(value["calendar_ref"], str)
                or not _OPAQUE.fullmatch(value["calendar_ref"])
                or not _valid_calendar_id(value["calendar_id"])
                or not isinstance(value["label"], str) or not 1 <= len(value["label"]) <= 120
                or any(ord(char) < 0x20 for char in value["label"])
                or value["calendar_ref"] in seen_refs or value["calendar_id"] in seen_ids):
            raise OwnerCalendarUnavailable("Calendar selection registration is malformed")
        seen_refs.add(value["calendar_ref"])
        seen_ids.add(value["calendar_id"])
        clean.append(dict(value))
    if row["selected_calendar_ref"] not in seen_refs:
        raise OwnerCalendarUnavailable("Calendar selection is unavailable")
    label = row["provider_identity_label"]
    if label is not None and (not isinstance(label, str) or len(label) > 120
                              or any(ord(char) < 0x20 for char in label)):
        raise OwnerCalendarUnavailable("Calendar identity label is malformed")
    consent = row["owner_ui_consent"]
    if (not isinstance(consent, Mapping) or set(consent) != _CONSENT_FIELDS
            or type(consent["schema"]) is not int or consent["schema"] != 1
            or consent["owner_subject_sha256"] != row["owner_subject_sha256"]
            or consent["action"] != "read-only-calendar-dashboard"
            or not isinstance(consent["confirmed_at"], str)
            or not _HASH.fullmatch(str(consent["core_generation"]))
            or consent["connection_generation_sha256"] != row["connection_generation_sha256"]
            or consent["source_binding_sha256"] != row["source_binding_sha256"]
            or not _HASH.fullmatch(str(consent["canonical_arguments_sha256"]))):
        raise OwnerCalendarUnavailable("Calendar owner consent record is unavailable")
    row["calendars"] = clean
    return row


def _open_registration_dir() -> int:
    if os.geteuid() != 0 or CALENDAR_REGISTRATION_PATH.parent != Path("/var/lib/hermes-installer/core-runtime"):
        raise OwnerCalendarUnavailable("Root Calendar registration custody is unavailable")
    from .core_native_observer import _open_root_master_plan_store
    return _open_root_master_plan_store()


def load_calendar_registrations() -> tuple[dict[str, Any], ...]:
    directory_fd = _open_registration_dir()
    try:
        try:
            fd = os.open(CALENDAR_REGISTRATION_PATH.name,
                         os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        except FileNotFoundError:
            return ()
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 1 <= before.st_size <= 128 * 1024):
                raise OwnerCalendarUnavailable("Root Calendar registration custody changed")
            raw = os.read(fd, 128 * 1024 + 1)
            after = os.fstat(fd)
            named = os.stat(CALENDAR_REGISTRATION_PATH.name, dir_fd=directory_fd,
                            follow_symlinks=False)
            if (len(raw) != before.st_size or len(raw) > 128 * 1024
                    or (before.st_dev, before.st_ino, before.st_mtime_ns)
                        != (after.st_dev, after.st_ino, after.st_mtime_ns)
                    or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)):
                raise OwnerCalendarUnavailable("Root Calendar registration changed during read")
        finally:
            os.close(fd)
        document = _json(raw, maximum=128 * 1024)
        if (not isinstance(document, Mapping) or set(document) != {"schema", "connections"}
                or type(document["schema"]) is not int or document["schema"] != 1
                or not isinstance(document["connections"], list)
                or len(document["connections"]) > MAX_REGISTRATIONS):
            raise OwnerCalendarUnavailable("Root Calendar registration is malformed")
        rows = tuple(_validate_registration(item) for item in document["connections"])
        if len({row["connection_id"] for row in rows}) != len(rows):
            raise OwnerCalendarUnavailable("Root Calendar connection registration is duplicated")
        return rows
    finally:
        os.close(directory_fd)


def write_calendar_registrations(rows: list[Mapping[str, Any]]) -> None:
    """Root-only atomic registration writer for an already reviewed account choice."""
    if os.geteuid() != 0 or not isinstance(rows, list) or len(rows) > MAX_REGISTRATIONS:
        raise OwnerCalendarUnavailable("Root Calendar registration writer is unavailable")
    checked = [_validate_registration(row) for row in rows]
    if len({row["connection_id"] for row in checked}) != len(checked):
        raise OwnerCalendarUnavailable("Calendar connection registration is duplicated")
    document = _canonical({"schema": 1, "connections": checked})
    if len(document) > 128 * 1024:
        raise OwnerCalendarUnavailable("Calendar registration exceeds its bound")
    directory_fd = _open_registration_dir()
    temporary = ".calendar-connections-" + secrets.token_hex(12) + ".tmp"
    try:
        import fcntl
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(document):
                offset += os.write(fd, document[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, CALENDAR_REGISTRATION_PATH.name,
                   src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
        # Read-back joins exact bytes to the reviewed atomic write.
        fd = os.open(CALENDAR_REGISTRATION_PATH.name,
                     os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        try:
            verify = os.read(fd, 128 * 1024 + 1)
        finally:
            os.close(fd)
        if verify != document:
            raise OwnerCalendarUnavailable("Calendar registration read-back changed")
    except OwnerCalendarUnavailable:
        raise
    except Exception:
        raise OwnerCalendarUnavailable("Root Calendar registration update failed") from None
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


@dataclass(frozen=True, slots=True)
class RootOwnerCalendarReadInvocation:
    schema: int
    invocation_class: str
    request_nonce: str
    owner_subject_sha256: str
    connection_id: str
    connection_generation_sha256: str
    source_binding_sha256: str
    calendar_ref: str
    canonical_arguments_sha256: str
    provider_principal_id: str
    credential_consumer_uid: int
    credential_scope: str
    admitted_jwt_expiry: int
    issued_monotonic: float
    expires_monotonic: float
    ingress_nonce: str
    ingress_proof_sha256: str
    _seal: object = field(repr=False, compare=False)

    def is_current(self, *, registration: Mapping[str, Any], now: float,
                   ingress_expiry: float) -> bool:
        try:
            return bool(type(self) is RootOwnerCalendarReadInvocation and self._seal is _SEAL
                and self.schema == 1 and self.invocation_class == CALENDAR_INVOCATION_CLASS
                and _HASH.fullmatch(self.request_nonce)
                and self.owner_subject_sha256 == registration["owner_subject_sha256"]
                and self.connection_id == registration["connection_id"]
                and self.connection_generation_sha256 == registration["connection_generation_sha256"]
                and self.source_binding_sha256 == registration["source_binding_sha256"]
                and registration["owner_ui_consent"]["owner_subject_sha256"] == self.owner_subject_sha256
                and registration["owner_ui_consent"]["canonical_arguments_sha256"]
                    == hashlib.sha256(_canonical({"calendarId": next(
                        item["calendar_id"] for item in registration["calendars"]
                        if item["calendar_ref"] == self.calendar_ref)})).hexdigest()
                and self.provider_principal_id == registration["provider_principal_id"]
                and self.credential_consumer_uid == registration["credential_consumer_uid"]
                and self.credential_scope == registration["credential_scope"]
                and self.calendar_ref in {item["calendar_ref"] for item in registration["calendars"]}
                and self.ingress_nonce and _HASH.fullmatch(self.ingress_nonce)
                and _HASH.fullmatch(self.ingress_proof_sha256)
                and math.isfinite(now) and math.isfinite(self.issued_monotonic)
                and math.isfinite(self.expires_monotonic)
                and self.issued_monotonic <= now < self.expires_monotonic
                and self.expires_monotonic <= min(ingress_expiry, self.issued_monotonic + MAX_CALL_SECONDS))
        except Exception:
            return False


@dataclass(frozen=True, slots=True)
class RootCalendarReadResult:
    schema: int
    owner_subject_sha256: str
    connection_id: str
    connection_generation_sha256: str
    source_binding_sha256: str
    opaque_calendar_ref: str
    tool_name: str
    canonical_arguments_sha256: str
    actual_response_sha256: str
    observed_at: str
    projection: Mapping[str, Any]
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def is_root_verified(self, invocation: RootOwnerCalendarReadInvocation, *, now: float) -> bool:
        try:
            return bool(type(self) is RootCalendarReadResult and self._seal is _SEAL
                and type(invocation) is RootOwnerCalendarReadInvocation
                and invocation._seal is _SEAL and self.schema == 1
                and self.owner_subject_sha256 == invocation.owner_subject_sha256
                and self.connection_id == invocation.connection_id
                and self.connection_generation_sha256 == invocation.connection_generation_sha256
                and self.source_binding_sha256 == invocation.source_binding_sha256
                and self.opaque_calendar_ref == invocation.calendar_ref
                and self.tool_name == GOOGLE_LIST_EVENTS_TOOL
                and self.canonical_arguments_sha256 == invocation.canonical_arguments_sha256
                and _HASH.fullmatch(self.actual_response_sha256)
                and type(self.projection) is dict
                and math.isfinite(now) and self.issued_monotonic <= now < self.expires_monotonic
                and self.expires_monotonic <= invocation.expires_monotonic)
        except Exception:
            return False


def _bounds(start: str, end: str, timezone_name: str, page_size: int) -> tuple[datetime, datetime]:
    if (not isinstance(start, str) or not isinstance(end, str)
            or type(page_size) is not int or not 1 <= page_size <= MAX_EVENTS
            or not isinstance(timezone_name, str) or len(timezone_name) > 128):
        raise OwnerCalendarUnavailable("Calendar read window is invalid")
    try:
        start_at = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_at = datetime.fromisoformat(end.replace("Z", "+00:00"))
        ZoneInfo(timezone_name)
    except (ValueError, ZoneInfoNotFoundError):
        raise OwnerCalendarUnavailable("Calendar timezone or window is invalid") from None
    if (start_at.tzinfo is None or end_at.tzinfo is None or end_at <= start_at
            or end_at - start_at > MAX_WINDOW):
        raise OwnerCalendarUnavailable("Calendar read window exceeds 31 days")
    return start_at, end_at


def _public_addresses(host: str, port: int) -> list[tuple[int, int, int, tuple[Any, ...]]]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not records or len(records) > 8:
            raise ValueError
        import ipaddress
        result = []
        for family, socktype, proto, _canon, sockaddr in records:
            address = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
            if not address.is_global:
                raise ValueError
            result.append((family, socktype, proto, sockaddr))
        return result
    except Exception:
        raise OwnerCalendarUnavailable("Google Calendar endpoint resolution is unavailable") from None


def _post(payload: Mapping[str, Any], *, bearer: str, session_id: str | None,
          deadline: float, notification: bool = False) -> tuple[Mapping[str, Any] | None, str | None, int]:
    if time.monotonic() >= deadline or not bearer or any(c in bearer for c in "\r\n\x00"):
        raise OwnerCalendarUnavailable("Calendar credential or read deadline is unavailable")
    body = _canonical(dict(payload))
    if len(body) > MAX_JSON_BYTES:
        raise OwnerCalendarUnavailable("Calendar request exceeded its bound")
    parsed = urlsplit(GOOGLE_CALENDAR_ENDPOINT)
    address = _public_addresses(parsed.hostname or "", parsed.port or 443)[0]
    sock = None
    tls = None
    try:
        timeout = max(0.05, min(3.0, deadline - time.monotonic()))
        sock = socket.socket(address[0], address[1], address[2])
        sock.settimeout(timeout)
        sock.connect(address[3])
        tls = ssl.create_default_context().wrap_socket(sock, server_hostname=parsed.hostname)
        tls.settimeout(timeout)
        request_id = payload.get("id")
        headers = [
            f"POST {parsed.path} HTTP/1.1", f"Host: {parsed.netloc}",
            "Accept: application/json, text/event-stream", "Content-Type: application/json",
            f"Authorization: Bearer {bearer}", "Connection: close",
            f"Content-Length: {len(body)}",
        ]
        if session_id is not None:
            headers.append("Mcp-Session-Id: " + session_id)
        tls.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body)
        response = http.client.HTTPResponse(tls, method="POST")
        response.begin()
        status = int(response.status)
        if status in {301, 302, 303, 307, 308}:
            raise OwnerCalendarUnavailable("Google Calendar redirect was denied")
        if notification:
            if status not in {200, 202, 204}:
                raise OwnerCalendarUnavailable("Calendar session initialization was denied")
            return None, session_id, status
        if status != 200:
            # Do not disclose provider body or authorization detail.
            raise OwnerCalendarUnavailable("Google Calendar read was denied or unavailable")
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type not in {"application/json", "text/event-stream"}:
            raise OwnerCalendarUnavailable("Google Calendar returned an unsupported response format")
        raw = response.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            raise OwnerCalendarUnavailable("Google Calendar response exceeded its bound")
        if content_type == "application/json":
            result = _json(raw)
        else:
            from ..mcp.transports import StreamableHTTPTransport, TransportError
            try:
                result = StreamableHTTPTransport._decode_sse(raw, request_id)
            except TransportError:
                raise OwnerCalendarUnavailable("Google Calendar event stream was invalid") from None
        if (not isinstance(result, Mapping) or result.get("jsonrpc") != "2.0"
                or result.get("id") != request_id or not isinstance(result.get("result"), Mapping)
                or "error" in result):
            raise OwnerCalendarUnavailable("Google Calendar protocol response was invalid")
        received_session = response.getheader("Mcp-Session-Id")
        if received_session is not None and (len(received_session) > 256
                or not re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", received_session)):
            raise OwnerCalendarUnavailable("Google Calendar session identifier was invalid")
        return result["result"], received_session or session_id, status
    except OwnerCalendarUnavailable:
        raise
    except Exception:
        raise OwnerCalendarUnavailable("Google Calendar transport failed") from None
    finally:
        if tls is not None:
            try:
                tls.close()
            except OSError:
                pass
        elif sock is not None:
            sock.close()


def _result_value(tool_result: Mapping[str, Any]) -> dict[str, Any]:
    value = tool_result.get("structuredContent")
    if isinstance(value, Mapping):
        return dict(value)
    content = tool_result.get("content")
    if isinstance(content, list) and len(content) == 1 and isinstance(content[0], Mapping):
        text = content[0].get("text")
        if isinstance(text, str) and len(text.encode("utf-8")) <= MAX_RESULT_BYTES:
            decoded = _json(text.encode("utf-8"), maximum=MAX_RESULT_BYTES)
            if isinstance(decoded, Mapping):
                return dict(decoded)
    raise OwnerCalendarUnavailable("Google Calendar returned no structured event page")


def _discover_schema(session_id: str | None, token: str, deadline: float,
                     registration: Mapping[str, Any]) -> str | None:
    request_id = secrets.token_hex(12)
    result, session_id, _ = _post({"jsonrpc": "2.0", "id": request_id, "method": "tools/list",
        "params": {}}, bearer=token, session_id=session_id, deadline=deadline)
    tools = result.get("tools") if isinstance(result, Mapping) else None
    matches = [row for row in tools if isinstance(row, Mapping)
               and row.get("name") == GOOGLE_LIST_EVENTS_TOOL] if isinstance(tools, list) else []
    if len(matches) != 1 or not isinstance(matches[0].get("inputSchema"), Mapping):
        raise OwnerCalendarUnavailable("Google Calendar list_events schema is unavailable")
    input_schema = dict(matches[0]["inputSchema"])
    if hashlib.sha256(_canonical(input_schema)).hexdigest() != registration["input_schema_sha256"]:
        raise OwnerCalendarUnavailable("Google Calendar list_events schema changed")
    output_schema = matches[0].get("outputSchema")
    if (not isinstance(output_schema, Mapping)
            or hashlib.sha256(_canonical(dict(output_schema))).hexdigest()
               != registration["output_schema_sha256"]):
        raise OwnerCalendarUnavailable("Google Calendar list_events output schema changed")
    if matches[0].get("annotations", {}).get("readOnlyHint") is not True:
        raise OwnerCalendarUnavailable("Google Calendar list_events is not verified read-only")
    return session_id


def _current_published_calendar_source(config: Any) -> tuple[dict[str, Any], Any]:
    """Resolve the exact selected Calendar service and schema rows from the live publication."""
    from ..authority.enrollment import RootCredentialVault, RootMCPCredentialHandle, load_published_protected_enrollment
    from ..authority.setup_policy_publication import PolicyPublicationReceiptResolver
    core = None
    try:
        core = PolicyPublicationReceiptResolver.resolve_selected_current_authority_core()
        if core.verify_current() is not core:
            raise ValueError
        enrollment = load_published_protected_enrollment(core, vault=RootCredentialVault())
        if (enrollment.publication_authority_core_sha256 != core.sha256
                or enrollment.protected_enrollment_digest != core.service_generation_digest):
            raise ValueError
        service = enrollment.mcp_services.get(GOOGLE_CALENDAR_SERVICE)
        from ..authority.enrollment import ProtectedMCPService
        if (type(service) is not ProtectedMCPService
                or service.service_id != GOOGLE_CALENDAR_SERVICE or service.channel != "http"
                or GOOGLE_LIST_EVENTS_TOOL not in service.allowed_tools
                or tuple(service.selection_arguments.get(GOOGLE_LIST_EVENTS_TOOL, ())) != ("calendarId",)):
            raise ValueError
        binding = enrollment.mcp_http_bindings.get(service.transport_binding_id)
        from ..mcp.enrolled_transport import ProtectedMCPHTTPBinding
        if (type(binding) is not ProtectedMCPHTTPBinding
                or binding.binding_id != service.transport_binding_id
                or binding.service_id != GOOGLE_CALENDAR_SERVICE
                or binding.endpoint != GOOGLE_CALENDAR_ENDPOINT
                or binding.endpoint_source_id != "https://developers.google.com/workspace/calendar/api/v3/reference/mcp/tools_list/list_events"
                or binding.reviewed_revision != service.reviewed_revision
                or type(binding.credential_handle) is not RootMCPCredentialHandle
                or binding.credential_handle._service_id != GOOGLE_CALENDAR_SERVICE):
            raise ValueError
        owner_binding = enrollment.bindings_by_uid.get(config.core_uid)
        if owner_binding is None or not isinstance(owner_binding.principal_id, str):
            raise ValueError
        native_rows = [row for row in enrollment.native_mcp_tool_binding_records
            if row.get("mcp_enrollment_id") == GOOGLE_CALENDAR_SERVICE
            and row.get("mcp_tool_name") == GOOGLE_LIST_EVENTS_TOOL
            and row.get("effect_operation") == "mcp.request"
            and row.get("effect_target") == "mcp:google-calendar:http"
            and row.get("capability") == "mcp:google-calendar:read"
            and row.get("recipient") is None]
        if len(native_rows) != 1:
            raise ValueError
        native = native_rows[0]
        scopes = native.get("scope_bindings")
        if (not isinstance(scopes, list) or len(scopes) != 1
                or set(scopes[0]) != {"argument_field", "selected_resource_id"}
                or scopes[0]["argument_field"] != "calendarId"
                or not _valid_calendar_id(scopes[0]["selected_resource_id"])):
            raise ValueError
        schema_rows = enrollment.native_schema_artifact_records
        expected_schemas = {}
        for kind, schema_id in (("arguments", native["request_schema_id"]),
                                ("result", native["result_schema_id"])):
            matches = [item for item in schema_rows if item.get("id") == schema_id
                and item.get("schema_kind") == kind
                and item.get("action_id") == native["id"]
                and item.get("adapter_id") == native["handler_artifact_id"]
                and item.get("native_package_id") == native["native_package_id"]
                and item.get("native_package_generation") == native["native_package_generation"]]
            if len(matches) != 1 or not _HASH.fullmatch(str(matches[0].get("sha256"))):
                raise ValueError
            expected_schemas[kind] = matches[0]["sha256"]
        credential_ref = binding.credential_handle._reference
        if (not isinstance(credential_ref, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", credential_ref)):
            raise ValueError
        source_fields = {
            "authority_core_sha256": core.sha256,
            "service_generation_sha256": core.service_generation_digest,
            "service_id": service.service_id,
            "transport_binding_id": binding.binding_id,
            "endpoint": binding.endpoint,
            "endpoint_source_id": binding.endpoint_source_id,
            "reviewed_revision": binding.reviewed_revision,
            "native_binding_id": native["id"],
            "mcp_generation": native["mcp_generation"],
            "selected_calendar_id": scopes[0]["selected_resource_id"],
            "input_schema_sha256": expected_schemas["arguments"],
            "output_schema_sha256": expected_schemas["result"],
        }
        source_digest = hashlib.sha256(_canonical(source_fields)).hexdigest()
        connection_generation = hashlib.sha256(_canonical({
            "authority_core_sha256": core.sha256,
            "mcp_generation": native["mcp_generation"],
            "transport_binding_id": binding.binding_id,
        })).hexdigest()
        from ..authority.enrollment import RootCredentialVault
        token = RootCredentialVault().resolve_reference(credential_ref,
            peer_uid=config.core_uid, required_scope="mcp:google-calendar:read",
            principal_id=owner_binding.principal_id)
        if not token:
            raise ValueError
        token = ""
        return ({"connection_id": "google-calendar-" + hashlib.sha256(
                    (binding.binding_id + core.service_generation_digest).encode("ascii")).hexdigest()[:24],
                 "generation_sha256": core.service_generation_digest,
                 "connection_generation_sha256": connection_generation,
                 "mcp_generation": native["mcp_generation"],
                 "source_binding_sha256": source_digest,
                 "provider_principal_id": owner_binding.principal_id,
                 "credential_consumer_uid": config.core_uid,
                 "credential_ref": credential_ref,
                 "credential_scope": "mcp:google-calendar:read",
                 "input_schema_sha256": expected_schemas["arguments"],
                 "output_schema_sha256": expected_schemas["result"],
                 "native_binding_id": native["id"],
                 "calendar_id": scopes[0]["selected_resource_id"],
                 "calendar_label": "Selected native Calendar",
                 "authority_core_sha256": core.sha256}, enrollment)
    except OwnerCalendarUnavailable:
        raise
    except Exception:
        raise OwnerCalendarUnavailable(
            "No current protected Google Calendar read connection is available") from None
    finally:
        if core is not None:
            try:
                core.close()
            except Exception:
                pass


def _calendar_source_is_current(config: Any, registration: Mapping[str, Any]) -> bool:
    selected, enrollment = _current_published_calendar_source(config)
    consent = registration["owner_ui_consent"]
    calendar = next((row for row in registration["calendars"]
                    if row["calendar_ref"] == registration["selected_calendar_ref"]), None)
    return bool(calendar is not None
        and selected["connection_id"] == registration["connection_id"]
        and selected["generation_sha256"] == registration["generation_sha256"]
        and selected["connection_generation_sha256"] == registration["connection_generation_sha256"]
        and selected["mcp_generation"] == registration["mcp_generation"]
        and selected["source_binding_sha256"] == registration["source_binding_sha256"]
        and selected["provider_principal_id"] == registration["provider_principal_id"]
        and selected["credential_consumer_uid"] == registration["credential_consumer_uid"]
        and selected["credential_ref"] == registration["credential_ref"]
        and selected["native_binding_id"] == registration["native_binding_id"]
        and selected["input_schema_sha256"] == registration["input_schema_sha256"]
        and selected["output_schema_sha256"] == registration["output_schema_sha256"]
        and selected["calendar_id"] == calendar["calendar_id"]
        and consent["core_generation"] == selected["authority_core_sha256"])


def update_owner_calendar_selection(*, config: Any, request: Mapping[str, Any],
                                    caller_pid: int, caller_uid: int, caller_gid: int,
                                    peer_pid: int, peer_uid: int, peer_gid: int) -> dict[str, Any]:
    """Persist explicit current owner consent for the protected native selection."""
    from .core_gateway import CORE_GATEWAY_UNIT, CoreGatewayConfig, _read_config_current
    from .core_gateway_inspector import (
        _check_unit_process, _consume_ingress_issue, observe_current_ingress,
    )
    fields = {"schema", "op", "nonce", "peer_pid", "peer_uid", "peer_gid", "access_jwt",
        "core_generation", "ingress_nonce", "ingress_proof_sha256", "confirmation", "action"}
    if (type(config) is not CoreGatewayConfig or not isinstance(request, Mapping)
            or set(request) != fields or type(request.get("schema")) is not int or request["schema"] != 1
            or request.get("op") != "select-owner-calendar"
            or request.get("confirmation") != "read-only-calendar-events"
            or request.get("action") not in {"enable", "disable"}
            or (request.get("peer_pid"), request.get("peer_uid"), request.get("peer_gid"))
                != (peer_pid, peer_uid, peer_gid)
            or caller_uid != config.gateway_uid or type(caller_pid) is not int or caller_pid <= 1
            or not isinstance(request.get("nonce"), str) or not _HASH.fullmatch(request["nonce"])
            or not isinstance(request.get("access_jwt"), str)
            or not 1 <= len(request["access_jwt"]) <= 16_384 or not request["access_jwt"].isascii()
            or not _HASH.fullmatch(str(request.get("core_generation")))
            or not _HASH.fullmatch(str(request.get("ingress_nonce")))
            or not _HASH.fullmatch(str(request.get("ingress_proof_sha256")))):
        raise OwnerCalendarUnavailable("Calendar owner selection request is invalid")
    inspector = __import__("hermes_installer.remote.core_gateway_inspector",
                            fromlist=["_proc_start_ticks"])
    started_ticks = inspector._proc_start_ticks(caller_pid)
    retained = _consume_ingress_issue(caller_pid=caller_pid, caller_start_ticks=started_ticks,
        nonce=request["ingress_nonce"], proof_sha256=request["ingress_proof_sha256"],
        peer=(peer_pid, peer_uid, peer_gid), core_generation=request["core_generation"], config=config)
    deadline = min(time.monotonic() + MAX_CALL_SECONDS, retained.expires_monotonic)
    _read_config_current(config)
    live = observe_current_ingress(config, nonce=retained.nonce,
        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
        peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
        _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
    pidfd, start_ticks, _ = _check_unit_process(config, unit=CORE_GATEWAY_UNIT,
        pid=caller_pid, deadline=deadline)
    try:
        if (start_ticks != retained.caller_start_ticks
                or live["proof_sha256"] != retained.proof_sha256
                or request["core_generation"] != live["core_generation"]):
            raise OwnerCalendarUnavailable("Calendar owner ingress changed")
    finally:
        os.close(pidfd)
    from .gateway import validate_access_jwt
    principal = validate_access_jwt(request["access_jwt"],
        policy=config.policy(inspector._learning_jwks(config, deadline=deadline)),
        deadline_monotonic=deadline)
    owner_hash = hashlib.sha256(principal.subject.encode("utf-8", "strict")).hexdigest()
    if (principal.email.casefold() not in config.allowed_emails
            or hashlib.sha256(request["access_jwt"].encode("ascii")).hexdigest()
                != principal.token_fingerprint):
        raise OwnerCalendarUnavailable("Calendar owner selection is not current")
    existing = list(load_calendar_registrations())
    if request["action"] == "disable":
        updated = [row for row in existing if row["owner_subject_sha256"] != owner_hash]
        write_calendar_registrations(updated)
        return {"schema": 1, "nonce": request["nonce"], "ok": True, "state": "disabled"}
    selected, _enrollment = _current_published_calendar_source(config)
    calendar_ref = secrets.token_urlsafe(32)
    calendar = {"calendar_ref": calendar_ref, "calendar_id": selected["calendar_id"],
        "label": selected["calendar_label"]}
    args = {"calendarId": selected["calendar_id"]}
    confirmed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    consent = {"schema": 1, "owner_subject_sha256": owner_hash,
        "action": "read-only-calendar-dashboard", "confirmed_at": confirmed_at,
        "core_generation": selected["authority_core_sha256"],
        "connection_generation_sha256": selected["connection_generation_sha256"],
        "source_binding_sha256": selected["source_binding_sha256"],
        "canonical_arguments_sha256": hashlib.sha256(_canonical(args)).hexdigest()}
    record = _validate_registration({"schema": 1,
        "owner_subject_sha256": owner_hash,
        "connection_id": selected["connection_id"],
        "generation_sha256": selected["generation_sha256"],
        "connection_generation_sha256": selected["connection_generation_sha256"],
        "mcp_generation": selected["mcp_generation"],
        "source_binding_sha256": selected["source_binding_sha256"],
        "provider_principal_id": selected["provider_principal_id"],
        "credential_consumer_uid": selected["credential_consumer_uid"],
        "credential_ref": selected["credential_ref"],
        "credential_scope": selected["credential_scope"],
        "endpoint": GOOGLE_CALENDAR_ENDPOINT, "tool_name": GOOGLE_LIST_EVENTS_TOOL,
        "input_schema_sha256": selected["input_schema_sha256"],
        "output_schema_sha256": selected["output_schema_sha256"],
        "invocation_class": CALENDAR_INVOCATION_CLASS,
        "calendars": [calendar], "selected_calendar_ref": calendar_ref,
        "provider_identity_label": None, "owner_ui_consent": consent,
        "native_binding_id": selected["native_binding_id"]})
    updated = [row for row in existing if row["owner_subject_sha256"] != owner_hash]
    updated.append(record)
    if not _calendar_source_is_current(config, record):
        raise OwnerCalendarUnavailable("Calendar source changed before consent was stored")
    _read_config_current(config)
    current = observe_current_ingress(config, nonce=retained.nonce,
        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
        peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
        _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
    if current["proof_sha256"] != retained.proof_sha256 or time.monotonic() >= deadline:
        raise OwnerCalendarUnavailable("Calendar owner consent expired before storage")
    write_calendar_registrations(updated)
    return {"schema": 1, "nonce": request["nonce"], "ok": True, "state": "selected"}


def perform_owner_calendar_read(*, config: Any, request: Mapping[str, Any],
                                caller_pid: int, caller_uid: int, caller_gid: int,
                                peer_pid: int, peer_uid: int, peer_gid: int) -> dict[str, Any]:
    """Root Inspector call after consuming a current ingress issuance."""
    from .core_gateway import (
        CORE_GATEWAY_UNIT, CoreGatewayConfig, CoreGatewayDenied, _read_config_current,
    )
    from .core_gateway_inspector import (
        CoreInspectionDenied, _check_unit_process, _consume_ingress_issue,
        observe_current_ingress,
    )
    fields = {"schema", "op", "nonce", "peer_pid", "peer_uid", "peer_gid", "access_jwt",
              "core_generation", "ingress_nonce", "ingress_proof_sha256", "calendar_ref",
              "start_time", "end_time", "timezone", "page_size"}
    if (type(config) is not CoreGatewayConfig or not isinstance(request, Mapping)
            or set(request) != fields or type(request.get("schema")) is not int or request["schema"] != 1
            or request.get("op") != "read-owner-calendar"
            or (request.get("peer_pid"), request.get("peer_uid"), request.get("peer_gid"))
                != (peer_pid, peer_uid, peer_gid)
            or type(peer_pid) is not int or peer_pid <= 0
            or any(type(v) is not int or v < 0 for v in (peer_uid, peer_gid))
            or type(caller_pid) is not int or caller_pid <= 1 or caller_uid != config.gateway_uid
            or not isinstance(request.get("nonce"), str) or not _HASH.fullmatch(request["nonce"])
            or not isinstance(request.get("access_jwt"), str)
            or not 1 <= len(request["access_jwt"]) <= 16_384 or not request["access_jwt"].isascii()
            or not _HASH.fullmatch(str(request.get("core_generation")))
            or not _HASH.fullmatch(str(request.get("ingress_nonce")))
            or not _HASH.fullmatch(str(request.get("ingress_proof_sha256")))
            or (request.get("calendar_ref") is not None and
                (not isinstance(request["calendar_ref"], str)
                 or not _OPAQUE.fullmatch(request["calendar_ref"])))):
        raise OwnerCalendarUnavailable("Calendar read request is invalid")
    start_at, end_at = _bounds(request["start_time"], request["end_time"],
                               request["timezone"], request["page_size"])
    caller_start_ticks = __import__("hermes_installer.remote.core_gateway_inspector",
                                    fromlist=["_proc_start_ticks"])._proc_start_ticks(caller_pid)
    retained = _consume_ingress_issue(caller_pid=caller_pid,
        caller_start_ticks=caller_start_ticks, nonce=request["ingress_nonce"],
        proof_sha256=request["ingress_proof_sha256"], peer=(peer_pid, peer_uid, peer_gid),
        core_generation=request["core_generation"], config=config)
    deadline = min(time.monotonic() + MAX_CALL_SECONDS, retained.expires_monotonic)
    _read_config_current(config)
    current = observe_current_ingress(config, nonce=retained.nonce,
        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
        peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
        _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
    gateway_pidfd, gateway_start_ticks, _invocation = _check_unit_process(
        config, unit=CORE_GATEWAY_UNIT, pid=caller_pid, deadline=deadline)
    try:
        if (gateway_start_ticks != retained.caller_start_ticks
                or current["proof_sha256"] != retained.proof_sha256):
            raise OwnerCalendarUnavailable("Calendar ingress changed")
    finally:
        os.close(gateway_pidfd)
    from .gateway import validate_access_jwt
    principal = validate_access_jwt(request["access_jwt"],
        policy=config.policy(__import__("hermes_installer.remote.core_gateway_inspector",
        fromlist=["_learning_jwks"])._learning_jwks(config, deadline=deadline)),
        deadline_monotonic=deadline)
    owner_hash = hashlib.sha256(principal.subject.encode("utf-8", "strict")).hexdigest()
    rows = load_calendar_registrations()
    candidates = [row for row in rows if row["owner_subject_sha256"] == owner_hash]
    if (len(candidates) != 1 or principal.email.casefold() not in config.allowed_emails
            or hashlib.sha256(request["access_jwt"].encode("ascii")).hexdigest() != principal.token_fingerprint
            or request["core_generation"] != current["core_generation"]):
        raise OwnerCalendarUnavailable("No current protected Calendar connection is registered for this owner")
    registration = candidates[0]
    selected_ref = request["calendar_ref"] or registration["selected_calendar_ref"]
    calendar_rows = [row for row in registration["calendars"]
                     if row["calendar_ref"] == selected_ref]
    if len(calendar_rows) != 1:
        raise OwnerCalendarUnavailable("Selected Calendar is outside the registered connection")
    calendar_row = calendar_rows[0]
    issued = time.monotonic()
    args = {"calendarId": calendar_row["calendar_id"],
            "startTime": start_at.isoformat(), "endTime": end_at.isoformat(),
            "timeZone": request["timezone"], "pageSize": request["page_size"]}
    canonical_args_hash = hashlib.sha256(_canonical(args)).hexdigest()
    invocation = RootOwnerCalendarReadInvocation(
        schema=1, invocation_class=CALENDAR_INVOCATION_CLASS,
        request_nonce=request["nonce"], owner_subject_sha256=owner_hash,
        connection_id=registration["connection_id"],
        connection_generation_sha256=registration["connection_generation_sha256"],
        source_binding_sha256=registration["source_binding_sha256"],
        calendar_ref=calendar_row["calendar_ref"], canonical_arguments_sha256=canonical_args_hash,
        provider_principal_id=registration["provider_principal_id"],
        credential_consumer_uid=registration["credential_consumer_uid"],
        credential_scope=registration["credential_scope"], admitted_jwt_expiry=principal.exp,
        issued_monotonic=issued, expires_monotonic=deadline,
        ingress_nonce=retained.nonce, ingress_proof_sha256=retained.proof_sha256, _seal=_SEAL)
    vault = RootCredentialVault()
    session_id = None
    response_hash = ""
    try:
        for leg in ("initialize", "notification", "discovery", "call"):
            _read_config_current(config)
            if time.monotonic() >= deadline:
                raise OwnerCalendarUnavailable("Calendar read exceeded the original ingress deadline")
            live_rows = load_calendar_registrations()
            matching = [row for row in live_rows if row["connection_id"] == registration["connection_id"]]
            if (len(matching) != 1 or _canonical(matching[0]) != _canonical(registration)
                    or not _calendar_source_is_current(config, registration)
                    or not invocation.is_current(registration=matching[0], now=time.monotonic(),
                                                 ingress_expiry=retained.expires_monotonic)):
                raise OwnerCalendarUnavailable("Calendar connection changed during the read")
            token = vault.resolve_reference(registration["credential_ref"],
                peer_uid=registration["credential_consumer_uid"],
                required_scope=registration["credential_scope"],
                principal_id=registration["provider_principal_id"])
            if leg == "initialize":
                rid = secrets.token_hex(12)
                result, session_id, status = _post({"jsonrpc": "2.0", "id": rid,
                    "method": "initialize", "params": {"protocolVersion": "2025-03-26",
                    "capabilities": {}, "clientInfo": {"name": "hermes-calendar-read", "version": "1"}}},
                    bearer=token, session_id=None, deadline=deadline)
                if (not isinstance(result, Mapping) or result.get("protocolVersion") not in
                        {"2025-03-26", "2024-11-05"} or not isinstance(result.get("capabilities"), Mapping)
                        or not isinstance(result.get("serverInfo"), Mapping)):
                    raise OwnerCalendarUnavailable("Google Calendar MCP initialization was invalid")
            elif leg == "notification":
                _post({"jsonrpc": "2.0", "method": "notifications/initialized"},
                      bearer=token, session_id=session_id, deadline=deadline, notification=True)
            elif leg == "discovery":
                session_id = _discover_schema(session_id, token, deadline, registration)
            else:
                rid = secrets.token_hex(12)
                result, session_id, _status = _post({"jsonrpc": "2.0", "id": rid,
                    "method": "tools/call", "params": {"name": GOOGLE_LIST_EVENTS_TOOL,
                    "arguments": args}}, bearer=token, session_id=session_id, deadline=deadline)
                value = _result_value(result)
                response_hash = hashlib.sha256(_canonical(dict(result))).hexdigest()
                if (not isinstance(value.get("events"), list)
                        or len(value["events"]) > request["page_size"]
                        or (value.get("nextPageToken") is not None
                            and not isinstance(value["nextPageToken"], str))):
                    raise OwnerCalendarUnavailable("Google Calendar event page exceeded its selected bound")
                from .jarvis_calendar import project_calendar_page
                projected_source = {
                    "status": "connected", "opaque_account_ref": registration["connection_id"],
                    "opaque_calendar_ref": calendar_row["calendar_ref"],
                    "account_label": "Selected connection · identity unknown",
                    "calendar_label": calendar_row["label"], "events": [
                        {"opaque_event_id": secrets.token_urlsafe(24),
                         "summary": event.get("summary", "Untitled event"),
                         "start": event.get("start"), "end": event.get("end")}
                        for event in value["events"] if isinstance(event, Mapping)],
                    "next_step": "", "partial": bool(value.get("nextPageToken")),
                }
                if projected_source["partial"]:
                    projected_source["status"] = "partial"
                projection = project_calendar_page(projected_source,
                    timezone_name=request["timezone"], window_start=args["startTime"],
                    window_end=args["endTime"], observed_at=datetime.now(UTC).isoformat())
                if len(projected_source["events"]) != len(value["events"]):
                    raise OwnerCalendarUnavailable("Google Calendar event row was malformed")
                now = time.monotonic()
                _read_config_current(config)
                current = observe_current_ingress(config, nonce=retained.nonce,
                    caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
                    peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
                    _issued=retained.issued_monotonic, _deadline=deadline,
                    _retain_issuance=False)
                after_rows = load_calendar_registrations()
                if (current["proof_sha256"] != retained.proof_sha256
                        or not any(_canonical(row) == _canonical(registration) for row in after_rows)
                        or not invocation.is_current(registration=registration, now=now,
                                                     ingress_expiry=retained.expires_monotonic)):
                    raise OwnerCalendarUnavailable("Calendar read became stale before projection")
                record = RootCalendarReadResult(
                    schema=1, owner_subject_sha256=owner_hash,
                    connection_id=registration["connection_id"],
                    connection_generation_sha256=registration["connection_generation_sha256"],
                    source_binding_sha256=registration["source_binding_sha256"],
                    opaque_calendar_ref=calendar_row["calendar_ref"], tool_name=GOOGLE_LIST_EVENTS_TOOL,
                    canonical_arguments_sha256=canonical_args_hash,
                    actual_response_sha256=response_hash,
                    observed_at=projection["observed_at"], projection=projection,
                    issued_monotonic=issued, expires_monotonic=deadline, _seal=_SEAL)
                if not record.is_root_verified(invocation, now=now):
                    raise OwnerCalendarUnavailable("Root Calendar result proof is invalid")
                return {"schema": 1, "ok": True, "read_result": {
                    "owner_subject_sha256": record.owner_subject_sha256,
                    "connection_id": record.connection_id,
                    "connection_generation_sha256": record.connection_generation_sha256,
                    "source_binding_sha256": record.source_binding_sha256,
                    "opaque_calendar_ref": record.opaque_calendar_ref,
                    "tool_name": record.tool_name,
                    "canonical_arguments_sha256": record.canonical_arguments_sha256,
                    "actual_response_sha256": record.actual_response_sha256,
                    "observed_at": record.observed_at,
                    "projection": dict(record.projection),
                }}
        raise OwnerCalendarUnavailable("Calendar read was incomplete")
    except OwnerCalendarUnavailable:
        raise
    except Exception:
        # This boundary intentionally collapses token/auth/protocol details.
        raise OwnerCalendarUnavailable("Calendar read is unavailable; reconnect the protected read-only connection") from None
    finally:
        token = ""
