"""Selected Hermes native-channel ingress into root Resources authority.

This module binds Telegram/Discord deliveries at their pinned SDK callback
paths.  A MessageEvent by itself is never evidence: the event must be produced
while the exact selected platform client's registered inbound callback is on
the stack, and its raw SDK message, normalized SessionSource and current
protected account/selection readers must all agree.

The installer does not hold bot tokens.  ``account_binding_reader`` resolves
the live SDK client against the protected credential-vault binding without
returning the credential.  Missing clients, selected rows, vault bindings,
root custody or the optional pinned SDK leave ingress unavailable.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_PAYLOAD = 256 * 1024
_DEDUP_TTL = 24 * 60 * 60.0
PINNED_HERMES_REVISION = "7085fbf7753266fc4943c55ac04926186bc90005"


class ChannelIngressUnavailable(RuntimeError):
    """The selected native channel cannot currently prove an inbound event."""


@dataclass(frozen=True, slots=True)
class ChannelIngressSelection:
    """Protected root-selected channel row; never decoded from channel YAML."""

    resource_id: str
    generation: str
    observer_enrollment_id: str
    controller_role_id: str
    source_issuer_id: str
    backend_id: str
    channel_name: str
    adapter_id: str
    account_binding_digest: str
    credential_vault_reference: str
    selected_config_digest: str
    allowed_scopes: tuple[str, ...]

    def __post_init__(self) -> None:
        for field_name in ("resource_id", "generation", "observer_enrollment_id",
                           "controller_role_id", "source_issuer_id", "backend_id",
                           "channel_name", "adapter_id", "credential_vault_reference"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
                raise ValueError(f"selected channel {field_name} is invalid")
        for field_name in ("account_binding_digest", "selected_config_digest"):
            if not isinstance(getattr(self, field_name), str) or not _SHA256.fullmatch(getattr(self, field_name)):
                raise ValueError(f"selected channel {field_name} must be SHA-256")
        if self.channel_name not in {"telegram", "discord", "whatsapp", "web", "voice"}:
            raise ValueError("selected channel name is not a pinned channel type")
        expected = {"telegram": "telegram", "discord": "discord",
                    "whatsapp": "composio-whatsapp-business", "web": "http",
                    "voice": "local-audio-assist"}[self.channel_name]
        if self.adapter_id != expected:
            raise ValueError("selected channel adapter does not match the pinned channel declaration")
        if (not isinstance(self.allowed_scopes, tuple)
                or not self.allowed_scopes
                or any(not isinstance(item, str) or not (
                    _IDENTIFIER.fullmatch(item) or re.fullmatch(r"-?[0-9]{1,20}", item))
                       for item in self.allowed_scopes)
                or len(set(self.allowed_scopes)) != len(self.allowed_scopes)):
            raise ValueError("selected channel scope must be a non-empty unique protected tuple")


@dataclass(frozen=True, slots=True)
class _NativeCallback:
    """Instance-private callback evidence; the issuer validates identity, not fields."""

    owner_token: object = field(repr=False, compare=False)
    platform: str
    client: object = field(repr=False, compare=False)
    raw: object = field(repr=False, compare=False)
    event: object = field(repr=False, compare=False)
    message: object = field(repr=False, compare=False)
    callback_nonce: object = field(repr=False, compare=False)
    update_key: str
    scope_id: str
    sender_id: str
    canonical_payload: bytes = field(repr=False)
    selection_digest: str
    account_binding_digest: str
    received_monotonic: float


@dataclass(frozen=True, slots=True)
class NativeIngressStatus:
    available: bool
    reason: str | None = None
    accepted: int = 0
    replayed: int = 0


@dataclass(frozen=True, slots=True)
class ComposioV3SelectedChannel:
    """Protected v45 WhatsApp enrollment joined to its source and backend rows."""

    id: str
    channel_resource_id: str
    resource_generation: str
    profile_id: str
    controller_role_id: str
    source_issuer_id: str
    composio_enrollment_id: str
    composio_user_id: str
    connected_account_id: str
    auth_config_id: str
    toolkit_version: str
    trigger_artifact_id: str
    trigger_artifact_sha256: str
    trigger_slug: str
    trigger_instance_id: str
    webhook_subscription_id: str
    webhook_route_enrollment_id: str
    webhook_secret_reference_id: str
    allowed_user_numbers: tuple[str, ...]
    payload_field_bindings: Mapping[str, str]
    max_event_age_seconds: int
    source_observer_enrollment_id: str
    backend_id: str

    def __post_init__(self) -> None:
        for name in (
            "id", "channel_resource_id", "resource_generation", "profile_id",
            "controller_role_id", "source_issuer_id", "composio_enrollment_id",
            "composio_user_id", "connected_account_id", "auth_config_id",
            "toolkit_version", "trigger_artifact_id", "trigger_slug",
            "trigger_instance_id", "webhook_subscription_id",
            "webhook_route_enrollment_id", "webhook_secret_reference_id",
            "source_observer_enrollment_id", "backend_id",
        ):
            if not isinstance(getattr(self, name), str) or not _IDENTIFIER.fullmatch(getattr(self, name)):
                raise ValueError(f"selected Composio field {name} is invalid")
        if not _SHA256.fullmatch(self.trigger_artifact_sha256):
            raise ValueError("selected Composio trigger artifact digest is invalid")
        if (not isinstance(self.allowed_user_numbers, tuple)
                or not self.allowed_user_numbers
                or any(not isinstance(number, str) or not re.fullmatch(r"\+[1-9][0-9]{1,14}", number)
                       for number in self.allowed_user_numbers)
                or len(set(self.allowed_user_numbers)) != len(self.allowed_user_numbers)):
            raise ValueError("selected WhatsApp number allowlist must contain unique E.164 values")
        bindings = dict(self.payload_field_bindings)
        if (set(bindings) != {"sender_user_number"}
                or not isinstance(bindings["sender_user_number"], str)
                or not bindings["sender_user_number"].startswith("/")
                or len(bindings["sender_user_number"]) > 256):
            raise ValueError("selected Composio trigger must bind one explicit sender_user_number JSON Pointer")
        from types import MappingProxyType
        object.__setattr__(self, "payload_field_bindings", MappingProxyType(bindings))
        if type(self.max_event_age_seconds) is not int or not 1 <= self.max_event_age_seconds <= 300:
            raise ValueError("selected Composio event age must be within the 300 second ingress bound")


@dataclass(frozen=True, slots=True)
class _ComposioObservation:
    owner_token: object = field(repr=False, compare=False)
    selection: ComposioV3SelectedChannel = field(repr=False, compare=False)
    request: object = field(repr=False, compare=False)
    raw_body: bytes = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)
    canonical_payload: bytes = field(repr=False)
    event_id: str
    sender_number: str
    body_sha256: str
    schema_digest: str
    route_enrollment_id: str
    route_proof: object = field(repr=False, compare=False)
    account_proof: object = field(repr=False, compare=False)
    schema_proof: object = field(repr=False, compare=False)
    received_wall_time: float


@dataclass(frozen=True, slots=True)
class ComposioDeliveryResult:
    accepted: bool
    duplicate: bool
    event_handle: object | None = field(default=None, repr=False)


class ComposioV3WebhookIngress:
    """Root-side authenticated Composio V3 trigger-message source adapter.

    The raw request is HMAC verified before JSON is trusted. A current protected
    v45 row, exact trigger-schema artifact, account-binding proof, route
    enrollment and durable replay ledger are required. SDK `subscribe()` values
    or constructible trigger DTOs cannot mint a source proof.
    """

    MAX_BODY_BYTES = 256 * 1024
    SIGNATURE_TOLERANCE_SECONDS = 300

    def __init__(self, *, selection: ComposioV3SelectedChannel,
                 current_selection: Callable[[], ComposioV3SelectedChannel | None],
                 secret_reader: Callable[[str], bytes],
                 account_binding_reader: Callable[[ComposioV3SelectedChannel], object],
                 schema_reader: Callable[[str, str], object],
                 listener_route_reader: Callable[[object], object],
                 backend_reader: Callable[[ComposioV3SelectedChannel], str],
                 replay_ledger: Any, issuer: Any, controller_registry: Any,
                 wall_time: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic):
        if selection.channel_resource_id == "":
            raise ChannelIngressUnavailable("selected Composio channel identity is unavailable")
        required = (current_selection, secret_reader, account_binding_reader,
                    schema_reader, listener_route_reader, backend_reader)
        if not all(callable(item) for item in required):
            raise ChannelIngressUnavailable("protected Composio selection, account, schema, route, and secret readers are required")
        if not all(callable(getattr(replay_ledger, name, None)) for name in ("begin", "commit", "rollback")):
            raise ChannelIngressUnavailable("durable Composio webhook replay ledger is unavailable")
        if (not callable(getattr(issuer, "register_source_producer", None))
                or not callable(getattr(issuer, "mint_source_proof", None))
                or not callable(getattr(controller_registry, "resolve_selected_ingress_controller", None))
                or not callable(getattr(controller_registry, "capture_selected_ingress", None))):
            raise ChannelIngressUnavailable("root selected channel source issuer/registry is unavailable")
        self.selection = selection
        self._current_selection = current_selection
        self._secret_reader = secret_reader
        self._account_binding_reader = account_binding_reader
        self._schema_reader = schema_reader
        self._listener_route_reader = listener_route_reader
        self._backend_reader = backend_reader
        self._replay_ledger = replay_ledger
        self._issuer = issuer
        self._controller_registry = controller_registry
        self._wall_time = wall_time
        self._monotonic = monotonic
        self._owner_token = object()
        self._context = __import__("contextvars").ContextVar(
            f"hermes_composio_ingress_{id(self)}", default=None)
        self._issuer_capability = issuer.register_source_producer(
            self, source_kind="native-input",
            observer_enrollment_id=selection.source_observer_enrollment_id,
            validate_provenance=self.validate_claims,
        )

    def accept_request(self, request: object) -> ComposioDeliveryResult:
        """Authenticate one raw Composio HTTP request and atomically capture it."""
        verified = self._verify_request(request)
        duplicate_result = self._replay_ledger.begin(
            self.selection.channel_resource_id, verified.event_id, verified.body_sha256,
            self._wall_time() + max(self.selection.max_event_age_seconds, 300))
        state = getattr(duplicate_result, "state", None)
        if state == "duplicate":
            if getattr(duplicate_result, "body_sha256", None) != verified.body_sha256:
                raise ChannelIngressUnavailable("Composio webhook replay identity conflicts with a different payload")
            return ComposioDeliveryResult(True, True, getattr(duplicate_result, "event_handle", None))
        if state != "reserved" or getattr(duplicate_result, "body_sha256", None) != verified.body_sha256:
            raise ChannelIngressUnavailable("Composio webhook replay ledger rejected or conflicted with this event")
        payload = verified.canonical_payload
        event_handle = "e" + secrets.token_urlsafe(32)
        token = self._context.set(verified)
        try:
            proof = self._issuer.mint_source_proof(
                self._issuer_capability, event_id=event_handle,
                resource_id=self.selection.channel_resource_id,
                resource_generation=self.selection.resource_generation,
                source_observer_enrollment_id=self.selection.source_observer_enrollment_id,
                payload=payload, provenance=verified,
            )
            backend_id = self._backend_reader(self.selection)
            if backend_id != self.selection.backend_id:
                raise ChannelIngressUnavailable("selected Composio backend binding changed")
            ingress = self._controller_registry.resolve_selected_ingress_controller(
                self.selection.controller_role_id, self.selection.source_issuer_id, backend_id)
            proof_handle = getattr(ingress, "proof_handle", None)
            if not isinstance(proof_handle, str) or not _IDENTIFIER.fullmatch(proof_handle):
                raise ChannelIngressUnavailable("root selected Composio ingress proof is malformed")
            result = self._controller_registry.capture_selected_ingress(proof_handle, proof)
            self._replay_ledger.commit(duplicate_result, result)
            return ComposioDeliveryResult(True, False, result)
        except BaseException:
            self._replay_ledger.rollback(duplicate_result)
            raise
        finally:
            self._context.reset(token)

    def _verify_request(self, request: object) -> _ComposioObservation:
        if self._current_selection() is not self.selection:
            raise ChannelIngressUnavailable("selected Composio source generation changed")
        try:
            raw_body = getattr(request, "body")
            headers = {str(key).lower(): str(value).strip()
                       for key, value in getattr(request, "headers").items()}
        except Exception:
            raise ChannelIngressUnavailable("Composio ingress requires the root listener's raw request object") from None
        if not isinstance(raw_body, bytes) or not 1 <= len(raw_body) <= self.MAX_BODY_BYTES:
            raise ChannelIngressUnavailable("Composio webhook body is empty or exceeds 256 KiB")
        route = self._listener_route_reader(request)
        route_id = getattr(route, "enrollment_id", None)
        if (route is None or isinstance(route, (bool, str, bytes, int, float, dict, list, tuple))
                or not callable(getattr(route, "revalidate_request", None))
                or route.revalidate_request(request) is not True
                or route_id != self.selection.webhook_route_enrollment_id):
            raise ChannelIngressUnavailable("Composio request did not arrive through its selected protected route")
        content_type = getattr(request, "content_type", None)
        media_type = content_type.split(";", 1)[0].strip().lower() if isinstance(content_type, str) else ""
        if getattr(request, "method", None) != "POST" or media_type != "application/json":
            raise ChannelIngressUnavailable("Composio V3 ingress requires the selected JSON POST route")
        if headers.get("x-composio-webhook-version") != "V3":
            raise ChannelIngressUnavailable("Composio V3 webhook version header is missing or unsupported")
        webhook_id = headers.get("webhook-id", "")
        timestamp_raw = headers.get("webhook-timestamp", "")
        signature_header = headers.get("webhook-signature", "")
        if not webhook_id or not _IDENTIFIER.fullmatch(webhook_id):
            raise ChannelIngressUnavailable("Composio webhook-id header is malformed")
        if not re.fullmatch(r"[0-9]{1,12}", timestamp_raw):
            raise ChannelIngressUnavailable("Composio webhook timestamp is malformed")
        try:
            timestamp = int(timestamp_raw)
            now = self._wall_time()
        except (TypeError, ValueError, OverflowError):
            raise ChannelIngressUnavailable("Composio webhook timestamp is malformed") from None
        if (type(timestamp) is not int or not math.isfinite(now)
                or abs(now - timestamp) > self.SIGNATURE_TOLERANCE_SECONDS):
            raise ChannelIngressUnavailable("Composio webhook signature timestamp is outside the 300 second window")
        secret = self._secret_reader(self.selection.webhook_secret_reference_id)
        if not isinstance(secret, bytes) or len(secret) < 16:
            raise ChannelIngressUnavailable("Composio webhook signing secret is unavailable")
        self._verify_signature(webhook_id, timestamp_raw, raw_body, signature_header, secret)
        payload = self._decode_json(raw_body)
        metadata = payload.get("metadata")
        if (not isinstance(payload, dict) or set(payload) != {"id", "type", "metadata", "data", "timestamp"}
                or payload.get("type") != "composio.trigger.message"
                or not isinstance(metadata, dict)
                or payload.get("id") != webhook_id
                or metadata.get("trigger_slug") != self.selection.trigger_slug
                or metadata.get("trigger_id") != self.selection.trigger_instance_id
                or metadata.get("connected_account_id") != self.selection.connected_account_id
                or metadata.get("auth_config_id") != self.selection.auth_config_id
                or metadata.get("user_id") != self.selection.composio_user_id
                or not isinstance(payload.get("data"), dict)):
            raise ChannelIngressUnavailable("Composio V3 envelope differs from the selected trigger/account binding")
        try:
            created = self._parse_iso_timestamp(payload["timestamp"])
        except (TypeError, ValueError):
            raise ChannelIngressUnavailable("Composio trigger event timestamp is invalid") from None
        if created > now + 5 or now - created > self.selection.max_event_age_seconds:
            raise ChannelIngressUnavailable("Composio event timestamp is outside the selected age/future-skew bound")
        account_proof = self._account_binding_reader(self.selection)
        if (account_proof is None or isinstance(account_proof, (bool, str, bytes, int, float, dict, list, tuple))
                or getattr(account_proof, "revalidate", lambda: False)() is not True
                or getattr(account_proof, "connected_account_id", None) != self.selection.connected_account_id
                or getattr(account_proof, "auth_config_id", None) != self.selection.auth_config_id
                or getattr(account_proof, "composio_user_id", None) != self.selection.composio_user_id):
            raise ChannelIngressUnavailable("selected Composio account/session is unavailable or changed")
        schema_proof = self._schema_reader(
            self.selection.trigger_artifact_id, self.selection.trigger_artifact_sha256)
        if (schema_proof is None or getattr(schema_proof, "artifact_id", None) != self.selection.trigger_artifact_id
                or getattr(schema_proof, "schema_sha256", None) != self.selection.trigger_artifact_sha256
                or getattr(schema_proof, "revalidate", lambda: False)() is not True
                or not callable(getattr(schema_proof, "validate_payload", None))
                or schema_proof.validate_payload(payload["data"]) is not True):
            raise ChannelIngressUnavailable("selected Composio trigger schema is unavailable or payload did not validate")
        sender_number = self._json_pointer(payload, self.selection.payload_field_bindings["sender_user_number"])
        if not isinstance(sender_number, str) or sender_number not in self.selection.allowed_user_numbers:
            raise ChannelIngressUnavailable("Composio WhatsApp sender is outside the selected E.164 allowlist")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                               allow_nan=False).encode("utf-8")
        digest = hashlib.sha256(raw_body).hexdigest()
        return _ComposioObservation(
            owner_token=self._owner_token, selection=self.selection, request=request,
            raw_body=raw_body, headers=headers, canonical_payload=canonical,
            event_id=webhook_id, sender_number=sender_number, body_sha256=digest,
            schema_digest=self.selection.trigger_artifact_sha256,
            route_enrollment_id=route_id, route_proof=route, account_proof=account_proof,
            schema_proof=schema_proof, received_wall_time=now,
        )

    @staticmethod
    def _verify_signature(webhook_id: str, timestamp: str, body: bytes,
                          signature: str, secret: bytes) -> None:
        # Composio V3: base64(HMAC-SHA256(secret, id + "." + timestamp + "." + rawBody)).
        if not signature.startswith("v1,") or signature.count(",") != 1:
            raise ChannelIngressUnavailable("Composio webhook signature format is invalid")
        received = signature[3:]
        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", received):
            raise ChannelIngressUnavailable("Composio webhook signature is malformed")
        signing_bytes = webhook_id.encode("ascii") + b"." + timestamp.encode("ascii") + b"." + body
        expected = base64.b64encode(hmac.new(secret, signing_bytes, hashlib.sha256).digest()).decode("ascii")
        if not hmac.compare_digest(expected, received):
            raise ChannelIngressUnavailable("Composio webhook signature is invalid")

    def validate_claims(self, observation: object) -> bool:
        if type(observation) is not _ComposioObservation or observation.owner_token is not self._owner_token:
            return False
        if self._context.get() is not observation or self._current_selection() is not self.selection:
            return False
        try:
            current = self._verify_request(observation.request)
        except Exception:
            return False
        return (current.raw_body == observation.raw_body
                and current.canonical_payload == observation.canonical_payload
                and current.body_sha256 == observation.body_sha256
                and current.event_id == observation.event_id
                and current.sender_number == observation.sender_number
                and current.schema_digest == observation.schema_digest
                and current.route_enrollment_id == observation.route_enrollment_id
                and current.route_proof is observation.route_proof
                and current.account_proof is observation.account_proof
                and current.schema_proof is observation.schema_proof)

    @staticmethod
    def _decode_json(body: bytes) -> dict[str, Any]:
        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            output: dict[str, Any] = {}
            for key, value in items:
                if key in output:
                    raise ValueError("duplicate JSON key")
                output[key] = value
            return output
        try:
            value = json.loads(body, object_pairs_hook=pairs,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            raise ChannelIngressUnavailable("Composio request body is not unambiguous JSON") from None
        if not isinstance(value, dict):
            raise ChannelIngressUnavailable("Composio trigger envelope is not a JSON object")
        return value

    @staticmethod
    def _parse_iso_timestamp(value: object) -> float:
        if not isinstance(value, str) or len(value) > 64:
            raise ValueError
        from datetime import datetime
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.timestamp()

    @staticmethod
    def _json_pointer(document: Any, pointer: str) -> Any:
        current = document
        for part in pointer.split("/")[1:]:
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
                current = current[int(part)]
            else:
                return None
        return current


class NativeChannelIngressProducer:
    """Root-composed accepted-event hook for pinned Telegram and Discord SDKs.

    Construct only in the root assembly from a protected selection, active
    account-vault resolver, live-selection reader, and custody resolver.  The
    two ``install_*`` methods wrap the existing pinned SDK callback registry;
    they do not expose a public RPC or accept caller-supplied authorization
    booleans.  A proof is issued only after Hermes' own ingress gate has
    produced a normalized event.
    """

    def __init__(self, *, selection: ChannelIngressSelection,
                 current_selection: Callable[[], ChannelIngressSelection | None],
                 account_binding_reader: Callable[[object, str], str | None],
                 connector_runtime_reader: Callable[[object, object, str, str], Any], issuer: Any,
                 controller_registry: Any, replay_ledger: Any,
                 monotonic: Callable[[], float] = time.monotonic,
                 wall_time: Callable[[], float] = time.time):
        if selection.channel_name not in {"telegram", "discord"}:
            raise ChannelIngressUnavailable(
                f"{selection.channel_name} source ingress unavailable: no reviewed authenticated connector producer")
        if (not callable(current_selection) or not callable(account_binding_reader)
                or not callable(connector_runtime_reader)):
            raise ChannelIngressUnavailable(
                "protected channel selection, account binding, and pinned Hermes runtime proof readers are required")
        if not callable(getattr(issuer, "register_source_producer", None)) or not callable(
                getattr(issuer, "mint_source_proof", None)):
            raise ChannelIngressUnavailable("root resource source-event issuer is unavailable")
        if not all(callable(getattr(replay_ledger, name, None))
                   for name in ("begin", "commit", "rollback")):
            raise ChannelIngressUnavailable("durable native channel replay ledger is unavailable")
        if (not callable(getattr(controller_registry, "resolve_selected_ingress_controller", None))
                or not callable(getattr(controller_registry, "capture_selected_ingress", None))):
            raise ChannelIngressUnavailable("root selected ingress custody and event capture registry are unavailable")
        self.selection = selection
        self._current_selection = current_selection
        self._account_binding_reader = account_binding_reader
        self._connector_runtime_reader = connector_runtime_reader
        self._issuer = issuer
        self._controller_registry = controller_registry
        self._replay_ledger = replay_ledger
        self._monotonic = monotonic
        self._wall_time = wall_time
        self._owner_token = object()
        self._lock = threading.RLock()
        self._active_clients: dict[str, object] = {}
        self._active_adapters: dict[str, object] = {}
        self._accepted = 0
        self._replayed = 0
        self._installed = False
        self._installing = False
        self._context = __import__("contextvars").ContextVar(
            f"hermes_channel_ingress_{id(self)}", default=None)
        self._issuer_capability = issuer.register_source_producer(
            self, source_kind="native-input",
            observer_enrollment_id=selection.observer_enrollment_id,
            validate_provenance=self.validate_claims,
        )

    @property
    def status(self) -> NativeIngressStatus:
        with self._lock:
            reason = self._unavailable_reason()
            if reason is not None:
                return NativeIngressStatus(False, reason, self._accepted, self._replayed)
            return NativeIngressStatus(True, accepted=self._accepted, replayed=self._replayed)

    def _unavailable_reason(self) -> str | None:
        try:
            selected = self._current_selection()
        except Exception:
            return "protected current channel selection could not be read"
        if selected is not self.selection:
            return "selected channel generation changed or is unavailable"
        if not self._active_clients:
            return "selected channel connector is not initialized and authenticated"
        for platform, client in self._active_clients.items():
            try:
                account_digest = self._account_binding_reader(
                    client, self.selection.credential_vault_reference)
            except Exception:
                return "selected channel credential-vault account binding is unavailable"
            if account_digest != self.selection.account_binding_digest:
                return "selected channel credential-vault account binding is unavailable or changed"
            adapter = self._active_adapters.get(platform)
            if adapter is None or not self._valid_runtime_proof(client, adapter, platform):
                return "selected Hermes connector process/package proof is unavailable or stale"
        if not self._installed:
            return "selected channel ingress callback is not installed"
        return None

    def install_telegram(self, application: object, adapter: object) -> None:
        """Wrap only Telegram's registered PTB message callbacks and event seam.

        The function intentionally requires Python Telegram Bot's actual
        Application/handler objects and the adapter's own registered bound
        methods. A detached or reconstructed MessageEvent cannot enter the
        callback context.
        """
        if self.selection.channel_name != "telegram":
            raise ChannelIngressUnavailable("selected resource is not Telegram")
        try:
            from telegram.ext import Application, MessageHandler as TelegramMessageHandler
        except ImportError as exc:
            raise ChannelIngressUnavailable("python-telegram-bot is not installed in the selected Hermes runtime") from exc
        if not isinstance(application, Application):
            raise ChannelIngressUnavailable("Telegram Application is not the pinned SDK instance")
        if getattr(adapter, "_app", None) is not application:
            raise ChannelIngressUnavailable("Telegram adapter is bound to a different Application")
        if not self._valid_runtime_proof(application, adapter, "telegram"):
            raise ChannelIngressUnavailable("Telegram adapter is not loaded from the selected pinned Hermes runtime")
        handlers = getattr(application, "handlers", None)
        if not isinstance(handlers, dict):
            raise ChannelIngressUnavailable("Telegram Application handler registry is unavailable")
        registrations: list[tuple[object, Callable[..., Any]]] = []
        for group in handlers.values():
            for handler in group:
                callback = getattr(handler, "callback", None)
                if (isinstance(handler, TelegramMessageHandler) and callable(callback)
                        and getattr(callback, "__self__", None) is adapter
                        and getattr(callback, "__name__", "") in {
                            "_handle_text_message", "_handle_command", "_handle_location_message",
                            "_handle_media_message"}):
                    registrations.append((handler, callback))
        if len(registrations) < 3:
            raise ChannelIngressUnavailable("Telegram registered message callback set does not match the pinned adapter")
        self._install_client("telegram", application, adapter)
        try:
            for handler, callback in registrations:
                async def guarded(update: object, context: object, *, _callback=callback) -> Any:
                    if getattr(context, "application", None) is not application:
                        raise ChannelIngressUnavailable("Telegram callback is detached from its live Application")
                    if not self._is_telegram_update(update):
                        raise ChannelIngressUnavailable("Telegram callback did not receive a pinned SDK Update")
                    token = self._context.set(("telegram", application, update, None))
                    try:
                        return await _callback(update, context)
                    finally:
                        self._context.reset(token)
                handler.callback = guarded
            self._wrap_event_seam(adapter, "_build_triggered_event", "telegram", application)
            self._wrap_event_seam(adapter, "handle_message", "telegram", application)
        except BaseException:
            self._uninstall_client("telegram", application)
            raise

    def install_discord(self, client: object, adapter: object) -> None:
        """Wrap the pinned discord.py registered ``on_message`` dispatch route."""
        if self.selection.channel_name != "discord":
            raise ChannelIngressUnavailable("selected resource is not Discord")
        try:
            import discord
            from discord.ext import commands
        except ImportError as exc:
            raise ChannelIngressUnavailable("discord.py is not installed in the selected Hermes runtime") from exc
        if not isinstance(client, commands.Bot):
            raise ChannelIngressUnavailable("Discord client is not the pinned discord.py Bot instance")
        if getattr(adapter, "_client", None) is not client:
            raise ChannelIngressUnavailable("Discord adapter is bound to a different Bot")
        if not self._valid_runtime_proof(client, adapter, "discord"):
            raise ChannelIngressUnavailable("Discord adapter is not loaded from the selected pinned Hermes runtime")
        callback = getattr(client, "on_message", None)
        if not callable(callback):
            raise ChannelIngressUnavailable("Discord registered on_message callback is unavailable")
        callback_function = getattr(callback, "__func__", callback)
        closure = getattr(callback_function, "__closure__", None) or ()
        closure_owns_adapter = False
        for cell in closure:
            try:
                closure_owns_adapter = closure_owns_adapter or cell.cell_contents is adapter
            except ValueError:
                continue
        if not closure_owns_adapter:
            raise ChannelIngressUnavailable("Discord on_message callback is not the selected Hermes adapter closure")
        self._install_client("discord", client, adapter)

        async def guarded(message: object) -> Any:
            if not self._is_discord_message(message):
                raise ChannelIngressUnavailable("Discord callback did not receive a pinned SDK Message")
            token = self._context.set(("discord", client, message, None))
            try:
                return await callback(message)
            finally:
                self._context.reset(token)

        setattr(client, "on_message", guarded)
        try:
            self._wrap_event_seam(adapter, "handle_message", "discord", client)
        except BaseException:
            setattr(client, "on_message", callback)
            self._uninstall_client("discord", client)
            raise

    def _install_client(self, platform: str, client: object, adapter: object) -> None:
        with self._lock:
            if self._installed or self._installing:
                raise ChannelIngressUnavailable("native channel ingress producer is already installed")
            if self._current_selection() is not self.selection:
                raise ChannelIngressUnavailable("selected channel row is stale")
            binding = self._account_binding_reader(client, self.selection.credential_vault_reference)
            if binding != self.selection.account_binding_digest:
                raise ChannelIngressUnavailable("selected channel account credential is unavailable or mismatched")
            if self._active_clients:
                raise ChannelIngressUnavailable("one producer cannot bind multiple connector sessions")
            self._active_clients[platform] = client
            self._active_adapters[platform] = adapter
            self._installing = True

    def _uninstall_client(self, platform: str, client: object) -> None:
        with self._lock:
            if self._active_clients.get(platform) is client:
                self._active_clients.pop(platform, None)
                self._active_adapters.pop(platform, None)
            self._installing = False
            self._installed = False

    def _wrap_event_seam(self, adapter: object, method_name: str, platform: str, client: object) -> None:
        original = getattr(adapter, method_name, None)
        if not callable(original):
            raise ChannelIngressUnavailable(f"pinned Hermes adapter lacks {method_name} accepted-event seam")
        producer = self

        if asyncio.iscoroutinefunction(original):
            async def wrapped(*args: Any, **kwargs: Any) -> Any:
                invocation = producer._context.get()
                eligible = (invocation is not None and invocation[0] == platform
                            and invocation[1] is client)
                result = await original(*args, **kwargs)
                if eligible:
                    raw = invocation[2]
                    event = result if method_name == "_build_triggered_event" else (
                        args[0] if args else kwargs.get("event"))
                    if producer._event_matches(platform, raw, event):
                        producer._accept_native_event(platform, client, raw, event)
                return result
        else:
            def wrapped(*args: Any, **kwargs: Any) -> Any:
                invocation = producer._context.get()
                eligible = (invocation is not None and invocation[0] == platform
                            and invocation[1] is client)
                result = original(*args, **kwargs)
                if eligible:
                    raw = invocation[2]
                    event = args[0] if args else kwargs.get("event")
                    if producer._event_matches(platform, raw, event):
                        producer._accept_native_event(platform, client, raw, event)
                return result
        setattr(adapter, method_name, wrapped)
        with self._lock:
            self._installed = True
            self._installing = False

    @staticmethod
    def _is_telegram_update(update: object) -> bool:
        try:
            from telegram import Update
            return type(update) is Update
        except ImportError:
            return False

    @staticmethod
    def _is_discord_message(message: object) -> bool:
        try:
            import discord
            return type(message) is discord.Message
        except ImportError:
            return False

    def _event_matches(self, platform: str, raw: object, event: object) -> bool:
        if event is None or not isinstance(getattr(event, "text", None), str):
            return False
        source = getattr(event, "source", None)
        raw_message = getattr(event, "raw_message", None)
        if platform == "telegram":
            message = getattr(raw, "effective_message", None) or getattr(raw, "message", None)
            update_id = getattr(raw, "update_id", None)
            if (message is None or raw_message is not message
                    or getattr(event, "platform_update_id", None) != update_id
                    or getattr(source, "platform", None) != "telegram"
                    or str(getattr(source, "chat_id", "")) != str(getattr(getattr(message, "chat", None), "id", ""))
                    or str(getattr(source, "user_id", "")) != str(getattr(getattr(message, "from_user", None), "id", ""))
                    or str(getattr(source, "message_id", "")) != str(getattr(message, "message_id", ""))):
                return False
            return True
        if raw_message is not raw or getattr(source, "platform", None) != "discord":
            return False
        guild = getattr(raw, "guild", None)
        guild_id = str(getattr(guild, "id", "")) if guild is not None else ""
        return bool(guild_id and str(getattr(source, "guild_id", "")) == guild_id
                    and str(getattr(source, "user_id", "")) == str(getattr(getattr(raw, "author", None), "id", ""))
                    and str(getattr(source, "message_id", "")) == str(getattr(raw, "id", "")))

    def _accept_native_event(self, platform: str, client: object, raw: object, event: object) -> None:
        selection = self._current_selection()
        if selection is not self.selection:
            raise ChannelIngressUnavailable("selected resource or channel generation changed")
        if self._active_clients.get(platform) is not client:
            raise ChannelIngressUnavailable("native connector session is no longer selected")
        account_digest = self._account_binding_reader(client, selection.credential_vault_reference)
        if account_digest != selection.account_binding_digest:
            raise ChannelIngressUnavailable("native connector credential/account binding changed")
        scope_id, sender_id, key = self._scope_sender_key(platform, raw, event)
        if scope_id not in selection.allowed_scopes:
            return
        now = self._monotonic()
        payload = self._canonical_payload(platform, raw, event, scope_id, sender_id, key)
        body_digest = hashlib.sha256(payload).hexdigest()
        reservation = self._replay_ledger.begin(
            selection.resource_id, f"{platform}:{key}", body_digest,
            self._wall_time() + _DEDUP_TTL,
        )
        if getattr(reservation, "state", None) == "duplicate":
            if getattr(reservation, "body_sha256", None) != body_digest:
                raise ChannelIngressUnavailable("native channel replay identity conflicts with a different payload")
            with self._lock:
                self._replayed += 1
            return
        if (getattr(reservation, "state", None) != "reserved"
                or getattr(reservation, "body_sha256", None) != body_digest):
            raise ChannelIngressUnavailable("durable native channel replay ledger rejected or conflicted with this event")
        observation = _NativeCallback(
            owner_token=self._owner_token, platform=platform, client=client, raw=raw,
            event=event, message=getattr(event, "raw_message"), callback_nonce=object(),
            update_key=key, scope_id=scope_id, sender_id=sender_id,
            canonical_payload=payload, selection_digest=selection.selected_config_digest,
            account_binding_digest=account_digest, received_monotonic=now,
        )
        event_id = "e" + secrets.token_urlsafe(32)
        try:
            proof = self._issuer.mint_source_proof(
                self._issuer_capability, event_id=event_id,
                resource_id=selection.resource_id, resource_generation=selection.generation,
                source_observer_enrollment_id=selection.observer_enrollment_id,
                payload=payload, provenance=observation,
            )
            selected_ingress = self._controller_registry.resolve_selected_ingress_controller(
                self.selection.controller_role_id,
                self.selection.source_issuer_id,
                self.selection.backend_id,
            )
            proof_handle = getattr(selected_ingress, "proof_handle", None)
            if not isinstance(proof_handle, str) or not _IDENTIFIER.fullmatch(proof_handle):
                raise ChannelIngressUnavailable("root selected native ingress proof is malformed")
            captured = self._controller_registry.capture_selected_ingress(proof_handle, proof)
            self._replay_ledger.commit(reservation, captured)
        except BaseException:
            self._replay_ledger.rollback(reservation)
            raise
        with self._lock:
            self._accepted += 1

    def _scope_sender_key(self, platform: str, raw: object, event: object) -> tuple[str, str, str]:
        if platform == "telegram":
            message = getattr(raw, "effective_message", None) or getattr(raw, "message", None)
            chat_id = str(getattr(getattr(message, "chat", None), "id", ""))
            sender_id = str(getattr(getattr(message, "from_user", None), "id", ""))
            update_id = getattr(raw, "update_id", None)
            message_id = getattr(message, "message_id", None)
            if not chat_id or not sender_id or type(update_id) is not int or type(message_id) is not int:
                raise ChannelIngressUnavailable("Telegram Update lacks authenticated chat, sender, or update identity")
            return chat_id, sender_id, f"{update_id}:{message_id}"
        guild_id = str(getattr(getattr(raw, "guild", None), "id", ""))
        sender_id = str(getattr(getattr(raw, "author", None), "id", ""))
        message_id = str(getattr(raw, "id", ""))
        if not guild_id or not sender_id or not message_id:
            raise ChannelIngressUnavailable("Discord Message lacks guild, sender, or message identity")
        return guild_id, sender_id, message_id

    def _canonical_payload(self, platform: str, raw: object, event: object,
                           scope_id: str, sender_id: str, key: str) -> bytes:
        if platform == "telegram":
            message = getattr(raw, "effective_message", None) or getattr(raw, "message", None)
            message_type = getattr(getattr(event, "message_type", None), "value", "text")
            source_id = str(getattr(message, "message_id"))
            update_id: int | None = getattr(raw, "update_id")
            chat_id = scope_id
            timestamp = getattr(event, "timestamp", None)
        else:
            message = raw
            message_type = getattr(getattr(event, "message_type", None), "value", "text")
            source_id = str(getattr(raw, "id"))
            update_id = None
            chat_id = str(getattr(getattr(raw, "channel", None), "id", ""))
            timestamp = getattr(event, "timestamp", None)
        body = {
            "schema": "hermes.native-channel-event/v1", "platform": platform,
            "update_key": key, "message_id": source_id, "update_id": update_id,
            "scope_id": scope_id, "chat_id": chat_id, "sender_id": sender_id,
            "message_type": str(message_type), "text": event.text,
            "timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else None,
            "media_urls": list(getattr(event, "media_urls", ()) or ())[:32],
            "media_types": list(getattr(event, "media_types", ()) or ())[:32],
            "selection_digest": self.selection.selected_config_digest,
            "account_binding_digest": self.selection.account_binding_digest,
        }
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(payload) > _MAX_PAYLOAD:
            raise ChannelIngressUnavailable("native channel event exceeds the 256 KiB source-event bound")
        return payload

    def validate_claims(self, provenance: object) -> bool:
        """Issuer callback: revalidate instance seal, callback stack and live bindings."""
        if type(provenance) is not _NativeCallback or provenance.owner_token is not self._owner_token:
            return False
        invocation = self._context.get()
        if (invocation is None or invocation[0] != provenance.platform
                or invocation[1] is not provenance.client or invocation[2] is not provenance.raw):
            return False
        if self._active_clients.get(provenance.platform) is not provenance.client:
            return False
        try:
            if self._current_selection() is not self.selection:
                return False
            adapter = self._active_adapters.get(provenance.platform)
            if adapter is None or not self._valid_runtime_proof(
                    provenance.client, adapter, provenance.platform):
                return False
            if self._account_binding_reader(provenance.client, self.selection.credential_vault_reference) != provenance.account_binding_digest:
                return False
        except Exception:
            return False
        if (provenance.account_binding_digest != self.selection.account_binding_digest
                or provenance.selection_digest != self.selection.selected_config_digest
                or provenance.message is not getattr(provenance.event, "raw_message", None)
                or not self._event_matches(provenance.platform, provenance.raw, provenance.event)):
            return False
        try:
            scope_id, sender_id, key = self._scope_sender_key(
                provenance.platform, provenance.raw, provenance.event)
        except ChannelIngressUnavailable:
            return False
        return (scope_id == provenance.scope_id and sender_id == provenance.sender_id
                and key == provenance.update_key and scope_id in self.selection.allowed_scopes
                and self._canonical_payload(provenance.platform, provenance.raw, provenance.event,
                                            scope_id, sender_id, key) == provenance.canonical_payload)

    def _valid_runtime_proof(self, client: object, adapter: object, platform: str) -> bool:
        """Require revalidatable loaded-package and peer evidence, never a boolean."""
        try:
            proof = self._connector_runtime_reader(
                client, adapter, platform, PINNED_HERMES_REVISION)
            if proof is None or isinstance(proof, (bool, str, bytes, int, float, dict, list, tuple)):
                return False
            revalidate = getattr(proof, "revalidate", None)
            if not callable(revalidate) or revalidate() is not True:
                return False
            if getattr(proof, "source_revision", None) != PINNED_HERMES_REVISION:
                return False
            if not _SHA256.fullmatch(str(getattr(proof, "loaded_module_sha256", ""))):
                return False
            if not _IDENTIFIER.fullmatch(str(getattr(proof, "profile_process_handle", ""))):
                return False
            return True
        except Exception:
            return False
