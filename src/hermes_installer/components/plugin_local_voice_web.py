"""Bounded native adapters for local Kanban, local Wyoming voice and web reads.

All side effects cross typed services injected by the trusted host. This module
contains no shell, socket, microphone, credential, or persistence discovery.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from ipaddress import ip_address
import json
import re
import time
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from hermes_installer.components.plugin_local_voice_web_schemas import PLUGIN_ACTION_SCHEMAS


class PluginAdapterError(RuntimeError):
    """A selected plugin service is missing or rejected the bounded request."""


class ToolContext(Protocol):
    def register_tool(self, name: str, toolset: str, schema: dict[str, Any],
                      handler: Any, **kwargs: Any) -> object: ...


@dataclass(frozen=True, slots=True)
class WebResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    final_url: str
    connected_ip: str
    tls_verified: bool
    used_proxy: bool
    tls_peer_sha256: str = ""


class PluginRuntime(Protocol):
    """Protected runtime extension surface; never populated from resource YAML."""
    identity: object
    plugin_effects: object | None
    voice_session_enrollment_id: str | None


class PluginEffectResolver(Protocol):
    """Root-authorized finite action resolver. Tool args never select targets."""
    def invoke(self, *, adapter_id: str, action_id: str,
               arguments: dict[str, Any], idempotency_key: str | None = None,
               opaque_confirmation_attestation_id: str | None = None) -> object: ...


class LocalKanbanImplementation:
    def register(self, ctx: ToolContext, runtime_context: PluginRuntime) -> None:
        _require_plugin_identity(runtime_context, "epic-kanban")
        effects = getattr(runtime_context, "plugin_effects", None)
        if not callable(getattr(effects, "invoke", None)):
            raise PluginAdapterError("protected selected-plugin effects are not enrolled")
        LocalKanbanPlugin(effects).register(ctx, runtime_context)


class WyomingVoiceImplementation:
    def register(self, ctx: ToolContext, runtime_context: PluginRuntime) -> None:
        _require_plugin_identity(runtime_context, "voice-pipeline")
        effects = getattr(runtime_context, "plugin_effects", None)
        if not callable(getattr(effects, "invoke", None)):
            raise PluginAdapterError("protected selected-plugin effects are not enrolled")
        enrollment_id = getattr(runtime_context, "voice_session_enrollment_id", None)
        _bounded_text(enrollment_id, "root-selected voice session enrollment", 128)
        WyomingVoicePlugin(effects, enrollment_id).register(ctx, runtime_context)


class PublicWebImplementation:
    def register(self, ctx: ToolContext, runtime_context: PluginRuntime) -> None:
        _require_plugin_identity(runtime_context, "web")
        effects = getattr(runtime_context, "plugin_effects", None)
        if not callable(getattr(effects, "invoke", None)):
            raise PluginAdapterError("protected selected-plugin effects are not enrolled")
        PublicWebPlugin(effects).register(ctx, runtime_context)


PLUGIN_IMPLEMENTATIONS = {
    "epic-kanban": LocalKanbanImplementation(),
    "voice-pipeline": WyomingVoiceImplementation(),
    "web": PublicWebImplementation(),
}


class LocalKanbanPlugin:
    """Per-profile ephemeral board CRUD; GitHub Projects is intentionally separate."""
    ACTIONS = {"create": "create", "read": "read", "add_item": "add_item",
               "move_item": "move_item", "delete_accepted": "delete_accepted"}
    def __init__(self, effects: PluginEffectResolver):
        if not callable(getattr(effects, "invoke", None)):
            raise TypeError("Epic board tools require the root plugin effect resolver")
        self.effects = effects

    def register(self, ctx: ToolContext, runtime_context: object) -> None:
        ctx.register_tool("epic_board", "epic_kanban", {
            "type": "object", "properties": {
                "operation": {"enum": ["create", "read", "add_item", "move_item", "delete_accepted"]},
                "epic_id": {"type": "string", "maxLength": 80},
                "board_id": {"type": "string", "maxLength": 80},
                "title": {"type": "string", "maxLength": 256},
                "item_type": {"enum": ["epic", "user-story", "task", "defect", "spike", "risk", "decision"]},
                "description": {"type": "string", "maxLength": 16384},
                "item_id": {"type": "string", "maxLength": 80},
                "state": {"enum": ["backlog", "ready", "in-progress", "review", "blocked", "done"]},
                "accepted_lifecycle_attestation_id": {"type": "string", "minLength": 8, "maxLength": 128},
            }, "required": ["operation"], "additionalProperties": False,
        }, self.invoke, description="Manage one local ephemeral board for the selected Epic.")

    def invoke(self, *, operation: str, epic_id: str | None = None,
               board_id: str | None = None, title: str = "", item_type: str | None = None,
               description: str = "", item_id: str | None = None, state: str | None = None,
               accepted_lifecycle_attestation_id: str | None = None) -> dict[str, Any]:
        if operation == "create":
            _bounded_text(epic_id, "epic_id", 80)
            _bounded_text(title, "title", 256)
            return _invoke_plugin_effect(self.effects, "epic-kanban", self.ACTIONS[operation],
                                         {"epic_id": epic_id, "title": title})
        if operation == "read":
            return _invoke_plugin_effect(self.effects, "epic-kanban", self.ACTIONS[operation],
                                         {"board_id": _board_id(board_id)})
        if operation == "add_item":
            _bounded_text(item_type, "item_type", 32)
            if item_type not in {"epic", "user-story", "task", "defect", "spike", "risk", "decision"}:
                raise PluginAdapterError("item_type is outside the enrolled Epic schema")
            _bounded_text(title, "title", 256)
            if not isinstance(description, str) or len(description) > 16384:
                raise PluginAdapterError("description exceeds the enrolled Epic schema")
            return _invoke_plugin_effect(self.effects, "epic-kanban", self.ACTIONS[operation],
                                         {"board_id": _board_id(board_id), "item_type": item_type,
                                          "title": title, "description": description})
        if operation == "move_item":
            _bounded_text(item_id, "item_id", 80)
            if state not in {"backlog", "ready", "in-progress", "review", "blocked", "done"}:
                raise PluginAdapterError("state is outside the enrolled Epic workflow")
            return _invoke_plugin_effect(self.effects, "epic-kanban", self.ACTIONS[operation],
                                         {"board_id": _board_id(board_id), "item_id": item_id,
                                          "state": state})
        if operation == "delete_accepted":
            _bounded_text(accepted_lifecycle_attestation_id, "accepted_lifecycle_attestation_id", 128)
            return _invoke_plugin_effect(self.effects, "epic-kanban", self.ACTIONS[operation],
                                         {"board_id": _board_id(board_id),
                                          "accepted_lifecycle_attestation_id": accepted_lifecycle_attestation_id})
        raise PluginAdapterError("unsupported local board operation")


class WyomingVoicePlugin:
    """Session-only local voice adapter; never stores or returns raw audio."""
    def __init__(self, effects: PluginEffectResolver, session_enrollment_id: str):
        if not callable(getattr(effects, "invoke", None)):
            raise TypeError("voice tools require the root plugin effect resolver")
        _bounded_text(session_enrollment_id, "root-selected voice session enrollment", 128)
        self.effects, self.session_enrollment_id = effects, session_enrollment_id

    def register(self, ctx: ToolContext, runtime_context: object) -> None:
        ctx.register_tool("voice_transcribe", "voice_pipeline", {
            "type": "object", "properties": {"mode": {"enum": ["general", "home_control"]}},
            "required": ["mode"], "additionalProperties": False,
        }, self.transcribe, description="Transcribe microphone input captured from the authorized current session.")
        ctx.register_tool("voice_speak", "voice_pipeline", {
            "type": "object", "properties": {"text": {"type": "string", "maxLength": 16384}},
            "required": ["text"], "additionalProperties": False,
        }, self.speak, description="Speak text through the enrolled local Piper endpoint in the current session.")

    def transcribe(self, *, mode: str) -> dict[str, Any]:
        if mode not in {"general", "home_control"}:
            raise PluginAdapterError("unknown utterance kind")
        session = _invoke_plugin_effect(self.effects, "voice-pipeline", "open_session", {
            "session_enrollment_id": self.session_enrollment_id,
            "direction": "input", "requested_lease_seconds": 60})
        session_handle, expires = _voice_session(session)
        try:
            artifact = _invoke_plugin_effect(self.effects, "voice-pipeline", "capture_audio", {
                "session_handle": session_handle, "maximum_seconds": 30})
            audio_id = _opaque_handle(artifact, "audio_artifact_id")
            if type(artifact.get("size_bytes")) is not int or not 1 <= artifact["size_bytes"] <= 16_777_216:
                raise PluginAdapterError("root voice capture returned an invalid bounded audio receipt")
            if not isinstance(artifact.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", artifact["sha256"]):
                raise PluginAdapterError("root voice capture returned an invalid content digest")
            if time.monotonic() >= expires:
                raise PluginAdapterError("root voice capture session expired before transcription")
            result = _invoke_plugin_effect(self.effects, "voice-pipeline", "voice_transcribe", {
                "session_handle": session_handle, "audio_artifact_id": audio_id, "mode": mode})
            if (set(result) != {"schema", "transcript", "source_receipt_handle", "profile_id",
                                "owner_generation", "operation_id", "expires_monotonic"}
                    or result.get("schema") != 1
                    or not isinstance(result.get("transcript"), str)
                    or len(result["transcript"]) > 65_536
                    or not _opaque_value(result.get("source_receipt_handle"))
                    or not all(isinstance(result.get(k), str) and result[k]
                               for k in ("profile_id", "owner_generation", "operation_id"))
                    or isinstance(result.get("expires_monotonic"), bool)
                    or not isinstance(result.get("expires_monotonic"), (int, float))
                    or result["expires_monotonic"] <= time.monotonic()):
                raise PluginAdapterError("local STT returned invalid transcript provenance")
            return result
        finally:
            _invoke_plugin_effect(self.effects, "voice-pipeline", "close_session",
                                  {"session_handle": session_handle})

    def speak(self, *, text: str) -> dict[str, Any]:
        _bounded_text(text, "text", 16384)
        session = _invoke_plugin_effect(self.effects, "voice-pipeline", "open_session", {
            "session_enrollment_id": self.session_enrollment_id,
            "direction": "output", "requested_lease_seconds": 60})
        session_handle, _expires = _voice_session(session)
        try:
            result = _invoke_plugin_effect(self.effects, "voice-pipeline", "voice_speak",
                                           {"session_handle": session_handle, "text": text})
            if set(result) != {"audio_artifact"} or not _valid_artifact_receipt(result["audio_artifact"]):
                raise PluginAdapterError("local Piper returned no bounded output receipt")
            return result
        finally:
            _invoke_plugin_effect(self.effects, "voice-pipeline", "close_session",
                                  {"session_handle": session_handle})


class PublicWebPlugin:
    """HTTPS-only, bounded retrieval with per-hop policy checks and receipt provenance."""
    MAX_BYTES = 1_000_000
    MAX_REDIRECTS = 4

    def __init__(self, dispatcher: PluginEffectResolver):
        if not callable(getattr(dispatcher, "invoke", None)):
            raise TypeError("web retrieval requires the root plugin effect resolver")
        self.dispatcher = dispatcher

    def register(self, ctx: ToolContext, runtime_context: object) -> None:
        ctx.register_tool("web_retrieve", "web", {
            "type": "object", "properties": {"url": {"type": "string", "maxLength": 2048}},
            "required": ["url"], "additionalProperties": False,
        }, self.retrieve, description="Retrieve bounded public HTTPS content as untrusted source material.")

    def retrieve(self, *, url: str) -> dict[str, Any]:
        canonical = _public_https_url(url)
        value = _invoke_plugin_effect(self.dispatcher, "web", "retrieve", {"url": canonical})
        if (value.get("untrusted_source") is not True or value.get("authority") != "none"
                or not isinstance(value.get("source_receipt"), dict)):
            raise PluginAdapterError("protected web read result lacks untrusted source provenance")
        return value


def _bounded_text(value: object, label: str, maximum: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise PluginAdapterError(f"{label} must be bounded non-empty text")


def _invoke_plugin_effect(effects: PluginEffectResolver, adapter_id: str, action_id: str,
                          arguments: dict[str, Any]) -> dict[str, Any]:
    invoke = getattr(effects, "invoke", None)
    if not callable(invoke):
        raise PluginAdapterError("protected selected-plugin effects are unavailable")
    actions = {"epic-kanban": {"create", "read", "add_item", "move_item", "delete_accepted"},
               "voice-pipeline": {"open_session", "capture_audio", "close_session",
                                  "voice_transcribe", "voice_speak"},
               "web": {"retrieve"}}
    if (adapter_id not in actions or action_id not in actions[adapter_id]
            or not isinstance(arguments, dict)):
        raise PluginAdapterError("plugin action is outside the fixed local schema")
    action_schema = PLUGIN_ACTION_SCHEMAS[(adapter_id, action_id)]
    invoke_options: dict[str, Any] = {}
    if action_schema.requires_idempotency:
        canonical = json.dumps({"adapter_id": adapter_id, "action_id": action_id,
                                "arguments": arguments}, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False,
                               allow_nan=False).encode("utf-8")
        invoke_options["idempotency_key"] = hashlib.sha256(canonical).hexdigest()
    envelope = invoke(adapter_id=adapter_id, action_id=action_id,
                      arguments=arguments, **invoke_options)
    expected_envelope = {"schema", "operation_id", "state", "result", "verification_status", "resume_action_id"}
    if (not isinstance(envelope, dict) or set(envelope) != expected_envelope
            or type(envelope.get("schema")) is not int or envelope["schema"] != 1
            or not isinstance(envelope.get("operation_id"), str)
            or not 1 <= len(envelope["operation_id"]) <= 128
            or envelope.get("state") not in {"read-complete", "committed", "pending", "ambiguous", "unavailable"}
            or not isinstance(envelope.get("verification_status"), str)
            or (envelope.get("resume_action_id") is not None
                and not isinstance(envelope["resume_action_id"], str))):
        raise PluginAdapterError("root plugin effect returned an invalid operation envelope")
    if envelope["state"] not in {"read-complete", "committed"}:
        raise PluginAdapterError(f"plugin action is {envelope['state']}; use its root resume action if provided")
    if envelope["state"] != action_schema.expected_state:
        raise PluginAdapterError("root plugin effect state does not match the selected action")
    result = envelope["result"]
    result_fields = {
        "create": {"board_id"}, "read": {"board"}, "add_item": {"item_id"},
        "move_item": {"state"}, "delete_accepted": {"receipt_id"},
        "open_session": {"session_handle", "expires_monotonic"},
        "capture_audio": {"audio_artifact_id", "sha256", "size_bytes"},
        "close_session": {"closed"},
        "voice_transcribe": {"schema", "transcript", "source_receipt_handle", "profile_id",
                             "owner_generation", "operation_id", "expires_monotonic"},
        "voice_speak": {"audio_artifact"},
        "retrieve": {"url", "content_type", "content", "untrusted_source", "authority",
                     "redirects", "source_receipt"},
    }[action_id]
    if not isinstance(result, dict) or set(result) != result_fields:
        raise PluginAdapterError("root plugin effect result must be a schema-bound object")
    try:
        encoded_result = json.dumps(result, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise PluginAdapterError("root plugin effect result is not valid JSON data") from None
    if len(encoded_result) > 2_097_152:
        raise PluginAdapterError("root plugin effect result exceeds its byte limit")
    return result


def _opaque_handle(result: dict[str, Any], field: str) -> str:
    value = result.get(field) if isinstance(result, dict) else None
    if not isinstance(value, str) or not 8 <= len(value) <= 128 or any(ord(c) < 33 for c in value):
        raise PluginAdapterError(f"root voice effect returned an invalid {field}")
    return value


def _opaque_value(value: object) -> bool:
    return isinstance(value, str) and 8 <= len(value) <= 128 and not any(ord(c) < 33 for c in value)


def _valid_artifact_receipt(receipt: object) -> bool:
    if not isinstance(receipt, dict) or set(receipt) != {
        "artifact_id", "sha256", "size_bytes", "media_type", "profile_id",
        "owner_generation", "operation_id", "source_receipt_handle", "expires_monotonic",
    }:
        return False
    return (_opaque_value(receipt.get("artifact_id"))
            and isinstance(receipt.get("sha256"), str)
            and re.fullmatch(r"[a-f0-9]{64}", receipt["sha256"]) is not None
            and type(receipt.get("size_bytes")) is int
            and 1 <= receipt["size_bytes"] <= 16_777_216
            and all(isinstance(receipt.get(k), str) and receipt[k]
                    for k in ("media_type", "profile_id", "owner_generation", "operation_id"))
            and _opaque_value(receipt.get("source_receipt_handle"))
            and isinstance(receipt.get("expires_monotonic"), (int, float))
            and not isinstance(receipt.get("expires_monotonic"), bool)
            and receipt["expires_monotonic"] > time.monotonic())


def _voice_session(result: dict[str, Any]) -> tuple[str, float]:
    handle = _opaque_handle(result, "session_handle")
    expiry = result.get("expires_monotonic") if isinstance(result, dict) else None
    if (isinstance(expiry, bool) or not isinstance(expiry, (int, float))
            or not time.monotonic() < expiry <= time.monotonic() + 60.0):
        raise PluginAdapterError("root voice session returned an invalid or expired lease")
    return handle, float(expiry)


def _require_plugin_identity(runtime_context: object, expected: str) -> None:
    identity = getattr(runtime_context, "identity", None)
    if (getattr(identity, "kind", None) != "plugins"
            or getattr(identity, "resource_id", None) != expected):
        raise PluginAdapterError(f"trusted selected Plugin identity must be {expected}")


def _board_id(value: object) -> str:
    _bounded_text(value, "board_id", 80)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", value):
        raise PluginAdapterError("invalid board id")
    return value


def _public_https_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise PluginAdapterError("URL is missing or too long")
    try:
        p = urlsplit(value)
        port = p.port
    except ValueError:
        raise PluginAdapterError("URL is malformed") from None
    if (p.scheme != "https" or not p.hostname or p.username or p.password
            or "@" in p.netloc or p.fragment):
        raise PluginAdapterError("only public HTTPS URLs without credentials or fragments are allowed")
    host = p.hostname.rstrip(".").lower()
    try:
        addr = ip_address(host)
        if not addr.is_global:
            raise PluginAdapterError("private or reserved address is denied")
    except ValueError:
        if "." not in host or host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
            raise PluginAdapterError("private or non-public hostname is denied")
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise PluginAdapterError("hostname is malformed") from None
    if port not in {None, 443}:
        raise PluginAdapterError("only HTTPS port 443 is permitted")
    if any(ord(c) < 32 for c in value):
        raise PluginAdapterError("control characters are denied")
    rendered_host = f"[{host}]" if ":" in host else host
    return urlunsplit(("https", rendered_host, p.path or "/", p.query, ""))
