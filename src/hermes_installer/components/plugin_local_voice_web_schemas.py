"""Source-reviewed immutable RB08 action schemas for local/web Plugins.

The adapter digest is filled from the checked-in component implementation
before publication; this catalog is separate so its value does not create a
self-referential source hash.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Any

from hermes_installer.components.plugin_effects import PluginActionSchema

# Updated with the SHA-256 of plugin_local_voice_web.py before each published
# source cohort. Selected enrollments must match this exact source digest.
PLUGIN_LOCAL_VOICE_WEB_ADAPTER_SHA256 = "8acfd074698c12242efeab9059830db0388df2e24392d044cc0ab7696cf06487"


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _row(adapter: str, action: str, operation: str, arguments: dict[str, Any],
         result: dict[str, Any], *, expected_state: str = "read-complete",
         requires_idempotency: bool = False,
         argument_schema_id: str | None = None,
         result_schema_id: str | None = None) -> PluginActionSchema:
    return PluginActionSchema(
        adapter_id=adapter,
        action_id=action,
        argument_schema_id=argument_schema_id or f"{adapter}.{action}.arguments.v1",
        result_schema_id=result_schema_id or f"{adapter}.{action}.result.v1",
        operation=operation,
        adapter_sha256=PLUGIN_LOCAL_VOICE_WEB_ADAPTER_SHA256,
        argument_schema=_freeze(arguments),
        result_schema=_freeze(result),
        requires_idempotency=requires_idempotency,
        expected_state=expected_state,
    )


def _obj(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required,
            "additionalProperties": False}


def _string(maximum: int, minimum: int = 0) -> dict[str, Any]:
    return {"type": "string", "minLength": minimum, "maxLength": maximum}


def _simple_string_result(name: str) -> dict[str, Any]:
    return _obj({name: _string(128, 1)}, [name])


def _source_receipt() -> dict[str, Any]:
    return _obj({
        "url": _string(2048, 1), "content_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "byte_length": {"type": "integer", "minimum": 0, "maximum": 2_097_152},
        "status": {"type": "integer", "minimum": 200, "maximum": 299},
        "peer_ip": _string(64, 1), "tls_peer_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "retrieved_at_unix": {"type": "integer", "minimum": 1},
        "redirect_chain": {"type": "array", "items": _string(2048, 1), "minItems": 1, "maxItems": 5},
        "enrollment_id": _string(128, 1), "generation": _string(128, 1),
        "receipt_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
    }, ["url", "content_sha256", "byte_length", "status", "peer_ip", "tls_peer_sha256",
        "retrieved_at_unix", "redirect_chain", "enrollment_id", "generation", "receipt_sha256"])


def _artifact_receipt() -> dict[str, Any]:
    return _obj({
        "artifact_id": _string(128, 8),
        "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "size_bytes": {"type": "integer", "minimum": 1, "maximum": 16_777_216},
        "media_type": _string(128, 1), "profile_id": _string(128, 1),
        "owner_generation": _string(128, 1), "operation_id": _string(128, 1),
        "source_receipt_handle": _string(128, 8),
        "expires_monotonic": {"type": "number", "minimum": 0},
    }, ["artifact_id", "sha256", "size_bytes", "media_type", "profile_id",
        "owner_generation", "operation_id", "source_receipt_handle", "expires_monotonic"])


def _stt_receipt() -> dict[str, Any]:
    return _obj({
        "schema": {"type": "integer", "enum": [1]},
        "transcript": _string(65_536),
        "source_receipt_handle": _string(128, 8),
        "profile_id": _string(128, 1), "owner_generation": _string(128, 1),
        "operation_id": _string(128, 1),
        "expires_monotonic": {"type": "number", "minimum": 0},
    }, ["schema", "transcript", "source_receipt_handle", "profile_id",
        "owner_generation", "operation_id", "expires_monotonic"])


_BOARD_TYPES = ["epic", "user-story", "task", "defect", "spike", "risk", "decision"]
_BOARD_STATES = ["backlog", "ready", "in-progress", "review", "blocked", "done"]
_BOARD_ID = _string(80, 1)
_ITEM_ID = _string(80, 1)
_SESSION_HANDLE = _string(128, 8)
_AUDIO_ID = _string(128, 8)

_rows = {
    ("epic-kanban", "create"): _row("epic-kanban", "create", "plugin.epic-kanban.write",
        _obj({"epic_id": _string(128, 1), "title": _string(256, 1)}, ["epic_id", "title"]),
        _simple_string_result("board_id"), expected_state="committed", requires_idempotency=True),
    ("epic-kanban", "read"): _row("epic-kanban", "read", "plugin.epic-kanban.read",
        _obj({"board_id": _BOARD_ID}, ["board_id"]),
        _obj({"board": {"anyOf": [
            {"type": "null"}, _obj({
                "board_id": _BOARD_ID, "epic_id": _string(128, 1), "title": _string(256, 1),
                "items": {"type": "array", "maxItems": 1000, "items": _obj({
                    "item_id": _ITEM_ID, "item_type": {"type": "string", "enum": _BOARD_TYPES},
                    "title": _string(256, 1), "state": {"type": "string", "enum": _BOARD_STATES},
                    "description": _string(16_384),
                }, ["item_id", "item_type", "title", "state", "description"])},
            }, ["board_id", "epic_id", "title", "items"]),
        ]}}, ["board"])),
    ("epic-kanban", "add_item"): _row("epic-kanban", "add_item", "plugin.epic-kanban.write",
        _obj({"board_id": _BOARD_ID, "item_type": {"type": "string", "enum": _BOARD_TYPES},
              "title": _string(256, 1), "description": _string(16_384)},
             ["board_id", "item_type", "title", "description"]),
        _simple_string_result("item_id"), expected_state="committed", requires_idempotency=True),
    ("epic-kanban", "move_item"): _row("epic-kanban", "move_item", "plugin.epic-kanban.write",
        _obj({"board_id": _BOARD_ID, "item_id": _ITEM_ID,
              "state": {"type": "string", "enum": _BOARD_STATES}}, ["board_id", "item_id", "state"]),
        _obj({"state": {"type": "string", "enum": _BOARD_STATES}}, ["state"]), expected_state="committed", requires_idempotency=True),
    ("epic-kanban", "delete_accepted"): _row("epic-kanban", "delete_accepted", "plugin.epic-kanban.delete",
        _obj({"board_id": _BOARD_ID, "accepted_lifecycle_attestation_id": _string(128, 8)},
             ["board_id", "accepted_lifecycle_attestation_id"]),
        _simple_string_result("receipt_id"), expected_state="committed", requires_idempotency=True),
    ("voice-pipeline", "open_session"): _row("voice-pipeline", "open_session", "plugin.voice-pipeline.session",
        _obj({"session_enrollment_id": _string(128, 1), "direction": {"type": "string", "enum": ["input", "output", "duplex"]},
              "requested_lease_seconds": {"type": "integer", "minimum": 1, "maximum": 60}},
             ["session_enrollment_id", "direction", "requested_lease_seconds"]),
        _obj({"session_handle": _SESSION_HANDLE, "expires_monotonic": {"type": "number", "minimum": 0}},
             ["session_handle", "expires_monotonic"]), requires_idempotency=True),
    ("voice-pipeline", "capture_audio"): _row("voice-pipeline", "capture_audio", "plugin.voice-pipeline.session",
        _obj({"session_handle": _SESSION_HANDLE, "maximum_seconds": {"type": "integer", "minimum": 1, "maximum": 30}},
             ["session_handle", "maximum_seconds"]),
        _obj({"audio_artifact_id": _AUDIO_ID, "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
              "size_bytes": {"type": "integer", "minimum": 1, "maximum": 16_777_216}},
             ["audio_artifact_id", "sha256", "size_bytes"]), requires_idempotency=True),
    ("voice-pipeline", "close_session"): _row("voice-pipeline", "close_session", "plugin.voice-pipeline.session",
        _obj({"session_handle": _SESSION_HANDLE}, ["session_handle"]),
        _obj({"closed": {"type": "boolean", "enum": [True]}}, ["closed"]), requires_idempotency=True),
    ("voice-pipeline", "voice_transcribe"): _row("voice-pipeline", "voice_transcribe", "plugin.voice-pipeline.stt",
        _obj({"session_handle": _SESSION_HANDLE, "audio_artifact_id": _AUDIO_ID,
              "mode": {"type": "string", "enum": ["general", "home_control"]}},
             ["session_handle", "audio_artifact_id", "mode"]),
        _stt_receipt(), requires_idempotency=True),
    ("voice-pipeline", "voice_speak"): _row("voice-pipeline", "voice_speak", "plugin.voice-pipeline.tts",
        _obj({"session_handle": _SESSION_HANDLE, "text": _string(16_384, 1)}, ["session_handle", "text"]),
        _obj({"audio_artifact": _artifact_receipt()}, ["audio_artifact"]), requires_idempotency=True),
    ("web", "retrieve"): _row("web", "retrieve", "plugin.web.read",
        _obj({"url": _string(2048, 1)}, ["url"]),
        _obj({"url": _string(2048, 1), "content_type": _string(256, 1), "content": _string(2_000_000),
              "untrusted_source": {"type": "boolean", "enum": [True]},
              "authority": {"type": "string", "enum": ["none"]}, "redirects": {"type": "integer", "minimum": 0, "maximum": 4},
              "source_receipt": _source_receipt()},
             ["url", "content_type", "content", "untrusted_source", "authority", "redirects", "source_receipt"])),
}

PLUGIN_ACTION_SCHEMAS = MappingProxyType(_rows)

# Selected only by the root action enrollment's exact argument schema ID. The
# fixed root workflow performs session open/capture/STT-or-TTS/close itself;
# native tool handlers never issue child actions.
PLUGIN_ACTION_SCHEMA_VARIANTS = MappingProxyType({
    ("voice-pipeline", "voice_transcribe", "voice-transcribe-session-workflow-v1"):
        _row("voice-pipeline", "voice_transcribe", "plugin.voice-pipeline.stt",
             _obj({"mode": {"type": "string", "enum": ["general", "home_control"]}}, ["mode"]),
             _stt_receipt(), argument_schema_id="voice-transcribe-session-workflow-v1",
             result_schema_id="voice-pipeline.voice_transcribe.result.v1", requires_idempotency=True),
    ("voice-pipeline", "voice_speak", "voice-speak-session-workflow-v1"):
        _row("voice-pipeline", "voice_speak", "plugin.voice-pipeline.tts",
             _obj({"text": _string(16_384, 1)}, ["text"]),
             _obj({"audio_artifact": _artifact_receipt()}, ["audio_artifact"]),
             argument_schema_id="voice-speak-session-workflow-v1",
             result_schema_id="voice-pipeline.voice_speak.result.v1", requires_idempotency=True),
})
