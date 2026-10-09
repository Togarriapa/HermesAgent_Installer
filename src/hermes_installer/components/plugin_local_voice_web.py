"""Bounded native adapters for local Kanban, local Wyoming voice and web reads.

All side effects cross typed services injected by the trusted host. This module
contains no shell, socket, microphone, credential, or persistence discovery.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
import re
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit


class PluginAdapterError(RuntimeError):
    """A selected plugin service is missing or rejected the bounded request."""


class ToolContext(Protocol):
    def register_tool(self, name: str, toolset: str, schema: dict[str, Any],
                      handler: Any, **kwargs: Any) -> object: ...


class LocalBoardStore(Protocol):
    """Already profile-scoped local store with ephemeral owned-root semantics."""
    def create(self, epic_id: str, title: str) -> str: ...
    def read(self, board_id: str) -> dict[str, Any] | None: ...
    def mutate(self, board_id: str, operation: str,
               item: dict[str, Any]) -> dict[str, Any]: ...
    def delete_after_accepted_done(self, board_id: str,
                                   accepted_summary: str) -> bool: ...


class VoiceSession(Protocol):
    """Trusted current-session boundary; it owns mic permission and audio lifetime."""
    def current(self) -> tuple[str, bool]: ...  # (session id, microphone authorized)
    def capture_current_session(self, *, max_bytes: int, timeout: float) -> bytes: ...
    def transcribe_local(self, endpoint: str, audio: bytes, *, timeout: float) -> str: ...
    def synthesize_local(self, endpoint: str, text: str, *, timeout: float) -> bytes: ...
    def play_current_session(self, session_id: str, audio: bytes) -> None: ...


@dataclass(frozen=True, slots=True)
class WebResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    final_url: str
    connected_ip: str
    tls_verified: bool
    used_proxy: bool


class DirectHttpsReader(Protocol):
    """One-hop HTTPS fetcher, configured without environment proxy inheritance."""
    def get_one_hop(self, url: str, *, timeout: float, max_bytes: int) -> WebResponse: ...


class PluginRuntime(Protocol):
    """Protected runtime extension surface; never populated from resource YAML."""
    identity: object
    local_board_store: LocalBoardStore | None
    voice_session: VoiceSession | None
    voice_endpoints: dict[str, str]
    direct_https_reader: DirectHttpsReader | None


class LocalKanbanImplementation:
    def register(self, ctx: ToolContext, runtime_context: PluginRuntime) -> None:
        _require_plugin_identity(runtime_context, "epic-kanban")
        store = getattr(runtime_context, "local_board_store", None)
        if not _has_methods(store, "create", "read", "mutate", "delete_after_accepted_done"):
            raise PluginAdapterError("protected profile-bound local board store is not enrolled")
        LocalKanbanPlugin(store).register(ctx, runtime_context)


class WyomingVoiceImplementation:
    def register(self, ctx: ToolContext, runtime_context: PluginRuntime) -> None:
        _require_plugin_identity(runtime_context, "voice-pipeline")
        session = getattr(runtime_context, "voice_session", None)
        if not _has_methods(session, "current", "capture_current_session", "transcribe_local",
                            "synthesize_local", "play_current_session"):
            raise PluginAdapterError("trusted current-session voice boundary is not enrolled")
        endpoints = getattr(runtime_context, "voice_endpoints", None)
        if not isinstance(endpoints, dict) or set(endpoints) - {"stt", "home_stt", "tts"}:
            raise PluginAdapterError("protected local Wyoming endpoint configuration is unavailable")
        WyomingVoicePlugin(session, stt_endpoint=endpoints.get("stt"),
                           home_stt_endpoint=endpoints.get("home_stt"),
                           tts_endpoint=endpoints.get("tts")).register(ctx, runtime_context)


class PublicWebImplementation:
    def register(self, ctx: ToolContext, runtime_context: PluginRuntime) -> None:
        _require_plugin_identity(runtime_context, "web")
        reader = getattr(runtime_context, "direct_https_reader", None)
        if not _has_methods(reader, "get_one_hop"):
            raise PluginAdapterError("reviewed direct public HTTPS retrieval service is not enrolled")
        PublicWebPlugin(reader).register(ctx, runtime_context)


PLUGIN_IMPLEMENTATIONS = {
    "epic-kanban": LocalKanbanImplementation(),
    "voice-pipeline": WyomingVoiceImplementation(),
    "web": PublicWebImplementation(),
}


class LocalKanbanPlugin:
    """Per-profile ephemeral board CRUD; GitHub Projects is intentionally separate."""
    def __init__(self, store: LocalBoardStore):
        self.store = store

    def register(self, ctx: ToolContext, runtime_context: object) -> None:
        ctx.register_tool("epic_board", "epic_kanban", {
            "type": "object", "properties": {
                "operation": {"enum": ["create", "read", "add_item", "move_item", "delete_accepted"]},
                "epic_id": {"type": "string", "maxLength": 80},
                "board_id": {"type": "string", "maxLength": 80},
                "title": {"type": "string", "maxLength": 200},
                "item": {"type": "object"}, "accepted_summary": {"type": "string", "maxLength": 4000},
            }, "required": ["operation"], "additionalProperties": False,
        }, self.invoke, description="Manage one local ephemeral board for the selected Epic.")

    def invoke(self, *, operation: str, epic_id: str | None = None,
               board_id: str | None = None, title: str = "", item: dict[str, Any] | None = None,
               accepted_summary: str = "") -> dict[str, Any]:
        if operation == "create":
            _bounded_text(epic_id, "epic_id", 80)
            _bounded_text(title, "title", 200)
            return {"board_id": self.store.create(epic_id or "", title)}
        if operation == "read":
            return {"board": self.store.read(_board_id(board_id))}
        if operation in {"add_item", "move_item"}:
            validated = _validate_item(item)
            return {"board": self.store.mutate(_board_id(board_id), operation, validated)}
        if operation == "delete_accepted":
            _bounded_text(accepted_summary, "accepted_summary", 4000)
            return {"deleted": self.store.delete_after_accepted_done(
                _board_id(board_id), accepted_summary)}
        raise PluginAdapterError("unsupported local board operation")


class WyomingVoicePlugin:
    """Session-only local voice adapter; never stores or returns raw audio."""
    def __init__(self, session: VoiceSession, *, stt_endpoint: str | None,
                 tts_endpoint: str | None, home_stt_endpoint: str | None = None):
        self.session, self.stt, self.tts, self.home_stt = session, stt_endpoint, tts_endpoint, home_stt_endpoint
        for value in (stt_endpoint, tts_endpoint, home_stt_endpoint):
            if value is not None and not _local_endpoint(value):
                raise ValueError("Wyoming endpoints must be explicitly configured local endpoints")

    def register(self, ctx: ToolContext, runtime_context: object) -> None:
        ctx.register_tool("voice_transcribe", "voice_pipeline", {
            "type": "object", "properties": {"utterance_kind": {"enum": ["general", "home_control"]}},
            "required": ["utterance_kind"], "additionalProperties": False,
        }, self.transcribe, description="Transcribe microphone input captured from the authorized current session.")
        ctx.register_tool("voice_speak", "voice_pipeline", {
            "type": "object", "properties": {"text": {"type": "string", "maxLength": 4000}},
            "required": ["text"], "additionalProperties": False,
        }, self.speak, description="Speak text through the enrolled local Piper endpoint in the current session.")

    def transcribe(self, *, utterance_kind: str) -> dict[str, str]:
        if utterance_kind not in {"general", "home_control"}:
            raise PluginAdapterError("unknown utterance kind")
        session_id, authorized = self.session.current()
        if not authorized:
            raise PluginAdapterError("microphone input is not authorized for this session")
        endpoint = self.home_stt if utterance_kind == "home_control" else self.stt
        if endpoint is None:
            raise PluginAdapterError("selected local Wyoming STT endpoint is not enrolled")
        try:
            audio = self.session.capture_current_session(max_bytes=900_000, timeout=10.0)
        except Exception as exc:
            raise PluginAdapterError("authorized session microphone capture failed") from exc
        if not isinstance(audio, bytes) or not audio or len(audio) > 900_000:
            raise PluginAdapterError("audio payload exceeds the session limit")
        transcript = self.session.transcribe_local(endpoint, audio, timeout=15.0)
        if not isinstance(transcript, str) or len(transcript) > 4000:
            raise PluginAdapterError("local STT returned an invalid transcript")
        del audio
        return {"transcript": transcript, "session_id": session_id}

    def speak(self, *, text: str) -> dict[str, bool]:
        _bounded_text(text, "text", 4000)
        session_id, _ = self.session.current()
        if self.tts is None:
            raise PluginAdapterError("selected local Piper endpoint is not enrolled")
        audio = self.session.synthesize_local(self.tts, text, timeout=15.0)
        if not isinstance(audio, bytes) or not audio or len(audio) > 2_000_000:
            raise PluginAdapterError("local Piper returned invalid or oversized audio")
        self.session.play_current_session(session_id, audio)
        del audio
        return {"played": True}


class PublicWebPlugin:
    """HTTPS-only, bounded retrieval with per-hop policy checks and receipt provenance."""
    MAX_BYTES = 1_000_000
    MAX_REDIRECTS = 4

    def __init__(self, reader: DirectHttpsReader):
        self.reader = reader

    def register(self, ctx: ToolContext, runtime_context: object) -> None:
        ctx.register_tool("web_retrieve", "web", {
            "type": "object", "properties": {"url": {"type": "string", "maxLength": 2048}},
            "required": ["url"], "additionalProperties": False,
        }, self.retrieve, description="Retrieve bounded public HTTPS content as untrusted source material.")

    def retrieve(self, *, url: str) -> dict[str, Any]:
        current = _public_https_url(url)
        for hop in range(self.MAX_REDIRECTS + 1):
            response = self.reader.get_one_hop(current, timeout=10.0, max_bytes=self.MAX_BYTES)
            if response.used_proxy or not response.tls_verified or not _public_ip(response.connected_ip):
                raise PluginAdapterError("retrieval transport failed direct public TLS policy")
            if response.final_url != current:
                raise PluginAdapterError("transport followed an unchecked redirect")
            if len(response.body) > self.MAX_BYTES:
                raise PluginAdapterError("retrieved content exceeds the size limit")
            if response.status in {301, 302, 303, 307, 308}:
                location = _header(response.headers, "location")
                if not location or hop == self.MAX_REDIRECTS:
                    raise PluginAdapterError("redirect limit or missing location")
                current = _public_https_url(urljoin(current, location))
                continue
            if response.status < 200 or response.status >= 300:
                raise PluginAdapterError(f"public retrieval returned HTTP {response.status}")
            content_type = _header(response.headers, "content-type") or "application/octet-stream"
            if "text/" not in content_type and "json" not in content_type and "xml" not in content_type:
                raise PluginAdapterError("only textual public content is supported")
            text = response.body.decode("utf-8", errors="replace")
            return {"url": current, "content_type": content_type, "content": text,
                    "untrusted_source": True, "redirects": hop, "authority": "none"}
        raise PluginAdapterError("redirect limit exceeded")


def _bounded_text(value: object, label: str, maximum: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise PluginAdapterError(f"{label} must be bounded non-empty text")


def _require_plugin_identity(runtime_context: object, expected: str) -> None:
    identity = getattr(runtime_context, "identity", None)
    if (getattr(identity, "kind", None) != "plugins"
            or getattr(identity, "resource_id", None) != expected):
        raise PluginAdapterError(f"trusted selected Plugin identity must be {expected}")


def _has_methods(value: object, *names: str) -> bool:
    return value is not None and all(callable(getattr(value, name, None)) for name in names)


def _board_id(value: object) -> str:
    _bounded_text(value, "board_id", 80)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", value):
        raise PluginAdapterError("invalid board id")
    return value


def _validate_item(item: object) -> dict[str, Any]:
    if not isinstance(item, dict) or set(item) - {"id", "type", "title", "state", "summary"}:
        raise PluginAdapterError("board item has unsupported fields")
    _bounded_text(item.get("id"), "item.id", 80)
    _bounded_text(item.get("title"), "item.title", 200)
    if item.get("type") not in {"epic", "user-story", "task", "defect", "spike", "risk", "decision"}:
        raise PluginAdapterError("unsupported item type")
    if item.get("state") not in {"backlog", "ready", "in-progress", "review", "blocked", "done"}:
        raise PluginAdapterError("unsupported workflow state")
    return dict(item)


def _local_endpoint(value: str) -> bool:
    p = urlsplit(value)
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password or p.query or p.fragment:
        return False
    try:
        return ip_address(p.hostname).is_loopback
    except ValueError:
        return p.hostname in {"localhost", "wyoming", "homeassistant"}


def _public_https_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise PluginAdapterError("URL is missing or too long")
    p = urlsplit(value)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.fragment:
        raise PluginAdapterError("only public HTTPS URLs without credentials or fragments are allowed")
    host = p.hostname.rstrip(".").lower()
    try:
        addr = ip_address(host)
        if not addr.is_global:
            raise PluginAdapterError("private or reserved address is denied")
    except ValueError:
        if "." not in host or host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
            raise PluginAdapterError("private or non-public hostname is denied")
    if p.port not in {None, 443}:
        raise PluginAdapterError("only HTTPS port 443 is permitted")
    if any(ord(c) < 32 for c in value):
        raise PluginAdapterError("control characters are denied")
    return urlunsplit(("https", host, p.path or "/", p.query, ""))


def _public_ip(value: str) -> bool:
    try:
        return ip_address(value).is_global
    except ValueError:
        return False


def _header(headers: dict[str, str], name: str) -> str | None:
    return next((v for k, v in headers.items() if k.lower() == name), None)
