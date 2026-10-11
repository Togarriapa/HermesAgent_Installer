"""Per-request, root-issued Jarvis Projects context for Hermes' native ContextEngine.

The selected Hermes engine is always called first. Project context is then appended to
the request's existing system message only; no saved transcript or user message changes.
The provider queries the finite root observer on every provider attempt so retries cannot
reuse stale owner, project, or core-generation context.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

_CONTEXT_SEAL = object()
_MAX_CONTEXT_CHARS = 24_000
_SESSION_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class RootCurrentProjectContext:
    """Exact owner-turn context returned by the root observer; caller text is not authority."""

    session_id: str
    prompt_sha256: str
    owner_turn_handle: str
    conversation_id: str
    gateway_turn_id: str
    owner_subject_sha256: str
    core_generation: str
    context_sha256: str
    text: str
    project_source_refs: tuple[str, ...]
    _seal: object = field(repr=False, compare=False)

    def is_current_shape(self, *, session_id: str, prompt_sha256: str) -> bool:
        try:
            return bool(type(self) is RootCurrentProjectContext
                and self._seal is _CONTEXT_SEAL
                and self.session_id == session_id
                and self.prompt_sha256 == prompt_sha256
                and _SESSION_RE.fullmatch(self.session_id) is not None
                and _HASH_RE.fullmatch(self.prompt_sha256) is not None
                and re.fullmatch(r"[0-9a-f]{32}", self.owner_turn_handle) is not None
                and re.fullmatch(r"[A-Za-z0-9_-]{24,64}", self.conversation_id) is not None
                and re.fullmatch(r"[A-Za-z0-9_-]{24,64}", self.gateway_turn_id) is not None
                and _HASH_RE.fullmatch(self.owner_subject_sha256) is not None
                and _HASH_RE.fullmatch(self.core_generation) is not None
                and _HASH_RE.fullmatch(self.context_sha256) is not None
                and isinstance(self.text, str) and len(self.text) <= _MAX_CONTEXT_CHARS
                and hashlib.sha256(self.text.encode("utf-8", "strict")).hexdigest()
                    == self.context_sha256
                and type(self.project_source_refs) is tuple
                and len(self.project_source_refs) <= 51
                and all(isinstance(item, str) and 1 <= len(item) <= 192 and item.isascii()
                        for item in self.project_source_refs))
        except Exception:
            return False


def _snapshot_from_root(row: dict[str, Any], *, session_id: str,
                        prompt_sha256: str) -> RootCurrentProjectContext:
    expected = {"schema", "nonce", "ok", "available", "session_id", "prompt_sha256",
                "owner_turn_handle",
                "conversation_id", "gateway_turn_id", "owner_subject_sha256",
                "core_generation", "context_sha256", "text", "project_source_refs"}
    if (type(row) is not dict or set(row) != expected
            or type(row.get("schema")) is not int or row.get("schema") != 1
            or not isinstance(row.get("nonce"), str) or row.get("ok") is not True
            or row.get("available") is not True
            or type(row.get("text")) is not str
            or type(row.get("project_source_refs")) is not list
            or len(row["project_source_refs"]) > 51
            or any(not isinstance(item, str) or not 1 <= len(item) <= 192
                   or not item.isascii() for item in row["project_source_refs"])):
        raise ValueError("root project context response is malformed or unavailable")
    result = RootCurrentProjectContext(
        session_id=row["session_id"], prompt_sha256=row["prompt_sha256"],
        owner_turn_handle=row["owner_turn_handle"],
        conversation_id=row["conversation_id"], gateway_turn_id=row["gateway_turn_id"],
        owner_subject_sha256=row["owner_subject_sha256"], core_generation=row["core_generation"],
        context_sha256=row["context_sha256"], text=row["text"],
        project_source_refs=tuple(row["project_source_refs"]), _seal=_CONTEXT_SEAL)
    if not result.is_current_shape(session_id=session_id, prompt_sha256=prompt_sha256):
        raise ValueError("root project context does not match this native request")
    return result


class CurrentProjectContextProvider:
    """Fixed native observer client; there is no injectable resolver callback."""

    def __init__(self, observer: Any | None = None):
        if observer is None:
            from .core_native_observer import CoreNativeObservationClient
            observer = CoreNativeObservationClient()
        from .core_native_observer import CoreNativeObservationClient
        if type(observer) is not CoreNativeObservationClient:
            raise TypeError("fixed current-core observation client required")
        self._observer = observer

    def read(self, *, session_id: str, prompt_sha256: str) -> RootCurrentProjectContext | None:
        if (_SESSION_RE.fullmatch(session_id or "") is None
                or _HASH_RE.fullmatch(prompt_sha256 or "") is None):
            raise ValueError("current native request identity is invalid")
        row = self._observer.current_project_context(
            session_id=session_id, prompt_sha256=prompt_sha256)
        if row is None:
            return None
        return _snapshot_from_root(row, session_id=session_id, prompt_sha256=prompt_sha256)


class ProjectContextEngine:
    """Decorator that composes the configured Hermes ContextEngine unchanged."""

    def __init__(self, delegate: Any, provider: CurrentProjectContextProvider | None = None,
                 *, native_session_id: str | None = None):
        if delegate is None or isinstance(delegate, ProjectContextEngine):
            raise TypeError("one configured Hermes ContextEngine is required")
        self._delegate = delegate
        self._provider = provider or CurrentProjectContextProvider()
        self._native_session_id = None
        if native_session_id is not None:
            self.bind_native_session(native_session_id)

    def bind_native_session(self, session_id: str) -> None:
        """Bind the concrete session ID from the host agent, never from model output."""
        if (_SESSION_RE.fullmatch(session_id or "") is None or not session_id.isascii()
                or any(ord(char) < 0x20 for char in session_id)):
            raise ValueError("native session identity is invalid")
        self._native_session_id = session_id

    def __getattr__(self, name: str) -> Any:
        # Compression, usage accounting, tool schemas and session lifecycle remain owned
        # by the configured engine; this adapter only overrides request selection.
        return getattr(self._delegate, name)

    def select_context(self, request_messages: list[dict[str, Any]], *,
                       conversation_messages: list[dict[str, Any]] | None = None,
                       incoming_message: dict[str, Any] | None = None,
                       budget_tokens: int = 0) -> list[dict[str, Any]] | None:
        selected = self._delegate.select_context(
            request_messages, conversation_messages=conversation_messages,
            incoming_message=incoming_message, budget_tokens=budget_tokens)
        messages = request_messages if selected is None else selected
        if (not isinstance(messages, list) or not messages
                or any(not isinstance(item, dict) for item in messages)
                or not isinstance(incoming_message, dict)):
            return selected
        session_id = self._native_session_id
        content = incoming_message.get("content")
        if not isinstance(session_id, str) or not isinstance(content, str):
            return selected
        prompt_sha256 = hashlib.sha256(content.encode("utf-8", "strict")).hexdigest()
        snapshot = self._provider.read(session_id=session_id, prompt_sha256=prompt_sha256)
        if snapshot is None or not snapshot.text:
            return selected
        if not snapshot.is_current_shape(session_id=session_id, prompt_sha256=prompt_sha256):
            return selected
        system_index = next((index for index, item in enumerate(messages)
                             if item.get("role") == "system"), None)
        if system_index is None:
            return selected
        result = [dict(item) for item in messages]
        base = result[system_index].get("content")
        if not isinstance(base, str):
            return selected
        marker = f"[Jarvis Projects context {snapshot.context_sha256}]"
        if marker in base:
            return result
        result[system_index]["content"] = (
            base + "\n\n" + marker + "\n" + snapshot.text
            + "\n[/Jarvis Projects context]")
        return result


def install_current_project_context_middleware(ctx: Any, *,
                                              provider: CurrentProjectContextProvider | None = None) -> Any:
    """Attach owner context at Hermes' supported per-provider-request seam.

    Hermes constructs the selected ContextEngine inside each agent after plugin
    discovery. Its official plugin ContextEngine registration is a replacement
    selected only when ``context.engine`` names it, so it cannot transparently
    decorate the built-in compressor or an existing user-selected engine. The
    official ``llm_request`` middleware runs after that engine's request selection
    on every attempt/retry. It preserves the configured engine and appends to the
    Codex Responses ``instructions`` field only when root proves the exact session
    and final user prompt belong to an active Jarvis owner turn.
    """
    register = getattr(ctx, "register_middleware", None)
    if not callable(register):
        raise RuntimeError("official Hermes LLM request middleware is unavailable")
    source = provider or CurrentProjectContextProvider()

    def add_project_context(*, request: Any, session_id: str = "", **_event: Any) -> Any:
        if type(request) is not dict or not isinstance(session_id, str):
            return None
        # The official Codex Responses builder emits one exact ``input_text`` user
        # message. Other transports have different role/content rules and are left
        # byte-for-byte unchanged until an equivalent official adapter is reviewed.
        items = request.get("input")
        if not isinstance(items, list):
            return None
        try:
            from .core_native_observer import _native_prompt_sha256
            prompt_sha256 = _native_prompt_sha256(request)
            snapshot = source.read(session_id=session_id, prompt_sha256=prompt_sha256)
        except Exception:
            # Context is optional for ordinary/non-Jarvis requests. The root API
            # returns data only for a current owner-turn join, and errors fail closed.
            return None
        if snapshot is None or not snapshot.text:
            return None
        if not snapshot.is_current_shape(session_id=session_id, prompt_sha256=prompt_sha256):
            return None
        marker = f"[Jarvis Projects context {snapshot.context_sha256}]"
        updated = dict(request)
        instructions = request.get("instructions")
        if not isinstance(instructions, str):
            return None
        if marker in instructions:
            return None
        updated["instructions"] = (
            instructions + "\n\n" + marker + "\n" + snapshot.text
            + "\n[/Jarvis Projects context]"
        )
        return {"request": updated, "source": "jarvis_projects",
                "reason": "root-verified owner-turn project context"}

    return register("llm_request", add_project_context)
