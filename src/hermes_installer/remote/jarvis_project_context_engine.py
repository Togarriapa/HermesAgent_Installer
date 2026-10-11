"""Per-request, root-issued Jarvis Projects context for Hermes' native provider request.

The configured Hermes ContextEngine runs unchanged. Root-issued project context is
appended to the provider's separate instructions field only; no saved transcript or
user message changes. The provider queries the finite root observer on every attempt,
replacing or removing its prior managed block so retries cannot reuse stale context.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

_CONTEXT_SEAL = object()
_MAX_CONTEXT_CHARS = 24_000
_SESSION_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MANAGED_CONTEXT_OPEN = re.compile(
    r"<!-- jarvis-project-context:v1:([A-Za-z0-9_-]{16}):([0-9a-f]{64}):([0-9a-f]{64}) -->"
)


def _context_block_mac(key: bytes, nonce: str, digest: str, text: str) -> str:
    material = nonce.encode("ascii") + b"\0" + digest.encode("ascii") + b"\0" + text.encode("utf-8", "strict")
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def _remove_owned_context_blocks(instructions: str, key: bytes) -> str:
    """Remove only intact blocks issued by this middleware instance.

    A tag-like string in user/provider instructions is not a credential. Its block
    is removed only if the instance-private MAC, nonce, and content digest all match.
    """
    spans: list[tuple[int, int]] = []
    for opening in _MANAGED_CONTEXT_OPEN.finditer(instructions):
        nonce, digest, signature = opening.groups()
        closing_text = f"\n<!-- /jarvis-project-context:v1:{nonce} -->"
        closing_at = instructions.find(closing_text, opening.end())
        if closing_at < 0:
            continue
        framed = instructions[opening.end():closing_at]
        if not framed.startswith("\n"):
            continue
        text = framed[1:]
        if (hashlib.sha256(text.encode("utf-8", "strict")).hexdigest() != digest
                or not hmac.compare_digest(signature, _context_block_mac(key, nonce, digest, text))):
            continue
        start = opening.start()
        if instructions[max(0, start - 2):start] == "\n\n":
            start -= 2
        spans.append((start, closing_at + len(closing_text)))
    if not spans:
        return instructions
    result = instructions
    for start, end in reversed(spans):
        result = result[:start] + result[end:]
    return result


def _make_owned_context_block(key: bytes, digest: str, text: str) -> str:
    nonce = secrets.token_urlsafe(12)
    signature = _context_block_mac(key, nonce, digest, text)
    return (f"<!-- jarvis-project-context:v1:{nonce}:{digest}:{signature} -->\n"
            f"{text}\n<!-- /jarvis-project-context:v1:{nonce} -->")


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
    block_key = secrets.token_bytes(32)

    def rewritten(request: dict[str, Any], instructions: str) -> Any:
        if instructions == request.get("instructions"):
            return None
        updated = dict(request)
        updated["instructions"] = instructions
        return {"request": updated, "source": "jarvis_projects",
                "reason": "refresh root-verified owner-turn project context"}

    def add_project_context(*, request: Any, session_id: str = "", **_event: Any) -> Any:
        if type(request) is not dict:
            return None
        original_instructions = request.get("instructions")
        if not isinstance(original_instructions, str):
            return None
        # Strip this instance's prior block before looking up current state. This
        # also removes it when the project was detached, archived, or its selected
        # Obsidian notes disappeared between an attempt and retry.
        base_instructions = _remove_owned_context_blocks(original_instructions, block_key)
        if not isinstance(session_id, str):
            return rewritten(request, base_instructions)
        # The official Codex Responses builder emits one exact ``input_text`` user
        # message. Other transports have different role/content rules and are left
        # byte-for-byte unchanged until an equivalent official adapter is reviewed.
        items = request.get("input")
        if not isinstance(items, list):
            return rewritten(request, base_instructions)
        try:
            from .core_native_observer import _native_prompt_sha256
            prompt_sha256 = _native_prompt_sha256(request)
            snapshot = source.read(session_id=session_id, prompt_sha256=prompt_sha256)
        except Exception:
            # Never replay a prior block after failed current-owner verification.
            return rewritten(request, base_instructions)
        if snapshot is None or not snapshot.text:
            return rewritten(request, base_instructions)
        if not snapshot.is_current_shape(session_id=session_id, prompt_sha256=prompt_sha256):
            return rewritten(request, base_instructions)
        block = _make_owned_context_block(block_key, snapshot.context_sha256, snapshot.text)
        instructions = base_instructions + "\n\n" + block
        return rewritten(request, instructions)

    return register("llm_request", add_project_context)
