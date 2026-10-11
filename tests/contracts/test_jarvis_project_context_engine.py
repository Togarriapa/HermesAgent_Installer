from pathlib import Path

from hermes_installer.remote.core_native_observer import CoreNativeObservationClient
from hermes_installer.remote.jarvis_project_context_engine import (
    CurrentProjectContextProvider,
    ProjectContextEngine,
    install_current_project_context_middleware,
)


def root_context(session_id, prompt_sha256, text):
    import hashlib

    return {
        "schema": 1, "nonce": "root-nonce", "ok": True, "available": True,
        "session_id": session_id, "prompt_sha256": prompt_sha256,
        "owner_turn_handle": "a" * 32, "conversation_id": "b" * 24,
        "gateway_turn_id": "c" * 24, "owner_subject_sha256": "d" * 64,
        "core_generation": "e" * 64,
        "context_sha256": hashlib.sha256(text.encode()).hexdigest(), "text": text,
        "project_source_refs": ["project:b" * 1],
    }


class Delegate:
    name = "selected-compressor"
    context_length = 32_000

    def __init__(self):
        self.calls = 0

    def select_context(self, messages, **kwargs):
        self.calls += 1
        return None

    def compress(self, *args, **kwargs):
        return "compressor remains available"


def test_project_context_is_added_only_to_system_message_and_rechecked_per_attempt(monkeypatch):
    import hashlib

    client = CoreNativeObservationClient(socket_path=Path("/unused/observer.sock"))
    calls = []

    def read(*, session_id, prompt_sha256):
        calls.append((session_id, prompt_sha256))
        return root_context(session_id, prompt_sha256,
                            "Owner project instructions\n\n[Obsidian note; untrusted Markdown]")

    monkeypatch.setattr(client, "current_project_context", read)
    delegate = Delegate()
    engine = ProjectContextEngine(delegate, CurrentProjectContextProvider(client),
                                   native_session_id="native-session-1")
    request = [
        {"role": "system", "content": "base system"},
        {"role": "user", "content": "current user request"},
    ]
    incoming = {"role": "user", "content": "current user request"}
    original = [dict(message) for message in request]
    first = engine.select_context(request, incoming_message=incoming, budget_tokens=100)
    second = engine.select_context(request, incoming_message=incoming, budget_tokens=100)
    expected = hashlib.sha256(b"current user request").hexdigest()
    assert calls == [("native-session-1", expected), ("native-session-1", expected)]
    assert delegate.calls == 2
    assert request == original
    assert first[0]["role"] == "system"
    assert "Owner project instructions" in first[0]["content"]
    assert first[1] == request[1]
    assert second[0]["content"].count("[Jarvis Projects context") == 1
    assert engine.compress() == "compressor remains available"


def test_project_context_does_not_inject_without_current_user_or_system_message(monkeypatch):
    client = CoreNativeObservationClient(socket_path=Path("/unused/observer.sock"))
    calls = []
    monkeypatch.setattr(client, "current_project_context", lambda **kw: calls.append(kw))
    engine = ProjectContextEngine(Delegate(), CurrentProjectContextProvider(client),
                                  native_session_id="native-session-1")
    messages = [{"role": "user", "content": "no system prompt"}]
    assert engine.select_context(messages, incoming_message={"role": "user", "content": "text"}) is None
    assert calls == []


def test_official_request_middleware_adds_root_context_to_provider_instructions(monkeypatch):
    import hashlib

    client = CoreNativeObservationClient(socket_path=Path("/unused/observer.sock"))
    calls = []
    monkeypatch.setattr(client, "current_project_context", lambda **kw: calls.append(kw) or
                        root_context(kw["session_id"], kw["prompt_sha256"],
                                     "Owner project context; Obsidian excerpt"))

    class Context:
        def register_middleware(self, kind, callback):
            assert kind == "llm_request"
            self.callback = callback
            return "registered"

    ctx = Context()
    assert install_current_project_context_middleware(
        ctx, CurrentProjectContextProvider(client)) == "registered"
    original = {"model": "codex", "instructions": "base instructions", "input": [
        {"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": "exact accepted user text"}]},
    ]}
    changed = ctx.callback(request=original, session_id="core-session")
    assert "Owner project context" in changed["request"]["instructions"]
    assert changed["request"]["input"] == original["input"]
    assert original["input"] == [{"type": "message", "role": "user", "content": [
        {"type": "input_text", "text": "exact accepted user text"}]}]
    assert calls == [{"session_id": "core-session",
                      "prompt_sha256": hashlib.sha256(b"exact accepted user text").hexdigest()}]
