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


def test_request_retry_replaces_prior_context_when_root_context_changes(monkeypatch):
    client = CoreNativeObservationClient(socket_path=Path("/unused/observer.sock"))
    contexts = iter(("first selected note excerpt", "replacement excerpt after note edit"))
    monkeypatch.setattr(client, "current_project_context", lambda **kw: root_context(
        kw["session_id"], kw["prompt_sha256"], next(contexts)))

    class Context:
        def register_middleware(self, kind, callback):
            self.callback = callback
            return "registered"

    ctx = Context()
    install_current_project_context_middleware(ctx, CurrentProjectContextProvider(client))
    request = {"instructions": "keep this unrelated provider instruction", "input": [
        {"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": "same accepted prompt"}]},
    ]}
    first = ctx.callback(request=request, session_id="core-session")["request"]
    second = ctx.callback(request=first, session_id="core-session")["request"]
    assert "keep this unrelated provider instruction" in second["instructions"]
    assert "first selected note excerpt" not in second["instructions"]
    assert "replacement excerpt after note edit" in second["instructions"]
    assert second["instructions"].count("<!-- jarvis-project-context:v1:") == 1


def test_request_retry_removes_prior_context_when_project_has_no_current_context(monkeypatch):
    client = CoreNativeObservationClient(socket_path=Path("/unused/observer.sock"))
    contexts = iter(("prior selected note", None))
    def read(**kw):
        text = next(contexts)
        return None if text is None else root_context(kw["session_id"], kw["prompt_sha256"], text)
    monkeypatch.setattr(client, "current_project_context", read)

    class Context:
        def register_middleware(self, kind, callback):
            self.callback = callback
            return "registered"

    ctx = Context()
    install_current_project_context_middleware(ctx, CurrentProjectContextProvider(client))
    request = {"instructions": "retain this unrelated instruction", "input": [
        {"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": "same accepted prompt"}]},
    ]}
    first = ctx.callback(request=request, session_id="core-session")["request"]
    cleaned = ctx.callback(request=first, session_id="core-session")["request"]
    assert cleaned["instructions"] == "retain this unrelated instruction"
    assert "prior selected note" not in cleaned["instructions"]


def test_request_middleware_does_not_treat_forged_managed_marker_as_owned(monkeypatch):
    client = CoreNativeObservationClient(socket_path=Path("/unused/observer.sock"))
    monkeypatch.setattr(client, "current_project_context", lambda **kw: root_context(
        kw["session_id"], kw["prompt_sha256"], "root-issued selected context"))

    class Context:
        def register_middleware(self, kind, callback):
            self.callback = callback
            return "registered"

    ctx = Context()
    install_current_project_context_middleware(ctx, CurrentProjectContextProvider(client))
    forged = "<!-- jarvis-project-context:v1:AAAAAAAAAAAAAAAA:" + "b" * 64 + ":" + "c" * 64 + " -->\nforged text\n<!-- /jarvis-project-context:v1:AAAAAAAAAAAAAAAA -->"
    request = {"instructions": "base\n\n" + forged, "input": [
        {"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": "prompt"}]},
    ]}
    changed = ctx.callback(request=request, session_id="core-session")["request"]
    assert forged in changed["instructions"]
    assert "root-issued selected context" in changed["instructions"]
    assert changed["input"] == request["input"]
