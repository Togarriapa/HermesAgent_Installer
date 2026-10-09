from __future__ import annotations

import pytest

from hermes_installer.components.plugin_local_voice_web import (
    LocalKanbanImplementation, LocalKanbanPlugin, PLUGIN_IMPLEMENTATIONS,
    PluginAdapterError, PublicWebImplementation, PublicWebPlugin, WebResponse,
    WyomingVoiceImplementation, WyomingVoicePlugin,
)


class BoardFixture:
    def __init__(self): self.boards = {}
    def create(self, epic_id, title):
        key = epic_id
        self.boards[key] = {"id": epic_id, "title": title, "items": []}
        return epic_id
    def read(self, board_id): return self.boards.get(board_id)
    def mutate(self, board_id, operation, item):
        board = self.boards[board_id]
        if operation == "add_item": board["items"].append(item)
        else:
            old = next(x for x in board["items"] if x["id"] == item["id"])
            old["state"] = item["state"]
        return board
    def delete_after_accepted_done(self, board_id, accepted_summary):
        board = self.boards[board_id]
        if not accepted_summary.strip() or not board["items"] or any(x["state"] != "done" for x in board["items"]):
            return False
        del self.boards[board_id]
        return True


class VoiceFixture:
    def __init__(self, authorized=True): self.authorized=authorized; self.seen=[]; self.played=[]
    def current(self): return ("trusted-session-1", self.authorized)
    def capture_current_session(self, *, max_bytes, timeout): self.seen.append(("capture", max_bytes)); return b"synthetic-wave"
    def transcribe_local(self, endpoint, audio, *, timeout): self.seen.append((endpoint, bytes(audio))); return "fixture transcript"
    def synthesize_local(self, endpoint, text, *, timeout): self.seen.append((endpoint, text)); return b"wav-fixture"
    def play_current_session(self, session_id, audio): self.played.append((session_id, audio))


class ReaderFixture:
    def __init__(self, responses): self.responses=list(responses); self.calls=[]
    def get_one_hop(self, url, *, timeout, max_bytes):
        self.calls.append((url, timeout, max_bytes))
        return self.responses.pop(0)


class RegistrationFixture:
    def __init__(self): self.tools={}
    def register_tool(self, name, toolset, schema, handler, **kwargs): self.tools[name]=(toolset, schema, handler)


def response(url, status=200, headers=None, body=b"source", ip="93.184.216.34", tls=True, proxy=False):
    return WebResponse(status, headers or {"content-type": "text/plain"}, body, url, ip, tls, proxy)


def test_local_board_crud_is_per_profile_and_delete_requires_accepted_done():
    store = BoardFixture(); plugin = LocalKanbanPlugin(store)
    board = plugin.invoke(operation="create", epic_id="E1", title="Delivery")["board_id"]
    item = {"id":"T1", "type":"task", "title":"Build", "state":"ready"}
    plugin.invoke(operation="add_item", board_id=board, item=item)
    assert plugin.invoke(operation="delete_accepted", board_id=board, accepted_summary="accepted")["deleted"] is False
    item["state"] = "done"
    plugin.invoke(operation="move_item", board_id=board, item=item)
    assert plugin.invoke(operation="delete_accepted", board_id=board, accepted_summary="accepted")["deleted"] is True


def test_kanban_rejects_unmodeled_item_fields_and_states():
    plugin = LocalKanbanPlugin(BoardFixture())
    with pytest.raises(PluginAdapterError):
        plugin.invoke(operation="add_item", board_id="b", item={"id":"i", "type":"task", "title":"x", "state":"ready", "path":"/"})


def test_voice_uses_only_authorized_session_and_local_endpoints_without_retaining_audio():
    fixture = VoiceFixture()
    plugin = WyomingVoicePlugin(fixture, stt_endpoint="http://127.0.0.1:10300", tts_endpoint="http://localhost:10200")
    assert plugin.transcribe(utterance_kind="general")["transcript"] == "fixture transcript"
    assert fixture.seen[:2] == [("capture", 900_000), ("http://127.0.0.1:10300", b"synthetic-wave")]
    assert plugin.speak(text="hello") == {"played": True}
    assert fixture.played == [("trusted-session-1", b"wav-fixture")]
    denied = WyomingVoicePlugin(VoiceFixture(False), stt_endpoint="http://127.0.0.1:10300", tts_endpoint=None)
    with pytest.raises(PluginAdapterError, match="not authorized"):
        denied.transcribe(utterance_kind="general")


def test_voice_rejects_remote_endpoint_and_caller_supplied_audio():
    with pytest.raises(ValueError):
        WyomingVoicePlugin(VoiceFixture(), stt_endpoint="https://voice.example", tts_endpoint=None)
    plugin = WyomingVoicePlugin(VoiceFixture(), stt_endpoint="http://127.0.0.1:10300", tts_endpoint=None)
    with pytest.raises(TypeError):
        plugin.transcribe(audio_b64="caller-controlled", utterance_kind="general")


def test_web_retrieval_checks_direct_tls_public_ip_size_and_untrusted_result():
    url="https://example.com/doc"
    ok=PublicWebPlugin(ReaderFixture([response(url, body=b"hello")])).retrieve(url=url)
    assert ok["content"] == "hello" and ok["untrusted_source"] and ok["authority"] == "none"
    for bad in [response(url, ip="127.0.0.1"), response(url, proxy=True), response(url, tls=False), response(url, body=b"x" * 1_000_001)]:
        with pytest.raises(PluginAdapterError): PublicWebPlugin(ReaderFixture([bad])).retrieve(url=url)


def test_web_redirect_is_revalidated_before_next_request_and_rejects_private_hosts():
    first="https://example.com/start"
    fixture=ReaderFixture([response(first, 302, {"Location":"https://127.0.0.1/admin"})])
    with pytest.raises(PluginAdapterError, match="private"):
        PublicWebPlugin(fixture).retrieve(url=first)
    assert len(fixture.calls) == 1
    for url in ["http://example.com", "https://user:pass@example.com", "https://localhost/x", "https://example.com:444/x"]:
        with pytest.raises(PluginAdapterError): PublicWebPlugin(ReaderFixture([])).retrieve(url=url)


def test_selected_implementations_fail_closed_without_trusted_identity_or_enrolled_services():
    assert set(PLUGIN_IMPLEMENTATIONS) == {"epic-kanban", "voice-pipeline", "web"}
    ctx=RegistrationFixture()
    wrong=type("Runtime", (), {"identity": type("Id", (), {"kind":"plugins", "resource_id":"web"})()})()
    with pytest.raises(PluginAdapterError, match="identity"):
        LocalKanbanImplementation().register(ctx, wrong)
    right=type("Runtime", (), {"identity": type("Id", (), {"kind":"plugins", "resource_id":"web"})(),
                                "direct_https_reader": None})()
    with pytest.raises(PluginAdapterError, match="not enrolled"):
        PublicWebImplementation().register(ctx, right)
    voice=type("Runtime", (), {"identity": type("Id", (), {"kind":"plugins", "resource_id":"voice-pipeline"})(),
                                "voice_session": None})()
    with pytest.raises(PluginAdapterError, match="voice boundary"):
        WyomingVoiceImplementation().register(ctx, voice)
