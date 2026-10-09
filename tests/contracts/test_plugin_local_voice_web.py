from __future__ import annotations

import pytest
import hashlib
import time

from hermes_installer.components.plugin_local_voice_web import (
    LocalKanbanImplementation, LocalKanbanPlugin, PLUGIN_IMPLEMENTATIONS,
    PluginAdapterError, PublicWebImplementation, PublicWebPlugin, WebResponse,
    WyomingVoiceImplementation, WyomingVoicePlugin,
)
from hermes_installer.components.plugin_local_voice_web_schemas import PLUGIN_ACTION_SCHEMAS
from hermes_installer.components.plugin_effects import StaticPluginActionSchemas
from hermes_installer.components.plugin_local_voice_web_schemas import PLUGIN_ACTION_SCHEMAS
from hermes_installer.components.plugin_effects import StaticPluginActionSchemas


class EffectsFixture:
    def __init__(self): self.calls=[]
    def invoke(self, *, adapter_id, action_id, arguments, **_kw):
        self.calls.append((adapter_id, action_id, arguments, dict(_kw)))
        if action_id == "open_session":
            result = {"session_handle": "session-handle", "expires_monotonic": time.monotonic() + 55}
        else:
            result = {
                "create": {"board_id": "board-1"},
                "read": {"board": {"board_id": "board-1"}},
                "add_item": {"item_id": "item-1"},
                "move_item": {"state": "done"},
                "delete_accepted": {"receipt_id": "receipt-1"},
                "capture_audio": {"audio_artifact_id": "audio-artifact", "sha256": "a" * 64, "size_bytes": 12},
                "close_session": {"closed": True},
                "voice_transcribe": {"schema": 1, "transcript": "fixture transcript",
                    "source_receipt_handle": "stt-receipt-1", "profile_id": "profile-1",
                    "owner_generation": "generation-1", "operation_id": "operation-1",
                    "expires_monotonic": time.monotonic() + 30},
                "voice_speak": {"audio_artifact": {
                    "artifact_id": "artifact-123", "sha256": "b" * 64, "size_bytes": 12,
                    "media_type": "audio/wav", "profile_id": "profile-1",
                    "owner_generation": "generation-1", "operation_id": "operation-1",
                    "source_receipt_handle": "tts-receipt-1", "expires_monotonic": time.monotonic() + 30}},
            }[action_id]
        state = "committed" if action_id in {"create", "add_item", "move_item", "delete_accepted"} else "read-complete"
        return {"schema": 1, "operation_id": "operation-1", "state": state,
                "result": result, "verification_status": "verified", "resume_action_id": None}


class ReaderFixture:
    def __init__(self, responses): self.responses=list(responses); self.calls=[]
    def get_one_hop(self, url, *, timeout, max_bytes, cancelled=None):
        self.calls.append((url, timeout, max_bytes))
        return self.responses.pop(0)


class RegistrationFixture:
    def __init__(self): self.tools={}
    def register_tool(self, name, toolset, schema, handler, **kwargs): self.tools[name]=(toolset, schema, handler)


def response(url, status=200, headers=None, body=b"source", ip="93.184.216.34", tls=True, proxy=False):
    return WebResponse(status, headers or {"content-type": "text/plain"}, body, url, ip, tls, proxy,
                       hashlib.sha256(b"fixture-cert").hexdigest())


def test_local_board_crud_is_per_profile_and_delete_requires_accepted_done():
    effects = EffectsFixture(); plugin = LocalKanbanPlugin(effects)
    board = plugin.invoke(operation="create", epic_id="E1", title="Delivery")["board_id"]
    plugin.invoke(operation="add_item", board_id=board, item_type="task", title="Build", description="Implementation")
    plugin.invoke(operation="move_item", board_id=board, item_id="item-1", state="done")
    plugin.invoke(operation="delete_accepted", board_id=board,
                  accepted_lifecycle_attestation_id="attestation-123")
    assert [call[1] for call in effects.calls] == ["create", "add_item", "move_item", "delete_accepted"]
    assert effects.calls[1][2] == {"board_id": board, "item_type": "task", "title": "Build", "description": "Implementation"}
    assert effects.calls[2][2] == {"board_id": board, "item_id": "item-1", "state": "done"}
    assert effects.calls[3][2] == {"board_id": board, "accepted_lifecycle_attestation_id": "attestation-123"}
    assert all(call[0] == "epic-kanban" for call in effects.calls)
    assert all(len(call[3].get("idempotency_key", "")) == 64 for call in effects.calls)


def test_kanban_rejects_unmodeled_item_fields_and_states():
    plugin = LocalKanbanPlugin(EffectsFixture())
    with pytest.raises(PluginAdapterError):
        plugin.invoke(operation="add_item", board_id="b", item_type="exec", title="x", description="")


def test_voice_uses_root_session_stt_tts_effects_without_retaining_audio():
    fixture = EffectsFixture()
    plugin = WyomingVoicePlugin(fixture, "voice-enrollment-1")
    assert plugin.transcribe(mode="general")["transcript"] == "fixture transcript"
    assert plugin.speak(text="hello")["audio_artifact"]["artifact_id"] == "artifact-123"
    assert [call[1] for call in fixture.calls] == ["open_session", "capture_audio", "voice_transcribe", "close_session", "open_session", "voice_speak", "close_session"]
    assert fixture.calls[0][2] == {"session_enrollment_id": "voice-enrollment-1", "direction": "input", "requested_lease_seconds": 60}
    assert fixture.calls[1][2] == {"session_handle": "session-handle", "maximum_seconds": 30}
    assert fixture.calls[2][2] == {"session_handle": "session-handle", "audio_artifact_id": "audio-artifact", "mode": "general"}
    assert fixture.calls[5][2] == {"session_handle": "session-handle", "text": "hello"}
    assert all(call[0] == "voice-pipeline" for call in fixture.calls)
    assert all(len(call[3].get("idempotency_key", "")) == 64 for call in fixture.calls)


def test_voice_rejects_caller_supplied_audio():
    plugin = WyomingVoicePlugin(EffectsFixture(), "voice-enrollment-1")
    with pytest.raises(TypeError):
        plugin.transcribe(audio_b64="caller-controlled", mode="general")


def test_web_retrieval_checks_direct_tls_public_ip_size_and_untrusted_result():
    url="https://example.com/doc"
    class DispatchFixture:
        def invoke(self, *, adapter_id, action_id, arguments):
            assert (adapter_id,action_id,arguments)==("web","retrieve",{"url":url})
            result = {"url":url,"content_type":"text/plain",
                    "content":"hello","untrusted_source":True,"authority":"none",
                    "redirects":0,"source_receipt":{"receipt_sha256":"fixture"}}
            return {"schema":1,"operation_id":"operation-web","state":"read-complete",
                    "result":result,"verification_status":"verified","resume_action_id":None}
    ok=PublicWebPlugin(DispatchFixture()).retrieve(url=url)
    assert ok["content"] == "hello" and ok["untrusted_source"] and ok["authority"] == "none"
    assert ok["source_receipt"]["receipt_sha256"] == "fixture"


def test_web_redirect_is_revalidated_before_next_request_and_rejects_private_hosts():
    first="https://example.com/start"
    fixture=ReaderFixture([response(first, 302, {"Location":"https://127.0.0.1/admin"})])
    from hermes_installer.components.plugin_public_https import PublicHttpsDenied, EnrolledPublicWebScope, PublicReadTarget, retrieve_scoped
    scope=EnrolledPublicWebScope("enrollment-1","target-1","generation-1","principal-1","profile-1",
            "public-web",(PublicReadTarget("example.com",("/",)),))
    with pytest.raises(Exception, match="private"):
        retrieve_scoped(fixture, scope, first, timeout=3, max_bytes=1000, cancelled=lambda:False)
    assert len(fixture.calls) == 1
    from hermes_installer.components.plugin_local_voice_web import _public_https_url
    for url in ["http://example.com", "https://user:pass@example.com", "https://localhost/x", "https://example.com:444/x"]:
        with pytest.raises(PluginAdapterError): _public_https_url(url)


def test_selected_implementations_fail_closed_without_trusted_identity_or_enrolled_services():
    assert set(PLUGIN_IMPLEMENTATIONS) == {"epic-kanban", "voice-pipeline", "web"}
    ctx=RegistrationFixture()
    wrong=type("Runtime", (), {"identity": type("Id", (), {"kind":"plugins", "resource_id":"web"})()})()
    with pytest.raises(PluginAdapterError, match="identity"):
        LocalKanbanImplementation().register(ctx, wrong)
    right=type("Runtime", (), {"identity": type("Id", (), {"kind":"plugins", "resource_id":"web"})(),
                                "plugin_effects": None})()
    with pytest.raises(PluginAdapterError, match="selected-plugin effects"):
        PublicWebImplementation().register(ctx, right)
    voice=type("Runtime", (), {"identity": type("Id", (), {"kind":"plugins", "resource_id":"voice-pipeline"})(),
                                "plugin_effects": None, "voice_session_enrollment_id": None})()
    with pytest.raises(PluginAdapterError, match="selected-plugin effects"):
        WyomingVoiceImplementation().register(ctx, voice)
    missing_session=type("Runtime", (), {"identity": type("Id", (), {"kind":"plugins", "resource_id":"voice-pipeline"})(),
                                         "plugin_effects": EffectsFixture(), "voice_session_enrollment_id": None})()
    with pytest.raises(PluginAdapterError, match="session enrollment"):
        WyomingVoiceImplementation().register(ctx, missing_session)
    epic=type("Runtime", (), {"identity": type("Id", (), {"kind":"plugins", "resource_id":"epic-kanban"})(),
                               "plugin_effects": None})()
    with pytest.raises(PluginAdapterError, match="selected-plugin effects"):
        LocalKanbanImplementation().register(ctx, epic)


def test_epic_and_voice_effects_fail_closed_without_selected_resolver():
    with pytest.raises(TypeError, match="root plugin effect resolver"):
        LocalKanbanPlugin(None)
    with pytest.raises(TypeError, match="root plugin effect resolver"):
        WyomingVoicePlugin(None, "voice-enrollment-1")
    with pytest.raises(PluginAdapterError, match="root-selected voice session enrollment"):
        WyomingVoicePlugin(EffectsFixture(), "")


def test_local_voice_web_action_schema_catalog_is_immutable_and_source_reviewed():
    catalog=StaticPluginActionSchemas(PLUGIN_ACTION_SCHEMAS)
    assert catalog.resolve("epic-kanban", "delete_accepted").operation == "plugin.epic-kanban.delete"
    assert catalog.resolve("epic-kanban", "create").requires_idempotency is True
    assert catalog.resolve("epic-kanban", "read").requires_idempotency is False
    assert catalog.resolve("voice-pipeline", "capture_audio").operation == "plugin.voice-pipeline.session"
    assert catalog.resolve("web", "retrieve").operation == "plugin.web.read"
    with pytest.raises(TypeError):
        PLUGIN_ACTION_SCHEMAS[("web", "retrieve")] = None


def test_local_voice_web_action_schema_catalog_is_immutable_and_source_reviewed():
    catalog=StaticPluginActionSchemas(PLUGIN_ACTION_SCHEMAS)
    assert catalog.resolve("epic-kanban", "delete_accepted").operation == "plugin.epic-kanban.delete"
    assert catalog.resolve("voice-pipeline", "capture_audio").operation == "plugin.voice-pipeline.session"
    assert catalog.resolve("web", "retrieve").operation == "plugin.web.read"
    with pytest.raises(TypeError):
        PLUGIN_ACTION_SCHEMAS[("web", "retrieve")] = None
