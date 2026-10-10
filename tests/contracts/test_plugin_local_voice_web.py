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
        result = {
            "create": {"board_id": "board-1"},
            "read": {"board": {"board_id": "board-1"}},
            "add_item": {"item_id": "item-1"},
            "move_item": {"state": "done"},
            "delete_accepted": {"receipt_id": "receipt-1"},
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
    plugin = WyomingVoicePlugin(fixture)
    assert plugin.transcribe(mode="general")["transcript"] == "fixture transcript"
    assert plugin.speak(text="hello")["audio_artifact"]["artifact_id"] == "artifact-123"
    assert [call[1] for call in fixture.calls] == ["voice_transcribe", "voice_speak"]
    assert fixture.calls[0][2] == {"mode": "general"}
    assert fixture.calls[1][2] == {"text": "hello"}
    assert all(call[0] == "voice-pipeline" for call in fixture.calls)
    assert all(len(call[3].get("idempotency_key", "")) == 64 for call in fixture.calls)


def test_voice_rejects_caller_supplied_audio():
    plugin = WyomingVoicePlugin(EffectsFixture())
    with pytest.raises(TypeError):
        plugin.transcribe(audio_b64="caller-controlled", mode="general")


def test_web_retrieval_checks_direct_tls_public_ip_size_and_untrusted_result():
    url="https://example.com/doc"
    body=b"hello"
    digest=hashlib.sha256(body).hexdigest()
    class DispatchFixture:
        def invoke(self, *, adapter_id, action_id, arguments):
            assert (adapter_id,action_id,arguments)==("web","retrieve",{"url":url})
            result = {"url":url,"content_type":"text/plain; charset=utf-8",
                    "content":"hello","untrusted_source":True,"authority":"none",
                    "redirects":[url],"source_receipt":{
                        "artifact_id":"web-content:"+digest,"sha256":digest,
                        "size_bytes":len(body),"media_type":"text/plain",
                        "profile_id":"profile-1","owner_generation":"generation-1",
                        "operation_id":"operation-web","source_receipt_handle":"receipt-handle-1",
                        "expires_monotonic":time.monotonic()+30}}
            return {"schema":1,"operation_id":"operation-web","state":"read-complete",
                    "result":result,"verification_status":"verified","resume_action_id":None}
    ok=PublicWebPlugin(DispatchFixture()).retrieve(url=url)
    assert ok["content"] == "hello" and ok["untrusted_source"] and ok["authority"] == "none"
    assert ok["source_receipt"]["artifact_id"] == "web-content:"+digest


@pytest.mark.parametrize("mutation", ["digest", "operation", "extra", "private_redirect", "trust"])
def test_web_result_rejects_unbound_receipt_or_promoted_source(mutation):
    url = "https://example.com/doc"
    digest = hashlib.sha256(b"hello").hexdigest()
    receipt = {
        "artifact_id": "web-content:" + digest, "sha256": digest, "size_bytes": 5,
        "media_type": "text/plain", "profile_id": "profile-1",
        "owner_generation": "generation-1", "operation_id": "operation-web",
        "source_receipt_handle": "receipt-handle-1", "expires_monotonic": time.monotonic() + 30,
    }
    result = {"url": url, "content_type": "text/plain", "content": "hello",
              "untrusted_source": True, "authority": "none", "redirects": [url],
              "source_receipt": receipt}
    if mutation == "digest":
        result["source_receipt"] = {**receipt, "sha256": "0" * 64}
    elif mutation == "operation":
        result["source_receipt"] = {**receipt, "operation_id": "other-operation"}
    elif mutation == "extra":
        result["source_receipt"] = {**receipt, "caller_source_id": "claimed"}
    elif mutation == "private_redirect":
        result["redirects"] = [url, "https://127.0.0.1/secret"]
        result["url"] = result["redirects"][-1]
    else:
        result["authority"] = "trusted"

    class DispatchFixture:
        def invoke(self, **_kwargs):
            return {"schema": 1, "operation_id": "operation-web", "state": "read-complete",
                    "result": result, "verification_status": "verified", "resume_action_id": None}

    with pytest.raises(PluginAdapterError):
        PublicWebPlugin(DispatchFixture()).retrieve(url=url)


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
    selected_voice=type("Runtime", (), {"identity": type("Id", (), {"kind":"plugins", "resource_id":"voice-pipeline"})(),
                                         "plugin_effects": EffectsFixture(), "voice_session_enrollment_id": None})()
    WyomingVoiceImplementation().register(ctx, selected_voice)
    epic=type("Runtime", (), {"identity": type("Id", (), {"kind":"plugins", "resource_id":"epic-kanban"})(),
                               "plugin_effects": None})()
    with pytest.raises(PluginAdapterError, match="selected-plugin effects"):
        LocalKanbanImplementation().register(ctx, epic)


def test_epic_and_voice_effects_fail_closed_without_selected_resolver():
    with pytest.raises(TypeError, match="root plugin effect resolver"):
        LocalKanbanPlugin(None)
    with pytest.raises(TypeError, match="root plugin effect resolver"):
        WyomingVoicePlugin(None)


def test_local_voice_web_action_schema_catalog_is_immutable_and_source_reviewed():
    from hermes_installer.components.plugin_local_voice_web_schemas import PLUGIN_ACTION_SCHEMA_VARIANTS
    catalog=StaticPluginActionSchemas(PLUGIN_ACTION_SCHEMAS, variants=PLUGIN_ACTION_SCHEMA_VARIANTS)
    assert catalog.resolve("epic-kanban", "delete_accepted").operation == "plugin.epic-kanban.delete"
    assert catalog.resolve("epic-kanban", "create").requires_idempotency is True
    assert catalog.resolve("epic-kanban", "read").requires_idempotency is False
    assert catalog.resolve("voice-pipeline", "capture_audio").operation == "plugin.voice-pipeline.session"
    assert catalog.resolve("web", "retrieve").operation == "plugin.web.read"
    transcribe = catalog.resolve("voice-pipeline", "voice_transcribe", "voice-transcribe-session-workflow-v1")
    speak = catalog.resolve("voice-pipeline", "voice_speak", "voice-speak-session-workflow-v1")
    assert transcribe is not None and transcribe.argument_schema["required"] == ("mode",)
    assert speak is not None and speak.argument_schema["required"] == ("text",)
    assert transcribe.result_schema_id == "voice-pipeline.voice_transcribe.result.v1"
    assert speak.result_schema_id == "voice-pipeline.voice_speak.result.v1"
    with pytest.raises(TypeError):
        PLUGIN_ACTION_SCHEMAS[("web", "retrieve")] = None
