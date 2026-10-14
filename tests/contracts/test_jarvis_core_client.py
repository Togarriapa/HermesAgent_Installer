from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import hermes_installer.remote.core_client as core_client
from hermes_installer.remote.core_client import CoreRpcClient, CoreTurnEvent
from hermes_installer.remote.jarvis_chat import JarvisChatDenied


def test_session_creation_and_restart_resume_use_only_server_owned_rpc_params():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    calls = []

    async def rpc(method, params):
        calls.append((method, params))
        if method == "session.create":
            return {"session_id": "runtime-a", "stored_session_id": "stored-a"}
        return {"session_id": "runtime-b", "resumed": "stored-a"}

    client._rpc = rpc
    runtime_id, stored_id = asyncio.run(client.create_session())
    assert (runtime_id, stored_id) == ("runtime-a", "stored-a")
    assert asyncio.run(client.resume_session(stored_id)) == "runtime-b"
    assert calls[0][0] == "session.create"
    assert set(calls[0][1]) == {"source", "title", "idempotency_key"}
    assert calls[0][1]["source"] == "jarvis"
    assert calls[0][1]["title"] == "Jarvis"
    assert calls[0][1]["idempotency_key"].startswith("jarvis_")
    assert calls[1] == ("session.resume", {
        "session_id": "stored-a", "source": "jarvis",
    })


def test_resume_history_uses_official_resume_payload_for_reaped_runtime_sessions():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    calls = []

    async def rpc(method, params):
        calls.append((method, params))
        return {"session_id": "runtime-restored", "resumed": "stored-a", "messages": [
            {"role": "user", "content": "question", "timestamp": 12},
            {"role": "tool", "content": "private tool output"},
            {"role": "assistant", "content": "answer", "reasoning": "private reasoning"},
        ]}

    client._rpc = rpc
    runtime_id, history = asyncio.run(client.resume_history("stored-a"))
    assert runtime_id == "runtime-restored"
    assert history == [
        {"role": "user", "content": "question", "createdAt": 12},
        {"role": "assistant", "content": "answer", "createdAt": 0},
    ]
    assert calls == [("session.resume", {"session_id": "stored-a", "source": "jarvis"})]


def test_resume_rejects_a_different_stored_session_binding():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))

    async def rpc(_method, _params):
        return {"session_id": "runtime-b", "resumed": "somebody-elses-session"}

    client._rpc = rpc
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.resume_session("stored-a"))


def test_history_projects_only_bounded_user_and_assistant_text():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    calls = []

    async def rpc(method, params):
        calls.append((method, params))
        return {"messages": [
            {"role": "user", "text": "question", "timestamp": 12},
            {"role": "tool", "text": "secret tool output", "arguments": {"token": "hidden"}},
            {"role": "assistant", "text": "answer", "reasoning": "private reasoning"},
        ]}

    client._rpc = rpc
    assert asyncio.run(client.history("runtime-a")) == [
        {"role": "user", "content": "question", "createdAt": 12},
        {"role": "assistant", "content": "answer", "createdAt": 0},
    ]
    assert calls == [("session.history", {"session_id": "runtime-a"})]


def test_stop_uses_only_fixed_session_interrupt_and_requires_confirmation():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    calls = []

    async def rpc(method, params):
        calls.append((method, params))
        return {"status": "interrupted"}

    client._rpc = rpc
    asyncio.run(client.stop("runtime-a"))
    assert calls == [("session.interrupt", {"session_id": "runtime-a"})]

    async def unconfirmed(_method, _params):
        return {"status": "unknown"}

    client._rpc = unconfirmed
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.stop("runtime-a"))


def test_lifecycle_startup_probe_uses_only_fixed_rpc_and_closed_single_use_receipt():
    class Socket:
        def __init__(self):
            self.frames = []
            self.closed = False

        async def send_json(self, frame):
            self.frames.append(frame)

        async def close(self):
            self.closed = True

    class ClientSession:
        def __init__(self):
            self.closed = False

        async def close(self):
            self.closed = True

    socket = Socket()
    session = ClientSession()
    client = CoreRpcClient(token_file=Path("/private/fake/token"))

    async def connect(*, total_timeout=None):
        assert total_timeout == 120.0
        return session, socket, SimpleNamespace()

    async def receive(_ws, _types, *, expected_id=None, deadline=None, **_kwargs):
        assert expected_id == socket.frames[0]["id"]
        assert deadline is not None
        assert _kwargs["startup_response"] is True
        return {"schema": 1, "probe_handle": "p" * 32,
                "completion_handle": "c" * 32, "status": "completed",
                "response_sha256": "a" * 64}

    client._connect = connect
    client._receive = receive
    assert asyncio.run(client.lifecycle_startup_probe("p" * 32)) == {
        "schema": 1, "probe_handle": "p" * 32,
        "completion_handle": "c" * 32, "status": "completed",
        "response_sha256": "a" * 64,
    }
    assert socket.frames[0]["method"] == "jarvis.lifecycle_startup_probe"
    assert socket.frames[0]["params"] == {"probe_handle": "p" * 32}
    assert socket.closed and session.closed


@pytest.mark.parametrize("result", [
    {"schema": 1, "probe_handle": "p" * 32, "completion_handle": "c" * 32,
     "status": "completed", "response_sha256": "a" * 64, "answer": "raw"},
    {"schema": 1, "probe_handle": "p" * 32, "completion_handle": "c" * 32,
     "status": "completed", "response_sha256": "a" * 63},
    {"schema": 1, "probe_handle": "p" * 32, "completion_handle": "c" * 32,
     "status": "pending", "response_sha256": "a" * 64},
])
def test_lifecycle_startup_probe_rejects_open_or_incomplete_wire_results(result):
    class Socket:
        async def send_json(self, _frame):
            pass

        async def close(self):
            pass

    class ClientSession:
        async def close(self):
            pass

    client = CoreRpcClient(token_file=Path("/private/fake/token"))

    async def connect(*, total_timeout=None):
        assert total_timeout == 120.0
        return ClientSession(), Socket(), SimpleNamespace()

    async def receive(*_args, **_kwargs):
        return result

    client._connect = connect
    client._receive = receive
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.lifecycle_startup_probe("p" * 32))


def test_lifecycle_startup_probe_rejects_caller_control_and_malformed_handles():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.lifecycle_startup_probe("short"))


@pytest.mark.parametrize("stage", [
    "route",
    "observer_route", "observer_request", "observer_instructions", "observer_input",
    "observer_account", "observer_attempt", "observer_provider", "observer_output",
    "observer_receipt", "result_shape", "result_status", "result_answer", "observer_missing",
])
def test_matched_startup_refusal_uses_fixed_stage_and_native_type_helpers(stage):
    class Socket:
        async def receive(self):
            return SimpleNamespace(type=1, data=json.dumps({
                "jsonrpc": "2.0", "id": "request-1", "error": {
                    "code": -32000, "message": "lifecycle startup probe refused",
                    "data": json.dumps({
                        "exception_type": "RuntimeError", "schema": 1, "stage": stage,
                    }, sort_keys=True, separators=(",", ":")),
                },
            }))

    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    ws_types = SimpleNamespace(TEXT=1, CLOSED=2, CLOSE=3, ERROR=4)
    with pytest.raises(core_client._StartupNativeRuntimeErrorDenied) as caught:
        asyncio.run(client._receive(Socket(), ws_types, expected_id="request-1",
                                    startup_response=True))
    assert str(caught.value) == "official core startup probe was refused"
    origin_names = []
    traceback = caught.value.__traceback__
    while traceback is not None:
        origin_names.append(traceback.tb_frame.f_code.co_name)
        traceback = traceback.tb_next
    assert f"_startup_refused_{stage}" in origin_names


def test_matched_startup_missing_method_has_fixed_refusal_origin():
    class Socket:
        async def receive(self):
            return SimpleNamespace(type=1, data=json.dumps({
                "jsonrpc": "2.0", "id": "request-1", "error": {
                    "code": -32601, "message": "unknown method: private-selector",
                    "data": {"private": "body"},
                },
            }))

    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    ws_types = SimpleNamespace(TEXT=1, CLOSED=2, CLOSE=3, ERROR=4)
    with pytest.raises(core_client._StartupNativeOtherDenied) as caught:
        asyncio.run(client._receive(Socket(), ws_types, expected_id="request-1",
                                    startup_response=True))
    assert str(caught.value) == "official core startup method is unavailable"
    assert core_client._parse_startup_error({
        "code": -32601, "message": "unknown method: hidden-selector",
    }) == ("method_missing", "other")


def test_foreign_startup_error_is_a_generic_refusal():
    class Socket:
        def __init__(self):
            self.frames = iter((
                {"jsonrpc": "2.0", "id": "foreign-request", "error": {
                    "code": -32000, "message": "lifecycle startup probe refused",
                    "data": '{"exception_type":"RuntimeError","schema":1,"stage":"route"}',
                }},
                {"jsonrpc": "2.0", "id": "request-1", "result": {"status": "completed"}},
            ))

        async def receive(self):
            return SimpleNamespace(type=1, data=json.dumps(next(self.frames)))

    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    ws_types = SimpleNamespace(TEXT=1, CLOSED=2, CLOSE=3, ERROR=4)
    assert asyncio.run(client._receive(Socket(), ws_types, expected_id="request-1",
                                       startup_response=True)) == {"status": "completed"}


def test_nonstartup_rpc_error_keeps_generic_refusal_behavior():
    class Socket:
        async def receive(self):
            return SimpleNamespace(type=1, data=json.dumps({
                "jsonrpc": "2.0", "id": "request-1", "error": {
                    "code": -32000, "message": "private native detail",
                    "data": "private native body",
                },
            }))

    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    ws_types = SimpleNamespace(TEXT=1, CLOSED=2, CLOSE=3, ERROR=4)
    with pytest.raises(JarvisChatDenied) as caught:
        asyncio.run(client._receive(Socket(), ws_types, expected_id="request-1"))
    assert type(caught.value) is JarvisChatDenied
    assert str(caught.value) == "official core gateway rejected the request"


@pytest.mark.parametrize("data", [
    '{"stage":"route","schema":1,"exception_type":"RuntimeError"}',
    '{"exception_type":"RuntimeError","schema":1,"stage":"route","stage":"account"}',
    '{"exception_type":"RuntimeError", "schema":1,"stage":"route"}',
    '{"exception_type":"RuntimeError","schema":1,"stage":"not-a-stage"}',
    '{"exception_type":"KeyError","schema":1,"stage":"route"}',
    '{"exception_type":"RuntimeError","schema":1,"stage":[]}',
    '{"exception_type":"RuntimeError","schema":1,"stage":"route"}' + (" " * 513),
    '"RuntimeError"',
])
def test_startup_refusal_parser_rejects_noncanonical_or_open_data(data):
    with pytest.raises((ValueError, UnicodeError)):
        core_client._parse_startup_error({
            "code": -32000, "message": "lifecycle startup probe refused", "data": data,
        })


@pytest.mark.parametrize("error", [
    {"code": -32001, "message": "lifecycle startup probe refused",
     "data": '{"exception_type":"RuntimeError","schema":1,"stage":"route"}'},
    {"code": -32000, "message": "different",
     "data": '{"exception_type":"RuntimeError","schema":1,"stage":"route"}'},
    {"code": -32601, "message": "unknown method: private-selector", "data": None,
     "extra": "foreign"},
    {"code": True, "message": "lifecycle startup probe refused",
     "data": '{"exception_type":"RuntimeError","schema":1,"stage":"route"}'},
])
def test_startup_refusal_parser_rejects_foreign_or_malformed_rpc_errors(error):
    with pytest.raises(ValueError):
        core_client._parse_startup_error(error)


def test_models_status_projects_only_codex_authentication_and_known_catalog():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    calls = []

    async def rpc(method, params):
        calls.append((method, params))
        return {"model": "gpt-6-luna", "provider": "unknown", "providers": [
            {"id": "openai-codex", "label": "ChatGPT Codex", "aliases": [],
             "authenticated": True},
            {"id": "openai", "label": "OpenAI API", "aliases": [],
             "authenticated": False},
        ]}

    client._rpc = rpc
    assert asyncio.run(client.get_model_provider_status()) == {
        "model": "gpt-6-luna", "provider_hint": "unknown",
        "codex_credential_configured": True, "known_model": True,
    }
    assert calls == [("config.get", {"key": "provider"})]


def test_models_status_rejects_ambiguous_or_malformed_codex_authentication():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))

    async def rpc(_method, _params):
        return {"model": "gpt-6-luna", "provider": "unknown", "providers": [
            {"id": "openai-codex", "authenticated": True},
            {"id": "openai-codex", "authenticated": False},
        ]}

    client._rpc = rpc
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.get_model_provider_status())


def test_context_and_status_reads_use_only_owner_resolved_live_session_and_strip_native_extras():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    calls = []
    native_context = {
        "categories": [{"color": "var(--private-color)", "id": "conversation",
                        "label": "Conversation", "tokens": 14}],
        "context_max": 100, "context_percent": 14, "context_used": 14,
        "estimated_total": 17, "context_estimated": False,
        "context_source": "provider_usage", "model": "zai/glm-5.2",
        "context_files": [{"path": "/home/private/CLAUDE.md", "chars": 42}],
    }
    native_status = {"output": (
        "Path: /home/private/workspace\nSession ID: private-runtime\n"
        "Created: 2026-10-11 09:30\nLast Activity: 2026-10-11 09:45\n"
        "Tokens: 14\nAgent Running: No\n")}

    async def rpc(method, params):
        calls.append((method, params))
        return native_context if method == "session.context_breakdown" else native_status

    client._rpc = rpc
    context = asyncio.run(client.session_context_breakdown("runtime-owner-live"))
    status = asyncio.run(client.session_status("runtime-owner-live"))
    assert calls == [
        ("session.context_breakdown", {"session_id": "runtime-owner-live"}),
        ("session.status", {"session_id": "runtime-owner-live"}),
    ]
    assert context == {
        "categories": [{"id": "conversation", "label": "Conversation", "tokens": 14}],
        "context_max": 100, "context_percent": 14, "context_used": 14,
        "estimated_total": 17, "context_estimated": False,
        "context_source": "provider_usage", "model": "zai/glm-5.2",
    }
    assert "private" not in repr(context)
    assert set(status) == {"output"}
    assert "/home/private" in status["output"]  # raw status stays private for Jarvis' allowlist parser
    from hermes_installer.remote.jarvis_context import decode_session_status
    projected = decode_session_status(status)
    assert projected["state"] == "observed" and projected["running"] is False
    assert "/home/private" not in repr(projected)
    assert "private-runtime" not in repr(projected)


@pytest.mark.parametrize("session_id", ["", "bad\nsession", {"session_id": "runtime"}])
def test_session_context_reads_reject_unresolved_or_malformed_session_selectors(session_id):
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    calls = []

    async def rpc(method, params):
        calls.append((method, params))
        return {}

    client._rpc = rpc
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.session_context_breakdown(session_id))
    assert calls == []


def test_context_adapter_rejects_malformed_native_stats_and_open_ended_fields():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))

    async def rpc(_method, _params):
        return {
            "categories": [], "context_max": True, "context_percent": 0, "context_used": 0,
            "estimated_total": 0, "context_estimated": False,
            "context_source": "provider_usage", "model": "zai/glm-5.2",
            "private_secret": "should never pass through",
        }

    client._rpc = rpc
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.session_context_breakdown("runtime-owner-live"))


def test_session_read_adapter_enforces_short_deadline_and_bounds_status_payload(monkeypatch):
    from hermes_installer.remote import core_client

    monkeypatch.setattr(core_client, "SESSION_READ_TIMEOUT_SECONDS", 0.01)
    client = CoreRpcClient(token_file=Path("/private/fake/token"))

    async def slow_rpc(_method, _params):
        await asyncio.sleep(0.1)
        return {"output": "never reached"}

    client._rpc = slow_rpc
    with pytest.raises(JarvisChatDenied, match="deadline"):
        asyncio.run(client.session_status("runtime-owner-live"))

    async def oversized_rpc(_method, _params):
        return {"output": "x" * 8_193}

    client._rpc = oversized_rpc
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.session_status("runtime-owner-live"))


def test_models_selection_constructs_only_fixed_session_scoped_native_call():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    socket = _ModelsWebSocket()

    async def connect():
        return _FakeClient(), socket, _WsTypes

    client._connect = connect
    bindings = []

    async def bind(actual_session_id):
        bindings.append(actual_session_id)
        return True

    assert asyncio.run(client.set_session_model("stored-a", "gpt-6-sol",
                                                before_set=bind)) == {
        "model": "gpt-6-sol", "state": "selected-for-session",
    }
    assert [frame["method"] for frame in socket.sent] == ["session.resume", "config.set"]
    assert socket.sent[0]["params"] == {"session_id": "stored-a", "source": "jarvis",
                                         "eager_build": True}
    assert socket.sent[1]["params"] == {"key": "model",
        "value": "gpt-6-sol --provider openai-codex --session", "session_id": "runtime-a"}
    assert bindings == ["runtime-a"]


@pytest.mark.parametrize("event_timing", ["early", "after-resume"])
def test_models_cold_resume_waits_for_matching_built_session_info(event_timing):
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    socket = _ModelsWebSocket(
        resume_info={"model": "gpt-6-luna", "provider": "openai-codex", "lazy": True},
        ready_event_timing=event_timing)

    async def connect():
        return _FakeClient(), socket, _WsTypes

    client._connect = connect
    calls = []

    async def bind(actual_session_id):
        calls.append(("bind", actual_session_id))
        return True

    result = asyncio.run(client.set_session_model("stored-a", "gpt-6-sol", before_set=bind))
    assert result == {"model": "gpt-6-sol", "state": "selected-for-session"}
    assert [frame["method"] for frame in socket.sent] == ["session.resume", "config.set"]
    assert calls == [("bind", "runtime-a")]


def test_models_cold_resume_timeout_does_not_bind_or_set_model():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    client._timeout_seconds = 0.01
    socket = _ModelsWebSocket(
        resume_info={"model": "gpt-6-luna", "provider": "openai-codex", "lazy": True})

    async def connect():
        return _FakeClient(), socket, _WsTypes

    client._connect = connect
    bindings = []

    async def bind(actual_session_id):
        bindings.append(actual_session_id)
        return True

    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.set_session_model("stored-a", "gpt-6-sol", before_set=bind))
    assert [frame["method"] for frame in socket.sent] == ["session.resume"]
    assert bindings == []


@pytest.mark.parametrize("session_id,model_id", [
    ("runtime-a", "arbitrary/model"), ("runtime-a", "gpt-5.3-codex-spark"),
    ("bad\nkey", "gpt-6-sol"), ("runtime-a", []),
])
def test_models_selection_rejects_unbounded_ids_before_rpc(session_id, model_id):
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    calls = []

    async def rpc(method, params):
        calls.append((method, params))
        return {}

    async def bind(_runtime_id):
        return True

    client._rpc = rpc
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.set_session_model(session_id, model_id, before_set=bind))
    assert calls == []


def test_models_selection_reports_deferred_and_denies_unexpected_scope():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    async def run_with(result):
        socket = _ModelsWebSocket(set_result=result)
        async def connect():
            return _FakeClient(), socket, _WsTypes
        client._connect = connect
        async def bind(_runtime_id):
            return True
        return await client.set_session_model("stored-a", "gpt-6-sol", before_set=bind)

    deferred = {"key": "model", "value": "gpt-6-sol", "scope": "session",
                "warning": "", "confirm_required": False, "confirm_message": "", "deferred": True}
    assert asyncio.run(run_with(deferred))["state"] == "deferred-next-turn"
    global_scope = {"key": "model", "value": "gpt-6-sol", "scope": "global",
                    "warning": "", "confirm_required": False, "confirm_message": ""}
    with pytest.raises(JarvisChatDenied):
        asyncio.run(run_with(global_scope))


class _FakeClient:
    async def close(self):
        pass


class _FakeWebSocket:
    def __init__(self, frames):
        self.frames = list(frames)
        self.sent = None

    async def send_json(self, frame):
        self.sent = frame

    async def receive(self):
        return self.frames.pop(0)

    async def close(self):
        pass


_WsTypes = SimpleNamespace(CLOSED=2, CLOSE=3, ERROR=4, TEXT=1)


class _ModelsWebSocket:
    def __init__(self, *, set_result=None, resume_info=None, ready_event_timing=None):
        self.frames = []
        self.sent = []
        self.resume_info = resume_info
        self.ready_event_timing = ready_event_timing
        self.ready_event_sent = False
        self.set_result = set_result or {"key": "model", "value": "gpt-6-sol", "scope": "session",
            "warning": "", "confirm_required": False, "confirm_message": ""}

    async def send_json(self, frame):
        self.sent.append(frame)
        if frame["method"] == "session.resume":
            stored_id = frame["params"]["session_id"]
            result = {"session_id": "runtime-a", "resumed": stored_id,
                      "info": self.resume_info or {
                          "model": "gpt-6-luna", "provider": "openai-codex",
                          "stored_session_id": stored_id}}
            if self.ready_event_timing == "early":
                self.frames.append(self._ready_event(stored_id))
        else:
            result = self.set_result
        self.frames.append(_frame("rpc", json.dumps({"jsonrpc": "2.0", "id": frame["id"],
                                                       "result": result})))

    async def receive(self):
        if not self.frames and self.ready_event_timing == "after-resume" and not self.ready_event_sent:
            stored_id = self.sent[0]["params"]["session_id"]
            self.ready_event_sent = True
            return self._ready_event(stored_id)
        if not self.frames:
            await asyncio.Future()
        return self.frames.pop(0)

    @staticmethod
    def _ready_event(stored_id):
        return _frame("event", json.dumps({"jsonrpc": "2.0", "method": "event",
            "params": {"type": "session.info", "session_id": "runtime-a", "payload": {
                "model": "gpt-6-luna", "provider": "openai-codex",
                "stored_session_id": stored_id}}}))

    async def close(self):
        pass


def _frame(kind, payload):
    return SimpleNamespace(type=1, data=payload, kind=kind)


def _resume_reply(frame):
    stored_id = frame["params"]["session_id"]
    return _frame("rpc", json.dumps({
        "jsonrpc": "2.0", "id": frame["id"],
        "result": {"session_id": "runtime-a", "resumed": stored_id},
    }))


def test_stream_filters_to_current_session_text_and_real_terminal_result():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    ws_types = SimpleNamespace(CLOSED=2, CLOSE=3, ERROR=4, TEXT=1)
    ws = _FakeWebSocket([])
    original_send = ws.send_json

    async def connect():
        return _FakeClient(), ws, ws_types

    client._connect = connect

    async def collect():
        async def send_and_set_frames(frame):
            await original_send(frame)
            if frame["method"] == "session.resume":
                ws.frames = [_resume_reply(frame)]
                return
            request_id = frame["id"]
            ws.frames = [
                _frame("rpc", '{"jsonrpc":"2.0","id":"' + request_id
                       + '","result":{"status":"streaming"}}'),
                _frame("event", '{"method":"event","params":{"type":"message.delta",'
                       '"session_id":"runtime-other","payload":{"text":"hidden"}}}'),
                _frame("event", '{"method":"event","params":{"type":"message.delta",'
                       '"session_id":"runtime-a","payload":{"text":"hello"}}}'),
                _frame("event", '{"method":"event","params":{"type":"message.complete",'
                       '"session_id":"runtime-a","payload":{"status":"complete",'
                       '"text":"hello"}}}'),
            ]

        ws.send_json = send_and_set_frames
        try:
            return [item async for item in client.stream("runtime-a", "hi")]
        finally:
            ws.send_json = original_send

    items = asyncio.run(collect())
    assert [item.kind for item in items] == ["delta", "activity", "complete"]
    assert items[1].activity.event_type == "message.complete"
    assert ws.sent["method"] == "prompt.submit"
    assert ws.sent["params"] == {"session_id": "runtime-a", "text": "hi"}


def test_final_only_response_is_projected_as_text_before_success():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    ws_types = SimpleNamespace(CLOSED=2, CLOSE=3, ERROR=4, TEXT=1)
    ws = _FakeWebSocket([])
    original_send = ws.send_json

    async def connect():
        return _FakeClient(), ws, ws_types

    async def send_with_final_only_response(frame):
        await original_send(frame)
        if frame["method"] == "session.resume":
            ws.frames = [_resume_reply(frame)]
            return
        request_id = frame["id"]
        ws.frames = [
            _frame("rpc", '{"jsonrpc":"2.0","id":"' + request_id
                   + '","result":{"status":"streaming"}}'),
            _frame("event", '{"method":"event","params":{"type":"message.complete",'
                   '"session_id":"runtime-a","payload":{"status":"complete",'
                   '"text":"answer without deltas"}}}'),
        ]

    client._connect = connect
    ws.send_json = send_with_final_only_response

    async def collect():
        return [item async for item in client.stream("runtime-a", "question")]

    items = asyncio.run(collect())
    assert [item.kind for item in items] == ["delta", "activity", "complete"]
    assert items[1].activity.event_type == "message.complete"


@pytest.mark.parametrize(("status", "expected"), [
    ("error", CoreTurnEvent("failed")),
    ("interrupted", CoreTurnEvent("cancelled")),
])
def test_backend_failure_or_interrupt_never_becomes_success(status, expected):
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    ws_types = SimpleNamespace(CLOSED=2, CLOSE=3, ERROR=4, TEXT=1)
    ws = _FakeWebSocket([])
    original_send = ws.send_json

    async def connect():
        return _FakeClient(), ws, ws_types

    async def send_terminal(frame):
        await original_send(frame)
        if frame["method"] == "session.resume":
            ws.frames = [_resume_reply(frame)]
            return
        request_id = frame["id"]
        ws.frames = [
            _frame("rpc", '{"jsonrpc":"2.0","id":"' + request_id
                   + '","result":{"status":"streaming"}}'),
            _frame("event", '{"method":"event","params":{"type":"message.complete",'
                   '"session_id":"runtime-a","payload":{"status":"' + status
                   + '","text":"sensitive backend error"}}}'),
        ]

    client._connect = connect
    ws.send_json = send_terminal

    async def collect():
        return [item async for item in client.stream("runtime-a", "question")]

    items = asyncio.run(collect())
    assert [item.kind for item in items] == ["activity", expected.kind]
    assert items[0].activity.event_type == "message.complete"


def test_final_text_mismatch_does_not_emit_a_false_success():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    ws_types = SimpleNamespace(CLOSED=2, CLOSE=3, ERROR=4, TEXT=1)
    ws = _FakeWebSocket([])
    original_send = ws.send_json

    async def connect():
        return _FakeClient(), ws, ws_types

    async def send_mismatched_final(frame):
        await original_send(frame)
        if frame["method"] == "session.resume":
            ws.frames = [_resume_reply(frame)]
            return
        request_id = frame["id"]
        ws.frames = [
            _frame("rpc", '{"jsonrpc":"2.0","id":"' + request_id
                   + '","result":{"status":"streaming"}}'),
            _frame("event", '{"method":"event","params":{"type":"message.delta",'
                   '"session_id":"runtime-a","payload":{"text":"draft"}}}'),
            _frame("event", '{"method":"event","params":{"type":"message.complete",'
                   '"session_id":"runtime-a","payload":{"status":"complete",'
                   '"text":"rewritten final"}}}'),
        ]

    client._connect = connect
    ws.send_json = send_mismatched_final

    async def collect():
        return [item async for item in client.stream("runtime-a", "question")]

    with pytest.raises(JarvisChatDenied, match="did not match"):
        asyncio.run(collect())


def test_stream_eof_without_backend_terminal_is_never_success():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    ws_types = SimpleNamespace(CLOSED=2, CLOSE=3, ERROR=4, TEXT=1)
    ws = _FakeWebSocket([])
    original_send = ws.send_json

    async def connect():
        return _FakeClient(), ws, ws_types

    client._connect = connect

    async def send_and_set_frames(frame):
        await original_send(frame)
        if frame["method"] == "session.resume":
            ws.frames = [_resume_reply(frame)]
            return
        request_id = frame["id"]
        ws.frames = [
            _frame("rpc", '{"jsonrpc":"2.0","id":"' + request_id
                   + '","result":{"status":"streaming"}}'),
            _frame("close", ""),
        ]
        ws.frames[-1].type = ws_types.CLOSED

    ws.send_json = send_and_set_frames

    async def collect():
        return [item async for item in client.stream("runtime-a", "hi")]

    with pytest.raises(JarvisChatDenied):
        asyncio.run(collect())


def test_native_activity_projection_is_session_bound_and_excludes_payload_content():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    frame = {"method": "event", "params": {
        "type": "tool.complete", "session_id": "runtime-a", "payload": {
            "tool_id": "tool-123", "name": "browser", "duration_s": 1.25,
            "args": {"token": "private-argument"}, "result": "private-result",
        }}}
    projected = client._activity_from_frame(frame, "runtime-a")
    assert projected.event_type == "tool.complete"
    assert projected.status == "returned"
    assert projected.duration_ms == 1250
    assert projected.source_identity == "tool-123"
    assert "private-argument" not in repr(projected)
    assert client._activity_from_frame(frame, "runtime-b") is None

    native_child = {"method": "event", "params": {
        "type": "subagent.start", "session_id": "runtime-a", "payload": {
            "goal": "private goal", "child_session_id": "native-child-session-42",
            "subagent_id": "native-subagent-key", "status": "running", "task_count": 1,
            "task_index": 0,
        }}}
    child = client._activity_from_frame(native_child, "runtime-a")
    assert child.event_type == "subagent.start"
    assert child.child_session_id == "native-child-session-42"
    assert child.status == "running"
    assert "private goal" not in repr(child)
    assert "native-child-session-42" not in repr(child)
    assert client._activity_from_frame(native_child, "runtime-b") is None
    malformed_child = {"method": "event", "params": {
        "type": "subagent.complete", "session_id": "runtime-a", "payload": {
            "child_session_id": "runtime-a", "status": "completed"}}}
    assert client._activity_from_frame(malformed_child, "runtime-a") is None

    delegation = {"method": "event", "params": {
        "type": "subagent.complete", "session_id": "runtime-a", "payload": {
            "goal": "secret user prompt", "subagent_id": "private-child-id", "status": "failed",
            "duration_seconds": 3.5, "tokens": 250,
        }}}
    subagent = client._activity_from_frame(delegation, "runtime-a")
    assert subagent.event_type == "subagent.complete"
    assert subagent.status == "failed"
    assert subagent.duration_ms == 3500
    assert subagent.usage is None
    assert "secret user prompt" not in repr(subagent)
    assert "private-child-id" not in repr(subagent)


def test_approval_event_observations_are_session_bound_and_do_not_reply():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    approval = {"method": "approval", "id": "server-request-1", "params": {
        "session_id": "runtime-a", "command": "private command"}}
    assert client._activity_from_frame(approval, "runtime-a").status == "pending"
    assert client._activity_from_frame(approval, "runtime-b") is None
    cancelled = {"method": "event", "params": {"type": "approval.cancelled",
        "session_id": "", "payload": {"session_id": "runtime-a", "request_ids": ["secret-id"]}}}
    projected = client._activity_from_frame(cancelled, "runtime-a")
    assert projected.status == "cancelled"
    assert projected.source_identity
    assert "secret-id" not in repr(projected)


def test_fixed_status_adapters_drop_metadata_and_use_server_default_profile():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    calls = []

    async def rpc(method, params):
        calls.append((method, params))
        if method == "profiles.list":
            return {"profiles": [
                {"name": "other", "is_default": False, "path": "/private/other"},
                {"name": "default", "display_name": "Home", "is_default": True,
                 "path": "/private/home", "model": "private-model", "provider": "private"},
            ]}
        if method == "cron.manage":
            return {"success": True, "jobs": [{"job_id": "job-secret-id", "name": "private prompt fallback",
                "prompt_preview": "private prompt", "schedule": "daily", "enabled": True,
                "next_run_at": "2026-10-12T09:00:00Z", "last_run_at": None,
                "last_status": "ok", "state": "scheduled", "paused_at": None,
                "workdir": "/private/path"}]}
        if method == "plugins.list":
            return {"plugins": [{"name": "local", "version": "1.2", "enabled": True,
                                 "settings": {"secret": "private"}}]}
        return {"servers": [{"name": "mcp", "transport": "stdio", "tools": 2,
                             "connected": False, "disabled": False, "status": "lazy",
                             "source": "private", "plugin": "private-name", "command": "secret"}],
                "checked_at": 1_791_691_200_000}

    client._rpc = rpc
    assert asyncio.run(client.list_profiles()) == [
        {"name": "default", "display_name": "Home", "is_default": True}]
    schedules = asyncio.run(client.list_schedules())
    assert schedules[0]["name"] == "Scheduled job"
    assert schedules[0]["schedule"] == "daily"
    assert schedules[0]["next_run_at"] == "2026-10-12T09:00:00Z"
    assert "workdir" not in schedules[0]
    assert asyncio.run(client.list_plugins()) == [
        {"name": "local", "version": "1.2", "enabled": True}]
    assert asyncio.run(client.mcp_status()) == {"servers": [{
        "name": "mcp", "transport": "stdio", "tools": 2, "connected": False,
        "disabled": False, "status": "lazy"}], "checked_at": 1_791_691_200_000}
    assert calls == [
        ("profiles.list", {"include_sessions": False}),
        ("cron.manage", {"action": "list", "include_disabled": True}),
        ("plugins.list", {}), ("mcp.servers.status", {}),
    ]


def test_mcp_extension_projection_keeps_provider_identity_without_connection_secrets():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    calls = []

    async def rpc(method, params):
        calls.append((method, params))
        return {"servers": [{"name": "plugin-server", "transport": "stdio", "enabled": True,
                             "source": "plugin", "plugin": "bundled-provider",
                             "command": "private-command", "env": {"TOKEN": "private-secret"}}]}

    client._rpc = rpc
    result = asyncio.run(client.list_mcp_servers())
    assert result[0]["plugin"] == "bundled-provider"
    assert result[0]["source"] == "plugin"
    assert "private-command" not in repr(result)
    assert "private-secret" not in repr(result)
    assert calls == [("mcp.servers.list", {})]
