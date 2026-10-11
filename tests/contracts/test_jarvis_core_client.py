from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

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


def test_models_selection_constructs_only_fixed_session_scoped_native_call():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    calls = []

    async def rpc(method, params):
        calls.append((method, params))
        return {"key": "model", "value": "gpt-6-sol", "scope": "session",
                "warning": "", "confirm_required": False, "confirm_message": ""}

    client._rpc = rpc
    assert asyncio.run(client.set_session_model("runtime-a", "gpt-6-sol")) == {
        "model": "gpt-6-sol", "state": "selected-for-session",
    }
    assert calls == [("config.set", {
        "key": "model", "value": "gpt-6-sol --provider openai-codex --session",
        "session_id": "runtime-a",
    })]


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

    client._rpc = rpc
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.set_session_model(session_id, model_id))
    assert calls == []


def test_models_selection_reports_deferred_and_denies_unexpected_scope():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))

    async def deferred(_method, _params):
        return {"key": "model", "value": "gpt-6-sol", "scope": "session",
                "warning": "", "confirm_required": False, "confirm_message": "",
                "deferred": True}

    client._rpc = deferred
    assert asyncio.run(client.set_session_model("runtime-a", "gpt-6-sol"))["state"] == "deferred-next-turn"

    async def global_scope(_method, _params):
        return {"key": "model", "value": "gpt-6-sol", "scope": "global",
                "warning": "", "confirm_required": False, "confirm_message": ""}

    client._rpc = global_scope
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.set_session_model("runtime-a", "gpt-6-sol"))


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
