from __future__ import annotations

import asyncio
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
        "session_id": "stored-a", "source": "jarvis", "defer_history": True,
        "omit_messages": True,
    })


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
    assert items == [CoreTurnEvent("delta", "hello"), CoreTurnEvent("complete")]
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

    assert asyncio.run(collect()) == [
        CoreTurnEvent("delta", "answer without deltas"), CoreTurnEvent("complete")]


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

    assert asyncio.run(collect()) == [expected]


def test_final_text_mismatch_does_not_emit_a_false_success():
    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    ws_types = SimpleNamespace(CLOSED=2, CLOSE=3, ERROR=4, TEXT=1)
    ws = _FakeWebSocket([])
    original_send = ws.send_json

    async def connect():
        return _FakeClient(), ws, ws_types

    async def send_mismatched_final(frame):
        await original_send(frame)
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
