from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from hermes_installer.remote.core_client import CoreRpcClient, NativeFileAttachment
from hermes_installer.remote.jarvis_chat import JarvisChatDenied


class _FixedReplyClient(CoreRpcClient):
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def _rpc(self, method, params):
        self.calls.append((method, params))
        return self.result


def test_toolset_and_skill_inventory_use_literal_no_argument_reads_and_closed_rows():
    client = _FixedReplyClient({"toolsets": [{
        "name": "web", "description": "private description", "tool_count": 1,
        "enabled": True, "tools": ["web.search"], "provider": "secret",
    }]})
    assert asyncio.run(client.toolsets_inventory()) == [{
        "name": "web", "tool_count": 1, "enabled": True, "tools": ["web.search"],
    }]
    assert client.calls == [("tools.list", {})]

    client.result = {"skills": {"general": ["summarize"]}}
    assert asyncio.run(client.skills_inventory()) == [{
        "category": "general", "names": ["summarize"],
    }]
    assert client.calls[-1] == ("skills.manage", {"action": "list"})


def test_inventory_rejects_unbounded_or_malformed_rows():
    client = _FixedReplyClient({"toolsets": [{
        "name": "web", "tool_count": 2, "enabled": True, "tools": ["ok", "bad\nname"],
    }]})
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.toolsets_inventory())
    client.result = {"skills": {"general": ["a", "b"], "extra": "not a list"}}
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.skills_inventory())


def test_file_attachment_adapter_constructs_only_bounded_data_url_and_hides_native_path():
    client = _FixedReplyClient({
        "attached": True, "uploaded": True, "name": "notes.txt",
        "path": "/private/home/attachments/notes.txt",
        "ref_text": "@file:attachments/notes.txt",
    })
    result = asyncio.run(client.attach_file(
        "runtime-session", name="notes.txt", media_type="text/plain", content=b"abc"))

    assert result == NativeFileAttachment("notes.txt", "@file:attachments/notes.txt")
    method, params = client.calls[0]
    assert method == "file.attach"
    assert params == {
        "session_id": "runtime-session", "path": "",
        "data_url": "data:text/plain;base64,YWJj", "name": "notes.txt",
    }
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.attach_file(
            "runtime-session", name="../secret", media_type="text/plain", content=b"abc"))


def test_schedule_pause_is_fixed_and_requires_native_paused_postcondition():
    client = _FixedReplyClient({
        "success": True, "job": {"job_id": "job-1", "state": "paused"},
    })
    assert asyncio.run(client.pause_schedule("job-1")) is None
    assert client.calls == [("cron.manage", {"action": "pause", "name": "job-1"})]

    client.result = {"success": True, "job": {"job_id": "job-1", "state": "scheduled"}}
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.pause_schedule("job-1"))


def test_owned_turn_resumes_and_submits_on_the_same_websocket_before_callback():
    order = []

    class FakeTypes:
        TEXT, CLOSED, CLOSE, ERROR = 1, 2, 3, 4

    class FakeClient:
        async def close(self):
            order.append("client_closed")

    class FakeSocket:
        def __init__(self):
            self.frames = []
            self.resume_id = None

        async def send_json(self, request):
            order.append(("send", request["method"], request["params"].copy()))
            if request["method"] == "session.resume":
                self.resume_id = request["id"]
                self.frames.append(SimpleNamespace(type=1, data=json.dumps({
                    "jsonrpc": "2.0", "id": request["id"],
                    "result": {"session_id": "runtime-after-idle", "resumed": "stored-key"},
                })))
            elif request["method"] == "prompt.submit":
                self.frames.extend((
                    SimpleNamespace(type=1, data=json.dumps({
                        "jsonrpc": "2.0", "id": request["id"], "result": {"status": "streaming"},
                    })),
                    SimpleNamespace(type=1, data=json.dumps({
                        "method": "event", "params": {
                            "type": "message.complete", "session_id": "runtime-after-idle",
                            "payload": {"status": "complete", "text": "restored answer"},
                        },
                    })),
                ))

        async def receive(self):
            return self.frames.pop(0)

        async def close(self):
            order.append("socket_closed")

    class Client(CoreRpcClient):
        async def _connect(self):
            return FakeClient(), socket, FakeTypes

    socket = FakeSocket()
    client = Client.__new__(Client)
    client._timeout_seconds = 1

    async def before_submit(runtime_id):
        order.append(("before_submit", runtime_id))

    async def consume():
        return [event async for event in client.stream_owned_turn(
            "stored-key", "hello", before_submit=before_submit)]

    events = asyncio.run(consume())
    assert [item[0] for item in order if isinstance(item, tuple)] == [
        "send", "before_submit", "send",
    ]
    assert order[0][1:] == ("session.resume", {"session_id": "stored-key", "source": "jarvis"})
    assert order[1] == ("before_submit", "runtime-after-idle")
    assert order[2][1:] == ("prompt.submit", {
        "session_id": "runtime-after-idle", "text": "hello",
    })
    assert events[-1].kind == "complete"
    assert events[0].text == "restored answer"
    assert order[-2:] == ["socket_closed", "client_closed"]


def test_isolated_turn_branches_full_native_history_and_sets_only_session_route():
    class Client(CoreRpcClient):
        def __init__(self, replies):
            self.replies = iter(replies)
            self.calls = []

        async def _rpc_on_socket(self, ws, ws_types, method, params, **kwargs):
            self.calls.append((method, params))
            return next(self.replies)

    client = Client([
        {"session_id": "runtime-new", "stored_session_id": "stored-new",
         "message_count": 4, "messages_omitted": True},
        {"key": "model", "value": "gpt-6-sol", "scope": "session",
         "confirm_required": False, "deferred": False},
        {"key": "reasoning", "value": "high"},
    ])
    result = asyncio.run(client._branch_isolated_turn_session(
        object(), object(), runtime_session_id="runtime-old", model_id="gpt-6-sol",
        reasoning_effort="high", early_session_info=[], deadline=10**12))
    assert result[:2] == ("runtime-new", "stored-new")
    assert client.calls[0][0] == "session.branch_whole"
    assert client.calls[0][1]["session_id"] == "runtime-old"
    assert client.calls[0][1]["idempotency_key"].startswith("jarvis_turn_")
    assert client.calls[1] == ("config.set", {
        "key": "model", "value": "gpt-6-sol --provider openai-codex --session",
        "session_id": "runtime-new",
    })
    assert client.calls[2] == ("config.set", {
        "key": "reasoning", "value": "high", "session_id": "runtime-new",
    })

    invalid = Client([])
    with pytest.raises(JarvisChatDenied):
        asyncio.run(invalid._branch_isolated_turn_session(
            object(), object(), runtime_session_id="runtime-old", model_id="gpt-5.5",
            reasoning_effort="max", early_session_info=[], deadline=10**12))
    assert invalid.calls == []


def test_isolated_turn_readback_precedes_prompt_submit_and_mapping_rotation():
    order = []

    class FakeTypes:
        TEXT, CLOSED, CLOSE, ERROR = 1, 2, 3, 4

    class FakeClient:
        async def close(self):
            order.append("client_closed")

    class FakeSocket:
        def __init__(self, info):
            self.info = info
            self.frames = []

        async def send_json(self, request):
            order.append(("send", request["method"], request["params"].copy()))
            if request["method"] == "session.resume":
                self.frames.append(SimpleNamespace(type=1, data=json.dumps({
                    "jsonrpc": "2.0", "id": request["id"],
                    "result": {"session_id": "runtime-parent", "resumed": "stored-parent",
                               "info": {"lazy": False, "stored_session_id": "stored-parent",
                                        "model": "gpt-6-sol", "provider": "openai-codex"}},
                })))
            elif request["method"] == "prompt.submit":
                self.frames.append(SimpleNamespace(type=1, data=json.dumps({
                    "jsonrpc": "2.0", "id": request["id"], "result": {"status": "streaming"},
                })))
                self.frames.append(SimpleNamespace(type=1, data=json.dumps({
                    "method": "event", "params": {
                        "type": "message.complete", "session_id": "runtime-child",
                        "payload": {"status": "complete", "text": "answer"},
                    },
                })))

        async def receive(self):
            return self.frames.pop(0)

        async def close(self):
            order.append("socket_closed")

    class Client(CoreRpcClient):
        def __init__(self, info):
            self._timeout_seconds = 1
            self.socket = FakeSocket(info)

        async def _connect(self):
            return FakeClient(), self.socket, FakeTypes

        async def _rpc_on_socket(self, ws, ws_types, method, params, **kwargs):
            order.append(("rpc", method, params.copy()))
            if method == "session.resume":
                return {"session_id": "runtime-parent", "resumed": "stored-parent",
                        "info": {"lazy": False, "stored_session_id": "stored-parent",
                                 "model": "gpt-6-sol", "provider": "openai-codex"}}
            if method == "session.branch_whole":
                return {"session_id": "runtime-child", "stored_session_id": "stored-child",
                        "message_count": 3, "messages_omitted": True}
            if method == "config.set" and params["key"] == "model":
                return {"key": "model", "value": "gpt-6-sol", "scope": "session",
                        "confirm_required": False, "deferred": False}
            if method == "config.set":
                return {"key": "reasoning", "value": "high"}
            raise AssertionError(method)

        async def _wait_for_model_session_ready(self, ws, ws_types, **kwargs):
            return info

        async def _branch_isolated_turn_session(self, ws, ws_types, **kwargs):
            session_id, stored_id, _ = await super()._branch_isolated_turn_session(ws, ws_types, **kwargs)
            return session_id, stored_id, {}

    info = {"lazy": False, "stored_session_id": "stored-child", "model": "gpt-6-sol",
            "provider": "openai-codex", "reasoning_effort": "high",
            "reasoning_effort_wire": "high"}
    client = Client(info)

    async def bind(runtime_id, stored_id):
        order.append(("bind", runtime_id, stored_id))
        return True

    async def consume():
        return [event async for event in client.stream_owned_turn(
            "stored-parent", "hello", isolated_model_id="gpt-6-sol",
            isolated_reasoning_effort="high", on_isolated_session=bind)]

    events = asyncio.run(consume())
    assert order[0][1] == "session.resume"
    assert order[1][1] == "session.branch_whole"
    assert order[2][1] == "config.set"
    assert order[3][1] == "config.set"
    assert order[4] == ("bind", "runtime-child", "stored-child")
    assert order[5][1] == "prompt.submit"
    assert events[0].kind == "configuration"
    assert events[0].configuration == {
        "provider": "openai-codex", "modelId": "gpt-6-sol",
        "reasoningEffort": "high", "reasoningEffortWire": "high",
    }
    assert events[-1].kind == "complete"


def test_isolated_turn_rejects_mismatched_readback_before_prompt_submit():
    class FakeTypes:
        TEXT, CLOSED, CLOSE, ERROR = 1, 2, 3, 4

    class FakeClient:
        async def close(self):
            pass

    class FakeSocket:
        def __init__(self):
            self.sent = []

        async def send_json(self, request):
            self.sent.append(request["method"])

        async def close(self):
            pass

    class Client(CoreRpcClient):
        def __init__(self):
            self._timeout_seconds = 1
            self.socket = FakeSocket()

        async def _connect(self):
            return FakeClient(), self.socket, FakeTypes

        async def _rpc_on_socket(self, ws, ws_types, method, params, **kwargs):
            if method == "session.resume":
                return {"session_id": "runtime-parent", "resumed": "stored-parent",
                        "info": {"lazy": False, "stored_session_id": "stored-parent",
                                 "model": "gpt-6-sol", "provider": "openai-codex"}}
            if method == "session.branch_whole":
                return {"session_id": "runtime-child", "stored_session_id": "stored-child",
                        "message_count": 2, "messages_omitted": True}
            if params.get("key") == "model":
                return {"key": "model", "value": "gpt-6-sol", "scope": "session",
                        "confirm_required": False, "deferred": False}
            if params.get("key") == "reasoning":
                return {"key": "reasoning", "value": "high"}
            raise AssertionError(method)

        async def _wait_for_model_session_ready(self, ws, ws_types, **kwargs):
            if kwargs["stored_session_id"] == "stored-parent":
                return {"lazy": False, "stored_session_id": "stored-parent",
                        "model": "gpt-6-sol", "provider": "openai-codex"}
            return {"lazy": False, "stored_session_id": "stored-child",
                    "model": "gpt-5.5", "provider": "openai-codex",
                    "reasoning_effort": "high", "reasoning_effort_wire": "high"}

    client = Client()
    async def consume():
        return [event async for event in client.stream_owned_turn(
            "stored-parent", "hello", isolated_model_id="gpt-6-sol",
            isolated_reasoning_effort="high", on_isolated_session=lambda *_: True)]

    with pytest.raises(JarvisChatDenied):
        asyncio.run(consume())
    assert client.socket.sent == ["session.resume"]  # readback failure happens before prompt.submit
