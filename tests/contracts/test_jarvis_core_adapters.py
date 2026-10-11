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
