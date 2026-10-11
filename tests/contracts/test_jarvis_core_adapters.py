from __future__ import annotations

import asyncio

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
