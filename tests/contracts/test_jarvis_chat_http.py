"""Meaningful route and lease contracts for the protected core-backed chat service.

These tests are executed only in the Pi gateway test environment; they are source coverage here,
not evidence that a deployed gateway or Hermes process is ready.
"""
from __future__ import annotations

import asyncio
import json
import time

from aiohttp.test_utils import TestClient, TestServer

from hermes_installer.remote.jarvis_chat import (
    ChatPrincipal,
    JarvisChatService,
    JarvisChatStore,
    MAX_LEASE_SECONDS,
)


SUBJECT = "verified-subject-a"
GENERATION_A = "core-generation-a"


class FakeBackend:
    def __init__(self):
        self.created = 0
        self.resumed = []
        self.stopped = []
        self.release = asyncio.Event()
        self.emit_completion = True

    async def create_session(self):
        self.created += 1
        return f"runtime-session-{self.created}", f"stored-session-{self.created}"

    async def resume_session(self, stored_session_id):
        self.resumed.append(stored_session_id)
        return "runtime-session-after-restart"

    async def history(self, session_id):
        return [{"role": "user", "content": f"history-for-{session_id}", "createdAt": 10}]

    async def stop(self, session_id):
        self.stopped.append(session_id)
        self.release.set()

    async def stream(self, session_id, text):
        await self.release.wait()
        from hermes_installer.remote.core_client import CoreTurnEvent
        yield CoreTurnEvent("delta", "answer")
        if self.emit_completion:
            yield CoreTurnEvent("complete")


def _principal(request):
    # Test-only trusted ingress seam; production gets this object from sealed gateway middleware.
    subject = request.headers.get("X-Test-Subject", SUBJECT)
    generation = request.headers.get("X-Test-Generation", GENERATION_A)
    expiry = time.monotonic() + 120
    return ChatPrincipal(subject, expiry, min(expiry, time.monotonic() + 5), generation)


def _client(tmp_path, backend=None):
    from aiohttp import web
    backend = backend or FakeBackend()
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    service = JarvisChatService(store, backend, principal_from_request=_principal)
    app = web.Application(client_max_size=16 * 1024)
    service.install(app)
    return TestClient(TestServer(app)), service, backend


async def _create(client):
    response = await client.post("/chat/api/conversations", json={})
    assert response.status == 201
    return (await response.json())["conversation"]["id"]


async def _begin(client, conversation_id):
    return await client.post(
        f"/chat/api/conversations/{conversation_id}/turns",
        json={"text": "hello"},
        headers={"Idempotency-Key": "idempotency-key-http-0001"},
    )


def test_http_deltas_completion_and_heartbeat_keep_jwt_deadline_immutable(tmp_path):
    async def scenario():
        client, service, backend = _client(tmp_path)
        await client.start_server()
        try:
            conversation_id = await _create(client)
            response = await _begin(client, conversation_id)
            assert response.status == 202
            turn = await response.json()
            assert turn["status"] == "queued"
            row = service.store.owned_turn(SUBJECT, turn["turnId"])
            original_jwt_expiry = row["jwt_expiry"]

            heartbeat = await client.post("/chat/api/heartbeat", json={
                "turnId": turn["turnId"], "nonce": turn["heartbeatNonce"],
            })
            assert heartbeat.status == 200
            rotated = await heartbeat.json()
            row = service.store.owned_turn(SUBJECT, turn["turnId"])
            assert row["jwt_expiry"] == original_jwt_expiry
            assert row["heartbeat_expiry"] <= original_jwt_expiry
            assert row["heartbeat_expiry"] <= time.monotonic() + MAX_LEASE_SECONDS

            backend.release.set()
            events = await client.get(f"/chat/api/turns/{turn['turnId']}/events")
            body = (await events.text())
            assert "event: message.delta\ndata: {\"sequence\": 1, \"text\": \"answer\"}" in body
            assert "event: message.completed\ndata: {}" in body
            assert "event: turn.completed\ndata: {}" in body
            assert rotated["nonce"] != turn["heartbeatNonce"]
        finally:
            backend.release.set()
            await client.close()

    asyncio.run(scenario())


def test_idle_event_stream_closes_at_segment_deadline_and_stop_cancels_backend(tmp_path, monkeypatch):
    async def scenario():
        from hermes_installer.remote import jarvis_chat
        monkeypatch.setattr(jarvis_chat, "SSE_CONNECTION_SECONDS", 0.05)
        client, service, backend = _client(tmp_path)
        await client.start_server()
        try:
            conversation_id = await _create(client)
            response = await _begin(client, conversation_id)
            turn = await response.json()
            started = time.monotonic()
            events = await client.get(f"/chat/api/turns/{turn['turnId']}/events")
            payload = await asyncio.wait_for(events.read(), timeout=1)
            assert payload == b""
            assert 0.04 <= time.monotonic() - started < 0.8

            stopped = await client.post(f"/chat/api/turns/{turn['turnId']}/stop", json={})
            assert stopped.status == 200
            assert (await stopped.json())["status"] == "cancelled"
            assert backend.stopped == ["runtime-session-1"]
        finally:
            await client.close()

    asyncio.run(scenario())


def test_expired_lease_cannot_be_revived_and_other_subject_cannot_stop_turn(tmp_path):
    async def scenario():
        client, service, backend = _client(tmp_path)
        await client.start_server()
        try:
            conversation_id = await _create(client)
            response = await _begin(client, conversation_id)
            turn = await response.json()
            with service.store._connect() as db:
                db.execute("UPDATE turns SET heartbeat_expiry=? WHERE id=?",
                           (time.monotonic() - 1, turn["turnId"]))

            denied = await client.post("/chat/api/heartbeat", json={
                "turnId": turn["turnId"], "nonce": turn["heartbeatNonce"],
            })
            assert denied.status == 403
            foreign = await client.post(
                f"/chat/api/turns/{turn['turnId']}/stop", json={},
                headers={"X-Test-Subject": "verified-subject-b"},
            )
            assert foreign.status == 404
            assert backend.stopped == []
        finally:
            backend.release.set()
            await client.close()

    asyncio.run(scenario())


def test_generation_change_resumes_only_stored_owner_mapping(tmp_path):
    async def scenario():
        client, service, backend = _client(tmp_path)
        await client.start_server()
        try:
            conversation_id = await _create(client)
            response = await client.get(
                f"/chat/api/conversations/{conversation_id}/messages",
                headers={"X-Test-Generation": "core-generation-b"},
            )
            assert response.status == 200
            messages = await response.json()
            assert "runtime-session-after-restart" in messages["messages"][0]["content"]
            assert backend.resumed == ["stored-session-1"]
            assert "stored-session-1" not in json.dumps(messages)

            foreign = await client.get(
                f"/chat/api/conversations/{conversation_id}/messages",
                headers={"X-Test-Subject": "verified-subject-b",
                         "X-Test-Generation": "core-generation-b"},
            )
            assert foreign.status == 404
            assert backend.resumed == ["stored-session-1"]
        finally:
            await client.close()

    asyncio.run(scenario())
