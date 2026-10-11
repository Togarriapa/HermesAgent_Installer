"""Source-fixture journey through the real owned-turn service and native event store.

This contract is run by the root's Pi suite after the Activity mission-binding API is integrated;
it proves source behavior only, never Pi deployment or official Hermes readiness.
"""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hermes_installer.remote.core_client import CoreTurnEvent
from hermes_installer.remote.jarvis_activity import NativeActivityEvent
from hermes_installer.remote.jarvis_chat import ChatPrincipal, JarvisChatService, JarvisChatStore
from hermes_installer.remote import jarvis_missions
from hermes_installer.remote.jarvis_mission_executor import _native_child_result_state


CORE = "a" * 64
SOURCE = "b" * 64


def test_mission_result_requires_matching_native_child_start_and_successful_completion():
    child_a, child_b = "a" * 64, "b" * 64
    assert _native_child_result_state([
        {"child_ref": child_a, "type": "subagent.start", "status": "running"},
        {"child_ref": child_a, "type": "subagent.complete", "status": "completed"},
    ]) == (True, True)
    assert _native_child_result_state([
        {"child_ref": child_a, "type": "subagent.start", "status": "running"},
        {"child_ref": child_b, "type": "subagent.complete", "status": "completed"},
    ]) == (True, False)
    assert _native_child_result_state([
        {"child_ref": child_a, "type": "subagent.start", "status": "running"},
        {"child_ref": child_a, "type": "message.complete", "status": "complete"},
    ]) == (True, False)
    assert _native_child_result_state([
        {"child_ref": child_a, "type": "subagent.complete", "status": "completed"},
    ]) == (False, False)


class ObservedBackend:
    def __init__(self):
        self.sessions_created = 0
        self.submitted = asyncio.Event()
        self.submitted_prompt = None

    async def create_session(self):
        self.sessions_created += 1
        return "runtime-session", "stored-session"

    async def stop(self, _session_id):
        return None

    async def stream_owned_turn(self, _stored_session_id, text, *, before_submit):
        self.submitted_prompt = text
        await before_submit("runtime-session")
        self.submitted.set()
        yield CoreTurnEvent("activity", activity=NativeActivityEvent(
            "subagent.start", "running", "runtime-session", source_identity="native-subagent-id",
            child_session_id="native-child-session-1"))
        yield CoreTurnEvent("delta", text="Observed local-source summary")
        yield CoreTurnEvent("activity", activity=NativeActivityEvent(
            "subagent.complete", "completed", "runtime-session", source_identity="native-subagent-id",
            child_session_id="native-child-session-1"))
        yield CoreTurnEvent("complete")


def _principal(request):
    expires = time.monotonic() + 60
    return ChatPrincipal(request.headers.get("X-Test-Subject", "owner-a"), expires, expires, CORE)


def test_mission_stays_pending_until_root_seals_master_plan_decision(tmp_path, monkeypatch):
    async def scenario():
        monkeypatch.setattr(jarvis_missions, "_verified_team_catalog", lambda: {
            "profiles": {"orchestrator": "Orchestrator"},
            "source": {"revision": "fixture", "catalog_version": "1", "package_sha256": "c" * 64},
        })

        @web.middleware
        async def accepted_core_ingress(request, handler):
            request["core_ingress"] = SimpleNamespace(root_observation=SimpleNamespace(
                core_generation=CORE, core_source_generation=SOURCE))
            return await handler(request)

        registered = []

        def register_owner_turn(**kwargs):
            registered.append(kwargs)
            return "d" * 32

        backend = ObservedBackend()
        store = JarvisChatStore(tmp_path / "mission.sqlite3")
        service = JarvisChatService(store, backend, principal_from_request=_principal,
                                    owner_turn_register=register_owner_turn)
        app = web.Application(middlewares=[accepted_core_ingress], client_max_size=16 * 1024)
        service.install(app)
        jarvis_missions.install_jarvis_missions_routes(app, service)
        client = TestClient(TestServer(app))
        headers = {"Cf-Access-Jwt-Assertion": "fixture-owner-token"}
        await client.start_server()
        try:
            created = await client.post("/chat/api/missions", headers=headers, json={
                "title": "Summarize approved source", "brief": "Summarize this local source.",
                "team_ids": ["orchestrator"], "idempotency_key": "fixture-create-idempotency-0001",
            })
            assert created.status == 201
            created_payload = await created.json()
            mission_id = created_payload["mission"]["mission_id"]
            assert created_payload["mission"]["execution_mode"] == "pending"
            preview_response = await client.post(
                f"/chat/api/missions/{mission_id}/preview", headers=headers, json={"revision": 1})
            assert preview_response.status == 200
            preview = await preview_response.json()
            approval_response = await client.post(f"/chat/api/missions/{mission_id}/approve",
                headers=headers, json={"revision": 1, "plan_sha256": preview["plan_sha256"],
                                      "autonomy_mode": "approval_required",
                                      "idempotency_key": "fixture-approval-idempotency-001"})
            assert approval_response.status == 409
            assert "planning decision" in await approval_response.text()
            launch_body = {"revision": 1, "plan_sha256": preview["plan_sha256"],
                           "approval_nonce": "0" * 64,
                           "idempotency_key": "fixture-launch-idempotency-0001"}
            launched = await client.post(f"/chat/api/missions/{mission_id}/launch",
                                         headers=headers, json=launch_body)
            assert launched.status == 409
            assert "unavailable" in await launched.text()
            assert backend.sessions_created == 0
            assert backend.submitted_prompt is None
            assert registered == []
            with store._connect() as db:
                assert db.execute("SELECT 1 FROM jarvis_mission_approvals WHERE mission_id=?",
                                  (mission_id,)).fetchone() is None

            foreign = await client.get(f"/chat/api/missions/{mission_id}",
                                       headers={**headers, "X-Test-Subject": "owner-b"})
            assert foreign.status == 404
            review = await client.post(f"/chat/api/missions/{mission_id}/review", headers=headers,
                json={"revision": 1, "decision": "accept",
                      "idempotency_key": "fixture-review-idempotency-0001"})
            assert review.status == 409
        finally:
            await client.close()

    asyncio.run(scenario())
