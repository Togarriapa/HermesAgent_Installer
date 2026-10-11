"""Source-fixture journey through the real owned-turn service and native event store.

This contract is run by the root's Pi suite after the Activity mission-binding API is integrated;
it proves source behavior only, never Pi deployment or official Hermes readiness.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from types import SimpleNamespace

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hermes_installer.remote.core_client import CoreTurnEvent
from hermes_installer.remote.jarvis_activity import NativeActivityEvent
from hermes_installer.remote.jarvis_chat import ChatPrincipal, JarvisChatService, JarvisChatStore
from hermes_installer.remote import jarvis_missions
from hermes_installer.remote.jarvis_mission_executor import (
    mission_execution_prompt, mission_goal_arguments_sha256, resolve_spent_mission_claim,
)


CORE = "a" * 64
SOURCE = "b" * 64


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
            "subagent.start", "running", "runtime-session", source_identity="child-1"))
        yield CoreTurnEvent("delta", text="Observed local-source summary")
        yield CoreTurnEvent("activity", activity=NativeActivityEvent(
            "subagent.complete", "completed", "runtime-session", source_identity="child-1"))
        yield CoreTurnEvent("complete")


def _principal(request):
    expires = time.monotonic() + 60
    return ChatPrincipal(request.headers.get("X-Test-Subject", "owner-a"), expires, expires, CORE)


def _goal_digest(goal):
    body = json.dumps({"goal": goal}, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def test_approved_orchestrator_reaches_one_owned_turn_and_native_observation(tmp_path, monkeypatch):
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
            mission_id = (await created.json())["mission"]["mission_id"]
            preview_response = await client.post(
                f"/chat/api/missions/{mission_id}/preview", headers=headers, json={"revision": 1})
            assert preview_response.status == 200
            preview = await preview_response.json()
            approval_response = await client.post(f"/chat/api/missions/{mission_id}/approve",
                headers=headers, json={"revision": 1, "plan_sha256": preview["plan_sha256"],
                                      "idempotency_key": "fixture-approval-idempotency-001"})
            assert approval_response.status == 200
            approval = await approval_response.json()
            launch_body = {"revision": 1, "plan_sha256": preview["plan_sha256"],
                           "approval_nonce": approval["intent_nonce"],
                           "idempotency_key": "fixture-launch-idempotency-0001"}
            launched = await client.post(f"/chat/api/missions/{mission_id}/launch",
                                         headers=headers, json=launch_body)
            assert launched.status == 202
            accepted = (await launched.json())["run"]
            assert accepted["turn_id"] and accepted["status"] in {"queued", "running", "review_pending"}
            await asyncio.wait_for(backend.submitted.wait(), timeout=2)
            approved_goal = "Summarize this local source."
            expected_prompt = mission_execution_prompt(approved_goal)
            assert backend.submitted_prompt == expected_prompt
            assert "exactly one call" in backend.submitted_prompt
            assert json.loads(backend.submitted_prompt.rsplit("\n", 1)[-1]) == {"goal": approved_goal}

            # A second request with the exact launch key returns the same reservation and does
            # not create another backend session or another Jarvis turn.
            replay = await client.post(f"/chat/api/missions/{mission_id}/launch",
                                       headers=headers, json=launch_body)
            assert replay.status == 202
            assert (await replay.json())["run"]["turn_id"] == accepted["turn_id"]
            assert backend.sessions_created == 1

            # Wait for the real fixture stream to be consumed into the existing owner stores.
            for _ in range(100):
                detail = await client.get(f"/chat/api/missions/{mission_id}", headers=headers)
                payload = await detail.json()
                if payload.get("run", {}).get("status") == "review_pending":
                    break
                await asyncio.sleep(0.01)
            run = payload["run"]
            assert run["status"] == "review_pending"
            assert run["native_child_started"] and run["native_child_completed"]
            assert run["result"] == "Observed local-source summary"
            binding = registered[0]["mission_binding"]
            assert binding.task_sha256 == _goal_digest(approved_goal)
            assert binding.task_sha256 == mission_goal_arguments_sha256(approved_goal)
            owner = store._owner("owner-a")
            assert resolve_spent_mission_claim(
                store, binding, run["turn_id"], owner, CORE, SOURCE, "orchestrator",
                _goal_digest(approved_goal)) is True
            assert resolve_spent_mission_claim(
                store, binding, run["turn_id"], "0" * 64, CORE, SOURCE, "orchestrator",
                _goal_digest(approved_goal)) is False

            foreign = await client.get(f"/chat/api/missions/{mission_id}",
                                       headers={**headers, "X-Test-Subject": "owner-b"})
            assert foreign.status == 404
            review = await client.post(f"/chat/api/missions/{mission_id}/review", headers=headers,
                json={"revision": 1, "decision": "accept",
                      "idempotency_key": "fixture-review-idempotency-0001"})
            assert review.status == 200
            assert (await review.json())["run"]["status"] == "accepted"
        finally:
            await client.close()

    asyncio.run(scenario())
