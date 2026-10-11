"""Owner and effect-boundary contracts for durable Jarvis mission planning.

Root's Pi environment runs these integration tests; source-level tests here do not establish
deployment or native Hermes dispatch readiness.
"""
from __future__ import annotations

import asyncio
import time

from aiohttp.test_utils import TestClient, TestServer

from hermes_installer.remote.jarvis_chat import ChatPrincipal, JarvisChatService, JarvisChatStore
from hermes_installer.remote import jarvis_missions
from hermes_installer.remote import jarvis_feature_registry
from hermes_installer.remote.jarvis_missions_assets import FEATURE_ASSETS as MISSION_ASSETS


class Backend:
    async def create_session(self):
        raise AssertionError("mission planning must not create a Hermes session")


def _principal(request):
    subject = request.headers.get("X-Test-Subject", "owner-a")
    expires = time.monotonic() + 60
    return ChatPrincipal(subject, expires, expires, "generation-a")


def test_owner_draft_preview_is_persisted_but_never_fabricates_execution(tmp_path, monkeypatch):
    async def scenario():
        monkeypatch.setattr(jarvis_missions, "_verified_team_catalog", lambda: {
            "profiles": {"reviewer": "Internal reviewer"},
            "source": {"revision": "rev-a", "tree": "tree-a", "content_digest": "digest-a",
                       "catalog_version": "1"},
        })
        from aiohttp import web
        store = JarvisChatStore(tmp_path / "chat.sqlite3")
        service = JarvisChatService(store, Backend(), principal_from_request=_principal)
        app = web.Application(client_max_size=16 * 1024)
        jarvis_missions.install_jarvis_missions_routes(app, service)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            body = {
                "title": "Review the release notes",
                "brief": "Summarize changes using only the approved local source.",
                "team_ids": ["reviewer"],
                "idempotency_key": "mission-create-idempotency-key-001",
            }
            created_response = await client.post("/chat/api/missions", json=body)
            assert created_response.status == 201
            mission = (await created_response.json())["mission"]
            assert mission["status"] == "draft"
            mission_id = mission["mission_id"]

            replay = await client.post("/chat/api/missions", json=body)
            assert replay.status == 201
            assert (await replay.json())["mission"]["mission_id"] == mission_id
            conflict = await client.post("/chat/api/missions", json={**body, "brief": "different"})
            assert conflict.status == 409

            excess = await client.post("/chat/api/missions", json={
                **body,
                "idempotency_key": "mission-create-excess-team-key-001",
                "team_ids": ["reviewer"] * 13,
            })
            assert excess.status == 400

            concurrent_body = {**body, "idempotency_key": "mission-create-concurrent-key-001"}
            first, second = await asyncio.gather(
                client.post("/chat/api/missions", json=concurrent_body),
                client.post("/chat/api/missions", json=concurrent_body),
            )
            assert first.status == second.status == 201
            concurrent_ids = {
                (await first.json())["mission"]["mission_id"],
                (await second.json())["mission"]["mission_id"],
            }
            assert len(concurrent_ids) == 1

            preview_response = await client.post(
                f"/chat/api/missions/{mission_id}/preview", json={"revision": 1})
            assert preview_response.status == 200
            preview = await preview_response.json()
            assert preview["status"] == "preview_pending"
            assert preview["team"] == [{
                "id": "reviewer", "label": "Internal reviewer", "readiness": "pending",
                "reason": "Bundled source identity is verified; current native dispatch and per-task authority are not.",
            }]
            assert preview["native_execution_available"] is False
            assert preview["approval_nonce"] is None and preview["expires_at"] is None
            assert len(preview["plan_sha256"]) == 64

            approval_body = {
                "revision": 1,
                "plan_sha256": preview["plan_sha256"],
                "idempotency_key": "mission-approve-idempotency-key-001",
            }
            approved_response = await client.post(
                f"/chat/api/missions/{mission_id}/approve", json=approval_body)
            assert approved_response.status == 200
            approved = await approved_response.json()
            assert approved["status"] == "approved-pending-execution"
            assert approved["native_execution_available"] is False
            assert approved["plan_sha256"] == preview["plan_sha256"]
            assert len(approved["intent_nonce"]) == 64
            assert approved["pending_reasons"]

            approval_replay = await client.post(
                f"/chat/api/missions/{mission_id}/approve", json=approval_body)
            assert approval_replay.status == 200
            assert (await approval_replay.json())["intent_nonce"] == approved["intent_nonce"]

            detail = await client.get(f"/chat/api/missions/{mission_id}")
            assert detail.status == 200
            assert (await detail.json())["preview"]["plan_sha256"] == preview["plan_sha256"]
            detail_payload = await detail.json()
            assert detail_payload["approval"]["status"] == "approved"
            assert "intent_nonce" not in detail_payload["approval"]

            launch = await client.post(f"/chat/api/missions/{mission_id}/launch", json={
                "revision": 1,
                "plan_sha256": preview["plan_sha256"],
                "approval_nonce": approved["intent_nonce"],
                "idempotency_key": "mission-launch-idempotency-key-001",
            })
            assert launch.status == 409
            assert "unavailable" in await launch.text()
            with store._connect() as db:
                approval_row = db.execute(
                    "SELECT status, turn_id FROM jarvis_mission_approvals WHERE mission_id=?",
                    (mission_id,),
                ).fetchone()
            assert approval_row["status"] == "approved"
            assert approval_row["turn_id"] is None

            stop = await client.post(f"/chat/api/missions/{mission_id}/stop", json={
                "revision": 1, "idempotency_key": "mission-stop-idempotency-key-001",
            })
            review = await client.post(f"/chat/api/missions/{mission_id}/review", json={
                "revision": 1, "decision": "accept",
                "idempotency_key": "mission-review-idempotency-key-001",
            })
            assert stop.status == review.status == 409

            foreign = await client.get(f"/chat/api/missions/{mission_id}", headers={"X-Test-Subject": "owner-b"})
            assert foreign.status == 404
            foreign_approval = await client.post(
                f"/chat/api/missions/{mission_id}/approve", json=approval_body,
                headers={"X-Test-Subject": "owner-b"})
            assert foreign_approval.status == 404
            listing = await client.get("/chat/api/missions")
            assert len((await listing.json())["missions"]) == 2
            with store._connect() as db:
                row = db.execute("SELECT status, plan_sha256 FROM jarvis_missions WHERE id=?", (mission_id,)).fetchone()
            assert row["status"] == "preview_pending"
            assert row["plan_sha256"] == preview["plan_sha256"]
        finally:
            await client.close()

    asyncio.run(scenario())


def test_mission_routes_and_feature_assets_are_literal_and_finite():
    assert {path for _method, path in jarvis_missions.FEATURE_ROUTES} == {
        "/chat/api/missions",
        "/chat/api/missions/{mission_id}",
        "/chat/api/missions/{mission_id}/preview",
        "/chat/api/missions/{mission_id}/approve",
        "/chat/api/missions/{mission_id}/launch",
        "/chat/api/missions/{mission_id}/stop",
        "/chat/api/missions/{mission_id}/review",
    }
    assert jarvis_feature_registry.FEATURE_ASSETS[0] == MISSION_ASSETS
    assert {asset.feature_id for asset in jarvis_feature_registry.FEATURE_ASSETS} == {
        "missions", "bots", "activity", "native-controls", "resources-learning",
    }
    assert jarvis_feature_registry.FEATURE_ROUTE_INSTALLERS == (
        ("missions", jarvis_missions.install_jarvis_missions_routes,
         jarvis_missions.FEATURE_ROUTES),
        ("bots", jarvis_feature_registry._bots.install_jarvis_bots_routes,
         jarvis_feature_registry._bots.FEATURE_ROUTES),
    )
    assert {feature_id for feature_id, _owner, _routes
            in jarvis_feature_registry.FEATURE_ROUTE_OWNERS} == {
                "activity", "native-controls", "resources-learning"}
    route_sets = [asset.api_routes for asset in jarvis_feature_registry.FEATURE_ASSETS]
    flattened = [(method, path.replace("{id}", "{}").replace("{turn_id}", "{}")
                  .replace("{mission_id}", "{}"))
                 for rows in route_sets for method, path in rows]
    assert len(flattened) == len(set(flattened))
