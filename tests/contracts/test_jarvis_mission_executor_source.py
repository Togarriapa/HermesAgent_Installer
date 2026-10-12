"""Source-fixture journey through the real owned-turn service and native event store.

This contract is run by the root's Pi suite after the Activity mission-binding API is integrated;
it proves source behavior only, never Pi deployment or official Hermes readiness.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hermes_installer.remote.core_client import CoreTurnEvent
from hermes_installer.remote.jarvis_activity import NativeActivityEvent
from hermes_installer.remote.jarvis_chat import (
    ChatPrincipal, JarvisChatDenied, JarvisChatService, JarvisChatStore,
)
from hermes_installer.remote import jarvis_missions
from hermes_installer.remote.jarvis_mission_executor import MissionBinding, _native_child_result_state


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


def test_spent_binding_root_preflight_denial_stops_before_owner_registration_or_model_submit(tmp_path):
    binding = MissionBinding(
        schema=2, mission_id="m" * 24, revision=1,
        plan_sha256="a" * 64, task_sha256="b" * 64, source_profile_id="hermes",
        execution_mode="oneshot", autonomy_mode="approval_required",
        selected_source_ids=("reviewer",), scope_sha256="c" * 64,
    )
    preflight_calls, registrations, submissions, compensations = [], [], [], []

    class Backend:
        async def stream_owned_turn(self, *_args, **_kwargs):
            submissions.append("model-submit")
            yield CoreTurnEvent("complete")

        async def stop(self, _session_id):
            return None

    store = JarvisChatStore(tmp_path / "preflight.sqlite3")
    conversation = store.create_conversation("owner-a", "runtime-session", "stored-session", CORE)
    service = JarvisChatService(
        store, Backend(), principal_from_request=_principal,
        owner_turn_register=lambda **kwargs: registrations.append(kwargs) or "d" * 32,
    )

    def deny_root(binding_arg, *, owner_subject_sha256, gateway_turn_id):
        preflight_calls.append((binding_arg, owner_subject_sha256, gateway_turn_id))
        return False

    service._native_mission_preflight = deny_root
    request = SimpleNamespace(headers={}, get=lambda _key: None)

    async def launch():
        with pytest.raises(JarvisChatDenied, match="root mission binding validation denied"):
            await service.start_server_turn(
                request, conversation_id=conversation["id"], text="bounded mission",
                idempotency_key="preflight-denial-key-0001",
                before_schedule=lambda turn_id: jarvis_missions._preflight_spent_mission_binding(
                    service, binding, "owner-a", gateway_turn_id=turn_id),
                require_mission_binding=True,
                on_schedule_failure=lambda turn_id: compensations.append(turn_id),
            )

    asyncio.run(launch())
    assert preflight_calls == [(binding, "owner-a", compensations[0])]
    assert len(compensations) == 1
    assert registrations == []
    assert submissions == []
    turn = store.owned_turn("owner-a", compensations[0])
    assert turn["status"] == "cancelled"


def test_spent_binding_root_preflight_requires_exact_true_and_returns_same_binding():
    binding = object()
    calls = []

    class Service:
        def _native_mission_preflight(self, value, *, owner_subject_sha256, gateway_turn_id):
            calls.append((value, owner_subject_sha256, gateway_turn_id))
            return True

    service = Service()
    assert jarvis_missions._preflight_spent_mission_binding(
        service, binding, "owner-a", gateway_turn_id="turn-generated-by-server") is binding
    assert calls == [(binding, "owner-a", "turn-generated-by-server")]

    service._native_mission_preflight = lambda *_args, **_kwargs: 1
    with pytest.raises(JarvisChatDenied, match="root mission binding validation denied"):
        jarvis_missions._preflight_spent_mission_binding(
            service, binding, "owner-a", gateway_turn_id="turn-generated-by-server")


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
            "sources": {"orchestrator": {"label": "Orchestrator", "kind": "profiles"}},
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
            assert "master planning decision is pending" in await launched.text()
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


def test_root_verified_mission_team_catalog_rejects_unbound_membership():
    from hermes_installer.remote.core_gateway_inspector import (
        CoreInspectionDenied, RootVerifiedMissionPlanningCatalog,
    )

    team = {
        "version": "1.2.0", "source_revision": "a" * 40,
        "bundle_generation_sha256": "b" * 64,
        "bundle_member_path": "registry/package/bundles/research.yaml",
        "bundle_member_sha256": "c" * 64,
        "source_member_path": "registry/package/installer-registry/declarations/bundles/research.yaml",
        "source_member_sha256": "d" * 64, "source_path": "bundles/research.yaml",
        "ordered_member_ids": ["researcher", "analyst"],
    }
    catalog = RootVerifiedMissionPlanningCatalog.from_wire({
        "catalog_sha256": "e" * 64, "teams": {"research": team},
    })
    assert catalog.teams["research"]["ordered_member_ids"] == ["researcher", "analyst"]
    with pytest.raises(CoreInspectionDenied):
        RootVerifiedMissionPlanningCatalog.from_wire({
            "catalog_sha256": "e" * 64,
            "teams": {"research": dict(team, bundle_member_sha256="not-a-digest")},
        })


def test_master_planner_prompt_is_bounded_and_treats_owner_sources_as_hints():
    row = {
        "id": "m" * 24,
        "revision": 3,
        "title": "Review the local release",
        "brief": "Compare the verified release notes and flag discrepancies.",
        "team_ids": '["reviewer"]',
    }
    catalog = {
        "profiles": {"reviewer": "Internal reviewer"},
        "sources": {"reviewer": {"label": "Internal reviewer", "kind": "profiles"}},
        "source": {"revision": "rev-a", "package_sha256": "a" * 64},
    }
    prompt = jarvis_missions.build_jarvis_mission_master_plan_prompt(row, catalog)
    assert len(prompt) <= 8_000
    assert '"owner_source_preferences":["reviewer"]' in prompt
    assert "preferences are hints" in prompt
    assert "Select zero or more internal expert profile IDs only from available_profile_ids" in prompt
    assert "owner_source_preferences are hints" in prompt
    assert "do not use tools, launch work, or perform any external effect" in prompt
    assert '"goal_sha256":"' in prompt and '"catalog_sha256":"' in prompt


def test_master_plan_turn_reserves_exact_owned_turn_once_before_scheduling(tmp_path, monkeypatch):
    from multidict import CIMultiDict
    from types import SimpleNamespace
    from hermes_installer.remote.core_gateway_inspector import PlanningContext

    class Request(dict):
        def __init__(self, ingress):
            super().__init__(core_ingress=ingress)
            self.headers = CIMultiDict({"Cf-Access-Jwt-Assertion": "fixture-owner-token"})

    class Backend:
        sessions_created = 0

        async def create_session(self):
            self.sessions_created += 1
            return ("backend-session-fixed", "stored-session-fixed")

    async def scenario():
        base_catalog = {
            "profiles": {"reviewer": "Internal reviewer"},
            "sources": {"reviewer": {"label": "Internal reviewer", "kind": "profiles"}},
            "teams": {},
            "source": {"revision": "rev-a", "package_sha256": "a" * 64},
        }
        monkeypatch.setattr(jarvis_missions, "_verified_team_catalog", lambda: dict(base_catalog))
        store = JarvisChatStore(tmp_path / "planning.sqlite3")
        jarvis_missions._initialize(store)
        owner = store._owner("owner-a")
        mission_id = "m" * 24
        now = time.time()
        with store._connect() as db:
            db.execute(
                "INSERT INTO jarvis_missions "
                "(id,owner,revision,title,brief,team_ids,execution_mode,status,create_key_hash,"
                "create_request_hash,created,updated) VALUES(?,?,?,?,?,?,?,'draft',?,?,?,?)",
                (mission_id, owner, 1, "Local review", "Review the approved local source.",
                 '["reviewer"]', "pending", "create-key", "request-hash", now, now),
            )
        ingress = SimpleNamespace(root_observation=SimpleNamespace(
            core_generation=CORE, core_source_generation="source-a"))
        request = Request(ingress)
        backend = Backend()
        service = JarvisChatService(store, backend, principal_from_request=_principal)
        from hermes_installer.remote.core_gateway_inspector import RootVerifiedMissionPlanningCatalog
        service.inspector = SimpleNamespace(
            prepare_master_planning_context=None,
            read_current_mission_teams=lambda *_args: RootVerifiedMissionPlanningCatalog(
                jarvis_missions.mission_catalog_sha256(base_catalog), {}),
        )

        def prepare(_jwt, accepted, got_id, revision, prompt_sha256):
            assert accepted is ingress and got_id == mission_id and revision == 1
            assert len(prompt_sha256) == 64
            return PlanningContext(
                schema=1, mission_id=mission_id, revision=1,
                goal_sha256=jarvis_missions._hash({"goal": "Review the approved local source."}),
                catalog_sha256=jarvis_missions.mission_catalog_sha256(
                    base_catalog),
                planner_prompt_sha256=prompt_sha256,
                master_source_generation_sha256="b" * 64,
                master_source_manifest_sha256="c" * 64,
                master_prompt_sha256="d" * 64, source_profile_id="hermes",
            )

        service.inspector.prepare_master_planning_context = prepare
        observed = []

        async def start_server_turn(_request, *, conversation_id, text, idempotency_key,
                                    before_schedule, on_schedule_failure, planning_context,
                                    require_planning_context):
            with store._connect() as db:
                saved_mission = db.execute("SELECT * FROM jarvis_missions WHERE id=?",
                                           (mission_id,)).fetchone()
            assert text == jarvis_missions.build_jarvis_mission_master_plan_prompt(
                saved_mission, jarvis_missions._verified_team_catalog())
            assert idempotency_key.startswith("jarvis-master-plan-")
            assert require_planning_context is True and planning_context == context
            before_schedule("t" * 24)
            observed.append((conversation_id, idempotency_key))
            return {"status": "queued", "turn_id": "t" * 24}

        with store._connect() as db:
            mission_for_prompt = db.execute(
                "SELECT * FROM jarvis_missions WHERE id=?", (mission_id,)
            ).fetchone()
        prompt = jarvis_missions.build_jarvis_mission_master_plan_prompt(
            mission_for_prompt, base_catalog)
        prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        context = prepare("", ingress, mission_id, 1, prompt_sha256)
        service.start_server_turn = start_server_turn
        first = await jarvis_missions.start_master_plan_turn(
            service, request, mission_id=mission_id, revision=1,
            idempotency_key="create-idempotency-key-0001")
        second = await jarvis_missions.start_master_plan_turn(
            service, request, mission_id=mission_id, revision=1,
            idempotency_key="create-idempotency-key-0001")
        assert first["status"] == second["status"] == "queued"
        assert len(observed) == 1
        assert backend.sessions_created == 1
        with store._connect() as db:
            row = db.execute("SELECT * FROM jarvis_mission_planning_turns WHERE mission_id=?",
                             (mission_id,)).fetchone()
        assert row["status"] == "queued"
        assert row["gateway_turn_id"] == "t" * 24
        assert row["conversation_id"] == first["conversation_id"]
        assert row["task_sha256"] == jarvis_missions._hash(
            {"goal": "Review the approved local source."})
        assert row["source_binding"] == jarvis_missions._canonical({
            "core_generation": CORE, "core_source_generation": "source-a",
        }).decode("utf-8")
        assert row["master_prompt_sha256"] == "d" * 64

    asyncio.run(scenario())
