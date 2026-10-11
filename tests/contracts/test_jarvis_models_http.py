from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hermes_installer.remote import jarvis_models
from hermes_installer.remote.jarvis_chat import (
    ChatPrincipal,
    JarvisChatService,
    JarvisChatStore,
)
from hermes_installer.remote.jarvis_models import FEATURE_ROUTES, install_jarvis_models_routes


def _principal(_request):
    now = time.monotonic()
    return ChatPrincipal("subject-a", now + 120, now + 30, "core-generation-a")


class _Backend:
    def __init__(self):
        self.selections = []

    async def get_model_provider_status(self):
        return {"model": "gpt-6-luna", "provider_hint": "unknown",
                "codex_credential_configured": True, "known_model": True}

    async def set_session_model(self, stored_session_id, model_id, *, before_set):
        runtime_session_id = "resumed-" + stored_session_id
        if await before_set(runtime_session_id) is not True:
            raise RuntimeError("binding denied")
        self.selections.append((stored_session_id, runtime_session_id, model_id))
        return {"model": model_id, "state": "selected-for-session"}


def _fixture_snapshot(monkeypatch):
    projection = {"provider": "openai-codex", "model": "gpt-6-luna"}
    observation = SimpleNamespace(config_sha256="a" * 64, projection=projection)

    async def snapshot(_request, service):
        principal = service._current(_request)
        return principal, object(), object(), observation, lambda: service._current(_request)

    monkeypatch.setattr(jarvis_models, "_verified_snapshot", snapshot)


def _app(tmp_path, monkeypatch):
    _fixture_snapshot(monkeypatch)
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = store.create_conversation(
        "subject-a", "runtime-session-a", "stored-session-a", "core-generation-a")
    backend = _Backend()
    service = JarvisChatService(store, backend, principal_from_request=_principal)
    app = web.Application()
    install_jarvis_models_routes(app, service)
    return app, store, conversation, backend


def test_models_routes_are_fixed_and_apply_only_once_to_owned_conversation(tmp_path, monkeypatch):
    app, store, conversation, backend = _app(tmp_path, monkeypatch)
    assert FEATURE_ROUTES == (
        ("GET", "/chat/api/models/conversations"),
        ("GET", "/chat/api/conversations/{conversation_id}/model-settings"),
        ("POST", "/chat/api/conversations/{conversation_id}/model-selection"),
    )

    async def exercise():
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            path = f"/chat/api/conversations/{conversation['id']}/model-settings"
            response = await client.get(path)
            payload = await response.json()
            assert response.status == 200
            assert payload["selectionAvailability"] == "available"
            assert payload["codexCredential"] == "configured"
            assert len(payload["models"]) == 9
            assert payload["models"][0]["reasoningEfforts"] == [
                "none", "low", "medium", "high", "xhigh", "max"]
            assert payload["models"][-1] == {
                "id": "gpt-5.3-codex-spark", "selectable": False,
                "status": "account-entitlement-unverified", "reasoningEfforts": [],
            }
            assert payload["turnSelection"] == {
                "availability": "available", "provider": "openai-codex",
                "defaultModel": {"id": "gpt-6-luna", "source": "profile-default"},
                "defaultReasoningEffort": {"id": None,
                                           "source": "profile-default-unobserved"},
                "models": payload["models"],
            }
            body = {
                "model_id": "gpt-6-sol", "revision": payload["revision"]["revision"],
                "approval_nonce": payload["revision"]["approval_nonce"],
                "idempotency_key": "model-selection-key-000001",
            }
            changed = await client.post(
                f"/chat/api/conversations/{conversation['id']}/model-selection", json=body)
            assert changed.status == 200
            assert await changed.json() == {"model": "gpt-6-sol", "state": "selected-for-session"}
            assert store.get_conversation("subject-a", conversation["id"])["backend_id"] == (
                "resumed-stored-session-a")
            assert backend.selections == [("stored-session-a", "resumed-stored-session-a", "gpt-6-sol")]
            replay = await client.post(
                f"/chat/api/conversations/{conversation['id']}/model-selection", json=body)
            assert replay.status == 200
            assert len(backend.selections) == 1
        finally:
            await client.close()

    asyncio.run(exercise())


def test_models_selection_is_unavailable_during_an_active_owned_turn(tmp_path, monkeypatch):
    app, store, conversation, backend = _app(tmp_path, monkeypatch)
    store.begin_turn("subject-a", conversation["id"], "active request",
                     "active-turn-model-denial-001", _principal(None))

    async def exercise():
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get(
                f"/chat/api/conversations/{conversation['id']}/model-settings")
            payload = await response.json()
            assert response.status == 200
            assert payload["selectionAvailability"] == "turn-active"
            assert payload["revision"] is None
            assert backend.selections == []
        finally:
            await client.close()

    asyncio.run(exercise())


def test_models_routes_do_not_cross_conversation_owners(tmp_path, monkeypatch):
    app, store, conversation, _backend = _app(tmp_path, monkeypatch)
    other = store.create_conversation(
        "subject-b", "runtime-session-b", "stored-session-b", "core-generation-a")
    service = app

    async def exercise():
        client = TestClient(TestServer(service))
        await client.start_server()
        try:
            response = await client.get(
                f"/chat/api/conversations/{other['id']}/model-settings")
            assert response.status in {403, 404}
            assert conversation["id"] != other["id"]
        finally:
            await client.close()

    asyncio.run(exercise())


def test_turn_rejects_effort_outside_selected_model_without_scheduling(tmp_path, monkeypatch):
    from hermes_installer.remote.jarvis_models import install_jarvis_models_routes

    _fixture_snapshot(monkeypatch)
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = store.create_conversation(
        "subject-a", "runtime-session-a", "stored-session-a", "core-generation-a")
    backend = _Backend()
    service = JarvisChatService(store, backend, principal_from_request=_principal)
    app = web.Application(client_max_size=16 * 1024)
    service.install(app)
    install_jarvis_models_routes(app, service)

    async def exercise():
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.post(
                f"/chat/api/conversations/{conversation['id']}/turns",
                json={"text": "use high effort", "modelId": "gpt-5.5",
                      "reasoningEffort": "max"},
                headers={"Idempotency-Key": "per-message-selection-denial-0001"})
            assert response.status == 400
            with store._connect() as db:
                assert db.execute("SELECT COUNT(*) FROM turns").fetchone()[0] == 0
            assert backend.selections == []
        finally:
            await client.close()

    asyncio.run(exercise())
