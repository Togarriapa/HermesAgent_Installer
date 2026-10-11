from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hermes_installer.remote.jarvis_chat import (
    ChatPrincipal,
    JarvisChatDenied,
    JarvisChatService,
    JarvisChatStore,
    MAX_ACTIVE_TURNS,
)


def principal(subject: str) -> ChatPrincipal:
    return ChatPrincipal(subject, time.monotonic() + 120, time.monotonic() + 4, "core-generation-a")


def test_history_failure_logs_only_fixed_phase_and_exception_class(tmp_path, caplog):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")

    class Backend:
        async def resume_history(self, _stored_session_id):
            raise RuntimeError("private upstream response marker")

    request = SimpleNamespace(
        match_info={"conversation_id": conversation["id"]},
    )
    service = JarvisChatService(
        store, Backend(), principal_from_request=lambda _request: principal("subject-a"))

    with pytest.raises(RuntimeError):
        asyncio.run(service.messages(request))

    records = [record.getMessage() for record in caplog.records
               if record.name.endswith("jarvis_chat")]
    assert records == ["jarvis_chat_messages_failed phase=runtime_resume exception=RuntimeError"]
    assert "private upstream response marker" not in " ".join(records)


def test_message_reload_resumes_stored_session_even_when_core_generation_is_unchanged(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    stored = store.get_conversation("subject-a", conversation["id"])
    stored_session_key = stored["session_key"]
    calls = []

    class Backend:
        async def resume_history(self, stored_session_id):
            calls.append(stored_session_id)
            return "fresh-runtime-session", [
                {"role": "user", "content": "question", "createdAt": 10},
                {"role": "assistant", "content": "answer", "createdAt": 11},
            ]

    request = SimpleNamespace(match_info={"conversation_id": conversation["id"]})
    service = JarvisChatService(
        store, Backend(), principal_from_request=lambda _request: principal("subject-a"))
    response = asyncio.run(service.messages(request))

    assert response.status == 200
    assert '"content": "answer"' in response.text
    updated = store.get_conversation("subject-a", conversation["id"])
    assert calls == [stored_session_key]
    assert updated["backend_id"] == "fresh-runtime-session"
    assert updated["session_key"] == stored_session_key
    assert updated["core_generation"] == "core-generation-a"


def new_conversation(store: JarvisChatStore, subject: str, index: int = 1) -> dict:
    return store.create_conversation(subject, f"private-runtime-session-{subject}-{index}",
                                     f"private-stored-session-{subject}-{index}", "core-generation-a")


def begin(store: JarvisChatStore, subject: str, conversation: dict, key: str, text: str = "hello"):
    return store.begin_turn(subject, conversation["id"], text, key, principal(subject))


def test_conversation_and_turn_ids_are_owned_before_read_or_control(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "access-subject-a")
    assert [item["id"] for item in store.list_conversations("access-subject-a")] == [conversation["id"]]
    assert store.list_conversations("access-subject-b") == []
    with pytest.raises(JarvisChatDenied):
        store.get_conversation("access-subject-b", conversation["id"])
    turn_id, _nonce, _ = begin(store, "access-subject-a", conversation, "request-key-0000000001")
    owned = store.owned_turn("access-subject-a", turn_id)
    assert owned["core_generation"] == "core-generation-a"
    assert owned["runtime_session_id"] == "private-runtime-session-access-subject-a-1"
    assert owned["session_key"] == "private-stored-session-access-subject-a-1"
    with pytest.raises(JarvisChatDenied):
        store.owned_turn("access-subject-b", turn_id)
    with pytest.raises(JarvisChatDenied):
        store.cancel_turn("access-subject-b", turn_id)


def test_store_refuses_non_private_state_directory(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(JarvisChatDenied, match="directory custody"):
        JarvisChatStore(tmp_path / "chat.sqlite3")


def test_two_active_turn_bound_and_one_turn_per_conversation(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3", max_active_turns=MAX_ACTIVE_TURNS)
    first = new_conversation(store, "subject-a", 1)
    second = new_conversation(store, "subject-b", 2)
    turn_id, _nonce, _ = begin(store, "subject-a", first, "request-key-0000000001")
    with pytest.raises(RuntimeError, match="busy"):
        begin(store, "subject-a", first, "request-key-0000000002")
    begin(store, "subject-b", second, "request-key-0000000003")
    third = new_conversation(store, "subject-c", 3)
    with pytest.raises(RuntimeError, match="busy"):
        begin(store, "subject-c", third, "request-key-0000000004")
    store.finish_turn(turn_id, "completed")
    next_turn, _nonce, _ = begin(store, "subject-c", third, "request-key-0000000004")
    assert next_turn


def test_model_selection_revision_is_owner_bound_one_use_and_serialized_with_turns(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    runtime_id = store.get_conversation("subject-a", conversation["id"])["backend_id"]
    digest = "a" * 64
    issued = store.issue_model_selection_revision(
        "subject-a", conversation["id"], "core-generation-a", digest)
    request = {
        "core_generation": "core-generation-a", "config_sha256": digest,
        "model_id": "gpt-6-sol", "revision": issued["revision"],
        "approval_nonce": issued["approval_nonce"],
        "idempotency_key": "model-selection-key-000001",
    }
    with pytest.raises(JarvisChatDenied):
        store.reserve_model_selection("subject-b", conversation["id"], **request)
    reserved = store.reserve_model_selection("subject-a", conversation["id"], **request)
    assert reserved["state"] == "reserved"
    assert reserved["runtime_session_id"] == runtime_id
    assert store.model_selection_activity(
        "subject-a", conversation["id"], "core-generation-a") == "busy"
    with pytest.raises(RuntimeError, match="model selection"):
        begin(store, "subject-a", conversation, "turn-during-model-change-001")

    resumed_runtime_id = "resumed-runtime-session-a"
    assert store.bind_model_selection_session(
        "subject-a", reserved["operation_id"], core_generation="core-generation-a",
        runtime_session_id=resumed_runtime_id) is True
    assert store.get_conversation("subject-a", conversation["id"])["backend_id"] == resumed_runtime_id

    store.finish_model_selection(
        "subject-a", reserved["operation_id"], state="selected-for-session",
        runtime_session_id=resumed_runtime_id)
    assert store.latest_model_selection(
        "subject-a", conversation["id"], "core-generation-a",
        resumed_runtime_id) == {"model": "gpt-6-sol", "state": "selected-for-session"}
    replay = store.reserve_model_selection("subject-a", conversation["id"], **request)
    assert replay["replayed"] is True
    assert replay["state"] == "selected-for-session"
    with pytest.raises(JarvisChatDenied, match="idempotency"):
        store.reserve_model_selection("subject-a", conversation["id"], **{
            **request, "model_id": "gpt-6-luna"})


def test_model_selection_revision_rejects_stale_generation_and_active_turn(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    with pytest.raises(JarvisChatDenied):
        store.issue_model_selection_revision(
            "subject-a", conversation["id"], "another-core-generation", "a" * 64)
    begin(store, "subject-a", conversation, "active-turn-model-denial-001")
    with pytest.raises(JarvisChatDenied, match="turn is active"):
        store.issue_model_selection_revision(
            "subject-a", conversation["id"], "core-generation-a", "a" * 64)


def test_server_turn_mapping_runs_before_worker_and_failure_compensates_without_submit(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    observed = []

    class Backend:
        async def resume_session(self, _stored):
            raise AssertionError("current generation does not require resume")

        def stream(self, _session_id, _text):
            async def completed():
                observed.append("submit")
                yield SimpleNamespace(kind="complete")
            return completed()

        async def stop(self, _session_id):
            pass

    request = SimpleNamespace()
    service = JarvisChatService(
        store, Backend(), principal_from_request=lambda _request: principal("subject-a"))

    async def exercise():
        async def before(turn_id):
            observed.append(("mapped", turn_id))

        queued = await service.start_server_turn(
            request, conversation_id=conversation["id"], text="server authored goal",
            idempotency_key="server-request-key-00000001", before_schedule=before)
        assert queued["turn_id"] == observed[0][1]
        assert observed[0][0] == "mapped"
        for _ in range(50):
            if store.owned_turn("subject-a", queued["turn_id"])["status"] == "completed":
                break
            await asyncio.sleep(0.01)
        assert store.owned_turn("subject-a", queued["turn_id"])["status"] == "completed"
        assert observed[1] == "submit"

        failure_turn = None
        def bind_then_fail(turn_id):
            nonlocal failure_turn
            failure_turn = turn_id
            observed.append("bound-before-failure")
            raise RuntimeError("mapping failure")

        def compensate(turn_id):
            assert turn_id == failure_turn
            observed.append("compensated")

        with pytest.raises(RuntimeError, match="mapping failure"):
            await service.start_server_turn(
                request, conversation_id=conversation["id"], text="another server goal",
                idempotency_key="server-request-key-00000002", before_schedule=bind_then_fail,
                on_schedule_failure=compensate)
        assert observed[-2:] == ["bound-before-failure", "compensated"]
        assert store.owned_turn("subject-a", failure_turn)["status"] == "cancelled"
        assert observed.count("submit") == 1

    asyncio.run(exercise())


def test_each_native_owned_turn_rebinds_runtime_and_turn_before_submit(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    initial = store.get_conversation("subject-a", conversation["id"])
    observed = []

    class Backend:
        async def resume_session(self, _stored):
            raise AssertionError("same-generation runtime is resumed on the submit socket")

        def stream_owned_turn(self, stored_session_id, text, *, before_submit):
            async def events():
                assert stored_session_id == initial["session_key"]
                assert text == "hello"
                await before_submit("runtime-after-idle")
                with store._connect() as db:
                    turn_id = db.execute(
                        "SELECT id FROM turns WHERE conversation_id=? AND status='running'",
                        (conversation["id"],)).fetchone()[0]
                turn = store.owned_turn("subject-a", turn_id)
                current = store.get_conversation("subject-a", conversation["id"])
                observed.append((current["backend_id"], turn["runtime_session_id"], turn_id))
                yield SimpleNamespace(kind="complete")
            return events()

        async def stream(self, _session_id, _text):
            raise AssertionError("native owned turns must use the resume-capable adapter")

        async def stop(self, _session_id):
            pass

    service = JarvisChatService(
        store, Backend(), principal_from_request=lambda _request: principal("subject-a"))

    async def exercise():
        queued = await service.start_server_turn(
            SimpleNamespace(), conversation_id=conversation["id"], text="hello",
            idempotency_key="idle-resume-request-key-0001")
        for _ in range(100):
            if store.owned_turn("subject-a", queued["turn_id"])["status"] == "completed":
                break
            await asyncio.sleep(0.01)
        assert store.owned_turn("subject-a", queued["turn_id"])["status"] == "completed"

    asyncio.run(exercise())
    assert observed[0][:2] == ("runtime-after-idle", "runtime-after-idle")
    assert store.get_conversation("subject-a", conversation["id"])["session_key"] == initial["session_key"]


def test_heartbeat_nonce_is_owner_bound_single_use_and_expiring(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    turn_id, nonce, _ = begin(store, "subject-a", conversation, "request-key-0000000001")
    rotated = store.rotate_heartbeat("subject-a", turn_id, nonce, principal("subject-a"))
    assert rotated != nonce
    with pytest.raises(JarvisChatDenied):
        store.rotate_heartbeat("subject-a", turn_id, nonce, principal("subject-a"))
    with pytest.raises(JarvisChatDenied):
        store.rotate_heartbeat("subject-b", turn_id, rotated, principal("subject-b"))
    store.finish_turn(turn_id, "cancelled")
    with pytest.raises(JarvisChatDenied):
        store.rotate_heartbeat("subject-a", turn_id, rotated, principal("subject-a"))


def test_sse_transport_reconnects_with_cursor_after_request_witness_expires(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    turn_id, _nonce, _ = begin(store, "subject-a", conversation, "sse-reconnect-key-00000001")
    store.append_delta(turn_id, "first")
    accepted_requests = 0

    @web.middleware
    async def fresh_request_witness(request, handler):
        nonlocal accepted_requests
        accepted_requests += 1
        request["principal"] = ChatPrincipal(
            "subject-a", time.monotonic() + 60, time.monotonic() + 0.45,
            "core-generation-a")
        return await handler(request)

    service = JarvisChatService(
        store, object(), principal_from_request=lambda request: request["principal"])
    app = web.Application(middlewares=[fresh_request_witness])
    app.router.add_get("/events/{turn_id}", service.events)

    async def exercise():
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            first = await client.get(f"/events/{turn_id}")
            first_body = await first.text()
            assert "id: 1\nevent: message.delta" in first_body
            assert accepted_requests == 1
            assert store.owned_turn("subject-a", turn_id)["status"] == "running"

            store.append_delta(turn_id, "second")
            store.finish_turn(turn_id, "completed")
            resumed = await client.get(
                f"/events/{turn_id}", headers={"Last-Event-ID": "1"})
            resumed_body = await resumed.text()
            assert accepted_requests == 2
            assert "id: 2\nevent: message.delta" in resumed_body
            assert "id: 4\nevent: turn.completed" in resumed_body
            assert "first" not in resumed_body
        finally:
            await client.close()

    asyncio.run(exercise())


def test_sse_turn_lease_expiry_cancels_owned_turn_and_emits_terminal_event(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    turn_id, _nonce, _ = begin(store, "subject-a", conversation, "sse-expiry-key-000000001")
    with store._connect() as db:
        db.execute("UPDATE turns SET heartbeat_expiry=? WHERE id=?",
                   (time.monotonic() - 1, turn_id))

    @web.middleware
    async def accepted_request(request, handler):
        request["principal"] = ChatPrincipal(
            "subject-a", time.monotonic() + 60, time.monotonic() + 3,
            "core-generation-a")
        return await handler(request)

    service = JarvisChatService(
        store, object(), principal_from_request=lambda request: request["principal"])
    app = web.Application(middlewares=[accepted_request])
    app.router.add_get("/events/{turn_id}", service.events)

    async def exercise():
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get(f"/events/{turn_id}")
            body = await response.text()
            assert response.status == 200
            assert "event: turn.cancelled" in body
            assert store.owned_turn("subject-a", turn_id)["status"] == "cancelled"
        finally:
            await client.close()

    asyncio.run(exercise())


def test_runtime_mapping_generation_cas_preserves_stored_session_key(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    updated = store.update_runtime_session("subject-a", conversation["id"], "core-generation-a",
                                           "private-runtime-session-after-restart", "core-generation-b")
    assert updated["backend_id"] == "private-runtime-session-after-restart"
    assert updated["session_key"] == "private-stored-session-subject-a-1"
    assert updated["core_generation"] == "core-generation-b"
    with pytest.raises(JarvisChatDenied):
        store.update_runtime_session("subject-a", conversation["id"], "core-generation-a",
                                     "stale-runtime-session", "core-generation-c")


def test_turn_creation_and_heartbeat_require_the_current_core_generation(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    stale = ChatPrincipal("subject-a", time.monotonic() + 120, time.monotonic() + 4,
                          "core-generation-b")
    with pytest.raises(JarvisChatDenied, match="generation"):
        store.begin_turn("subject-a", conversation["id"], "hello", "request-key-0000000001", stale)
    turn_id, nonce, _ = begin(store, "subject-a", conversation, "request-key-0000000001")
    with pytest.raises(JarvisChatDenied):
        store.rotate_heartbeat("subject-a", turn_id, nonce, stale)


def test_idempotency_is_principal_scoped_and_duplicate_does_not_start_another_turn(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    turn_id, _nonce, _ = begin(store, "subject-a", conversation, "same-request-key-000001")
    with pytest.raises(JarvisChatDenied, match="replay"):
        begin(store, "subject-a", conversation, "same-request-key-000001")
    other = new_conversation(store, "subject-b")
    other_turn, _nonce, _ = begin(store, "subject-b", other, "same-request-key-000001")
    assert other_turn != turn_id


def test_safe_event_projection_and_restart_close_inflight_turns(tmp_path):
    path = tmp_path / "chat.sqlite3"
    store = JarvisChatStore(path)
    conversation = new_conversation(store, "subject-a")
    turn_id, _nonce, _ = begin(store, "subject-a", conversation, "request-key-0000000001")
    store.append_delta(turn_id, "hello")
    store.finish_turn(turn_id, "completed")
    rows, status, _expiry = store.events_after("subject-a", turn_id, 0)
    assert status == "completed"
    assert [row["name"] for row in rows] == ["message.delta", "message.completed", "turn.completed"]
    assert rows[0]["data"] == '{"sequence": 1, "text": "hello"}'
    event_data = " ".join(row["data"] for row in rows)
    assert "private-runtime-session" not in event_data
    assert "private-stored-session" not in event_data
    assert [m["role"] for m in store.messages("subject-a", conversation["id"])] == ["user", "assistant"]

    pending = new_conversation(store, "subject-a", 2)
    pending_id, _nonce, _ = begin(store, "subject-a", pending, "request-key-0000000002")
    restarted = JarvisChatStore(path)
    rows, status, _expiry = restarted.events_after("subject-a", pending_id, 0)
    assert status == "cancelled"
    assert rows[-1]["name"] == "turn.cancelled"
