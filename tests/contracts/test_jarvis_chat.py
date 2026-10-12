from __future__ import annotations

import asyncio
import hashlib
import sys
import time
from dataclasses import dataclass
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


def test_per_message_model_effort_is_bound_into_turn_idempotency(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    request = {
        "model_id": "gpt-6-sol",
        "reasoning_effort": "high",
    }
    store.begin_turn("subject-a", conversation["id"], "same prompt", "per-message-key-000000000001",
                     principal("subject-a"), turn_configuration=request)
    with pytest.raises(JarvisChatDenied, match="idempotency"):
        store.begin_turn("subject-a", conversation["id"], "same prompt", "per-message-key-000000000001",
                         principal("subject-a"), turn_configuration={
                         "model_id": "gpt-6-sol", "reasoning_effort": "low"})


def test_per_message_isolated_session_registers_project_context_before_submit(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    access_jwt, ingress = "accepted-jwt-fixture", object()
    registered, submitted = [], []

    class Headers:
        def getall(self, name, default=()):
            return [access_jwt] if name == "Cf-Access-Jwt-Assertion" else list(default)

    class Request:
        headers = Headers()

        def get(self, key):
            return ingress if key == "core_ingress" else None

    class Backend:
        def stream_owned_turn(self, stored_session_id, text, *, isolated_model_id,
                              isolated_reasoning_effort, on_isolated_session):
            async def events():
                assert stored_session_id == "private-stored-session-subject-a-1"
                assert isolated_model_id == "gpt-6-sol"
                assert isolated_reasoning_effort == "high"
                await on_isolated_session("runtime-isolated", "stored-isolated")
                submitted.append(text)
                yield SimpleNamespace(kind="configuration", configuration={
                    "provider": "openai-codex", "modelId": "gpt-6-sol",
                    "reasoningEffort": "high", "reasoningEffortWire": "high"})
                yield SimpleNamespace(kind="complete")
            return events()

        async def stop(self, _session_id):
            pass

    def register_owner_turn(**kwargs):
        registered.append(kwargs)
        return "a" * 32

    service = JarvisChatService(
        store, Backend(), principal_from_request=lambda _request: principal("subject-a"),
        owner_turn_register=register_owner_turn)

    async def exercise():
        queued = await service.start_server_turn(
            Request(), conversation_id=conversation["id"], text="Use the project context.",
            idempotency_key="per-message-context-request-0001",
            turn_configuration={"model_id": "gpt-6-sol", "reasoning_effort": "high"})
        for _ in range(500):
            if store.owned_turn("subject-a", queued["turn_id"])["status"] == "completed":
                break
            await asyncio.sleep(0.01)
        assert store.owned_turn("subject-a", queued["turn_id"])["status"] == "completed"

    asyncio.run(exercise())

    assert submitted == ["Use the project context."]
    assert len(registered) == 1
    assert registered[0]["session_id"] == "runtime-isolated"
    assert registered[0]["conversation_id"] == conversation["id"]
    assert registered[0]["prompt_sha256"] == hashlib.sha256(
        b"Use the project context.").hexdigest()
    assert store.get_conversation("subject-a", conversation["id"])["session_key"] == "stored-isolated"


@pytest.mark.parametrize("revocation", ["wrong-owner", "expired", "expired-during-registration"])
def test_per_message_isolated_session_denies_stale_owner_before_rebind_or_submit(tmp_path, revocation):
    store = JarvisChatStore(tmp_path / f"chat-{revocation}.sqlite3")
    conversation = new_conversation(store, "subject-a")
    original = store.get_conversation("subject-a", conversation["id"])
    access_jwt, ingress = "accepted-jwt-fixture", object()
    current = [principal("subject-a")]
    registered, submitted, failed_turn_ids = [], [], []

    class Headers:
        def getall(self, name, default=()):
            return [access_jwt] if name == "Cf-Access-Jwt-Assertion" else list(default)

    class Request:
        headers = Headers()

        def get(self, key):
            return ingress if key == "core_ingress" else None

    class Backend:
        def stream_owned_turn(self, _stored_session_id, _text, *, isolated_model_id,
                              isolated_reasoning_effort, on_isolated_session):
            async def events():
                if revocation == "wrong-owner":
                    current[0] = principal("subject-b")
                elif revocation == "expired":
                    current[0] = ChatPrincipal(
                        "subject-a", time.monotonic() - 1, time.monotonic() - 1,
                        "core-generation-a")
                await on_isolated_session("runtime-isolated", "stored-isolated")
                submitted.append((isolated_model_id, isolated_reasoning_effort))
                yield SimpleNamespace(kind="complete")
            return events()

        async def stop(self, _session_id):
            pass

    def register_owner_turn(**kwargs):
        registered.append(kwargs)
        if revocation == "expired-during-registration":
            current[0] = ChatPrincipal(
                "subject-a", time.monotonic() - 1, time.monotonic() - 1,
                "core-generation-a")
        return "a" * 32

    service = JarvisChatService(
        store, Backend(), principal_from_request=lambda _request: current[0],
        owner_turn_register=register_owner_turn)

    async def exercise():
        queued = await service.start_server_turn(
            Request(), conversation_id=conversation["id"], text="Do not submit after revocation.",
            idempotency_key=f"per-message-revocation-{revocation}-0001",
            turn_configuration={"model_id": "gpt-6-sol", "reasoning_effort": "high"})
        failed_turn_ids.append(queued["turn_id"])
        for _ in range(500):
            if store.owned_turn("subject-a", queued["turn_id"])["status"] == "failed":
                break
            await asyncio.sleep(0.01)
        assert store.owned_turn("subject-a", queued["turn_id"])["status"] == "failed"

    asyncio.run(exercise())

    assert len(registered) == (1 if revocation == "expired-during-registration" else 0)
    assert submitted == []
    unchanged = store.get_conversation("subject-a", conversation["id"])
    assert unchanged["backend_id"] == original["backend_id"]
    assert unchanged["session_key"] == original["session_key"]
    with store._connect() as db:
        events = db.execute("SELECT name,data FROM turn_events WHERE turn_id=? ORDER BY sequence",
                            (failed_turn_ids[0],)).fetchall()
        # Revocation denies all native configuration/activity/output before submit,
        # while the owned local turn still records its terminal failure.
        assert [(row["name"], row["data"]) for row in events] == [("turn.failed", "{}")]
    assert service.owner_turn_handle_for(principal("subject-a"), failed_turn_ids[0]) is None


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


def test_owner_turn_registration_uses_actual_rebound_session_and_final_prompt(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    initial = store.get_conversation("subject-a", conversation["id"])
    access_jwt = "accepted-jwt-fixture"
    ingress = object()
    calls = []
    sent = []
    turn_ids = []
    attachment_reference = "[attachment reference]"
    accepted_text = "private accepted prompt"
    final_first_prompt = accepted_text + "\n\n" + attachment_reference
    final_second_prompt = "ordinary chat remains available\n\n" + attachment_reference

    class Headers:
        def getall(self, name, default=()):
            return [access_jwt] if name == "Cf-Access-Jwt-Assertion" else list(default)

    class Request:
        headers = Headers()

        def get(self, key):
            return ingress if key == "core_ingress" else None

    class Backend:
        def stream_owned_turn(self, stored_session_id, text, *, before_submit):
            async def events():
                if not sent:
                    assert stored_session_id == initial["session_key"]
                    assert text == final_first_prompt
                    actual_session = "runtime-after-idle"
                else:
                    actual_session = "runtime-after-idle"
                await before_submit(actual_session)
                sent.append((actual_session, text))
                yield SimpleNamespace(kind="complete")
            return events()

        async def stop(self, _session_id):
            pass

    def register_owner_turn(**kwargs):
        calls.append(kwargs)
        if len(calls) > 1:
            raise RuntimeError("root owner observation unavailable")
        return "a" * 32

    service = JarvisChatService(
        store, Backend(), principal_from_request=lambda _request: principal("subject-a"),
        owner_turn_register=register_owner_turn)
    request = Request()
    service.files_store.claim_pending = lambda **_kwargs: [attachment_reference]

    async def exercise():
        queued = await service.start_server_turn(
            request, conversation_id=conversation["id"], text=accepted_text,
            idempotency_key="owner-turn-request-key-00000001")
        assert "owner_turn_handle" not in queued
        turn_ids.append(queued["turn_id"])
        for _ in range(50):
            if store.owned_turn("subject-a", queued["turn_id"])["status"] == "completed":
                break
            await asyncio.sleep(0.01)
        assert store.owned_turn("subject-a", queued["turn_id"])["status"] == "completed"
        unavailable = await service.start_server_turn(
            request, conversation_id=conversation["id"], text="ordinary chat remains available",
            idempotency_key="owner-turn-request-key-00000002")
        turn_ids.append(unavailable["turn_id"])
        for _ in range(50):
            if store.owned_turn("subject-a", unavailable["turn_id"])["status"] == "completed":
                break
            await asyncio.sleep(0.01)
        assert store.owned_turn("subject-a", unavailable["turn_id"])["status"] == "completed"

    asyncio.run(exercise())

    assert sent == [("runtime-after-idle", final_first_prompt),
                    ("runtime-after-idle", final_second_prompt)]
    assert calls[0] == {
        "access_jwt": access_jwt,
        "accepted_ingress": ingress,
        "session_id": "runtime-after-idle",
        "conversation_id": conversation["id"],
        "gateway_turn_id": turn_ids[0],
        "prompt_sha256": hashlib.sha256(final_first_prompt.encode("utf-8")).hexdigest(),
    }
    assert calls[1]["gateway_turn_id"] == turn_ids[1]
    assert calls[1]["prompt_sha256"] == hashlib.sha256(
        final_second_prompt.encode("utf-8")).hexdigest()
    assert service.owner_turn_handle_for(principal("subject-a"), turn_ids[0]) == "a" * 32
    assert service.owner_turn_handle_for(principal("subject-a"), turn_ids[1]) is None
    with pytest.raises(JarvisChatDenied):
        service.owner_turn_handle_for(principal("subject-b"), turn_ids[0])
    assert sent == [("runtime-after-idle", final_first_prompt),
                    ("runtime-after-idle", final_second_prompt)]
    current = store.get_conversation("subject-a", conversation["id"])
    assert current["backend_id"] == "runtime-after-idle"
    assert current["session_key"] == initial["session_key"]


def test_mission_binding_is_captured_after_schedule_mapping_and_required_at_root_submit(
        tmp_path, monkeypatch):
    @dataclass(frozen=True, slots=True)
    class MissionBinding:
        schema: int
        mission_id: str
        revision: int
        plan_sha256: str
        task_sha256: str
        source_profile_id: str

        def to_wire(self):
            return {
                "schema": self.schema, "mission_id": self.mission_id,
                "revision": self.revision, "plan_sha256": self.plan_sha256,
                "task_sha256": self.task_sha256, "source_profile_id": self.source_profile_id,
            }

        @classmethod
        def from_wire(cls, value):
            if set(value) != {"schema", "mission_id", "revision", "plan_sha256",
                              "task_sha256", "source_profile_id"}:
                raise ValueError("closed MissionBinding fields required")
            return cls(**value)

    monkeypatch.setitem(sys.modules, "hermes_installer.remote.jarvis_mission_executor",
                        SimpleNamespace(MissionBinding=MissionBinding))
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = new_conversation(store, "subject-a")
    binding = MissionBinding(1, "m" * 24, 3, "a" * 64, "b" * 64, "orchestrator")
    access_jwt, ingress = "accepted-mission-jwt", object()
    order, registered, submitted = [], [], []

    class Headers:
        def getall(self, name, default=()):
            return [access_jwt] if name == "Cf-Access-Jwt-Assertion" else list(default)

    class Request:
        headers = Headers()

        def get(self, key):
            return ingress if key == "core_ingress" else None

    class Backend:
        def stream_owned_turn(self, stored_session_id, text, *, before_submit):
            async def events():
                assert stored_session_id == "private-stored-session-subject-a-1"
                assert text in {"server mission prompt", "ordinary prompt"}
                await before_submit("runtime-for-mission")
                submitted.append(text)
                yield SimpleNamespace(kind="complete")
            return events()

        async def stop(self, _session_id):
            pass

    def register_owner_turn(**kwargs):
        order.append("root-verify")
        registered.append(kwargs)
        if kwargs.get("mission_binding") is not None:
            raise RuntimeError("mission binding unavailable at root")
        return "c" * 32

    service = JarvisChatService(
        store, Backend(), principal_from_request=lambda _request: principal("subject-a"),
        owner_turn_register=register_owner_turn)

    async def exercise():
        def bind_before_schedule(turn_id):
            order.append(("persist-intent", turn_id))
            return binding

        def compensate(turn_id):
            order.append(("invalidate", turn_id))

        queued = await service.start_server_turn(
            Request(), conversation_id=conversation["id"], text="server mission prompt",
            idempotency_key="mission-binding-request-key-0001",
            before_schedule=bind_before_schedule, on_schedule_failure=compensate)
        for _ in range(100):
            if store.owned_turn("subject-a", queued["turn_id"])["status"] == "failed":
                break
            await asyncio.sleep(0.01)
        assert store.owned_turn("subject-a", queued["turn_id"])["status"] == "failed"

        missing_turn_ids = []
        with pytest.raises(JarvisChatDenied, match="approved mission binding is unavailable"):
            await service.start_server_turn(
                Request(), conversation_id=conversation["id"], text="server mission prompt",
                idempotency_key="mission-binding-required-key-01",
                before_schedule=lambda _turn_id: None,
                require_mission_binding=True,
                on_schedule_failure=lambda turn_id: missing_turn_ids.append(turn_id))
        assert len(missing_turn_ids) == 1
        assert store.owned_turn("subject-a", missing_turn_ids[0])["status"] == "cancelled"
        assert all(call["gateway_turn_id"] != missing_turn_ids[0] for call in registered)
        assert submitted == []

        ordinary = await service.start_server_turn(
            Request(), conversation_id=conversation["id"], text="ordinary prompt",
            idempotency_key="mission-binding-ordinary-key-01")
        for _ in range(100):
            if store.owned_turn("subject-a", ordinary["turn_id"])["status"] == "completed":
                break
            await asyncio.sleep(0.01)
        assert store.owned_turn("subject-a", ordinary["turn_id"])["status"] == "completed"

    asyncio.run(exercise())
    assert order[0][0] == "persist-intent"
    assert order[1] == "root-verify"
    assert registered[0]["mission_binding"] == binding
    assert registered[1].get("mission_binding") is None
    assert submitted == ["ordinary prompt"]


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
    with store._connect() as db:
        db.execute("UPDATE turns SET status='running' WHERE id=? AND status='queued'", (turn_id,))
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
