from __future__ import annotations

import time

import pytest

from hermes_installer.remote.jarvis_chat import (
    ChatPrincipal,
    JarvisChatDenied,
    JarvisChatStore,
    MAX_ACTIVE_TURNS,
)


def principal(subject: str) -> ChatPrincipal:
    return ChatPrincipal(subject, time.monotonic() + 120, time.monotonic() + 4, "core-generation-a")


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
