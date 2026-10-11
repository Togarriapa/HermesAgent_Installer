from __future__ import annotations

import time

import pytest

from hermes_installer.remote.jarvis_activity import JarvisActivityStore, NativeActivityEvent
from hermes_installer.remote.jarvis_chat import (
    ChatPrincipal,
    JarvisChatDenied,
    JarvisChatStore,
)


def _principal(subject="owner-a", generation="core-generation-a"):
    return ChatPrincipal(subject, time.monotonic() + 120, time.monotonic() + 4, generation)


def _turn(store, subject="owner-a"):
    conversation = store.create_conversation(
        subject, f"runtime-{subject}", f"stored-{subject}", "core-generation-a")
    turn_id, _nonce, _conversation = store.begin_turn(
        subject, conversation["id"], "question", "request-key-00000001", _principal(subject))
    return conversation, turn_id


def test_activity_requires_exact_native_type_and_owner_session_generation_lease(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    activity = JarvisActivityStore(store)
    conversation, turn_id = _turn(store)
    event = NativeActivityEvent("tool.start", "running", "runtime-owner-a", "native-tool-1")

    recorded = activity.record_core_event(
        principal=_principal(), conversation_id=conversation["id"], turn_id=turn_id,
        core_generation="core-generation-a", event=event)
    assert recorded["type"] == "tool.start"
    assert recorded["status"] == "running"
    assert recorded["source_event_id"].startswith("evt_")

    assert activity.record_core_event(
        principal=_principal(), conversation_id=conversation["id"], turn_id=turn_id,
        core_generation="core-generation-a", event=event) is None
    with pytest.raises(JarvisChatDenied):
        activity.record_core_event(
            principal=_principal("owner-b"), conversation_id=conversation["id"], turn_id=turn_id,
            core_generation="core-generation-a", event=event)
    with pytest.raises(JarvisChatDenied):
        activity.record_core_event(
            principal=_principal(generation="core-generation-b"),
            conversation_id=conversation["id"], turn_id=turn_id,
            core_generation="core-generation-b", event=event)
    with pytest.raises(JarvisChatDenied):
        activity.record_core_event(
            principal=_principal(), conversation_id=conversation["id"], turn_id=turn_id,
            core_generation="core-generation-a",
            event=NativeActivityEvent("tool.start", "running", "another-runtime"))


def test_activity_persists_closed_projection_and_owner_only_pages(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    activity = JarvisActivityStore(store)
    conversation, turn_id = _turn(store)
    event = NativeActivityEvent(
        "session.usage", "observed", "runtime-owner-a", "usage-1",
        duration_ms=12_345, usage=(("input", 120), ("output", 33), ("cache_hit_pct", 82)))
    activity.record_core_event(
        principal=_principal(), conversation_id=conversation["id"], turn_id=turn_id,
        core_generation="core-generation-a", event=event)

    events, next_before = activity.for_turn("owner-a", turn_id)
    usage = activity.usage_for_turn("owner-a", turn_id)
    assert next_before is None
    assert events[0]["usage"]["input"] == 120
    assert events[0]["usage"]["cache_hit_pct"] == 82
    assert events[0]["usage"]["cost_usd"] is None
    assert usage["cost_usd"] is None
    assert usage["cost_status"] == "unknown"
    assert usage["usage_scope"] == "session_cumulative_snapshot"
    assert activity.for_turn("owner-b", turn_id)[0] == []
    assert activity.recent_for_owner("owner-a")["events"][0]["turnId"] == turn_id
    assert activity.recent_for_owner("owner-b")["events"] == []

    with store._connect() as db:
        payloads = [row[0] for row in db.execute(
            "SELECT data FROM turn_events WHERE turn_id=? AND name='activity.event'", (turn_id,))]
    assert len(payloads) == 1
    assert "runtime-owner-a" not in payloads[0]
    assert "tool-args" not in payloads[0]


def test_activity_accepts_no_untyped_browser_observations(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    activity = JarvisActivityStore(store)
    conversation, turn_id = _turn(store)
    with pytest.raises(JarvisChatDenied):
        activity.record_core_event(
            principal=_principal(), conversation_id=conversation["id"], turn_id=turn_id,
            core_generation="core-generation-a",
            event={"event_type": "tool.start", "session_id": "runtime-owner-a"})
