"""Source contracts for the bounded, root-observed native child activity journal.

These fixtures exercise the serializer and observer seam only. Pi acceptance must
run through the identified hardware validation path.
"""
from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

import pytest

import hermes_installer.remote.core_native_observer as observer


def _row(*, owner: str = "a" * 64, execution: str = "e" * 32,
         source_generation: str = "b" * 64, status: str = "admitted") -> dict:
    created = time.time() - 5
    return {
        "execution_key": execution, "display_alias": "Dev Peter",
        "owner_subject_sha256": owner, "mission_id": None, "mission_revision": None,
        "gateway_turn_id": "turn_12345678901234567890", "profile_id": "developer",
        "source_revision": "rev-17", "source_generation_sha256": source_generation,
        "source_manifest_sha256": "c" * 64, "core_generation": "d" * 64,
        "core_source_generation": "f" * 64, "child_lineage_sha256": "1" * 64,
        "parent_lineage_sha256": "2" * 64, "created_at": created,
        "updated_at": created + 1, "tool_count_total": 0,
        "seen_event_ids": ["3" * 64], "status": status,
        "events": [{"event_id": "3" * 64, "kind": "admitted", "status": "accepted",
                    "at": created, "duration_ms": None, "tool_count": 0}],
    }


def _registry(rows: list[dict], *, owner: str = "a" * 64):
    registry = object.__new__(observer.RootCoreNativeObservationRegistry)
    registry._lock = threading.RLock()
    registry._closed = False
    registry._activity_store_ok = True
    registry._activity_records = {row["execution_key"]: row for row in rows}
    registry._activity_started_at = time.time()
    registry._custody = SimpleNamespace(core_generation="d" * 64,
                                        core_source_generation="f" * 64)
    source = SimpleNamespace(artifact_sha256="b" * 64,
                             is_current_sealed=lambda _custody, now: True)
    registry._current_master_source = lambda: source
    return registry


def test_activity_snapshot_replay_restores_alias_and_rejects_duplicates():
    first = _row()
    raw = json.dumps({"schema": 1, "instances": [first]}, sort_keys=True,
                     separators=(",", ":"), ensure_ascii=False).encode()
    restored = observer._native_activity_snapshot_from_bytes(raw)
    assert restored == [first]
    assert restored[0]["display_alias"] == "Dev Peter"

    duplicate = _row(execution="e" * 32)
    corrupt = json.dumps({"schema": 1, "instances": [first, duplicate]}, sort_keys=True,
                         separators=(",", ":"), ensure_ascii=False).encode()
    assert observer._native_activity_snapshot_from_bytes(corrupt) is None
    assert observer._native_activity_snapshot_from_bytes(raw + b" ") is None


def test_real_observed_callback_event_is_owner_source_bound_and_replay_deduped(monkeypatch):
    saved = []
    monkeypatch.setattr(observer, "_publish_root_native_activity_bytes", saved.append)
    registry = object.__new__(observer.RootCoreNativeObservationRegistry)
    registry._activity_store_ok = True
    registry._activity_records = {}
    owner = SimpleNamespace(owner_subject_sha256="a" * 64,
        mission_binding=None, planning_context=None,
        gateway_turn_id="turn_12345678901234567890", core_generation="d" * 64,
        core_source_generation="f" * 64)
    child = {"owner": owner, "activity": None, "source": SimpleNamespace(source_revision="rev-17"),
        "profile_id": "developer", "source_generation_sha256": "b" * 64,
        "source_manifest_sha256": "c" * 64,
        "session_id": "private-child-session", "parent_session_id": "private-parent-session",
        "parent_turn_id": "private-native-turn"}

    registry._record_child_activity(child, kind="admitted", status="accepted", event_id="unused")
    registry._record_child_activity(child, kind="attempt", status="started", event_id="4" * 64)
    registry._record_child_activity(child, kind="attempt", status="started", event_id="4" * 64)
    registry._record_child_activity(child, kind="tool_call", status="observed", event_id="5" * 64,
                                    tool_count=1)
    for index in range(9):
        registry._record_child_activity(child, kind="attempt", status="started",
            event_id=f"{index + 6:064x}")
    registry._record_child_activity(child, kind="tool_call", status="observed", event_id="5" * 64,
                                    tool_count=1)

    assert len(saved) == 12
    rows = observer._native_activity_snapshot_from_bytes(saved[-1])
    assert rows is not None and len(rows) == 1
    row = rows[0]
    assert row["owner_subject_sha256"] == owner.owner_subject_sha256
    assert row["profile_id"] == "developer" and row["source_generation_sha256"] == "b" * 64
    assert row["display_alias"].startswith("Dev ")
    assert len(row["events"]) == observer._NATIVE_ACTIVITY_MAX_EVENTS_PER_INSTANCE
    assert row["tool_count_total"] == 1
    serialized = saved[-1].decode()
    assert "private-child-session" not in serialized
    assert "private-parent-session" not in serialized
    assert "private-native-turn" not in serialized


def test_activity_projection_filters_owner_and_source_and_never_exposes_private_lineage():
    row = _row()
    registry = _registry([row])
    result = registry.read_native_activity(owner_subject_sha256="a" * 64,
        core_generation="d" * 64, core_source_generation="f" * 64)
    assert len(result["instances"]) == 1
    item = result["instances"][0]
    assert item["execution_key"] == "e" * 32
    assert item["display_alias"] == "Dev Peter"
    assert item["tool_count"] == 0
    assert "owner_subject_sha256" not in item and "child_lineage_sha256" not in item

    other_owner = registry.read_native_activity(owner_subject_sha256="9" * 64,
        core_generation="d" * 64, core_source_generation="f" * 64)
    assert other_owner["instances"] == []
    row["source_generation_sha256"] = "8" * 64
    stale_source = registry.read_native_activity(owner_subject_sha256="a" * 64,
        core_generation="d" * 64, core_source_generation="f" * 64)
    assert stale_source["instances"] == []


def test_activity_journal_failure_and_unknown_owner_fail_closed():
    registry = _registry([_row()])
    registry._activity_store_ok = False
    with pytest.raises(observer.CoreNativeObservationUnavailable):
        registry.read_native_activity(owner_subject_sha256="a" * 64,
            core_generation="d" * 64, core_source_generation="f" * 64)

    registry._activity_store_ok = True
    with pytest.raises(observer.CoreNativeObservationUnavailable):
        registry.read_native_activity(owner_subject_sha256="not-an-owner",
            core_generation="d" * 64, core_source_generation="f" * 64)


def test_restart_marks_unfinished_durable_execution_unknown_not_live():
    row = _row(status="running")
    row["updated_at"] = time.time() - 1
    registry = _registry([row])
    registry._activity_started_at = time.time()
    result = registry.read_native_activity(owner_subject_sha256="a" * 64,
        core_generation="d" * 64, core_source_generation="f" * 64)
    assert result["instances"][0]["status"] == "unknown"
    assert result["instances"][0]["stale"] is True


def test_read_caps_instances_and_summaries():
    rows = []
    for index in range(120):
        row = _row(execution=f"{index:032x}")
        row["events"] = [{**row["events"][0],
                          "event_id": f"{index * 8 + event_index + 1:064x}"}
                         for event_index in range(8)]
        row["seen_event_ids"] = [event["event_id"] for event in row["events"]]
        rows.append(row)
    registry = _registry(rows)
    result = registry.read_native_activity(owner_subject_sha256="a" * 64,
        core_generation="d" * 64, core_source_generation="f" * 64)
    assert len(result["instances"]) == observer._NATIVE_ACTIVITY_MAX_INSTANCES
    assert sum(len(item["events"]) for item in result["instances"]) == 200
    assert all(item["events"] for item in result["instances"])
