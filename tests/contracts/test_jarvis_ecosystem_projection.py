from __future__ import annotations

import time

import pytest

from hermes_installer.remote.jarvis_ecosystem import project_native_activity_snapshot


def _instance(*, status: str = "completed", stale: bool = False, profile: str = "developer") -> dict:
    now = time.time()
    return {
        "execution_key": "a" * 32,
        "display_alias": "Dev Peter",
        "gateway_turn_id": "b" * 32,
        "mission_id": "c" * 32,
        "mission_revision": 2,
        "profile_id": profile,
        "source_revision": "source-v17",
        "source_generation_sha256": "d" * 64,
        "status": status,
        "stale": stale,
        "created_at": now - 12,
        "updated_at": now,
        "tool_count": 1,
        "events": [
            {"kind": "admitted", "status": "accepted", "at": now - 12,
             "duration_ms": None, "tool_count": 0},
            {"kind": "attempt", "status": "started", "at": now - 10,
             "duration_ms": None, "tool_count": 0},
            {"kind": "tool_call", "status": "observed", "at": now - 7,
             "duration_ms": None, "tool_count": 1},
            {"kind": "response", "status": "completed", "at": now - 2,
             "duration_ms": 8_000, "tool_count": 0},
            {"kind": "completed", "status": "completed", "at": now,
             "duration_ms": None, "tool_count": 0},
        ],
    }


def _snapshot(instances: list[dict]) -> dict:
    return {
        "schema": 1,
        "observed_at": time.time(),
        "window_seconds": 7 * 24 * 60 * 60,
        "coverage": "observed-callbacks",
        "instances": instances,
        "relations": [],
    }


def _team_snapshot() -> dict:
    sender = _instance(profile="developer")
    sender["execution_key"] = "e" * 32
    sender["gateway_turn_id"] = "f" * 32
    recipient = _instance(profile="researcher")
    recipient["execution_key"] = "g" * 32
    recipient["gateway_turn_id"] = "f" * 32
    now = max(sender["updated_at"], recipient["updated_at"])
    team_key = "T" * 32
    return {
        "schema": 2, "observed_at": now, "window_seconds": 7 * 24 * 60 * 60,
        "coverage": "observed-callbacks", "partial": False,
        "instances": [sender, recipient],
        "team_instances": [{
            "team_execution_key": team_key, "team_id": "pair_1",
            "source_revision": "team-source-v3", "mission_id": "c" * 32,
            "mission_revision": 2, "members": [sender["execution_key"], recipient["execution_key"]],
            "state": "historical", "coverage": "observed-callbacks",
        }],
        "relations": [{
            "relation_key": "Q" * 32, "team_execution_key": team_key,
            "mission_id": "c" * 32, "mission_revision": 2,
            "sender_execution_key": sender["execution_key"],
            "recipient_execution_key": recipient["execution_key"],
            "kind": "completed_message", "event_at": now - 1,
            "state": "historical", "coverage": "observed-callbacks",
        }],
    }


def test_projection_exposes_actual_completed_worker_and_measured_activity_only():
    projected = project_native_activity_snapshot(_snapshot([_instance()]))

    assert projected["observation"]["partial"] is True
    assert projected["summary"]["active_instances"] is None
    assert projected["summary"]["observed_completed_executions"] == 1
    assert projected["summary"]["observed_tool_calls"] == 1
    assert projected["summary"]["response_duration_ms"] == 8_000
    assert projected["summary"]["response_duration_coverage"] == 1
    assert projected["instances"][0]["display_name"] == "Dev Peter"
    assert projected["instances"][0]["state"] == "completed"
    assert projected["instances"][0]["events"][-1]["kind"] == "completed"
    assert projected["top_experts"] == [{
        "profile_id": "developer", "source_revision": "source-v17",
        "completed_executions": 1, "observed_tool_calls": 1, "instances": 1,
        "basis": "completed root-observed executions and their observed native tool calls",
        "coverage": "observed-callbacks", "partial": True,
    }]
    assert projected["teams"] == []
    assert projected["relations"] == []
    assert projected["pending"]["communication_edges"] == "no_verified_sender_recipient_records"
    # Native/session and root source-generation identifiers do not escape to the browser DTO.
    assert "gateway_turn_id" not in projected["instances"][0]
    assert "source_generation_sha256" not in projected["instances"][0]


def test_persisted_collision_alias_is_preserved():
    row = _instance()
    row["display_alias"] = "Dev Peter ·2"

    projected = project_native_activity_snapshot(_snapshot([row]))

    assert projected["instances"][0]["display_name"] == "Dev Peter ·2"


def test_stale_rows_become_unknown_and_absent_measurements_stay_null():
    row = _instance(status="running", stale=True)
    row["events"] = [item for item in row["events"] if item["kind"] != "response"]
    projected = project_native_activity_snapshot(_snapshot([row]))

    assert projected["instances"][0]["state"] == "unknown"
    assert projected["summary"]["active_instances"] is None
    assert projected["summary"]["response_duration_ms"] is None
    assert projected["summary"]["response_duration_coverage"] == 0
    assert projected["instances"][0]["completed_executions"] == 0
    assert projected["summary"]["observed_completed_executions"] == 0
    assert projected["top_experts"] == []


@pytest.mark.parametrize("mutate", [
    lambda value: value["instances"][0].update(extra="untrusted"),
    lambda value: value["instances"][0].update(source_generation_sha256="not-a-digest"),
    lambda value: value.update(relations=[{"kind": "invented-team-edge"}]),
])
def test_projection_rejects_open_or_unverified_root_data(mutate):
    value = _snapshot([_instance()])
    mutate(value)

    with pytest.raises(ValueError):
        project_native_activity_snapshot(value)


def test_projection_rejects_oversized_instance_or_event_windows():
    too_many_instances = _snapshot([_instance() for _ in range(101)])
    with pytest.raises(ValueError):
        project_native_activity_snapshot(too_many_instances)

    too_many_events = _snapshot([_instance()])
    too_many_events["instances"][0]["events"] *= 41
    with pytest.raises(ValueError):
        project_native_activity_snapshot(too_many_events)


def test_projection_rejects_future_and_out_of_window_activity_timestamps():
    future = _snapshot([_instance()])
    future["instances"][0]["events"][0]["at"] = future["observed_at"] + 1
    with pytest.raises(ValueError):
        project_native_activity_snapshot(future)

    old = _snapshot([_instance()])
    old["instances"][0]["created_at"] = old["observed_at"] - old["window_seconds"] - 1
    with pytest.raises(ValueError):
        project_native_activity_snapshot(old)


def test_empty_current_snapshot_is_truthfully_quiet_with_observation_window():
    projected = project_native_activity_snapshot(_snapshot([]))

    assert projected["observation"]["state"] == "quiet"
    assert projected["observation"]["partial"] is True
    assert projected["summary"]["observed_instances"] == 0
    assert projected["instances"] == []
    assert projected["teams"] == []
    assert projected["relations"] == []


def test_projection_exposes_only_root_joined_team_instances_and_completed_message_edges():
    projected = project_native_activity_snapshot(_team_snapshot())

    assert projected["schema"] == 2
    assert projected["observation"]["partial"] is True
    assert projected["pending"]["team_membership"] == "verified"
    assert projected["pending"]["communication_edges"] == "verified"
    assert projected["teams"] == [{
        "id": "T" * 32, "team_execution_key": "T" * 32, "team_id": "pair_1",
        "name": "pair_1", "source_revision": "team-source-v3",
        "mission_id": "c" * 32, "mission_revision": 2,
        "members": ["e" * 32, "g" * 32], "state": "historical",
        "coverage": "observed-callbacks", "partial": False,
    }]
    assert projected["relations"] == [{
        "id": "Q" * 32, "team_id": "T" * 32, "team_execution_key": "T" * 32,
        "mission_id": "c" * 32, "mission_revision": 2,
        "from": "e" * 32, "to": "g" * 32,
        "sender_execution_key": "e" * 32, "recipient_execution_key": "g" * 32,
        "kind": "completed_message", "at": projected["relations"][0]["at"],
        "state": "historical", "coverage": "observed-callbacks", "partial": False,
    }]
    # The projection carries no completion handles, message bytes, or digest material.
    assert "excerpt_sha256" not in str(projected)
    assert "completion_handle" not in str(projected)


@pytest.mark.parametrize("mutate", [
    lambda value: value["team_instances"][0].update(members=["z" * 32]),
    lambda value: value["relations"][0].update(mission_revision=3),
    lambda value: value["relations"][0].update(recipient_execution_key="z" * 32),
])
def test_projection_rejects_team_relations_without_exact_included_mission_join(mutate):
    value = _team_snapshot()
    mutate(value)

    with pytest.raises(ValueError):
        project_native_activity_snapshot(value)


def test_partial_or_stale_team_and_relation_state_is_preserved():
    value = _team_snapshot()
    value["partial"] = True
    value["team_instances"][0]["state"] = "partial"
    value["team_instances"][0]["coverage"] = "partial"
    value["relations"][0]["state"] = "stale"

    projected = project_native_activity_snapshot(value)

    assert projected["observation"]["state"] == "partial"
    assert projected["teams"][0]["state"] == "partial"
    assert projected["teams"][0]["partial"] is True
    assert projected["relations"][0]["state"] == "stale"


@pytest.mark.parametrize("field, rows", [
    ("team_instances", [{}] * 101),
    ("relations", [{}] * 201),
])
def test_projection_rejects_oversized_team_or_relation_payload(field, rows):
    value = _team_snapshot()
    value[field] = rows

    with pytest.raises(ValueError):
        project_native_activity_snapshot(value)
