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


def test_stale_rows_become_unknown_and_absent_measurements_stay_null():
    row = _instance(status="running", stale=True)
    row["events"] = [item for item in row["events"] if item["kind"] != "response"]
    projected = project_native_activity_snapshot(_snapshot([row]))

    assert projected["instances"][0]["state"] == "unknown"
    assert projected["summary"]["active_instances"] is None
    assert projected["summary"]["response_duration_ms"] is None
    assert projected["summary"]["response_duration_coverage"] == 0
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


def test_empty_current_snapshot_is_truthfully_quiet_with_observation_window():
    projected = project_native_activity_snapshot(_snapshot([]))

    assert projected["observation"]["state"] == "quiet"
    assert projected["observation"]["partial"] is True
    assert projected["summary"]["observed_instances"] == 0
    assert projected["instances"] == []
    assert projected["teams"] == []
    assert projected["relations"] == []
