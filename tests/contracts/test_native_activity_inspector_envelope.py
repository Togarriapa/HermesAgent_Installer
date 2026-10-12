from __future__ import annotations

import time

import pytest

from hermes_installer.remote.core_gateway_inspector import _native_activity_read_envelope_is_valid


def _legacy_envelope() -> dict:
    return {
        "schema": 1, "observed_at": time.time(), "window_seconds": 604800,
        "coverage": "observed-callbacks", "instances": [], "relations": [],
    }


def _team_envelope() -> dict:
    return {
        "schema": 2, "observed_at": time.time(), "window_seconds": 604800,
        "coverage": "observed-callbacks", "partial": False,
        "instances": [], "team_instances": [], "relations": [],
    }


def test_inspector_accepts_bounded_team_activity_envelope_and_legacy_read_shape():
    assert _native_activity_read_envelope_is_valid(_legacy_envelope())
    assert _native_activity_read_envelope_is_valid(_team_envelope())


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(extra="untrusted"),
    lambda value: value.update(partial=1),
    lambda value: value.update(team_instances=[{}] * 101),
    lambda value: value.update(relations=[{}] * 201),
    lambda value: value.update(observed_at=float("inf")),
    lambda value: value.update(instances=[{"events": [None] * 201}]),
])
def test_inspector_rejects_open_or_unbounded_team_activity_envelopes(mutate):
    value = _team_envelope()
    mutate(value)

    assert not _native_activity_read_envelope_is_valid(value)


def test_inspector_keeps_legacy_relation_rows_closed_until_schema_two():
    value = _legacy_envelope()
    value["relations"] = [{"kind": "invented"}]

    assert not _native_activity_read_envelope_is_valid(value)
