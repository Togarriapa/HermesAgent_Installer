from __future__ import annotations

import hashlib

import pytest

from hermes_installer.remote.jarvis_learning import (
    JarvisLearningUnavailable,
    build_learning_projection,
)


class Reader:
    def __init__(self, records, diffs):
        self.records = records
        self.diffs = diffs
        self.diff_reads = []

    def list_pending_skills(self):
        return self.records

    def skill_pending_diff(self, record):
        self.diff_reads.append(record["id"])
        return self.diffs[record["id"]]


def test_projection_uses_native_diff_and_never_exposes_mutation_actions():
    record = {
        "id": "a1b2c3d4", "action": "create", "name": "private-skill",
        "summary": "  Add a reviewed   helper\nwith references ",
        "origin": "background_review", "created_at": 1234.5,
        "payload": {"content": "private full candidate payload"},
    }
    diff = "--- a/SKILL.md\n+++ b/SKILL.md\n+candidate\n"
    reader = Reader([record], {record["id"]: diff})

    result = build_learning_projection(reader, owner_principal_verified=True)

    assert reader.diff_reads == [record["id"]]
    assert result["state"] == "read-only-native-review"
    assert result["canApply"] is False and result["canRollback"] is False
    assert result["candidates"] == [{
        "id": record["id"], "action": "create", "summary": "Add a reviewed helper with references",
        "origin": "background_review", "createdAt": 1234.5, "diff": diff,
        "diffSha256": hashlib.sha256(diff.encode()).hexdigest(),
        "reviewState": "awaiting-native-approval",
        "approvalRoute": "Hermes /skills pending and /skills approve <id>",
    }]
    assert "payload" not in result["candidates"][0]
    assert "name" not in result["candidates"][0]


def test_projection_denies_unverified_principal_before_reading_native_queue():
    reader = Reader([], {})
    with pytest.raises(JarvisLearningUnavailable, match="owner-only"):
        build_learning_projection(reader, owner_principal_verified=False)
    assert reader.diff_reads == []


@pytest.mark.parametrize("bad_record", [
    {"id": "../../etc", "action": "create", "created_at": 1},
    {"id": "aaaaaaaa", "action": "delete", "created_at": 1},
    {"id": "aaaaaaaa", "action": [], "created_at": 1},
    {"id": "aaaaaaaa", "action": "create", "created_at": True},
    {"id": "aaaaaaaa", "action": "create", "created_at": 10**10000},
])
def test_projection_rejects_invalid_ids_actions_and_timestamps(bad_record):
    reader = Reader([bad_record], {})
    with pytest.raises(JarvisLearningUnavailable, match="malformed"):
        build_learning_projection(reader, owner_principal_verified=True)
    assert reader.diff_reads == []


def test_projection_rejects_ambiguous_duplicate_pending_ids():
    row = {"id": "aaaaaaaa", "action": "create", "created_at": 1}
    reader = Reader([row, dict(row)], {"aaaaaaaa": "diff"})
    with pytest.raises(JarvisLearningUnavailable, match="malformed"):
        build_learning_projection(reader, owner_principal_verified=True)


def test_projection_rejects_oversized_diff_instead_of_truncating_review():
    row = {"id": "aaaaaaaa", "action": "create", "created_at": 1}
    reader = Reader([row], {"aaaaaaaa": "x" * 16_001})
    with pytest.raises(JarvisLearningUnavailable, match="exceeds its bound"):
        build_learning_projection(reader, owner_principal_verified=True)
