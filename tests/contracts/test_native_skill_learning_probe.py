from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hermes_installer.remote import native_skill_learning_probe as probe


class NativeApproval:
    def __init__(self, folder: Path, diff: str = "--- a/SKILL.md\n+++ b/SKILL.md\n+new\n"):
        self.folder = folder
        self.diff = diff
        self.calls = []
        self.on_diff = None

    def list_pending(self, subsystem):
        self.calls.append(("list", subsystem))
        return [json.loads(path.read_text()) for path in sorted(self.folder.glob("*.json"))]

    def skill_pending_diff(self, record):
        self.calls.append(("diff", record["id"]))
        if self.on_diff:
            self.on_diff()
        return self.diff


@pytest.fixture
def owner_pending(tmp_path, monkeypatch):
    home = tmp_path / "home" / "admin" / ".hermes"
    pending = home / "pending" / "skills"
    pending.mkdir(parents=True, mode=0o700)
    for path in (tmp_path, tmp_path / "home", tmp_path / "home" / "admin", home,
                 home / "pending", pending):
        path.chmod(0o700)
    monkeypatch.setattr(probe, "_CANONICAL_HOME", home)
    monkeypatch.setattr(probe, "_PENDING_COMPONENTS", tuple(pending.relative_to(Path("/")).parts))
    monkeypatch.setattr(probe, "_UID", os.getuid())
    return home, pending


def stage(pending: Path, *, pending_id="a1b2c3d4", action="create") -> Path:
    record = {
        "id": pending_id,
        "subsystem": "skills",
        "action": action,
        "summary": "Add a reviewed helper",
        "origin": "foreground",
        "created_at": 1234.5,
        "payload": {"action": action, "name": "jarvis-helper", "content": "candidate"},
    }
    path = pending / f"{pending_id}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    path.chmod(0o600)
    return path


def stage_base(home: Path, name="jarvis-helper") -> Path:
    base = home / "skills" / name
    base.mkdir(parents=True, mode=0o700)
    (home / "skills").chmod(0o700)
    (base / "SKILL.md").write_text("owner base bytes\n", encoding="utf-8")
    (base / "SKILL.md").chmod(0o600)
    base.chmod(0o700)
    return base


def test_fixed_probe_calls_only_native_list_and_diff_and_returns_closed_bounded_candidate(owner_pending):
    home, pending = owner_pending
    path = stage(pending)
    native = NativeApproval(pending)

    result = probe._collect(home, native)

    assert native.calls == [("list", "skills"), ("diff", "a1b2c3d4")]
    assert set(result) == {"schema", "state", "candidates", "pending_reasons", "candidate_count", "diff_bytes"}
    assert result["state"] == "read-only-native-review"
    candidate = result["candidates"][0]
    assert set(candidate) == {
        "opaque_id", "revision_sha256", "action", "created_at", "skill_label", "summary",
        "diff_text", "diff_sha256", "truncated", "state",
    }
    assert candidate["state"] == "pending-review"
    assert candidate["revision_sha256"]
    assert candidate["diff_text"] == native.diff
    assert candidate["opaque_id"] != "a1b2c3d4"
    assert "payload" not in candidate and "path" not in candidate
    assert probe._read_member(pending, path.name)[0][0] == path.stat().st_dev


def test_corrupt_member_silently_skipped_by_native_api_is_explicit_partial(owner_pending):
    home, pending = owner_pending
    stage(pending)

    class NativeSkips(NativeApproval):
        def list_pending(self, subsystem):
            self.calls.append(("list", subsystem))
            return []

    result = probe._collect(home, NativeSkips(pending))

    assert result["state"] == "partial"
    assert result["pending_reasons"] == ["pending_record_skipped"]
    assert result["candidates"] == []


def test_symlink_pending_member_is_not_passed_to_native_list_or_diff(owner_pending, tmp_path):
    home, pending = owner_pending
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (pending / "a1b2c3d4.json").symlink_to(outside)
    native = NativeApproval(pending)

    result = probe._collect(home, native)

    assert result["state"] == "partial"
    assert native.calls == []


def test_pending_membership_mutation_during_native_diff_discards_snapshot(owner_pending):
    home, pending = owner_pending
    path = stage(pending)
    native = NativeApproval(pending)
    native.on_diff = lambda: path.write_text("changed", encoding="utf-8")

    result = probe._collect(home, native)

    assert result["state"] == "partial"
    assert "pending_custody_changed" in result["pending_reasons"]
    assert result["candidates"] == []


def test_invalid_action_and_path_payload_is_partial_without_native_diff(owner_pending):
    home, pending = owner_pending
    path = stage(pending, action="write_file")
    record = json.loads(path.read_text())
    record["payload"]["file_path"] = "../../outside"
    path.write_text(json.dumps(record), encoding="utf-8")
    path.chmod(0o600)
    native = NativeApproval(pending)

    result = probe._collect(home, native)

    assert result["state"] == "partial"
    assert result["pending_reasons"] == ["pending_record_invalid"]
    assert native.calls == [("list", "skills")]


def test_native_list_record_must_exactly_match_preread_object(owner_pending):
    home, pending = owner_pending
    stage(pending)

    class NativeRaces(NativeApproval):
        def list_pending(self, subsystem):
            record = super().list_pending(subsystem)[0]
            record["summary"] = "changed between filesystem and native reads"
            return [record]

    native = NativeRaces(pending)
    result = probe._collect(home, native)

    assert result["state"] == "partial"
    assert result["pending_reasons"] == ["pending_custody_changed"]
    assert result["candidates"] == []
    assert native.calls == [("list", "skills")]


def test_skill_base_content_mutation_during_native_diff_discards_candidate(owner_pending):
    home, pending = owner_pending
    stage(pending, action="edit")
    base = stage_base(home)
    native = NativeApproval(pending)

    def mutate_base():
        (base / "SKILL.md").write_text("changed while native diff read\n", encoding="utf-8")

    native.on_diff = mutate_base
    result = probe._collect(home, native)

    assert result["state"] == "partial"
    assert result["pending_reasons"] == ["pending_custody_changed"]
    assert result["candidates"] == []


def test_unowned_or_symlink_skill_base_is_rejected_before_native_diff(owner_pending, tmp_path):
    home, pending = owner_pending
    stage(pending, action="edit")
    skills = home / "skills"
    skills.mkdir(mode=0o700)
    skills.chmod(0o700)
    outside = tmp_path / "outside-skill"
    outside.mkdir(mode=0o700)
    (outside / "SKILL.md").write_text("outside\n", encoding="utf-8")
    (skills / "jarvis-helper").symlink_to(outside, target_is_directory=True)
    native = NativeApproval(pending)

    result = probe._collect(home, native)

    assert result["state"] == "partial"
    assert result["pending_reasons"] == ["pending_member_invalid"]
    assert result["candidates"] == []
    assert native.calls == [("list", "skills")]


def test_batch_skill_base_is_snapshotted_and_late_change_discards_all_candidates(owner_pending):
    home, pending = owner_pending
    first = stage(pending, pending_id="a1b2c3d4", action="edit")
    second = stage(pending, pending_id="b1c2d3e4", action="edit")
    first_record = json.loads(first.read_text())
    first_record["action"] = "batch"
    first_record["payload"] = {"action": "batch", "operations": [
        {"action": "edit", "name": "jarvis-helper"},
        {"action": "patch", "name": "jarvis-other", "file_path": "SKILL.md"},
    ]}
    first.write_text(json.dumps(first_record), encoding="utf-8")
    first.chmod(0o600)
    second_record = json.loads(second.read_text())
    second_record["payload"]["name"] = "jarvis-other"
    second.write_text(json.dumps(second_record), encoding="utf-8")
    second.chmod(0o600)
    first_base = stage_base(home, "jarvis-helper")
    other_base = stage_base(home, "jarvis-other")
    native = NativeApproval(pending)

    def mutate_first_after_its_diff():
        if native.calls.count(("diff", "b1c2d3e4")):
            (first_base / "SKILL.md").write_text("late change after first diff\n", encoding="utf-8")

    native.on_diff = mutate_first_after_its_diff
    result = probe._collect(home, native)

    assert result["state"] == "partial"
    assert result["pending_reasons"] == ["pending_custody_changed"]
    assert result["candidates"] == []
    assert other_base.is_dir()
