"""Filesystem effects for fixed Hermes-home skill edit/archive/restore transactions.

These temporary-tree contracts are intended for the Pi Python environment; they
must not be run on the development Mac against an installed Hermes home.
"""
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer.remote import jarvis_profile_source_adapter as adapter


def _file_read(path: Path, skill_id: str):
    raw = path.read_bytes()
    info = path.stat(follow_symlinks=False)
    return adapter.ProfileFileRead("hermes", "skill", f"skills/{skill_id}/SKILL.md",
        raw.decode("utf-8"), hashlib.sha256(raw).hexdigest(), adapter._signature(info))


@pytest.mark.skipif(os.geteuid() != 0,
    reason="owner-skill archive journals and writes require the production root role")
def test_owner_skill_edit_cas_idempotency_archive_and_exact_restore(tmp_path, monkeypatch):
    skill_id = "owner-tool"
    body = b"---\nname: owner-tool\n\nOriginal owner skill.\n"
    path = tmp_path / "skills" / skill_id
    path.mkdir(parents=True)
    (path / "SKILL.md").write_bytes(body)
    (path / "SKILL.md").chmod(0o644)
    backup = tmp_path / "backup"
    backup.mkdir(mode=0o700)
    monkeypatch.setattr(adapter, "HOME_UID", os.geteuid())
    monkeypatch.setattr(adapter, "HOME_GID", os.getegid())
    monkeypatch.setattr(adapter, "_open_skill_directory",
        lambda _skill: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    monkeypatch.setattr(adapter, "_backup_directory",
        lambda: os.open(backup, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    monkeypatch.setattr(adapter, "read_profile_skill",
        lambda _profile, _skill: _file_read(path / "SKILL.md", skill_id))

    def helper_process(args, *, input, **_kwargs):
        request = json.loads(input.decode("utf-8"))
        result = adapter._run_profile_file_helper(request)
        return SimpleNamespace(returncode=0,
            stdout=json.dumps(result, sort_keys=True, separators=(",", ":")).encode())

    monkeypatch.setattr(adapter.subprocess, "run", helper_process)
    generation = "a" * 64
    initial_sha = hashlib.sha256(body).hexdigest()
    replacement = "---\nname: owner-tool\n\nEdited by the owner.\n"
    key = "idempotency-owner-skill-edit-000001"
    result = adapter.write_profile_skill(skill_id, expected_sha256=initial_sha,
        content=replacement, idempotency_key=key, core_source_generation=generation)
    assert result.state == "active" and result.readback is True
    edited = (path / "SKILL.md").read_bytes()
    edited_sha = hashlib.sha256(edited).hexdigest()
    assert edited == replacement.encode()

    replay = adapter.write_profile_skill(skill_id, expected_sha256=initial_sha,
        content=replacement, idempotency_key=key, core_source_generation=generation)
    assert replay.state == "active" and replay.sha256 == edited_sha
    with pytest.raises(adapter.ProfileFileCustodyError):
        adapter.write_profile_skill(skill_id, expected_sha256=initial_sha,
            content=replacement + "different\n", idempotency_key=key,
            core_source_generation=generation)
    stale = adapter.write_profile_skill(skill_id, expected_sha256=initial_sha,
        content=replacement, idempotency_key="idempotency-stale-skill-cas-000001",
        core_source_generation=generation)
    assert stale.state == "conflict" and (path / "SKILL.md").read_bytes() == edited

    monkeypatch.setattr(adapter.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=b""))
    failed_archive = adapter.archive_profile_skill(skill_id, expected_sha256=edited_sha,
        idempotency_key="idempotency-failed-skill-archive-001", core_source_generation=generation)
    assert failed_archive.state == "unknown-pending"
    assert (path / "SKILL.md").read_bytes() == edited

    monkeypatch.setattr(adapter.subprocess, "run", helper_process)

    archived = adapter.archive_profile_skill(skill_id, expected_sha256=edited_sha,
        idempotency_key="idempotency-owner-skill-archive-0001", core_source_generation=generation)
    assert archived.state == "archived" and archived.readback is True
    assert not (path / "SKILL.md").exists()
    versions = adapter.list_archived_profile_skills(None)
    assert {"skill_id": skill_id, "restore_id": archived.recovery_id,
            "sha256": edited_sha} in versions

    monkeypatch.setattr(adapter.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=b""))
    failed_restore = adapter.restore_profile_skill(skill_id, expected_sha256=edited_sha,
        restore_id=archived.recovery_id, idempotency_key="idempotency-failed-skill-restore-001",
        core_source_generation=generation)
    assert failed_restore.state == "unknown-pending" and not (path / "SKILL.md").exists()
    monkeypatch.setattr(adapter.subprocess, "run", helper_process)

    restored = adapter.restore_profile_skill(skill_id, expected_sha256=edited_sha,
        restore_id=archived.recovery_id, idempotency_key="idempotency-owner-skill-restore-0001",
        core_source_generation=generation)
    assert restored.state == "restored" and restored.readback is True
    assert (path / "SKILL.md").read_bytes() == edited
    replayed_restore = adapter.restore_profile_skill(skill_id, expected_sha256=edited_sha,
        restore_id=archived.recovery_id, idempotency_key="idempotency-owner-skill-restore-0001",
        core_source_generation=generation)
    assert replayed_restore.state == "restored"


@pytest.mark.skipif(os.geteuid() != 0,
    reason="owner-skill restore custody checks require the production root role")
def test_owner_skill_archive_rejects_symlinked_restore_leaf_without_following(tmp_path, monkeypatch):
    skill_id = "owner-tool"
    path = tmp_path / "skills" / skill_id
    path.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("preserve this target\n", encoding="utf-8")
    (path / "SKILL.md").symlink_to(outside)
    backup = tmp_path / "backup"
    backup.mkdir(mode=0o700)
    monkeypatch.setattr(adapter, "HOME_UID", os.geteuid())
    monkeypatch.setattr(adapter, "HOME_GID", os.getegid())
    monkeypatch.setattr(adapter, "_open_skill_directory",
        lambda _skill: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    monkeypatch.setattr(adapter, "_backup_directory",
        lambda: os.open(backup, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    def nofollow_read(_profile, _skill):
        fd = os.open(path / "SKILL.md", os.O_RDONLY | os.O_NOFOLLOW)
        try:
            raw, signature = adapter._read_fd(fd, uid=os.geteuid(), gid=os.getegid())
        finally:
            os.close(fd)
        return adapter.ProfileFileRead("hermes", "skill", "skills/owner-tool/SKILL.md",
            raw.decode(), hashlib.sha256(raw).hexdigest(), signature)
    monkeypatch.setattr(adapter, "read_profile_skill", nofollow_read)

    with pytest.raises(OSError):
        adapter.restore_profile_skill(skill_id, expected_sha256="0" * 64,
            restore_id="recovery-id-123456789", idempotency_key="idempotency-symlink-test-000001",
            core_source_generation="a" * 64)
    assert outside.read_text(encoding="utf-8") == "preserve this target\n"
