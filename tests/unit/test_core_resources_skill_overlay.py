"""Temporary-filesystem effect contracts for owner Resources overlays.

Run on the identified Pi with the project Python; never against production Hermes
paths. Native directory replacement and byte readback are real, while the typed
Hermes receipt is generated from the exact installed files in this isolated tree.
"""
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer import core_runtime as core
from hermes_installer.registry import manual_jarvis_skills as native
from hermes_installer.registry import resources_skill_overlay as overlay
from hermes_installer.registry.native_install import NativeInstallReceipt


@pytest.fixture
def overlay_runtime(tmp_path, monkeypatch):
    if __import__("os").geteuid() != 0:
        pytest.skip("root-owned overlay journal contract requires the Pi root test role")
    home = tmp_path / "hermes-home"
    home.mkdir(mode=0o700)
    (home / "SOUL.md").write_text("# Jarvis\n", encoding="utf-8")
    (home / "SOUL.md").chmod(0o644)
    store = tmp_path / "overlay-journal"
    cas = tmp_path / "cas"
    monkeypatch.setattr(core, "ROOT_UID", 0)
    monkeypatch.setattr(core, "ROOT_GID", 0)
    monkeypatch.setattr(core, "HERMES_HOME", home)
    monkeypatch.setattr(core, "RESOURCES_SKILL_OVERLAYS", store)
    monkeypatch.setattr(core, "RESOURCES_CAS", cas)
    base = native.build_manual_jarvis_skills_artifact()
    base_sha = hashlib.sha256(base).hexdigest()
    core._ensure_dir(cas, 0, 0, 0o700)
    core._atomic_replace(cas / f"{base_sha}.zip", base, 0o600, 0, 0)
    native.install_manual_jarvis_skills(base, hermes_home=home, expected_sha256=base_sha)

    installed = {"archive": base, "sha256": base_sha}

    def discover_and_load_selected(*, hermes_root, skill_ids, **_kwargs):
        target = Path(hermes_root) / "skills" / native._GENERATION
        digests = {f"skill:{name}": hashlib.sha256(
            (target / "skills" / name / "SKILL.md").read_bytes()).hexdigest() for name in skill_ids}
        digests["profile:default"] = hashlib.sha256((Path(hermes_root) / "SOUL.md").read_bytes()).hexdigest()
        return NativeInstallReceipt(hermes_revision=native.PINNED_HERMES_REVISION,
            python_version="3.14.7", profile_id="default", discovered_profile=True,
            profile_identity_loaded=True, profile_display_name="Jarvis",
            discovered_skills=tuple(skill_ids), loaded_skills=tuple(skill_ids),
            content_digests=digests)

    monkeypatch.setattr("hermes_installer.registry.native_install.discover_and_load_selected",
        discover_and_load_selected)

    def install_owner(next_archive, previous_archive, *, next_sha, previous_sha):
        installed["archive"] = next_archive
        installed["sha256"] = next_sha
        native.install_and_verify_manual_jarvis_skills(next_archive, hermes_home=home,
            expected_sha256=next_sha, hermes_source="/pinned/hermes", python="/pinned/python",
            replace_owned_from_archive=previous_archive, replace_owned_from_sha256=previous_sha)

    monkeypatch.setattr(core, "_install_resources_skill_overlay_as_owner", install_owner)
    current = {"artifact_sha256": base_sha}
    monkeypatch.setattr(core, "read_current_resources_discovery", lambda **_kwargs: {
        "resources_state": "discovered", "artifact_sha256": current["artifact_sha256"]})

    def write_receipt(**_kwargs):
        _record, contents, _raw = core._resources_skill_overlay_read()
        effective, digest_map = overlay.compose_overlays(base, contents)
        digest = hashlib.sha256(effective).hexdigest()
        for skill_id, row in _record["skills"].items():
            assert digest_map[skill_id] == row["archive_sha256"]
        core._atomic_replace(cas / f"{digest}.zip", effective, 0o600, 0, 0)
        manifest, files = native._read_artifact(effective, digest)
        core._hash_generation_tree(home, manifest, files, digest)
        current["artifact_sha256"] = digest
        return {"artifact_sha256": digest}

    monkeypatch.setattr(core, "_write_resources_discovery", write_receipt)
    member = native._read_artifact(base, base_sha)[0]["skill_members"][0]
    content = native._read_artifact(base, base_sha)[1][member["archive_path"]]
    return SimpleNamespace(home=home, base=base, base_sha=base_sha,
        skill_id=member["skill_id"], base_content=content, installed=installed,
        current=current, generation="a" * 64)


def test_resources_write_cas_idempotency_archive_restore_and_native_readback(overlay_runtime):
    fixture = overlay_runtime
    edited = fixture.base_content + b"\nOwner overlay text.\n"
    base_sha = hashlib.sha256(fixture.base_content).hexdigest()
    key = "1" * 64
    saved = core.admin_resources_skill("write", fixture.skill_id,
        expected_sha256=base_sha, content=edited, idempotency_key=key,
        core_source_generation=fixture.generation)
    assert saved["state"] == "discovered" and saved["effective_readback"] is True
    effective = Path(fixture.home) / "skills" / native._GENERATION / "skills" / fixture.skill_id / "SKILL.md"
    assert effective.read_bytes() == edited
    effective_sha = hashlib.sha256(edited).hexdigest()
    assert fixture.installed["sha256"] == fixture.current["artifact_sha256"]

    replay = core.admin_resources_skill("write", fixture.skill_id,
        expected_sha256=base_sha, content=edited, idempotency_key=key,
        core_source_generation=fixture.generation)
    assert replay["sha256"] == effective_sha
    with pytest.raises(core.CoreRuntimeError):
        core.admin_resources_skill("write", fixture.skill_id,
            expected_sha256=base_sha, content=edited + b"changed\n", idempotency_key=key,
            core_source_generation=fixture.generation)
    with pytest.raises(core.CoreRuntimeError):
        core.admin_resources_skill("write", fixture.skill_id,
            expected_sha256=base_sha, content=edited + b"stale\n", idempotency_key="2" * 64,
            core_source_generation=fixture.generation)
    assert effective.read_bytes() == edited

    archived = core.admin_resources_skill("archive", fixture.skill_id,
        expected_sha256=effective_sha, idempotency_key="3" * 64,
        core_source_generation=fixture.generation)
    assert archived["state"] == "discovered" and archived["effective_readback"] is True
    assert effective.read_bytes() == fixture.base_content
    assert fixture.current["artifact_sha256"] == fixture.base_sha
    versions = core.list_archived_resources_skill_versions(fixture.skill_id, fixture.generation)
    assert {"restore_id": archived["recovery_id"], "sha256": effective_sha} in versions

    restored = core.admin_resources_skill("restore", fixture.skill_id,
        expected_sha256=hashlib.sha256(fixture.base_content).hexdigest(),
        restore_id=archived["recovery_id"], idempotency_key="4" * 64,
        core_source_generation=fixture.generation)
    assert restored["state"] == "discovered" and restored["effective_readback"] is True
    assert effective.read_bytes() == edited
    archived_ids = {row["skill_id"]: row["versions"]
        for row in core.list_archived_resources_skills(fixture.generation)}
    assert any(row["restore_id"] == restored["recovery_id"] for row in archived_ids[fixture.skill_id])


def test_failed_native_probe_restores_old_generation_and_does_not_report_active(overlay_runtime, monkeypatch):
    fixture = overlay_runtime
    target = fixture.home / "skills" / native._GENERATION / "skills" / fixture.skill_id / "SKILL.md"
    before = target.read_bytes()
    old_artifact = fixture.current["artifact_sha256"]
    from hermes_installer.registry.native_install import NativeInstallError
    monkeypatch.setattr("hermes_installer.registry.native_install.discover_and_load_selected",
        lambda **_kwargs: (_ for _ in ()).throw(NativeInstallError("simulated native readback failure")))
    with pytest.raises(core.CoreRuntimeError):
        core.admin_resources_skill("write", fixture.skill_id,
            expected_sha256=hashlib.sha256(before).hexdigest(),
            content=before + b"\nnew\n", idempotency_key="5" * 64,
            core_source_generation=fixture.generation)
    assert target.read_bytes() == before
    assert fixture.current["artifact_sha256"] == old_artifact
    record, contents, _raw = core._resources_skill_overlay_read()
    assert record["skills"] == {} and contents == {}


@pytest.mark.parametrize("install_new,expected_sha", [(True, "new"), (False, "old")])
def test_interrupted_overlay_journal_recovers_only_exact_old_or_new_generation(
        overlay_runtime, install_new, expected_sha):
    fixture = overlay_runtime
    edited = fixture.base_content + b"\nInterrupted owner edit.\n"
    new_archive, new_sha = overlay.build_effective_artifact(fixture.base,
        fixture.skill_id, edited)
    effective_member_sha = hashlib.sha256(edited).hexdigest()
    archive_member_sha = hashlib.sha256(new_archive).hexdigest()
    core._ensure_dir(core.RESOURCES_SKILL_OVERLAYS, 0, 0, 0o700)
    core._atomic_replace(core.RESOURCES_CAS / f"{archive_member_sha}.zip",
        new_archive, 0o600, 0, 0)
    core._atomic_replace(core.RESOURCES_SKILL_OVERLAYS / f"{effective_member_sha}.bin",
        edited, 0o600, 0, 0)
    old_record = {"schema": 1, "base_artifact_sha256": fixture.base_sha, "skills": {}}
    new_record = {"schema": 1, "base_artifact_sha256": fixture.base_sha,
        "skills": {fixture.skill_id: {"content_sha256": effective_member_sha,
            "archive_sha256": archive_member_sha}}}
    pending = {"schema": 1, "old_record": None, "new_record": new_record,
        "old_archive_sha256": fixture.base_sha, "new_archive_sha256": archive_member_sha,
        "idempotency_key": "6" * 64, "request_sha256": "7" * 64,
        "result": {"state": "discovered", "skill_id": fixture.skill_id}}
    core._atomic_replace(core.RESOURCES_SKILL_OVERLAYS / "pending.json",
        __import__("json").dumps(pending, sort_keys=True, separators=(",", ":")).encode(),
        0o600, 0, 0)
    if install_new:
        native.install_manual_jarvis_skills(new_archive, hermes_home=fixture.home,
            expected_sha256=archive_member_sha, replace_owned_from_archive=fixture.base,
            replace_owned_from_sha256=fixture.base_sha)
    assert core.recover_resources_skill_overlay() is True
    target = fixture.home / "skills" / native._GENERATION / "skills" / fixture.skill_id / "SKILL.md"
    expected_bytes = edited if expected_sha == "new" else fixture.base_content
    assert target.read_bytes() == expected_bytes
    assert not (core.RESOURCES_SKILL_OVERLAYS / "pending.json").exists()
    if install_new:
        active, content_map, _raw = core._resources_skill_overlay_read()
        assert active == new_record and content_map == {fixture.skill_id: edited}
        operation = core.RESOURCES_SKILL_OVERLAYS / "operations" / ("6" * 64 + ".json")
        assert operation.is_file()
    else:
        assert not (core.RESOURCES_SKILL_OVERLAYS / "active.json").exists()
        assert not (core.RESOURCES_SKILL_OVERLAYS / "operations" / ("6" * 64 + ".json")).exists()


def test_interrupted_overlay_journal_refuses_unrecognized_native_tree(overlay_runtime):
    fixture = overlay_runtime
    edited = fixture.base_content + b"\nInterrupted owner edit.\n"
    new_archive, new_sha = overlay.build_effective_artifact(fixture.base,
        fixture.skill_id, edited)
    archive_member_sha = hashlib.sha256(new_archive).hexdigest()
    effective_member_sha = hashlib.sha256(edited).hexdigest()
    core._ensure_dir(core.RESOURCES_SKILL_OVERLAYS, 0, 0, 0o700)
    core._atomic_replace(core.RESOURCES_CAS / f"{archive_member_sha}.zip",
        new_archive, 0o600, 0, 0)
    core._atomic_replace(core.RESOURCES_SKILL_OVERLAYS / f"{effective_member_sha}.bin",
        edited, 0o600, 0, 0)
    pending = {"schema": 1, "old_record": None,
        "new_record": {"schema": 1, "base_artifact_sha256": fixture.base_sha,
            "skills": {fixture.skill_id: {"content_sha256": effective_member_sha,
                "archive_sha256": archive_member_sha}}},
        "old_archive_sha256": fixture.base_sha,
        "new_archive_sha256": archive_member_sha,
        "idempotency_key": "8" * 64, "request_sha256": "9" * 64,
        "result": {"state": "discovered", "skill_id": fixture.skill_id}}
    core._atomic_replace(core.RESOURCES_SKILL_OVERLAYS / "pending.json",
        __import__("json").dumps(pending, sort_keys=True, separators=(",", ":")).encode(),
        0o600, 0, 0)
    target = fixture.home / "skills" / native._GENERATION / "skills" / fixture.skill_id / "SKILL.md"
    target.write_bytes(b"unrecognized partial native state")
    before_pending = (core.RESOURCES_SKILL_OVERLAYS / "pending.json").read_bytes()
    with pytest.raises(core.CoreRuntimeError, match="operator review"):
        core.recover_resources_skill_overlay()
    assert target.read_bytes() == b"unrecognized partial native state"
    assert (core.RESOURCES_SKILL_OVERLAYS / "pending.json").read_bytes() == before_pending
