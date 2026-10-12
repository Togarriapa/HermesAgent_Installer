"""Managed primary SOUL block custody and native effective-readback checks."""
import hashlib
import json
import os
import stat
from types import SimpleNamespace

import pytest

from hermes_installer import primary_prompt_manager as manager
from hermes_installer.registry.primary_prompt import (
    END_MARKER,
    PrimaryPromptBlockError,
    append_managed_block,
    render_managed_block,
    split_managed_block,
)
from hermes_installer.registry import manual_jarvis_skills


def test_managed_block_preserves_exact_owner_prefix_and_complete_source_prompt():
    prefix = b"# Owner's Jarvis context\r\n\nKeep my preferences exactly.\n"
    source = b"# Jarvis\n\n## Role instructions\n\nRoute work to Orchestrator.\n"
    block = render_managed_block(source)
    merged, separator = append_managed_block(prefix, block)
    actual_prefix, actual_separator, actual_block = split_managed_block(
        merged, owner_prefix_length=len(prefix), separator=separator
    )

    assert actual_prefix == prefix
    assert merged.startswith(prefix)
    assert actual_separator == separator
    assert actual_block == block
    assert source in actual_block
    assert hashlib.sha256(actual_block).hexdigest() == hashlib.sha256(block).hexdigest()


def test_managed_block_parser_denies_edited_or_ambiguous_markers():
    prefix = b"Owner context.\n"
    block = render_managed_block(b"# Jarvis\n\nPrimary logic.\n")
    merged, separator = append_managed_block(prefix, block)

    edited_end = merged.replace(END_MARKER, b"<!-- changed marker -->")
    with pytest.raises(PrimaryPromptBlockError):
        split_managed_block(edited_end, owner_prefix_length=len(prefix), separator=separator)
    duplicate = merged + block
    with pytest.raises(PrimaryPromptBlockError):
        split_managed_block(duplicate, owner_prefix_length=len(prefix), separator=separator)


def test_atomic_admin_replace_preserves_file_identity_contract_and_refuses_stale_prefix(tmp_path, monkeypatch):
    uid, gid = os.getuid(), os.getgid()
    home = tmp_path / "hermes"
    home.mkdir()
    soul = home / "SOUL.md"
    owner_prefix = b"# Existing owner context\nKeep this exact text.\n"
    soul.write_bytes(owner_prefix)
    soul.chmod(0o600)
    monkeypatch.setattr(manager, "HOME_UID", uid)
    monkeypatch.setattr(manager, "HOME_GID", gid)
    monkeypatch.setattr(manager, "_open_home", lambda _core: os.open(
        home, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    ))
    before = manager._signature(soul.stat())
    merged = owner_prefix + b"\nmanaged block\n"

    after = manager._atomic_admin_replace(
        SimpleNamespace(), merged, expected_signature=before, uid=uid, gid=gid,
        mode=0o600, stage_name=".SOUL.md.jarvis-0123456789abcdef01234567.stage",
    )
    assert soul.read_bytes() == merged
    assert soul.stat().st_uid == uid and soul.stat().st_gid == gid
    assert stat.S_IMODE(soul.stat().st_mode) == 0o600
    assert merged.startswith(owner_prefix)
    assert len(after) == 9

    changed = soul.read_bytes() + b"user edit\n"
    soul.write_bytes(changed)
    with pytest.raises(manager.PrimaryPromptAdoptionError, match="changed"):
        manager._atomic_admin_replace(
            SimpleNamespace(), b"must not replace", expected_signature=before, uid=uid, gid=gid,
            mode=0o600, stage_name=".SOUL.md.jarvis-fedcba9876543210fedcba98.stage",
        )
    assert soul.read_bytes() == changed


def test_native_readback_denies_an_omitted_or_truncated_full_managed_block(monkeypatch, tmp_path):
    from hermes_installer import core_runtime as core

    skills = [f"skill-{index:03d}" for index in range(396)]
    rows = [{"skill_id": name, "archive_path": f"skills/{name}/SKILL.md"} for name in skills]
    files = {row["archive_path"]: f"body-{row['skill_id']}".encode() for row in rows}
    files["registry/profiles/hermes/SOUL.md"] = b"bundled primary"
    manifest = {"skill_members": rows}
    active = b"owner prefix plus managed block"
    profile_sha = hashlib.sha256(active).hexdigest()
    digests = {"profile:default": profile_sha}
    digests.update({"skill:" + row["skill_id"]: hashlib.sha256(files[row["archive_path"]]).hexdigest()
                    for row in rows})
    expected_block = hashlib.sha256(b"complete managed block").hexdigest()
    payload = {
        "python_version": "3.14.7", "profile": "default", "skills": skills, "loaded": skills,
        "visible_profiles": ["default"], "profile_display_name": "Jarvis",
        "profile_file_sha256": profile_sha, "managed_prompt_block_sha256": expected_block,
        "effective_prompt_contains_managed_block": False, "effective_prompt_truncated": True,
        "native_effective_prompt_sha256": profile_sha, "native_effective_prompt_chars": len(active),
        "expected_managed_block_sha256": expected_block, "digests": digests,
    }
    monkeypatch.setattr(core.pwd, "getpwnam", lambda _name: SimpleNamespace(
        pw_uid=1000, pw_gid=1000, pw_dir="/home/admin"))
    monkeypatch.setattr(core, "_validated_executable", lambda path, _owners: path)
    monkeypatch.setattr(core, "SOURCE", tmp_path)
    monkeypatch.setattr(core.subprocess, "run", lambda *_args, **_kwargs:
        SimpleNamespace(returncode=0, stdout=__import__("json").dumps(payload).encode()))

    with pytest.raises(core.CoreRuntimeError, match="did not match") as error:
        core._root_native_readback(
            manifest, files, active, expected_managed_block_sha256=expected_block
        )
    assert "managed_prompt_not_fully_effective" in str(error.value)
    assert "complete managed block" not in str(error.value)


@pytest.mark.parametrize("tamper", [None, "tree", "generation", "artifact"])
def test_fixed_bundle_joins_finite_discovery_to_protected_resources_record_and_cas(
        monkeypatch, tmp_path, tamper):
    from hermes_installer import core_runtime as core

    if os.geteuid() != 0:
        pytest.skip("protected Resources projection contract requires the Pi root test role")
    archive = manual_jarvis_skills.build_manual_jarvis_skills_artifact()
    artifact_sha = hashlib.sha256(archive).hexdigest()
    manifest, files = manual_jarvis_skills._read_artifact(archive, artifact_sha)
    source = manifest["source"]
    generation = "d" * 64
    resources_tree = source["git_tree"]
    record_generation = "e" * 64 if tamper == "generation" else generation
    record_tree = "0" * 40 if tamper == "tree" else resources_tree
    record_artifact = "f" * 64 if tamper == "artifact" else artifact_sha

    # This deliberately matches the finite public discovery projection; tree
    # and generation provenance stay in the protected root record/CAS join.
    discovery = {
        "core_version": core.COMMIT[:12], "provider": None, "model": None,
        "account_state": "unknown", "resources_state": "discovered",
        "resource_counts": {"native_skills": 396, "internal_profiles": 207,
                            "source_profiles_preserved": 208,
                            "other_declarations_preserved":
                                len(manifest["bundled_resource_inventory"]) - 396 - 208},
        "resources_revision": source["revision"], "artifact_sha256": artifact_sha,
        "discovery_observed_at_utc": "2026-10-12T00:00:00Z",
        "active_prompt_matches_bundled_primary": False,
    }
    assert "resources_tree" not in discovery
    protected_record = {
        "schema": 3, "native_readback_method": "root-pinned-hermes-loader-v2",
        "core_source_generation": record_generation,
        "resources_revision": source["revision"], "resources_tree": record_tree,
        "artifact_sha256": record_artifact,
    }
    cas = tmp_path / "resources-cas"
    cas.mkdir(mode=0o700)
    cas_file = cas / f"{artifact_sha}.zip"
    cas_file.write_bytes(archive)
    cas_file.chmod(0o600)
    record_file = tmp_path / "resources-record.json"
    record_file.write_text(json.dumps(protected_record, sort_keys=True), encoding="ascii")
    record_file.chmod(0o600)
    os.chown(cas_file, 0, 0)
    os.chown(record_file, 0, 0)
    monkeypatch.setattr(core, "RESOURCES_CAS", cas)
    monkeypatch.setattr(core, "RESOURCES_RECORD", record_file)
    monkeypatch.setattr(core, "_core_source_generation", lambda: generation)
    monkeypatch.setattr(core, "read_current_resources_discovery",
                        lambda **_kwargs: dict(discovery))

    if tamper is not None:
        with pytest.raises(manager.PrimaryPromptAdoptionError,
                           match="current Resources source receipt changed"):
            manager._fixed_bundle(core)
        return

    bound_generation, bound_discovery, bound_artifact, bound_manifest, bound_files, prompt = \
        manager._fixed_bundle(core)
    assert bound_generation == generation
    assert bound_discovery == discovery
    assert bound_artifact == artifact_sha
    assert bound_manifest["source"]["git_tree"] == resources_tree
    assert bound_files is not files
    assert prompt == files["registry/profiles/hermes/SOUL.md"]

    owner_prefix = b"# Existing owner context\nKeep these bytes unchanged.\n"
    block = render_managed_block(prompt)
    merged, separator = append_managed_block(owner_prefix, block)
    record = manager._new_record(
        generation, discovery, artifact_sha, resources_tree, prompt, block,
        owner_prefix, [1, 2, stat.S_IFREG | 0o600, 1000, 1000, 1,
                       len(owner_prefix), 3, 4], owner_prefix, separator)
    actual_prefix, _actual_separator, actual_block = split_managed_block(
        merged, owner_prefix_length=len(owner_prefix), separator=separator)
    assert actual_prefix == owner_prefix
    assert actual_block == block
    assert record["owner_prefix_sha256"] == hashlib.sha256(owner_prefix).hexdigest()
    assert record["resources_tree"] == resources_tree
