"""Temporary-filesystem effect contracts for owner Resources overlays.

Run on the identified Pi with the project Python; never against production Hermes
paths. Native directory replacement and byte readback are real, while the typed
Hermes receipt is generated from the exact installed files in this isolated tree.
"""
import hashlib
import io
import json
import os
import pwd
import shutil
import tempfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer import core_runtime as core
from hermes_installer.registry import manual_jarvis_skills as native
from hermes_installer.registry import resources_skill_overlay as overlay
from hermes_installer.registry.native_install import NativeInstallReceipt

_PRODUCTION_READ_RESOURCES_DISCOVERY = core.read_current_resources_discovery
_PRODUCTION_WRITE_RESOURCES_DISCOVERY = core._write_resources_discovery


def _replace_helper(archive_bytes, helper_bytes):
    manifest, files = native._read_artifact(archive_bytes, hashlib.sha256(archive_bytes).hexdigest())
    manifest["installer"] = {"archive_path": "manual_stage_jarvis_skills.py",
                             "size_bytes": len(helper_bytes),
                             "sha256": hashlib.sha256(helper_bytes).hexdigest()}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        native._zip_write(archive, "manifest.json", native._canonical_json(manifest))
        for name, content in sorted(files.items()):
            native._zip_write(archive, name, content)
        native._zip_write(archive, "manual_stage_jarvis_skills.py", helper_bytes)
    return stream.getvalue()


def _two_overlay_history(base_archive):
    base_sha = hashlib.sha256(base_archive).hexdigest()
    manifest, files = native._read_artifact(base_archive, base_sha)
    selected = manifest["skill_members"][:2]
    contents = {}
    for row in selected:
        original = files[row["archive_path"]]
        contents[row["skill_id"]] = original + b"\nOwner retained overlay.\n"
    current = base_archive
    digests = {}
    for skill_id, content in sorted(contents.items()):
        current, digests[skill_id] = overlay.build_effective_artifact(current, skill_id, content)
    journal = {"schema": 1, "base_artifact_sha256": base_sha, "skills": {
        skill_id: {"content_sha256": hashlib.sha256(contents[skill_id]).hexdigest(),
                   "archive_sha256": digests[skill_id]}
        for skill_id in sorted(contents)}}
    return current, (json.dumps(journal, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"), contents


def _committed_row(reconstruction):
    row = {
        "schema": 1, "purpose": "helper-only-overlay-reconstruction",
        "cohort_transaction_id": "a" * 64, "owner_uid": 1000,
        "home_role": "jarvis-primary-home",
        "old_base_artifact_sha256": reconstruction.old_base_artifact_sha256,
        "new_base_artifact_sha256": reconstruction.new_base_artifact_sha256,
        "old_composed_artifact_sha256": reconstruction.old_composed_artifact_sha256,
        "new_composed_artifact_sha256": reconstruction.new_composed_artifact_sha256,
        "overlay_journal_sha256": reconstruction.overlay_journal_sha256,
        "overlay_contents": [{"skill_id": name, "content_sha256": digest}
                              for name, digest in reconstruction.overlay_contents],
        "base_non_installer_manifest_sha256": reconstruction.base_non_installer_manifest_sha256,
        "composed_non_installer_manifest_sha256": reconstruction.composed_non_installer_manifest_sha256,
        "materialized_tree_sha256": reconstruction.materialized_tree_sha256,
        "old_installed_journal_sha256": "b" * 64, "new_installed_journal_sha256": "c" * 64,
        "old_discovery_sha256": "d" * 64, "new_discovery_sha256": "e" * 64,
        "old_core_source_generation": "f" * 64, "new_core_source_generation": "1" * 64,
        "old_source_recipe_sha256": "2" * 64, "new_source_recipe_sha256": "3" * 64,
        "phase": "committed",
    }
    context = {key: row[key] for key in (
        "cohort_transaction_id", "owner_uid", "home_role", "old_installed_journal_sha256",
        "new_installed_journal_sha256", "old_discovery_sha256", "new_discovery_sha256",
        "old_core_source_generation", "new_core_source_generation",
        "old_source_recipe_sha256", "new_source_recipe_sha256", "phase")}
    return row, context


def test_helper_only_overlay_reconstruction_preserves_two_exact_overlay_steps():
    old_base = _replace_helper(native.build_manual_jarvis_skills_artifact(), b"retained old helper")
    new_base = native.build_manual_jarvis_skills_artifact()
    old_composed, journal, contents = _two_overlay_history(old_base)
    old_composed_manifest, old_composed_files = native._read_artifact(
        old_composed, hashlib.sha256(old_composed).hexdigest())
    new_base_manifest, new_base_files = native._read_artifact(
        new_base, hashlib.sha256(new_base).hexdigest())
    # The base classifier must continue to reject A0→B1 because A0 contains
    # owner edits. Reconstruction proves B0→B1 and A0→A1 separately.
    assert not native.verify_same_materialization_transition(
        old_composed_manifest, old_composed_files, new_base_manifest, new_base_files)

    result = overlay.reconstruct_helper_only_overlay_transition(
        old_base, new_base, old_composed, journal, contents)

    new_manifest, new_files = native._read_artifact(
        result.new_composed_archive, result.new_composed_artifact_sha256)
    old_manifest, old_files = native._read_artifact(
        old_composed, result.old_composed_artifact_sha256)
    assert result.verified_intermediate_archive_sha256 == tuple(
        (skill_id, journal_digest)
        for skill_id, journal_digest in sorted(
            (skill_id, row["archive_sha256"])
            for skill_id, row in json.loads(journal)["skills"].items()))
    new_base_manifest, _ = native._read_artifact(new_base, result.new_base_artifact_sha256)
    assert new_manifest["installer"] == new_base_manifest["installer"]
    assert old_files == new_files
    member_by_skill = {row["skill_id"]: row["archive_path"] for row in new_manifest["skill_members"]}
    assert {name: new_files[member_by_skill[name]] for name in contents} == contents
    assert result.overlay_journal_sha256 == hashlib.sha256(journal).hexdigest()

    row, context = _committed_row(result)
    current = overlay.resolve_committed_helper_only_overlay_reconstruction(
        old_base, new_base, old_composed, journal, contents, row, current_context=context)
    assert current.new_composed_archive == result.new_composed_archive
    changed = dict(context)
    changed["new_core_source_generation"] = "4" * 64
    with pytest.raises(overlay.ResourcesSkillOverlayError, match="cohort differs"):
        overlay.resolve_committed_helper_only_overlay_reconstruction(
            old_base, new_base, old_composed, journal, contents, row, current_context=changed)
    foreign = dict(row)
    foreign["cohort_transaction_id"] = "9" * 64
    assert not overlay.verify_committed_helper_only_overlay_reconstruction(
        result, foreign, current_context=context)


@pytest.mark.parametrize("tamper", ["intermediate", "content", "journal", "manifest"])
def test_helper_only_overlay_reconstruction_denies_changed_chain_or_manifest(tamper):
    old_base = _replace_helper(native.build_manual_jarvis_skills_artifact(), b"retained old helper")
    new_base = native.build_manual_jarvis_skills_artifact()
    old_composed, journal, contents = _two_overlay_history(old_base)
    if tamper == "intermediate":
        value = json.loads(journal)
        key = sorted(value["skills"])[0]
        value["skills"][key]["archive_sha256"] = "0" * 64
        journal = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    elif tamper == "content":
        key = sorted(contents)[0]
        contents[key] += b"forged\n"
    elif tamper == "journal":
        journal = journal.replace(b'"schema":1', b'"schema":1,"schema":1')
    else:
        manifest, files = native._read_artifact(new_base, hashlib.sha256(new_base).hexdigest())
        manifest["readiness"]["enabled"] = not manifest["readiness"].get("enabled", False)
        # A changed source manifest must fail the fixed artifact parser/helper pair.
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            native._zip_write(archive, "manifest.json", native._canonical_json(manifest))
            for name, content in sorted(files.items()):
                native._zip_write(archive, name, content)
            native._zip_write(archive, "manual_stage_jarvis_skills.py",
                              Path(native.__file__).read_bytes())
        new_base = stream.getvalue()

    with pytest.raises(overlay.ResourcesSkillOverlayError):
        overlay.reconstruct_helper_only_overlay_transition(
            old_base, new_base, old_composed, journal, contents)


@pytest.fixture
def overlay_runtime(tmp_path, monkeypatch, request):
    if __import__("os").geteuid() != 0:
        pytest.skip("root-owned overlay journal contract requires the Pi root test role")
    account = pwd.getpwnam("admin")
    # The verifier intentionally accepts only the real production layout:
    # every ancestor is root-owned/non-writable, then `admin/.hermes` is
    # admin-owned mode 0700. A pytest tmp_path beneath `/tmp` cannot satisfy
    # that contract, so keep this fixture's journals and CAS under `/run` too.
    sandbox = Path(tempfile.mkdtemp(prefix="hermes-overlay-fixture-", dir="/run"))
    sandbox.chmod(0o755)
    record_dir = sandbox / "root-records"
    record_dir.mkdir(mode=0o700)
    record_dir.chmod(0o700)
    admin_home = sandbox / "admin"
    admin_home.mkdir(mode=0o700)
    home = admin_home / ".hermes"
    home.mkdir(mode=0o700)
    request.addfinalizer(lambda: shutil.rmtree(sandbox, ignore_errors=True))
    (home / "SOUL.md").write_text("# Jarvis\n", encoding="utf-8")
    (home / "SOUL.md").chmod(0o644)
    store = sandbox / "overlay-journal"
    cas_parent = sandbox / "resource-cas-parent"
    cas_parent.mkdir(mode=0o700)
    cas = cas_parent / "cas"
    monkeypatch.setattr(core, "ROOT_UID", 0)
    monkeypatch.setattr(core, "HERMES_HOME", home)
    monkeypatch.setattr(core, "RESOURCES_SKILL_OVERLAYS", store)
    monkeypatch.setattr(core, "RESOURCES_CAS", cas)
    base = native.build_manual_jarvis_skills_artifact()
    base_sha = hashlib.sha256(base).hexdigest()
    core._ensure_dir(cas, 0, 0, 0o700)
    core._atomic_replace(cas / f"{base_sha}.zip", base, 0o600, 0, 0)
    native.install_manual_jarvis_skills(base, hermes_home=home, expected_sha256=base_sha)

    def set_generation_owner(uid, gid):
        skills = home / "skills"
        for root, directories, filenames in os.walk(skills, topdown=False, followlinks=False):
            for filename in filenames:
                os.chown(Path(root) / filename, uid, gid, follow_symlinks=False)
            for dirname in directories:
                os.chown(Path(root) / dirname, uid, gid, follow_symlinks=False)
        os.chown(skills, uid, gid)

    def set_home_owner(uid, gid):
        for root, directories, filenames in os.walk(home, topdown=False, followlinks=False):
            for filename in filenames:
                os.chown(Path(root) / filename, uid, gid, follow_symlinks=False)
            for dirname in directories:
                os.chown(Path(root) / dirname, uid, gid, follow_symlinks=False)
        os.chown(home, uid, gid)
        os.chown(admin_home, uid, gid)
        os.chmod(home, 0o700)
        os.chmod(admin_home, 0o700)

    def own_generation_as_admin():
        set_generation_owner(account.pw_uid, account.pw_gid)
        set_home_owner(account.pw_uid, account.pw_gid)

    own_generation_as_admin()

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
        set_home_owner(0, 0)
        native.install_and_verify_manual_jarvis_skills(next_archive, hermes_home=home,
            expected_sha256=next_sha, hermes_source="/pinned/hermes", python="/pinned/python",
            replace_owned_from_archive=previous_archive, replace_owned_from_sha256=previous_sha)
        own_generation_as_admin()

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
    return SimpleNamespace(sandbox=sandbox, record_dir=record_dir,
        home=home, base=base, base_sha=base_sha,
        cas_parent=cas_parent, cas=cas,
        skill_id=member["skill_id"], base_content=content, installed=installed,
        current=current, generation="a" * 64,
        own_generation=lambda uid=account.pw_uid, gid=account.pw_gid: set_generation_owner(uid, gid),
        set_home_owner=set_home_owner, own_generation_as_admin=own_generation_as_admin)


def _replace_resources_base_ancestor(fixture):
    path = fixture.cas / f"{fixture.base_sha}.zip"
    before = path.stat()
    signature = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                               value.st_gid, value.st_nlink, value.st_size,
                               value.st_mtime_ns, value.st_ctime_ns)
    moved = fixture.sandbox / "previous-resource-cas-parent"
    os.replace(fixture.cas_parent, moved)
    fixture.cas_parent.mkdir(mode=0o700)
    fixture.cas_parent.chmod(0o700)
    os.replace(moved / "cas", fixture.cas)
    assert signature((fixture.cas / f"{fixture.base_sha}.zip").stat()) == signature(before)


def test_runtime_resources_base_reads_retained_cas_without_recompiling(overlay_runtime, monkeypatch):
    fixture = overlay_runtime

    def forbidden_compile():
        raise AssertionError("runtime Resources reads must not invoke the compiler")

    monkeypatch.setattr(native, "build_manual_jarvis_skills_artifact", forbidden_compile)
    prepared = core._load_resources_base()
    record, contents, raw = core._resources_skill_overlay_read()

    assert prepared.archive == fixture.base
    assert prepared.source_witness
    assert record == {"schema": 1, "base_artifact_sha256": fixture.base_sha, "skills": {}}
    assert contents == {} and raw is None


def test_runtime_base_bound_precedes_hashing_and_retention_recovers_cleanly(
        overlay_runtime, monkeypatch):
    fixture = overlay_runtime
    oversized = core._PreparedResourcesBase(
        bytes(16 * 1024 * 1024 + 1), (), (), (), core._RESOURCES_BASE_SEAL)

    def forbidden_hash(_value):
        raise AssertionError("prepared bytes must be bounded before hashing")

    with monkeypatch.context() as scoped:
        scoped.setattr(core.hashlib, "sha256", forbidden_hash)
        with pytest.raises(core.CoreRuntimeError, match="prepared Resources base is unavailable"):
            core._check_prepared_resources_base(oversized)

    path = fixture.cas / f"{fixture.base_sha}.zip"
    witness = core._resources_base_source_witness()
    path.chmod(0o640)
    with pytest.raises(core.CoreRuntimeError, match="projection file custody"):
        core._retain_compiled_resources_base(fixture.base, witness)
    assert path.read_bytes() == fixture.base
    assert path.stat().st_mode & 0o777 == 0o640
    path.chmod(0o600)
    path.unlink()
    with monkeypatch.context() as scoped:
        scoped.setattr(core, "_resources_base_source_witness", lambda: ("changed",))
        with pytest.raises(core.CoreRuntimeError, match="changed before retention"):
            core._retain_compiled_resources_base(fixture.base, witness)
    assert not path.exists()

    original_writer = core._write_resources_cas_artifact

    def interrupt_after_retaining(archive, digest):
        original_writer(archive, digest)
        raise core.CoreRuntimeError("simulated stop after immutable CAS retention")

    with monkeypatch.context() as scoped:
        scoped.setattr(core, "_write_resources_cas_artifact", interrupt_after_retaining)
        with pytest.raises(core.CoreRuntimeError, match="simulated stop"):
            core._retain_compiled_resources_base(fixture.base, witness)
    assert path.read_bytes() == fixture.base
    first = core._load_resources_base()
    first_file_identity = path.stat().st_ino
    second = core._retain_compiled_resources_base(fixture.base, witness)
    assert second.archive == first.archive == fixture.base
    assert path.stat().st_ino == first_file_identity


def test_runtime_base_denies_missing_cas_without_compiler_fallback(overlay_runtime, monkeypatch):
    fixture = overlay_runtime
    (fixture.cas / f"{fixture.base_sha}.zip").unlink()
    calls = []

    def forbidden_compile():
        calls.append("compile")
        raise AssertionError("runtime read must not invoke the compiler")

    monkeypatch.setattr(native, "build_manual_jarvis_skills_artifact", forbidden_compile)
    with pytest.raises(core.CoreRuntimeError, match="CAS is unavailable"):
        core._load_resources_base()
    assert calls == []


def test_archived_resources_readers_reuse_the_verified_base(overlay_runtime, monkeypatch):
    fixture = overlay_runtime
    restore_id = "a" * 64
    content = fixture.base_content + b"\narchived version\n"
    content_sha = hashlib.sha256(content).hexdigest()
    core._ensure_dir(core.RESOURCES_SKILL_OVERLAYS, core.ROOT_UID, core.ROOT_UID, 0o700)
    core._atomic_replace(core.RESOURCES_SKILL_OVERLAYS / f"{content_sha}.bin",
        content, 0o600, core.ROOT_UID, core.ROOT_UID)
    metadata = {"schema": 1, "skill_id": fixture.skill_id,
                "content_sha256": content_sha, "restore_id": restore_id}
    core._atomic_replace(core.RESOURCES_SKILL_OVERLAYS / f"{restore_id}.json",
        (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        0o600, core.ROOT_UID, core.ROOT_UID)

    def current(*, core_source_generation, _prepared_base):
        assert core_source_generation == fixture.generation
        assert _prepared_base.archive == fixture.base
        return {"resources_state": "discovered"}

    def forbidden_compile():
        raise AssertionError("archive reads must not invoke the Resources compiler")

    monkeypatch.setattr(core, "read_current_resources_discovery", current)
    monkeypatch.setattr(native, "build_manual_jarvis_skills_artifact", forbidden_compile)

    assert core.list_archived_resources_skill_versions(
        fixture.skill_id, fixture.generation) == [{"restore_id": restore_id, "sha256": content_sha}]
    assert core.list_archived_resources_skills(fixture.generation) == [{
        "skill_id": fixture.skill_id,
        "versions": [{"restore_id": restore_id, "sha256": content_sha}],
    }]


@pytest.mark.parametrize("fresh_writer", [False, True])
def test_current_discovery_verifies_installed_tree_without_recompiling(
        overlay_runtime, monkeypatch, fresh_writer):
    fixture = overlay_runtime
    journal = {"schema": 1, "state": "installed", "service": core.SERVICE}
    journal_path = fixture.sandbox / "ownership.json"
    record_path = fixture.record_dir / "resources-discovery.json"
    journal_raw = (json.dumps(journal, sort_keys=True) + "\n").encode()
    core._atomic_replace(journal_path, journal_raw, 0o600, core.ROOT_UID, core.ROOT_UID)
    monkeypatch.setattr(core, "JOURNAL", journal_path)
    monkeypatch.setattr(core, "RESOURCES_RECORD", record_path)
    monkeypatch.setattr(core, "_journal", lambda: journal)
    monkeypatch.setattr(core, "_core_source_generation", lambda: fixture.generation)

    prepared = None if fresh_writer else core._load_resources_base()
    if fresh_writer:
        (fixture.cas / f"{fixture.base_sha}.zip").unlink()
    source_archive = fixture.base if fresh_writer else prepared.archive
    manifest, files = native._read_artifact(source_archive, fixture.base_sha)
    inventory = native._canonical_json([{
        "skill_id": row["skill_id"],
        "sha256": hashlib.sha256(files[row["archive_path"]]).hexdigest(),
    } for row in sorted(manifest["skill_members"], key=lambda item: item["skill_id"])])
    active_prompt = (fixture.home / "SOUL.md").read_bytes()
    monkeypatch.setattr(core, "_root_native_readback", lambda _manifest, _files, prompt, **_kwargs: {
        "active_primary_prompt_sha256": hashlib.sha256(prompt).hexdigest(),
        "bundled_primary_prompt_sha256": hashlib.sha256(
            _files["registry/profiles/hermes/SOUL.md"]).hexdigest(),
        "active_prompt_matches_bundled_primary": prompt == _files[
            "registry/profiles/hermes/SOUL.md"],
        "loaded_skill_inventory_sha256": hashlib.sha256(inventory).hexdigest(),
    })

    if fresh_writer:
        original_compile = native.build_manual_jarvis_skills_artifact
        compile_calls = []

        def counted_compile():
            compile_calls.append("compile")
            return original_compile()

        monkeypatch.setattr(native, "build_manual_jarvis_skills_artifact", counted_compile)
        _PRODUCTION_WRITE_RESOURCES_DISCOVERY()
        assert compile_calls == ["compile"]
    else:
        _PRODUCTION_WRITE_RESOURCES_DISCOVERY(_prepared_base=prepared)

    def forbidden_compile():
        raise AssertionError("current discovery must read the retained base CAS")

    monkeypatch.setattr(native, "build_manual_jarvis_skills_artifact", forbidden_compile)
    result = _PRODUCTION_READ_RESOURCES_DISCOVERY(core_source_generation=fixture.generation)

    assert result["resources_state"] == "discovered"
    assert result["artifact_sha256"] == fixture.base_sha
    assert result["resource_counts"]["native_skills"] == 396


@pytest.mark.parametrize("mutation", ["source", "cas-file", "ancestor"])
def test_current_discovery_rechecks_source_and_cas_before_disclosure(
        overlay_runtime, monkeypatch, mutation):
    fixture = overlay_runtime
    journal = {"schema": 1, "state": "installed", "service": core.SERVICE}
    journal_path = fixture.sandbox / "ownership.json"
    record_path = fixture.record_dir / "resources-discovery.json"
    journal_raw = (json.dumps(journal, sort_keys=True) + "\n").encode()
    core._atomic_replace(journal_path, journal_raw, 0o600, core.ROOT_UID, core.ROOT_UID)
    monkeypatch.setattr(core, "JOURNAL", journal_path)
    monkeypatch.setattr(core, "RESOURCES_RECORD", record_path)
    monkeypatch.setattr(core, "_journal", lambda: journal)
    monkeypatch.setattr(core, "_core_source_generation", lambda: fixture.generation)
    prepared = core._load_resources_base()
    manifest, files = native._read_artifact(prepared.archive, fixture.base_sha)
    inventory = native._canonical_json([{
        "skill_id": row["skill_id"],
        "sha256": hashlib.sha256(files[row["archive_path"]]).hexdigest(),
    } for row in sorted(manifest["skill_members"], key=lambda item: item["skill_id"])])
    original_witness = core._resources_base_source_witness
    changed = {"value": False}

    def root_readback(_manifest, _files, prompt, **_kwargs):
        if mutation == "source":
            changed["value"] = True
        elif mutation == "cas-file":
            core._atomic_replace(fixture.cas / f"{fixture.base_sha}.zip", fixture.base,
                0o600, core.ROOT_UID, core.ROOT_UID)
        else:
            _replace_resources_base_ancestor(fixture)
        return {
            "active_primary_prompt_sha256": hashlib.sha256(prompt).hexdigest(),
            "bundled_primary_prompt_sha256": hashlib.sha256(
                _files["registry/profiles/hermes/SOUL.md"]).hexdigest(),
            "active_prompt_matches_bundled_primary": prompt == _files[
                "registry/profiles/hermes/SOUL.md"],
            "loaded_skill_inventory_sha256": hashlib.sha256(inventory).hexdigest(),
        }

    def source_witness():
        witness = original_witness()
        return witness + (("changed",) if changed["value"] else ())

    monkeypatch.setattr(core, "_resources_base_source_witness", source_witness)
    monkeypatch.setattr(core, "_root_native_readback", root_readback)
    with pytest.raises(core.CoreRuntimeError, match="prepared Resources base changed during use"):
        _PRODUCTION_WRITE_RESOURCES_DISCOVERY(_prepared_base=prepared)
    assert not record_path.exists()


@pytest.mark.parametrize("mutation", ["source", "cas-file", "ancestor"])
def test_current_discovery_read_rechecks_final_base_before_disclosure(
        overlay_runtime, monkeypatch, mutation):
    fixture = overlay_runtime
    journal = {"schema": 1, "state": "installed", "service": core.SERVICE}
    journal_path = fixture.sandbox / "ownership.json"
    core._atomic_replace(journal_path,
        (json.dumps(journal, sort_keys=True) + "\n").encode(),
        0o600, core.ROOT_UID, core.ROOT_UID)
    monkeypatch.setattr(core, "JOURNAL", journal_path)
    monkeypatch.setattr(core, "RESOURCES_RECORD", fixture.record_dir / "resources-discovery.json")
    monkeypatch.setattr(core, "_journal", lambda: journal)
    monkeypatch.setattr(core, "_core_source_generation", lambda: fixture.generation)
    prepared = core._load_resources_base()
    manifest, files = native._read_artifact(prepared.archive, fixture.base_sha)
    inventory = native._canonical_json([{
        "skill_id": row["skill_id"],
        "sha256": hashlib.sha256(files[row["archive_path"]]).hexdigest(),
    } for row in sorted(manifest["skill_members"], key=lambda item: item["skill_id"])])
    monkeypatch.setattr(core, "_root_native_readback",
        lambda _manifest, _files, prompt, **_kwargs: {
            "active_primary_prompt_sha256": hashlib.sha256(prompt).hexdigest(),
            "bundled_primary_prompt_sha256": hashlib.sha256(
                _files["registry/profiles/hermes/SOUL.md"]).hexdigest(),
            "active_prompt_matches_bundled_primary": prompt == _files[
                "registry/profiles/hermes/SOUL.md"],
            "loaded_skill_inventory_sha256": hashlib.sha256(inventory).hexdigest(),
        })
    _PRODUCTION_WRITE_RESOURCES_DISCOVERY(_prepared_base=prepared)

    original_hash_tree = core._hash_generation_tree
    original_witness = core._resources_base_source_witness
    changed = {"value": False}
    source_changed = {"value": False}

    def hash_then_mutate(home, current_manifest, current_files, artifact_sha, **kwargs):
        result = original_hash_tree(home, current_manifest, current_files, artifact_sha, **kwargs)
        if not changed["value"]:
            changed["value"] = True
            if mutation == "source":
                source_changed["value"] = True
            elif mutation == "cas-file":
                core._atomic_replace(fixture.cas / f"{fixture.base_sha}.zip", fixture.base,
                    0o600, core.ROOT_UID, core.ROOT_UID)
            else:
                _replace_resources_base_ancestor(fixture)
        return result

    def source_witness():
        witness = original_witness()
        return witness + (("changed",) if source_changed["value"] else ())

    monkeypatch.setattr(core, "_hash_generation_tree", hash_then_mutate)
    monkeypatch.setattr(core, "_resources_base_source_witness", source_witness)

    def forbidden_compile():
        raise AssertionError("discovery reads must not fall back to the compiler")

    monkeypatch.setattr(native, "build_manual_jarvis_skills_artifact", forbidden_compile)
    result = _PRODUCTION_READ_RESOURCES_DISCOVERY(core_source_generation=fixture.generation)
    assert changed["value"]
    assert result["resources_state"] == "stale"


def test_runtime_resources_base_rejects_each_changed_pinned_input(
        overlay_runtime, monkeypatch):
    original = tuple(core._ROOT_UPDATE_ARTIFACT_EXPECTED_INPUT_SHA256)
    assert len(original) == 19
    for index, (path, _digest) in enumerate(original):
        pins = list(original)
        pins[index] = (path, "0" * 64)
        monkeypatch.setattr(core, "_ROOT_UPDATE_ARTIFACT_EXPECTED_INPUT_SHA256", tuple(pins))
        with pytest.raises(core.CoreRuntimeError, match="source witness differs"):
            core._load_resources_base()
        monkeypatch.setattr(core, "_ROOT_UPDATE_ARTIFACT_EXPECTED_INPUT_SHA256", original)


def test_runtime_resources_base_rejects_unsafe_or_changed_cas(overlay_runtime):
    fixture = overlay_runtime
    path = fixture.cas / f"{fixture.base_sha}.zip"
    link = fixture.cas / "unexpected-link"

    path.chmod(0o640)
    with pytest.raises(core.CoreRuntimeError, match="CAS custody"):
        core._load_resources_base()
    path.chmod(0o600)

    os.link(path, link)
    with pytest.raises(core.CoreRuntimeError, match="CAS custody"):
        core._load_resources_base()
    link.unlink()

    path.write_bytes(fixture.base[:-1] + bytes([fixture.base[-1] ^ 1]))
    path.chmod(0o600)
    with pytest.raises(core.CoreRuntimeError, match="CAS digest"):
        core._load_resources_base()
    core._atomic_replace(path, fixture.base, 0o600, core.ROOT_UID, core.ROOT_UID)

    with path.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    path.chmod(0o600)
    with pytest.raises(core.CoreRuntimeError, match="CAS custody"):
        core._load_resources_base()
    path.unlink()
    target = fixture.cas / "replacement.zip"
    target.write_bytes(fixture.base)
    target.chmod(0o600)
    path.symlink_to(target.name)
    with pytest.raises((core.CoreRuntimeError, OSError)):
        core._load_resources_base()
    path.unlink()
    target.unlink()
    core._atomic_replace(path, fixture.base, 0o600, core.ROOT_UID, core.ROOT_UID)


def test_runtime_resources_base_rejects_sticky_writable_ancestor(overlay_runtime):
    fixture = overlay_runtime
    fixture.sandbox.chmod(0o1777)
    try:
        with pytest.raises(core.CoreRuntimeError, match="ancestry custody"):
            core._load_resources_base()
    finally:
        fixture.sandbox.chmod(0o755)


def test_runtime_resources_base_rechecks_cas_identity_before_return(
        overlay_runtime, monkeypatch):
    fixture = overlay_runtime
    snapshot = core._resources_base_cas_snapshot
    calls = 0

    def replace_after_first_snapshot():
        nonlocal calls
        result = snapshot()
        calls += 1
        if calls == 1:
            core._atomic_replace(fixture.cas / f"{fixture.base_sha}.zip",
                fixture.base, 0o600, core.ROOT_UID, core.ROOT_UID)
        return result

    monkeypatch.setattr(core, "_resources_base_cas_snapshot", replace_after_first_snapshot)
    with pytest.raises(core.CoreRuntimeError, match="changed during verification"):
        core._load_resources_base()
    assert calls == 2


def test_prepared_base_keeps_directory_object_identity_without_rejecting_owned_writes(
        overlay_runtime):
    fixture = overlay_runtime
    prepared = core._load_resources_base()
    sibling = fixture.cas / "owned-composed-or-journal-entry"
    core._atomic_replace(sibling, b"legitimate operation-local artifact",
        0o600, core.ROOT_UID, core.ROOT_UID)
    assert core._check_prepared_resources_base(prepared) is prepared

    before_file_identity = prepared.cas_identity
    _replace_resources_base_ancestor(fixture)
    path = fixture.cas / f"{fixture.base_sha}.zip"
    file_stat = path.stat()
    assert (file_stat.st_dev, file_stat.st_ino, file_stat.st_mode, file_stat.st_uid,
            file_stat.st_gid, file_stat.st_nlink, file_stat.st_size,
            file_stat.st_mtime_ns, file_stat.st_ctime_ns) == before_file_identity
    with pytest.raises(core.CoreRuntimeError, match="changed during use"):
        core._check_prepared_resources_base(prepared)


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
    restored_versions = core.list_archived_resources_skill_versions(
        fixture.skill_id, fixture.generation)
    assert restored["recovery_id"] is None
    assert archived["recovery_id"] in {row["restore_id"] for row in restored_versions}


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
        fixture.set_home_owner(0, 0)
        native.install_manual_jarvis_skills(new_archive, hermes_home=fixture.home,
            expected_sha256=archive_member_sha, replace_owned_from_archive=fixture.base,
            replace_owned_from_sha256=fixture.base_sha)
        fixture.own_generation_as_admin()
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
