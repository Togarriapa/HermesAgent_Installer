"""Interrupted initial-primary stage checks against the Root cohort journal."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from hermes_installer import core_runtime as core
from hermes_installer import primary_prompt_manager as primary
from hermes_installer.registry import manual_jarvis_skills
from hermes_installer.registry.primary_prompt import append_managed_block, render_managed_block

# Reuse the fixture that writes a real, schema-validated source-starting Root
# cohort and its journal/resource/unit/launcher/backup projections.
from test_core_runtime import _adapter_cohort_starting_fixture


def _refresh_exact_starting_unit_recipe(cohort):
    """Rebuild the fixture's current starting tuple from the generated guarded recipe."""
    unit = core._unit(
        adapter_source=Path(cohort["new_source"]),
        cohort_gate=True,
        backup_generation=cohort["old_adapter_generation"],
    )
    core._atomic_replace(core.UNIT, unit, 0o644, core.ROOT_UID, core.ROOT_UID)

    journal_raw = core._projection_file(
        core.JOURNAL, owner=core.ROOT_UID, group=core.ROOT_UID, mode=0o600,
        maximum=64 * 1024)
    journal = json.loads(journal_raw)
    journal["unit_sha256"] = hashlib.sha256(unit).hexdigest()
    core._replace_journal(journal, expected_raw=journal_raw)
    journal_raw = core._projection_file(
        core.JOURNAL, owner=core.ROOT_UID, group=core.ROOT_UID, mode=0o600,
        maximum=64 * 1024)

    resources_raw = core._projection_file(
        core.RESOURCES_RECORD, owner=core.ROOT_UID, group=core.ROOT_UID, mode=0o600,
        maximum=16 * 1024)
    resources = json.loads(resources_raw)
    resources["core_ownership_sha256"] = hashlib.sha256(journal_raw).hexdigest()
    resources_raw = core._canonical_json(resources)
    core._atomic_replace(core.RESOURCES_RECORD, resources_raw, 0o600,
                         core.ROOT_UID, core.ROOT_UID)

    current, cohort_raw = core._read_adapter_update_cohort()
    current["new_unit_sha256"] = hashlib.sha256(unit).hexdigest()
    current["new_source_recipe_sha256"] = core._adapter_recipe_sha256(
        current["new_source"], current["new_adapter_generation"],
        current["new_unit_sha256"], current["new_launcher_sha256"])
    reconstruction = dict(current["reconstruction"])
    reconstruction["new_source_recipe_sha256"] = current["new_source_recipe_sha256"]
    reconstruction["new_discovery_sha256"] = hashlib.sha256(resources_raw).hexdigest()
    current["reconstruction"] = reconstruction
    current["reconstruction_sha256"] = hashlib.sha256(
        core._canonical_json(reconstruction)).hexdigest()
    current["starting_journal_sha256"] = hashlib.sha256(journal_raw).hexdigest()
    current["starting_resources_record_sha256"] = hashlib.sha256(resources_raw).hexdigest()
    core._write_adapter_update_cohort(current, expected_raw=cohort_raw)
    return current


@pytest.mark.skipif(os.geteuid() != 0, reason="Root initial-primary journal fixture requires Pi root")
def test_interrupted_preparing_stage_is_retained_and_refuses_owner_soul_drift(
        tmp_path, monkeypatch, request):
    _unit, cohort, _journal_raw, _resources_raw = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request)
    cohort = _refresh_exact_starting_unit_recipe(cohort)

    runtime = tmp_path / "primary-runtime"
    owner_home = tmp_path / "admin" / ".hermes"
    primary_backups = runtime / "primary-backups"
    primary_journal = runtime / "primary-prompt-ownership.json"
    for directory in (runtime, owner_home, primary_backups):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)

    monkeypatch.setattr(core, "HERMES_HOME", owner_home)
    monkeypatch.setattr(core, "PRIMARY_PROMPT_JOURNAL", primary_journal)
    monkeypatch.setattr(core, "PRIMARY_PROMPT_BACKUPS", primary_backups)
    monkeypatch.setattr(primary, "HOME_UID", 1000)
    monkeypatch.setattr(primary, "HOME_GID", 1000)
    monkeypatch.setattr(primary, "_open_home", lambda _core: os.open(
        owner_home, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)))

    prefix = b"# Owner context\nPreserve this exact prefix.\n"
    soul = owner_home / "SOUL.md"
    soul.write_bytes(prefix)
    soul.chmod(0o600)
    os.chown(soul, 1000, 1000)
    signature = primary._signature(soul.stat())

    archive = manual_jarvis_skills.build_manual_jarvis_skills_artifact()
    manifest, files = manual_jarvis_skills._read_artifact(archive, hashlib.sha256(archive).hexdigest())
    source_prompt = files["registry/profiles/hermes/SOUL.md"]
    block = render_managed_block(source_prompt)
    desired, separator = append_managed_block(prefix, block)
    resources_before = core.RESOURCES_RECORD.read_bytes()
    transition = {
        "schema": 1,
        "purpose": "initial-primary-adoption",
        "state": "pending",
        "prior_record_state": "absent",
        "prior_soul_sha256": hashlib.sha256(prefix).hexdigest(),
        "prior_soul_signature": signature,
        "source_prompt_sha256": hashlib.sha256(source_prompt).hexdigest(),
        "managed_block_sha256": hashlib.sha256(block).hexdigest(),
        "desired_soul_sha256": hashlib.sha256(desired).hexdigest(),
        "owner_separator_hex": separator.hex(),
        "owner_backup_sha256": None,
        "preparing_record_sha256": None,
        "writing_record_sha256": None,
        "adopted_record_sha256": None,
        "before_resources_record_sha256": hashlib.sha256(resources_before).hexdigest(),
        "after_resources_record_sha256": None,
    }
    cohort["initial_primary_transition"] = transition
    cohort_raw = core._write_adapter_update_cohort(
        cohort, expected_raw=core._projection_file(
            core.ADAPTER_UPDATE_COHORT, owner=0, group=0, mode=0o400, maximum=128 * 1024))

    # Exercise the fixed manager's real durable "preparing" journal and backup
    # writes, then stop before Root records that exact stage: this is the crash
    # window the cohort recovery validator must reconcile.
    discovery = {"resources_revision": manifest["source"]["revision"]}
    record = primary._new_record(
        cohort["new_core_source_generation"], discovery, cohort["new_artifact_sha256"],
        manifest["source"]["git_tree"], source_prompt, block, prefix, signature,
        prefix, separator)
    primary._write_record(core, record)
    primary._backup_bytes(core, record, prefix)
    stage_raw = primary_journal.read_bytes()
    retained_digest = core._retain_initial_primary_stage(cohort["cohort_transaction_id"], stage_raw)
    retained_stage = (core.ADAPTER_UPDATE_BACKUPS
                      / ("initial-primary-" + cohort["cohort_transaction_id"])
                      / (retained_digest + ".json"))

    transition["state"] = "preparing"
    cohort["initial_primary_transition"] = transition
    preparing_cohort_raw = core._write_adapter_update_cohort(cohort, expected_raw=cohort_raw)
    current_cohort, current_raw = core._read_adapter_update_cohort()
    assert current_raw == preparing_cohort_raw
    assert primary._read_record(core)["state"] == "preparing"
    assert primary._backup_read(core, record) == prefix
    assert stat.S_IMODE(retained_stage.stat().st_mode) == 0o400
    assert retained_stage.read_bytes() == stage_raw

    backup_dir = core.ADAPTER_UPDATE_BACKUPS / cohort["old_adapter_generation"]
    contents = {name: (backup_dir / name).read_bytes()
                for name in core._ADAPTER_UPDATE_BACKUP_MEMBERS}
    # The old cohort predates this initial-primary record and an absent owner
    # binding; all other backup bytes remain the actual immutable fixture.
    contents["primary-record.json"] = b""
    contents["overlay-record.json"] = b""
    contents["obsidian-registration.json"] = b""
    prior = {"adapter_source": cohort["old_source"]}
    core._check_adapter_cohort_rollback_currentness(current_cohort, prior, contents)

    before_journal = primary_journal.read_bytes()
    before_cohort = core.ADAPTER_UPDATE_COHORT.read_bytes()
    before_backup = retained_stage.read_bytes()
    soul.write_bytes(b"# Owner edited during interrupted Core update\n")
    soul.chmod(0o600)
    os.chown(soul, 1000, 1000)
    with pytest.raises(core.CoreRuntimeError, match="initial primary stage or owner SOUL changed"):
        core._check_adapter_cohort_rollback_currentness(current_cohort, prior, contents)

    assert primary_journal.read_bytes() == before_journal
    assert core.ADAPTER_UPDATE_COHORT.read_bytes() == before_cohort
    assert retained_stage.read_bytes() == before_backup
    assert soul.read_bytes() == b"# Owner edited during interrupted Core update\n"

    # Both public consumers reject absent/unissued custody before changing any
    # of the persisted interrupted-stage evidence.
    with pytest.raises(primary.PrimaryPromptAdoptionError, match="sealed starting-cohort"):
        primary.adopt_primary_prompt_for_starting_cohort(None)
    with pytest.raises(core.CoreRuntimeError, match="initial primary manager stage"):
        core.record_initial_primary_manager_stage(None)
    assert primary_journal.read_bytes() == before_journal
    assert core.ADAPTER_UPDATE_COHORT.read_bytes() == before_cohort
    assert retained_stage.read_bytes() == before_backup
