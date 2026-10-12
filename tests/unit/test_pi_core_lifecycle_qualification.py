"""Pure result-classification contracts for the Pi-only Core adapter runner.

These fixtures verify the runner's evidence gate only; they do not represent a
live source update, protected backup, native process, or Pi acceptance result.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest


TOOL = Path(__file__).resolve().parents[2] / "tools" / "pi_core_lifecycle_qualification.py"
SPEC = importlib.util.spec_from_file_location("pi_core_lifecycle_qualification", TOOL)
assert SPEC is not None and SPEC.loader is not None
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)


def _snapshots():
    before = {
        "adapter_source": "/opt/hermes-installer-core-aaaaaaaaa/src",
        "adapter_generation": "a" * 64,
        "core_source_generation": "b" * 64,
        "plugin_selection_sha256": "c" * 64,
        "overlay_content_count": 2,
        "overlay_contents_sha256": "d" * 64,
        "obsidian_registration_state": "registered",
        "obsidian_registration_sha256": "e" * 64,
        "obsidian_vault_tree_sha256": "f" * 64,
    }
    after = {
        **before,
        "adapter_source": "/opt/hermes-installer-core-bbbbbbbbb/src",
        "adapter_generation": "9" * 64,
        "adapter_update_state": "active",
        "adapter_update_previous_source": before["adapter_source"],
        "adapter_update_backup_source_generation": before["adapter_generation"],
    }
    return before, after


def test_candidate_identity_requires_full_lowercase_commit_sha():
    assert qualification._candidate_source("a" * 40) == Path(
        "/opt/hermes-installer-core-aaaaaaaaa/src")
    for invalid in ("a" * 39, "A" * 40, "../" + "a" * 37, "a" * 40 + "b"):
        with pytest.raises(ValueError, match="full lowercase SHA"):
            qualification._candidate_source(invalid)


def test_only_current_candidate_commit_and_preserved_bindings_qualify():
    before, after = _snapshots()
    checks = qualification._success_checks(
        before, after, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase="committed", listener_current=True)
    assert checks and all(checks.values())

    changed = dict(after, plugin_selection_sha256="0" * 64)
    checks = qualification._success_checks(
        before, changed, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase="committed", listener_current=True)
    assert checks["candidate_adapter_is_active"] is True
    assert checks["selected_plugin_preserved"] is False


@pytest.mark.parametrize("mutation,phase,listener", [
    ({"adapter_source": "/opt/hermes-installer-core-ccccccccc/src"}, "committed", True),
    ({"overlay_contents_sha256": "0" * 64}, "committed", True),
    ({"obsidian_vault_tree_sha256": "0" * 64}, "committed", True),
    ({}, "bindings-verified", True),
    ({}, "committed", False),
])
def test_partial_or_mismatched_update_readback_stays_pending(mutation, phase, listener):
    before, after = _snapshots()
    after.update(mutation)
    checks = qualification._success_checks(
        before, after, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase=phase, listener_current=listener)
    assert any(value is False for value in checks.values())


def _backup_fixture():
    journal = b'{"adapter_generation":"' + b"a" * 64 + b'"}'
    raw = {
        "journal": journal,
        "unit": b"prior-unit-bytes",
        "launcher": b"prior-launcher-bytes",
        "resources_record": b"prior-resources-binding",
        "overlay_record": b"prior-overlay-binding",
        "primary_record": b"prior-primary-record",
        "obsidian_registration": b"prior-obsidian-registration",
        "prior_cohort": b"prior-cohort",
        "plugin_selection_sha256": "c" * 64,
        "token_sha256": "d" * 64,
        "primary": {"state": "adopted", "owner_prefix": b"owner bytes",
                    "backup": b"owner bytes"},
    }
    contents = {
        "journal.json": raw["journal"], "unit": raw["unit"],
        "launcher": raw["launcher"], "resources-record.json": raw["resources_record"],
        "overlay-record.json": raw["overlay_record"],
        "primary-record.json": raw["primary_record"],
        "obsidian-registration.json": raw["obsidian_registration"],
        "cohort.json": raw["prior_cohort"],
        "plugin-selection.json": b'{"schema":1,"selection_sha256":"' + b"c" * 64 + b'"}',
    }
    after_journal = b'{"adapter_update_backup":{"path":"fixed","source_generation":"' + b"a" * 64 + b'"}}'
    after = {"journal": after_journal, "token_sha256": raw["token_sha256"],
             "primary": {"state": "adopted", "owner_prefix": b"owner bytes",
                         "backup": b"owner bytes"}}
    prior = {"adapter_generation": "a" * 64}

    class Runtime:
        @staticmethod
        def _read_adapter_update_backup(reference):
            assert reference == {"path": "fixed", "source_generation": "a" * 64}
            return prior, contents

    return Runtime(), raw, after, contents


def test_protected_backup_requires_exact_old_journal_unit_launcher_and_bindings():
    runtime, before, after, _contents = _backup_fixture()
    assert qualification._backup_matches_before(runtime, before, after) is True


@pytest.mark.parametrize("field", [
    "unit", "launcher", "resources_record", "overlay_record", "primary_record",
    "obsidian_registration", "prior_cohort",
])
def test_protected_backup_byte_change_is_not_a_generation_name_match(field):
    runtime, before, after, contents = _backup_fixture()
    filename = {
        "unit": "unit", "launcher": "launcher", "resources_record": "resources-record.json",
        "overlay_record": "overlay-record.json", "primary_record": "primary-record.json",
        "obsidian_registration": "obsidian-registration.json", "prior_cohort": "cohort.json",
    }[field]
    contents[filename] += b" altered"
    assert qualification._backup_matches_before(runtime, before, after) is False


def test_update_proof_rejects_changed_token_and_primary_owner_prefix_or_backup():
    runtime, before, after, _contents = _backup_fixture()
    after["token_sha256"] = "e" * 64
    assert qualification._backup_matches_before(runtime, before, after) is False
    after["token_sha256"] = before["token_sha256"]
    after["primary"]["owner_prefix"] = b"altered owner bytes"
    assert qualification._backup_matches_before(runtime, before, after) is False
    after["primary"]["owner_prefix"] = before["primary"]["owner_prefix"]
    after["primary"]["backup"] = b"altered immutable backup"
    assert qualification._backup_matches_before(runtime, before, after) is False


def test_update_proof_allows_only_exact_initial_primary_append():
    runtime, before, after, _contents = _backup_fixture()
    initial = b"original owner SOUL\n"
    separator = b"\n"
    managed = b"<verified managed block>"
    before["primary"] = {"state": "unmanaged", "soul": initial}
    after["primary"] = {
        "state": "adopted", "owner_prefix": initial, "backup": initial,
        "separator": separator, "managed_block": managed,
        "soul": initial + separator + managed,
        "record": {"state": "adopted", "owner_prefix_length": len(initial)},
    }
    assert qualification._backup_matches_before(runtime, before, after) is True
    after["primary"]["soul"] = initial + b"unexpected bytes"
    assert qualification._backup_matches_before(runtime, before, after) is False


@pytest.mark.skipif(os.geteuid() != 0, reason="staged helper custody fixture requires root")
def test_held_helper_is_custody_checked_and_read_without_execution(tmp_path):
    generation = tmp_path / "generation"
    tools = generation / "tools"
    tools.mkdir(parents=True, mode=0o755)
    marker = tmp_path / "unexpected-import-effect"
    helper = tools / "pi_native_core_adopt.py"
    helper.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    helper.chmod(0o644)
    generation.chmod(0o755)
    generation_fd = os.open(generation, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        source, held_fds = qualification._read_held_helper(generation_fd)
        try:
            assert b"unexpected-import-effect" in source
            assert not marker.exists()
        finally:
            for fd in reversed(held_fds):
                os.close(fd)
        tools.chmod(0o777)
        with pytest.raises(RuntimeError, match="ancestor custody"):
            qualification._read_held_helper(generation_fd)
        assert not marker.exists()
    finally:
        os.close(generation_fd)
