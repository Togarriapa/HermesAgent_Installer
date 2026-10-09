from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from hermes_installer.components.antropic_cybersecurity_skills import (
    ATTRIBUTION,
    EXERCISE_STATUS,
    CybersecuritySkillsError,
    discover_procedures,
    stage_procedures,
)
from hermes_installer.components.skill_refs import audit_skill_file_map
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.state import Journal, OwnedRoot, process_lock
from tests.fixtures.component_source import verified_component_source


def _source():
    return verified_component_source("antropic-cybersecurity-skills", {
        "LICENSE": b"Apache License 2.0 fixture\n",
        "skills/analyzing-fixture/SKILL.md": (
            b"---\nname: analyzing-fixture\ndescription: Analyze a harmless fixture.\n---\n"
            b"Read the supplied sample offline and report observations.\n"
            b"SQL pattern: `([0-9]*)`\n"
            b"```python\nprint('[missing](../../etc/passwd)')\n```\n"
        ),
    })


def test_discovery_labels_third_party_and_keeps_procedures_instruction_only() -> None:
    catalog = discover_procedures(_source())

    assert catalog.procedures == ("analyzing-fixture",)
    assert "Third-party" in catalog.attribution
    assert "not created, owned" in catalog.attribution
    assert "Anthropic-owned" not in catalog.attribution
    assert catalog.exercise_status == EXERCISE_STATUS
    assert catalog.discovery.reference_audit.complete


def test_markdown_code_examples_are_not_treated_as_file_references() -> None:
    example = {
        "skills/procedure/SKILL.md": (
            b"---\nname: procedure\ndescription: Offline procedure.\n---\n"
            b"SQL pattern: `([0-9]*)` and `[View]({cert['crt_sh_url']})`.\n"
            b"```python\nprint('[missing](../../etc/passwd)')\n```\n"
        ),
    }
    audit = audit_skill_file_map(example)
    assert audit.complete

    genuine_missing = {
        "skills/procedure/SKILL.md": (
            b"---\nname: procedure\ndescription: Offline procedure.\n---\n"
            b"Read the [missing reference](references/does-not-exist.md).\n"
        ),
    }
    broken = audit_skill_file_map(genuine_missing)
    assert not broken.complete
    assert broken.problems[0].reason == "referenced file or directory is missing"


def test_install_copies_procedure_without_running_embedded_exercise(tmp_path: Path) -> None:
    source = _source()
    marker = tmp_path / "exercise-ran"
    marker_script = f"#!/bin/sh\nprintf executed > '{marker}'\n".encode()
    source_files = dict(source.files)
    source_files["skills/analyzing-fixture/scripts/exercise.sh"] = marker_script
    source = verified_component_source("antropic-cybersecurity-skills", source_files,
                                       executable=("skills/analyzing-fixture/scripts/exercise.sh",))
    profile_root = tmp_path / "profiles" / "default"
    owned = OwnedRoot(profile_root)
    owned.ensure()
    with process_lock(owned.path("installer.lock")):
        store = GenerationStore(owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True)
        installation = stage_procedures(source, store, profile_id="default", profile_data_root=profile_root)

    assert installation.binding.names == ("analyzing-fixture",)
    assert (installation.binding.external_dir / "skills/analyzing-fixture/SKILL.md").is_file()
    assert (installation.binding.external_dir / "skills/analyzing-fixture/scripts/exercise.sh").is_file()
    assert not marker.exists()
    assert installation.binding.status == "staged_pending_native_discovery"
    assert installation.exercise_status == EXERCISE_STATUS
    assert installation.arm64_status == "unverified"
    assert installation.redistribution_status == "private_source_staging_only; no redistribution authorization asserted"


def test_unreviewed_revision_fails_before_creating_owned_generation(tmp_path: Path) -> None:
    source = replace(_source(), revision="0" * 40)
    profile_root = tmp_path / "profiles" / "default"
    owned = OwnedRoot(profile_root)
    owned.ensure()
    marker = owned.root / "sources"
    with process_lock(owned.path("installer.lock")):
        store = GenerationStore(owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True)
        with pytest.raises(CybersecuritySkillsError, match="reviewed pin"):
            stage_procedures(source, store, profile_id="default", profile_data_root=profile_root)
    assert not marker.exists()
