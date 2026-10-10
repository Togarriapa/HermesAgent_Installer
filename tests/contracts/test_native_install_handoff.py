"""Actual pinned Hermes discovery and selected profile/skill loading."""
from __future__ import annotations

import os
import json
from pathlib import Path

import pytest

from hermes_installer.registry.native_install import (
    NativeInstallError,
    PINNED_HERMES_REVISION,
    discover_and_load_selected,
    selected_profile_materialization,
    discover_and_load_bundle,
)
from hermes_installer.registry.native import NativeRegistry
from hermes_installer.registry.source import BundledRegistrySource, PinnedSource


def test_profile_scoped_materialization_maps_skill_closure_to_hermes_profile_home(tmp_path: Path) -> None:
    generation = tmp_path / "generation"
    ledger = generation / "installer-registry" / "crosswalk.json"
    ledger.parent.mkdir(parents=True)
    ledger.write_text(json.dumps({
        "items": [{"id": "demo", "kind": "profiles"}, {"id": "howto", "kind": "skills"}],
        "native_materialization": {
            "schema": 1,
            "destination_root": "data_root",
            "preserve_existing": True,
            "files": [
                {"staged": "homes/profiles/demo/SOUL.md", "target": "profiles/demo/SOUL.md", "conflict_policy": "preserve-existing"},
                {"staged": "homes/skills/howto/SKILL.md", "target": "skills/howto/SKILL.md", "conflict_policy": "preserve-existing"},
                {"staged": "homes/profiles/unrelated/SOUL.md", "target": "profiles/unrelated/SOUL.md", "conflict_policy": "preserve-existing"},
            ],
        },
    }), encoding="utf-8")
    assert selected_profile_materialization(generation, "demo") == {
        "homes/profiles/demo/SOUL.md": "profiles/demo/SOUL.md",
        "homes/skills/howto/SKILL.md": "profiles/demo/skills/howto/SKILL.md",
    }
    assert selected_profile_materialization(
        generation, "demo", native_profile_key="default",
    ) == {
        "homes/profiles/demo/SOUL.md": "SOUL.md",
        "homes/skills/howto/SKILL.md": "skills/howto/SKILL.md",
    }


def test_selected_profile_and_skill_use_pinned_hermes_apis(tmp_path: Path) -> None:
    """Opt-in because the Hermes PM Python 3.14 environment is target-specific."""
    source = os.environ.get("HERMES_NATIVE_TEST_SOURCE")
    python = os.environ.get("HERMES_NATIVE_TEST_PYTHON")
    if not source or not python:
        pytest.skip("set HERMES_NATIVE_TEST_SOURCE and HERMES_NATIVE_TEST_PYTHON to run pinned Hermes API probe")

    root = tmp_path / "hermes"
    profile = root / "profiles" / "native-fixture"
    skill = profile / "skills" / "selected-fixture"
    skill.mkdir(parents=True)
    (profile / "profile.yaml").write_text("display_name: Native fixture\ndescription: harmless\n", encoding="utf-8")
    (profile / "config.yaml").write_text("{}\n", encoding="utf-8")
    (profile / "SOUL.md").write_text("A harmless native profile fixture.\n", encoding="utf-8")
    (skill / "SKILL.md").write_text(
        "---\nname: selected-fixture\ndescription: Harmless local operation\n---\n"
        "Read the provided synthetic fixture and report its title.\n",
        encoding="utf-8",
    )

    receipt = discover_and_load_selected(
        hermes_source=source,
        python=python,
        hermes_root=root,
        profile_id="native-fixture",
        skill_ids=("selected-fixture",),
    )
    assert receipt.hermes_revision == PINNED_HERMES_REVISION
    assert receipt.python_version.startswith("3.14.")
    assert receipt.discovered_profile and receipt.profile_identity_loaded
    assert receipt.profile_display_name == "Native fixture"
    assert "selected-fixture" in receipt.discovered_skills
    assert receipt.loaded_skills == ("selected-fixture",)
    assert set(receipt.content_digests) == {"profile:native-fixture", "skill:selected-fixture"}


def test_complete_vendored_profiles_and_skills_load_through_pinned_hermes_apis(tmp_path: Path) -> None:
    """Full 208/396 fixture; API calls load each actual generated identity/card."""
    source = os.environ.get("HERMES_NATIVE_TEST_SOURCE")
    python = os.environ.get("HERMES_NATIVE_TEST_PYTHON")
    if not source or not python:
        pytest.skip("set HERMES_NATIVE_TEST_SOURCE and HERMES_NATIVE_TEST_PYTHON for the full native bundle audit")

    bundle = Path(__file__).parents[2] / "src" / "hermes_installer" / "registry" / "bundle_data"
    pin = PinnedSource.from_mapping(json.loads((bundle / "hermes-agent-resources.pin.json").read_text(encoding="utf-8")))
    verified = BundledRegistrySource(pin).load((bundle / "hermes-agent-resources-2.3.1.tar.gz").read_bytes())
    registry = NativeRegistry.from_verified_source(verified)
    discovery = registry.discover_all()
    artifacts = registry.materialize(discovery)
    profile_ids = tuple(sorted(item.resource.id for item in discovery.resources if item.resource.kind.value == "profiles"))
    skill_ids = tuple(sorted(item.resource.id for item in discovery.resources if item.resource.kind.value == "skills"))
    assert len(verified.files) == 739
    assert len(discovery.resources) == 692
    assert len(profile_ids) == 208 and len(set(profile_ids)) == 208
    assert len(skill_ids) == 396 and len(set(skill_ids)) == 396

    root = tmp_path / "hermes"
    for path, content in artifacts.items():
        if path.startswith("homes/profiles/"):
            destination = root / "profiles" / path.removeprefix("homes/profiles/")
        elif path.startswith("homes/skills/"):
            destination = root / "skills" / path.removeprefix("homes/skills/")
        else:
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    receipt = discover_and_load_bundle(
        hermes_source=source,
        python=python,
        hermes_root=root,
        profile_ids=profile_ids,
        skill_ids=skill_ids,
        timeout=300,
    )
    assert receipt.hermes_revision == PINNED_HERMES_REVISION
    assert receipt.python_version.startswith("3.14.")
    assert len(receipt.profiles_discovered) == len(receipt.profiles_loaded) == 208
    assert len(receipt.skills_discovered) == len(receipt.skills_loaded) == 396
    assert receipt.profile_aliases == {
        name: ("Jarvis" if name == "hermes"
               else name.replace("-", " ").replace("_", " ").title())
        for name in profile_ids
    }
    assert len(receipt.profile_digests) == 208
    assert len(receipt.skill_digests) == 396


def test_primary_jarvis_is_the_only_pinned_default_home_profile(tmp_path: Path) -> None:
    """Exercise real profile.list display metadata and sole-default guard at pinned Hermes."""
    source = os.environ.get("HERMES_NATIVE_TEST_SOURCE")
    python = os.environ.get("HERMES_NATIVE_TEST_PYTHON")
    if not source or not python:
        pytest.skip("set HERMES_NATIVE_TEST_SOURCE and HERMES_NATIVE_TEST_PYTHON to run the pinned primary profile probe")

    bundle = Path(__file__).parents[2] / "src" / "hermes_installer" / "registry" / "bundle_data"
    pin = PinnedSource.from_mapping(json.loads(
        (bundle / "hermes-agent-resources.pin.json").read_text(encoding="utf-8")))
    verified = BundledRegistrySource(pin).load(
        (bundle / "hermes-agent-resources-2.3.1.tar.gz").read_bytes())
    registry = NativeRegistry.from_verified_source(verified)
    discovery = registry.discover(["profiles/hermes@*"])
    compiled = registry.materialize(discovery)
    from hermes_installer.authority.native_materialization import _selected_files
    selected = _selected_files(compiled, "hermes", native_profile_key="default")
    root = tmp_path / "hermes"
    root.mkdir()
    for relative, content in selected.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    skill_ids = tuple(sorted(
        relative.removeprefix("skills/").removesuffix("/SKILL.md")
        for relative in selected if relative.startswith("skills/")
    ))

    receipt = discover_and_load_selected(
        hermes_source=source,
        python=python,
        hermes_root=root,
        profile_id="default",
        skill_ids=skill_ids,
        require_sole_profile=True,
    )
    assert receipt.hermes_revision == PINNED_HERMES_REVISION
    assert receipt.profile_id == "default"
    assert receipt.profile_display_name == "Jarvis"
    assert receipt.profile_identity_loaded


@pytest.mark.parametrize("profile_id", ["", "../escape", "Uppercase", "a" * 65, "a" * 97])
def test_rejects_invalid_profile_before_runtime_access(profile_id: str) -> None:
    with pytest.raises(NativeInstallError, match="profile id is malformed"):
        discover_and_load_selected(
            hermes_source="/does/not/exist",
            python="/does/not/exist/python",
            hermes_root="/does/not/exist/home",
            profile_id=profile_id,
            skill_ids=(),
        )


def test_rejects_duplicate_skills_before_runtime_access() -> None:
    with pytest.raises(NativeInstallError, match="duplicates"):
        discover_and_load_selected(
            hermes_source="/does/not/exist",
            python="/does/not/exist/python",
            hermes_root="/does/not/exist/home",
            profile_id="demo",
            skill_ids=("demo-skill", "demo-skill"),
        )
