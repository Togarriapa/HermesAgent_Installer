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
)


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
    assert receipt.discovered_profile and receipt.profile_identity_loaded
    assert "selected-fixture" in receipt.discovered_skills
    assert receipt.loaded_skills == ("selected-fixture",)
    assert set(receipt.content_digests) == {"profile:native-fixture", "skill:selected-fixture"}


@pytest.mark.parametrize("profile_id", ["", "../escape", "Uppercase", "a" * 97])
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
