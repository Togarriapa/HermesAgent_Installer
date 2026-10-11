import hashlib
from pathlib import Path

import pytest

from hermes_installer.components.resources_active_profile_source import (
    PROFILE_ID,
    _load_profile_manifest,
    _source_members,
)


def _pinned_orchestrator_yaml():
    path = (Path(__file__).parents[2] / "resources" / "vendor"
            / "hermes-agent-resources-2.3.1" / "profiles" / "orchestrator.yaml")
    return path.read_bytes()


def test_source_profile_keeps_internal_restrictions_and_does_not_invent_tool_grants():
    profile = _load_profile_manifest(_pinned_orchestrator_yaml())

    assert profile["required_skill_ids"]
    assert profile["required_plugin_ids"] == ("epic-kanban",)
    # `requires.skills` and `requires.plugins` are source dependencies, not
    # executable permissions. The YAML has no explicit tool-grant field.
    assert profile["profile_tool_names"] == ()
    assert len(profile["interaction_policy_sha256"]) == 64


def test_member_rows_bind_both_exact_profile_files_and_reject_mutation():
    prompt = b"selected orchestrator prompt\n"
    manifest = b"kind: Profile\nmetadata:\n  name: orchestrator\n"
    row = {
        "source_id": PROFILE_ID,
        "identity_sha256": hashlib.sha256(prompt).hexdigest(),
        "profile_yaml_sha256": hashlib.sha256(manifest).hexdigest(),
    }

    members = _source_members(row, prompt, manifest)
    assert [member.path for member in members] == [
        "registry/profiles/orchestrator/SOUL.md",
        "registry/profiles/orchestrator/profile.yaml",
    ]
    assert [member.size for member in members] == [len(prompt), len(manifest)]
    assert _source_members(row, prompt + b"changed", manifest) == ()


def test_source_manifest_rejects_changed_privacy_interaction_policy():
    payload = _pinned_orchestrator_yaml().replace(
        b"directUserContact: deny", b"directUserContact: allow", 1
    )

    with pytest.raises(ValueError, match="interaction policy"):
        _load_profile_manifest(payload)
