from __future__ import annotations

import pytest

from hermes_installer.components.emil_kowalski_impeccable import (
    SOURCE_IDENTITY,
    SOURCE_REVISION,
    emil_kowalski_skill_pack_offer,
    invoke_impeccable_skill,
    linux_arm64_engine_asset_state,
    native_design_hook_state,
)
from hermes_installer.components.portable_skill_adapters import PortableSkillError
from hermes_installer.components.portable_skill_adapters import route_skill
from portable_skill_fixtures import pinned_fixture


def test_impeccable_skill_route_keeps_pbakaus_attribution_and_has_fixture_effect():
    source = pinned_fixture("emil-kowalski-impeccable", {
        ".hermes/skills/impeccable/SKILL.md": (
            b"---\nname: impeccable\ndescription: Design review skill fixture.\n---\n"
            b"Inspect the selected screen and recommend one concrete hierarchy change.\n"
        ),
    })
    route = invoke_impeccable_skill(source, "Review the synthetic account panel.")
    assert (source.source_identity, source.revision) == (SOURCE_IDENTITY, SOURCE_REVISION)
    assert route.command == "/impeccable"
    assert "one concrete hierarchy change" in route.skill.body
    state = native_design_hook_state(source)
    assert state.status == "unavailable"
    assert "native design hook" in state.reason
    engine = linux_arm64_engine_asset_state(pinned_fixture("emil-kowalski-impeccable", {
        ".hermes/skills/impeccable/SKILL.md": b"---\nname: impeccable\n---\nFixture.\n",
        "cli/platform-packages/linux-arm64/package.json": (
            b'{"name":"@impeccable/cli-linux-arm64","os":["linux"],'
            b'"cpu":["arm64"],"bin":{"impeccable-linux-arm64":"bin/impeccable"}}'
        ),
    }))
    assert engine.status == "pending-runtime"
    assert "separate npm optional package" in engine.reason
    with pytest.raises(PortableSkillError, match="different component"):
        route_skill("humanizer", route.skill, "wrong route")


def test_emil_kowalski_pack_remains_a_separate_optional_source():
    identity, revision, url = emil_kowalski_skill_pack_offer()
    assert identity == "emilkowalski/skills"
    assert revision == "e8a175de22ae1e49370fc144c1f3bb9aeedf988d"
    assert url == "https://github.com/emilkowalski/skills"
    assert identity != SOURCE_IDENTITY
