from __future__ import annotations

import pytest
from dataclasses import replace

from hermes_installer.components.portable_skill_adapters import PortableSkillError
from hermes_installer.components.taste_skill import SOURCE_REVISION, select_design_style
from portable_skill_fixtures import pinned_fixture


def test_style_selection_returns_only_the_requested_skill_and_its_references():
    source = pinned_fixture("taste-skill", {
        "skills/minimalist/SKILL.md": (
            b"---\nname: warm-minimal\ndescription: Minimal style fixture.\n---\n"
            b"Use a warm neutral palette. See [rules](rules.md).\n"
        ),
        "skills/minimalist/rules.md": b"Keep the layout open and the copy plain.\n",
        "skills/brutalist/SKILL.md": (
            b"---\nname: hard-brutalism\ndescription: Brutalist style fixture.\n---\n"
            b"Use a dense grid and hard red accents.\n"
        ),
    })
    selected = select_design_style(source, "warm-minimal")
    assert selected.revision == SOURCE_REVISION
    assert selected.name == "warm-minimal"
    assert "warm neutral palette" in selected.body
    assert "hard red accents" not in selected.body
    assert selected.references == ("skills/minimalist/rules.md",)


def test_style_selection_fails_closed_for_missing_or_wrong_revision():
    source = pinned_fixture("taste-skill", {
        "skills/minimalist/SKILL.md": b"---\nname: warm-minimal\n---\nWarm.\n",
    })
    with pytest.raises(PortableSkillError, match="missing or ambiguous"):
        select_design_style(source, "unselected-style")
    with pytest.raises(PortableSkillError, match="immutable revision"):
        select_design_style(replace(source, revision="0" * 40), "warm-minimal")
