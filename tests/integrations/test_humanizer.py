from __future__ import annotations

import pytest

from hermes_installer.components.humanizer import SOURCE_REVISION, invoke_humanizer_procedure
from hermes_installer.components.portable_skill_adapters import PortableSkillError
from portable_skill_fixtures import pinned_fixture


def test_humanizer_exposes_the_declared_local_procedure_without_a_service():
    source = pinned_fixture("humanizer", {
        "SKILL.md": (
            b"---\nname: humanizer\ndescription: Rewrite prose while preserving claims.\n---\n"
            b"Mark tells, draft a rewrite, check claims, then write the final version.\n"
        ),
    })
    route = invoke_humanizer_procedure(source, "Our release is ready for review.")
    assert route.command == "/humanizer"
    assert route.skill.revision == SOURCE_REVISION
    assert "check claims" in route.skill.body
    assert route.request_text == "Our release is ready for review."
    with pytest.raises(PortableSkillError, match="input"):
        invoke_humanizer_procedure(source, " ")
