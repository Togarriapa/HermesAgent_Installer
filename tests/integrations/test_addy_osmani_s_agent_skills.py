from __future__ import annotations

from dataclasses import replace

import pytest

from hermes_installer.components.addy_osmani_s_agent_skills import (
    AddyAgentSkillsError,
    load_for_task,
)
from tests.fixtures.component_source import verified_component_source


def _source():
    return verified_component_source("addy-osmani-s-agent-skills", {
        "LICENSE": b"MIT fixture\n",
        "skills/security-audit/SKILL.md": (
            b"---\nname: security-audit\ndescription: Audit an input boundary.\n---\n"
            b"Read the [shared checklist](../../references/security-checklist.md).\n"
        ),
        "references/security-checklist.md": b"Use the [API guide](api-guide.md).\n",
        "references/api-guide.md": b"Validate input at the API boundary.\n",
        "skills/other-skill/SKILL.md": b"---\nname: other-skill\ndescription: Other work.\n---\nUnrelated.\n",
        "AGENTS.md": b"Global instruction that must not be concatenated.\n",
        "CLAUDE.md": b"Another host's global instruction.\n",
        "README.md": b"Repository overview, not task context.\n",
    })


def test_selected_skill_loads_recursive_shared_references_only() -> None:
    result = load_for_task(_source(), "security-audit")

    assert result.name == "security-audit"
    assert result.skill_file == "skills/security-audit/SKILL.md"
    assert result.loaded_paths == (
        "skills/security-audit/SKILL.md",
        "references/api-guide.md",
        "references/security-checklist.md",
    )
    assert b"Global instruction" not in result.instructions
    assert b"Another host" not in result.instructions
    assert b"Global instruction" not in b"".join(body for _, body in result.referenced_files)
    assert dict(result.referenced_files)["references/api-guide.md"] == b"Validate input at the API boundary.\n"


def test_task_loader_rejects_wrong_pin_missing_or_ambiguous_skill_and_escape() -> None:
    source = _source()
    with pytest.raises(AddyAgentSkillsError, match="reviewed pin"):
        load_for_task(replace(source, revision="f" * 40), "security-audit")
    with pytest.raises(AddyAgentSkillsError, match="missing or ambiguous"):
        load_for_task(source, "not-present")

    duplicate = replace(source, files=dict(source.files) | {
        "skills/second/security-audit/SKILL.md": (
            b"---\nname: security-audit\ndescription: Duplicate name.\n---\nDuplicate.\n"
        ),
    })
    with pytest.raises(AddyAgentSkillsError, match="missing or ambiguous"):
        load_for_task(duplicate, "security-audit")

    escaped = replace(source, files=dict(source.files) | {
        "skills/security-audit/SKILL.md": (
            b"---\nname: security-audit\ndescription: Unsafe reference.\n---\n"
            b"[outside](../../../outside.md)\n"
        ),
    })
    with pytest.raises(AddyAgentSkillsError, match="reference audit failed"):
        load_for_task(escaped, "security-audit")
