from __future__ import annotations

import json

import pytest

from hermes_installer.components.obsidian_skills import (
    SOURCE_REVISION,
    bind_selected_profile_vault,
    obsidian_cli_state,
    select_obsidian_skill,
    write_canvas,
    write_markdown_note,
)
from hermes_installer.components.portable_skill_adapters import PortableSkillError
from portable_skill_fixtures import pinned_fixture


def test_markdown_and_canvas_effects_stay_inside_the_approved_fixture_vault(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir(mode=0o700)
    approved_vault = bind_selected_profile_vault(lambda: vault)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    source = pinned_fixture("obsidian-skills", {
        "skills/obsidian-markdown/SKILL.md": (
            b"---\nname: obsidian-markdown\ndescription: Create valid vault notes.\n---\n"
            b"Use [[wikilinks]] and [text](url) for external URLs.\n"
        ),
        "skills/obsidian-markdown/references/PROPERTIES.md": b"Properties are YAML frontmatter.\n",
        "skills/json-canvas/SKILL.md": (
            b"---\nname: json-canvas\ndescription: Create JSON Canvas files.\n---\n"
            b"Canvas documents contain node and edge arrays.\n"
        ),
    })
    selected = select_obsidian_skill(source, "json-canvas")
    assert selected.revision == SOURCE_REVISION
    assert "node and edge arrays" in selected.body
    assert "wikilinks" not in selected.body

    note = write_markdown_note(approved_vault, "Projects/fixture.md", "---\ntags: [fixture]\n---\nA [[local note]].\n")
    canvas_content = json.dumps({
        "nodes": [
            {"id": "a", "type": "text", "text": "Start", "x": 0, "y": 0, "width": 180, "height": 80},
            {"id": "b", "type": "text", "text": "Done", "x": 220, "y": 0, "width": 180, "height": 80},
        ],
        "edges": [{"id": "edge-a-b", "fromNode": "a", "toNode": "b"}],
    })
    canvas = write_canvas(approved_vault, "Projects/fixture.canvas", canvas_content)
    assert note.read_text().endswith("A [[local note]].\n")
    assert json.loads(canvas.read_text()) == json.loads(canvas_content)
    assert note.resolve().is_relative_to(vault.resolve())
    assert canvas.resolve().is_relative_to(vault.resolve())

    (vault / "outside-link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(PortableSkillError, match="symlink"):
        write_markdown_note(approved_vault, "outside-link/escape.md", "denied")
    with pytest.raises(PortableSkillError, match="normalized relative"):
        write_markdown_note(approved_vault, "../outside/escape.md", "denied")
    assert not (outside / "escape.md").exists()


def test_invalid_canvas_and_missing_optional_cli_are_reported(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    approved_vault = bind_selected_profile_vault(lambda: vault)
    with pytest.raises(PortableSkillError, match="unknown node"):
        write_canvas(approved_vault, "bad.canvas", json.dumps({
            "nodes": [{"id": "a", "x": 0, "y": 0, "width": 1, "height": 1}],
            "edges": [{"fromNode": "a", "toNode": "missing"}],
        }))
    state = obsidian_cli_state("hermes-no-obsidian-fixture-cli")
    assert state.status == "unavailable"
    assert "file support remains available" in state.reason
