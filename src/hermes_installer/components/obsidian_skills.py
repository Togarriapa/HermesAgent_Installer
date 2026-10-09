"""Safe local Markdown and JSON Canvas fixtures for Obsidian skill users."""
from __future__ import annotations

import shutil
from pathlib import Path

from hermes_installer.components.portable_skill_adapters import (
    CapabilityState,
    ApprovedVault,
    PortableSkillError,
    PortableSkill,
    bind_selected_profile_vault,
    safe_vault_write,
    select_portable_skill,
    unavailable_capability,
    validate_canvas_document,
)
from hermes_installer.components.source_bundle import VerifiedComponentSource


SOURCE_IDENTITY = "kepano/obsidian-skills"
SOURCE_REVISION = "3ccff5338ea700537839b21900aa5358a0402c98"
COMPONENT_ID = "obsidian-skills"


def select_obsidian_skill(source: VerifiedComponentSource, name: str) -> PortableSkill:
    return select_portable_skill(COMPONENT_ID, source, name)


def write_markdown_note(vault: ApprovedVault, relative_path: str, content: str) -> Path:
    if not relative_path.casefold().endswith(".md"):
        raise PortableSkillError("Obsidian markdown output must use the .md extension")
    if not isinstance(content, str) or not content.strip():
        raise PortableSkillError("Obsidian markdown content must contain text")
    encoded = content.encode("utf-8")
    if len(encoded) > 1_048_576:
        raise PortableSkillError("Obsidian markdown fixture exceeds the 1 MiB limit")
    return safe_vault_write(vault, relative_path, encoded)


def write_canvas(vault: ApprovedVault, relative_path: str, content: str) -> Path:
    if not relative_path.casefold().endswith(".canvas"):
        raise PortableSkillError("JSON Canvas output must use the .canvas extension")
    if len(content.encode("utf-8")) > 1_048_576:
        raise PortableSkillError("JSON Canvas fixture exceeds the 1 MiB limit")
    validate_canvas_document(content)
    return safe_vault_write(vault, relative_path, content.encode("utf-8"))


def obsidian_cli_state(executable: str = "obsidian") -> CapabilityState:
    """Report optional desktop CLI separately from portable file-format support."""
    resolved = shutil.which(executable)
    if resolved is None:
        return unavailable_capability(
            "Obsidian CLI is not installed or enrolled; Markdown and JSON Canvas file support remains available"
        )
    return CapabilityState("available-unverified", f"CLI executable found at {resolved}; vault operation not tested")
