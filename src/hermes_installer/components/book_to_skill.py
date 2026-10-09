"""Status for the selected book-to-skill source and its two-stage workflow."""
from __future__ import annotations

from dataclasses import dataclass

from hermes_installer.components.adapters import resolve_component_adapter


@dataclass(frozen=True, slots=True)
class BookToSkillStatus:
    component_id: str
    source_identity: str
    revision: str
    source_selection: str
    source_skill_status: str
    local_extraction_status: str
    generation_status: str
    profile_activation_status: str
    reason: str


def book_to_skill_status() -> BookToSkillStatus:
    """Keep the star-selected source and agent-mediated generation distinct."""
    source = resolve_component_adapter("book-to-skill")
    if (source.source_identity != "virgiliojr94/book-to-skill"
            or source.revision != "e180fc46365e8c1aab0120778cc8a40b9515324b"):
        raise RuntimeError("book-to-skill source contract differs from the reviewed selection")
    return BookToSkillStatus(
        component_id=source.component_id,
        source_identity=source.source_identity,
        revision=source.revision,
        source_selection=source.source_selection,
        source_skill_status="pinned source contains a Hermes-discoverable SKILL.md",
        local_extraction_status="fixture verified; managed isolated runtime pending",
        generation_status="pending: the pinned source delegates generation to the agent workflow",
        profile_activation_status="pending profile-scoped import",
        reason=("the installer has no supported boundary to invoke the agent generation "
                "workflow or its model; configure extraction dependencies in an isolated "
                "on-demand runtime before enabling local extraction"),
    )
