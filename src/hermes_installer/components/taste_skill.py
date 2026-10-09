"""Selectable, task-scoped styles from the pinned Taste Skill pack."""
from __future__ import annotations

from hermes_installer.components.portable_skill_adapters import (
    PortableSkill,
    select_portable_skill,
)
from hermes_installer.components.source_bundle import VerifiedComponentSource


SOURCE_IDENTITY = "Leonxlnx/taste-skill"
SOURCE_REVISION = "18dfc928b135629e0eddfdd445a06400d04ed439"
COMPONENT_ID = "taste-skill"


def select_design_style(source: VerifiedComponentSource, style_name: str) -> PortableSkill:
    """Load exactly one selected pack member with its source references intact."""
    return select_portable_skill(COMPONENT_ID, source, style_name)
