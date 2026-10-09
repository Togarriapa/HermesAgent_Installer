"""Scoped access to the pinned Humanizer writing procedure."""
from __future__ import annotations

from hermes_installer.components.portable_skill_adapters import (
    PortableSkillError,
    SkillRoute,
    route_skill,
    select_portable_skill,
)
from hermes_installer.components.source_bundle import VerifiedComponentSource


SOURCE_IDENTITY = "blader/humanizer"
SOURCE_REVISION = "225a6f39ac85f76ee48dbad772ea4abe4ed6c9d8"
COMPONENT_ID = "humanizer"


def invoke_humanizer_procedure(source: VerifiedComponentSource, text: str) -> SkillRoute:
    """Expose the declared portable skill route; no local or paid service runs."""
    if not isinstance(text, str) or not text.strip():
        raise PortableSkillError("Humanizer input must contain text")
    skill = select_portable_skill(COMPONENT_ID, source, "humanizer")
    return route_skill(COMPONENT_ID, skill, text)
