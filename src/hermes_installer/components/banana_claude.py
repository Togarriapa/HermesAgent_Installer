"""Fail-closed status for the pinned Banana Claude image skill.

The upstream skill calls Google Gemini directly. The installer currently has
no image-generation route which can mediate that call, so this adapter keeps
the portable skill distinct from an available image-generation capability.
"""
from __future__ import annotations

from dataclasses import dataclass

from hermes_installer.components.adapters import resolve_component_adapter


@dataclass(frozen=True, slots=True)
class BananaClaudeStatus:
    component_id: str
    source_identity: str
    revision: str
    skill_source_status: str
    generation_available: bool
    generation_status: str
    reason: str
    automatic_paid_generation: bool = False


def banana_claude_status() -> BananaClaudeStatus:
    """Describe the pinned source and its current installer-owned boundary."""
    source = resolve_component_adapter("banana-claude")
    if (source.source_identity != "AgriciDaniel/banana-claude"
            or source.revision != "6a2b1b51fdcc35932184f06e513646a6f6f4f7d8"):
        raise RuntimeError("banana-claude source contract differs from the reviewed pin")
    return BananaClaudeStatus(
        component_id=source.component_id,
        source_identity=source.source_identity,
        revision=source.revision,
        skill_source_status="pinned; source-only; native invocation unverified",
        generation_available=False,
        generation_status="unavailable",
        reason=("the pinned plugin invokes Google Gemini directly; an installer-owned "
                "image route with capability, privacy, credential, and budget mediation "
                "is not implemented"),
    )
