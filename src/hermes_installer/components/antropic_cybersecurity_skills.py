"""Source-only adapter for the third-party cybersecurity procedure catalog.

Setup discovers and copies reviewed skill trees. It never invokes a procedure,
scanner, network client, or security exercise.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from hermes_installer.components.adapters import ComponentAdapterContract, resolve_component_adapter
from hermes_installer.components.skill_binding import ComponentSkillBinding, stage_component_skill
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.components.skill_handlers import SkillAdapterError, SkillDiscovery, discover_component_skills
from hermes_installer.registry.generation import GenerationStore


COMPONENT_ID = "antropic-cybersecurity-skills"
ATTRIBUTION = (
    "Third-party project mukul975/Anthropic-Cybersecurity-Skills; it is not "
    "created, owned, maintained, or endorsed by Anthropic."
)
EXERCISE_STATUS = "instruction_only; execution requires separate authorization and reviewed tools"


class CybersecuritySkillsError(ValueError):
    """The selected procedure source is unresolved or outside its pinned revision."""


@dataclass(frozen=True, slots=True)
class ProcedureCatalog:
    component_id: str
    revision: str
    attribution: str
    discovery: SkillDiscovery
    exercise_status: str = EXERCISE_STATUS

    @property
    def procedures(self) -> tuple[str, ...]:
        return tuple(skill.name for skill in self.discovery.skills)


@dataclass(frozen=True, slots=True)
class ProcedureInstallation:
    attribution: str
    binding: ComponentSkillBinding
    exercise_status: str = EXERCISE_STATUS
    arm64_status: str = "unverified"
    redistribution_status: str = "private_source_staging_only; no redistribution authorization asserted"


def _pinned_source(source: VerifiedComponentSource) -> ComponentAdapterContract:
    if not isinstance(source, VerifiedComponentSource):
        raise CybersecuritySkillsError("cybersecurity procedures require a verified pinned source archive")
    contract = resolve_component_adapter(COMPONENT_ID)
    if (source.component_id != COMPONENT_ID or source.source_identity != contract.source_identity
            or source.revision != contract.revision):
        raise CybersecuritySkillsError("cybersecurity source identity or revision does not match the reviewed pin")
    if (source.license != contract.license
            or source.redistribution_license_review_required != contract.redistribution_license_review_required):
        raise CybersecuritySkillsError("cybersecurity license evidence differs from the reviewed contract")
    return contract


def discover_procedures(source: VerifiedComponentSource) -> ProcedureCatalog:
    """Discover procedure documents and references without interpreting them."""
    _pinned_source(source)
    try:
        discovery = discover_component_skills(COMPONENT_ID, source.files)
    except SkillAdapterError as exc:
        raise CybersecuritySkillsError(str(exc)) from None
    if not discovery.skills:
        raise CybersecuritySkillsError("the selected source contains no discoverable procedures")
    return ProcedureCatalog(COMPONENT_ID, source.revision, ATTRIBUTION, discovery)


def stage_procedures(
    source: VerifiedComponentSource,
    store: GenerationStore,
    *,
    profile_id: str,
    profile_data_root: Path,
) -> ProcedureInstallation:
    """Stage the verified procedures inside one profile-owned data root.

    This writes immutable skill source only. It does not edit Hermes config,
    activate discovery, or run embedded tools and exercises.
    """
    _pinned_source(source)
    binding = stage_component_skill(
        source, store, profile_id=profile_id, profile_data_root=profile_data_root,
    )
    return ProcedureInstallation(ATTRIBUTION, binding)
