"""Bind a verified component source to one installer-owned profile root.

The returned path is an input to the reviewed Hermes profile writer. This
module never edits HERMES_HOME or runs source hooks.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.skill_handlers import discover_component_skills
from hermes_installer.components.source_bundle import ComponentSourceError, VerifiedComponentSource
from hermes_installer.registry.generation import GenerationStore


class ComponentBindingError(ValueError):
    """A component cannot be safely exposed to the selected profile."""


@dataclass(frozen=True, slots=True)
class ComponentSkillBinding:
    profile_id: str
    component_id: str
    source_identity: str
    revision: str
    external_dir: Path
    skill_files: tuple[str, ...]
    names: tuple[str, ...]
    source_sha256: str
    redistribution_license_review_required: bool
    status: str = "staged_pending_native_discovery"


_PROFILE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def stage_component_skill(
    source: VerifiedComponentSource,
    store: GenerationStore,
    *,
    profile_id: str,
    profile_data_root: Path,
) -> ComponentSkillBinding:
    """Stage a component within one profile's owned data root.

    `store` must have been constructed from an OwnedRoot whose root is exactly
    `profile_data_root`. The result may be added to that profile's reviewed
    ``skills.external_dirs`` entry; callers decide activation separately.
    """
    if not isinstance(profile_id, str) or not _PROFILE_ID.fullmatch(profile_id):
        raise ComponentBindingError("profile id is not a safe native profile identifier")
    try:
        profile_root = profile_data_root.resolve(strict=True)
        owned_root = store.owned.root.resolve(strict=True)
    except (OSError, AttributeError):
        raise ComponentBindingError("profile data root is not initialized") from None
    if profile_data_root.is_symlink() or owned_root != profile_root:
        raise ComponentBindingError("generation store is not rooted in this profile's installer-owned data")
    if not store.root.resolve(strict=True).is_relative_to(profile_root):
        raise ComponentBindingError("component generations escaped the profile data root")
    if not source.files or not source.source_identity or not re.fullmatch(r"[a-f0-9]{40}", source.revision):
        raise ComponentBindingError("component source lacks a complete pinned identity")
    contract = resolve_component_adapter(source.component_id)
    if source.source_identity != contract.source_identity or source.revision != contract.revision:
        raise ComponentBindingError("component source identity differs from the reviewed source pin")
    source_files = {
        name: body for name, body in source.files.items()
        if name != "INSTALLER-SOURCE-PROVENANCE.json"
    }
    source_modes = {
        name: mode for name, mode in source.file_modes.items()
        if name in source_files
    }
    from hermes_installer.registry.source import _git_tree
    try:
        source_tree, _ = _git_tree(source_files, source_modes)
    except Exception as exc:
        raise ComponentBindingError(f"component source tree is invalid: {exc}") from None
    if source_tree != source.source_tree_sha:
        raise ComponentBindingError("component source files differ from the pinned Git tree")
    try:
        discovery = discover_component_skills(source.component_id, source.files)
    except (ValueError, KeyError) as exc:
        raise ComponentBindingError(f"component skills are not importable: {exc}") from None
    if not discovery.importable:
        raise ComponentBindingError("pinned component tree has no complete skill tree")

    try:
        staged = source.stage(store).resolve(strict=True)
        if not staged.is_relative_to(profile_root) or staged.is_symlink():
            raise ComponentBindingError("staged component path escaped the profile data root")
        # Re-audit the actual immutable generation so that source-map discovery
        # alone cannot mask a staging or filesystem discrepancy.
        actual = {
            path.relative_to(staged).as_posix(): path.read_bytes()
            for path in staged.rglob("*")
            if path.is_file() and path.name != "INSTALLER-SOURCE-PROVENANCE.json"
        }
        actual_discovery = discover_component_skills(source.component_id, actual)
        if actual_discovery.skills != discovery.skills:
            raise ComponentBindingError("staged skill files differ from the verified source tree")
    except ComponentBindingError:
        raise
    except (OSError, ComponentSourceError, ValueError) as exc:
        raise ComponentBindingError(f"component generation failed verification: {exc}") from None

    digest = hashlib.sha256()
    for relative in sorted(source.files):
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(source.files[relative]).digest())
    return ComponentSkillBinding(
        profile_id=profile_id,
        component_id=source.component_id,
        source_identity=source.source_identity,
        revision=source.revision,
        external_dir=staged,
        skill_files=tuple(skill.skill_file for skill in discovery.skills),
        names=tuple(skill.name for skill in discovery.skills),
        source_sha256=digest.hexdigest(),
        redistribution_license_review_required=source.redistribution_license_review_required,
    )
