"""Task-scoped loader for Addy Osmani's pinned Agent Skills repository."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.skill_handlers import SkillAdapterError, discover_component_skills
from hermes_installer.components.source_bundle import VerifiedComponentSource


COMPONENT_ID = "addy-osmani-s-agent-skills"


class AddyAgentSkillsError(ValueError):
    """The requested skill cannot be safely selected from the reviewed source."""


@dataclass(frozen=True, slots=True)
class TaskScopedSkill:
    component_id: str
    revision: str
    name: str
    skill_file: str
    instructions: bytes
    referenced_files: tuple[tuple[str, bytes], ...]

    @property
    def loaded_paths(self) -> tuple[str, ...]:
        return (self.skill_file, *(path for path, _ in self.referenced_files))


def load_for_task(
    source: VerifiedComponentSource,
    skill_name: str,
) -> TaskScopedSkill:
    """Load one skill and its recursively linked shared/local files only.

    Root instructions such as AGENTS.md, CLAUDE.md, and README.md are not
    concatenated into the selected task context unless the skill links them.
    """
    if not isinstance(source, VerifiedComponentSource):
        raise AddyAgentSkillsError("Agent Skills requires a verified pinned source archive")
    contract = resolve_component_adapter(COMPONENT_ID)
    if (source.component_id != COMPONENT_ID or source.source_identity != contract.source_identity
            or source.revision != contract.revision):
        raise AddyAgentSkillsError("Agent Skills source identity or revision does not match the reviewed pin")
    if (source.license != contract.license
            or source.redistribution_license_review_required != contract.redistribution_license_review_required):
        raise AddyAgentSkillsError("Agent Skills license evidence differs from the reviewed contract")
    if not isinstance(skill_name, str) or not skill_name.strip():
        raise AddyAgentSkillsError("a skill name is required")
    try:
        discovery = discover_component_skills(COMPONENT_ID, source.files)
    except SkillAdapterError as exc:
        raise AddyAgentSkillsError(str(exc)) from None
    wanted = skill_name.casefold()
    selected = [skill for skill in discovery.skills
                if skill.name.casefold() == wanted
                or PurePosixPath(skill.skill_directory).name.casefold() == wanted]
    if len(selected) != 1:
        raise AddyAgentSkillsError("requested skill is missing or ambiguous")
    record = selected[0]
    body = source.files.get(record.skill_file)
    if not isinstance(body, bytes):
        raise AddyAgentSkillsError("selected skill instructions are missing")

    # The audit starts at each SKILL.md and records every transitive link. A
    # directory link includes its files, while unlinked repository-root text
    # stays outside this task's prompt.
    targets = dict(discovery.reference_audit.skill_resolved_targets).get(record.skill_file, ())
    selected_paths: set[str] = set()
    for target in targets:
        target_path = PurePosixPath(target)
        if target in source.files:
            selected_paths.add(target)
        else:
            selected_paths.update(path for path in source.files
                                  if path.startswith(target.rstrip("/") + "/"))
    selected_paths.discard(record.skill_file)
    references = tuple((path, source.files[path]) for path in sorted(selected_paths))
    if any(not isinstance(content, bytes) for _, content in references):
        raise AddyAgentSkillsError("a selected shared or local reference is not byte content")
    if len(body) + sum(len(content) for _, content in references) > 8 * 1024 * 1024:
        raise AddyAgentSkillsError("selected skill and references exceed the 8 MiB task context limit")
    return TaskScopedSkill(
        COMPONENT_ID, source.revision, record.name, record.skill_file, body, references,
    )
