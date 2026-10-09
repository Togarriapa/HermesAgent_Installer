"""Source-specific skill discovery and inert host-hook review.

This module indexes complete source trees and inventories hook effects. It does
not execute upstream helpers or silently install host callbacks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.skill_refs import SkillReferenceAudit, audit_skill_file_map


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ /+-]{0,119}$")
_EFFECTS = (
    ("network", re.compile(r"\b(fetch|curl|wget|requests\.|httpx\.|urllib\.|axios|https?://)", re.I)),
    ("subprocess", re.compile(r"\b(subprocess\.|os\.system|exec\(|spawn\(|child_process|shell\s*[:=])", re.I)),
    ("filesystem-write", re.compile(r"\b(write_text|write_bytes|writeFile(?:Sync)?|appendFile(?:Sync)?|unlink(?:Sync)?\(|rmdir\(|mkdir\(|open\([^\n]{0,120}['\"]w)", re.I)),
    ("credential-or-environment", re.compile(r"\b(os\.environ|process\.env|environment|secret|token|credential)", re.I)),
    ("dynamic-code", re.compile(r"\b(eval\(|exec\(|import_module\()", re.I)),
)
_SCRIPT_SUFFIXES = frozenset({".py", ".sh", ".bash", ".js", ".mjs", ".cjs", ".ts", ".tsx"})


class SkillAdapterError(ValueError):
    """The selected source tree cannot safely be exposed as native skills."""


@dataclass(frozen=True, slots=True)
class DiscoveredSkill:
    component_id: str
    name: str
    source_url: str
    revision: str
    skill_file: str
    skill_directory: str
    description: str
    references: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SkillDiscovery:
    component_id: str
    revision: str
    skills: tuple[DiscoveredSkill, ...]
    reference_audit: SkillReferenceAudit

    @property
    def importable(self) -> bool:
        return bool(self.skills) and self.reference_audit.complete


@dataclass(frozen=True, slots=True)
class HookCandidate:
    component_id: str
    path: str
    effects: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class HookReview:
    component_id: str
    candidates: tuple[HookCandidate, ...]
    status: str = "review-required"

    @property
    def may_install(self) -> bool:
        return False


def _metadata(text: str, skill_path: str) -> tuple[str, str]:
    name = ""
    description = ""
    lines = text.splitlines()
    if lines and lines[0].strip() == "---":
        for line in lines[1:]:
            if line.strip() == "---":
                break
            key, sep, value = line.partition(":")
            if not sep:
                continue
            if key.strip().casefold() == "name":
                name = value.strip().strip("'\"")
            elif key.strip().casefold() == "description":
                description = value.strip().strip("'\"")
    if not name:
        heading = next((line.strip()[2:].strip() for line in lines if line.startswith("# ")), "")
        name = heading or PurePosixPath(skill_path).parent.name
    if not _NAME.fullmatch(name):
        raise SkillAdapterError(f"invalid skill name in {skill_path}")
    return name, description[:500]


def discover_component_skills(component_id: str, files: Mapping[str, bytes]) -> SkillDiscovery:
    """Discover separate SKILL.md roots without flattening helper or shared files."""
    contract = resolve_component_adapter(component_id)
    if contract.unresolved_reason():
        raise SkillAdapterError(contract.unresolved_reason())
    audit = audit_skill_file_map(dict(files))
    if not audit.complete:
        first = audit.problems[0]
        raise SkillAdapterError(f"skill reference audit failed at {first.source_path}:{first.line}: {first.reason}")
    records = []
    for skill_path in audit.skill_files:
        body = files[skill_path]
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            raise SkillAdapterError(f"skill metadata is not UTF-8: {skill_path}") from None
        name, description = _metadata(text, skill_path)
        parent = PurePosixPath(skill_path).parent.as_posix()
        scope = "" if parent == "." else parent + "/"
        references = tuple(path for path in audit.resolved_targets
                           if path == parent or path.startswith(scope) or "/" not in path)
        records.append(DiscoveredSkill(
            component_id=component_id,
            name=name,
            source_url=contract.selected_source_url,
            revision=contract.revision or "",
            skill_file=skill_path,
            skill_directory=parent,
            description=description,
            references=references,
        ))
    return SkillDiscovery(component_id, contract.revision or "", tuple(records), audit)


def review_host_hooks(component_id: str, files: Mapping[str, bytes]) -> HookReview:
    """Inventory likely host hook scripts and their visible effect signals inertly."""
    resolve_component_adapter(component_id)  # Reject unknown component IDs.
    candidates = []
    for path in sorted(files):
        relative = PurePosixPath(path)
        parts = {part.casefold() for part in relative.parts}
        suffix = relative.suffix.casefold()
        manifest_candidate = (
            suffix == ".json"
            and relative.name.casefold() in {"settings.json", "plugin.json", "hooks.json"}
        )
        hook_script = (bool(parts & {"hook", "hooks"}) or "hook" in relative.name.casefold()) and suffix in _SCRIPT_SUFFIXES
        if not (manifest_candidate or hook_script):
            continue
        body = files[path]
        if not isinstance(body, bytes) or len(body) > 262_144:
            candidates.append(HookCandidate(
                component_id, path, ("unreadable-or-oversized",),
                "not executed; manual bounded source review required",
            ))
            continue
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            candidates.append(HookCandidate(
                component_id, path, ("non-utf8",),
                "not executed; manual source review required",
            ))
            continue
        effects = tuple(name for name, pattern in _EFFECTS if pattern.search(text))
        candidates.append(HookCandidate(
            component_id, path, effects or ("no-static-effect-signal-found",),
            "not executed; static signals are advisory and never approval",
        ))
    return HookReview(component_id, tuple(candidates))
