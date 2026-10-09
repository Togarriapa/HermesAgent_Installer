"""Source-pinned helpers for portable skill trees.

These helpers expose selected Markdown and local data to a task. They do not
execute upstream hooks or install host callbacks.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Callable, Mapping

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.skill_handlers import discover_component_skills
from hermes_installer.components.source_bundle import VerifiedComponentSource


PINNED_SOURCES: Mapping[str, tuple[str, str]] = {
    "ui-ux-pro-max": ("nextlevelbuilder/ui-ux-pro-max-skill", "50d8a7de0900119855614541f15a1a616691eb33"),
    "taste-skill": ("Leonxlnx/taste-skill", "18dfc928b135629e0eddfdd445a06400d04ed439"),
    "humanizer": ("blader/humanizer", "225a6f39ac85f76ee48dbad772ea4abe4ed6c9d8"),
    "obsidian-skills": ("kepano/obsidian-skills", "3ccff5338ea700537839b21900aa5358a0402c98"),
    "emil-kowalski-impeccable": ("pbakaus/impeccable", "d631a8827f99414d2b6daba4ef08b7f8701751d7"),
}


class PortableSkillError(ValueError):
    """A selected source, skill or file-format operation is unavailable."""


@dataclass(frozen=True, slots=True)
class PortableSkill:
    component_id: str
    source_identity: str
    revision: str
    name: str
    skill_file: str
    body: str
    references: tuple[str, ...]


def validate_pinned_source(component_id: str, source: VerifiedComponentSource) -> None:
    expected = PINNED_SOURCES.get(component_id)
    contract = resolve_component_adapter(component_id)
    if expected is None or expected != (contract.source_identity, contract.revision):
        raise PortableSkillError("component source contract differs from its reviewed pin")
    if (not isinstance(source, VerifiedComponentSource)
            or source.component_id != component_id
            or (source.source_identity, source.revision) != expected):
        raise PortableSkillError("source bundle does not match the selected immutable revision")


def select_portable_skill(
    component_id: str,
    source: VerifiedComponentSource,
    selected_name: str,
) -> PortableSkill:
    """Return one scoped skill and its intact source-relative references."""
    validate_pinned_source(component_id, source)
    files = dict(source.files)
    if component_id == "obsidian-skills":
        files = _obsidian_template_links_for_audit(files)
    try:
        discovery = discover_component_skills(component_id, files)
    except (ValueError, UnicodeError) as exc:
        raise PortableSkillError(f"selected skill tree is unavailable: {exc}") from exc
    matches = [skill for skill in discovery.skills
               if skill.name.casefold() == selected_name.casefold()
               or skill.skill_file.casefold() == selected_name.casefold()
               or PurePosixPath(skill.skill_file).parent.name.casefold() == selected_name.casefold()]
    if len(matches) != 1:
        raise PortableSkillError("selected skill name is missing or ambiguous in the pinned source")
    skill = matches[0]
    body = source.files[skill.skill_file].decode("utf-8")
    return PortableSkill(
        component_id=component_id,
        source_identity=source.source_identity,
        revision=source.revision,
        name=skill.name,
        skill_file=skill.skill_file,
        body=body,
        references=skill.references,
    )


def _obsidian_template_links_for_audit(files: dict[str, bytes]) -> dict[str, bytes]:
    """Ignore the upstream literal `(url)` template, without changing import bytes."""
    result = dict(files)
    path = "skills/obsidian-markdown/SKILL.md"
    body = result.get(path)
    if body is None:
        return result
    text = body.decode("utf-8")
    # At the pinned source, this is an instructional Markdown placeholder for
    # external links, not a link to a bundled file. Keep the original in source.
    if text.count("[text](url)") == 1:
        result[path] = text.replace("[text](url)", "[text](https://example.invalid/)").encode("utf-8")
    return result


@dataclass(frozen=True, slots=True)
class SkillRoute:
    component_id: str
    command: str
    skill: PortableSkill
    request_text: str


def route_skill(component_id: str, skill: PortableSkill, request_text: str) -> SkillRoute:
    expected = PINNED_SOURCES.get(component_id)
    if (expected is None or skill.component_id != component_id
            or (skill.source_identity, skill.revision) != expected):
        raise PortableSkillError("selected skill belongs to a different component")
    if not isinstance(request_text, str) or not request_text.strip():
        raise PortableSkillError("skill request must contain text")
    return SkillRoute(component_id, f"/{skill.name}", skill, request_text)


@dataclass(frozen=True, slots=True)
class CapabilityState:
    status: str
    reason: str


def unavailable_capability(reason: str) -> CapabilityState:
    return CapabilityState("unavailable", reason)


_VAULT_PROOF = object()


@dataclass(frozen=True, slots=True, init=False)
class ApprovedVault:
    """Opaque root resolved through the selected profile's trusted callback."""

    _root: "Path"
    _proof: object


def bind_selected_profile_vault(vault_resolver: Callable[[], "Path"]) -> ApprovedVault:
    """Bind writes to the current selected profile's approved vault root."""
    from pathlib import Path

    if not callable(vault_resolver):
        raise TypeError("selected-profile vault resolver must be callable")
    root_arg = Path(vault_resolver())
    if root_arg.is_symlink() or not root_arg.is_dir():
        raise PortableSkillError("approved vault must be an existing real directory")
    root = root_arg.resolve(strict=True)
    vault = object.__new__(ApprovedVault)
    object.__setattr__(vault, "_root", root)
    object.__setattr__(vault, "_proof", _VAULT_PROOF)
    return vault


def safe_vault_write(vault: ApprovedVault, relative_path: str, content: bytes) -> "Path":
    """Write one validated file below an approved, existing vault root."""
    from pathlib import Path
    import os
    import tempfile

    if not isinstance(relative_path, str):
        raise PortableSkillError("vault path must be a normalized relative path")
    if not isinstance(vault, ApprovedVault) or vault._proof is not _VAULT_PROOF:
        raise PortableSkillError("vault writes require the selected profile's approved vault binding")
    root = vault._root
    relative = PurePosixPath(relative_path)
    if (not isinstance(relative_path, str) or not relative_path or relative.is_absolute()
            or ".." in relative.parts or relative.as_posix() != relative_path
            or "\\" in relative_path):
        raise PortableSkillError("vault path must be a normalized relative path")
    if not isinstance(content, bytes):
        raise TypeError("vault content must be bytes")
    target = root.joinpath(*relative.parts)
    cursor = root
    for part in relative.parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise PortableSkillError("vault path cannot traverse a symlink")
        if not cursor.exists():
            cursor.mkdir(mode=0o700)
    if target.is_symlink() or target.is_dir():
        raise PortableSkillError("vault target must be a regular file path")
    if not target.resolve(strict=False).is_relative_to(root):
        raise PortableSkillError("vault path resolves outside the approved vault")
    fd, temporary_name = tempfile.mkstemp(prefix=".hermes-vault-", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return target


def validate_canvas_document(content: str) -> dict:
    try:
        document = json.loads(content)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PortableSkillError("JSON Canvas fixture is not valid JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("nodes"), list) or not isinstance(document.get("edges"), list):
        raise PortableSkillError("JSON Canvas document requires nodes and edges arrays")
    ids: set[str] = set()
    for node in document["nodes"]:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not node["id"] or node["id"] in ids:
            raise PortableSkillError("JSON Canvas nodes require unique non-empty ids")
        if not all(isinstance(node.get(key), int) for key in ("x", "y", "width", "height")):
            raise PortableSkillError("JSON Canvas nodes require integer geometry")
        ids.add(node["id"])
    for edge in document["edges"]:
        if not isinstance(edge, dict) or edge.get("fromNode") not in ids or edge.get("toNode") not in ids:
            raise PortableSkillError("JSON Canvas edge references an unknown node")
    return document
