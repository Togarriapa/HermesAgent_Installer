"""Pinned adapter for the complete jakeschincariol/replica-skill tree."""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.skill_handlers import DiscoveredSkill, SkillAdapterError, SkillDiscovery, discover_component_skills


_PYTHON_COMMAND = re.compile(r"(?m)^\s*(?:\$\s*)?(?:python|python3(?:\.\d+)?)\s+([^\s`]+\.py)(?=\s|$)")
_FIXTURE_HELPER = "replica-diff/parity.py"


@dataclass(frozen=True, slots=True)
class ReplicaHelperReference:
    skill_file: str
    written_path: str
    source_path: str


@dataclass(frozen=True, slots=True)
class ReplicaSkillSet:
    component_id: str
    revision: str
    skills: tuple[DiscoveredSkill, ...]
    helper_references: tuple[ReplicaHelperReference, ...]
    discovery: SkillDiscovery
    status: str = "fixture-ready; native discovery and live target pending"


@dataclass(frozen=True, slots=True)
class ReplicaFixtureResult:
    helper: str
    exit_code: int
    score: float
    stdout: str
    stderr: str
    status: str = "fixture-verified; native discovery and live target pending"


def _pinned_contract():
    contract = resolve_component_adapter("jakeschincariol/replica-skill")
    if contract.component_id != "jakeschincariol-replica-skill" or contract.revision != "77c9436fb3d18c3d58169efb8caf4fe906b0dc51":
        raise SkillAdapterError("replica-skill source identity differs from the reviewed pin")
    return contract


def discover_replica_skill(files: Mapping[str, bytes]) -> ReplicaSkillSet:
    """Resolve the entire pinned skill pack and every documented Python helper."""
    contract = _pinned_contract()
    if not files or any(not isinstance(name, str) or not isinstance(body, bytes) for name, body in files.items()):
        raise SkillAdapterError("replica-skill source tree must be a non-empty byte map")
    discovery = discover_component_skills(contract.component_id, files)
    references: set[ReplicaHelperReference] = set()
    for skill in discovery.skills:
        text = files[skill.skill_file].decode("utf-8")
        for match in _PYTHON_COMMAND.finditer(text):
            written = match.group(1).strip("\"'")
            path = PurePosixPath(skill.skill_directory, written)
            parts: list[str] = []
            for part in path.parts:
                if part in {"", "."}:
                    continue
                if part == "..":
                    if not parts:
                        raise SkillAdapterError(f"helper reference escapes source tree: {skill.skill_file} -> {written}")
                    parts.pop()
                else:
                    parts.append(part)
            normalized = PurePosixPath(*parts)
            target = normalized.as_posix()
            if target not in files:
                raise SkillAdapterError(f"documented helper is missing: {skill.skill_file} -> {written}")
            references.add(ReplicaHelperReference(skill.skill_file, written, target))
    if not discovery.skills:
        raise SkillAdapterError("replica-skill source contains no discoverable skills")
    return ReplicaSkillSet(
        component_id=contract.component_id,
        revision=contract.revision or "",
        skills=discovery.skills,
        helper_references=tuple(sorted(references, key=lambda item: (item.skill_file, item.written_path))),
        discovery=discovery,
    )


def run_replica_parity_fixture(
    source_root: Path,
    workspace: Path,
    *,
    python_executable: Path,
    timeout_seconds: int = 10,
) -> ReplicaFixtureResult:
    """Run the documented local feature-parity helper on synthetic data.

    The workspace CSV is authored by the caller and contains no real app data.
    The helper path and arguments are fixed; no shell, network, or caller argv
    is accepted. Native skill discovery and target acceptance remain separate.
    """
    contract = _pinned_contract()
    source = Path(source_root)
    work = Path(workspace)
    if source.is_symlink() or work.is_symlink():
        raise ValueError("source and synthetic workspace must not be symlinks")
    source = source.resolve(strict=True)
    work = work.resolve(strict=True)
    if not source.is_dir() or not work.is_dir():
        raise ValueError("source and synthetic workspace must be directories")
    temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
    if not work.is_relative_to(temp_root):
        raise ValueError("synthetic replication workspace must be inside the system temporary directory")
    try:
        interpreter = Path(python_executable).resolve(strict=True)
    except OSError:
        raise ValueError("Python interpreter is unavailable") from None
    if not interpreter.is_file() or not 1 <= timeout_seconds <= 30:
        raise ValueError("invalid Python interpreter or fixture timeout")

    if any(path.is_symlink() for path in source.rglob("*")):
        raise ValueError("replica-skill source tree contains a symlink")
    skill_files = {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    provenance_bytes = skill_files.get("INSTALLER-SOURCE-PROVENANCE.json")
    try:
        provenance = json.loads(provenance_bytes.decode("utf-8"))
    except (AttributeError, UnicodeError, ValueError):
        raise ValueError("replica-skill source has no verified installer provenance") from None
    if (provenance.get("component_id") != contract.component_id
            or provenance.get("source_identity") != contract.source_identity
            or provenance.get("revision") != contract.revision):
        raise ValueError("replica-skill source provenance differs from the reviewed pin")
    source_files = {name: body for name, body in skill_files.items() if name != "INSTALLER-SOURCE-PROVENANCE.json"}
    source_modes = {
        path.relative_to(source).as_posix(): 0o755 if path.stat().st_mode & 0o111 else 0o644
        for path in source.rglob("*")
        if path.is_file() and not path.is_symlink() and path.name != "INSTALLER-SOURCE-PROVENANCE.json"
    }
    try:
        from hermes_installer.registry.source import _git_tree
        source_tree, _ = _git_tree(source_files, source_modes)
    except Exception:
        raise ValueError("replica-skill source tree could not be reverified") from None
    if source_tree != provenance.get("source_tree_sha"):
        raise ValueError("replica-skill files differ from their pinned Git tree")
    skill_set = discover_replica_skill(skill_files)
    if skill_set.component_id != contract.component_id or skill_set.revision != contract.revision:
        raise ValueError("replica-skill source differs from its reviewed pin")
    if not any(reference.source_path == _FIXTURE_HELPER for reference in skill_set.helper_references):
        raise ValueError("pinned pack does not document the selected parity helper")
    helper = source / _FIXTURE_HELPER
    matrix = work / "features.csv"
    if helper.is_symlink() or not helper.is_file() or matrix.is_symlink() or not matrix.is_file():
        raise ValueError("parity helper or synthetic feature matrix is unavailable")

    try:
        completed = subprocess.run(
            [str(interpreter), str(helper), str(matrix)],
            cwd=work,
            env={"PATH": str(interpreter.parent), "HOME": str(work), "TMPDIR": str(work)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("replica-skill synthetic helper exceeded its deadline") from None
    except OSError as exc:
        raise RuntimeError(f"replica-skill synthetic helper could not start: {exc}") from None
    match = re.search(r"Parity:\s+([0-9]+(?:\.[0-9]+)?)\s+/\s+100", completed.stdout)
    if completed.returncode != 0 or not match:
        raise RuntimeError("replica-skill parity helper did not return its documented score")
    return ReplicaFixtureResult(_FIXTURE_HELPER, completed.returncode, float(match.group(1)), completed.stdout[:8192], completed.stderr[:8192])
