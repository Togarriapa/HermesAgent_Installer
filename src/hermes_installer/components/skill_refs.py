"""Safe integrity checks for complete, locally sourced skill trees."""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


_LINK = re.compile(r"!?(?:\[[^\]\n]*\])\(\s*(<[^>\n]+>|[^)\s]+)(?:\s+[^)]*)?\)")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_INLINE_CODE = re.compile(r"(`+).*?\1(?!`)", re.DOTALL)


def _mask_markdown_code(text: str) -> str:
    """Blank fenced, indented and inline code while preserving source offsets."""
    output: list[str] = []
    fence_char: str | None = None
    fence_size = 0
    for line in text.splitlines(keepends=True):
        marker = _FENCE.match(line.rstrip("\r\n"))
        if fence_char is not None:
            output.append("".join("\n" if char == "\n" else "\r" if char == "\r" else " " for char in line))
            if (marker and marker.group(1)[0] == fence_char
                    and len(marker.group(1)) >= fence_size and not marker.group(2).strip()):
                fence_char = None
                fence_size = 0
            continue
        if marker:
            fence_char = marker.group(1)[0]
            fence_size = len(marker.group(1))
            output.append("".join("\n" if char == "\n" else "\r" if char == "\r" else " " for char in line))
            continue
        if line.startswith("    ") or line.startswith("\t"):
            output.append("".join("\n" if char == "\n" else "\r" if char == "\r" else " " for char in line))
            continue
        output.append(line)
    masked = "".join(output)
    return _INLINE_CODE.sub(lambda match: "".join("\n" if char == "\n" else "\r" if char == "\r" else " " for char in match.group(0)), masked)


@dataclass(frozen=True, slots=True)
class SkillReferenceProblem:
    source_path: str
    line: int
    target: str
    reason: str


@dataclass(frozen=True, slots=True)
class SkillReferenceAudit:
    skill_files: tuple[str, ...]
    checked_markdown: tuple[str, ...]
    resolved_targets: tuple[str, ...]
    problems: tuple[SkillReferenceProblem, ...]
    skill_resolved_targets: tuple[tuple[str, tuple[str, ...]], ...] = ()
    quarantined_skill_problems: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @property
    def complete(self) -> bool:
        return not self.problems


def audit_skill_references(source_root: Path) -> SkillReferenceAudit:
    """Resolve local Markdown links transitively from every SKILL.md.

    All paths are bounded by source_root. This checks skill/helper/asset and
    shared-root references without executing upstream code.
    """
    root = source_root.resolve(strict=True)
    if not root.is_dir() or source_root.is_symlink():
        raise ValueError("skill source root must be a real directory")

    skills = tuple(sorted(
        path for path in root.rglob("SKILL.md")
        if path.is_file() and not path.is_symlink()
    ))
    pending = [(skill, skill) for skill in skills]
    checked: set[Path] = set()
    resolved: set[str] = set()
    skill_resolved: dict[str, set[str]] = {path.relative_to(root).as_posix(): set() for path in skills}
    visited_by_skill: dict[str, set[Path]] = {path.relative_to(root).as_posix(): set() for path in skills}
    problems: list[SkillReferenceProblem] = []

    while pending:
        skill, markdown = pending.pop()
        skill_name = skill.relative_to(root).as_posix()
        if markdown in visited_by_skill[skill_name]:
            continue
        visited_by_skill[skill_name].add(markdown)
        checked.add(markdown)
        try:
            text = markdown.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            problems.append(SkillReferenceProblem(
                markdown.relative_to(root).as_posix(), 1, "", "markdown file cannot be read as UTF-8"
            ))
            continue

        for match in _LINK.finditer(_mask_markdown_code(text)):
            raw = match.group(1)
            target = raw[1:-1] if raw.startswith("<") and raw.endswith(">") else raw
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith("#"):
                continue
            relative = unquote(parsed.path)
            if not relative:
                continue
            if relative.startswith("/") or re.match(r"^[A-Za-z]:[/\\]", relative):
                problems.append(SkillReferenceProblem(
                    markdown.relative_to(root).as_posix(),
                    text.count("\n", 0, match.start()) + 1,
                    target,
                    "absolute path is outside the bundled source tree",
                ))
                continue

            source_relative = markdown.relative_to(root).parent.as_posix()
            normalized = posixpath.normpath(posixpath.join(source_relative, relative))
            if normalized in {"", "."}:
                normalized = source_relative
            if normalized == ".." or normalized.startswith("../"):
                problems.append(SkillReferenceProblem(
                    markdown.relative_to(root).as_posix(),
                    text.count("\n", 0, match.start()) + 1,
                    target,
                    "relative path escapes the bundled source tree",
                ))
                continue

            candidate = root.joinpath(*PurePosixPath(normalized).parts)
            cursor = root
            symlinked = False
            for part in PurePosixPath(normalized).parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    symlinked = True
                    break
            source_path = markdown.relative_to(root).as_posix()
            line = text.count("\n", 0, match.start()) + 1
            if symlinked:
                problems.append(SkillReferenceProblem(source_path, line, target, "reference traverses a symlink"))
                continue
            if not candidate.exists():
                problems.append(SkillReferenceProblem(source_path, line, target, "referenced file or directory is missing"))
                continue

            resolved.add(normalized)
            skill_resolved[skill_name].add(normalized)
            if candidate.is_file() and candidate.suffix.casefold() == ".md":
                pending.append((skill, candidate))

    return SkillReferenceAudit(
        skill_files=tuple(path.relative_to(root).as_posix() for path in skills),
        checked_markdown=tuple(sorted(path.relative_to(root).as_posix() for path in checked)),
        resolved_targets=tuple(sorted(resolved)),
        problems=tuple(problems),
        skill_resolved_targets=tuple((name, tuple(sorted(targets))) for name, targets in sorted(skill_resolved.items())),
    )


def audit_skill_file_map(
    files: dict[str, bytes], *, skill_files: tuple[str, ...] | None = None,
) -> SkillReferenceAudit:
    """Audit a validated source archive in memory before it is staged."""
    paths = set(files)
    for name, body in files.items():
        relative = PurePosixPath(name)
        if (not isinstance(name, str) or not isinstance(body, bytes)
            or relative.is_absolute() or not relative.parts or ".." in relative.parts
            or relative.as_posix() != name or "\\" in name):
            raise ValueError("source archive contains an unsafe path or non-byte file")
    available_skills = {name for name in paths if PurePosixPath(name).name == "SKILL.md"}
    if skill_files is None:
        skills = tuple(sorted(available_skills))
    else:
        if (not skill_files or len(skill_files) != len(set(skill_files))
                or any(name not in available_skills for name in skill_files)):
            raise ValueError("selected skill files must name existing distinct SKILL.md paths")
        skills = tuple(sorted(skill_files))
    pending = [(skill, skill) for skill in skills]
    checked: set[str] = set()
    resolved: set[str] = set()
    skill_resolved: dict[str, set[str]] = {name: set() for name in skills}
    visited_by_skill: dict[str, set[str]] = {name: set() for name in skills}
    problems: list[SkillReferenceProblem] = []

    while pending:
        skill, source = pending.pop()
        if source in visited_by_skill[skill]:
            continue
        visited_by_skill[skill].add(source)
        checked.add(source)
        try:
            text = files[source].decode("utf-8")
        except UnicodeDecodeError:
            problems.append(SkillReferenceProblem(source, 1, "", "markdown file cannot be read as UTF-8"))
            continue
        source_parent = PurePosixPath(source).parent.as_posix()
        for match in _LINK.finditer(_mask_markdown_code(text)):
            raw = match.group(1)
            target = raw[1:-1] if raw.startswith("<") and raw.endswith(">") else raw
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith("#"):
                continue
            relative = unquote(parsed.path)
            if not relative:
                continue
            if relative.startswith("/") or re.match(r"^[A-Za-z]:[/\\\\]", relative):
                problems.append(SkillReferenceProblem(
                    source, text.count("\\n", 0, match.start()) + 1, target,
                    "absolute path is outside the bundled source tree",
                ))
                continue
            normalized = posixpath.normpath(posixpath.join(source_parent, relative))
            if normalized in {"", "."}:
                normalized = source_parent
            if normalized == ".." or normalized.startswith("../"):
                problems.append(SkillReferenceProblem(
                    source, text.count("\\n", 0, match.start()) + 1, target,
                    "relative path escapes the bundled source tree",
                ))
                continue
            is_file = normalized in paths
            is_directory = any(name.startswith(normalized.rstrip("/") + "/") for name in paths)
            if not is_file and not is_directory:
                problems.append(SkillReferenceProblem(
                    source, text.count("\\n", 0, match.start()) + 1, target,
                    "referenced file or directory is missing",
                ))
                continue
            resolved.add(normalized)
            skill_resolved[skill].add(normalized)
            if is_file and PurePosixPath(normalized).suffix.casefold() == ".md":
                pending.append((skill, normalized))

    return SkillReferenceAudit(
        skill_files=skills,
        checked_markdown=tuple(sorted(checked)),
        resolved_targets=tuple(sorted(resolved)),
        problems=tuple(problems),
        skill_resolved_targets=tuple((name, tuple(sorted(targets))) for name, targets in sorted(skill_resolved.items())),
    )


def audit_component_skill_file_map(
    component_id: str, revision: str, files: dict[str, bytes], *,
    skill_files: tuple[str, ...] | None = None,
) -> SkillReferenceAudit:
    """Apply only exact reviewed source-specific Markdown template rules.

    Obsidian's pinned format skill uses literal ``[text](url)`` as a prose
    template, not as a path to a bundled file. Audit a transformed copy while
    retaining the original pinned bytes unchanged for provenance/staging.
    """
    audit_files = files
    if (component_id == "obsidian-skills"
            and revision == "3ccff5338ea700537839b21900aa5358a0402c98"):
        path = "skills/obsidian-markdown/SKILL.md"
        body = files.get(path)
        placeholder = b"[text](url)"
        if isinstance(body, bytes) and body.count(placeholder) == 1:
            audit_files = dict(files)
            audit_files[path] = body.replace(placeholder, b"[text](https://example.invalid/)")
    if (component_id == "ecc"
            and revision == "ef648e01899ba3e8dc6371642deaaf64b4477775"
            and skill_files is None):
        full = audit_skill_file_map(audit_files)
        closure_by_skill = {
            skill: {skill, *targets}
            for skill, targets in full.skill_resolved_targets
        }
        issues_by_skill: dict[str, list[str]] = {skill: [] for skill in full.skill_files}
        for issue in full.problems:
            for skill, closure in closure_by_skill.items():
                if issue.source_path in closure:
                    issues_by_skill[skill].append(
                        f"{issue.source_path}:{issue.line}: {issue.reason} ({issue.target})"
                    )
        quarantined = tuple(
            (skill, tuple(issues))
            for skill, issues in sorted(issues_by_skill.items()) if issues
        )
        eligible = tuple(skill for skill in full.skill_files if not issues_by_skill[skill])
        if eligible:
            selected = audit_skill_file_map(audit_files, skill_files=eligible)
            return SkillReferenceAudit(
                skill_files=selected.skill_files,
                checked_markdown=selected.checked_markdown,
                resolved_targets=selected.resolved_targets,
                problems=selected.problems,
                skill_resolved_targets=selected.skill_resolved_targets,
                quarantined_skill_problems=quarantined,
            )
        return SkillReferenceAudit(
            skill_files=(), checked_markdown=full.checked_markdown,
            resolved_targets=full.resolved_targets, problems=(),
            skill_resolved_targets=(), quarantined_skill_problems=quarantined,
        )
    return audit_skill_file_map(audit_files, skill_files=skill_files)
