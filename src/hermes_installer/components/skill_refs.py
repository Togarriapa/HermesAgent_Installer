"""Safe integrity checks for complete, locally sourced skill trees."""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


_LINK = re.compile(r"!?(?:\[[^\]\n]*\])\(\s*(<[^>\n]+>|[^)\s]+)(?:\s+[^)]*)?\)")


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
    pending = list(skills)
    checked: set[Path] = set()
    resolved: set[str] = set()
    problems: list[SkillReferenceProblem] = []

    while pending:
        markdown = pending.pop()
        if markdown in checked:
            continue
        checked.add(markdown)
        try:
            text = markdown.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            problems.append(SkillReferenceProblem(
                markdown.relative_to(root).as_posix(), 1, "", "markdown file cannot be read as UTF-8"
            ))
            continue

        for match in _LINK.finditer(text):
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
            if candidate.is_file() and candidate.suffix.casefold() == ".md":
                pending.append(candidate)

    return SkillReferenceAudit(
        skill_files=tuple(path.relative_to(root).as_posix() for path in skills),
        checked_markdown=tuple(sorted(path.relative_to(root).as_posix() for path in checked)),
        resolved_targets=tuple(sorted(resolved)),
        problems=tuple(problems),
    )
