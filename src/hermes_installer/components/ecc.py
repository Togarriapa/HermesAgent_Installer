"""ECC source adapter: portable skills, inert hook review, and one fixture event.

ECC ships hooks for several different agent hosts. This adapter selects only
the documented Codex SessionStart registration for its bounded callback proof;
it does not translate Claude hooks into Hermes behavior or enable hooks merely
because their source files were copied.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.skill_handlers import HookReview, SkillAdapterError, review_host_hooks
from hermes_installer.components.skill_refs import SkillReferenceAudit, audit_skill_file_map


_SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_ECC_HOOK = "scripts/hooks/session-start-bootstrap.js"


@dataclass(frozen=True, slots=True)
class EccSkillSet:
    component_id: str
    revision: str
    eligible_skill_files: tuple[str, ...]
    excluded_skill_problems: tuple[tuple[str, tuple[str, ...]], ...]
    reference_audit: SkillReferenceAudit
    hook_review: HookReview
    host_hook_status: str = "unavailable_until_fixture_adapter_verified"

    @property
    def importable(self) -> bool:
        return bool(self.eligible_skill_files)


@dataclass(frozen=True, slots=True)
class EccHookFixtureResult:
    event: str
    session_id: str
    callback_path: str
    exit_code: int
    stdout: str
    stderr: str
    status: str = "fixture-verified; native registration pending"


def discover_ecc_skills(files: Mapping[str, bytes]) -> EccSkillSet:
    """Discover only skill roots whose own transitive references resolve.

    The pinned ECC repository contains intentionally illustrative links in
    many unrelated skills. They must not make every sibling unavailable, and
    they must not be silently hidden from the report. Each selected skill is
    audited against the full pinned tree and broken roots are listed exactly.
    """
    contract = resolve_component_adapter("ecc")
    if contract.component_id != "ecc" or "ecc" not in {alias.casefold() for alias in contract.aliases}:
        raise SkillAdapterError("ECC aliases do not resolve to the reviewed component")
    if not files or any(not isinstance(name, str) or not isinstance(body, bytes) for name, body in files.items()):
        raise SkillAdapterError("ECC source tree must be a non-empty byte map")

    skills = tuple(sorted(name for name in files if PurePosixPath(name).name == "SKILL.md"))
    audit = audit_skill_file_map(dict(files))
    # The common auditor returns a resolved closure for each skill. Attribute
    # each failure to roots whose own entrypoint or resolved closure contains
    # the Markdown file that owns it. This keeps the report proportional to a
    # single source pass even for ECC's 1,000+ skill tree.
    closure_by_skill = {
        skill: {skill, *targets}
        for skill, targets in audit.skill_resolved_targets
    }
    problems_by_skill: dict[str, list[str]] = {skill: [] for skill in skills}
    for issue in audit.problems:
        for skill, closure in closure_by_skill.items():
            if issue.source_path in closure:
                problems_by_skill[skill].append(
                    f"{issue.source_path}:{issue.line}: {issue.reason} ({issue.target})"
                )
    eligible = tuple(skill for skill in skills if not problems_by_skill[skill])
    excluded = tuple(
        (skill, tuple(reasons))
        for skill, reasons in sorted(problems_by_skill.items())
        if reasons
    )
    return EccSkillSet(
        component_id=contract.component_id,
        revision=contract.revision or "",
        eligible_skill_files=eligible,
        excluded_skill_problems=excluded,
        reference_audit=audit,
        hook_review=review_host_hooks(contract.component_id, files),
    )


def ecc_hook_status(*, fixture_proof: EccHookFixtureResult | None = None) -> tuple[bool, str]:
    """Keep hooks closed until a real callback fixture has produced an effect."""
    if fixture_proof is None or fixture_proof.status != "fixture-verified; native registration pending":
        return False, "Codex SessionStart hook unavailable until its selected adapter produces a fixture callback"
    return False, "fixture adapter verified; native host registration and target acceptance remain pending"


def _check_fixture_directory(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{label} must be a directory")
    return resolved


def invoke_codex_session_start_fixture(
    source_root: Path,
    project_dir: Path,
    home_dir: Path,
    *,
    node_executable: Path,
    session_id: str = "ecc-fixture-session",
    timeout_seconds: int = 10,
) -> EccHookFixtureResult:
    """Invoke ECC's selected SessionStart bootstrap in an isolated temp project.

    This is a host-hook adapter proof only. Both HOME and cwd must be owned
    temporary directories; the command is an absolute Node path plus a fixed
    relative script path, with no shell and a small sanitized environment.
    """
    contract = resolve_component_adapter("affaan-m/ECC")
    if contract.component_id != "ecc" or contract.revision is None:
        raise ValueError("ECC source pin is unresolved")
    root = _check_fixture_directory(Path(source_root), "ECC source root")
    project = _check_fixture_directory(Path(project_dir), "coding fixture")
    home = _check_fixture_directory(Path(home_dir), "fixture home")
    temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
    if not project.is_relative_to(temp_root) or not home.is_relative_to(temp_root):
        raise ValueError("coding fixture and fixture home must be inside the system temporary directory")
    if not _SESSION_ID.fullmatch(session_id):
        raise ValueError("fixture session ID is invalid")
    if not 1 <= timeout_seconds <= 30:
        raise ValueError("hook timeout must be between 1 and 30 seconds")
    raw_node = Path(node_executable)
    if raw_node.is_symlink():
        raise ValueError("Node executable must not be a symlink")
    try:
        node = raw_node.resolve(strict=True)
    except OSError:
        raise ValueError("Node executable is unavailable") from None
    if not node.is_file() or node.is_symlink():
        raise ValueError("Node executable must be a regular file")

    config_path = root / "hooks" / "codex-hooks.json"
    script = root / _ECC_HOOK
    provenance_path = root / "INSTALLER-SOURCE-PROVENANCE.json"
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise ValueError("ECC source tree has no verified installer provenance") from None
    if (provenance.get("component_id") != "ecc"
            or provenance.get("source_identity") != contract.source_identity
            or provenance.get("revision") != contract.revision):
        raise ValueError("ECC source tree provenance differs from the reviewed pin")
    files: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("ECC source tree contains a symlink")
        if path.is_file() and path != provenance_path:
            relative = path.relative_to(root).as_posix()
            files[relative] = path.read_bytes()
            modes[relative] = 0o755 if path.stat().st_mode & 0o111 else 0o644
    try:
        from hermes_installer.registry.source import _git_tree
        tree_sha, _ = _git_tree(files, modes)
    except Exception:
        raise ValueError("ECC source tree could not be reverified") from None
    if tree_sha != provenance.get("source_tree_sha"):
        raise ValueError("ECC source files differ from their pinned Git tree")
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise ValueError("pinned ECC Codex hook registration is unavailable") from None
    session_hooks = config.get("hooks", {}).get("SessionStart")
    registered = any(
        isinstance(entry, dict)
        and any(
            isinstance(hook, dict)
            and hook.get("type") == "command"
            and "scripts/hooks/session-start-bootstrap.js" in hook.get("command", "")
            for hook in entry.get("hooks", ())
        )
        for entry in session_hooks or ()
    )
    if not registered or not script.is_file() or script.is_symlink():
        raise ValueError("selected ECC Codex SessionStart callback is not present in the pinned source")
    lease_dir = project / ".observer-sessions"
    if lease_dir.is_symlink() or lease_dir.exists():
        raise ValueError("coding fixture already has an ECC callback directory")

    event = {
        "hook_event_name": "SessionStart",
        "source": "startup",
        "session_id": session_id,
        "cwd": str(project),
    }
    environment = {
        "HOME": str(home),
        "TMPDIR": str(home),
        "PATH": str(node.parent),
        "CLAUDE_PLUGIN_ROOT": str(root),
        "ECC_PLUGIN_ROOT": str(root),
        "CLAUDE_SESSION_ID": session_id,
        "ECC_SESSION_START_CONTEXT": "0",
        "ECC_SESSION_RETENTION_DAYS": "0",
    }
    try:
        completed = subprocess.run(
            [str(node), str(script)],
            input=json.dumps(event, separators=(",", ":")),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=project,
            env=environment,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("ECC SessionStart fixture hook exceeded its deadline") from None
    except OSError as exc:
        raise RuntimeError(f"ECC SessionStart fixture hook could not start: {exc}") from None

    lease = project / ".observer-sessions" / f"{session_id}.json"
    if lease.parent.is_symlink() or not lease.parent.is_dir():
        raise RuntimeError("ECC SessionStart fixture callback directory is not a private directory")
    if completed.returncode != 0 or not lease.is_file() or lease.is_symlink():
        raise RuntimeError("ECC SessionStart fixture did not produce its expected callback lease")
    try:
        receipt = json.loads(lease.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise RuntimeError("ECC SessionStart fixture callback lease is unreadable") from None
    if receipt.get("sessionId") != session_id or receipt.get("hook") != "SessionStart" or Path(receipt.get("cwd", "")) != project:
        raise RuntimeError("ECC SessionStart fixture callback receipt does not match its event")
    return EccHookFixtureResult(
        event="SessionStart",
        session_id=session_id,
        callback_path=lease.relative_to(project).as_posix(),
        exit_code=completed.returncode,
        stdout=completed.stdout[:8192],
        stderr=completed.stderr[:8192],
    )
