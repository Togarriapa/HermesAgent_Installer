"""ECC source adapter: portable skills, inert hook review, and one fixture event.

ECC ships hooks for several different agent hosts. This adapter selects only
the documented Codex SessionStart registration for its bounded callback proof;
it does not translate Claude hooks into Hermes behavior or enable hooks merely
because their source files were copied.
"""
from __future__ import annotations

import json
import hashlib
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


def stage_ecc_skills_for_profile(
    source: object,
    store: object,
    *,
    profile_id: str,
    profile_data_root: Path,
    selected_skill_files: tuple[str, ...] | None = None,
):
    """Stage only complete reviewed ECC skill closures for one profile.

    The full immutable source generation remains available for audit. The
    profile-facing ``external_dirs`` generation contains only eligible skill
    roots and their transitive references; broken sibling skills are recorded
    in the installer selection manifest and never exposed to Hermes discovery.
    """
    from hermes_installer.components.skill_binding import ComponentSkillBinding
    from hermes_installer.components.source_bundle import VerifiedComponentSource
    from hermes_installer.components.runtime_source import bind_component_runtime_source

    contract = resolve_component_adapter("ecc")
    if (not isinstance(source, VerifiedComponentSource)
            or source.component_id != contract.component_id
            or source.source_identity != contract.source_identity
            or source.revision != contract.revision):
        raise SkillAdapterError("ECC staging requires the complete selected verified source bundle")
    if not isinstance(profile_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", profile_id):
        raise SkillAdapterError("profile id is not a safe native profile identifier")
    profile_root = Path(profile_data_root)
    try:
        if profile_root.is_symlink() or profile_root.resolve(strict=True) != profile_root:
            raise SkillAdapterError("profile data root must be canonical and symlink-free")
        if store.owned.root.resolve(strict=True) != profile_root:
            raise SkillAdapterError("ECC generation store is not rooted in the selected profile")
    except (OSError, AttributeError):
        raise SkillAdapterError("selected profile data root is not initialized") from None

    # This stages and fully re-verifies the original tree, including quarantined
    # skills, before selecting any profile-facing subset.
    bind_component_runtime_source(source, store, component_id="ecc")
    skill_set = discover_ecc_skills(source.files)
    eligible = set(skill_set.eligible_skill_files)
    selected = tuple(sorted(eligible if selected_skill_files is None else set(selected_skill_files)))
    if not selected or not set(selected).issubset(eligible):
        raise SkillAdapterError("ECC selection must contain only complete eligible pinned skill roots")

    references = dict(skill_set.reference_audit.skill_resolved_targets)
    selected_paths: set[str] = set()
    for skill_file in selected:
        selected_paths.add(skill_file)
        for target in references.get(skill_file, ()):
            if target in source.files:
                selected_paths.add(target)
            else:
                prefix = target.rstrip("/") + "/"
                descendants = {name for name in source.files if name.startswith(prefix)}
                if not descendants:
                    raise SkillAdapterError("ECC reference closure changed after source verification")
                selected_paths.update(descendants)
    selected_paths.update(
        name for name in source.files
        if PurePosixPath(name).name.casefold().startswith(("license", "copying", "notice"))
    )
    selected_paths.add("INSTALLER-SOURCE-PROVENANCE.json")
    missing = selected_paths - set(source.files)
    if missing:
        raise SkillAdapterError("ECC source closure contains a missing file")
    extra_roots = {
        name for name in selected_paths
        if PurePosixPath(name).name == "SKILL.md" and name not in selected
    }
    if extra_roots:
        raise SkillAdapterError("ECC skill closure crosses into a separate skill root")

    from hermes_installer.components.skill_handlers import discover_component_skills
    selected_discovery = discover_component_skills("ecc", source.files, skill_files=selected)
    if not selected_discovery.importable:
        raise SkillAdapterError("selected ECC skill closure failed its independent reference audit")
    filtered_files = {name: source.files[name] for name in sorted(selected_paths)}
    selection_document = {
        "schema": 1,
        "component_id": "ecc",
        "source_identity": source.source_identity,
        "source_revision": source.revision,
        "source_git_tree_sha": source.source_tree_sha,
        "selected_skill_files": list(selected),
        "quarantined_skill_problems": [
            {"skill_file": skill, "problems": list(problems)}
            for skill, problems in skill_set.excluded_skill_problems
        ],
    }
    selection_bytes = json.dumps(selection_document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    selection_path = "INSTALLER-ECC-SKILL-SELECTION.json"
    if selection_path in filtered_files:
        raise SkillAdapterError("ECC source collides with the installer skill-selection manifest")
    filtered_files[selection_path] = selection_bytes
    digest = hashlib.sha256()
    for name, body in sorted(filtered_files.items()):
        digest.update(name.encode("utf-8") + b"\0" + hashlib.sha256(body).digest())
    generation_id = f"ecc-skills-{source.revision[:12]}-{digest.hexdigest()[:12]}"
    modes = {name: source.file_modes.get(name, 0o644) for name in filtered_files}
    modes[selection_path] = 0o644
    staged = store.stage(generation_id, filtered_files, file_modes=modes).resolve(strict=True)
    try:
        verified_root, manifest, _generation_digest = store._verify(generation_id)
        expected_files = {
            name: {
                "sha256": hashlib.sha256(body).hexdigest(),
                "mode": store._private_mode(modes[name]),
            }
            for name, body in filtered_files.items()
        }
        if (verified_root.resolve(strict=True) != staged or staged.is_symlink()
                or not staged.is_relative_to(store.root.resolve(strict=True))
                or manifest.get("files") != expected_files):
            raise SkillAdapterError("staged ECC profile generation failed ownership or content verification")
    except SkillAdapterError:
        raise
    except Exception as exc:
        raise SkillAdapterError("staged ECC profile generation failed ownership or content verification") from exc
    actual = {
        path.relative_to(staged).as_posix(): path.read_bytes()
        for path in staged.rglob("*") if path.is_file()
    }
    actual_discovery = discover_component_skills("ecc", actual, skill_files=selected)
    if (not actual_discovery.importable
            or tuple(item.skill_file for item in actual_discovery.skills) != selected):
        raise SkillAdapterError("staged ECC profile skill closure differs from the audited selection")
    source_digest = hashlib.sha256()
    for name in sorted(source.files):
        source_digest.update(name.encode("utf-8") + b"\0")
        source_digest.update(hashlib.sha256(source.files[name]).digest())
    return ComponentSkillBinding(
        profile_id=profile_id, component_id="ecc", source_identity=source.source_identity,
        revision=source.revision, external_dir=staged, skill_files=selected,
        names=tuple(item.name for item in actual_discovery.skills),
        source_sha256=source_digest.hexdigest(),
        redistribution_license_review_required=source.redistribution_license_review_required,
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
