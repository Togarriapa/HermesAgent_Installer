"""Bind a verified component source to one installer-owned profile root.

The returned path is an input to the reviewed Hermes profile writer. This
module never edits HERMES_HOME or runs source hooks.
"""
from __future__ import annotations

import hashlib
import fcntl
import os
import re
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import yaml

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.skill_handlers import discover_component_skills
from hermes_installer.components.source_bundle import ComponentSourceError, VerifiedComponentSource
from hermes_installer.registry.generation import GenerationStore


class ComponentBindingError(ValueError):
    """A component cannot be safely exposed to the selected profile."""


@dataclass(frozen=True, slots=True)
class SelectedProfileConfigTarget:
    """Protected installer resolution of the one profile selected for this operation.

    Only the trusted installer/native-loader integration may provide this
    value. In particular, plugin arguments and component declarations must
    never choose ``profile_id`` or either path.
    """

    profile_id: str
    hermes_home: Path
    profile_data_root: Path
    owner_uid: int


class SelectedProfileConfigResolver(Protocol):
    """Root-owned resolver; it selects the active profile without caller input."""

    def resolve_selected_profile(self) -> SelectedProfileConfigTarget | None: ...


@dataclass(frozen=True, slots=True)
class SkillConfigWriteReceipt:
    profile_id: str
    config_path: Path
    previous_sha256: str | None
    config_sha256: str
    external_dir: str
    status: str = "configured_pending_native_discovery"


_MAX_PROFILE_CONFIG_BYTES = 1_048_576


def _read_profile_config(path: Path, owner_uid: int) -> bytes | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise ComponentBindingError("selected profile config cannot be inspected") from None
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner_uid or info.st_mode & 0o077
            or info.st_size > _MAX_PROFILE_CONFIG_BYTES):
        raise ComponentBindingError("selected profile config is not a private owner-controlled file")
    try:
        data = path.read_bytes()
    except OSError:
        raise ComponentBindingError("selected profile config cannot be read") from None
    if len(data) > _MAX_PROFILE_CONFIG_BYTES:
        raise ComponentBindingError("selected profile config exceeds the size limit")
    return data


def _merge_external_dir(config_bytes: bytes | None, external_entry: str) -> bytes:
    if config_bytes is None:
        document: object = {}
    else:
        try:
            document = yaml.safe_load(config_bytes.decode("utf-8-sig"))
        except (UnicodeDecodeError, yaml.YAMLError):
            raise ComponentBindingError("selected profile config is not valid safe UTF-8 YAML") from None
        if document is None:
            document = {}
    if not isinstance(document, dict):
        raise ComponentBindingError("selected profile config root must be a mapping")
    merged = dict(document)
    skills_value = merged.get("skills", {})
    if not isinstance(skills_value, dict):
        raise ComponentBindingError("selected profile skills config must be a mapping")
    skills = dict(skills_value)
    current = skills.get("external_dirs", [])
    if isinstance(current, str):
        current = [current]
    if not isinstance(current, list) or any(not isinstance(entry, str) for entry in current):
        raise ComponentBindingError("selected profile skills.external_dirs must be a string or string list")
    entries = list(current)
    if external_entry not in entries:
        entries.append(external_entry)
    skills["external_dirs"] = entries
    merged["skills"] = skills
    try:
        rendered = yaml.safe_dump(merged, sort_keys=False, allow_unicode=True).encode("utf-8")
    except yaml.YAMLError:
        raise ComponentBindingError("selected profile config cannot be safely rendered") from None
    if len(rendered) > _MAX_PROFILE_CONFIG_BYTES:
        raise ComponentBindingError("merged selected profile config exceeds the size limit")
    return rendered


def configure_selected_profile_skill(
    binding: ComponentSkillBinding,
    resolver: SelectedProfileConfigResolver,
    *,
    expected_config_sha256: str | None,
) -> SkillConfigWriteReceipt:
    """Atomically append a staged component root to the protected selected profile.

    The caller supplies only a binding and an expected config revision. Profile
    identity and paths come from the no-argument trusted resolver. Passing
    ``None`` as the expected revision is required when config.yaml is absent.
    Existing settings and external roots are retained; unexpected concurrent
    edits fail with a retryable conflict instead of being overwritten.
    """
    if not callable(getattr(resolver, "resolve_selected_profile", None)):
        raise ComponentBindingError("trusted selected-profile resolver is required")
    target = resolver.resolve_selected_profile()
    if not isinstance(target, SelectedProfileConfigTarget):
        raise ComponentBindingError("trusted selected profile is unavailable")
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", target.profile_id)
            or binding.profile_id != target.profile_id):
        raise ComponentBindingError("component binding does not match the protected selected profile")
    if type(target.owner_uid) is not int or target.owner_uid != os.geteuid():
        raise ComponentBindingError("selected profile must be owned by the installer user")
    home = target.hermes_home
    data_root = target.profile_data_root
    if not isinstance(home, Path) or not isinstance(data_root, Path) or not home.is_absolute() or not data_root.is_absolute():
        raise ComponentBindingError("selected profile resolver returned invalid paths")
    try:
        if home.resolve(strict=True) != home or data_root.resolve(strict=True) != data_root:
            raise ComponentBindingError("selected profile paths may not contain symlinks")
        if not binding.external_dir.is_absolute() or binding.external_dir.resolve(strict=True) != binding.external_dir:
            raise ComponentBindingError("component generation path is not canonical")
        if binding.external_dir.is_symlink() or not binding.external_dir.is_dir():
            raise ComponentBindingError("component generation is not an existing directory")
        if not binding.external_dir.is_relative_to(data_root):
            raise ComponentBindingError("component generation escaped its installer-owned profile data root")
        home_info, data_info = home.lstat(), data_root.lstat()
    except OSError:
        raise ComponentBindingError("selected profile paths are unavailable") from None
    for info in (home_info, data_info):
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != target.owner_uid or info.st_mode & 0o077):
            raise ComponentBindingError("selected profile roots are not private and owner-controlled")
    if expected_config_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", expected_config_sha256):
        raise ComponentBindingError("expected selected profile config revision is invalid")

    # Hermes' pinned get_config_path() is get_hermes_home()/config.yaml;
    # external_dirs entries are resolved relative to that same home.
    config_path = home / "config.yaml"
    external_entry = binding.external_dir.relative_to(home).as_posix() if binding.external_dir.is_relative_to(home) else str(binding.external_dir)
    lock_path = home / ".installer-skills-config.lock"
    temporary: Path | None = None
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError:
        raise ComponentBindingError("cannot open the private selected profile config lock") from None
    try:
        lock_info = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != target.owner_uid
                or lock_info.st_mode & 0o077):
            raise ComponentBindingError("selected profile config lock is not private")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        old = _read_profile_config(config_path, target.owner_uid)
        old_digest = hashlib.sha256(old).hexdigest() if old is not None else None
        if old_digest != expected_config_sha256:
            raise ComponentBindingError("selected profile config revision changed; retry from a fresh resolver snapshot")
        payload = _merge_external_dir(old, external_entry)
        temporary = home / f".config.yaml.skills-{uuid.uuid4().hex}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if _read_profile_config(config_path, target.owner_uid) != old:
            raise ComponentBindingError("selected profile config changed during write; retry from a fresh snapshot")
        os.replace(temporary, config_path)
        temporary = None
        directory_fd = os.open(home, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return SkillConfigWriteReceipt(
            profile_id=target.profile_id,
            config_path=config_path,
            previous_sha256=old_digest,
            config_sha256=hashlib.sha256(payload).hexdigest(),
            external_dir=external_entry,
        )
    except ComponentBindingError:
        raise
    except OSError:
        raise ComponentBindingError("selected profile config write failed") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
        os.close(lock_fd)


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
