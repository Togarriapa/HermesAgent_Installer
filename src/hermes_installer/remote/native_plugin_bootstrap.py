"""Stage the fixed Resources adapter through Hermes' official user-plugin seam.

This does not patch the pinned Hermes source. Staging is followed by Hermes'
official plugin-selection transaction under the fixed admin account; the
installer verifies the exact config delta and restores only its owned selection
fields if that transaction changes unrelated settings.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.resources
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping


PLUGIN_KEY = "hermes-installer-resources-delegation"
PLUGIN_FILES = ("plugin.yaml", "__init__.py")
PLUGIN_BUNDLE = "hermes_installer.components.resources_native_plugin_bundle"
HERMES_HOME = Path("/home/admin/.hermes")
PLUGIN_PARENT = HERMES_HOME / "plugins"
PLUGIN_DIRECTORY = PLUGIN_PARENT / PLUGIN_KEY


class NativePluginBootstrapUnavailable(PermissionError):
    """The fixed native plugin could not be staged without changing unrelated data."""


@dataclass(frozen=True, slots=True)
class StagedNativeResourcesPlugin:
    """Receipt of the two fixed bytes staged for the official plugin loader."""

    plugin_key: str
    manifest_sha256: str
    module_sha256: str
    manifest_path: Path
    module_path: Path


@dataclass(frozen=True, slots=True)
class NativePluginSelectionReceipt:
    """Read-only projection of the official saved plugin and toolset selection."""

    plugin_key: str
    selection_sha256: str


@dataclass(frozen=True, slots=True)
class NativePluginSelectionBackup:
    """Bounded, non-secret prior selection needed to reverse core migration."""

    snapshot_json: bytes
    prior_selection_sha256: str
    migrated_selection_sha256: str


@dataclass(frozen=True, slots=True)
class NativeResourcesPluginTransitionReceipt:
    """Bounded observation of one Core-owned fixed plugin transition step.

    The receipt is evidence for CoreRuntime's journal only. It is not a grant
    and cannot be constructed through any public bootstrap operation.
    """

    schema: int
    operation: str
    cohort_transaction_id: str | None
    old_adapter_generation: str
    new_adapter_generation: str
    plugin_selection_sha256: str
    old_member_sha256: Mapping[str, str]
    new_member_sha256: Mapping[str, str]
    installed_member_sha256: Mapping[str, str]
    installed_member_signatures: Mapping[str, tuple[int, ...]]
    receipt_sha256: str


@dataclass(frozen=True, slots=True)
class NativeResourcesPluginMemberSnapshot:
    """Read-only fixed-path snapshot for CoreRuntime's pre-effect qualification."""

    members: Mapping[str, bytes]
    signatures: Mapping[str, tuple[int, ...]]


_TRANSITION_HASH_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


def _transition_stat_signature(info: os.stat_result) -> tuple[int, ...]:
    """Return the stable file identity tuple shared with CoreRuntime."""
    return (int(info.st_dev), int(info.st_ino), int(stat.S_IMODE(info.st_mode)),
            int(info.st_uid), int(info.st_gid), int(info.st_nlink), int(info.st_size),
            int(info.st_mtime_ns), int(info.st_ctime_ns))


def _read_transition_member(directory_fd: int, name: str) -> tuple[bytes, tuple[int, ...]]:
    """Read one fixed member and prove the opened inode stayed named while read."""
    if name not in PLUGIN_FILES:
        raise NativePluginBootstrapUnavailable("transition member name is not fixed")
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    except OSError:
        raise NativePluginBootstrapUnavailable("fixed plugin member is unavailable") from None
    try:
        before = os.fstat(fd)
        signature = _transition_stat_signature(before)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) != 0o444 or before.st_nlink != 1
                or before.st_size < 1 or before.st_size > 64 * 1024
                or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
                or stat.S_ISLNK(named.st_mode)):
            raise NativePluginBootstrapUnavailable("fixed plugin member custody changed")
        chunks = bytearray()
        while len(chunks) < before.st_size:
            block = os.read(fd, min(8192, before.st_size - len(chunks)))
            if not block:
                raise NativePluginBootstrapUnavailable("fixed plugin member changed while read")
            chunks.extend(block)
        if os.read(fd, 1):
            raise NativePluginBootstrapUnavailable("fixed plugin member changed while read")
        after = os.fstat(fd)
        named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (_transition_stat_signature(after) != signature
                or (named_after.st_dev, named_after.st_ino) != (before.st_dev, before.st_ino)
                or stat.S_ISLNK(named_after.st_mode)):
            raise NativePluginBootstrapUnavailable("fixed plugin member changed while read")
        return bytes(chunks), signature
    except NativePluginBootstrapUnavailable:
        raise
    except OSError:
        raise NativePluginBootstrapUnavailable("fixed plugin member changed while read") from None
    finally:
        os.close(fd)


def _transition_context(operation: str):
    """Read only the exact CoreRuntime-owned, lock-scoped transition context."""
    if os.name != "posix" or os.geteuid() != 0:
        raise NativePluginBootstrapUnavailable("native plugin transition requires root custody")
    try:
        from hermes_installer import core_runtime
        context_type = core_runtime._NativeResourcesPluginTransitionContext
        context = core_runtime._current_native_resources_plugin_transition()
    except (AttributeError, ImportError, RuntimeError):
        raise NativePluginBootstrapUnavailable("Core plugin transition context is unavailable") from None
    if type(context) is not context_type or context.operation != operation:
        raise NativePluginBootstrapUnavailable("Core plugin transition scope is not current")
    names = set(PLUGIN_FILES)
    try:
        if (type(context.old_members) is not MappingProxyType
                or type(context.new_members) is not MappingProxyType
                or set(context.old_members) != names or set(context.new_members) != names
                or type(context.installed_member_signatures) is not MappingProxyType
                or set(context.installed_member_signatures) != names):
            raise ValueError
        old_members = dict(context.old_members)
        new_members = dict(context.new_members)
        signatures = dict(context.installed_member_signatures)
        for members in (old_members, new_members):
            if any(type(value) is not bytes or not 1 <= len(value) <= 64 * 1024
                   for value in members.values()):
                raise ValueError
        if (old_members["plugin.yaml"] != new_members["plugin.yaml"]
                or old_members["__init__.py"] == new_members["__init__.py"]):
            raise ValueError
        for value in signatures.values():
            if (type(value) is not tuple or len(value) != 9
                    or any(type(part) is not int or part < 0 for part in value)):
                raise ValueError
        if (type(context.old_adapter_generation) is not str or not context.old_adapter_generation
                or len(context.old_adapter_generation) > 256
                or type(context.new_adapter_generation) is not str or not context.new_adapter_generation
                or len(context.new_adapter_generation) > 256
                or type(context.plugin_selection_sha256) is not str
                or _TRANSITION_HASH_RE.fullmatch(context.plugin_selection_sha256) is None):
            raise ValueError
        if operation == "prepare":
            if (context.cohort_transaction_id is not None or context.transition_row is not None
                    or context.backup_reference is not None or context.phase is not None):
                raise ValueError
        else:
            if (type(context.cohort_transaction_id) is not str
                    or not context.cohort_transaction_id or len(context.cohort_transaction_id) > 128
                    or context.transition_row is None or context.backup_reference is None
                    or type(context.phase) is not str or not context.phase):
                raise ValueError
    except (AttributeError, TypeError, ValueError):
        raise NativePluginBootstrapUnavailable("Core plugin transition context is malformed") from None
    return context, old_members, new_members, signatures


def _validate_transition_directory_names(directory_fd: int,
                                        allowed_temporaries: tuple[str, ...] = ()) -> None:
    allowed = set(PLUGIN_FILES) | set(allowed_temporaries)
    if (len(allowed) != len(PLUGIN_FILES) + len(allowed_temporaries)
            or set(os.listdir(directory_fd)) != allowed):
        raise NativePluginBootstrapUnavailable("fixed plugin directory contains unrelated files")


def _transition_plugin_directory_fd() -> int:
    """Open the existing fixed root-owned plugin directory without creating it."""
    try:
        account = pwd.getpwnam("admin")
        if (Path(account.pw_dir) != Path("/home/admin") or account.pw_uid != 1000
                or account.pw_gid != 1000):
            raise NativePluginBootstrapUnavailable("fixed Hermes account identity changed")
        root_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                          | getattr(os, "O_NOFOLLOW", 0))
        try:
            home_fd = _open_child_directory(root_fd, "home", uid=0, gid=0, create=False)
        finally:
            os.close(root_fd)
        try:
            admin_fd = _open_child_directory(home_fd, "admin", uid=account.pw_uid,
                                              gid=account.pw_gid,
                                              create=False)
        finally:
            os.close(home_fd)
        try:
            hermes_fd = _open_child_directory(admin_fd, ".hermes", uid=account.pw_uid,
                                              gid=account.pw_gid,
                                              create=False, exact_mode=0o700)
        finally:
            os.close(admin_fd)
        try:
            plugins_fd = _open_child_directory(hermes_fd, "plugins", uid=account.pw_uid,
                                                gid=account.pw_gid,
                                                create=False)
        finally:
            os.close(hermes_fd)
        try:
            plugin_fd = _open_child_directory(plugins_fd, PLUGIN_KEY, uid=0, gid=0,
                                              create=False, exact_mode=0o555)
        finally:
            os.close(plugins_fd)
        try:
            _validate_transition_directory_names(plugin_fd)
        except BaseException:
            os.close(plugin_fd)
            raise
        return plugin_fd
    except NativePluginBootstrapUnavailable:
        raise
    except OSError:
        raise NativePluginBootstrapUnavailable("fixed plugin path is not safely available") from None


def read_installed_native_resources_plugin_members() -> NativeResourcesPluginMemberSnapshot:
    """Read the installed fixed pair for a root-locked CoreRuntime qualification."""
    if os.name != "posix" or os.geteuid() != 0:
        raise NativePluginBootstrapUnavailable("plugin snapshot requires root custody")
    directory_fd = _transition_plugin_directory_fd()
    try:
        members, signatures = _transition_observe(directory_fd)
        return NativeResourcesPluginMemberSnapshot(
            members=MappingProxyType(members),
            signatures=MappingProxyType(signatures),
        )
    finally:
        os.close(directory_fd)


def _transition_member_sha256(members: Mapping[str, bytes]) -> dict[str, str]:
    if set(members) != set(PLUGIN_FILES):
        raise NativePluginBootstrapUnavailable("transition member set differs")
    return {name: hashlib.sha256(members[name]).hexdigest() for name in PLUGIN_FILES}


def _transition_receipt(context, operation: str, old_members: Mapping[str, bytes],
                         new_members: Mapping[str, bytes], installed: Mapping[str, bytes],
                         signatures: Mapping[str, tuple[int, ...]]) -> NativeResourcesPluginTransitionReceipt:
    old_hashes = _transition_member_sha256(old_members)
    new_hashes = _transition_member_sha256(new_members)
    installed_hashes = _transition_member_sha256(installed)
    stable_signatures = {name: tuple(signatures[name]) for name in PLUGIN_FILES}
    metadata = {
        "schema": 1,
        "operation": operation,
        "cohort_transaction_id": context.cohort_transaction_id,
        "old_adapter_generation": context.old_adapter_generation,
        "new_adapter_generation": context.new_adapter_generation,
        "plugin_selection_sha256": context.plugin_selection_sha256,
        "old_member_sha256": old_hashes,
        "new_member_sha256": new_hashes,
        "installed_member_sha256": installed_hashes,
        "installed_member_signatures": {name: list(stable_signatures[name]) for name in PLUGIN_FILES},
    }
    digest = hashlib.sha256(json.dumps(metadata, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=True).encode("ascii")).hexdigest()
    return NativeResourcesPluginTransitionReceipt(
        schema=1, operation=operation, cohort_transaction_id=context.cohort_transaction_id,
        old_adapter_generation=context.old_adapter_generation,
        new_adapter_generation=context.new_adapter_generation,
        plugin_selection_sha256=context.plugin_selection_sha256,
        old_member_sha256=MappingProxyType(old_hashes),
        new_member_sha256=MappingProxyType(new_hashes),
        installed_member_sha256=MappingProxyType(installed_hashes),
        installed_member_signatures=MappingProxyType(stable_signatures),
        receipt_sha256=digest,
    )


def _replace_transition_member(directory_fd: int, name: str, data: bytes,
                               expected_bytes: bytes, expected_signature: tuple[int, ...]) -> tuple[bytes, tuple[int, ...]]:
    """CAS one fixed member, then durably replace it with root:root0444 bytes."""
    current, signature = _read_transition_member(directory_fd, name)
    if current != expected_bytes or signature != expected_signature:
        raise NativePluginBootstrapUnavailable("plugin transition member CAS changed")
    temporary = f".{name}.{secrets.token_hex(12)}.transition"
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
    try:
        os.fchown(fd, 0, 0)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short write replacing native plugin member")
            view = view[count:]
        os.fchmod(fd, 0o444)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    os.close(fd)
    try:
        before_replace, before_signature = _read_transition_member(directory_fd, name)
        if before_replace != expected_bytes or before_signature != expected_signature:
            raise NativePluginBootstrapUnavailable("plugin transition member CAS changed")
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    try:
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    return _read_transition_member(directory_fd, name)


def _transition_observe(directory_fd: int) -> tuple[dict[str, bytes], dict[str, tuple[int, ...]]]:
    members: dict[str, bytes] = {}
    signatures: dict[str, tuple[int, ...]] = {}
    for name in PLUGIN_FILES:
        members[name], signatures[name] = _read_transition_member(directory_fd, name)
    return members, signatures


def prepare_native_resources_plugin_transition() -> NativeResourcesPluginTransitionReceipt:
    """Verify the old installed pair and report hashes without changing files."""
    context, old_members, new_members, expected_signatures = _transition_context("prepare")
    directory_fd = _transition_plugin_directory_fd()
    try:
        installed, signatures = _transition_observe(directory_fd)
        if installed != old_members or signatures != expected_signatures:
            raise NativePluginBootstrapUnavailable("installed plugin does not match the captured old bundle")
        return _transition_receipt(context, "prepare", old_members, new_members,
                                   installed, signatures)
    finally:
        os.close(directory_fd)


def install_native_resources_plugin_transition() -> NativeResourcesPluginTransitionReceipt:
    """Replace only the two stopped-Core plugin members after an exact old-pair CAS."""
    context, old_members, new_members, expected_signatures = _transition_context("install")
    directory_fd = _transition_plugin_directory_fd()
    try:
        installed, signatures = _transition_observe(directory_fd)
        if installed != old_members or signatures != expected_signatures:
            raise NativePluginBootstrapUnavailable("installed plugin changed before transition")
        # The old/new manifest is commonly byte-identical; retain its inode
        # and replace only members that actually differ in the reviewed bundle.
        for name in PLUGIN_FILES:
            if new_members[name] != old_members[name]:
                _replace_transition_member(directory_fd, name, new_members[name],
                                           old_members[name], expected_signatures[name])
        installed, signatures = _transition_observe(directory_fd)
        if installed != new_members:
            raise NativePluginBootstrapUnavailable("incoming plugin pair failed readback")
        return _transition_receipt(context, "install", old_members, new_members,
                                   installed, signatures)
    finally:
        os.close(directory_fd)


def restore_native_resources_plugin_transition() -> NativeResourcesPluginTransitionReceipt:
    """Restore backed-up old bytes from only an exact old/new per-member mixture."""
    context, old_members, new_members, expected_signatures = _transition_context("restore")
    directory_fd = _transition_plugin_directory_fd()
    try:
        installed, signatures = _transition_observe(directory_fd)
        for name in PLUGIN_FILES:
            if installed[name] not in (old_members[name], new_members[name]):
                raise NativePluginBootstrapUnavailable("installed plugin member is outside transition closure")
            if signatures[name] != expected_signatures[name]:
                raise NativePluginBootstrapUnavailable("installed plugin member custody changed")
        for name in PLUGIN_FILES:
            if installed[name] == new_members[name]:
                if installed[name] != old_members[name]:
                    installed[name], signatures[name] = _replace_transition_member(
                        directory_fd, name, old_members[name], installed[name], signatures[name])
        installed, signatures = _transition_observe(directory_fd)
        if installed != old_members:
            raise NativePluginBootstrapUnavailable("old plugin pair failed restore readback")
        return _transition_receipt(context, "restore", old_members, new_members,
                                   installed, signatures)
    finally:
        os.close(directory_fd)


def _fixed_bundle_bytes() -> dict[str, bytes]:
    root = importlib.resources.files(PLUGIN_BUNDLE)
    result: dict[str, bytes] = {}
    for name in PLUGIN_FILES:
        data = root.joinpath(name).read_bytes()
        if not data or len(data) > 64 * 1024:
            raise NativePluginBootstrapUnavailable("fixed plugin bundle member is unavailable")
        result[name] = data
    return result


def _open_child_directory(parent_fd: int, name: str, *, uid: int, gid: int,
                          create: bool, create_mode: int = 0o750,
                          exact_mode: int | None = None) -> int:
    """Open one relative directory without traversing a symlink; optionally create it."""
    if not name or name in {".", ".."} or "/" in name:
        raise NativePluginBootstrapUnavailable("fixed plugin path component is invalid")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
        os.mkdir(name, create_mode, dir_fd=parent_fd)
        fd = os.open(name, flags, dir_fd=parent_fd)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, create_mode)
    info = os.fstat(fd)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(named.st_mode)
            or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
            or info.st_uid != uid or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) & 0o022
            or (exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode)):
        os.close(fd)
        raise NativePluginBootstrapUnavailable("fixed Hermes plugin directory custody changed")
    return fd


def _read_member(directory_fd: int, name: str, *, uid: int, gid: int) -> bytes | None:
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1
                or info.st_size > 64 * 1024):
            raise NativePluginBootstrapUnavailable("fixed Hermes plugin member custody changed")
        chunks = bytearray()
        while len(chunks) < info.st_size:
            block = os.read(fd, min(8192, info.st_size - len(chunks)))
            if not block:
                raise NativePluginBootstrapUnavailable("fixed Hermes plugin member changed while read")
            chunks.extend(block)
        if os.read(fd, 1):
            raise NativePluginBootstrapUnavailable("fixed Hermes plugin member changed while read")
        return bytes(chunks)
    finally:
        os.close(fd)


def _write_member(directory_fd: int, name: str, data: bytes) -> None:
    temporary = f".{name}.{secrets.token_hex(12)}.tmp"
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
    try:
        os.fchown(fd, 0, 0)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short write staging native plugin")
            view = view[count:]
        os.fchmod(fd, 0o444)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(temporary, dir_fd=directory_fd)
        raise
    os.close(fd)
    os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)


def stage_native_resources_plugin() -> StagedNativeResourcesPlugin:
    """Atomically stage only the fixed plugin files; leave config and other plugins untouched."""
    if os.name != "posix" or os.geteuid() != 0:
        raise NativePluginBootstrapUnavailable("plugin staging requires the root installer bootstrap")
    try:
        account = pwd.getpwnam("admin")
    except KeyError:
        raise NativePluginBootstrapUnavailable("fixed Hermes account is unavailable") from None
    if Path(account.pw_dir) != Path("/home/admin"):
        raise NativePluginBootstrapUnavailable("fixed Hermes home identity changed")

    members = _fixed_bundle_bytes()
    try:
        root_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                          | getattr(os, "O_NOFOLLOW", 0))
        try:
            system_home_fd = _open_child_directory(root_fd, "home", uid=0, gid=0,
                                                   create=False)
        finally:
            os.close(root_fd)
        try:
            user_home_fd = _open_child_directory(system_home_fd, "admin", uid=account.pw_uid,
                                                 gid=account.pw_gid, create=False)
        finally:
            os.close(system_home_fd)
        try:
            hermes_fd = _open_child_directory(user_home_fd, ".hermes", uid=account.pw_uid,
                                              gid=account.pw_gid, create=False, exact_mode=0o700)
        finally:
            os.close(user_home_fd)
        try:
            parent_fd = _open_child_directory(hermes_fd, "plugins", uid=account.pw_uid,
                                              gid=account.pw_gid, create=True)
        finally:
            os.close(hermes_fd)
        try:
            plugin_fd = _open_child_directory(parent_fd, PLUGIN_KEY, uid=0, gid=0,
                                              create=True, create_mode=0o555,
                                              exact_mode=0o555)
        finally:
            os.close(parent_fd)
    except (OSError, PermissionError):
        raise NativePluginBootstrapUnavailable("fixed Hermes plugin path is not safely available") from None

    try:
        names = set(os.listdir(plugin_fd))
        if names - set(PLUGIN_FILES):
            raise NativePluginBootstrapUnavailable("fixed plugin directory contains unrelated files")
        for name, data in members.items():
            current = _read_member(plugin_fd, name, uid=0, gid=0)
            if current is None:
                _write_member(plugin_fd, name, data)
            elif current != data:
                raise NativePluginBootstrapUnavailable(
                    "fixed root-owned plugin bytes differ from the reviewed bundle")
    finally:
        os.close(plugin_fd)

    return StagedNativeResourcesPlugin(
        plugin_key=PLUGIN_KEY,
        manifest_sha256=hashlib.sha256(members["plugin.yaml"]).hexdigest(),
        module_sha256=hashlib.sha256(members["__init__.py"]).hexdigest(),
        manifest_path=PLUGIN_DIRECTORY / "plugin.yaml",
        module_path=PLUGIN_DIRECTORY / "__init__.py",
    )


_OFFICIAL_ENABLE_SCRIPT = r'''import copy
from hermes_cli.config import load_config
from hermes_cli.plugins_cmd import cmd_enable, cmd_disable
from hermes_cli.plugins_cmd import _toggle_plugin_toolset
from hermes_cli.toolset_validation import parse_platform_toolsets_value

key = "hermes-installer-resources-delegation"
toolset = "resources_internal"
def read():
    value = load_config()
    if not isinstance(value, dict):
        raise RuntimeError("Hermes config is unavailable")
    return value
def lists(config, field):
    plugins = config.get("plugins") or {}
    if not isinstance(plugins, dict):
        raise RuntimeError("Hermes plugin selection is malformed")
    value = plugins.get(field, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RuntimeError("Hermes plugin selection is malformed")
    return list(value)
before = read()
before_enabled, before_disabled = lists(before, "enabled"), lists(before, "disabled")
was_enabled = key in before_enabled and key not in before_disabled
if was_enabled:
    platforms = before.get("platform_toolsets")
    if isinstance(platforms, dict):
        for raw in platforms.values():
            parsed = parse_platform_toolsets_value(raw)
            if parsed is not None and toolset not in parsed:
                raise RuntimeError("already-enabled plugin has inconsistent saved tool selection")
expected_enabled = set(before_enabled) | {key}
expected_disabled = set(before_disabled) - {key}
expected = copy.deepcopy(before)
platforms = expected.get("platform_toolsets")
if not was_enabled and isinstance(platforms, dict):
    for platform, raw in list(platforms.items()):
        parsed = parse_platform_toolsets_value(raw)
        if parsed is not None and toolset not in parsed:
            platforms[platform] = [*parsed, toolset]
plugins = expected.setdefault("plugins", {})
plugins["enabled"] = sorted(expected_enabled)
plugins["disabled"] = sorted(expected_disabled)
try:
    if not was_enabled:
        # This plugin declares no tool overrides. `None` leaves any existing
        # grant untouched; an explicit False is an authorization change in
        # Hermes and can add a persisted denial entry to the user's config.
        cmd_enable(key, allow_tool_override=None)
    after = read()
    if after != expected:
        raise RuntimeError("official enable changed unrelated Hermes config")
except BaseException:
    if not was_enabled:
        try:
            cmd_disable(key)
            rolled_back = read()
            actual_plugins = rolled_back.get("plugins") or {}
            actual_enabled = actual_plugins.get("enabled", [])
            actual_disabled = actual_plugins.get("disabled", [])
            if (not isinstance(actual_enabled, list) or not isinstance(actual_disabled, list)
                    or set(actual_enabled) != set(before_enabled)
                    or set(actual_disabled) != set(before_disabled)):
                raise RuntimeError("official plugin-selection rollback did not restore prior keys")
            rollback_expected = copy.deepcopy(before)
            rollback_plugins = rollback_expected.get("plugins") or {}
            rollback_plugins["enabled"] = sorted(before_enabled)
            rollback_plugins["disabled"] = sorted(before_disabled)
            if rolled_back != rollback_expected:
                raise RuntimeError("official plugin-selection rollback changed unrelated config")
        except BaseException:
            raise RuntimeError("native plugin enable failed and official rollback is incomplete") from None
    raise
print("native-plugin-selection-verified")
'''


def enable_native_resources_plugin() -> StagedNativeResourcesPlugin:
    """Stage then enable only this plugin via Hermes' own transactional CLI API.

    The official API owns config persistence. Its exact before/after projection is
    checked in the target interpreter; if an unexpected delta occurs, the same
    official API disables the just-added key and checks the prior selection.
    """
    staged = stage_native_resources_plugin()
    from .core_gateway_inspector import (
        CORE_NATIVE_ADAPTER_SOURCE, CORE_PYTHON_LINK, CORE_SOURCE,
        _current_native_adapter_generation, verify_staged_native_resources_plugin,
    )

    deadline = time.monotonic() + 35.0
    adapter_generation = _current_native_adapter_generation(deadline=deadline)
    staged_digest = verify_staged_native_resources_plugin(deadline=deadline)
    if not adapter_generation or not isinstance(staged_digest, str) or len(staged_digest) != 64:
        raise NativePluginBootstrapUnavailable("reviewed native plugin generation is not current")
    try:
        account = pwd.getpwnam("admin")
        environment = {
            "HOME": "/home/admin",
            "HERMES_HOME": str(HERMES_HOME),
            "PATH": "/home/admin/.hermes/bin:/home/admin/.local/bin:/usr/local/bin:/usr/bin:/bin",
            "HERMES_DISABLE_LAZY_INSTALLS": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": f"{CORE_SOURCE}:{CORE_NATIVE_ADAPTER_SOURCE}",
        }
        result = subprocess.run(
            [str(CORE_PYTHON_LINK), "-B", "-c", _OFFICIAL_ENABLE_SCRIPT],
            cwd=CORE_SOURCE, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
            check=False, user=account.pw_uid, group=account.pw_gid, extra_groups=(),
        )
        if (result.returncode != 0 or len(result.stdout) > 64 * 1024
                or len(result.stderr) > 64 * 1024
                or b"native-plugin-selection-verified" not in result.stdout):
            raise NativePluginBootstrapUnavailable("official Hermes plugin enablement was not verified")
        if (_current_native_adapter_generation(deadline=deadline) != adapter_generation
                or verify_staged_native_resources_plugin(deadline=deadline) != staged_digest):
            raise NativePluginBootstrapUnavailable("native plugin source changed during activation")
    except NativePluginBootstrapUnavailable:
        raise
    except Exception:
        raise NativePluginBootstrapUnavailable("official Hermes plugin activation is unavailable") from None
    return staged


_OFFICIAL_SELECTION_READ_SCRIPT = r'''import hashlib
import json
from hermes_cli.config import load_config
from hermes_cli.toolset_validation import parse_platform_toolsets_value

key = "hermes-installer-resources-delegation"
toolset = "resources_internal"
config = load_config()
if not isinstance(config, dict):
    raise RuntimeError("Hermes config is unavailable")
plugins = config.get("plugins") or {}
if not isinstance(plugins, dict):
    raise RuntimeError("Hermes plugin selection is malformed")
enabled, disabled = plugins.get("enabled", []), plugins.get("disabled", [])
if (not isinstance(enabled, list) or not isinstance(disabled, list)
        or any(not isinstance(value, str) for value in (*enabled, *disabled))
        or key not in enabled or key in disabled):
    raise RuntimeError("fixed Resources plugin is not selected")
platforms = config.get("platform_toolsets") or {}
if not isinstance(platforms, dict):
    raise RuntimeError("Hermes toolset selection is malformed")
selected = {}
for name, raw in platforms.items():
    if not isinstance(name, str):
        raise RuntimeError("Hermes toolset selection is malformed")
    parsed = parse_platform_toolsets_value(raw)
    if raw is not None and parsed is None:
        raise RuntimeError("Hermes toolset selection is ambiguous")
    if parsed is not None:
        if toolset not in parsed:
            raise RuntimeError("fixed Resources toolset is not selected")
        selected[name] = sorted(set(parsed))
projection = {"enabled": sorted(set(enabled)), "disabled": sorted(set(disabled)),
              "platform_toolsets": selected}
digest = hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=True).encode("ascii")).hexdigest()
print("native-plugin-selection:" + digest)
'''


_OFFICIAL_SELECTION_BACKUP_SCRIPT = r'''import base64
import copy
import hashlib
import json
from hermes_cli.config import load_config
from hermes_cli.toolset_validation import parse_platform_toolsets_value

key = "hermes-installer-resources-delegation"
toolset = "resources_internal"
config = load_config()
if not isinstance(config, dict):
    raise RuntimeError("Hermes config is unavailable")
plugins_present = "plugins" in config
plugins = config.get("plugins") or {}
if not isinstance(plugins, dict):
    raise RuntimeError("Hermes plugin selection is malformed")
enabled_present, disabled_present = "enabled" in plugins, "disabled" in plugins
enabled, disabled = plugins.get("enabled", []), plugins.get("disabled", [])
if (not isinstance(enabled, list) or not isinstance(disabled, list)
        or any(not isinstance(value, str) for value in (*enabled, *disabled))
        or len(enabled) > 256 or len(disabled) > 256
        or len(set(enabled)) != len(enabled) or len(set(disabled)) != len(disabled)):
    raise RuntimeError("Hermes plugin selection is malformed")
platform_present = "platform_toolsets" in config
platforms = config.get("platform_toolsets") or {}
if not isinstance(platforms, dict) or len(platforms) > 64:
    raise RuntimeError("Hermes toolset selection is malformed")
for name, raw in platforms.items():
    if (not isinstance(name, str) or not name or len(name) > 128
            or (raw is not None and not isinstance(raw, (str, list)))
            or (isinstance(raw, list) and (len(raw) > 512
                or any(not isinstance(item, str) for item in raw)))):
        raise RuntimeError("Hermes toolset selection is malformed")
    parsed = parse_platform_toolsets_value(raw)
    if raw is not None and parsed is None:
        raise RuntimeError("Hermes toolset selection is ambiguous")
prior = {"schema": 1, "plugins_present": plugins_present,
         "enabled_present": enabled_present, "disabled_present": disabled_present,
         "enabled": enabled, "disabled": disabled,
         "platform_present": platform_present, "platform_toolsets": platforms}
def projection(value):
    pl = value.get("plugins") or {}
    selected = {}
    for name, raw in (value.get("platform_toolsets") or {}).items():
        parsed = parse_platform_toolsets_value(raw)
        if raw is not None and parsed is None:
            raise RuntimeError("Hermes toolset selection is ambiguous")
        if parsed is not None:
            selected[name] = sorted(set(parsed))
    return {"enabled": sorted(set(pl.get("enabled", []))),
            "disabled": sorted(set(pl.get("disabled", []))),
            "platform_toolsets": selected}
def digest(value):
    return hashlib.sha256(json.dumps(projection(value), sort_keys=True,
        separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
expected = copy.deepcopy(config)
was_enabled = key in enabled and key not in disabled
new_plugins = expected.setdefault("plugins", {})
new_plugins["enabled"] = sorted(set(enabled) | {key})
new_plugins["disabled"] = sorted(set(disabled) - {key})
new_platforms = expected.get("platform_toolsets")
if not was_enabled and isinstance(new_platforms, dict):
    for name, raw in list(new_platforms.items()):
        parsed = parse_platform_toolsets_value(raw)
        if parsed is not None and toolset not in parsed:
            new_platforms[name] = [*parsed, toolset]
prior_json = json.dumps(prior, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True).encode("ascii")
print("native-plugin-selection-backup:" + base64.b64encode(prior_json).decode("ascii")
      + ":" + digest(config) + ":" + digest(expected))
'''


_OFFICIAL_SELECTION_RESTORE_SCRIPT = r'''import base64
import copy
import hashlib
import json
import sys
from hermes_cli.config import load_config, save_config
from hermes_cli.plugins_cmd import cmd_disable
from hermes_cli.toolset_validation import parse_platform_toolsets_value

key = "hermes-installer-resources-delegation"
toolset = "resources_internal"
request = json.load(sys.stdin)
if (not isinstance(request, dict) or set(request) != {"snapshot_b64", "expected_current_sha256"}
        or not isinstance(request["snapshot_b64"], str)
        or (request["expected_current_sha256"] is not None
            and (not isinstance(request["expected_current_sha256"], str)
                 or len(request["expected_current_sha256"]) != 64))):
    raise RuntimeError("migration selection restore request is malformed")
prior = json.loads(base64.b64decode(request["snapshot_b64"], validate=True))
fields = {"schema", "plugins_present", "enabled_present", "disabled_present", "enabled",
          "disabled", "platform_present", "platform_toolsets"}
if (not isinstance(prior, dict) or set(prior) != fields or prior.get("schema") != 1
        or type(prior.get("plugins_present")) is not bool
        or type(prior.get("enabled_present")) is not bool
        or type(prior.get("disabled_present")) is not bool
        or type(prior.get("platform_present")) is not bool
        or not isinstance(prior.get("enabled"), list)
        or not isinstance(prior.get("disabled"), list)
        or not isinstance(prior.get("platform_toolsets"), dict)):
    raise RuntimeError("migration selection backup is malformed")
def projection(value):
    plugins = value.get("plugins") or {}
    selected = {}
    for name, raw in (value.get("platform_toolsets") or {}).items():
        parsed = parse_platform_toolsets_value(raw)
        if raw is not None and parsed is None:
            raise RuntimeError("Hermes toolset selection is ambiguous")
        if parsed is not None:
            selected[name] = sorted(set(parsed))
    return {"enabled": sorted(set(plugins.get("enabled", []))),
            "disabled": sorted(set(plugins.get("disabled", []))),
            "platform_toolsets": selected}
def digest(value):
    return hashlib.sha256(json.dumps(projection(value), sort_keys=True,
        separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
config = load_config()
if not isinstance(config, dict):
    raise RuntimeError("Hermes config is unavailable")
prior_projection = {"enabled": sorted(set(prior["enabled"])),
                    "disabled": sorted(set(prior["disabled"])), "platform_toolsets": {}}
for name, raw in prior["platform_toolsets"].items():
    parsed = parse_platform_toolsets_value(raw)
    if raw is not None and parsed is None:
        raise RuntimeError("prior platform toolset selection is ambiguous")
    if parsed is not None:
        prior_projection["platform_toolsets"][name] = sorted(set(parsed))
prior_digest = hashlib.sha256(json.dumps(prior_projection, sort_keys=True,
    separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
post_projection = copy.deepcopy(prior_projection)
was_enabled = key in prior["enabled"] and key not in prior["disabled"]
post_projection["enabled"] = sorted(set(prior["enabled"]) | {key})
post_projection["disabled"] = sorted(set(prior["disabled"]) - {key})
if not was_enabled:
    for platform, names in post_projection["platform_toolsets"].items():
        if toolset not in names:
            post_projection["platform_toolsets"][platform] = sorted(set((*names, toolset)))
post_digest = hashlib.sha256(json.dumps(post_projection, sort_keys=True,
    separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
current_digest = digest(config)
if request["expected_current_sha256"] is not None and request["expected_current_sha256"] != post_digest:
    raise RuntimeError("journal plugin selection digest differs from the fixed migration projection")
def restore_prior_selection(current):
    # The snapshot owns only plugin enablement and platform toolset selection.
    # Start from the live config so unrelated current settings and any newer
    # grant metadata survive the narrow recovery write.
    restored = copy.deepcopy(current)
    restored_plugins = restored.get("plugins")
    if not isinstance(restored_plugins, dict):
        restored_plugins = {}
        restored["plugins"] = restored_plugins
    for name, present, value in (("enabled", prior["enabled_present"], prior["enabled"]),
                                 ("disabled", prior["disabled_present"], prior["disabled"])):
        if present:
            restored_plugins[name] = value
        else:
            restored_plugins.pop(name, None)
    if not prior["plugins_present"] and not restored_plugins:
        restored.pop("plugins", None)
    if prior["platform_present"]:
        restored["platform_toolsets"] = prior["platform_toolsets"]
    else:
        restored.pop("platform_toolsets", None)
    save_config(restored)
    verified = load_config()
    if verified != restored or digest(verified) != prior_digest:
        raise RuntimeError("prior native plugin selection did not restore exactly")
    return verified
if current_digest == prior_digest:
    original_plugins = config.get("plugins") or {}
    if (("plugins" in config) != prior["plugins_present"]
            or (("enabled" in original_plugins) != prior["enabled_present"])
            or (("disabled" in original_plugins) != prior["disabled_present"])
            or original_plugins.get("enabled", []) != prior["enabled"]
            or original_plugins.get("disabled", []) != prior["disabled"]
            or (("platform_toolsets" in config) != prior["platform_present"])
            or (config.get("platform_toolsets") or {}) != prior["platform_toolsets"]):
        raise RuntimeError("plugin selection has same effective grants but different saved form")
    print("native-plugin-selection-restored:" + prior_digest)
    sys.exit(0)
if current_digest != post_digest:
    # cmd_disable, used by the previous interrupted enable transaction, writes
    # both selection arrays even when the original config omitted them. Accept
    # only that exact derived rollback state; unknown selection changes remain
    # a hard CAS conflict.
    current_plugins = config.get("plugins")
    current_enabled = current_plugins.get("enabled") if isinstance(current_plugins, dict) else None
    current_disabled = current_plugins.get("disabled") if isinstance(current_plugins, dict) else None
    failed_enable_rollback = (
        not was_enabled and isinstance(current_plugins, dict)
        and ("plugins" in config)
        and "enabled" in current_plugins and "disabled" in current_plugins
        and isinstance(current_enabled, list) and isinstance(current_disabled, list)
        and all(isinstance(item, str) for item in (*current_enabled, *current_disabled))
        and len(set(current_enabled)) == len(current_enabled)
        and len(set(current_disabled)) == len(current_disabled)
        and set(current_enabled) == (set(prior["enabled"]) - {key})
        and set(current_disabled) == (set(prior["disabled"]) | {key})
        and (("platform_toolsets" in config) == prior["platform_present"])
        and (config.get("platform_toolsets") or {}) == prior["platform_toolsets"])
    if not failed_enable_rollback:
        raise RuntimeError("current plugin selection changed since migration")
    verified = restore_prior_selection(config)
    print("native-plugin-selection-restored:" + digest(verified))
    sys.exit(0)
plugins = config.get("plugins") or {}
enabled, disabled = plugins.get("enabled", []), plugins.get("disabled", [])
platforms = config.get("platform_toolsets") or {}
if (key not in enabled or key in disabled or not isinstance(platforms, dict)
        or any((parsed := parse_platform_toolsets_value(raw)) is not None and toolset not in parsed
               for raw in platforms.values())):
    raise RuntimeError("migrated native plugin selection is not exact")
if not was_enabled:
    cmd_disable(key)
current = load_config()
if not isinstance(current, dict):
    raise RuntimeError("Hermes config is unavailable after plugin disable")
verified = restore_prior_selection(current)
print("native-plugin-selection-restored:" + digest(verified))
'''


def verify_native_resources_plugin_selection() -> NativePluginSelectionReceipt:
    """Read current PM-owned enable/toolset selection without changing Hermes config.

    This receipt proves saved selection only. The live native ToolEntry, observer
    route and root-issued delegation claim remain independent checks.
    """
    from .core_gateway_inspector import CORE_NATIVE_ADAPTER_SOURCE, CORE_PYTHON_LINK, CORE_SOURCE

    try:
        account = pwd.getpwnam("admin")
        environment = {
            "HOME": "/home/admin",
            "HERMES_HOME": str(HERMES_HOME),
            "PATH": "/home/admin/.hermes/bin:/home/admin/.local/bin:/usr/local/bin:/usr/bin:/bin",
            "HERMES_DISABLE_LAZY_INSTALLS": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": f"{CORE_SOURCE}:{CORE_NATIVE_ADAPTER_SOURCE}",
        }
        result = subprocess.run(
            [str(CORE_PYTHON_LINK), "-B", "-c", _OFFICIAL_SELECTION_READ_SCRIPT],
            cwd=CORE_SOURCE, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            check=False, user=account.pw_uid, group=account.pw_gid, extra_groups=(),
        )
        prefix = b"native-plugin-selection:"
        if result.returncode != 0 or len(result.stdout) > 1024 or len(result.stderr) > 16 * 1024:
            raise NativePluginBootstrapUnavailable("official native plugin selection is not current")
        lines = result.stdout.strip().splitlines()
        if len(lines) != 1 or not lines[0].startswith(prefix):
            raise NativePluginBootstrapUnavailable("official native plugin selection is malformed")
        digest = lines[0][len(prefix):].decode("ascii", "strict")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise NativePluginBootstrapUnavailable("official native plugin selection is malformed")
        return NativePluginSelectionReceipt(PLUGIN_KEY, digest)
    except NativePluginBootstrapUnavailable:
        raise
    except Exception:
        raise NativePluginBootstrapUnavailable("official native plugin selection is unavailable") from None


def _run_official_selection_script(script: str, *, input_bytes: bytes | None = None,
                                   timeout: int = 10) -> subprocess.CompletedProcess:
    from .core_gateway_inspector import CORE_NATIVE_ADAPTER_SOURCE, CORE_PYTHON_LINK, CORE_SOURCE
    account = pwd.getpwnam("admin")
    environment = {
        "HOME": "/home/admin", "HERMES_HOME": str(HERMES_HOME),
        "PATH": "/home/admin/.hermes/bin:/home/admin/.local/bin:/usr/local/bin:/usr/bin:/bin",
        "HERMES_DISABLE_LAZY_INSTALLS": "1", "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": f"{CORE_SOURCE}:{CORE_NATIVE_ADAPTER_SOURCE}",
    }
    return subprocess.run(
        [str(CORE_PYTHON_LINK), "-B", "-c", script], cwd=CORE_SOURCE,
        env=environment, input=input_bytes, stdin=subprocess.DEVNULL if input_bytes is None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
        user=account.pw_uid, group=account.pw_gid, extra_groups=(),
    )


def capture_native_resources_plugin_selection() -> NativePluginSelectionBackup:
    """Capture exact pre-migration selection in a small non-secret root-journal payload."""
    from .core_gateway_inspector import _current_native_adapter_generation
    deadline = time.monotonic() + 35.0
    generation = _current_native_adapter_generation(deadline=deadline)
    try:
        result = _run_official_selection_script(_OFFICIAL_SELECTION_BACKUP_SCRIPT, timeout=10)
        prefix = b"native-plugin-selection-backup:"
        if result.returncode != 0 or len(result.stdout) > 64 * 1024 or len(result.stderr) > 16 * 1024:
            raise ValueError
        lines = result.stdout.strip().splitlines()
        if len(lines) != 1 or not lines[0].startswith(prefix):
            raise ValueError
        encoded, prior_digest, migrated_digest = lines[0][len(prefix):].decode("ascii", "strict").split(":")
        snapshot = base64.b64decode(encoded, validate=True)
        if len(snapshot) > 32 * 1024:
            raise ValueError
        value = json.loads(snapshot.decode("ascii", "strict"))
        expected = {"schema", "plugins_present", "enabled_present", "disabled_present", "enabled",
                    "disabled", "platform_present", "platform_toolsets"}
        if (not isinstance(value, dict) or set(value) != expected or value["schema"] != 1
                or any(type(value[key]) is not bool for key in (
                    "plugins_present", "enabled_present", "disabled_present", "platform_present"))
                or not isinstance(value["enabled"], list) or not isinstance(value["disabled"], list)
                or not isinstance(value["platform_toolsets"], dict)
                or any(not isinstance(item, str) for item in (*value["enabled"], *value["disabled"]))
                or json.dumps(value, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True).encode("ascii") != snapshot
                or not re.fullmatch(r"[0-9a-f]{64}", prior_digest)
                or not re.fullmatch(r"[0-9a-f]{64}", migrated_digest)
                or _current_native_adapter_generation(deadline=deadline) != generation):
            raise ValueError
        return NativePluginSelectionBackup(snapshot, prior_digest, migrated_digest)
    except NativePluginBootstrapUnavailable:
        raise
    except Exception:
        raise NativePluginBootstrapUnavailable("prior Hermes plugin selection could not be safely journaled") from None


def restore_native_resources_plugin_selection(snapshot_json: bytes, *,
                                               expected_current_sha256: str | None) -> str:
    """Restore only the prior plugin/toolset selection through Hermes' official config API."""
    from .core_gateway_inspector import _current_native_adapter_generation
    if (not isinstance(snapshot_json, bytes) or not 1 <= len(snapshot_json) <= 32 * 1024
            or (expected_current_sha256 is not None
                and re.fullmatch(r"[0-9a-f]{64}", expected_current_sha256) is None)):
        raise NativePluginBootstrapUnavailable("journaled plugin selection backup is malformed")
    try:
        generation = _current_native_adapter_generation(deadline=time.monotonic() + 35.0)
        payload = json.dumps({
            "snapshot_b64": base64.b64encode(snapshot_json).decode("ascii"),
            "expected_current_sha256": expected_current_sha256,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        result = _run_official_selection_script(
            _OFFICIAL_SELECTION_RESTORE_SCRIPT, input_bytes=payload, timeout=15)
        prefix = b"native-plugin-selection-restored:"
        if (result.returncode != 0 or len(result.stdout) > 1024 or len(result.stderr) > 16 * 1024
                or len(result.stdout.strip().splitlines()) != 1
                or not result.stdout.strip().startswith(prefix)):
            raise ValueError
        digest = result.stdout.strip()[len(prefix):].decode("ascii", "strict")
        if (re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or _current_native_adapter_generation(deadline=time.monotonic() + 35.0) != generation):
            raise ValueError
        return digest
    except NativePluginBootstrapUnavailable:
        raise
    except Exception:
        raise NativePluginBootstrapUnavailable("prior Hermes plugin selection did not restore exactly") from None


__all__ = [
    "NativePluginBootstrapUnavailable", "NativePluginSelectionReceipt", "PLUGIN_KEY",
    "StagedNativeResourcesPlugin", "stage_native_resources_plugin",
    "NativeResourcesPluginMemberSnapshot", "NativeResourcesPluginTransitionReceipt",
    "read_installed_native_resources_plugin_members",
    "prepare_native_resources_plugin_transition", "install_native_resources_plugin_transition",
    "restore_native_resources_plugin_transition",
    "NativePluginSelectionBackup", "enable_native_resources_plugin",
    "verify_native_resources_plugin_selection", "capture_native_resources_plugin_selection",
    "restore_native_resources_plugin_selection",
]
