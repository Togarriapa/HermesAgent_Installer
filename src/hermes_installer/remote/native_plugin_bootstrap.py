"""Stage the fixed Resources adapter through Hermes' official user-plugin seam.

This does not patch the pinned Hermes source or mutate plugin selection. After
staging, an operator may explicitly select the fixed key with Hermes' supported
``plugins enable`` command, which owns its transactional config update.
"""
from __future__ import annotations

import hashlib
import importlib.resources
import os
import pwd
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path


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
                          create: bool) -> int:
    """Open one relative directory without traversing a symlink; optionally create it."""
    if not name or name in {".", ".."} or "/" in name:
        raise NativePluginBootstrapUnavailable("fixed plugin path component is invalid")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
        os.mkdir(name, 0o750, dir_fd=parent_fd)
        fd = os.open(name, flags, dir_fd=parent_fd)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o750)
    info = os.fstat(fd)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(named.st_mode)
            or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
            or info.st_uid != uid or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) & 0o022):
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


def _write_member(directory_fd: int, name: str, data: bytes, *, uid: int, gid: int) -> None:
    temporary = f".{name}.{secrets.token_hex(12)}.tmp"
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
    try:
        os.fchown(fd, uid, gid)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short write staging native plugin")
            view = view[count:]
        os.fchmod(fd, 0o644)
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
                                              gid=account.pw_gid, create=False)
        finally:
            os.close(user_home_fd)
        try:
            parent_fd = _open_child_directory(hermes_fd, "plugins", uid=account.pw_uid,
                                              gid=account.pw_gid, create=True)
        finally:
            os.close(hermes_fd)
        try:
            plugin_fd = _open_child_directory(parent_fd, PLUGIN_KEY, uid=account.pw_uid,
                                              gid=account.pw_gid, create=True)
        finally:
            os.close(parent_fd)
    except (OSError, PermissionError):
        raise NativePluginBootstrapUnavailable("fixed Hermes plugin path is not safely available") from None

    try:
        names = set(os.listdir(plugin_fd))
        if names - set(PLUGIN_FILES):
            raise NativePluginBootstrapUnavailable("fixed plugin directory contains unrelated files")
        for name, data in members.items():
            current = _read_member(plugin_fd, name, uid=account.pw_uid, gid=account.pw_gid)
            if current != data:
                _write_member(plugin_fd, name, data, uid=account.pw_uid, gid=account.pw_gid)
    finally:
        os.close(plugin_fd)

    return StagedNativeResourcesPlugin(
        plugin_key=PLUGIN_KEY,
        manifest_sha256=hashlib.sha256(members["plugin.yaml"]).hexdigest(),
        module_sha256=hashlib.sha256(members["__init__.py"]).hexdigest(),
        manifest_path=PLUGIN_DIRECTORY / "plugin.yaml",
        module_path=PLUGIN_DIRECTORY / "__init__.py",
    )


__all__ = [
    "NativePluginBootstrapUnavailable", "PLUGIN_KEY", "StagedNativeResourcesPlugin",
    "stage_native_resources_plugin",
]
