"""Stage the fixed Resources adapter through Hermes' official user-plugin seam.

This does not patch the pinned Hermes source. Staging is followed by Hermes'
official plugin-selection transaction under the fixed admin account; the
installer verifies the exact config delta and asks the same API to roll back
if that transaction changes unrelated settings.
"""
from __future__ import annotations

import hashlib
import importlib.resources
import os
import pwd
import secrets
import stat
import subprocess
import time
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
                                              gid=account.pw_gid, create=False)
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


_OFFICIAL_ENABLE_SCRIPT = r'''\
import copy
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
        cmd_enable(key, allow_tool_override=False)
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


__all__ = [
    "NativePluginBootstrapUnavailable", "PLUGIN_KEY", "StagedNativeResourcesPlugin",
    "stage_native_resources_plugin", "enable_native_resources_plugin",
]
