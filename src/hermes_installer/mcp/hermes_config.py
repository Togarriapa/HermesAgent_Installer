"""Fail-closed merge adapter for Hermes' pinned config.yaml MCP format.

Upstream schema pin: NousResearch/hermes-agent 7085fbf7753266fc4943c55ac04926186bc90005.
Installer entries are proposed by reviewed adapters; this module never chooses a
transport or creates credentials. Existing user entries are preserved verbatim.
"""
from __future__ import annotations

import hashlib
import os
import stat
import uuid
import fcntl
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


MAX_CONFIG_BYTES = 1_048_576
_SERVER_NAME = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z")
_ALLOWED_ENTRY_KEYS = frozenset({
    "command", "args", "env", "cwd", "url", "headers", "enabled", "timeout",
    "connect_timeout", "supports_parallel_tool_calls", "auth", "oauth", "tools",
    "ssl_verify", "client_cert", "client_key",
})


class HermesMCPConfigError(ValueError):
    """Invalid or conflicting Hermes MCP configuration."""


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_fingerprint(entry: Mapping[str, Any]) -> str:
    """Content identity for ownership records; callers keep this in private state."""
    return hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()


def _validate_entry(name: str, entry: Mapping[str, Any]) -> dict[str, Any]:
    if not _SERVER_NAME.fullmatch(name):
        raise HermesMCPConfigError("MCP server name must be a simple lowercase identifier")
    if not isinstance(entry, Mapping) or set(entry) - _ALLOWED_ENTRY_KEYS:
        raise HermesMCPConfigError("MCP entry has an unsupported Hermes config field")
    has_stdio = "command" in entry
    has_http = "url" in entry
    if has_stdio == has_http:
        raise HermesMCPConfigError("MCP entry must select exactly one stdio command or HTTP URL")
    if not isinstance(entry.get("enabled", False), bool):
        raise HermesMCPConfigError("MCP enabled must be boolean")
    for field in ("timeout", "connect_timeout"):
        value = entry.get(field, 9)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 9:
            raise HermesMCPConfigError(f"MCP {field} must be in (0, 9] seconds")
    tools = entry.get("tools")
    if not isinstance(tools, Mapping) or set(tools) != {"include"}:
        raise HermesMCPConfigError("MCP entry requires an explicit tools.include allowlist")
    include = tools["include"]
    if not isinstance(include, Sequence) or isinstance(include, (str, bytes)) or not include:
        raise HermesMCPConfigError("MCP tools.include must be a non-empty list")
    if any(not isinstance(tool, str) or not tool or len(tool) > 128 for tool in include):
        raise HermesMCPConfigError("MCP tools.include contains an invalid name")
    if len(set(include)) != len(include):
        raise HermesMCPConfigError("MCP tools.include contains duplicate names")
    if has_stdio:
        command = entry["command"]
        args = entry.get("args", [])
        if not isinstance(command, str) or not command or "\x00" in command or not isinstance(args, list):
            raise HermesMCPConfigError("MCP stdio command or args are invalid")
        if any(not isinstance(arg, str) or "\x00" in arg for arg in args):
            raise HermesMCPConfigError("MCP stdio args must be NUL-free strings")
        if any(arg.lower() in {"--token", "--api-key", "--authorization"} for arg in args):
            raise HermesMCPConfigError("MCP credentials must not be placed in command arguments")
        if "env" in entry:
            env = entry["env"]
            if not isinstance(env, Mapping) or any(
                not isinstance(key, str) or not re.fullmatch(r"MCP_[A-Z0-9_]{1,120}", key)
                or not isinstance(value, str) or not value.startswith("\u0024{")
                or not re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]{0,127}\}", value)
                for key, value in env.items()
            ):
                raise HermesMCPConfigError("MCP stdio env must contain secret variable references only")
    else:
        parsed = urlsplit(entry["url"] if isinstance(entry["url"], str) else "")
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise HermesMCPConfigError("MCP remote endpoint must be HTTPS without user information or fragment")
        if "headers" in entry:
            headers = entry["headers"]
            if not isinstance(headers, Mapping) or any(
                not isinstance(key, str) or not isinstance(value, str)
                or not re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]{0,127}\}", value)
                for key, value in headers.items()
            ):
                raise HermesMCPConfigError("MCP HTTP headers must contain secret references only")
        if entry.get("auth") not in {None, "oauth"}:
            raise HermesMCPConfigError("MCP HTTP auth must be OAuth or omitted")
    result = dict(entry)
    result.setdefault("enabled", False)
    result.setdefault("timeout", 9)
    result.setdefault("connect_timeout", 9)
    result["tools"] = {"include": list(include)}
    return result


def merge_hermes_mcp_config(
    existing_text: str | None,
    proposed: Mapping[str, Mapping[str, Any]],
    *,
    owned_fingerprints: Mapping[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    """Merge reviewed entries without replacing user-owned Hermes configuration.

    owned_fingerprints must come from installer state. An existing named MCP
    can only be updated when that recorded fingerprint matches its current exact
    entry. Unowned conflicts fail closed; unrelated Hermes keys and entries stay.
    """
    if not isinstance(proposed, Mapping) or not proposed:
        raise HermesMCPConfigError("at least one reviewed MCP entry is required")
    raw = existing_text or ""
    if len(raw.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise HermesMCPConfigError("Hermes config exceeds the 1 MiB limit")
    try:
        document = yaml.safe_load(raw) if raw.strip() else {}
    except yaml.YAMLError:
        raise HermesMCPConfigError("Hermes config is not valid safe YAML") from None
    if document is None:
        document = {}
    if not isinstance(document, Mapping):
        raise HermesMCPConfigError("Hermes config root must be a mapping")
    document = dict(document)
    current = document.get("mcp_servers", {})
    if not isinstance(current, Mapping):
        raise HermesMCPConfigError("Hermes mcp_servers must be a mapping")
    current = dict(current)
    owners = dict(owned_fingerprints or {})
    if set(owners) - set(current):
        raise HermesMCPConfigError("installer ownership record refers to a missing MCP entry")
    next_owners = dict(owners)
    for name, raw_entry in proposed.items():
        entry = _validate_entry(name, raw_entry)
        if entry["enabled"]:
            raise HermesMCPConfigError(
                "installer-managed MCP entries cannot be enabled until native calls are authority-mediated"
            )
        if name in current:
            old = current[name]
            if not isinstance(old, Mapping):
                raise HermesMCPConfigError("existing MCP entry is not a mapping")
            if name not in owners or entry_fingerprint(old) != owners[name]:
                raise HermesMCPConfigError(f"refusing to replace unowned or user-modified MCP entry: {name}")
        current[name] = entry
        next_owners[name] = entry_fingerprint(entry)
    document["mcp_servers"] = current
    rendered = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
    if len(rendered.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise HermesMCPConfigError("merged Hermes config exceeds the 1 MiB limit")
    return rendered, next_owners


def write_selected_profile_mcp_config(
    *,
    hermes_home,
    config_path,
    proposed: Mapping[str, Mapping[str, Any]],
    owned_fingerprints: Mapping[str, str] | None,
    expected_owner_uid: int,
) -> tuple[dict[str, str], str]:
    """Atomically merge MCP config into the selected native profile config.

    hermes_home is the isolated Hermes instance root; config_path must be
    profiles/<selected-profile-id>/config.yaml beneath it. The function verifies
    every ownership boundary and preserves unrelated config and MCP entries.
    """
    home = Path(hermes_home)
    target = Path(config_path)
    if not isinstance(expected_owner_uid, int) or isinstance(expected_owner_uid, bool):
        raise HermesMCPConfigError("expected profile owner is invalid")
    if expected_owner_uid != os.geteuid():
        raise HermesMCPConfigError("profile config may only be written by its owning installer user")
    try:
        resolved_home = home.resolve(strict=True)
        if not home.is_absolute() or resolved_home != home or not target.is_absolute():
            raise HermesMCPConfigError("MCP config path is outside the selected Hermes profile")
        relative = target.relative_to(home)
        if (len(relative.parts) != 3 or relative.parts[0] != "profiles"
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", relative.parts[1])
                or relative.parts[2] != "config.yaml"):
            raise HermesMCPConfigError("MCP config path must name a selected native profile")
        home_stat = home.lstat()
        profiles = home / "profiles"
        profiles_stat = profiles.lstat()
        profile_dir = target.parent
        profile_stat = profile_dir.lstat()
        if profiles.resolve(strict=True) != profiles or profile_dir.resolve(strict=True) != profile_dir:
            raise HermesMCPConfigError("selected Hermes profile path contains a symlink")
    except (OSError, ValueError):
        raise HermesMCPConfigError("selected Hermes profile home is unavailable") from None
    for directory_stat in (home_stat, profiles_stat, profile_stat):
        if (stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(directory_stat.st_mode)
                or directory_stat.st_uid != expected_owner_uid or directory_stat.st_mode & 0o077):
            raise HermesMCPConfigError("selected Hermes profile path is not private and owner-controlled")

    lock_path = profile_dir / ".mcp-config.lock"
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError:
        raise HermesMCPConfigError("cannot open the private MCP config lock") from None
    temporary = None
    try:
        lock_stat = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_uid != expected_owner_uid
                or lock_stat.st_mode & 0o077):
            raise HermesMCPConfigError("MCP config lock is not a private regular file")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

        existing_bytes = _read_private_config(target, expected_owner_uid)
        try:
            current_text = existing_bytes.decode("utf-8") if existing_bytes is not None else None
        except UnicodeDecodeError:
            raise HermesMCPConfigError("Hermes config is not UTF-8") from None
        rendered, next_owners = merge_hermes_mcp_config(
            current_text, proposed, owned_fingerprints=owned_fingerprints
        )
        payload = rendered.encode("utf-8")
        temporary = profile_dir / f".config.yaml.mcp-{uuid.uuid4().hex}.tmp"
        try:
            write_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                               | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(write_fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            raise HermesMCPConfigError("temporary Hermes MCP config could not be written") from None

        # Detect edits by writers that do not honor the advisory lock.
        if _read_private_config(target, expected_owner_uid) != existing_bytes:
            raise HermesMCPConfigError("Hermes config changed during the MCP merge; retry from a fresh read")
        os.replace(temporary, target)
        temporary = None
        directory_fd = os.open(profile_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                               | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return next_owners, hashlib.sha256(payload).hexdigest()
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        os.close(lock_fd)


def _read_private_config(path: Path, expected_owner_uid: int) -> bytes | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise HermesMCPConfigError("existing Hermes MCP config cannot be inspected") from None
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_owner_uid or info.st_mode & 0o077
            or info.st_size > MAX_CONFIG_BYTES):
        raise HermesMCPConfigError("existing Hermes config is not private and owner-controlled")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        raise HermesMCPConfigError("existing Hermes config cannot be read safely") from None
    if len(data) > MAX_CONFIG_BYTES:
        raise HermesMCPConfigError("Hermes config exceeds the 1 MiB limit")
    return data
