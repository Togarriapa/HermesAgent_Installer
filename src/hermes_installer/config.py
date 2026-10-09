"""Strict, dependency-free installer configuration loading."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class ConfigError(ValueError):
    """Raised when configuration is malformed or unsafe."""


_TOP_LEVEL = {"schema_version", "timezone", "paths", "components", "privacy", "remote_desktop"}
_PATHS = {"data_root", "state_root", "cache_root", "model_root"}
_COMPONENTS = {"hermes_agent", "hermes_desktop", "registry", "providers", "memory", "mcp", "colibri", "coral", "remote_desktop"}
_HOSTNAME = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\Z")
_EMAIL = re.compile(r"[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+\Z")
_SECRET_REF_PREFIXES = ("keyring://", "secret://", "file://", "env://")


@dataclass(frozen=True, slots=True)
class InstallerConfig:
    schema_version: int
    timezone: str
    paths: dict[str, str]
    components: dict[str, bool]
    privacy: dict[str, Any]
    remote_desktop: dict[str, Any]


def validate_config(data: Any) -> InstallerConfig:
    if not isinstance(data, dict):
        raise ConfigError("Configuration root must be an object")
    unknown = set(data) - _TOP_LEVEL
    if unknown:
        raise ConfigError(f"Unknown configuration keys: {', '.join(sorted(unknown))}")
    if data.get("schema_version") != 1:
        raise ConfigError("schema_version must be 1")
    timezone = data.get("timezone", "Europe/Lisbon")
    if not isinstance(timezone, str):
        raise ConfigError("timezone must be a string")
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConfigError(f"Unknown IANA timezone: {timezone}") from exc

    paths = data.get("paths", {})
    if not isinstance(paths, dict) or set(paths) - _PATHS:
        raise ConfigError("paths must contain only data_root, state_root, cache_root, and model_root")
    for name, value in paths.items():
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ConfigError(f"paths.{name} must be a non-empty path string")

    components = data.get("components", {})
    if not isinstance(components, dict) or set(components) - _COMPONENTS:
        raise ConfigError(f"components must contain only: {', '.join(sorted(_COMPONENTS))}")
    if any(not isinstance(value, bool) for value in components.values()):
        raise ConfigError("component selections must be booleans")

    privacy = data.get("privacy", {})
    if not isinstance(privacy, dict):
        raise ConfigError("privacy must be an object")
    if privacy.get("additional_metered_budget", 0) != 0:
        raise ConfigError("additional_metered_budget must remain zero until a reviewed budget is configured")

    remote = data.get("remote_desktop", {})
    if not isinstance(remote, dict):
        raise ConfigError("remote_desktop must be an object")
    if "hostname" in remote:
        hostname = remote["hostname"]
        if not isinstance(hostname, str) or (hostname and not _HOSTNAME.fullmatch(hostname.lower())):
            raise ConfigError("remote_desktop.hostname must be an explicitly selected DNS hostname")
    if "allowed_emails" in remote:
        emails = remote["allowed_emails"]
        hostname = remote.get("hostname", "")
        if not isinstance(emails, list) or (hostname and not emails) or any(not isinstance(e, str) or not _EMAIL.fullmatch(e) for e in emails):
            raise ConfigError("remote_desktop.allowed_emails must contain valid addresses when a hostname is configured")
    if "management_token_ref" in remote and (not isinstance(remote["management_token_ref"], str) or not remote["management_token_ref"].startswith(_SECRET_REF_PREFIXES)):
        raise ConfigError("remote_desktop.management_token_ref must use keyring://, secret://, file://, or env://, never a token value")
    if components.get("remote_desktop"):
        if not remote.get("hostname"):
            raise ConfigError("remote_desktop.hostname is required when remote_desktop is selected; no default hostname is provided")
        if not remote.get("allowed_emails"):
            raise ConfigError("remote_desktop.allowed_emails is required when remote_desktop is selected")
        if not remote.get("management_token_ref"):
            raise ConfigError("remote_desktop.management_token_ref is required for noninteractive remote setup")

    return InstallerConfig(1, timezone, dict(paths), dict(components), dict(privacy), dict(remote))


def load_config(path: Path) -> InstallerConfig:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Cannot read config {path}: {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}") from exc
    return validate_config(data)


def write_example(path: Path) -> None:
    """Write a minimal, secret-free sample without replacing an existing file."""
    payload = {
        "schema_version": 1,
        "timezone": "Europe/Lisbon",
        "paths": {"data_root": "~/HermesInstaller/data", "state_root": "~/HermesInstaller/state"},
        "components": {"hermes_agent": True, "hermes_desktop": True},
        "privacy": {"additional_metered_budget": 0},
        "remote_desktop": {"hostname": "", "allowed_emails": []},
    }
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
