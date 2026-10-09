"""Fail-closed merge adapter for Hermes' pinned config.yaml MCP format.

Upstream schema pin: NousResearch/hermes-agent 7085fbf7753266fc4943c55ac04926186bc90005.
Installer entries are proposed by reviewed adapters; this module never chooses a
transport or creates credentials. Existing user entries are preserved verbatim.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
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
                or not re.fullmatch(r"\\$\\{[A-Za-z_][A-Za-z0-9_]{0,127}\\}", value)
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
                or not re.fullmatch(r"\\$\\{[A-Za-z_][A-Za-z0-9_]{0,127}\\}", value)
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
