"""Closed, read-only Jarvis projections for native provider/plugin/MCP status.

This module deliberately accepts only the public Settings DTO. It does not read
Hermes configuration, credentials, environment variables, or invoke native APIs.
Presence here is configuration/process observation, never authentication or
functional readiness.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

_HEX_ID = re.compile(r"^[0-9a-f]{32}$")
_CORE_COMMIT = re.compile(r"^[0-9a-f]{12}$")
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,79}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_SAFE_CONFIG_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/+-]{0,159}$")
_STATUSES = frozenset({"connected", "disabled", "connecting", "failed", "lazy", "configured"})
_TRANSPORTS = frozenset({"http", "stdio", "unknown"})
_MAX_ROWS = 64


def _plain_label(value: Any) -> str | None:
    return value if isinstance(value, str) and _SAFE_LABEL.fullmatch(value) else None


def _configured_value(value: Any) -> str | None:
    if (not isinstance(value, str) or not _SAFE_CONFIG_VALUE.fullmatch(value)
            or "://" in value or "\\" in value or value.startswith("/")
            or value.endswith("/") or "//" in value):
        return None
    return value


def _utc_timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.utcoffset() is None or parsed.microsecond:
        return None
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _exact_keys(value: Any, expected: frozenset[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def _opaque(opaque_id: Any, kind: str, name: str) -> str | None:
    try:
        value = opaque_id(kind, name)
    except Exception:
        return None
    return value if isinstance(value, str) and _HEX_ID.fullmatch(value) else None


@dataclass(frozen=True, slots=True)
class SettingValue:
    value: str | None
    status: str

    def as_dict(self) -> dict[str, Any]:
        return {"value": self.value, "status": self.status}


@dataclass(frozen=True, slots=True)
class PluginRecord:
    id: str
    label: str
    version: str | None
    enabled: bool
    loaded: bool

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label, "version": self.version,
                "enabled": self.enabled, "loaded": self.loaded}


@dataclass(frozen=True, slots=True)
class McpRecord:
    id: str
    label: str
    transport: str
    tool_count: int | None
    connected: bool | None
    disabled: bool | None
    status: str | None

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label, "transport": self.transport,
                "toolCount": self.tool_count, "connected": self.connected,
                "disabled": self.disabled, "status": self.status}


@dataclass(frozen=True, slots=True)
class NativeControlsSnapshot:
    readiness: str
    provider: SettingValue
    model: SettingValue
    core_version: SettingValue
    account_state: SettingValue
    plugins_state: str
    plugins: tuple[PluginRecord, ...]
    mcp_state: str
    mcp_checked_at: str | None
    mcp_servers: tuple[McpRecord, ...]

    def to_public_dict(self) -> dict[str, Any]:
        """Return a fresh plain closed DTO safe for the Jarvis Settings response."""
        return {
            "readiness": self.readiness,
            "provider": self.provider.as_dict(),
            "model": self.model.as_dict(),
            "coreVersion": self.core_version.as_dict(),
            "accountState": self.account_state.as_dict(),
            "plugins": {"state": self.plugins_state,
                        "items": [row.as_dict() for row in self.plugins]},
            "mcp": {"state": self.mcp_state, "checkedAt": self.mcp_checked_at,
                    "servers": [row.as_dict() for row in self.mcp_servers]},
        }


def pending_native_controls() -> NativeControlsSnapshot:
    """A fail-closed snapshot used when a source is absent, stale, or malformed."""
    pending = SettingValue(None, "pending")
    return NativeControlsSnapshot(
        readiness="pending",
        provider=pending,
        model=pending,
        core_version=pending,
        account_state=SettingValue("unknown", "pending"),
        plugins_state="unknown",
        plugins=(),
        mcp_state="unknown",
        mcp_checked_at=None,
        mcp_servers=(),
    )


def _setting(value: Any, *, core: bool = False) -> SettingValue | None:
    if not _exact_keys(value, frozenset({"value", "status"})):
        return None
    raw, status = value["value"], value["status"]
    if core:
        if raw is None and status == "pending":
            return SettingValue(None, "pending")
        if isinstance(raw, str) and _CORE_COMMIT.fullmatch(raw) and status == "verified":
            return SettingValue(raw, "verified")
        return None
    if raw is None and status == "pending":
        return SettingValue(None, "pending")
    label = _configured_value(raw)
    if label is not None and status == "configured-unverified":
        return SettingValue(label, "configured-unverified")
    return None


def _plugins(value: Any) -> tuple[str, tuple[PluginRecord, ...]] | None:
    if not _exact_keys(value, frozenset({"state", "items"})):
        return None
    rows = value["items"]
    if not isinstance(rows, list) or len(rows) > _MAX_ROWS:
        return None
    if not rows:
        if value["state"] != "unknown":
            return None
        return "unknown", ()
    if value["state"] != "observed":
        return None
    result: list[PluginRecord] = []
    seen: set[str] = set()
    expected = frozenset({"id", "label", "version", "enabled", "loaded"})
    for row in rows:
        if not _exact_keys(row, expected):
            return None
        ident = row["id"]
        label = _plain_label(row["label"])
        version = row["version"]
        if (not isinstance(ident, str) or not _HEX_ID.fullmatch(ident) or ident in seen
                or label is None or not isinstance(row["enabled"], bool)
                or not isinstance(row["loaded"], bool)):
            return None
        if not isinstance(version, str) or not _SAFE_VERSION.fullmatch(version):
            return None
        seen.add(ident)
        result.append(PluginRecord(ident, label, version, row["enabled"], row["loaded"]))
    return "observed", tuple(result)


def build_native_controls_snapshot(
    *, provider: Any, model: Any, core_version: Any, plugins: Any, mcp: Any,
    opaque_id: Any,
) -> NativeControlsSnapshot:
    """Project fixed current-core adapter results into the public closed DTO.

    ``opaque_id`` is supplied by the owner/generation-bound API service and must
    return a 128-bit HMAC rendered as exactly 32 lowercase hexadecimal digits.
    Passing ``None`` for an unavailable/stale source keeps that section unknown.
    The function accepts only the two fixed adapter envelopes, never arbitrary
    method names, configuration dictionaries, or raw backend responses.
    """
    provider_row, model_row = _setting(provider), _setting(model)
    version_row = _setting(core_version, core=True)
    if provider_row is None or model_row is None or version_row is None or not callable(opaque_id):
        return pending_native_controls()

    plugin_state = "unknown"
    plugin_rows: tuple[PluginRecord, ...] = ()
    if _exact_keys(plugins, frozenset({"plugins"})) and isinstance(plugins["plugins"], list):
        raw_rows = plugins["plugins"]
        if len(raw_rows) <= _MAX_ROWS and raw_rows:
            built: list[PluginRecord] = []
            seen: set[str] = set()
            for item in raw_rows:
                if not _exact_keys(item, frozenset({"name", "version", "enabled"})):
                    built = []
                    break
                name = _plain_label(item["name"])
                version = item["version"]
                enabled = item["enabled"]
                if (name is None or not isinstance(version, str) or not _SAFE_VERSION.fullmatch(version)
                        or not isinstance(enabled, bool)):
                    built = []
                    break
                ident = _opaque(opaque_id, "plugin", item["name"])
                if ident is None or ident in seen:
                    built = []
                    break
                seen.add(ident)
                built.append(PluginRecord(ident, name, version, enabled, True))
            if built:
                plugin_state, plugin_rows = "observed", tuple(built)

    mcp_state = "unknown"
    mcp_checked_at: str | None = None
    mcp_rows: tuple[McpRecord, ...] = ()
    if _exact_keys(mcp, frozenset({"servers", "checked_at"})):
        raw_rows, checked_at = mcp["servers"], mcp["checked_at"]
        if (isinstance(raw_rows, list) and len(raw_rows) <= _MAX_ROWS
                and type(checked_at) is int and checked_at > 0):
            try:
                timestamp = datetime.fromtimestamp(checked_at / 1000, tz=timezone.utc)
                checked = timestamp.isoformat(timespec="seconds").replace("+00:00", "Z")
            except (OverflowError, OSError, ValueError):
                checked = ""
            built_mcp: list[McpRecord] = []
            seen_mcp: set[str] = set()
            malformed = not checked
            for item in raw_rows:
                if not _exact_keys(item, frozenset({"name", "transport", "tools", "connected", "disabled", "status"})):
                    malformed = True
                    break
                name = _plain_label(item["name"])
                transport_value = item["transport"]
                transport = transport_value if isinstance(transport_value, str) and transport_value in {"http", "stdio"} else "unknown"
                tools = item["tools"]
                connected, disabled, status = item["connected"], item["disabled"], item["status"]
                if (name is None or (tools is not None and (type(tools) is not int or not 0 <= tools <= 1000))
                        or (connected is not None and not isinstance(connected, bool))
                        or (disabled is not None and not isinstance(disabled, bool))
                        or (status is not None and (not isinstance(status, str) or status not in _STATUSES))):
                    malformed = True
                    break
                ident = _opaque(opaque_id, "mcp", item["name"])
                if ident is None or ident in seen_mcp:
                    malformed = True
                    break
                seen_mcp.add(ident)
                built_mcp.append(McpRecord(ident, name, transport, tools, connected, disabled, status))
            if not malformed:
                mcp_state, mcp_checked_at, mcp_rows = "observed", checked, tuple(built_mcp)

    projected = NativeControlsSnapshot(
        "pending", provider_row, model_row, version_row,
        SettingValue("unknown", "pending"), plugin_state, plugin_rows,
        mcp_state, mcp_checked_at, mcp_rows,
    )
    return decode_native_controls(projected.to_public_dict())


def _mcp(value: Any) -> tuple[str, str | None, tuple[McpRecord, ...]] | None:
    if not _exact_keys(value, frozenset({"state", "checkedAt", "servers"})):
        return None
    state, timestamp, rows = value["state"], value["checkedAt"], value["servers"]
    if state == "unknown":
        if timestamp is not None or rows != []:
            return None
        return "unknown", None, ()
    if state != "observed" or (timestamp := _utc_timestamp(timestamp)) is None:
        return None
    if not isinstance(rows, list) or len(rows) > _MAX_ROWS:
        return None
    result: list[McpRecord] = []
    seen: set[str] = set()
    expected = frozenset({"id", "label", "transport", "toolCount", "connected",
                          "disabled", "status"})
    for row in rows:
        if not _exact_keys(row, expected):
            return None
        ident = row["id"]
        label = _plain_label(row["label"])
        transport = row["transport"]
        tools = row["toolCount"]
        connected, disabled, status = row["connected"], row["disabled"], row["status"]
        if (not isinstance(ident, str) or not _HEX_ID.fullmatch(ident) or ident in seen
                or label is None or not isinstance(transport, str) or transport not in _TRANSPORTS
                or (tools is not None and (type(tools) is not int or not 0 <= tools <= 1000))
                or (connected is not None and not isinstance(connected, bool))
                or (disabled is not None and not isinstance(disabled, bool))
                or (status is not None and (not isinstance(status, str) or status not in _STATUSES))):
            return None
        seen.add(ident)
        result.append(McpRecord(ident, label, transport, tools, connected, disabled, status))
    return "observed", timestamp, tuple(result)


def decode_native_controls(value: Any) -> NativeControlsSnapshot:
    """Strictly decode the finite Settings response; reject expansion and stale claims.

    A malformed DTO collapses wholly to pending rather than partially trusting a
    response that may have mixed generations or included unreviewed fields.
    """
    expected = frozenset({"readiness", "provider", "model", "coreVersion", "accountState",
                          "plugins", "mcp"})
    if not _exact_keys(value, expected) or value["readiness"] != "pending":
        return pending_native_controls()
    provider = _setting(value["provider"])
    model = _setting(value["model"])
    core_version = _setting(value["coreVersion"], core=True)
    account = value["accountState"]
    plugins = _plugins(value["plugins"])
    mcp = _mcp(value["mcp"])
    if (provider is None or model is None or core_version is None
            or not _exact_keys(account, frozenset({"value", "status"}))
            or account != {"value": "unknown", "status": "pending"}
            or plugins is None or mcp is None):
        return pending_native_controls()
    plugin_state, plugin_rows = plugins
    mcp_state, checked_at, mcp_rows = mcp
    return NativeControlsSnapshot("pending", provider, model, core_version,
                                  SettingValue("unknown", "pending"), plugin_state,
                                  plugin_rows, mcp_state, checked_at, mcp_rows)
