"""Source-reviewed schemas for the three pinned homelab Plugin adapters.

Manifest hashes bind each adapter to the vendored Resources source. The
adapter hash is pinned to ``plugin_homelab.py`` (kept separate from this
catalog to avoid a self-referential digest). Root enrollments must match the
exact action, operation, schema IDs, both hashes, bounds, and expected state.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Any

from hermes_installer.components.plugin_effects import PluginActionSchema


PLUGIN_HOMELAB_ADAPTER_SHA256 = "ba1d3bcad55fb13e09ce78fa953a7c90499c3bebf6b5b181564b2f614793e68d"
PLUGIN_HOMELAB_MANIFEST_SHA256 = MappingProxyType({
    "authentik-authorization": "88075741bee9d27e1b7c8536cda4e641c335c952cde7e1083c8d3131be25ce2e",
    "cloudflare-homelab": "5623e42ba85a5056c7cae8e3e1ae5b0d48613071220772e82027864f6cfdd7c5",
    "homelab-ops-broker": "bb4de61e7136f57e6fed77b3d907f2f669b2c7f070eb124ed9b0a783109d35d2",
})

_HOSTS = ["hermes", "nextcloud"]
_HOSTNAMES = ["ha.togarriapahome.uk", "hr.togarriapahome.uk", "nc.togarriapahome.uk"]
_TUNNELS = ["ha", "hr", "nc"]
_AUTHENTIK = [
    "resolve-session-principal-to-user", "read-active-user-identity",
    "read-user-effective-groups", "verify-effective-System-membership",
    "list-current-effective-System-members-for-alarm-delivery",
]
_CF_READ = ["read-approved-dns-records", "read-approved-tunnel-state",
            "read-approved-tunnel-connectors", "read-approved-tunnel-configuration"]
_CF_WRITE = ["update-approved-dns-record", "update-approved-tunnel-configuration"]
_OPS_READ = [
    "host-health", "cpu-memory-temperature-and-disk", "approved-service-status",
    "approved-container-status", "bounded-service-logs", "installed-runtime-and-container-versions",
    "backup-status-and-integrity-metadata", "nextcloud-status",
    "nextcloud-background-job-status", "nextcloud-maintenance-state",
]
_OPS_WRITE = [
    "restart-approved-service", "restart-approved-container", "update-approved-service-or-container",
    "rollback-approved-service-or-container", "run-approved-backup", "run-approved-restore",
    "enter-or-exit-nextcloud-maintenance-mode", "run-approved-nextcloud-repair",
    "run-approved-nextcloud-background-job-operation", "bounded-approved-cleanup",
]
_DESTRUCTIVE = frozenset({
    "update-approved-service-or-container", "rollback-approved-service-or-container",
    "run-approved-restore", "run-approved-nextcloud-repair", "bounded-approved-cleanup",
})


def _obj(properties: dict[str, Any] | None = None, required: list[str] | None = None) -> dict[str, Any]:
    return {"type": "object", "properties": properties or {}, "required": required or [],
            "additionalProperties": False}


def _string(maximum: int, minimum: int = 1) -> dict[str, Any]:
    return {"type": "string", "minLength": minimum, "maxLength": maximum}


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _row(adapter: str, action: str, operation: str, arguments: dict[str, Any],
         result: dict[str, Any], *, write: bool = False, confirmation: bool = False,
         response_limit: int = 2_097_152, deadline: float = 30.0) -> PluginActionSchema:
    return PluginActionSchema(
        adapter_id=adapter, action_id=action,
        argument_schema_id=f"{adapter}.{action}.arguments.v1",
        result_schema_id=f"{adapter}.{action}.result.v1", operation=operation,
        adapter_sha256=PLUGIN_HOMELAB_ADAPTER_SHA256,
        argument_schema=_freeze(arguments), result_schema=_freeze(result),
        request_bytes_limit=262_144, response_bytes_limit=response_limit,
        deadline_seconds=deadline, requires_idempotency=write,
        requires_confirmation=confirmation,
        # The current backends do not prove writes by readback; they return an
        # ambiguous receipt. They can never claim a write committed.
        expected_state="committed" if write else "read-complete",
    )


_ANY_PROVIDER_OBJECT = {"type": "object"}


def _json_value(depth: int = 0) -> dict[str, Any]:
    """Bound arbitrary JSON observations while retaining their native shape."""
    kinds = ["object", "string", "integer", "number", "boolean", "null"]
    if depth < 8:
        kinds.append("array")
    result: dict[str, Any] = {"type": kinds}
    if depth < 8:
        result["items"] = _json_value(depth + 1)
    return result


_OPS_RESULT = _obj({"result": _json_value()}, ["result"])
_AUTH_RESULT = {
    "resolve-session-principal-to-user": _obj({
        "principal_id": _string(128), "subject_id": _string(256),
        "policy_revision": _string(128), "checked_at_monotonic": {"type": "number", "minimum": 0},
    }, ["principal_id", "subject_id", "policy_revision", "checked_at_monotonic"]),
    "read-active-user-identity": _obj({
        "principal_id": _string(128), "username": _string(256), "email": _string(320),
        "subject_id": _string(256), "checked_at_monotonic": {"type": "number", "minimum": 0},
    }, ["principal_id", "username", "email", "subject_id", "checked_at_monotonic"]),
    "read-user-effective-groups": _obj({
        "direct_group_ids": {"type": "array", "maxItems": 512, "items": _string(128)},
        "effective_group_ids": {"type": "array", "maxItems": 512, "items": _string(128)},
        "checked_at_monotonic": {"type": "number", "minimum": 0},
    }, ["direct_group_ids", "effective_group_ids", "checked_at_monotonic"]),
    "verify-effective-System-membership": _obj({
        "system_member": {"type": "boolean"}, "policy_revision": _string(128),
        "checked_at_monotonic": {"type": "number", "minimum": 0},
    }, ["system_member", "policy_revision", "checked_at_monotonic"]),
    # This action is installable only with a finite root-enrolled recipient ID
    # set; addresses are returned by the fresh Authentik host policy.
    "list-current-effective-System-members-for-alarm-delivery": _obj({
        "system_recipients": {"type": "array", "maxItems": 256, "items": _obj({
            "recipient_id": _string(128), "email": _string(320),
        }, ["recipient_id", "email"])},
        "policy_revision": _string(128), "checked_at_monotonic": {"type": "number", "minimum": 0},
    }, ["system_recipients", "policy_revision", "checked_at_monotonic"]),
}

_rows: dict[tuple[str, str], PluginActionSchema] = {}
for _action in _AUTHENTIK:
    _rows[("authentik-authorization", _action)] = _row(
        "authentik-authorization", _action, "plugin.authentik-authorization.read",
        _obj(), _AUTH_RESULT[_action], response_limit=262_144, deadline=15.0)

for _action in _CF_READ:
    _args = (_obj({"hostname": {"type": "string", "enum": _HOSTNAMES}}, ["hostname"])
             if _action == "read-approved-dns-records" else
             _obj({"tunnel": {"type": "string", "enum": _TUNNELS}}, ["tunnel"]))
    _rows[("cloudflare-homelab", _action)] = _row(
        "cloudflare-homelab", _action, "plugin.cloudflare-homelab.read",
        _args, _ANY_PROVIDER_OBJECT, response_limit=1_048_576, deadline=15.0)

_rows[("cloudflare-homelab", "update-approved-dns-record")] = _row(
    "cloudflare-homelab", "update-approved-dns-record", "plugin.cloudflare-homelab.write",
    _obj({"hostname": {"type": "string", "enum": _HOSTNAMES},
          "content": _string(253), "ttl": {"type": "integer", "minimum": 60, "maximum": 86400},
          "proxied": {"type": "boolean"}}, ["hostname", "content", "ttl", "proxied"]),
    _ANY_PROVIDER_OBJECT, write=True, confirmation=True, response_limit=1_048_576)
_rows[("cloudflare-homelab", "update-approved-tunnel-configuration")] = _row(
    "cloudflare-homelab", "update-approved-tunnel-configuration", "plugin.cloudflare-homelab.write",
    _obj({"tunnel": {"type": "string", "enum": _TUNNELS},
          "hostname": {"type": "string", "enum": _HOSTNAMES}}, ["tunnel", "hostname"]),
    _ANY_PROVIDER_OBJECT, write=True, confirmation=True, response_limit=1_048_576)

for _action in _OPS_READ:
    _rows[("homelab-ops-broker", _action)] = _row(
        "homelab-ops-broker", _action, "plugin.homelab-ops-broker.read",
        _obj({"host": {"type": "string", "enum": _HOSTS},
              "query": {"type": "string", "enum": [_action]}}, ["host", "query"]),
        _OPS_RESULT, response_limit=1_048_576, deadline=15.0)
for _action in _OPS_WRITE:
    _rows[("homelab-ops-broker", _action)] = _row(
        "homelab-ops-broker", _action, "plugin.homelab-ops-broker.write",
        _obj({"host": {"type": "string", "enum": _HOSTS},
              "action": {"type": "string", "enum": [_action]}}, ["host", "action"]),
        _OPS_RESULT, write=True, confirmation=_action in _DESTRUCTIVE,
        response_limit=1_048_576, deadline=30.0)

PLUGIN_ACTION_SCHEMAS = MappingProxyType(_rows)
