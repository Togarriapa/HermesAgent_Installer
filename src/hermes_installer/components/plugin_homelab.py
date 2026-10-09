"""Scoped native handlers for the three pinned homelab plugin resources.

Every external call is a root-brokered fixed effect. These handlers have no
credential resolver, network client, endpoint, SSH, subprocess, or shell access.
The root maps the fixed action and plugin identity to protected enrollment.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from typing import Any

from hermes_installer.registry.resources_runtime import (
    FixedResourceEffect,
    NativePluginRuntimeContext,
    PluginRegistrationContext,
    invoke_fixed_resource_effect,
)


PLUGIN_IDS = frozenset({
    "authentik-authorization", "cloudflare-homelab", "homelab-ops-broker",
})
_HOSTS = frozenset({"hermes", "nextcloud"})
_CLOUDFLARE_HOSTNAMES = frozenset({
    "ha.togarriapahome.uk", "nc.togarriapahome.uk", "hr.togarriapahome.uk",
})
_TUNNELS = frozenset({"ha", "nc", "hr"})
_READ_QUERIES = frozenset({
    "host-health", "cpu-memory-temperature-and-disk", "approved-service-status",
    "approved-container-status", "bounded-service-logs", "installed-runtime-and-container-versions",
    "backup-status-and-integrity-metadata", "nextcloud-status",
    "nextcloud-background-job-status", "nextcloud-maintenance-state",
})
_WRITE_ACTIONS = frozenset({
    "restart-approved-service", "restart-approved-container",
    "update-approved-service-or-container", "rollback-approved-service-or-container",
    "run-approved-backup", "run-approved-restore", "enter-or-exit-nextcloud-maintenance-mode",
    "run-approved-nextcloud-repair", "run-approved-nextcloud-background-job-operation",
    "bounded-approved-cleanup",
})
_DESTRUCTIVE = frozenset({
    "update-approved-service-or-container", "rollback-approved-service-or-container",
    "run-approved-restore", "bounded-approved-cleanup",
})
_MAX_RESULT_BYTES = 1_048_576


class HomelabPluginUnavailable(RuntimeError):
    """The reviewed root effect is not enrolled or its target is unavailable."""


def _selected(runtime: object, plugin_id: str) -> NativePluginRuntimeContext:
    if not isinstance(runtime, NativePluginRuntimeContext):
        raise HomelabPluginUnavailable("trusted native plugin runtime context is required")
    identity = runtime.identity
    if identity.kind != "plugins" or identity.resource_id != plugin_id or identity.version != "1.0.0":
        raise HomelabPluginUnavailable("plugin identity does not match the pinned v1.0.0 adapter")
    if runtime.authority is None or not callable(runtime.invocation_contexts):
        raise HomelabPluginUnavailable("root authority and trusted invocation lineage are required")
    return runtime


def _object(value: object, allowed: frozenset[str], required: frozenset[str] = frozenset()) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("arguments must contain only the reviewed fields")
    if set(value) - allowed:
        raise ValueError("arguments contain fields outside the reviewed schema")
    missing = required - set(value)
    if missing:
        raise ValueError("required fields are missing: " + ", ".join(sorted(missing)))
    return value


def _text(value: object, *, name: str, max_length: int = 128) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= max_length or any(ord(c) < 32 for c in value):
        raise ValueError(f"{name} must be a nonempty bounded string")
    return value


def _response(response: object) -> dict[str, Any]:
    status, body = getattr(response, "status", None), getattr(response, "body", None)
    if type(status) is not int or status != 200 or not isinstance(body, bytes) or len(body) > _MAX_RESULT_BYTES:
        raise HomelabPluginUnavailable("root homelab effect did not return a bounded successful result")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise HomelabPluginUnavailable("root homelab effect returned malformed JSON") from None
    if not isinstance(value, dict) or set(value) != {"result"} or not isinstance(value["result"], (dict, list, str, int, float, bool, type(None))):
        raise HomelabPluginUnavailable("root homelab effect returned an unexpected response shape")
    return value["result"] if isinstance(value["result"], dict) else {"result": value["result"]}


def _call(runtime: NativePluginRuntimeContext, *, plugin_id: str, capability: str,
          operation: str, action: str, arguments: Mapping[str, Any], intent: str,
          timeout: float = 15.0) -> dict[str, Any]:
    runtime = _selected(runtime, plugin_id)
    target = f"resource:plugins/{runtime.identity.resource_id}@{runtime.identity.version}"
    effect = FixedResourceEffect(capability=capability, target=target,
                                 recipient=None, operation=operation,
                                 timeout_seconds=timeout)
    payload = {"schema": 1, "plugin": plugin_id, "action": action, "arguments": dict(arguments)}
    response = invoke_fixed_resource_effect(runtime, effect, payload, intent=intent)
    return _response(response)


class AuthentikAuthorizationImplementation:
    """Read-only broker requests; actor and recipient identity stay root-owned."""

    def register(self, ctx: PluginRegistrationContext, runtime_context: NativePluginRuntimeContext) -> None:
        _selected(runtime_context, "authentik-authorization")
        # No principal, user ID, group ID, email, endpoint, or token is accepted
        # from tool arguments. Root resolves the signed session and live groups.
        empty = {"type": "object", "properties": {}, "additionalProperties": False}
        actions = (
            ("authentik_current_principal", "read-current-principal", "Read the signed session's current Authentik identity."),
            ("authentik_active_user_identity", "read-active-user-identity", "Read the signed principal's current active Authentik user record."),
            ("authentik_effective_groups", "read-user-effective-groups", "Read the signed principal's current direct and indirect Authentik groups."),
            ("authentik_verify_system_membership", "verify-effective-system-membership", "Freshly check this signed principal's effective System membership."),
            ("authentik_system_alarm_recipients", "list-current-system-alarm-recipients", "Resolve the current System alarm recipient set."),
        )
        for name, action, description in actions:
            def handler(args: object, action: str = action) -> dict[str, Any]:
                _object(args, frozenset())
                return _call(runtime_context, plugin_id="authentik-authorization",
                             capability="plugin.authentik.read", operation="provider.dispatch",
                             action=action, arguments={}, intent=description)
            ctx.register_tool(name=name, toolset="authentik_authorization", schema=empty,
                              handler=handler, requires_env=None, is_async=False,
                              description=description)


class CloudflareHomelabImplementation:
    """Health reads and a fixed three-name/tunnel Cloudflare action surface."""

    def register(self, ctx: PluginRegistrationContext, runtime_context: NativePluginRuntimeContext) -> None:
        _selected(runtime_context, "cloudflare-homelab")
        read_schema = {"type": "object", "properties": {
            "hostname": {"type": "string", "enum": sorted(_CLOUDFLARE_HOSTNAMES)},
            "tunnel": {"type": "string", "enum": sorted(_TUNNELS)},
        }, "additionalProperties": False}
        dns_write_schema = {"type": "object", "properties": {
            "hostname": {"type": "string", "enum": sorted(_CLOUDFLARE_HOSTNAMES)},
            "content": {"type": "string", "minLength": 1, "maxLength": 253},
            "ttl": {"type": "integer", "minimum": 60, "maximum": 86400},
            "proxied": {"type": "boolean"},
            "confirmation_id": {"type": "string", "minLength": 24, "maxLength": 128},
        }, "required": ["hostname", "content", "ttl", "proxied", "confirmation_id"], "additionalProperties": False}
        tunnel_write_schema = {"type": "object", "properties": {
            "tunnel": {"type": "string", "enum": sorted(_TUNNELS)},
            "hostname": {"type": "string", "enum": sorted(_CLOUDFLARE_HOSTNAMES)},
            "confirmation_id": {"type": "string", "minLength": 24, "maxLength": 128},
        }, "required": ["tunnel", "hostname", "confirmation_id"], "additionalProperties": False}

        def read_dns(args: object) -> dict[str, Any]:
            fields = _object(args, frozenset({"hostname"}), frozenset({"hostname"}))
            hostname = fields["hostname"]
            if hostname not in _CLOUDFLARE_HOSTNAMES:
                raise ValueError("hostname is outside the approved homelab set")
            return _call(runtime_context, plugin_id="cloudflare-homelab", capability="plugin.cloudflare.read",
                         operation="provider.dispatch", action="read-approved-dns-record",
                         arguments={"hostname": hostname}, intent="Read one approved homelab DNS record")

        def read_tunnel(args: object, *, view: str) -> dict[str, Any]:
            fields = _object(args, frozenset({"tunnel"}), frozenset({"tunnel"}))
            tunnel = fields["tunnel"]
            if tunnel not in _TUNNELS:
                raise ValueError("tunnel is outside the approved homelab set")
            return _call(runtime_context, plugin_id="cloudflare-homelab", capability="plugin.cloudflare.read",
                         operation="provider.dispatch", action=view,
                         arguments={"tunnel": tunnel}, intent="Read one approved homelab tunnel")

        def update_dns(args: object) -> dict[str, Any]:
            fields = _object(args, frozenset({"hostname", "content", "ttl", "proxied", "confirmation_id"}),
                             frozenset({"hostname", "content", "ttl", "proxied", "confirmation_id"}))
            hostname, content = fields["hostname"], fields["content"]
            if hostname not in _CLOUDFLARE_HOSTNAMES:
                raise ValueError("hostname is outside the approved homelab set")
            if not isinstance(content, str) or not 1 <= len(content) <= 253 or any(c in content for c in "\r\n\x00"):
                raise ValueError("DNS content is malformed")
            try:
                ipaddress.ip_address(content)
            except ValueError:
                if not re.fullmatch(r"[A-Za-z0-9.-]+\.togarriapahome\.uk\.?", content, re.IGNORECASE):
                    raise ValueError("DNS target must be an IP address or a hostname in the approved domain")
            if type(fields["ttl"]) is not int or not 60 <= fields["ttl"] <= 86400 or type(fields["proxied"]) is not bool:
                raise ValueError("DNS TTL or proxy flag is invalid")
            confirmation = fields["confirmation_id"]
            if not isinstance(confirmation, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", confirmation):
                raise ValueError("DNS update requires a host-issued one-shot confirmation reference")
            return _call(runtime_context, plugin_id="cloudflare-homelab", capability="plugin.cloudflare.write",
                         operation="host.write", action="update-approved-dns-record",
                         arguments={"hostname": hostname, "content": content,
                                    "ttl": fields["ttl"], "proxied": fields["proxied"],
                                    "confirmation_id": confirmation},
                         intent="Update one approved homelab DNS record")

        def update_tunnel(args: object) -> dict[str, Any]:
            fields = _object(args, frozenset({"tunnel", "hostname", "confirmation_id"}),
                             frozenset({"tunnel", "hostname", "confirmation_id"}))
            if fields["tunnel"] not in _TUNNELS or fields["hostname"] not in _CLOUDFLARE_HOSTNAMES:
                raise ValueError("tunnel or hostname is outside the approved homelab set")
            confirmation = fields["confirmation_id"]
            if not isinstance(confirmation, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", confirmation):
                raise ValueError("tunnel update requires a host-issued one-shot confirmation reference")
            return _call(runtime_context, plugin_id="cloudflare-homelab", capability="plugin.cloudflare.write",
                         operation="host.write", action="update-approved-tunnel-configuration",
                         arguments={"tunnel": fields["tunnel"], "hostname": fields["hostname"],
                                    "confirmation_id": confirmation},
                         intent="Reconcile one approved tunnel to its enrolled hostname")

        for name, schema, handler, description in (
            ("cloudflare_homelab_read_dns", read_schema, read_dns, "Read an approved homelab DNS record."),
            ("cloudflare_homelab_read_tunnel", read_schema,
             lambda args: read_tunnel(args, view="read-approved-tunnel-state"), "Read approved tunnel state."),
            ("cloudflare_homelab_read_tunnel_connectors", read_schema,
             lambda args: read_tunnel(args, view="read-approved-tunnel-connectors"), "Read connectors for an approved tunnel."),
            ("cloudflare_homelab_read_tunnel_configuration", read_schema,
             lambda args: read_tunnel(args, view="read-approved-tunnel-configuration"), "Read configuration for an approved tunnel."),
            ("cloudflare_homelab_update_dns", dns_write_schema, update_dns, "Update one journal-owned approved DNS record; fresh System membership is checked by root."),
            ("cloudflare_homelab_update_tunnel", tunnel_write_schema, update_tunnel, "Reconcile an approved tunnel using protected root configuration; fresh System membership is checked by root."),
        ):
            ctx.register_tool(name=name, toolset="cloudflare_homelab", schema=schema,
                              handler=handler, requires_env=None, is_async=False,
                              description=description)


class HomelabOpsBrokerImplementation:
    """Named operation broker; there is no arbitrary command or target field."""

    def register(self, ctx: PluginRegistrationContext, runtime_context: NativePluginRuntimeContext) -> None:
        _selected(runtime_context, "homelab-ops-broker")
        read_schema = {"type": "object", "properties": {
            "host": {"type": "string", "enum": sorted(_HOSTS)},
            "query": {"type": "string", "enum": sorted(_READ_QUERIES)},
        }, "required": ["host", "query"], "additionalProperties": False}
        write_schema = {"type": "object", "properties": {
            "host": {"type": "string", "enum": sorted(_HOSTS)},
            "action": {"type": "string", "enum": sorted(_WRITE_ACTIONS)},
            "confirmation_id": {"type": "string", "maxLength": 128},
        }, "required": ["host", "action"], "additionalProperties": False}

        def inspect(args: object) -> dict[str, Any]:
            fields = _object(args, frozenset({"host", "query"}), frozenset({"host", "query"}))
            if fields["host"] not in _HOSTS or fields["query"] not in _READ_QUERIES:
                raise ValueError("host or query is outside the approved broker scope")
            return _call(runtime_context, plugin_id="homelab-ops-broker", capability="plugin.homelab.read",
                         operation="provider.dispatch", action="inspect-approved-target",
                         arguments={"host": fields["host"], "query": fields["query"]},
                         intent="Inspect an allowlisted homelab health or service target")

        def operate(args: object) -> dict[str, Any]:
            fields = _object(args, frozenset({"host", "action", "confirmation_id"}),
                             frozenset({"host", "action"}))
            host, action = fields["host"], fields["action"]
            if host not in _HOSTS or action not in _WRITE_ACTIONS:
                raise ValueError("host or action is outside the approved broker scope")
            confirmation = fields.get("confirmation_id")
            if action in _DESTRUCTIVE:
                if not isinstance(confirmation, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", confirmation):
                    raise ValueError("destructive action requires a host-issued one-shot confirmation reference")
            elif confirmation is not None:
                raise ValueError("confirmation_id is accepted only for destructive operations")
            return _call(runtime_context, plugin_id="homelab-ops-broker", capability="plugin.homelab.write",
                         operation="host.write", action=action,
                         arguments={"host": host, "confirmation_id": confirmation},
                         intent=f"Run the approved {action} operation on the configured {host} target",
                         timeout=120.0)

        for name, schema, handler, description in (
            ("homelab_ops_inspect", read_schema, inspect, "Read bounded status from configured Hermes or Nextcloud targets."),
            ("homelab_ops_run", write_schema, operate, "Run one named operation on an enrolled target; every write receives a fresh root Authentik System check."),
        ):
            ctx.register_tool(name=name, toolset="homelab_ops_broker", schema=schema,
                              handler=handler, requires_env=None, is_async=False,
                              description=description)


AUTHENTIK_AUTHORIZATION_IMPLEMENTATION = AuthentikAuthorizationImplementation()
CLOUDFLARE_HOMELAB_IMPLEMENTATION = CloudflareHomelabImplementation()
HOMELAB_OPS_BROKER_IMPLEMENTATION = HomelabOpsBrokerImplementation()


def resolve_homelab_plugin_implementation(plugin_id: str) -> object | None:
    return {
        "authentik-authorization": AUTHENTIK_AUTHORIZATION_IMPLEMENTATION,
        "cloudflare-homelab": CLOUDFLARE_HOMELAB_IMPLEMENTATION,
        "homelab-ops-broker": HOMELAB_OPS_BROKER_IMPLEMENTATION,
    }.get(plugin_id)
