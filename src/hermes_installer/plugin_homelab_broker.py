"""Root-side fixed effects for the three pinned homelab plugins (RB08).

This module is intentionally separate from the general authority service. The
daemon may register only handlers built from root-selected enrollments here;
plugin YAML and worker arguments never select credentials, endpoints, account
IDs, physical target IDs, recipients, paths, or commands.
"""
from __future__ import annotations

import json
import ipaddress
import math
import re
import time
import uuid
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import quote, urlsplit

from hermes_installer.authority.types import AuthorityDenied, EffectAuthorization, HostContext, canonical_digest
from hermes_installer.network import BoundedNetwork, NetworkError

MAX_REQUEST = 262_144
MAX_RESPONSE = 2_097_152
MAX_DEADLINE = 30.0
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CF_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_MANIFESTS = {
    "authentik-authorization": "88075741bee9d27e1b7c8536cda4e641c335c952cde7e1083c8d3131be25ce2e",
    "cloudflare-homelab": "5623e42ba85a5056c7cae8e3e1ae5b0d48613071220772e82027864f6cfdd7c5",
    "homelab-ops-broker": "bb4de61e7136f57e6fed77b3d907f2f669b2c7f070eb124ed9b0a783109d35d2",
}
_OPERATIONS = {
    "authentik-authorization": frozenset({"plugin.authentik-authorization.read"}),
    "cloudflare-homelab": frozenset({"plugin.cloudflare-homelab.read", "plugin.cloudflare-homelab.write"}),
    "homelab-ops-broker": frozenset({"plugin.homelab-ops-broker.read", "plugin.homelab-ops-broker.write"}),
}
PLUGIN_HOMELAB_OPERATIONS = frozenset().union(*_OPERATIONS.values())
PLUGIN_EFFECT_RECORD_FIELDS = frozenset({
    "adapter_id", "manifest_sha256", "handler_artifact_id", "handler_sha256",
    "action_id", "argument_schema_id", "operation", "capability", "target_id",
    "generation", "principal_id", "profile_id", "recipient", "credential_reference_id",
    "scope_reference_id", "confirmation_policy_id", "idempotency_policy_id",
    "request_bytes_limit", "response_bytes_limit", "deadline_seconds",
})
_HOSTS = frozenset({"hermes", "nextcloud"})
_HOSTNAMES = frozenset({"ha.togarriapahome.uk", "nc.togarriapahome.uk", "hr.togarriapahome.uk"})
_TUNNELS = frozenset({"ha", "nc", "hr"})
_CLOUDFLARE_ACTIONS = frozenset({"read-approved-dns-records", "read-approved-tunnel-state",
                    "read-approved-tunnel-connectors", "read-approved-tunnel-configuration",
                    "update-approved-dns-record", "update-approved-tunnel-configuration"})
_OPS_READS = frozenset({"host-health", "cpu-memory-temperature-and-disk", "approved-service-status",
                        "approved-container-status", "bounded-service-logs",
                        "installed-runtime-and-container-versions", "backup-status-and-integrity-metadata",
                        "nextcloud-status", "nextcloud-background-job-status", "nextcloud-maintenance-state"})
_OPS_WRITES = frozenset({"restart-approved-service", "restart-approved-container",
                         "update-approved-service-or-container", "rollback-approved-service-or-container",
                         "run-approved-backup", "run-approved-restore", "enter-or-exit-nextcloud-maintenance-mode",
                         "run-approved-nextcloud-repair", "run-approved-nextcloud-background-job-operation",
                         "bounded-approved-cleanup"})
_AUTHENTIK_ACTIONS = frozenset({"resolve-session-principal-to-user", "read-active-user-identity",
                                "read-user-effective-groups", "verify-effective-System-membership",
                                "list-current-effective-System-members-for-alarm-delivery"})


class HomelabEffectDenied(PermissionError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class HomelabVault(Protocol):
    def resolve_reference(self, reference: str, *, peer_uid: int | None = None,
                          required_scope: str | None = None,
                          principal_id: str | None = None) -> str: ...


class ConfirmationVerifier(Protocol):
    def consume_plugin_confirmation(self, *, attestation_id: str, context: HostContext,
                                    authorization: EffectAuthorization, action_id: str,
                                    payload_digest: str, enrollment_id: str, target: str) -> object: ...


class IdempotencyLedger(Protocol):
    def claim(self, key: str, request_digest: str, operation_id: str) -> Mapping[str, Any]: ...
    def finish(self, key: str, state: str, receipt: Mapping[str, Any]) -> None: ...


class SystemMembershipVerifier(Protocol):
    def require_fresh_system_member(self, *, context: HostContext,
                                   authorization: EffectAuthorization) -> None: ...


class AuthentikReadPolicy(Protocol):
    def principal_snapshot(self, context: HostContext, *,
                           require_system_membership: bool = False) -> object: ...
    def authorize_delivery_recipient(self, recipient_id: str) -> str: ...


@dataclass(frozen=True, slots=True)
class AuthentikSystemMembershipVerifier:
    """Apply the existing root-owned fresh hierarchy check to homelab writes."""
    policy: AuthentikReadPolicy

    def require_fresh_system_member(self, *, context: HostContext,
                                    authorization: EffectAuthorization) -> None:
        snapshot = self.policy.principal_snapshot(context, require_system_membership=True)
        if getattr(snapshot, "system_member", None) is not True:
            raise HomelabEffectDenied("system.denied", "principal is not a current effective System member")


@dataclass(frozen=True, slots=True)
class HomelabTargetEnrollment:
    """Root-enrolled provider scope. IDs and service URLs never come from a tool."""
    adapter_id: str
    enrollment_id: str
    principal_id: str
    profile_id: str
    recipient: str | None
    account_id: str | None = None
    zone_id: str | None = None
    tunnel_ids: Mapping[str, str] | None = None
    dns_record_ids: Mapping[str, str] | None = None
    tunnel_hostname_by_id: Mapping[str, str] | None = None
    tunnel_service_by_hostname: Mapping[str, str] | None = None
    broker_origin: str | None = None
    host_target_ids: Mapping[str, str] | None = None
    credential_reference_id: str | None = None
    credential_scope: str | None = None
    action_ids: frozenset[str] = frozenset()
    system_recipient_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.adapter_id not in _MANIFESTS:
            raise ValueError("unsupported homelab adapter")
        for name in ("enrollment_id", "principal_id", "profile_id"):
            if not isinstance(getattr(self, name), str) or not _ID.fullmatch(getattr(self, name)):
                raise ValueError(f"invalid protected {name}")
        if self.recipient is not None and (not isinstance(self.recipient, str) or not _ID.fullmatch(self.recipient)):
            raise ValueError("protected recipient is malformed")
        for name in ("tunnel_ids", "dns_record_ids", "tunnel_hostname_by_id",
                     "tunnel_service_by_hostname", "host_target_ids"):
            value = getattr(self, name) or {}
            if not isinstance(value, Mapping):
                raise ValueError(f"protected {name} must be a mapping")
            object.__setattr__(self, name, MappingProxyType(dict(value)))
        if self.adapter_id == "cloudflare-homelab":
            if not all(isinstance(x, str) and _CF_ID.fullmatch(x) for x in (self.account_id, self.zone_id)):
                raise ValueError("Cloudflare account and zone must be explicitly enrolled")
            if set(self.tunnel_ids or {}) - _TUNNELS or set(self.dns_record_ids or {}) - _HOSTNAMES:
                raise ValueError("Cloudflare enrollment exceeds the fixed tunnel or hostname set")
            if any(not isinstance(x, str) or not _CF_ID.fullmatch(x) for x in (self.tunnel_ids or {}).values()):
                raise ValueError("Cloudflare tunnel ID is malformed")
            if any(not isinstance(x, str) or not _CF_ID.fullmatch(x) for x in (self.dns_record_ids or {}).values()):
                raise ValueError("Cloudflare DNS record ID is malformed")
            if set(self.tunnel_hostname_by_id or {}) - _TUNNELS or any(x not in _HOSTNAMES for x in (self.tunnel_hostname_by_id or {}).values()):
                raise ValueError("Cloudflare tunnel-to-hostname map exceeds the fixed owned set")
            if set(self.tunnel_hostname_by_id or {}) - set(self.tunnel_ids or {}):
                raise ValueError("tunnel hostname map contains an unenrolled tunnel")
            if set(self.tunnel_service_by_hostname or {}) - _HOSTNAMES or any(
                    not _valid_local_service(x) for x in (self.tunnel_service_by_hostname or {}).values()):
                raise ValueError("Cloudflare tunnel service routes must be fixed protected localhost/private-service references")
            if not isinstance(self.credential_reference_id, str) or not _ID.fullmatch(self.credential_reference_id):
                raise ValueError("Cloudflare token reference is required")
        if self.adapter_id == "homelab-ops-broker":
            if not _valid_https_origin(self.broker_origin):
                raise ValueError("broker origin must be a protected HTTPS origin")
            if set(self.host_target_ids or {}) != _HOSTS or any(not isinstance(x, str) or not _ID.fullmatch(x) for x in (self.host_target_ids or {}).values()):
                raise ValueError("both fixed physical host targets must be enrolled")
            if not isinstance(self.credential_reference_id, str) or not _ID.fullmatch(self.credential_reference_id):
                raise ValueError("broker credential reference is required")
        if self.adapter_id == "authentik-authorization":
            if any(not isinstance(x, str) or not _ID.fullmatch(x) for x in self.system_recipient_ids):
                raise ValueError("Authentik alarm recipients must be a root-enrolled principal ID list")
            if len(set(self.system_recipient_ids)) != len(self.system_recipient_ids):
                raise ValueError("Authentik recipient IDs must be unique")
        if not self.action_ids or any(not isinstance(x, str) or not _ID.fullmatch(x) for x in self.action_ids):
            raise ValueError("finite action allowlist is required")


@dataclass(frozen=True, slots=True)
class HomelabActionEnrollment:
    adapter_id: str
    manifest_sha256: str
    handler_artifact_id: str
    handler_sha256: str
    action_id: str
    argument_schema_id: str
    operation: str
    capability: str
    target_id: str
    generation: str
    principal_id: str
    profile_id: str
    recipient: str | None
    enrollment_id: str
    argument_schema: Mapping[str, Any]
    mutating: bool
    confirmation_policy_id: str | None = None
    idempotency_policy_id: str | None = None
    request_bytes_limit: int = MAX_REQUEST
    response_bytes_limit: int = MAX_RESPONSE
    deadline_seconds: float = MAX_DEADLINE

    def __post_init__(self) -> None:
        if self.adapter_id not in _MANIFESTS or self.manifest_sha256 != _MANIFESTS[self.adapter_id]:
            raise ValueError("plugin manifest digest is not the pinned reviewed source")
        if not _HEX.fullmatch(self.handler_sha256):
            raise ValueError("handler artifact digest is invalid")
        for name in ("handler_artifact_id", "action_id", "argument_schema_id", "target_id", "generation",
                     "principal_id", "profile_id", "enrollment_id"):
            if not isinstance(getattr(self, name), str) or not _ID.fullmatch(getattr(self, name)):
                raise ValueError(f"invalid {name}")
        if self.recipient is not None and (not isinstance(self.recipient, str) or not _ID.fullmatch(self.recipient)):
            raise ValueError("protected recipient is malformed")
        if self.capability != f"plugin:{self.adapter_id}" or self.operation not in _OPERATIONS[self.adapter_id]:
            raise ValueError("plugin capability or fixed operation mismatch")
        allowed_actions = {
            "authentik-authorization": _AUTHENTIK_ACTIONS,
            "cloudflare-homelab": _CLOUDFLARE_ACTIONS,
            "homelab-ops-broker": _OPS_READS | _OPS_WRITES,
        }[self.adapter_id]
        if self.action_id not in allowed_actions:
            raise ValueError("plugin action is outside the source-pinned manifest capability set")
        if not isinstance(self.argument_schema, Mapping) or type(self.mutating) is not bool:
            raise ValueError("action schema or mutating flag is invalid")
        if (type(self.request_bytes_limit) is not int or not 1 <= self.request_bytes_limit <= MAX_REQUEST
                or type(self.response_bytes_limit) is not int or not 1 <= self.response_bytes_limit <= MAX_RESPONSE
                or isinstance(self.deadline_seconds, bool) or not isinstance(self.deadline_seconds, (int, float))
                or not math.isfinite(self.deadline_seconds) or not 0.1 <= self.deadline_seconds <= MAX_DEADLINE):
            raise ValueError("homelab action bounds exceed hard limits")
        if self.mutating and self.idempotency_policy_id is None:
            raise ValueError("writes require enrolled idempotency policy")
        object.__setattr__(self, "argument_schema", MappingProxyType(dict(self.argument_schema)))

    @property
    def target(self) -> str:
        return f"plugin:{self.adapter_id}:{self.target_id}:{self.generation}"


def parse_homelab_action_record(record: Mapping[str, Any], *,
                                argument_schemas: Mapping[str, Mapping[str, Any]],
                                target: HomelabTargetEnrollment) -> HomelabActionEnrollment:
    """Decode one exact root-selected effect row and join only protected schema/target data."""
    if not isinstance(record, Mapping) or set(record) != PLUGIN_EFFECT_RECORD_FIELDS:
        raise ValueError("selected homelab effect record has unknown or missing fields")
    schema_id = record["argument_schema_id"]
    schema = argument_schemas.get(schema_id) if isinstance(schema_id, str) else None
    if not isinstance(schema, Mapping):
        raise ValueError("selected homelab action lacks its protected argument schema")
    adapter = record["adapter_id"]
    if (adapter != target.adapter_id or record["principal_id"] != target.principal_id
            or record["profile_id"] != target.profile_id or record["recipient"] != target.recipient):
        # `enrollment_id` is carried by the selected protected resource record,
        # not the fixed effect contract row. Keep that ID attached from target.
        raise ValueError("selected homelab action differs from its root target binding")
    if (record["credential_reference_id"] != target.credential_reference_id
            or record["scope_reference_id"] != target.credential_scope):
        raise ValueError("selected homelab action credential scope differs from target enrollment")
    operation = record["operation"]
    mutating = isinstance(operation, str) and operation.endswith(".write")
    if operation not in _OPERATIONS.get(adapter, frozenset()):
        raise ValueError("selected homelab action uses an unknown operation")
    return HomelabActionEnrollment(
        adapter_id=adapter, manifest_sha256=record["manifest_sha256"],
        handler_artifact_id=record["handler_artifact_id"], handler_sha256=record["handler_sha256"],
        action_id=record["action_id"], argument_schema_id=schema_id,
        operation=operation, capability=record["capability"], target_id=record["target_id"],
        generation=record["generation"], principal_id=record["principal_id"],
        profile_id=record["profile_id"], recipient=record["recipient"],
        enrollment_id=target.enrollment_id, argument_schema=schema, mutating=mutating,
        confirmation_policy_id=record["confirmation_policy_id"],
        idempotency_policy_id=record["idempotency_policy_id"],
        request_bytes_limit=record["request_bytes_limit"],
        response_bytes_limit=record["response_bytes_limit"],
        deadline_seconds=record["deadline_seconds"],
    )


class HomelabBackend(Protocol):
    def invoke(self, *, target: HomelabTargetEnrollment, action: HomelabActionEnrollment,
               arguments: Mapping[str, Any], credential: str, timeout: float,
               cancelled: Callable[[], bool]) -> Mapping[str, Any]: ...


class FixedHomelabHTTPSBackend:
    """Bounded HTTPS implementation for enrolled Cloudflare and ops-broker scopes."""
    def __init__(self, network: BoundedNetwork | None = None):
        self.network = network or BoundedNetwork(deadline_seconds=MAX_DEADLINE,
            max_response_bytes=MAX_RESPONSE)

    def invoke(self, *, target: HomelabTargetEnrollment, action: HomelabActionEnrollment,
               arguments: Mapping[str, Any], credential: str, timeout: float,
               cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        if cancelled():
            raise HomelabEffectDenied("effect.cancelled", "effect cancelled before network dispatch")
        if target.adapter_id == "cloudflare-homelab":
            return self._cloudflare(target, action, arguments, credential, cancelled)
        if target.adapter_id == "homelab-ops-broker":
            return self._ops(target, action, arguments, credential, timeout, cancelled)
        raise HomelabEffectDenied("effect.unavailable", "Authentik root reader is not enrolled")

    def _request(self, url: str, method: str, token: str, body: Mapping[str, Any] | None,
                 cancelled: Callable[[], bool]) -> Any:
        if not url.startswith("https://api.cloudflare.com/client/v4/") and not url.startswith("https://"):
            raise HomelabEffectDenied("endpoint.invalid", "fixed HTTPS endpoint is invalid")
        encoded = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        if encoded is not None and len(encoded) > MAX_REQUEST:
            raise HomelabEffectDenied("request.bounds", "provider request exceeds hard limit")
        try:
            response = self.network.request(url, method=method,
                headers={"Authorization": "Bearer " + token, "Accept": "application/json",
                         "Content-Type": "application/json"}, body=encoded, cancelled=cancelled)
        except (NetworkError, OSError):
            raise HomelabEffectDenied("network.failed", "fixed provider HTTPS request failed") from None
        if not 200 <= response.status < 300 or len(response.body) > MAX_RESPONSE:
            raise HomelabEffectDenied("provider.failed", "fixed provider returned unsuccessful or oversized response")
        try:
            value = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HomelabEffectDenied("provider.response", "fixed provider response is malformed") from None
        return value

    def _cloudflare(self, target: HomelabTargetEnrollment, action: HomelabActionEnrollment,
                    args: Mapping[str, Any], token: str, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        root = "https://api.cloudflare.com/client/v4"
        zone, account = quote(target.zone_id or "", safe=""), quote(target.account_id or "", safe="")
        act = action.action_id
        if act == "read-approved-dns-records":
            hostname = _approved_hostname(args.get("hostname"))
            record_id = (target.dns_record_ids or {}).get(hostname)
            if record_id is None: raise HomelabEffectDenied("target.unenrolled", "DNS record is not root-enrolled")
            path = f"/zones/{zone}/dns_records/{quote(record_id, safe='')}"
            data = self._request(root + path, "GET", token, None, cancelled)
            record = _cf_result(data)
            _assert_owned_dns_record(record, record_id, hostname)
            return record
        if act == "update-approved-dns-record":
            hostname = _approved_hostname(args.get("hostname"))
            record_id = (target.dns_record_ids or {}).get(hostname)
            if record_id is None: raise HomelabEffectDenied("target.unenrolled", "DNS record is not root-enrolled")
            # Read before update and preserve identity/type/name; a stale/replaced or
            # unowned row is a hard conflict, never silently adopted.
            path = f"/zones/{zone}/dns_records/{quote(record_id, safe='')}"
            current = _cf_result(self._request(root + path, "GET", token, None, cancelled))
            _assert_owned_dns_record(current, record_id, hostname)
            typ = current.get("type")
            if typ not in {"A", "AAAA", "CNAME"}:
                raise HomelabEffectDenied("target.conflict", "enrolled DNS record type is unsupported")
            content, ttl, proxied = args.get("content"), args.get("ttl"), args.get("proxied")
            if not isinstance(content, str) or not 1 <= len(content) <= 253 or any(ch in content for ch in "\r\n\x00"):
                raise HomelabEffectDenied("arguments.content", "DNS content is invalid")
            if type(ttl) is not int or not 60 <= ttl <= 86400 or type(proxied) is not bool:
                raise HomelabEffectDenied("arguments.record", "DNS TTL or proxy flag is invalid")
            try:
                address = ipaddress.ip_address(content)
            except ValueError:
                allowed_cnames = {f"{item}.cfargotunnel.com" for item in (target.tunnel_ids or {}).values()}
                if (typ != "CNAME" or content.rstrip(".").casefold() not in allowed_cnames
                        and not re.fullmatch(r"[A-Za-z0-9.-]+\.togarriapahome\.uk\.?", content, re.IGNORECASE)):
                    raise HomelabEffectDenied("arguments.content", "DNS target must be a valid IP or enrolled-domain CNAME")
            else:
                if typ == "A" and address.version != 4 or typ == "AAAA" and address.version != 6 or typ == "CNAME":
                    raise HomelabEffectDenied("arguments.content", "DNS address family does not match the owned record type")
            data = self._request(root + path, "PUT", token, {"type": typ, "name": hostname,
                "content": content, "ttl": ttl, "proxied": proxied}, cancelled)
            return _cf_result(data)
        tunnel = args.get("tunnel")
        if tunnel in _TUNNELS:
            tunnel_id = (target.tunnel_ids or {}).get(tunnel)
            if tunnel_id is None: raise HomelabEffectDenied("target.unenrolled", "tunnel is not root-enrolled")
            tid = quote(tunnel_id, safe="")
            base = f"{root}/accounts/{account}/cfd_tunnel/{tid}"
            if act == "read-approved-tunnel-state":
                return _cf_result(self._request(base, "GET", token, None, cancelled))
            if act == "read-approved-tunnel-connectors":
                return _cf_result(self._request(base + "/connections", "GET", token, None, cancelled))
            if act in {"read-approved-tunnel-configuration", "update-approved-tunnel-configuration"}:
                config_url = base + "/configurations"
                data = _cf_result(self._request(config_url, "GET", token, None, cancelled))
                if act == "read-approved-tunnel-configuration": return data
                # Reconcile a single enrolled hostname route while preserving all other
                # route data. Desired service is a root-protected local service reference.
                config = data.get("config") if isinstance(data, Mapping) else None
                ingress = config.get("ingress") if isinstance(config, Mapping) else None
                host = _approved_hostname(args.get("hostname"))
                if (target.tunnel_hostname_by_id or {}).get(tunnel) != host:
                    raise HomelabEffectDenied("target.denied", "hostname does not match the enrolled tunnel mapping")
                service = (target.tunnel_service_by_hostname or {}).get(host)
                if service is None:
                    raise HomelabEffectDenied("effect.unavailable", "approved tunnel service route is not root-enrolled")
                if not isinstance(ingress, list) or not ingress or not isinstance(ingress[-1], Mapping) or ingress[-1].get("service") != "http_status:404":
                    raise HomelabEffectDenied("target.conflict", "tunnel ingress does not have the enrolled safe terminal rule")
                matches = [row for row in ingress[:-1] if isinstance(row, Mapping) and row.get("hostname") == host]
                if len(matches) != 1: raise HomelabEffectDenied("target.conflict", "hostname route is absent or ambiguous")
                updated = dict(config)
                rules = [dict(row) if row is matches[0] else row for row in ingress]
                route_index = next(index for index, row in enumerate(ingress[:-1]) if row is matches[0])
                rules[route_index]["service"] = service
                updated["ingress"] = rules
                if _canonical(updated) == _canonical(config):
                    return {"unchanged": True, "hostname": host, "tunnel": tunnel}
                return _cf_result(self._request(config_url, "PUT", token, updated, cancelled))
        raise HomelabEffectDenied("action.unsupported", "Cloudflare action is outside the fixed handler set")

    def _ops(self, target: HomelabTargetEnrollment, action: HomelabActionEnrollment,
             args: Mapping[str, Any], token: str, timeout: float,
             cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        operation = args.get("action") if action.mutating else args.get("query")
        host = args.get("host")
        allowed_operations = _OPS_WRITES if action.mutating else _OPS_READS
        if host not in _HOSTS or operation not in allowed_operations or operation != action.action_id:
            raise HomelabEffectDenied("action.unsupported", "host operation is outside the fixed allowlist")
        is_write = operation in _OPS_WRITES
        if is_write != action.mutating:
            raise HomelabEffectDenied("action.binding", "read/write operation does not match enrolled effect")
        target_id = (target.host_target_ids or {}).get(host)
        if target_id is None: raise HomelabEffectDenied("target.unenrolled", "physical host target is not enrolled")
        # Protocol contract is deliberately path-fixed. No caller path, argv, URL,
        # command, service name, or filesystem target is forwarded.
        url = f"{target.broker_origin}/v1/targets/{quote(target_id, safe='')}/operations/{quote(operation, safe='')}"
        value = self._request(url, "POST" if is_write else "GET", token,
                              {"arguments": {}} if is_write else None, cancelled)
        if not isinstance(value, Mapping) or value.get("success") is not True or not isinstance(value.get("result"), (dict, list, str, int, float, bool, type(None))):
            raise HomelabEffectDenied("provider.response", "operations broker response violates the fixed schema")
        return {"result": value["result"]}


def build_plugin_homelab_effect_handlers(*,
    actions: Mapping[tuple[str, str], tuple[HomelabActionEnrollment, HomelabTargetEnrollment]],
    vault: HomelabVault, backend: HomelabBackend, ledger: IdempotencyLedger,
    confirmation: ConfirmationVerifier | None = None,
    system_membership: SystemMembershipVerifier | None = None,
    authentik_policy: AuthentikReadPolicy | None = None,
) -> dict[tuple[str, str], Callable[..., Mapping[str, Any]]]:
    """Construct exact root handlers; absent endpoint/account enrollments stay absent."""
    handlers = {}
    seen: set[tuple[str, str, str]] = set()
    for key, pair in actions.items():
        if not isinstance(pair, tuple) or len(pair) != 2: raise ValueError("plugin enrollment pair is malformed")
        action, target = pair
        if not isinstance(action, HomelabActionEnrollment) or not isinstance(target, HomelabTargetEnrollment):
            raise ValueError("typed protected homelab enrollment records are required")
        if (action.adapter_id != target.adapter_id or action.enrollment_id != target.enrollment_id
                or action.principal_id != target.principal_id or action.profile_id != target.profile_id
                or action.recipient != target.recipient or action.action_id not in target.action_ids
                or key != (action.operation, action.target)):
            raise ValueError("action is not bound to the selected protected target enrollment")
        unique = (action.adapter_id, action.enrollment_id, action.action_id)
        if unique in seen: raise ValueError("duplicate homelab action enrollment")
        seen.add(unique)
        if action.adapter_id == "authentik-authorization":
            if authentik_policy is None:
                continue  # A public root-owned identity reader is not enrolled.
            if (action.action_id == "list-current-effective-System-members-for-alarm-delivery"
                    and not target.system_recipient_ids):
                continue
            handlers[key] = _authentik_handler(action, target, authentik_policy)
            continue
        def handler(*, context: HostContext, authorization: EffectAuthorization,
                    payload: bytes, timeout: float, peer_pid: int,
                    cancelled: Callable[[], bool], _action=action, _target=target) -> Mapping[str, Any]:
            result = _perform(_action, _target, context, authorization, payload, timeout, peer_pid,
                              cancelled, vault, backend, ledger, confirmation, system_membership)
            body = _canonical(result)
            return {"status": 200, "body": body, "headers": {"Content-Type": "application/json"},
                    "receipt_id": result["operation_id"]}
        handlers[key] = handler
    return handlers


def _authentik_handler(action: HomelabActionEnrollment, target: HomelabTargetEnrollment,
                       policy: AuthentikReadPolicy) -> Callable[..., Mapping[str, Any]]:
    def handler(*, context: HostContext, authorization: EffectAuthorization,
                payload: bytes, timeout: float, peer_pid: int,
                cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        request = _parse(payload, action)
        digest = canonical_digest(payload)
        if (digest != authorization.request_digest or digest != context.final_payload_digest
                or authorization.final_payload_digest != digest
                or authorization.capability != action.capability or authorization.target != action.target
                or authorization.operation != action.operation or context.operation != action.operation
                or authorization.enrollment_id != target.enrollment_id
                or authorization.generation != action.generation
                or authorization.principal_id != target.principal_id
                or authorization.profile_id != target.profile_id
                or context.principal_id != target.principal_id or context.profile_id != target.profile_id
                or authorization.recipient != target.recipient
                or action.capability not in context.capabilities or peer_pid <= 0
                or not math.isfinite(timeout) or timeout <= 0 or timeout > action.deadline_seconds
                or authorization.monotonic_expires_at <= time.monotonic() or cancelled()):
            raise HomelabEffectDenied("grant.binding", "fresh Authentik read grant does not match its selected action")
        try:
            result = _authentik_read(policy, action.action_id, target, context)
        except Exception:
            raise HomelabEffectDenied("authentik.denied", "fresh Authentik read is unavailable or denied") from None
        safe = _safe_json(result)
        if not isinstance(safe, Mapping) or len(_canonical(safe)) > action.response_bytes_limit:
            raise HomelabEffectDenied("response.bounds", "Authentik result exceeds its enrolled response bound")
        response = _response(uuid.uuid4().hex, "read-complete", safe, "fresh-authentik-observation", None)
        body = _canonical(response)
        return {"status": 200, "body": body, "headers": {"Content-Type": "application/json"},
                "receipt_id": response["operation_id"]}
    return handler


def _authentik_read(policy: AuthentikReadPolicy, action_id: str,
                    target: HomelabTargetEnrollment, context: HostContext) -> Mapping[str, Any]:
    if action_id not in {"resolve-session-principal-to-user", "read-active-user-identity",
                         "read-user-effective-groups", "verify-effective-System-membership",
                         "list-current-effective-System-members-for-alarm-delivery"}:
        raise HomelabEffectDenied("action.unsupported", "Authentik action is outside its read-only contract")
    require_system = action_id == "list-current-effective-System-members-for-alarm-delivery"
    snapshot = policy.principal_snapshot(context, require_system_membership=require_system)
    if action_id == "resolve-session-principal-to-user":
        return {"principal_id": snapshot.principal_id, "subject_id": snapshot.subject_id,
                "policy_revision": snapshot.policy_revision,
                "checked_at_monotonic": snapshot.checked_at_monotonic}
    if action_id == "read-active-user-identity":
        return {"principal_id": snapshot.principal_id, "username": snapshot.username,
                "email": snapshot.email, "subject_id": snapshot.subject_id,
                "checked_at_monotonic": snapshot.checked_at_monotonic}
    if action_id == "read-user-effective-groups":
        return {"direct_group_ids": sorted(snapshot.direct_group_ids),
                "effective_group_ids": sorted(snapshot.effective_group_ids),
                "checked_at_monotonic": snapshot.checked_at_monotonic}
    if action_id == "verify-effective-System-membership":
        return {"system_member": snapshot.system_member,
                "policy_revision": snapshot.policy_revision,
                "checked_at_monotonic": snapshot.checked_at_monotonic}
    recipients = []
    for recipient_id in target.system_recipient_ids:
        email = policy.authorize_delivery_recipient(recipient_id)
        recipients.append({"recipient_id": recipient_id, "email": email})
    return {"system_recipients": recipients,
            "policy_revision": snapshot.policy_revision,
            "checked_at_monotonic": snapshot.checked_at_monotonic}


def _perform(action: HomelabActionEnrollment, target: HomelabTargetEnrollment,
             context: HostContext, authorization: EffectAuthorization, payload: bytes,
             timeout: float, peer_pid: int, cancelled: Callable[[], bool], vault: HomelabVault,
             backend: HomelabBackend, ledger: IdempotencyLedger,
             confirmation: ConfirmationVerifier | None,
             system_membership: SystemMembershipVerifier | None) -> Mapping[str, Any]:
    req = _parse(payload, action)
    digest = canonical_digest(payload)
    if (digest != authorization.request_digest or digest != context.final_payload_digest
            or authorization.final_payload_digest != digest or authorization.capability != action.capability
            or authorization.target != action.target or authorization.operation != action.operation
            or context.operation != action.operation or authorization.enrollment_id != target.enrollment_id
            or authorization.generation != action.generation or authorization.principal_id != target.principal_id
            or authorization.profile_id != target.profile_id or context.principal_id != target.principal_id
            or context.profile_id != target.profile_id or authorization.recipient != target.recipient
            or action.capability not in context.capabilities or peer_pid <= 0
            or not math.isfinite(timeout) or timeout <= 0 or timeout > action.deadline_seconds
            or authorization.monotonic_expires_at <= time.monotonic()):
        raise HomelabEffectDenied("grant.binding", "fresh one-use effect grant does not match the enrolled action")
    args = req["arguments"]
    idem = req.get("idempotency_key")
    operation_id = uuid.uuid4().hex
    ledger_key = None
    if action.mutating:
        if system_membership is None:
            raise HomelabEffectDenied("authority.unavailable", "fresh System membership checker is not enrolled")
        system_membership.require_fresh_system_member(context=context, authorization=authorization)
        if action.confirmation_policy_id:
            if confirmation is None or not req.get("opaque_confirmation_attestation_id"):
                raise HomelabEffectDenied("confirmation.required", "trusted exact-payload human confirmation is required")
            if confirmation.consume_plugin_confirmation(
                    attestation_id=req["opaque_confirmation_attestation_id"], context=context,
                    authorization=authorization, action_id=action.action_id, payload_digest=digest,
                    enrollment_id=target.enrollment_id, target=action.target) is None:
                raise HomelabEffectDenied("confirmation.denied", "trusted human confirmation was denied")
    if cancelled() or authorization.monotonic_expires_at <= time.monotonic():
        raise HomelabEffectDenied("effect.expired", "plugin effect was cancelled or expired")
    ref = target.credential_reference_id
    if ref is None: raise HomelabEffectDenied("credential.unavailable", "root credential reference is not enrolled")
    credential = vault.resolve_reference(ref, peer_uid=0, required_scope=target.credential_scope,
                                         principal_id=target.principal_id)
    if not isinstance(credential, str) or not credential or any(ch in credential for ch in "\x00\r\n"):
        raise HomelabEffectDenied("credential.invalid", "root credential value is invalid")
    if action.mutating:
        if idem is None: raise HomelabEffectDenied("request.idempotency", "write requires idempotency key")
        ledger_key = canonical_digest({"principal": context.principal_id, "adapter": action.adapter_id,
            "enrollment": target.enrollment_id, "target": action.target, "action": action.action_id,
            "digest": digest, "key": idem})
        prior = ledger.claim(ledger_key, digest, operation_id)
        if prior["state"] != "new":
            return _response(prior["operation_id"], "ambiguous" if prior["state"] in {"pending", "ambiguous"} else prior["state"],
                             prior.get("receipt", {}), "reconciliation-required", action.action_id)
    try:
        result = backend.invoke(target=target, action=action, arguments=args, credential=credential,
                                timeout=min(timeout, action.deadline_seconds), cancelled=cancelled)
    except Exception as exc:
        pre_effect_codes = {"target.conflict", "target.unenrolled", "target.denied", "action.unsupported",
                            "action.binding", "provider.failed", "provider.response"}
        before_effect = isinstance(exc, HomelabEffectDenied) and exc.code in pre_effect_codes
        if ledger_key:
            ledger.finish(ledger_key, "failed-before-effect" if before_effect else "ambiguous",
                          {"action_id": action.action_id, "digest": digest,
                           "reason": exc.code if before_effect else "outcome-unknown"})
        if before_effect:
            raise
        return _response(operation_id, "ambiguous", {}, "unknown-outcome", action.action_id) if ledger_key else _safe_failure()
    if not isinstance(result, Mapping):
        if ledger_key: ledger.finish(ledger_key, "ambiguous", {"action_id": action.action_id, "digest": digest})
        raise HomelabEffectDenied("provider.response", "fixed provider returned malformed result")
    safe = _safe_json(result)
    if len(_canonical(safe)) > action.response_bytes_limit:
        raise HomelabEffectDenied("response.bounds", "provider result exceeds enrolled response bound")
    if ledger_key:
        ledger.finish(ledger_key, "ambiguous", {"action_id": action.action_id, "digest": digest,
                                                 "result": safe})
        # Cloudflare has no universal transaction ID/conditional update, so an
        # acknowledged write remains unverified and requires a fresh read.
        return _response(operation_id, "ambiguous", safe, "verification-required", action.action_id)
    return _response(operation_id, "read-complete", safe, "not-applicable", None)


def _parse(payload: bytes, action: HomelabActionEnrollment) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= action.request_bytes_limit:
        raise HomelabEffectDenied("request.bounds", "plugin payload exceeds enrolled request limit")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise HomelabEffectDenied("request.format", "plugin payload is malformed") from None
    fields = {"schema", "adapter_id", "action_id", "enrollment_id", "generation", "arguments",
              "idempotency_key", "opaque_confirmation_attestation_id"}
    if (not isinstance(value, dict) or set(value) - fields or value.get("schema") != 1
            or value.get("adapter_id") != action.adapter_id or value.get("action_id") != action.action_id
            or value.get("enrollment_id") != action.enrollment_id or value.get("generation") != action.generation
            or not isinstance(value.get("arguments"), dict)):
        raise HomelabEffectDenied("request.scope", "payload differs from exact selected plugin enrollment")
    required = {"schema", "adapter_id", "action_id", "enrollment_id", "generation", "arguments"}
    if action.mutating: required.add("idempotency_key")
    if action.confirmation_policy_id: required.add("opaque_confirmation_attestation_id")
    if set(value) != required:
        raise HomelabEffectDenied("request.fields", "payload fields do not match the enrolled read/write schema")
    if action.mutating and not _ID.fullmatch(value["idempotency_key"]):
        raise HomelabEffectDenied("request.idempotency", "write idempotency reference is malformed")
    if action.confirmation_policy_id and not _ID.fullmatch(value["opaque_confirmation_attestation_id"]):
        raise HomelabEffectDenied("request.attestation", "confirmation attestation is malformed")
    if not action.confirmation_policy_id and "opaque_confirmation_attestation_id" in value:
        raise HomelabEffectDenied("request.attestation", "unexpected confirmation attestation")
    _validate_schema(action.argument_schema, value["arguments"])
    if _canonical(value) != payload:
        raise HomelabEffectDenied("request.canonical", "payload must be canonical JSON")
    return value


def _validate_schema(schema: Mapping[str, Any], value: Any, depth: int = 0) -> None:
    if depth > 8 or not isinstance(schema, Mapping): raise ValueError("enrolled schema is invalid")
    kind = schema.get("type")
    if kind == "object":
        props, required = schema.get("properties"), set(schema.get("required", ()))
        if schema.get("additionalProperties", False) is not False or not isinstance(props, Mapping): raise ValueError("object schema must be closed")
        if not isinstance(value, Mapping) or set(value) - set(props) or required - set(value): raise HomelabEffectDenied("arguments.object", "arguments differ from the root schema")
        for key, item in value.items(): _validate_schema(props[key], item, depth + 1)
    elif kind == "array":
        items = schema.get("items")
        if not isinstance(value, list) or len(value) > schema.get("maxItems", 128): raise HomelabEffectDenied("arguments.array", "array arguments exceed schema bounds")
        for item in value: _validate_schema(items, item, depth + 1)
    else:
        valid = {"string": isinstance(value, str), "integer": type(value) is int,
                 "boolean": type(value) is bool, "number": type(value) in {int, float}}.get(kind, False)
        if not valid: raise HomelabEffectDenied("arguments.type", "argument type differs from root schema")
        if "enum" in schema and value not in schema["enum"]: raise HomelabEffectDenied("arguments.enum", "argument is outside enrolled choices")
        if kind == "string" and (len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 65536)
                                  or "pattern" in schema and not re.fullmatch(schema["pattern"], value)):
            raise HomelabEffectDenied("arguments.value", "string argument violates root schema")
        if kind in {"integer", "number"} and ("minimum" in schema and value < schema["minimum"] or "maximum" in schema and value > schema["maximum"]):
            raise HomelabEffectDenied("arguments.range", "numeric argument violates root schema")


def _approved_hostname(value: Any) -> str:
    if value not in _HOSTNAMES: raise HomelabEffectDenied("target.denied", "hostname is outside the approved set")
    return value


def _valid_https_origin(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 512:
        return False
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return False
    return (parts.scheme == "https" and bool(parts.hostname)
            and parts.username is None and parts.password is None
            and not parts.path and not parts.query and not parts.fragment
            and (port is None or 1 <= port <= 65535)
            and re.fullmatch(r"[A-Za-z0-9.-]+", parts.hostname) is not None)


def _valid_local_service(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 512:
        return False
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return False
    if (parts.scheme not in {"http", "https"} or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or port is not None and not 1 <= port <= 65535):
        return False
    host = parts.hostname.casefold()
    if host == "localhost" or host.endswith((".local", ".lan", ".internal")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback


def _cf_result(value: Any) -> Any:
    if not isinstance(value, Mapping) or value.get("success") is not True:
        raise HomelabEffectDenied("provider.response", "Cloudflare response indicates failure")
    return value.get("result")


def _assert_owned_dns_record(value: Any, record_id: str, hostname: str) -> None:
    if (not isinstance(value, Mapping) or value.get("id") != record_id
            or not isinstance(value.get("name"), str)
            or value["name"].rstrip(".").casefold() != hostname.casefold()):
        raise HomelabEffectDenied("target.conflict", "enrolled DNS record no longer matches its owned hostname")


def _response(operation_id: str, state: str, result: Any, verification: str,
              resume: str | None) -> Mapping[str, Any]:
    value = {"schema": 1, "operation_id": operation_id, "state": state,
             "result": _safe_json(result), "verification_status": verification,
             "resume_action_id": resume}
    if state not in {"committed", "read-complete", "pending", "ambiguous", "unavailable"}:
        raise HomelabEffectDenied("response.state", "invalid operation state")
    return value


def _safe_failure() -> Mapping[str, Any]:
    raise HomelabEffectDenied("provider.failed", "fixed provider effect failed")


def _safe_json(value: Any, depth: int = 0) -> Any:
    if depth > 12: raise HomelabEffectDenied("response.depth", "provider response is too deep")
    if value is None or type(value) in {bool, int, str}: return value
    if type(value) is float and math.isfinite(value): return value
    if isinstance(value, Mapping):
        return {key: _safe_json(item, depth + 1) for key, item in value.items()
                if isinstance(key, str) and key.casefold() not in {"token", "secret", "password", "authorization", "cookie", "access_token"}}
    if isinstance(value, (tuple, list)): return [_safe_json(item, depth + 1) for item in value[:1024]]
    raise HomelabEffectDenied("response.shape", "provider response contains unsupported data")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate key")
        result[key] = value
    return result
