"""Typed component-side dispatch for RB08 protected Plugin effects.

The native adapter supplies a reviewed action ID and its typed arguments. A
root-selected resolver supplies the immutable enrollment, and the trusted host
AuthorityClient binds the canonical request bytes to a fresh, one-use grant.
Neither the Plugin manifest nor tool arguments can select a target, recipient,
operation, capability, account, credential, generation, or executable.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol


class PluginEffectUnavailable(PermissionError):
    """A selected root-owned Plugin effect is not enrolled or did not verify."""


class SelectedPluginEffect(Protocol):
    """Immutable resolver display row; authority must re-resolve on dispatch."""
    adapter_id: str
    manifest_sha256: str
    adapter_sha256: str
    action_id: str
    argument_schema_id: str
    result_schema_id: str
    effect_enrollment_id: str
    operation: str
    capability: str
    target_id: str
    recipient: str | None
    generation: str


class SelectedPluginEffectsResolver(Protocol):
    """Trusted resolver over root-enrolled selected per-action records."""

    def resolve(self, adapter_id: str, action_id: str) -> SelectedPluginEffect | None: ...


class PluginAuthority(Protocol):
    def context(self, *, purpose: str, intent: str, operation: str,
                source_contexts: Sequence[object] = (),
                source_receipt_handles: Sequence[str] = (),
                final_payload_digest: str,
                lease_seconds: float) -> object: ...

    def authorize_effect(self, context: object, *, capability: str, target: str,
                         recipient: str | None, request_digest: str,
                         retry_index: int = 0) -> object: ...

    def verify_effect(self, authorization: object, context: object, *, capability: str,
                      target: str, recipient: str | None, request_digest: str,
                      retry_index: int = 0) -> object: ...

    def perform_effect(self, authorization: object, *, operation: str, payload: bytes,
                       timeout: float) -> object: ...


class InvocationContexts(Protocol):
    def __call__(self, *, adapter_id: str, action_id: str,
                 arguments_sha256: str, purpose: str, intent: str) -> object: ...


class NativeInvocationContexts(Protocol):
    """Root response for one currently executing pinned Hermes tool call."""
    schema: int
    invocation_handle: str
    source_receipt_handles: Sequence[str]
    parent_closure_digest: str
    arguments_sha256: str
    expires_monotonic: float


def root_invocation_source_receipt_handles(
    invocation_contexts: InvocationContexts, *, adapter_id: str, action_id: str,
    arguments_sha256: str, purpose: str, intent: str,
) -> tuple[str, ...]:
    """Resolve root-owned lineage for this exact selected tool invocation.

    The provider is expected to read only the opaque invocation binding scoped
    by the trusted native tool executor, then call the root get-contexts RPC.
    This helper validates the bounded response DTO; receipt handles remain
    opaque and are accepted only by AuthorityClient.context.
    """
    lineage = invocation_contexts(
        adapter_id=adapter_id, action_id=action_id,
        arguments_sha256=arguments_sha256, purpose=purpose, intent=intent,
    )
    handles = getattr(lineage, "source_receipt_handles", None)
    handles_valid = (
        isinstance(handles, (tuple, list)) and len(handles) <= 64
        and all(isinstance(handle, str)
                and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle)
                for handle in handles)
    )
    expires = getattr(lineage, "expires_monotonic", None)
    if (getattr(lineage, "schema", None) != 1
            or not isinstance(getattr(lineage, "invocation_handle", None), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", lineage.invocation_handle)
            or not _HEX.fullmatch(getattr(lineage, "parent_closure_digest", ""))
            or getattr(lineage, "arguments_sha256", None) != arguments_sha256
            or isinstance(expires, bool) or not isinstance(expires, (int, float))
            or not time.monotonic() < expires <= time.monotonic() + 30
            or not handles_valid):
        raise PluginEffectUnavailable("trusted invocation lineage is unavailable")
    return tuple(handles)


@dataclass(frozen=True, slots=True)
class PluginActionSchema:
    adapter_id: str
    action_id: str
    argument_schema_id: str
    result_schema_id: str
    operation: str
    adapter_sha256: str
    argument_schema: Mapping[str, Any]
    result_schema: Mapping[str, Any]
    request_bytes_limit: int = 262_144
    response_bytes_limit: int = 2_097_152
    deadline_seconds: float = 30.0
    requires_idempotency: bool = False
    requires_confirmation: bool = False
    expected_state: str = "read-complete"


class PluginActionSchemaRegistry(Protocol):
    def resolve(self, adapter_id: str, action_id: str) -> PluginActionSchema | None: ...


class StaticPluginActionSchemas:
    """Installer-owned source schema table; declarations cannot extend it."""

    def __init__(self, schemas: Mapping[tuple[str, str], PluginActionSchema]):
        if not isinstance(schemas, Mapping):
            raise TypeError("component-owned Plugin action schemas are required")
        checked: dict[tuple[str, str], PluginActionSchema] = {}
        for key, schema in schemas.items():
            if (not isinstance(key, tuple) or len(key) != 2
                    or not isinstance(schema, PluginActionSchema)
                    or key != (schema.adapter_id, schema.action_id)
                    or schema.operation not in _OPERATIONS.get(schema.adapter_id, ())
                    or not _HEX.fullmatch(schema.adapter_sha256)
                    or not _OPAQUE.fullmatch(schema.argument_schema_id)
                    or not _OPAQUE.fullmatch(schema.result_schema_id)
                    or type(schema.request_bytes_limit) is not int
                    or not 1 <= schema.request_bytes_limit <= 262_144
                    or type(schema.response_bytes_limit) is not int
                    or not 1 <= schema.response_bytes_limit <= 2_097_152
                    or isinstance(schema.deadline_seconds, bool)
                    or not isinstance(schema.deadline_seconds, (int, float))
                    or not math.isfinite(schema.deadline_seconds)
                    or not 0.1 <= schema.deadline_seconds <= 30.0
                    or schema.expected_state not in {"read-complete", "committed"}):
                raise ValueError("component Plugin action schema catalog is malformed")
            checked[key] = PluginActionSchema(
                adapter_id=schema.adapter_id, action_id=schema.action_id,
                argument_schema_id=schema.argument_schema_id,
                result_schema_id=schema.result_schema_id, operation=schema.operation,
                adapter_sha256=schema.adapter_sha256,
                argument_schema=_freeze_schema(schema.argument_schema),
                result_schema=_freeze_schema(schema.result_schema),
                request_bytes_limit=schema.request_bytes_limit,
                response_bytes_limit=schema.response_bytes_limit,
                deadline_seconds=float(schema.deadline_seconds),
                requires_idempotency=schema.requires_idempotency,
                requires_confirmation=schema.requires_confirmation,
                expected_state=schema.expected_state,
            )
        self._schemas = MappingProxyType(checked)

    def resolve(self, adapter_id: str, action_id: str) -> PluginActionSchema | None:
        return self._schemas.get((adapter_id, action_id))


def merge_plugin_action_schema_catalogs(*catalogs: Mapping[tuple[str, str], PluginActionSchema]
                                        ) -> StaticPluginActionSchemas:
    """Combine disjoint owner-reviewed schemas without allowing overrides."""
    merged: dict[tuple[str, str], PluginActionSchema] = {}
    for catalog in catalogs:
        if not isinstance(catalog, Mapping):
            raise TypeError("each component action catalog must be an immutable mapping")
        overlap = set(merged).intersection(catalog)
        if overlap:
            raise ValueError(f"duplicate component action schemas: {sorted(overlap)!r}")
        merged.update(catalog)
    return StaticPluginActionSchemas(merged)


def component_plugin_action_schema_registry() -> StaticPluginActionSchemas:
    """Load the finite schemas owned by each reviewed native adapter cohort.

    This is called by the trusted installer loader, never by a Plugin. Every
    schema map is checked against its immutable implementation file digest;
    documents and finance additionally validate their explicit manifest pins.
    Missing/incomplete owner modules fail closed instead of silently dropping
    an adapter's schema rows.
    """
    from hashlib import sha256
    from pathlib import Path

    from hermes_installer.components.plugin_accounts_schemas import (
        PLUGIN_ACTION_SCHEMAS as accounts,
        PLUGIN_ACCOUNTS_ADAPTER_SHA256,
    )
    from hermes_installer.components.plugin_document_schemas import (
        PLUGIN_ACTION_SCHEMAS as documents,
        PLUGIN_DOCUMENT_ADAPTER_SHA256,
        validate_document_action_pins,
    )
    from hermes_installer.components.plugin_finance_schemas import (
        PLUGIN_ACTION_SCHEMAS as finance,
        PLUGIN_FINANCE_ADAPTER_SHA256,
        validate_financial_plugin_pins,
    )
    from hermes_installer.components.plugin_homelab_schemas import (
        PLUGIN_ACTION_SCHEMAS as homelab,
        PLUGIN_HOMELAB_ADAPTER_SHA256,
        PLUGIN_HOMELAB_MANIFEST_SHA256,
    )
    from hermes_installer.components.plugin_local_voice_web_schemas import (
        PLUGIN_ACTION_SCHEMAS as local_voice_web,
        PLUGIN_LOCAL_VOICE_WEB_ADAPTER_SHA256,
    )

    root = Path(__file__).resolve().parents[3]
    implementation_pins = {
        "plugin_accounts_adapters.py": (accounts, PLUGIN_ACCOUNTS_ADAPTER_SHA256),
        "plugin_documents.py": (documents, PLUGIN_DOCUMENT_ADAPTER_SHA256),
        "plugin_finance.py": (finance, PLUGIN_FINANCE_ADAPTER_SHA256),
        "plugin_homelab.py": (homelab, PLUGIN_HOMELAB_ADAPTER_SHA256),
        "plugin_local_voice_web.py": (local_voice_web, PLUGIN_LOCAL_VOICE_WEB_ADAPTER_SHA256),
    }
    for filename, (rows, pinned_digest) in implementation_pins.items():
        path = Path(__file__).with_name(filename)
        if (not path.is_file() or not _HEX.fullmatch(pinned_digest)
                or sha256(path.read_bytes()).hexdigest() != pinned_digest
                or any(row.adapter_sha256 != pinned_digest for row in rows.values())):
            raise PluginEffectUnavailable(f"source-reviewed action catalog pin failed for {filename}")
    validate_document_action_pins()
    validate_financial_plugin_pins()
    for plugin_id, pinned_digest in PLUGIN_HOMELAB_MANIFEST_SHA256.items():
        manifest = root / "resources/vendor/hermes-agent-resources-2.3.1/plugins" / f"{plugin_id}.yaml"
        if not manifest.is_file() or sha256(manifest.read_bytes()).hexdigest() != pinned_digest:
            raise PluginEffectUnavailable(f"source-reviewed manifest pin failed for {plugin_id}")
    plugin_dir = root / "resources/vendor/hermes-agent-resources-2.3.1/plugins"
    for plugin_id, pinned_digest in _PLUGIN_MANIFEST_SHA256.items():
        manifest = plugin_dir / f"{plugin_id}.yaml"
        if (not manifest.is_file() or not _HEX.fullmatch(pinned_digest)
                or sha256(manifest.read_bytes()).hexdigest() != pinned_digest):
            raise PluginEffectUnavailable(f"source-reviewed manifest pin failed for {plugin_id}")
    catalog = merge_plugin_action_schema_catalogs(accounts, documents, finance, homelab, local_voice_web)
    if set(catalog._schemas) != _EXPECTED_ACTION_KEYS:
        raise PluginEffectUnavailable("source-reviewed Plugin action catalog is incomplete or contains unexpected actions")
    return catalog


_HEX = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_OPERATIONS = {
    "agent-live-wallet": frozenset({"plugin.agent-live-wallet.read", "plugin.agent-live-wallet.execute"}),
    "agent-sandbox-wallet": frozenset({"plugin.agent-sandbox-wallet.read", "plugin.agent-sandbox-wallet.execute"}),
    "authentik-authorization": frozenset({"plugin.authentik-authorization.read"}),
    "cloudflare-homelab": frozenset({"plugin.cloudflare-homelab.read", "plugin.cloudflare-homelab.write"}),
    "codex": frozenset({"plugin.codex.run"}),
    "composio": frozenset({"plugin.composio.invoke"}),
    "ebook-toolchain": frozenset({"plugin.ebook-toolchain.run"}),
    "epic-kanban": frozenset({"plugin.epic-kanban.read", "plugin.epic-kanban.write", "plugin.epic-kanban.delete"}),
    "financial-data-hub": frozenset({"plugin.financial-data-hub.read"}),
    "financial-execution-gateway": frozenset({"plugin.financial-execution-gateway.execute"}),
    "github": frozenset({"plugin.github.read", "plugin.github.write", "plugin.github.admin"}),
    "homelab-ops-broker": frozenset({"plugin.homelab-ops-broker.read", "plugin.homelab-ops-broker.write"}),
    "kobo-bridge": frozenset({"plugin.kobo-bridge.read", "plugin.kobo-bridge.deliver"}),
    "resource-overlay-store": frozenset({"plugin.resource-overlay-store.read", "plugin.resource-overlay-store.write", "plugin.resource-overlay-store.backup"}),
    "voice-pipeline": frozenset({"plugin.voice-pipeline.session", "plugin.voice-pipeline.stt", "plugin.voice-pipeline.tts"}),
    "web": frozenset({"plugin.web.read"}),
}
_PUBLIC_REGISTRY_IDS = frozenset({"mcp-registry", "agent37-discovery"})
_PLUGIN_MANIFEST_SHA256 = MappingProxyType({
    "agent-live-wallet": "726ab3b7e8b6f3137310a125c8e7d18589105f20b3be859362390e2557f7e39d",
    "agent-sandbox-wallet": "c512f2c29d211ee8e407841a624d03a699114c59ea3204d94f303746510e30a1",
    "agent37-discovery": "cc32bfb48527bf6ebbc39ace65656c16a10cd58dc8f8e38b01715c190496c8a6",
    "authentik-authorization": "88075741bee9d27e1b7c8536cda4e641c335c952cde7e1083c8d3131be25ce2e",
    "cloudflare-homelab": "5623e42ba85a5056c7cae8e3e1ae5b0d48613071220772e82027864f6cfdd7c5",
    "codex": "7b169020508e4d51367e22bf29a1363ad8a51f24ce1b2b9731ac5fe462942b62",
    "composio": "93fe2f7b966a05d43732b66a2340606e44aba5a4dd813a7cc7f71ab40743e885",
    "ebook-toolchain": "5fedf94c58d32b076af69429c04bd1d71fe83fbfd57e00c175fdd623b955ecff",
    "epic-kanban": "06b8b9e802a97403b7d86a1fa21a1c12e231f5a267112944d0d2f1181956948d",
    "financial-data-hub": "37bbf84f32168b19df69d97296fbae09ca11d495d31d15daea159872c79b8b47",
    "financial-execution-gateway": "887192082ab9f8249cd860f00257d844fa417a74e59c30a90c94cdf88a16b133",
    "github": "f08aa0f34d79eb20cf1ad1c65cc0275b6079c374204435730ef14fdab3fa8f6c",
    "homelab-ops-broker": "bb4de61e7136f57e6fed77b3d907f2f669b2c7f070eb124ed9b0a783109d35d2",
    "kobo-bridge": "d7577722c50c6ab5cb2f057084717b9b41d77b315b3f14ca55438160f3d21f30",
    "mcp-registry": "342c337f08916cc9a755fd7aa061774c2fd690fbdcf6d03021587d7f64e626ec",
    "resource-overlay-store": "518a4e4001d9f42ac80169eddbed8caa4aa7fd1802dc4d30b992a692ce553403",
    "voice-pipeline": "6b74903bda136fcbce570f339c6ae2c06ed03fad348c564ff15672f72f3e2cd2",
    "web": "30aafed0be80db4d6b9417bc3c2ef20bcfd1bdcd417efef8f84ac605cdb88c43",
})
_EXPECTED_ACTION_KEYS = frozenset({
    ("codex", "run"), ("composio", "invoke.read"), ("composio", "invoke.write"),
    ("financial-data-hub", "read"), ("financial-execution-gateway", "execute"),
    ("web", "retrieve"),
}).union(*(
    {(adapter, action) for action in actions}
    for adapter, actions in {
        "agent-live-wallet": ("read", "execute"),
        "agent-sandbox-wallet": ("read", "execute"),
        "authentik-authorization": (
        "resolve-session-principal-to-user", "read-active-user-identity",
        "read-user-effective-groups", "verify-effective-System-membership",
        "list-current-effective-System-members-for-alarm-delivery",
        ),
        "cloudflare-homelab": (
        "read-approved-dns-records", "read-approved-tunnel-state",
        "read-approved-tunnel-connectors", "read-approved-tunnel-configuration",
        "update-approved-dns-record", "update-approved-tunnel-configuration",
        ),
        "ebook-toolchain": ("run", "inspect", "validate"),
        "epic-kanban": ("create", "read", "add_item", "move_item", "delete_accepted"),
        "github": ("repo.get", "issues.list", "content.get", "content.put", "issue.create"),
        "homelab-ops-broker": (
        "host-health", "cpu-memory-temperature-and-disk", "approved-service-status",
        "approved-container-status", "bounded-service-logs", "installed-runtime-and-container-versions",
        "backup-status-and-integrity-metadata", "nextcloud-status", "nextcloud-background-job-status",
        "nextcloud-maintenance-state", "restart-approved-service", "restart-approved-container",
        "update-approved-service-or-container", "rollback-approved-service-or-container",
        "run-approved-backup", "run-approved-restore", "enter-or-exit-nextcloud-maintenance-mode",
        "run-approved-nextcloud-repair", "run-approved-nextcloud-background-job-operation",
        "bounded-approved-cleanup",
        ),
        "kobo-bridge": ("read", "deliver"),
        "voice-pipeline": (
        "open_session", "capture_audio", "close_session", "voice_transcribe", "voice_speak",
        ),
    }.items()
))


def _freeze_schema(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_schema(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_schema(item) for item in value)
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError("component action schemas must contain only immutable JSON schema values")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise PluginEffectUnavailable("plugin action arguments are not canonical JSON values") from None


def _validate_schema(schema: Mapping[str, Any], value: Any, *, depth: int = 0) -> None:
    if depth > 32 or not isinstance(schema, Mapping):
        raise PluginEffectUnavailable("selected plugin action schema is invalid")
    kind = schema.get("type")
    valid = {
        "object": lambda v: isinstance(v, Mapping),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: type(v) is int,
        "number": lambda v: type(v) in (int, float) and math.isfinite(v),
        "boolean": lambda v: type(v) is bool,
        "null": lambda v: v is None,
    }
    kinds = kind if isinstance(kind, (list, tuple)) else [kind]
    if not kinds or any(item not in valid for item in kinds) or not any(valid[item](value) for item in kinds):
        raise PluginEffectUnavailable("plugin action arguments do not match the enrolled schema type")
    if "enum" in schema and value not in schema["enum"]:
        raise PluginEffectUnavailable("plugin action argument is outside the enrolled enum")
    if isinstance(value, Mapping) and "object" in kinds:
        props = schema.get("properties", {})
        required = schema.get("required", [])
        if (not isinstance(props, Mapping) or not isinstance(required, (list, tuple))
                or set(required) - set(value)
                or ("properties" in schema and
                    (set(value) - set(props) or schema.get("additionalProperties", False) is not False))):
            raise PluginEffectUnavailable("plugin action argument fields do not match the enrolled object schema")
        if "properties" in schema:
            for key, item in value.items():
                _validate_schema(props[key], item, depth=depth + 1)
    if isinstance(value, list) and "array" in kinds:
        if "items" not in schema:
            raise PluginEffectUnavailable("enrolled array schema lacks an item schema")
        for item in value:
            _validate_schema(schema["items"], item, depth=depth + 1)
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 262_144):
            raise PluginEffectUnavailable("plugin action string exceeds its enrolled bounds")
        pattern = schema.get("pattern")
        if pattern is not None and (not isinstance(pattern, str) or len(pattern) > 512
                                    or re.search(pattern, value) is None):
            raise PluginEffectUnavailable("plugin action string does not match its enrolled pattern")
    if isinstance(value, list) and (len(value) < schema.get("minItems", 0)
                                    or len(value) > schema.get("maxItems", 262_144)):
        raise PluginEffectUnavailable("plugin action array exceeds its enrolled bounds")
    if type(value) in (int, float):
        if "minimum" in schema and value < schema["minimum"]:
            raise PluginEffectUnavailable("plugin action number is below its enrolled minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise PluginEffectUnavailable("plugin action number exceeds its enrolled maximum")


class PluginEffectDispatcher:
    """One-use, digest-bound dispatcher over root-selected Plugin effects."""

    def __init__(self, *, authority: PluginAuthority,
                 invocation_contexts: InvocationContexts,
                 selected_effects: SelectedPluginEffectsResolver,
                 action_schemas: PluginActionSchemaRegistry,
                 identity: object):
        if not callable(getattr(authority, "context", None)) or not callable(getattr(authority, "perform_effect", None)):
            raise TypeError("root-owned AuthorityClient is required")
        if not callable(getattr(invocation_contexts, "__call__", None)):
            raise TypeError("trusted invocation-context provider is required")
        if not callable(getattr(selected_effects, "resolve", None)):
            raise TypeError("root-selected Plugin action resolver is required")
        if not callable(getattr(action_schemas, "resolve", None)):
            raise TypeError("component-owned action schema catalog is required")
        self.authority = authority
        self.invocation_contexts = invocation_contexts
        self.selected_effects = selected_effects
        self.action_schemas = action_schemas
        self.identity = identity

    def invoke(self, adapter_id: str, action_id: str, arguments: Mapping[str, Any],
               idempotency_key: str | None = None,
               opaque_confirmation_attestation_id: str | None = None) -> dict[str, Any]:
        if adapter_id in _PUBLIC_REGISTRY_IDS:
            raise PluginEffectUnavailable("public registry discovery uses its separate fixed registry.read route")
        identity = self.identity
        if (adapter_id not in _OPERATIONS or getattr(identity, "kind", None) != "plugins"
                or getattr(identity, "resource_id", None) != adapter_id):
            raise PluginEffectUnavailable("plugin action does not match the trusted selected source identity")
        selected = self.selected_effects.resolve(adapter_id, action_id)
        if selected is None:
            raise PluginEffectUnavailable(f"{adapter_id}/{action_id}: no selected root enrollment is available")
        schema = self.action_schemas.resolve(adapter_id, action_id)
        if schema is None:
            raise PluginEffectUnavailable(f"{adapter_id}/{action_id}: source-reviewed action schema is unavailable")
        self._validate_selection(selected, schema)
        if not isinstance(arguments, Mapping):
            raise PluginEffectUnavailable("plugin action arguments must be a JSON object")
        args = dict(arguments)
        _validate_schema(schema.argument_schema, args)
        # Round-trip through JSON so custom Mapping/number objects cannot
        # smuggle non-JSON values into the authorization digest.
        try:
            args = json.loads(_canonical(args).decode("utf-8"), parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
        except (ValueError, json.JSONDecodeError, RecursionError):
            raise PluginEffectUnavailable("plugin action arguments are not valid JSON") from None
        has_idempotency = schema.requires_idempotency
        has_confirmation = schema.requires_confirmation
        if has_idempotency != (idempotency_key is not None):
            raise PluginEffectUnavailable("plugin action idempotency key does not match the selected policy")
        if has_confirmation != (opaque_confirmation_attestation_id is not None):
            raise PluginEffectUnavailable("plugin action confirmation handle does not match the selected policy")
        for label, value, required in (("idempotency key", idempotency_key, has_idempotency),
                                       ("confirmation handle", opaque_confirmation_attestation_id, has_confirmation)):
            if required and (not isinstance(value, str) or not _OPAQUE.fullmatch(value)):
                raise PluginEffectUnavailable(f"plugin action {label} is malformed")
        envelope: dict[str, Any] = {
            "schema": 1, "adapter_id": adapter_id, "action_id": action_id,
            "enrollment_id": selected.effect_enrollment_id, "generation": selected.generation,
            "arguments": args,
        }
        if idempotency_key is not None:
            envelope["idempotency_key"] = idempotency_key
        if opaque_confirmation_attestation_id is not None:
            envelope["opaque_confirmation_attestation_id"] = opaque_confirmation_attestation_id
        payload = _canonical(envelope)
        digest = hashlib.sha256(payload).hexdigest()
        if len(payload) > schema.request_bytes_limit:
            raise PluginEffectUnavailable("plugin action exceeds its enrolled request byte bound")
        intent = f"Invoke selected native Plugin action {adapter_id}/{action_id}"
        arguments_digest = hashlib.sha256(_canonical(args)).hexdigest()
        source_receipt_handles = root_invocation_source_receipt_handles(
            self.invocation_contexts, adapter_id=adapter_id, action_id=action_id,
            arguments_sha256=arguments_digest,
            purpose="native-hermes-chat", intent=intent,
        )
        context = self.authority.context(
            purpose="native-hermes-chat", intent=intent, operation=selected.operation,
            source_receipt_handles=source_receipt_handles, final_payload_digest=digest,
            lease_seconds=min(30.0, float(schema.deadline_seconds)),
        )
        if (not isinstance(getattr(context, "principal_id", None), str)
                or not isinstance(getattr(context, "profile_id", None), str)
                or getattr(context, "operation", None) != selected.operation
                or getattr(context, "final_payload_digest", None) != digest):
            raise PluginEffectUnavailable("authority context does not match the selected action enrollment")
        target = f"plugin:{adapter_id}:{selected.target_id}:{selected.generation}"
        authorization = self.authority.authorize_effect(
            context, capability=selected.capability, target=target,
            recipient=selected.recipient, request_digest=digest, retry_index=0,
        )
        self.authority.verify_effect(
            authorization, context, capability=selected.capability, target=target,
            recipient=selected.recipient, request_digest=digest, retry_index=0,
        )
        response = self.authority.perform_effect(
            authorization, operation=selected.operation, payload=payload,
            timeout=float(schema.deadline_seconds),
        )
        body = getattr(response, "body", None)
        if (type(getattr(response, "status", None)) is not int or response.status != 200
                or not isinstance(body, bytes) or len(body) > schema.response_bytes_limit):
            raise PluginEffectUnavailable("protected Plugin effect returned an invalid or oversized response")
        try:
            result = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_pairs,
                                parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            raise PluginEffectUnavailable("protected Plugin effect returned malformed JSON") from None
        envelope_fields = {"schema", "operation_id", "state", "result", "verification_status", "resume_action_id"}
        resume_action = result.get("resume_action_id") if isinstance(result, dict) else None
        invalid_resume = (resume_action is not None
                          and (not isinstance(resume_action, str) or not _OPAQUE.fullmatch(resume_action)))
        if (not isinstance(result, dict) or set(result) != envelope_fields
                or type(result.get("schema")) is not int or result["schema"] != 1
                or not isinstance(result.get("operation_id"), str)
                or not _OPAQUE.fullmatch(result["operation_id"])
                or result.get("state") not in {"read-complete", "committed", "pending", "ambiguous", "unavailable"}
                or not isinstance(result.get("verification_status"), str)
                or not 1 <= len(result["verification_status"]) <= 64
                or any(ord(char) < 32 for char in result["verification_status"])
                or invalid_resume):
            raise PluginEffectUnavailable("protected Plugin effect returned an invalid operation envelope")
        if result["state"] in {"read-complete", "committed"}:
            if result["state"] != schema.expected_state or not isinstance(result["result"], dict):
                raise PluginEffectUnavailable("protected Plugin effect state does not match its selected action")
            if result["state"] == "committed" and result["verification_status"] != "verified":
                raise PluginEffectUnavailable("committed Plugin effect lacks verified post-effect evidence")
            _validate_schema(schema.result_schema, result["result"])
        elif result["result"] is not None and not isinstance(result["result"], dict):
            raise PluginEffectUnavailable("nonfinal Plugin effect result must be bounded structured data")
        return result

    def _validate_selection(self, selected: SelectedPluginEffect,
                            schema: PluginActionSchema) -> None:
        adapter_id, action_id = schema.adapter_id, schema.action_id
        if (selected.adapter_id != adapter_id or selected.action_id != action_id
                or selected.operation != schema.operation
                or selected.operation not in _OPERATIONS[adapter_id]
                or selected.capability != f"plugin:{adapter_id}"
                or getattr(self.identity, "content_digest", None) != selected.manifest_sha256
                or not _HEX.fullmatch(selected.manifest_sha256)
                or selected.adapter_sha256 != schema.adapter_sha256
                or not _HEX.fullmatch(selected.adapter_sha256)
                or selected.adapter_sha256 == "0" * 64
                or selected.argument_schema_id != schema.argument_schema_id
                or selected.result_schema_id != schema.result_schema_id
                or not _OPAQUE.fullmatch(selected.effect_enrollment_id)
                or not _OPAQUE.fullmatch(selected.generation)
                or not _OPAQUE.fullmatch(selected.target_id)
                or (selected.recipient is not None
                    and (not isinstance(selected.recipient, str)
                         or not 1 <= len(selected.recipient) <= 256
                         or any(ord(char) < 32 for char in selected.recipient)))):
            raise PluginEffectUnavailable("selected Plugin action does not match its source or bounded contract")
        target = f"plugin:{adapter_id}:{selected.target_id}:{selected.generation}"
        if target != f"plugin:{selected.adapter_id}:{selected.target_id}:{selected.generation}":
            raise PluginEffectUnavailable("selected Plugin target is malformed")


def build_plugin_effects_facade(*, authority: PluginAuthority,
                                invocation_contexts: InvocationContexts,
                                identity: object,
                                action_schemas: PluginActionSchemaRegistry | None = None,
                                selected_package: object | None = None,
                                ) -> PluginEffectDispatcher:
    """Bind a facade to the root-selected immutable Plugin package.

    This factory is for the protected installer loader only. It deliberately
    requires a trusted invocation-context provider; a plugin, tool argument,
    manifest, or caller-provided principal/source label cannot supply one.
    The protected loader may pass its already verified SelectedNativePackage;
    otherwise this function binds the package itself. Resolver metadata only
    selects an action. The AuthorityClient still re-resolves the root grant for
    every effect and consumes its one-use authorization before performing it.
    """
    if not callable(getattr(invocation_contexts, "__call__", None)):
        raise PluginEffectUnavailable("root trusted invocation-context provider is unavailable")
    identity_digest = getattr(identity, "content_digest", None)
    if (getattr(identity, "kind", None) != "plugins"
            or not isinstance(getattr(identity, "resource_id", None), str)
            or not getattr(identity, "resource_id", None)
            or not isinstance(identity_digest, str) or not _HEX.fullmatch(identity_digest)):
        raise PluginEffectUnavailable("trusted selected Plugin identity is unavailable")
    if action_schemas is None:
        action_schemas = component_plugin_action_schema_registry()
    try:
        from hermes_installer.native_plugin_loader import (
            SelectedNativePackage,
            bind_current_native_plugin_package,
        )
        if selected_package is None:
            binder = getattr(authority, "bind_selected_native_package", None)
            if not callable(binder):
                raise ValueError("root native-package binding is unavailable")
            selected = bind_current_native_plugin_package(authority)
        elif isinstance(selected_package, SelectedNativePackage):
            selected = selected_package
        else:
            raise ValueError("the protected native package loader is required")
        if (not callable(getattr(selected, "resolve", None))
                or not callable(getattr(selected, "manifest_digest_for_adapter", None))
                or selected.manifest_digest_for_adapter(identity.resource_id)
                != identity_digest):
            raise ValueError("selected Plugin manifest digest does not match the protected source identity")
    except (ImportError, RuntimeError, ValueError, PermissionError):
        raise PluginEffectUnavailable("root-selected Plugin package binding is unavailable") from None
    return PluginEffectDispatcher(authority=authority,
                                  invocation_contexts=invocation_contexts,
                                  selected_effects=selected,
                                  action_schemas=action_schemas,
                                  identity=identity)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON response key")
        result[key] = value
    return result
