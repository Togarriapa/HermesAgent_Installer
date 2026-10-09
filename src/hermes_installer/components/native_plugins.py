"""Typed bridge from preserved Plugin resources to reviewed native adapters.

Resource manifests supply identity and declared capabilities only. They never
supply Python callables, endpoints, or credential values. Implementations are
resolved from the installer-owned selected-adapter registry.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
import base64
import binascii
import re
from collections.abc import Mapping

from hermes_installer.components.public_registries import invoke_public_registry_read


@dataclass(frozen=True, slots=True)
class NativePluginAdapterContract:
    adapter_id: str
    resource_id: str
    component_adapter_id: str | None
    handler_available: bool
    status: str
    blocker: str | None


_PLUGIN_IDS = (
    "agent-live-wallet",
    "agent-sandbox-wallet",
    "agent37-discovery",
    "authentik-authorization",
    "cloudflare-homelab",
    "codex",
    "composio",
    "ebook-toolchain",
    "epic-kanban",
    "financial-data-hub",
    "financial-execution-gateway",
    "github",
    "homelab-ops-broker",
    "kobo-bridge",
    "mcp-registry",
    "resource-overlay-store",
    "voice-pipeline",
    "web",
)
_PLUGIN_VERSIONS = {
    "agent-live-wallet": "1.0.0", "agent-sandbox-wallet": "1.0.0",
    "agent37-discovery": "1.0.0", "authentik-authorization": "1.0.0",
    "cloudflare-homelab": "1.0.0", "codex": "1.0.1", "composio": "1.0.0",
    "ebook-toolchain": "1.0.0", "epic-kanban": "1.0.1",
    "financial-data-hub": "1.0.1", "financial-execution-gateway": "1.0.0",
    "github": "1.0.1", "homelab-ops-broker": "1.0.0", "kobo-bridge": "1.0.0",
    "mcp-registry": "1.0.0", "resource-overlay-store": "1.0.1",
    "voice-pipeline": "1.0.1", "web": "1.0.1",
}

_PLUGIN_BLOCKERS = {
    "agent-live-wallet": "Reviewed fixed handler exists; selected activation remains blocked until an enrolled wallet runtime, encrypted host vault, network/asset allowlist, protected signer, and one-shot explicit-order confirmation path are supplied. Mainnet activity is not enabled.",
    "agent-sandbox-wallet": "Reviewed fixed handler exists; selected activation remains blocked until an isolated wallet runtime and reviewed Sepolia/Solana Devnet RPC and test-asset route are enrolled. Never connect mainnet or user funds.",
    "agent37-discovery": "Handler is implemented; public reads still require root `registry-agent37-read` enrollment and the protected installer loader before native discovery/invocation.",
    "authentik-authorization": "Reviewed fixed broker handler exists; activation requires root-enrolled Authentik principal/session and live effective-System-membership resolvers plus recipient listing. No caller-supplied principal, group, endpoint, or token is accepted.",
    "cloudflare-homelab": "Reviewed fixed broker handler exists; activation requires root-enrolled owned account/zone/tunnel targets, scoped token reference, and live Authentik System check. Only the fixed DNS/tunnel verbs are exposed.",
    "codex": "Reviewed task-run handler exists; activation requires host-owned authentication, assigned workspace identity, pinned ARM64 runtime and bounded managed runner without copying credentials into plugin state.",
    "composio": "Reviewed enrolled-action handlers exist; activation requires a user-authorized profile-scoped OAuth connection, selected toolkit/action schemas and root-vault reference. Unlisted actions stay unavailable.",
    "ebook-toolchain": "The bounded EPUB builder is implemented; native tools remain unavailable until root supplies rights-attested source material and approved per-profile output roots. DRM removal and arbitrary shell stay denied.",
    "epic-kanban": "Reviewed local-board handler exists; activation requires a profile-bound ephemeral board store. GitHub Projects remains separate and requires an enrolled project scope.",
    "financial-data-hub": "Reviewed read-only handler exists; activation requires user-consented per-provider accounts and namespaced host-vault refs. Payment, trading, signing and transfer operations remain excluded.",
    "financial-execution-gateway": "Reviewed fixed execution handler exists; activation requires provider adapters, independently enrolled account scopes, duplicate protection and a fresh one-shot confirmation verifier. No standing or autonomous financial actions.",
    "github": "Reviewed fixed-action handlers exist; activation requires a root-enrolled least-privilege repository scope and protected credential reference. Writes require task-specific confirmation, idempotency and provider readback verification.",
    "homelab-ops-broker": "Reviewed fixed broker handler exists; activation requires root-enrolled target IDs, read/write capabilities, Authentik System verifier and bounded fixed-operation transport. Raw shell/SSH remain denied.",
    "kobo-bridge": "A no-overwrite EPUB export primitive is implemented; native tools remain unavailable until root supplies an enrolled model/device resolver, approved USB-root custody and explicit non-DRM transfer consent. Account scraping and notebook writes remain denied.",
    "mcp-registry": "Handler is implemented; public reads still require root `registry-read` enrollment and the protected installer loader before native discovery/invocation.",
    "resource-overlay-store": "Encrypted backup is unavailable until lifecycle provides a host-managed encrypted backup/restore API; local private CAS read/write/history/delete remains profile-scoped.",
    "voice-pipeline": "Reviewed session-bound local Wyoming/Piper handler exists; activation requires root-enrolled local endpoints and the current-session microphone/audio boundary. Cloud fallback and raw-audio persistence remain denied.",
    "web": "Reviewed bounded public-HTTPS handler exists; activation requires root-injected direct one-hop TLS reader that proves destination IP and disables inherited proxies. Authenticated actions and credential-bearing requests remain denied.",
}

# Plugin resources are source identities from the user's preserved registry,
# not aliases for unrelated seed repositories. A matching source adapter ID is
# attached only after a reviewed one-to-one source crosswalk exists.
NATIVE_PLUGIN_ADAPTERS = tuple(
    NativePluginAdapterContract(
        adapter_id=plugin_id,
        resource_id=plugin_id,
        component_adapter_id=(plugin_id if plugin_id in {
            "resource-overlay-store", "mcp-registry", "agent37-discovery",
            "agent-live-wallet", "agent-sandbox-wallet", "authentik-authorization",
            "cloudflare-homelab", "epic-kanban", "financial-data-hub",
            "financial-execution-gateway", "homelab-ops-broker", "voice-pipeline", "web",
            "ebook-toolchain", "kobo-bridge", "github", "composio", "codex",
        } else None),
        handler_available=(plugin_id in {
            "resource-overlay-store", "mcp-registry", "agent37-discovery",
            "agent-live-wallet", "agent-sandbox-wallet", "authentik-authorization",
            "cloudflare-homelab", "financial-data-hub", "financial-execution-gateway",
            "homelab-ops-broker", "epic-kanban", "voice-pipeline", "web",
            "ebook-toolchain", "kobo-bridge", "github", "composio", "codex",
        }),
        status=("reviewed-local-profile-handler" if plugin_id == "resource-overlay-store"
                else "reviewed-root-brokered-public-read" if plugin_id in {"mcp-registry", "agent37-discovery"}
                else "reviewed-root-brokered-handler" if plugin_id in {
                    "authentik-authorization", "cloudflare-homelab", "homelab-ops-broker",
                }
                else "reviewed-scoped-financial-handler" if plugin_id in {
                    "agent-live-wallet", "agent-sandbox-wallet", "financial-data-hub", "financial-execution-gateway",
                }
                else "reviewed-profile-service-handler" if plugin_id in {
                    "epic-kanban", "voice-pipeline", "web", "ebook-toolchain", "kobo-bridge",
                }
                else "reviewed-root-brokered-handler" if plugin_id in {"github", "composio", "codex"}
                else "typed-adapter-registry-required"),
        blocker=_PLUGIN_BLOCKERS[plugin_id],
    )
    for plugin_id in _PLUGIN_IDS
)
_PLUGIN_BY_ID = {row.adapter_id: row for row in NATIVE_PLUGIN_ADAPTERS}


class NativePluginImplementation(Protocol):
    def register(self, ctx: object, runtime_context: object) -> None:
        """Register only the implementation's fixed reviewed Hermes tools."""


class PluginAdapterRegistry(Protocol):
    def resolve_plugin_adapter(self, adapter_id: str) -> NativePluginImplementation | None:
        """Resolve an implementation from installer-owned reviewed adapters."""


class NativePluginRuntimeContext(Protocol):
    selected_adapters: PluginAdapterRegistry


class NativePluginUnavailable(RuntimeError):
    """A preserved plugin has no reviewed native handler available."""


def resolve_native_plugin_adapter(adapter_id: str) -> NativePluginAdapterContract:
    try:
        return _PLUGIN_BY_ID[adapter_id]
    except (KeyError, TypeError):
        raise KeyError(f"unknown native Plugin adapter ID {adapter_id!r}") from None


def native_plugin_handler_available(adapter_id: str) -> bool:
    """Pure readiness hint for registry generation; never implies activation."""
    return resolve_native_plugin_adapter(adapter_id).handler_available


def create_native_plugin_handler(adapter_id: str, runtime_context: NativePluginRuntimeContext):
    """Return a native `register(ctx)` closure backed by a typed adapter.

    The registry is installer-owned and accepts implementations, never
    callables declared by imported plugin YAML. Missing implementations fail
    explicitly so resource discovery cannot imply activation.
    """
    contract = resolve_native_plugin_adapter(adapter_id)
    if runtime_context is None or not hasattr(runtime_context, "selected_adapters"):
        raise NativePluginUnavailable(f"{adapter_id}: trusted selected-adapter registry is unavailable")
    identity = getattr(runtime_context, "identity", None)
    if (identity is None or getattr(identity, "kind", None) != "plugins"
            or getattr(identity, "resource_id", None) != adapter_id
            or getattr(identity, "version", None) != _PLUGIN_VERSIONS[adapter_id]):
        raise NativePluginUnavailable(f"{adapter_id}: trusted context does not match the selected Plugin identity")
    implementation = runtime_context.selected_adapters.resolve_plugin_adapter(adapter_id)
    if implementation is None:
        raise NativePluginUnavailable(
            f"{adapter_id}: {contract.blocker}; preserve as discovered/pending until a reviewed adapter is registered"
        )

    def register(ctx: object) -> None:
        implementation.register(ctx, runtime_context)

    return register


# Resource-overlay-store has a native, profile-scoped local implementation.
# Its backup capability intentionally has no registration until lifecycle's
# encrypted-backup API is available.
_RECORD_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
_MAX_OVERLAY_BYTES = 1_048_576


class ProfileOverlayView(Protocol):
    def read(self, record_id: str): ...
    def write(self, record_id: str, value: bytes, expected_revision: str | None) -> str: ...
    def history(self, record_id: str) -> tuple[str, ...]: ...
    def delete(self, record_id: str, expected_revision: str | None) -> str: ...


def _tool_object(value: object, *, fields: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) - fields:
        raise ValueError("tool arguments must be an object with only reviewed fields")
    return value


def _record_id(value: object) -> str:
    if not isinstance(value, str) or not _RECORD_ID.fullmatch(value):
        raise ValueError("record_id must be a bounded opaque identifier")
    return value


class ResourceOverlayStoreImplementation:
    """Fixed native tools over an installer-scoped profile overlay view."""

    def register(self, ctx: object, runtime_context: object) -> None:
        view = getattr(runtime_context, "local_overlay_store", None)
        if view is None:
            raise NativePluginUnavailable("resource-overlay-store: selected profile overlay view is unavailable")
        methods = ("read", "write", "history", "delete")
        if any(not callable(getattr(view, method, None)) for method in methods):
            raise NativePluginUnavailable("resource-overlay-store: profile overlay view lacks the reviewed CAS API")
        register_tool = getattr(ctx, "register_tool", None)
        if not callable(register_tool):
            raise NativePluginUnavailable("resource-overlay-store: Hermes PluginContext.register_tool is unavailable")
        read_schema = {"type": "object", "properties": {"record_id": {"type": "string", "maxLength": 128}}, "required": ["record_id"], "additionalProperties": False}
        write_schema = {"type": "object", "properties": {"record_id": {"type": "string", "maxLength": 128}, "value_base64": {"type": "string", "maxLength": 1398104}, "expected_revision": {"type": ["string", "null"], "maxLength": 64}}, "required": ["record_id", "value_base64"], "additionalProperties": False}
        delete_schema = {"type": "object", "properties": {"record_id": {"type": "string", "maxLength": 128}, "expected_revision": {"type": ["string", "null"], "maxLength": 64}}, "required": ["record_id", "expected_revision"], "additionalProperties": False}

        def read(args: object):
            record_id = _record_id(_tool_object(args, fields=frozenset({"record_id"})).get("record_id"))
            value = view.read(record_id)
            if value is None:
                return {"found": False, "record_id": record_id}
            body = getattr(value, "value", None)
            revision = getattr(value, "revision", None)
            deleted = getattr(value, "deleted", False)
            if deleted:
                return {"found": False, "record_id": record_id}
            if not isinstance(body, bytes) or len(body) > _MAX_OVERLAY_BYTES or not isinstance(revision, str):
                raise RuntimeError("overlay store returned an invalid bounded value")
            return {"found": True, "record_id": record_id, "value_base64": base64.b64encode(body).decode("ascii"), "revision": revision}

        def write(args: object):
            fields = _tool_object(args, fields=frozenset({"record_id", "value_base64", "expected_revision"}))
            record_id = _record_id(fields.get("record_id"))
            encoded = fields.get("value_base64")
            if not isinstance(encoded, str) or len(encoded) > 1_398_104:
                raise ValueError("value_base64 is missing or exceeds the one MiB decoded limit")
            try:
                body = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                raise ValueError("value_base64 must be canonical base64") from None
            if len(body) > _MAX_OVERLAY_BYTES or base64.b64encode(body).decode("ascii") != encoded:
                raise ValueError("overlay value exceeds one MiB or is not canonical base64")
            expected = fields.get("expected_revision")
            if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
                raise ValueError("expected_revision must be a SHA-256 revision or null")
            revision = view.write(record_id, body, expected_revision=expected)
            if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
                raise RuntimeError("overlay store returned an invalid revision")
            return {"record_id": record_id, "revision": revision}

        def history(args: object):
            record_id = _record_id(_tool_object(args, fields=frozenset({"record_id"})).get("record_id"))
            revisions = view.history(record_id)
            if (not isinstance(revisions, tuple) or len(revisions) > 256
                    or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item) for item in revisions)):
                raise RuntimeError("overlay store returned invalid version history")
            return {"record_id": record_id, "revisions": list(revisions)}

        def delete(args: object):
            fields = _tool_object(args, fields=frozenset({"record_id", "expected_revision"}))
            record_id = _record_id(fields.get("record_id"))
            expected = fields.get("expected_revision")
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError("delete requires the exact current SHA-256 revision")
            tombstone = view.delete(record_id, expected_revision=expected)
            if not isinstance(tombstone, str) or not re.fullmatch(r"[0-9a-f]{64}", tombstone):
                raise RuntimeError("overlay store returned an invalid tombstone revision")
            return {"record_id": record_id, "deleted_revision": tombstone}

        for suffix, schema, handler, description in (
            ("read", read_schema, read, "Read a private overlay from the selected profile."),
            ("write", write_schema, write, "Write a private overlay with optional compare-and-swap revision."),
            ("history", read_schema, history, "Read bounded revision history for a private overlay."),
            ("delete", delete_schema, delete, "Soft-delete a private overlay using its exact current revision."),
        ):
            register_tool(
                name=f"resource_overlay_{suffix}", toolset="resource_overlay_store",
                schema=schema, handler=handler, requires_env=None, is_async=False,
                description=description,
            )


RESOURCE_OVERLAY_STORE_IMPLEMENTATION = ResourceOverlayStoreImplementation()


class MCPRegistryImplementation:
    """Fixed read-only tools for the official public MCP Registry."""

    def register(self, ctx: object, runtime_context: object) -> None:
        if getattr(getattr(runtime_context, "identity", None), "resource_id", None) != "mcp-registry":
            raise NativePluginUnavailable("mcp-registry: selected source identity does not match")
        register_tool = getattr(ctx, "register_tool", None)
        if not callable(register_tool):
            raise NativePluginUnavailable("mcp-registry: Hermes PluginContext.register_tool is unavailable")
        discovery_schema = {"type": "object", "properties": {
            "search": {"type": "string", "maxLength": 200},
            "limit": {"type": "integer", "minimum": 1, "maximum": 30},
            "cursor": {"type": ["string", "null"], "maxLength": 1024},
            "latest_only": {"type": "boolean"},
        }, "additionalProperties": False}
        inspect_schema = {"type": "object", "properties": {
            "server_name": {"type": "string", "minLength": 1, "maxLength": 200},
            "version": {"type": "string", "maxLength": 128},
        }, "required": ["server_name"], "additionalProperties": False}

        def discover(args: object) -> dict[str, Any]:
            fields = _tool_object(args, fields=frozenset({"search", "limit", "cursor", "latest_only"}))
            query: dict[str, Any] = {}
            if "search" in fields:
                query["search"] = fields["search"]
            if fields.get("latest_only") is True:
                query["version"] = "latest"
            elif "latest_only" in fields and type(fields["latest_only"]) is not bool:
                raise ValueError("latest_only must be a boolean")
            return invoke_public_registry_read(
                runtime_context, service_id="registry:modelcontextprotocol", query=query,
                limit=_bounded_page(fields.get("limit"), 30), cursor=_cursor(fields.get("cursor")),
                action_id="discover-servers", invocation_arguments=fields,
                intent="Discover public MCP server metadata without installing or executing it",
            )

        def inspect(args: object) -> dict[str, Any]:
            fields = _tool_object(args, fields=frozenset({"server_name", "version"}))
            server_name = _server_name(fields.get("server_name"))
            query: dict[str, Any] = {"name": server_name}
            if "version" in fields:
                query["version"] = fields["version"]
            return invoke_public_registry_read(
                runtime_context, service_id="registry:modelcontextprotocol", query=query,
                limit=20, cursor=None,
                action_id=("inspect-server-metadata" if "version" in fields
                           else "inspect-versions"), invocation_arguments=fields,
                intent="Inspect public MCP server metadata and version history only",
            )

        for name, schema, handler, description in (
            ("mcp_registry_discover", discovery_schema, discover,
             "Search the official public MCP Registry. Results are untrusted metadata; this does not install or run servers."),
            ("mcp_registry_inspect", inspect_schema, inspect,
             "Read public MCP server version metadata by exact registry name; no server execution or installation."),
        ):
            register_tool(name=name, toolset="mcp_registry", schema=schema, handler=handler,
                          requires_env=None, is_async=False, description=description)


class Agent37DiscoveryImplementation:
    """Fixed read-only Agent37 skill-index search and metadata tools."""

    def register(self, ctx: object, runtime_context: object) -> None:
        if getattr(getattr(runtime_context, "identity", None), "resource_id", None) != "agent37-discovery":
            raise NativePluginUnavailable("agent37-discovery: selected source identity does not match")
        register_tool = getattr(ctx, "register_tool", None)
        if not callable(register_tool):
            raise NativePluginUnavailable("agent37-discovery: Hermes PluginContext.register_tool is unavailable")
        discover_schema = {"type": "object", "properties": {
            "search": {"type": "string", "minLength": 1, "maxLength": 160},
            "owner": {"type": "string", "maxLength": 64},
            "repo": {"type": "string", "maxLength": 128},
            "sort": {"type": "string", "enum": ["relevance", "updated"]},
            "minimum_stars": {"type": "integer", "enum": [10]},
            "recently_updated": {"type": "boolean"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 30},
            "cursor": {"type": ["string", "null"], "pattern": "^(0|[1-9][0-9]{0,5})$"},
        }, "required": ["search"], "additionalProperties": False}
        inspect_schema = {"type": "object", "properties": {
            "skill_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
        }, "required": ["skill_id"], "additionalProperties": False}

        def discover(args: object) -> dict[str, Any]:
            fields = _tool_object(args, fields=frozenset({"search", "owner", "repo", "sort", "minimum_stars", "recently_updated", "limit", "cursor"}))
            query = {key: fields[source] for source, key in (
                ("search", "search"), ("owner", "owner"), ("repo", "repo"),
                ("sort", "sort"), ("minimum_stars", "min_stars"),
            ) if source in fields}
            if fields.get("recently_updated") is True:
                query["recent"] = True
            elif "recently_updated" in fields and type(fields["recently_updated"]) is not bool:
                raise ValueError("recently_updated must be a boolean")
            return invoke_public_registry_read(
                runtime_context, service_id="registry:agent37", query=query,
                limit=_bounded_page(fields.get("limit"), 30), cursor=_cursor(fields.get("cursor")),
                action_id="discover-skill-candidates", invocation_arguments=fields,
                intent="Discover public Agent37 skill metadata; do not import or execute candidates",
            )

        def inspect(args: object) -> dict[str, Any]:
            fields = _tool_object(args, fields=frozenset({"skill_id"}))
            return invoke_public_registry_read(
                runtime_context, service_id="registry:agent37", query={"id": fields.get("skill_id")},
                limit=1, cursor=None,
                action_id="inspect-public-metadata", invocation_arguments=fields,
                intent="Inspect a public Agent37 metadata record without importing its skill content",
            )

        for name, schema, handler, description in (
            ("agent37_discover_skills", discover_schema, discover,
             "Search the public Agent37 skills index. Skill content and ranking remain untrusted; results are not installed or executed."),
            ("agent37_inspect_skill", inspect_schema, inspect,
             "Read bounded public metadata for an exact Agent37 skill ID. Instructions are omitted."),
        ):
            register_tool(name=name, toolset="agent37_discovery", schema=schema, handler=handler,
                          requires_env=None, is_async=False, description=description)


MCP_REGISTRY_IMPLEMENTATION = MCPRegistryImplementation()
AGENT37_DISCOVERY_IMPLEMENTATION = Agent37DiscoveryImplementation()


def _bounded_page(value: object, maximum: int) -> int:
    if value is None:
        return min(20, maximum)
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"limit must be an integer from 1 to {maximum}")
    return value


def _cursor(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 1024 or any(ord(ch) < 32 for ch in value):
        raise ValueError("cursor must be an opaque bounded string")
    return value


def _server_name(value: object) -> str:
    if (not isinstance(value, str) or not value or len(value) > 512
            or any(ord(ch) < 33 or ch in "?#\\" for ch in value)):
        raise ValueError("server_name must be one exact bounded registry name")
    return value


def resolve_native_plugin_implementation(adapter_id: str) -> NativePluginImplementation | None:
    """Return the actual implementation, never the metadata crosswalk record."""
    contract = resolve_native_plugin_adapter(adapter_id)
    if not contract.handler_available:
        return None
    if adapter_id == "resource-overlay-store":
        return RESOURCE_OVERLAY_STORE_IMPLEMENTATION
    if adapter_id == "mcp-registry":
        return MCP_REGISTRY_IMPLEMENTATION
    if adapter_id == "agent37-discovery":
        return AGENT37_DISCOVERY_IMPLEMENTATION
    if adapter_id in {"agent-live-wallet", "agent-sandbox-wallet",
                      "financial-data-hub", "financial-execution-gateway"}:
        from hermes_installer.components.plugin_finance import FINANCIAL_PLUGIN_IMPLEMENTATIONS
        return FINANCIAL_PLUGIN_IMPLEMENTATIONS.get(adapter_id)
    if adapter_id in {"authentik-authorization", "cloudflare-homelab", "homelab-ops-broker"}:
        from hermes_installer.components.plugin_homelab import resolve_homelab_plugin_implementation
        return resolve_homelab_plugin_implementation(adapter_id)
    if adapter_id in {"epic-kanban", "voice-pipeline", "web"}:
        from hermes_installer.components.plugin_local_voice_web import PLUGIN_IMPLEMENTATIONS
        return PLUGIN_IMPLEMENTATIONS.get(adapter_id)
    if adapter_id in {"ebook-toolchain", "kobo-bridge"}:
        from hermes_installer.components.plugin_documents import DOCUMENT_PLUGIN_IMPLEMENTATIONS
        return DOCUMENT_PLUGIN_IMPLEMENTATIONS.get(adapter_id)
    if adapter_id in {"github", "composio", "codex"}:
        from hermes_installer.components.plugin_accounts_adapters import PLUGIN_IMPLEMENTATIONS
        return PLUGIN_IMPLEMENTATIONS.get(adapter_id)
    return None
