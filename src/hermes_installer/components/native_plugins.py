"""Typed bridge from preserved Plugin resources to reviewed native adapters.

Resource manifests supply identity and declared capabilities only. They never
supply Python callables, endpoints, or credential values. Implementations are
resolved from the installer-owned selected-adapter registry.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class NativePluginAdapterContract:
    adapter_id: str
    resource_id: str
    component_adapter_id: str | None
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

# Plugin resources are source identities from the user's preserved registry,
# not aliases for unrelated seed repositories. A matching source adapter ID is
# attached only after a reviewed one-to-one source crosswalk exists.
NATIVE_PLUGIN_ADAPTERS = tuple(
    NativePluginAdapterContract(
        adapter_id=plugin_id,
        resource_id=plugin_id,
        component_adapter_id=None,
        status="typed-adapter-registry-required",
        blocker="No one-to-one reviewed seed-source crosswalk or registered native handler yet",
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


def create_native_plugin_handler(adapter_id: str, runtime_context: NativePluginRuntimeContext):
    """Return a native `register(ctx)` closure backed by a typed adapter.

    The registry is installer-owned and accepts implementations, never
    callables declared by imported plugin YAML. Missing implementations fail
    explicitly so resource discovery cannot imply activation.
    """
    contract = resolve_native_plugin_adapter(adapter_id)
    if runtime_context is None or not hasattr(runtime_context, "selected_adapters"):
        raise NativePluginUnavailable(f"{adapter_id}: trusted selected-adapter registry is unavailable")
    implementation = runtime_context.selected_adapters.resolve_plugin_adapter(adapter_id)
    if implementation is None:
        raise NativePluginUnavailable(
            f"{adapter_id}: {contract.blocker}; preserve as discovered/pending until a reviewed adapter is registered"
        )

    def register(ctx: object) -> None:
        implementation.register(ctx, runtime_context)

    return register
