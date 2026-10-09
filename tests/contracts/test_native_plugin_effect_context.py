from __future__ import annotations

from types import ModuleType

import pytest

from hermes_installer.components.plugin_effects import (
    PluginEffectUnavailable,
    PluginActionSchema,
    StaticPluginActionSchemas,
    bind_plugin_effects_to_runtime_context,
)
from hermes_installer.registry.resources_runtime import (
    NativePluginRuntimeContext,
    ResourceIdentity,
)


class _Authority:
    def context(self, **_kwargs):
        raise AssertionError("binding the runtime context must not issue an effect")

    def perform_effect(self, *_args, **_kwargs):
        raise AssertionError("binding the runtime context must not issue an effect")

    def get_invocation_contexts(self, _handle):
        raise AssertionError("binding the runtime context must not issue an effect")


class _SelectedPackage:
    package_id = "package-fixture"
    profile_id = "profile-fixture"
    generation = "generation-fixture"

    def __init__(self, digest: str):
        self.digest = digest

    def resolve(self, _adapter_id, _action_id):
        return None

    def manifest_digest_for_adapter(self, adapter_id):
        return self.digest if adapter_id == "web" else None


class _AdapterRegistry:
    def resolve_plugin_adapter(self, _adapter_id):
        return None


def _context(authority: object) -> NativePluginRuntimeContext:
    return NativePluginRuntimeContext(
        identity=ResourceIdentity(
            resource_id="web", kind="plugins", version="1.0.1",
            source_path="plugins/web.yaml", source_revision="fixture",
            content_digest="a" * 64,
        ),
        declared_capabilities=("retrieve-public-web-content",),
        authority=authority,
        invocation_contexts=lambda **_kwargs: None,
        selected_adapters=_AdapterRegistry(),
    )


def test_trusted_context_composition_installs_facades_pairwise(monkeypatch):
    import sys

    loader = ModuleType("hermes_installer.native_plugin_loader")
    loader.SelectedNativePackage = _SelectedPackage
    loader.bind_current_native_plugin_package = lambda _authority: _SelectedPackage("a" * 64)
    monkeypatch.setitem(sys.modules, loader.__name__, loader)

    authority = _Authority()
    package = _SelectedPackage("a" * 64)
    schemas = StaticPluginActionSchemas({("web", "retrieve-public-web-content"): PluginActionSchema(
        adapter_id="web", action_id="retrieve-public-web-content",
        argument_schema_id="web.retrieve.arguments.v1", result_schema_id="web.retrieve.result.v1",
        operation="plugin.web.read", adapter_sha256="b" * 64,
        argument_schema={"type": "object", "properties": {}, "additionalProperties": False},
        result_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )})

    bound = bind_plugin_effects_to_runtime_context(
        authority=authority, selected_package=package,
        current_binding=lambda: None, runtime_context=_context(authority),
        action_schemas=schemas,
    )

    assert callable(bound.invocation_contexts)
    assert callable(bound.plugin_effects.invoke)
    assert bound.authority is authority
    assert bound.identity.resource_id == "web"
    assert bound.plugin_effects.invocation_contexts is bound.invocation_contexts


def test_trusted_context_composition_rejects_wrong_authority_or_source_digest(monkeypatch):
    import sys

    loader = ModuleType("hermes_installer.native_plugin_loader")
    loader.SelectedNativePackage = _SelectedPackage
    loader.bind_current_native_plugin_package = lambda _authority: _SelectedPackage("a" * 64)
    monkeypatch.setitem(sys.modules, loader.__name__, loader)
    authority = _Authority()

    with pytest.raises(PluginEffectUnavailable, match="runtime context"):
        bind_plugin_effects_to_runtime_context(
            authority=authority, selected_package=_SelectedPackage("a" * 64),
            current_binding=lambda: None, runtime_context=_context(_Authority()),
        )

    context = _context(authority)
    altered = NativePluginRuntimeContext(
        identity=ResourceIdentity(
            resource_id="web", kind="plugins", version="1.0.1",
            source_path="plugins/web.yaml", source_revision="fixture",
            content_digest="c" * 64,
        ),
        declared_capabilities=context.declared_capabilities,
        authority=authority, invocation_contexts=context.invocation_contexts,
        selected_adapters=context.selected_adapters,
    )
    with pytest.raises(PluginEffectUnavailable, match="runtime context"):
        bind_plugin_effects_to_runtime_context(
            authority=authority, selected_package=_SelectedPackage("a" * 64),
            current_binding=lambda: None, runtime_context=altered,
        )
