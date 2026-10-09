"""Native homelab wrappers fail closed without the root selected-effect resolver."""
from __future__ import annotations

import unittest

from hermes_installer.components.plugin_homelab import (
    AUTHENTIK_AUTHORIZATION_IMPLEMENTATION,
    CLOUDFLARE_HOMELAB_IMPLEMENTATION,
    HOMELAB_OPS_BROKER_IMPLEMENTATION,
    HomelabPluginUnavailable,
)
from hermes_installer.registry.resources_runtime import NativePluginRuntimeContext, ResourceIdentity


class _PluginContext:
    def register_tool(self, **kwargs):
        raise AssertionError("no tool may register without selected root effects")


def _runtime(plugin_id: str, version: str = "1.0.0") -> NativePluginRuntimeContext:
    return NativePluginRuntimeContext(
        identity=ResourceIdentity(plugin_id, "plugins", version, f"plugins/{plugin_id}.yaml",
                                  "a" * 40, "b" * 64),
        declared_capabilities=(), authority=object(), invocation_contexts=lambda **_: (object(),),
        selected_adapters=object(),
    )


class HomelabNativeWrapperTests(unittest.TestCase):
    def test_no_homelab_resource_uses_generic_provider_or_host_write(self):
        for implementation, plugin_id in (
            (AUTHENTIK_AUTHORIZATION_IMPLEMENTATION, "authentik-authorization"),
            (CLOUDFLARE_HOMELAB_IMPLEMENTATION, "cloudflare-homelab"),
            (HOMELAB_OPS_BROKER_IMPLEMENTATION, "homelab-ops-broker"),
        ):
            with self.subTest(plugin_id=plugin_id):
                with self.assertRaisesRegex(HomelabPluginUnavailable, "selected-plugin effect enrollment"):
                    implementation.register(_PluginContext(), _runtime(plugin_id))

    def test_wrong_source_identity_never_registers_tools(self):
        for implementation, plugin_id in (
            (AUTHENTIK_AUTHORIZATION_IMPLEMENTATION, "authentik-authorization"),
            (CLOUDFLARE_HOMELAB_IMPLEMENTATION, "cloudflare-homelab"),
            (HOMELAB_OPS_BROKER_IMPLEMENTATION, "homelab-ops-broker"),
        ):
            with self.subTest(plugin_id=plugin_id):
                with self.assertRaisesRegex(HomelabPluginUnavailable, "pinned v1.0.0"):
                    implementation.register(_PluginContext(), _runtime(plugin_id, "9.9.9"))


if __name__ == "__main__":
    unittest.main()
