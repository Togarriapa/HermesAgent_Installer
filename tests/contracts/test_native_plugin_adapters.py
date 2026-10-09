"""Native Plugin identity is explicit and activation needs a trusted adapter."""
import unittest

from hermes_installer.components.native_plugins import (
    NATIVE_PLUGIN_ADAPTERS,
    NativePluginUnavailable,
    create_native_plugin_handler,
    resolve_native_plugin_adapter,
)


class _Registry:
    def __init__(self, implementation=None):
        self.implementation = implementation
        self.lookups = []

    def resolve_plugin_adapter(self, adapter_id):
        self.lookups.append(adapter_id)
        return self.implementation


class _Context:
    def __init__(self, implementation=None):
        self.selected_adapters = _Registry(implementation)


class NativePluginAdapterTests(unittest.TestCase):
    def test_all_preserved_plugin_ids_have_distinct_explicit_adapter_identity(self):
        ids = [row.adapter_id for row in NATIVE_PLUGIN_ADAPTERS]
        self.assertEqual(len(ids), 18)
        self.assertEqual(len(ids), len(set(ids)))
        for plugin_id in ids:
            self.assertEqual(resolve_native_plugin_adapter(plugin_id).resource_id, plugin_id)

    def test_missing_handler_fails_closed_before_activation(self):
        ctx = _Context()
        with self.assertRaisesRegex(NativePluginUnavailable, "discovered/pending"):
            create_native_plugin_handler("financial-execution-gateway", ctx)
        self.assertEqual(ctx.selected_adapters.lookups, ["financial-execution-gateway"])

    def test_handler_registers_only_through_selected_typed_implementation(self):
        events = []

        class Implementation:
            def register(self, native_ctx, runtime_context):
                events.append((native_ctx, runtime_context))

        runtime = _Context(Implementation())
        register = create_native_plugin_handler("resource-overlay-store", runtime)
        native_ctx = object()
        self.assertIsNone(register(native_ctx))
        self.assertEqual(events, [(native_ctx, runtime)])

    def test_unknown_plugin_id_is_not_accepted_as_alias(self):
        with self.assertRaisesRegex(KeyError, "unknown native Plugin"):
            create_native_plugin_handler("codex-plugin-from-declaration", _Context())


if __name__ == "__main__":
    unittest.main()
