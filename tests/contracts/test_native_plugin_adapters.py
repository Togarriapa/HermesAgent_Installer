"""Native Plugin identity is explicit and activation needs a trusted adapter."""
import unittest
from dataclasses import dataclass
import base64
import hashlib
from types import SimpleNamespace

from hermes_installer.components.native_plugins import (
    NATIVE_PLUGIN_ADAPTERS,
    NativePluginUnavailable,
    create_native_plugin_handler,
    resolve_native_plugin_adapter,
    RESOURCE_OVERLAY_STORE_IMPLEMENTATION,
    native_plugin_handler_available,
    resolve_native_plugin_implementation,
)


class _Registry:
    def __init__(self, implementation=None):
        self.implementation = implementation
        self.lookups = []

    def resolve_plugin_adapter(self, adapter_id):
        self.lookups.append(adapter_id)
        return self.implementation


class _Context:
    def __init__(self, implementation=None, plugin_id="financial-execution-gateway"):
        self.selected_adapters = _Registry(implementation)
        self.identity = SimpleNamespace(kind="plugins", resource_id=plugin_id)


class NativePluginAdapterTests(unittest.TestCase):
    def test_all_preserved_plugin_ids_have_distinct_explicit_adapter_identity(self):
        ids = [row.adapter_id for row in NATIVE_PLUGIN_ADAPTERS]
        self.assertEqual(len(ids), 18)
        self.assertEqual(len(ids), len(set(ids)))
        for plugin_id in ids:
            self.assertEqual(resolve_native_plugin_adapter(plugin_id).resource_id, plugin_id)
        self.assertTrue(native_plugin_handler_available("resource-overlay-store"))
        self.assertFalse(native_plugin_handler_available("agent-live-wallet"))
        self.assertIs(RESOURCE_OVERLAY_STORE_IMPLEMENTATION,
                      resolve_native_plugin_implementation("resource-overlay-store"))
        self.assertIsNone(resolve_native_plugin_implementation("agent-live-wallet"))

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

        runtime = _Context(Implementation(), plugin_id="resource-overlay-store")
        register = create_native_plugin_handler("resource-overlay-store", runtime)
        native_ctx = object()
        self.assertIsNone(register(native_ctx))
        self.assertEqual(events, [(native_ctx, runtime)])

    def test_handler_rejects_context_from_another_plugin_before_registry_lookup(self):
        context = _Context(plugin_id="github")
        with self.assertRaisesRegex(NativePluginUnavailable, "selected Plugin identity"):
            create_native_plugin_handler("resource-overlay-store", context)
        self.assertEqual([], context.selected_adapters.lookups)

    def test_unknown_plugin_id_is_not_accepted_as_alias(self):
        with self.assertRaisesRegex(KeyError, "unknown native Plugin"):
            create_native_plugin_handler("codex-plugin-from-declaration", _Context())

    def test_overlay_tools_write_read_history_and_cas_delete_effects(self):
        @dataclass(frozen=True)
        class Value:
            value: bytes
            revision: str

        class Store:
            def __init__(self):
                self.values = {}
                self.versions = {}

            def read(self, record_id):
                return self.values.get(record_id)

            def write(self, record_id, value, *, expected_revision):
                current = self.values.get(record_id)
                if (current.revision if current else None) != expected_revision:
                    raise RuntimeError("overlay compare-and-swap conflict")
                revision = hashlib.sha256(value).hexdigest()
                self.values[record_id] = Value(value, revision)
                self.versions.setdefault(record_id, []).append(revision)
                return revision

            def history(self, record_id):
                return tuple(self.versions.get(record_id, ()))

            def delete(self, record_id, *, expected_revision):
                current = self.values.get(record_id)
                if current is None or current.revision != expected_revision:
                    raise RuntimeError("overlay compare-and-swap conflict")
                del self.values[record_id]
                tombstone = hashlib.sha256((record_id + expected_revision).encode()).hexdigest()
                self.versions[record_id].append(tombstone)
                return tombstone

        class PluginContext:
            def __init__(self):
                self.tools = {}

            def register_tool(self, *, name, toolset, schema, handler, **kwargs):
                self.tools[name] = (toolset, schema, handler, kwargs)

        class Runtime:
            def __init__(self):
                self.local_overlay_store = Store()

        runtime = Runtime()
        plugin = PluginContext()
        RESOURCE_OVERLAY_STORE_IMPLEMENTATION.register(plugin, runtime)
        write = plugin.tools["resource_overlay_write"][2]
        read = plugin.tools["resource_overlay_read"][2]
        history = plugin.tools["resource_overlay_history"][2]
        delete = plugin.tools["resource_overlay_delete"][2]
        first = write({"record_id": "lesson-1", "value_base64": base64.b64encode(b"learned").decode()})
        self.assertEqual(read({"record_id": "lesson-1"})["value_base64"], base64.b64encode(b"learned").decode())
        second = write({"record_id": "lesson-1", "value_base64": base64.b64encode(b"updated").decode(), "expected_revision": first["revision"]})
        self.assertEqual(len(history({"record_id": "lesson-1"})["revisions"]), 2)
        self.assertNotEqual(first["revision"], second["revision"])
        with self.assertRaisesRegex(RuntimeError, "conflict"):
            delete({"record_id": "lesson-1", "expected_revision": first["revision"]})
        deletion = delete({"record_id": "lesson-1", "expected_revision": second["revision"]})
        self.assertEqual(read({"record_id": "lesson-1"}), {"found": False, "record_id": "lesson-1"})
        self.assertEqual(len(deletion["deleted_revision"]), 64)


if __name__ == "__main__":
    unittest.main()
