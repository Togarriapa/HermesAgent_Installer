"""HI08/HI09/RB08 tests for root-selected native package discovery records."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from hermes_installer.native_plugin_bindings import (
    NativePluginBindingUnavailable,
    RootSelectedPluginEffects,
)


def resolver_wire(*, rows=None):
    process_role_records_sha256 = hashlib.sha256(b"[]").hexdigest()
    body = {
        "schema": 1,
        "package_id": "native-package-fixture",
        "profile_id": "profile-fixture",
        "generation": "generation-fixture",
        "process_role_records_sha256": process_role_records_sha256,
        "owner_overlay_operation_records": [],
        "adapters": list(rows if rows is not None else [{
            "adapter_id": "fixture-plugin",
            "manifest_sha256": "a" * 64,
            "adapter_sha256": "b" * 64,
            "action_id": "fixture.read",
            "argument_schema_id": "schema.fixture.args",
            "result_schema_id": "schema.fixture.result",
            "effect_enrollment_id": "effect.fixture.read",
            "operation": "plugin.fixture-plugin.read",
            "capability": "plugin:fixture-plugin",
            "target_id": "plugin:fixture-plugin:target-fixture:generation-fixture",
            "recipient": None,
            "generation": "generation-fixture",
        }]),
    }
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"), allow_nan=False).encode("utf-8")
    return {**body, "resolver_sha256": hashlib.sha256(canonical).hexdigest()}


def owner_overlay_wire(registration_id="resource-overlay-store:tool:resource_overlay_read"):
    method, operation = {
        "resource-overlay-store:tool:resource_overlay_read": ("read", "plugin.resource-overlay-store.read"),
        "resource-overlay-store:tool:resource_overlay_history": ("history", "plugin.resource-overlay-store.read"),
        "resource-overlay-store:tool:resource_overlay_write": ("write", "plugin.resource-overlay-store.write"),
        "resource-overlay-store:tool:resource_overlay_delete": ("delete", "plugin.resource-overlay-store.write"),
    }[registration_id]
    return {
        "registration_id": registration_id, "method": method, "operation": operation,
        "capability": "plugin:resource-overlay-store", "target_id": "target-1", "recipient": None,
        "effect_enrollment_id": "effect-1", "profile_id": "profile-fixture",
        "profile_generation": "profile-gen-1", "principal_id": "principal-1",
        "namespace_id": "namespace-1", "package_id": "native-package-fixture",
        "package_generation": "generation-fixture", "argument_schema_id": "args-1",
        "argument_schema_sha256": "a" * 64, "argument_schema_receipt_handle": "args-receipt-1",
        "result_schema_id": "result-1", "result_schema_sha256": "b" * 64,
        "result_schema_receipt_handle": "result-receipt-1", "handler_artifact_id": "handler-1",
        "handler_sha256": "c" * 64, "handler_source_receipt_handle": "handler-receipt-1",
        "profile_view_selection_handle": "view-selection-1", "profile_view_receipt_handle": "view-receipt-1",
        "data_root_selection_handle": "data-root-selection-1", "data_root_receipt_handle": "data-root-receipt-1",
        "target_selection_handle": "target-selection-1", "target_receipt_handle": "target-receipt-1",
        "prepared_source_observer_selection_handle": "observer-selection-1",
        "source_observer_enrollment_ids": ["observer-1"], "process_role_id": "role-1",
        "source_issuer_id": "issuer-1",
    }


class AuthorityFixture:
    def __init__(self, resolver=None, *, expires=50.0):
        self.resolver = resolver if resolver is not None else resolver_wire()
        self.expires = expires
        self.calls = []

    def bind_selected_native_package(self):
        self.calls.append(("bind", ()))
        return {
            "schema": 1,
            "opaque_binding_handle": "opaque_binding_handle_fixture_0001",
            "package_id": "native-package-fixture",
            "profile_id": "profile-fixture",
            "generation": "generation-fixture",
            "resolver_digest": self.resolver["resolver_sha256"],
            "compiled_closure_sha256": "c" * 64,
            "entrypoint_sha256": "d" * 64,
            "expires_monotonic": self.expires,
        }

    def read_native_resolver(self, binding_handle):
        self.calls.append(("resolver", binding_handle))
        return self.resolver


class NativePluginBindingTests(unittest.TestCase):
    def test_selected_binding_is_no_argument_and_resolver_is_presentation_only(self):
        authority = AuthorityFixture()
        effects = RootSelectedPluginEffects(authority, clock=lambda: 10.0)

        selected = effects.resolve("fixture-plugin", "fixture.read")
        self.assertEqual(authority.calls, [
            ("bind", ()),
            ("resolver", "opaque_binding_handle_fixture_0001"),
        ])
        self.assertEqual(effects.package_id, "native-package-fixture")
        self.assertEqual(effects.profile_id, "profile-fixture")
        self.assertEqual(effects.generation, "generation-fixture")
        self.assertEqual(selected.effect_enrollment_id, "effect.fixture.read")
        self.assertIsNone(effects.resolve("unselected-plugin", "fixture.read"))
        self.assertEqual(effects.adapter_rows[0].adapter_id, "fixture-plugin")
        self.assertEqual(effects.owner_overlay_operations, ())
        with self.assertRaises((AttributeError, TypeError)):
            selected.generation = "other-generation"

    def test_owner_overlay_rows_are_a_separate_complete_local_lane(self):
        rows = [owner_overlay_wire(registration) for registration in sorted({
            "resource-overlay-store:tool:resource_overlay_read",
            "resource-overlay-store:tool:resource_overlay_history",
            "resource-overlay-store:tool:resource_overlay_write",
            "resource-overlay-store:tool:resource_overlay_delete",
        })]
        wire = resolver_wire()
        wire["owner_overlay_operation_records"] = rows
        canonical = {key: wire[key] for key in (
            "schema", "package_id", "profile_id", "generation", "process_role_records_sha256",
            "adapters", "owner_overlay_operation_records")}
        wire["resolver_sha256"] = hashlib.sha256(json.dumps(
            canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False).encode("utf-8")).hexdigest()
        selected = RootSelectedPluginEffects(AuthorityFixture(wire), clock=lambda: 10.0)
        self.assertEqual({row.method for row in selected.owner_overlay_operations},
                         {"read", "history", "write", "delete"})
        self.assertEqual(len(selected.adapter_rows), 1)
        self.assertIsNone(selected.resolve("resource-overlay-store", rows[0]["registration_id"]))
        self.assertEqual(selected.resolve_owner_overlay(rows[0]["registration_id"]).method,
                         rows[0]["method"])

        rows[0]["data_root_receipt_handle"] = ""
        wire["owner_overlay_operation_records"] = rows
        canonical["owner_overlay_operation_records"] = rows
        wire["resolver_sha256"] = hashlib.sha256(json.dumps(
            canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False).encode("utf-8")).hexdigest()
        with self.assertRaises(NativePluginBindingUnavailable):
            RootSelectedPluginEffects(AuthorityFixture(wire), clock=lambda: 10.0)

    def test_opaque_target_identifier_is_metadata_not_an_authority_shape(self):
        wire = resolver_wire(rows=[{
            **resolver_wire()["adapters"][0],
            "target_id": "overlay.store.read.v1",
        }])
        effects = RootSelectedPluginEffects(AuthorityFixture(wire), clock=lambda: 10.0)
        self.assertEqual(effects.resolve("fixture-plugin", "fixture.read").target_id,
                         "overlay.store.read.v1")

    def test_missing_authority_binding_methods_stay_unavailable(self):
        with self.assertRaises(NativePluginBindingUnavailable):
            RootSelectedPluginEffects(object())

    def test_binding_rejects_bad_lease_or_invalid_root_selected_binding(self):
        authority = AuthorityFixture(expires=10.0)
        with self.assertRaises(NativePluginBindingUnavailable):
            RootSelectedPluginEffects(authority, clock=lambda: 10.0)

        authority = AuthorityFixture()
        authority.bind_selected_native_package = lambda: {
            "schema": 1,
            "opaque_binding_handle": "../attacker",
            "package_id": "native-package-fixture",
            "profile_id": "profile-fixture",
            "generation": "generation-fixture",
            "resolver_digest": "0" * 64,
            "compiled_closure_sha256": "c" * 64,
            "entrypoint_sha256": "d" * 64,
            "expires_monotonic": 20.0,
        }
        with self.assertRaises(NativePluginBindingUnavailable):
            RootSelectedPluginEffects(authority, clock=lambda: 10.0)

    def test_resolver_rejects_extra_rows_fields_digest_drift_and_generation_mismatch(self):
        mutations = []
        extra = resolver_wire()
        extra["caller_selected"] = True
        mutations.append(extra)

        wrong_digest = resolver_wire()
        wrong_digest["resolver_sha256"] = "0" * 64
        mutations.append(wrong_digest)

        wrong_generation = resolver_wire()
        wrong_generation["adapters"][0]["generation"] = "generation-other"
        canonical = {key: wrong_generation[key] for key in
                     ("schema", "package_id", "profile_id", "generation",
                      "process_role_records_sha256", "adapters", "owner_overlay_operation_records")}
        wrong_generation["resolver_sha256"] = hashlib.sha256(json.dumps(
            canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False).encode("utf-8")).hexdigest()
        mutations.append(wrong_generation)

        for wire in mutations:
            with self.subTest(wire=wire):
                with self.assertRaises(NativePluginBindingUnavailable):
                    RootSelectedPluginEffects(AuthorityFixture(wire), clock=lambda: 10.0)

    def test_resolver_rejects_duplicate_actions_and_nonselected_target_or_operation(self):
        row = resolver_wire()["adapters"][0]
        invalid_rows = [
            [row, row],
            [{**row, "target_id": "https://example.invalid"}],
            [{**row, "operation": "plugin.other.read"}],
            [{**row, "capability": "plugin:*"}],
            [{**row, "manifest_sha256": "not-a-digest"}],
        ]
        for rows in invalid_rows:
            with self.subTest(rows=rows):
                with self.assertRaises(NativePluginBindingUnavailable):
                    RootSelectedPluginEffects(AuthorityFixture(resolver_wire(rows=rows)),
                                              clock=lambda: 10.0)

    def test_resolver_lease_expires_without_stale_row_fallback(self):
        now = [10.0]
        effects = RootSelectedPluginEffects(AuthorityFixture(expires=11.0), clock=lambda: now[0])
        now[0] = 11.0
        with self.assertRaises(NativePluginBindingUnavailable):
            effects.resolve("fixture-plugin", "fixture.read")
        with self.assertRaises(NativePluginBindingUnavailable):
            _ = effects.binding_handle


if __name__ == "__main__":
    unittest.main()
