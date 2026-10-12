"""Contracts for the finite native profile reasoning setting."""
from __future__ import annotations

import unittest

from hermes_installer.remote.jarvis_chat import JarvisChatDenied
from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.jarvis_feature_registry import FEATURE_ASSETS as REGISTERED_ASSETS
from hermes_installer.remote.jarvis_settings_admin import (
    FEATURE_ROUTES,
    _RevisionLedger,
    apply_global_reasoning,
    decode_native_reasoning,
)
from hermes_installer.remote.jarvis_settings_admin_assets import FEATURE_ASSETS


class _Backend:
    def __init__(self, *, accepted="high", readback="high"):
        self.accepted = accepted
        self.readback = readback
        self.calls = []

    async def _rpc(self, method, params):
        self.calls.append((method, params))
        if method == "config.set":
            return {"key": "reasoning", "value": self.accepted}
        if method == "config.get":
            return {"value": self.readback, "display": "show"}
        raise AssertionError("unexpected native method")


class JarvisSettingsAdminTests(unittest.IsolatedAsyncioTestCase):
    def test_leaf_is_registered_with_only_its_fixed_setting_routes(self):
        validate_feature_assets((FEATURE_ASSETS,))
        self.assertIn(FEATURE_ASSETS, REGISTERED_ASSETS)
        self.assertEqual(FEATURE_ASSETS.feature_id, "settings-admin")
        self.assertEqual(FEATURE_ASSETS.api_routes, FEATURE_ROUTES)
        self.assertEqual(FEATURE_ROUTES, (
            ("GET", "/chat/api/settings/reasoning-effort"),
            ("POST", "/chat/api/settings/reasoning-effort"),
        ))
        self.assertIn("agent.reasoning_effort", FEATURE_ASSETS.view_html)
        self.assertIn("future-conversations", FEATURE_ASSETS.mount_js)
        self.assertNotIn("innerHTML", FEATURE_ASSETS.mount_js)

    async def test_native_write_uses_fixed_global_setter_then_sanitized_readback(self):
        backend = _Backend(accepted="xhigh", readback="xhigh")
        result = await apply_global_reasoning(backend, "xhigh")
        self.assertEqual(result, {"effort": "xhigh", "display": "show"})
        self.assertEqual(backend.calls, [
            ("config.set", {"key": "reasoning", "value": "xhigh", "scope": "global"}),
            ("config.get", {"key": "reasoning"}),
        ])

    async def test_unlisted_value_or_wrong_native_readback_is_not_accepted(self):
        backend = _Backend()
        with self.assertRaises(JarvisChatDenied):
            await apply_global_reasoning(backend, "../../custom_providers")
        self.assertEqual(backend.calls, [])
        backend = _Backend(accepted="high", readback="low")
        with self.assertRaises(JarvisChatDenied):
            await apply_global_reasoning(backend, "high")
        self.assertEqual(len(backend.calls), 2)

    def test_projection_rejects_config_dumps_and_secret_or_unknown_fields(self):
        self.assertEqual(decode_native_reasoning({"value": "medium", "display": "hide"}),
                         {"effort": "medium", "display": "hide"})
        for invalid in (
            {"value": "medium", "display": "show", "api_key": "secret"},
            {"value": {"enabled": True, "effort": "medium"}, "display": "show"},
            {"value": "typo", "display": "show"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(JarvisChatDenied):
                decode_native_reasoning(invalid)

    def test_write_grant_is_one_use_and_bound_to_owner_generation_and_config(self):
        ledger = _RevisionLedger()
        token = ledger.issue(subject="owner-a", generation="generation-a",
                             config_sha256="a" * 64, effort="medium")
        self.assertFalse(ledger.consume(token, subject="owner-b", generation="generation-a",
                                        config_sha256="a" * 64, current_effort="medium"))
        token = ledger.issue(subject="owner-a", generation="generation-a",
                             config_sha256="a" * 64, effort="medium")
        self.assertFalse(ledger.consume(token, subject="owner-a", generation="generation-b",
                                        config_sha256="a" * 64, current_effort="medium"))
        token = ledger.issue(subject="owner-a", generation="generation-a",
                             config_sha256="a" * 64, effort="medium")
        self.assertFalse(ledger.consume(token, subject="owner-a", generation="generation-a",
                                        config_sha256="b" * 64, current_effort="medium"))
        token = ledger.issue(subject="owner-a", generation="generation-a",
                             config_sha256="a" * 64, effort="medium")
        self.assertTrue(ledger.consume(token, subject="owner-a", generation="generation-a",
                                       config_sha256="a" * 64, current_effort="medium"))
        self.assertFalse(ledger.consume(token, subject="owner-a", generation="generation-a",
                                        config_sha256="a" * 64, current_effort="medium"))


if __name__ == "__main__":
    unittest.main()
