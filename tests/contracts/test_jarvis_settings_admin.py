"""Contracts for the finite native profile reasoning setting."""
from __future__ import annotations

import unittest

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hermes_installer.remote.jarvis_chat import JarvisChatDenied, JarvisChatService
from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.jarvis_feature_registry import FEATURE_ASSETS as REGISTERED_ASSETS
from hermes_installer.remote.jarvis_settings_admin import (
    FEATURE_ROUTES,
    _RevisionLedger,
    apply_global_busy_mode,
    apply_global_reasoning,
    decode_native_busy,
    decode_native_reasoning,
    install_jarvis_settings_admin_routes,
)
from hermes_installer.remote.jarvis_settings_admin_assets import FEATURE_ASSETS


class _Backend:
    def __init__(self, *, accepted="high", readback="high", busy_mode="interrupt"):
        self.accepted = accepted
        self.readback = readback
        self.busy_mode = busy_mode
        self.calls = []

    async def _rpc(self, method, params):
        self.calls.append((method, params))
        if method == "config.set":
            if params.get("key") == "busy":
                self.busy_mode = params["value"]
                return {"key": "busy", "value": self.busy_mode}
            return {"key": "reasoning", "value": self.accepted}
        if method == "config.get":
            if params.get("key") == "busy":
                return {"value": self.busy_mode}
            return {"value": self.readback, "display": "show"}
        raise AssertionError("unexpected native method")


class JarvisSettingsAdminTests(unittest.IsolatedAsyncioTestCase):
    async def test_route_installation_preserves_finite_methods_and_denies_head(self):
        app = web.Application()
        # Route installation is independent of service execution. Exercise the
        # actual aiohttp router so unsupported add_post keyword arguments fail
        # here instead of during application startup on the Pi.
        service = object.__new__(JarvisChatService)
        install_jarvis_settings_admin_routes(app, service)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            for _method, path in FEATURE_ROUTES:
                head = await client.head(path)
                self.assertEqual(head.status, 405, path)
                put = await client.put(path)
                self.assertEqual(put.status, 405, path)
            for _method, path in (route for route in FEATURE_ROUTES if route[0] == "POST"):
                post = await client.post(path, data="{}", headers={"Content-Type": "application/json"})
                self.assertEqual(post.status, 400, path)
        finally:
            await client.close()

    def test_leaf_is_registered_with_only_its_fixed_setting_routes(self):
        validate_feature_assets((FEATURE_ASSETS,))
        self.assertIn(FEATURE_ASSETS, REGISTERED_ASSETS)
        self.assertEqual(FEATURE_ASSETS.feature_id, "settings-admin")
        self.assertEqual(FEATURE_ASSETS.api_routes, FEATURE_ROUTES)
        self.assertEqual(FEATURE_ROUTES, (
            ("GET", "/chat/api/settings/reasoning-effort"),
            ("POST", "/chat/api/settings/reasoning-effort"),
            ("GET", "/chat/api/settings/busy-input"),
            ("POST", "/chat/api/settings/busy-input"),
        ))
        self.assertIn("agent.reasoning_effort", FEATURE_ASSETS.view_html)
        self.assertIn("display.busy_input_mode", FEATURE_ASSETS.view_html)
        self.assertIn("future-conversations", FEATURE_ASSETS.mount_js)
        self.assertIn("native-conversation-input", FEATURE_ASSETS.mount_js)
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

    async def test_busy_mode_uses_native_allowlisted_choice_and_readback(self):
        backend = _Backend()
        self.assertEqual(await apply_global_busy_mode(backend, "queue"), "queue")
        self.assertEqual(backend.calls, [
            ("config.set", {"key": "busy", "value": "queue"}),
            ("config.get", {"key": "busy"}),
        ])
        with self.assertRaises(JarvisChatDenied):
            await apply_global_busy_mode(backend, "shell")
        self.assertEqual(decode_native_busy({"value": "steer"}), "steer")
        with self.assertRaises(JarvisChatDenied):
            decode_native_busy({"value": "interrupt", "config": {"secret": "value"}})

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
                             config_sha256="a" * 64, setting_id="agent.reasoning_effort",
                             current_value="medium")
        self.assertFalse(ledger.consume(token, subject="owner-b", generation="generation-a",
                                        config_sha256="a" * 64,
                                        setting_id="agent.reasoning_effort", current_value="medium"))
        token = ledger.issue(subject="owner-a", generation="generation-a",
                             config_sha256="a" * 64, setting_id="agent.reasoning_effort",
                             current_value="medium")
        self.assertFalse(ledger.consume(token, subject="owner-a", generation="generation-b",
                                        config_sha256="a" * 64,
                                        setting_id="agent.reasoning_effort", current_value="medium"))
        token = ledger.issue(subject="owner-a", generation="generation-a",
                             config_sha256="a" * 64, setting_id="agent.reasoning_effort",
                             current_value="medium")
        self.assertFalse(ledger.consume(token, subject="owner-a", generation="generation-a",
                                        config_sha256="b" * 64,
                                        setting_id="agent.reasoning_effort", current_value="medium"))
        token = ledger.issue(subject="owner-a", generation="generation-a",
                             config_sha256="a" * 64, setting_id="agent.reasoning_effort",
                             current_value="medium")
        self.assertTrue(ledger.consume(token, subject="owner-a", generation="generation-a",
                                       config_sha256="a" * 64,
                                       setting_id="agent.reasoning_effort", current_value="medium"))
        self.assertFalse(ledger.consume(token, subject="owner-a", generation="generation-a",
                                        config_sha256="a" * 64,
                                        setting_id="agent.reasoning_effort", current_value="medium"))
        token = ledger.issue(subject="owner-a", generation="generation-a",
                             config_sha256="a" * 64, setting_id="display.busy_input_mode",
                             current_value="queue")
        self.assertFalse(ledger.consume(token, subject="owner-a", generation="generation-a",
                                        config_sha256="a" * 64,
                                        setting_id="agent.reasoning_effort", current_value="queue"))


if __name__ == "__main__":
    unittest.main()
