"""Pinned homelab Plugins request only typed root-brokered fixed effects."""
from __future__ import annotations

import json
import unittest
from types import SimpleNamespace

from hermes_installer.authority.types import canonical_digest
from hermes_installer.components.plugin_homelab import (
    AUTHENTIK_AUTHORIZATION_IMPLEMENTATION,
    CLOUDFLARE_HOMELAB_IMPLEMENTATION,
    HOMELAB_OPS_BROKER_IMPLEMENTATION,
)
from hermes_installer.registry.resources_runtime import (
    NativePluginRuntimeContext,
    ResourceIdentity,
)


class _Authority:
    def __init__(self, *, deny=False):
        self.deny = deny
        self.calls = []

    def context(self, **kwargs):
        self.calls.append(("context", kwargs))
        return object()

    def authorize_effect(self, context, **kwargs):
        self.calls.append(("authorize", kwargs))
        if self.deny:
            raise PermissionError("fresh Authentik System check denied")
        return SimpleNamespace(request_digest=kwargs["request_digest"])

    def verify_effect(self, authorization, context, **kwargs):
        self.calls.append(("verify", kwargs))

    def perform_effect(self, authorization, *, operation, payload, timeout, **kwargs):
        self.calls.append(("perform", {"operation": operation, "payload": payload, "timeout": timeout}))
        return SimpleNamespace(status=200, body=b'{"result":{"accepted":true}}')


class _PluginContext:
    def __init__(self):
        self.tools = {}

    def register_tool(self, *, name, toolset, schema, handler, **kwargs):
        self.tools[name] = (toolset, schema, handler, kwargs)


def _runtime(plugin_id, authority=None):
    identity = ResourceIdentity(plugin_id, "plugins", "1.0.0", f"plugins/{plugin_id}.yaml",
                                 "a" * 40, "b" * 64)
    return NativePluginRuntimeContext(
        identity=identity, declared_capabilities=(), authority=authority or _Authority(),
        invocation_contexts=lambda **kwargs: (object(),), selected_adapters=object(),
    )


class HomelabPluginTests(unittest.TestCase):
    def test_authentik_tools_never_accept_user_supplied_identity_or_groups(self):
        runtime, plugin = _runtime("authentik-authorization"), _PluginContext()
        AUTHENTIK_AUTHORIZATION_IMPLEMENTATION.register(plugin, runtime)
        self.assertEqual(set(plugin.tools), {
            "authentik_current_principal", "authentik_verify_system_membership",
            "authentik_system_alarm_recipients",
        })
        for _, schema, _, _ in plugin.tools.values():
            self.assertEqual(schema["properties"], {})
            self.assertFalse(schema["additionalProperties"])
        result = plugin.tools["authentik_verify_system_membership"][2]({})
        call = [row for row in runtime.authority.calls if row[0] == "perform"][0][1]
        body = json.loads(call["payload"])
        self.assertEqual(body["action"], "verify-effective-system-membership")
        self.assertEqual(body["arguments"], {})
        self.assertEqual(call["operation"], "provider.dispatch")
        self.assertEqual(result, {"accepted": True})

    def test_cloudflare_actions_bind_approved_hostname_and_fixed_root_operation(self):
        runtime, plugin = _runtime("cloudflare-homelab"), _PluginContext()
        CLOUDFLARE_HOMELAB_IMPLEMENTATION.register(plugin, runtime)
        read = plugin.tools["cloudflare_homelab_read_dns"][2]
        read({"hostname": "ha.togarriapahome.uk"})
        read_call = [row for row in runtime.authority.calls if row[0] == "perform"][-1][1]
        self.assertEqual(read_call["operation"], "provider.dispatch")
        self.assertEqual(json.loads(read_call["payload"])["arguments"], {"hostname": "ha.togarriapahome.uk"})

        update = plugin.tools["cloudflare_homelab_update_dns"][2]
        update({"hostname": "ha.togarriapahome.uk", "content": "192.0.2.8", "ttl": 300, "proxied": False})
        write_call = [row for row in runtime.authority.calls if row[0] == "perform"][-1][1]
        self.assertEqual(write_call["operation"], "host.write")
        payload = json.loads(write_call["payload"])
        self.assertEqual(payload["action"], "update-approved-dns-record")
        auth = [row[1] for row in runtime.authority.calls if row[0] == "authorize"][-1]
        self.assertEqual(auth["target"], "resource:plugins/cloudflare-homelab@1.0.0")
        self.assertEqual(auth["capability"], "plugin.cloudflare.write")
        self.assertEqual(auth["request_digest"], canonical_digest(write_call["payload"]))
        self.assertTrue(runtime.authority.calls[0][1]["source_contexts"])
        self.assertEqual([row[0] for row in runtime.authority.calls[-4:]],
                         ["context", "authorize", "verify", "perform"])

    def test_cloudflare_rejects_unapproved_hosts_targets_and_endpoints_before_authority(self):
        runtime, plugin = _runtime("cloudflare-homelab"), _PluginContext()
        CLOUDFLARE_HOMELAB_IMPLEMENTATION.register(plugin, runtime)
        with self.assertRaises(ValueError):
            plugin.tools["cloudflare_homelab_read_dns"][2]({"hostname": "other.example"})
        with self.assertRaises(ValueError):
            plugin.tools["cloudflare_homelab_update_dns"][2]({
                "hostname": "ha.togarriapahome.uk", "content": "attacker.example",
                "ttl": 300, "proxied": False,
            })
        with self.assertRaises(ValueError):
            plugin.tools["cloudflare_homelab_read_dns"][2]({
                "hostname": "ha.togarriapahome.uk", "url": "https://attacker.example",
            })
        self.assertEqual(runtime.authority.calls, [])

    def test_ops_broker_only_sends_enumerated_named_actions_and_gates_writes(self):
        runtime, plugin = _runtime("homelab-ops-broker"), _PluginContext()
        HOMELAB_OPS_BROKER_IMPLEMENTATION.register(plugin, runtime)
        plugin.tools["homelab_ops_inspect"][2]({"host": "hermes", "query": "host-health"})
        read_call = [row for row in runtime.authority.calls if row[0] == "perform"][-1][1]
        self.assertEqual(read_call["operation"], "provider.dispatch")
        self.assertEqual(json.loads(read_call["payload"])["action"], "inspect-approved-target")

        with self.assertRaises(ValueError):
            plugin.tools["homelab_ops_run"][2]({"host": "hermes", "action": "arbitrary-shell"})
        with self.assertRaises(ValueError):
            plugin.tools["homelab_ops_run"][2]({
                "host": "hermes", "action": "run-approved-restore",
            })
        plugin.tools["homelab_ops_run"][2]({
            "host": "nextcloud", "action": "run-approved-restore",
            "confirmation_id": "root-issued-confirmation-reference-1234",
        })
        write_call = [row for row in runtime.authority.calls if row[0] == "perform"][-1][1]
        self.assertEqual(write_call["operation"], "host.write")
        self.assertEqual(json.loads(write_call["payload"])["action"], "run-approved-restore")

    def test_fresh_authority_denial_happens_before_root_effect_dispatch(self):
        authority = _Authority(deny=True)
        runtime, plugin = _runtime("homelab-ops-broker", authority), _PluginContext()
        HOMELAB_OPS_BROKER_IMPLEMENTATION.register(plugin, runtime)
        with self.assertRaisesRegex(PermissionError, "System check denied"):
            plugin.tools["homelab_ops_run"][2]({
                "host": "hermes", "action": "restart-approved-service",
            })
        self.assertFalse(any(name == "perform" for name, _ in authority.calls))

    def test_plugin_identity_and_version_are_checked_before_tool_registration(self):
        for implementation, plugin_id in (
            (AUTHENTIK_AUTHORIZATION_IMPLEMENTATION, "authentik-authorization"),
            (CLOUDFLARE_HOMELAB_IMPLEMENTATION, "cloudflare-homelab"),
            (HOMELAB_OPS_BROKER_IMPLEMENTATION, "homelab-ops-broker"),
        ):
            bad = _runtime(plugin_id)
            object.__setattr__(bad.identity, "version", "9.9.9")
            with self.assertRaisesRegex(RuntimeError, "pinned v1.0.0"):
                implementation.register(_PluginContext(), bad)


if __name__ == "__main__":
    unittest.main()
