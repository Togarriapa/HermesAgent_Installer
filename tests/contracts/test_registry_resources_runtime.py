"""Contract tests for Resources runtime effects and failure boundaries (RB-T02/RB-T05)."""
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from hermes_installer.registry.resources_runtime import (
    FixedResourceEffect,
    NativePluginRuntimeContext,
    PluginAdapterUnavailable,
    ResourceIdentity,
    ResourceOverlayStore,
    ResourceRuntimeError,
    WebhookVerifier,
    create_native_plugin_handler,
    invoke_channel_route,
    invoke_fixed_resource_effect,
    invoke_internal_bundle_recruitment,
    invoke_scheduled_profile_run,
    invoke_webhook_delivery,
    materialize_runtime_resource,
)
from hermes_installer.state import Journal, OwnedRoot


class _FakeAuthority:
    def __init__(self):
        self.calls = []
        self.response = object()

    def context(self, **kwargs):
        self.calls.append(("context", kwargs))
        return "signed-fresh-context"

    def authorize_effect(self, context, **kwargs):
        self.calls.append(("authorize", context, kwargs))
        return "single-use-grant"

    def verify_effect(self, grant, context, **kwargs):
        self.calls.append(("verify", grant, context, kwargs))

    def perform_effect(self, grant, **kwargs):
        self.calls.append(("perform", grant, kwargs))
        return self.response


class _ReplayStore:
    def __init__(self):
        self.ids = set()

    def claim(self, resource_id, event_id, expires_at):
        key = (resource_id, event_id)
        if key in self.ids:
            return False
        self.ids.add(key)
        return True


class _NoPluginAdapters:
    def resolve_plugin_adapter(self, adapter_id):
        return None


class ResourcesRuntimeTests(unittest.TestCase):
    def _context(self, *, kind="plugins", name="fixture"):
        authority = _FakeAuthority()
        context = NativePluginRuntimeContext(
            identity=ResourceIdentity(name, kind, "1.0.0", f"{kind}/{name}.yaml", "a" * 40, "b" * 64),
            declared_capabilities=("declared-only",), authority=authority,
            invocation_contexts=lambda **kw: ("root-issued-source-lineage",),
            selected_adapters=_NoPluginAdapters(),
        )
        return context, authority

    def test_fixed_effect_gets_fresh_source_lineage_and_one_bound_grant(self):
        context, authority = self._context()
        effect = FixedResourceEffect("test.capability", "resource:plugins/fixture@1.0.0", None, "provider.dispatch")
        response = invoke_fixed_resource_effect(
            context, effect, {"message": "bounded"}, intent="test operation", retry_index=1,
        )
        self.assertIs(response, authority.response)
        self.assertEqual([call[0] for call in authority.calls], ["context", "authorize", "verify", "perform"])
        self.assertEqual(authority.calls[0][1]["source_contexts"], ("root-issued-source-lineage",))
        grant_args = authority.calls[1][2]
        self.assertEqual(grant_args["retry_index"], 1)
        self.assertEqual(grant_args["request_digest"], hashlib.sha256(
            json.dumps({"message": "bounded"}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest())
        self.assertEqual(authority.calls[3][2]["operation"], "provider.dispatch")

    def test_effect_rejects_target_spoof_before_authority_call(self):
        context, authority = self._context()
        effect = FixedResourceEffect("test.capability", "resource:plugins/other@1.0.0", None, "provider.dispatch")
        with self.assertRaises(ResourceRuntimeError):
            invoke_fixed_resource_effect(context, effect, {}, intent="test")
        self.assertEqual(authority.calls, [])

    def test_channel_cron_and_webhook_are_typed_fixed_hermes_operations(self):
        channel, channel_auth = self._context(kind="channels", name="discord")
        channel_effect = FixedResourceEffect("channel.route", "resource:channels/discord@1.0.0", None, "resource.channel.route")
        invoke_channel_route(channel, channel_effect, direction="inbound", conversation_id="c-1", content="hi", intent="inbound")
        payload = channel_auth.calls[-1][2]["payload"]
        self.assertIn(b'"profile_id":"hermes"', payload)
        self.assertEqual(channel_auth.calls[0][1]["purpose"], "native-hermes-channel")

        cron, cron_auth = self._context(kind="crons", name="daily")
        cron_effect = FixedResourceEffect("cron.run", "resource:crons/daily@1.0.0", None, "resource.cron.run")
        invoke_scheduled_profile_run(cron, cron_effect, profile_id="hermes", scheduled_for="2026-10-09T12:00:00Z", intent="scheduled")
        self.assertEqual(cron_auth.calls[0][1]["purpose"], "native-hermes-cron")

        webhook, webhook_auth = self._context(kind="webhooks", name="hook")
        receipt = type("Receipt", (), {
            "resource_id": "hook", "event_id": "event-1", "event_type": "push",
            "body": b'{"x":1}', "body_sha256": hashlib.sha256(b'{"x":1}').hexdigest(), "received_at": 1.0,
        })()
        webhook_effect = FixedResourceEffect("webhook.deliver", "resource:webhooks/hook@1.0.0", None, "resource.webhook.deliver")
        invoke_webhook_delivery(webhook, webhook_effect, receipt, intent="verified webhook")
        self.assertEqual(webhook_auth.calls[0][1]["purpose"], "native-hermes-webhook")

    def test_bundle_recruitment_cannot_escape_resolved_roster(self):
        context, authority = self._context(kind="bundles", name="research-agent")
        effect = FixedResourceEffect("bundle.recruit", "resource:bundles/research-agent@1.0.0", None, "resource.orchestrator.recruit")
        with self.assertRaisesRegex(ResourceRuntimeError, "outside the resolved"):
            invoke_internal_bundle_recruitment(
                context, effect, request_id="0123456789abcdef", user_request="research",
                resolved_roster=("researcher",), selected_roster=("administrator",), intent="work request",
            )
        self.assertEqual(authority.calls, [])

    def test_webhook_authentication_and_replay_claim_precede_dispatch(self):
        secret = b"s" * 32
        body = b'{"action":"read-only"}'
        signature = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
        spec = {
            "path": "/hooks/example", "method": "POST",
            "authentication": {"type": "hmac-sha256", "signatureHeader": "X-Signature"},
            "action": {"type": "repository-change-review", "mutate": False},
            "replayProtection": {"deliveryIdHeader": "X-Delivery"},
            "policy": {"authorityFromWebhookReceipt": "deny"},
        }
        headers = {"Content-Type": "application/json", "X-Signature": signature, "X-Delivery": "d-1"}
        verifier = WebhookVerifier(_ReplayStore(), now=lambda: 100.0)
        receipt = verifier.verify("example", spec, headers, body, secret)
        self.assertEqual(receipt.body_sha256, hashlib.sha256(body).hexdigest())
        with self.assertRaisesRegex(ResourceRuntimeError, "duplicate"):
            verifier.verify("example", spec, headers, body, secret)
        with self.assertRaises(ResourceRuntimeError):
            verifier.verify("example", spec, {**headers, "X-Signature": "sha256=" + "0" * 64}, body, secret)

    def test_cron_and_channel_fail_closed_on_missing_policy(self):
        with self.assertRaisesRegex(ResourceRuntimeError, "authority"):
            materialize_runtime_resource("crons", "daily", "1.0.0", "crons/daily.yaml", {}, {
                "schedule": "0 1 * * *", "timezone": "UTC", "action": {"type": "profile-run", "profile": "worker"},
                "requires": {"profiles": ["worker"]}, "runtime": {"engine": "hermes-cron", "profileSelection": "registry-action-profile"},
                "policy": {"staticRecipientListAsAuthority": "deny"},
            }, "a" * 40, "2.3.1")
        with self.assertRaisesRegex(ResourceRuntimeError, "route through Hermes"):
            materialize_runtime_resource("channels", "web", "1.0.0", "channels/web.yaml", {}, {
                "adapter": "http", "routing": {"inboundProfile": "worker", "outboundProfile": "hermes", "allowDirectProfileSelection": False},
                "policy": {"requireHermesGateway": True, "rejectNonHermesProfileTarget": True},
            }, "a" * 40, "2.3.1")

    def test_unavailable_plugin_handler_does_not_register_fake_tools(self):
        context, _ = self._context()
        with self.assertRaises(PluginAdapterUnavailable):
            create_native_plugin_handler("fixture", context)

    def test_profile_overlay_is_private_cas_and_soft_delete(self):
        with tempfile.TemporaryDirectory() as temp:
            owned = OwnedRoot(Path(temp) / "installer")
            owned.ensure()
            store = ResourceOverlayStore(owned, Journal(owned.path("state.sqlite3")))
            view = store.for_profile("hermes")
            first = view.write("record-1", b"private", expected_revision=None)
            self.assertEqual(view.read("record-1").value, b"private")
            self.assertEqual(view.history("record-1"), (first,))
            with self.assertRaisesRegex(ResourceRuntimeError, "compare-and-swap"):
                view.write("record-1", b"stale", expected_revision=None)
            tombstone = view.delete("record-1", expected_revision=first)
            self.assertIsNone(view.read("record-1"))
            self.assertEqual(set(view.history("record-1")), {first, tombstone})
            self.assertEqual((owned.root / "resource-overlays/hermes/record-1/current.json").stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
