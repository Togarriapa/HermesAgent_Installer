"""Contract tests for Resources runtime effects and failure boundaries (RB-T02/RB-T05)."""
import hashlib
import hmac
import json
import tempfile
import threading
import time
from contextlib import closing
from types import ModuleType
import unittest
from pathlib import Path
import base64
from unittest.mock import patch

from hermes_installer.registry.resources_runtime import (
    FixedResourceEffect,
    HermesProfileExecutionTarget,
    NativePluginRuntimeContext,
    ReviewedPluginAdapterRegistry,
    PluginAdapterUnavailable,
    ResourceIdentity,
    ResourceOverlayStore,
    ReplayStoreFull,
    SelectedResourceExecution,
    SelectedResourceRegistry,
    ResourceRuntimeError,
    WebhookVerifier,
    SQLiteReplayStore,
    create_native_plugin_handler,
    build_selected_resource_effect_handlers,
    selected_resource_effect_blockers,
    invoke_channel_route,
    invoke_fixed_resource_effect,
    invoke_internal_bundle_recruitment,
    invoke_scheduled_profile_run,
    invoke_webhook_delivery,
    materialize_runtime_resource,
    _verified_installed_resource_bundle,
)
from hermes_installer.registry.source import load_bundled_source
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

    def test_native_plugin_voice_enrollment_is_only_an_opaque_bounded_reference(self):
        context, _ = self._context()
        self.assertIsNone(context.voice_session_enrollment_id)
        selected = NativePluginRuntimeContext(
            identity=context.identity, declared_capabilities=(), authority=context.authority,
            invocation_contexts=context.invocation_contexts,
            selected_adapters=context.selected_adapters,
            voice_session_enrollment_id="voice-device-gen-4",
        )
        self.assertEqual(selected.voice_session_enrollment_id, "voice-device-gen-4")
        with self.assertRaises(ValueError):
            NativePluginRuntimeContext(
                identity=context.identity, declared_capabilities=(), authority=context.authority,
                invocation_contexts=context.invocation_contexts,
                selected_adapters=context.selected_adapters,
                voice_session_enrollment_id="../../raw/device/path",
            )

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
        with self.assertRaisesRegex(ResourceRuntimeError, "signature header name"):
            WebhookVerifier(_ReplayStore()).verify(
                "example", {**spec, "authentication": {"type": "hmac-sha256", "signatureHeader": "X-Bad\r\nHeader"}},
                {}, body, secret,
            )
        headers = {"Content-Type": "application/json", "X-Signature": signature, "X-Delivery": "d-1"}
        verifier = WebhookVerifier(_ReplayStore(), now=lambda: 100.0)
        receipt = verifier.verify("example", spec, headers, body, secret)
        self.assertEqual(receipt.body_sha256, hashlib.sha256(body).hexdigest())
        with self.assertRaisesRegex(ResourceRuntimeError, "duplicate"):
            verifier.verify("example", spec, headers, body, secret)
        with self.assertRaisesRegex(ResourceRuntimeError, "identity header is missing"):
            verifier.verify("example", spec, {key: value for key, value in headers.items() if key != "X-Delivery"}, body, secret)
        with self.assertRaises(ResourceRuntimeError):
            verifier.verify("example", spec, {**headers, "X-Signature": "sha256=" + "0" * 64}, body, secret)

        # The source catalog's registry-update notice stores the bounded
        # delivery-ID policy under `policy`, not `replayProtection`.
        policy_spec = {
            "path": "/hooks/registry/update", "method": "POST",
            "authentication": {"type": "hmac-sha256", "signatureHeader": "X-Signature"},
            "action": {"type": "registry-update-assessment", "mutate": False},
            "policy": {
                "authorityFromWebhookReceipt": "deny",
                "deliveryIdHeader": "X-Delivery", "deduplicateByDeliveryId": True,
            },
        }
        policy_signature = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
        policy_receipt = WebhookVerifier(_ReplayStore(), now=lambda: 101.0).verify(
            "registry-update-notice", policy_spec,
            {"Content-Type": "application/json", "X-Signature": policy_signature, "X-Delivery": "d-2"},
            body, secret,
        )
        self.assertEqual(policy_receipt.event_id, "d-2")

    def test_durable_webhook_replay_store_survives_restart_and_fails_closed_when_full(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            store_path = root / "replay.sqlite3"
            store = SQLiteReplayStore(store_path, max_entries=1)
            self.assertTrue(store.claim("example", "delivery-1", time.time() + 60))
            self.assertFalse(SQLiteReplayStore(store_path, max_entries=1).claim(
                "example", "delivery-1", time.time() + 60
            ))
            with self.assertRaises(ReplayStoreFull):
                store.claim("example", "delivery-2", time.time() + 60)
            # The private database persists only a digest of the resource/event pair.
            import sqlite3
            with closing(sqlite3.connect(store_path)) as db:
                raw = " ".join(str(value) for row in db.execute("SELECT * FROM replay_claims") for value in row)
            self.assertNotIn("delivery-1", raw)

    def test_durable_webhook_replay_claim_prunes_expired_rows_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            store = SQLiteReplayStore(root / "replay.sqlite3", max_entries=1)
            with patch("hermes_installer.registry.resources_runtime.time.time", return_value=100.0):
                self.assertTrue(store.claim("example", "expired", 101.0))
            with patch("hermes_installer.registry.resources_runtime.time.time", return_value=102.0):
                self.assertTrue(store.claim("example", "current", 103.0))

    def test_durable_webhook_replay_claim_is_atomic_across_ingress_workers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "replay.sqlite3"
            stores = [SQLiteReplayStore(path, max_entries=4) for _ in range(2)]
            gate = threading.Barrier(2)
            results = []

            def claim(store):
                gate.wait(timeout=2)
                results.append(store.claim("example", "same-delivery", time.time() + 60))

            workers = [threading.Thread(target=claim, args=(store,)) for store in stores]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=4)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual(sorted(results), [False, True])

    def test_durable_webhook_replay_store_rejects_unprivate_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            with self.assertRaisesRegex(ResourceRuntimeError, "private"):
                SQLiteReplayStore(root / "replay.sqlite3")

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

    def test_reviewed_plugin_handler_is_not_emitted_as_hermes_discovery_asset(self):
        artifact = materialize_runtime_resource(
            "plugins", "resource-overlay-store", "1.0.0",
            "plugins/resource-overlay-store.yaml", {"name": "resource-overlay-store"},
            {}, "a" * 40, "2.3.1",
        )
        self.assertEqual(artifact.adapter_id, "resource-overlay-store")
        self.assertIsNone(artifact.native_path)
        self.assertEqual(artifact.files, {})
        self.assertFalse(artifact.readiness.materialized)
        self.assertTrue(any("PluginContext loader" in blocker for blocker in artifact.blockers))

    def test_selected_cron_handler_delegates_only_the_pinned_profile_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = root / "resources/vendor/hermes-agent-resources-2.3.1"
            bundle.mkdir(parents=True)
            # Stage the exact package-data snapshot into the selected immutable
            # artifact root. The runtime must not read the source checkout tree.
            with patch("urllib.request.urlopen", side_effect=AssertionError("network access")):
                pinned = load_bundled_source()
            for relative, content in pinned.files.items():
                path = bundle / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                path.chmod(pinned.file_modes[relative])
            revision = pinned.revision
            identity = ResourceIdentity("daily-review", "crons", "1.0.0", "crons/daily-review.yaml", revision, "b" * 64)
            spec = {
                "schedule": "0 1 * * *", "timezone": "UTC",
                "action": {
                    "type": "installer-resource-candidate-assessment", "mode": "candidate-assessment",
                    "profile": "hermes", "source": {
                        "kind": "installer-bundle", "catalogVersion": "2.3.1",
                        "path": "resources/vendor/hermes-agent-resources-2.3.1", "revision": revision,
                    },
                },
                "requires": {"profiles": ["hermes"]},
                "runtime": {"engine": "hermes-cron", "profileSelection": "registry-action-profile"},
                "policy": {"authorityFromSchedule": "deny", "staticRecipientListAsAuthority": "deny"},
            }
            selected = SelectedResourceExecution(
                identity=identity, generation_digest="c" * 64, effective_spec=spec,
                capability="resource.cron.run", target="resource:crons/daily-review@1.0.0",
                operation="resource.cron.run", recipient=None, delegation_id="cron-to-profile",
                profile_id="hermes", enabled=True,
            )
            # Root-owned action data cannot be mutated after selection.
            spec["action"]["mode"] = "changed"
            with self.assertRaises(TypeError):
                selected.effective_spec["action"]["mode"] = "changed"

            executable = root / "venv/bin/hermes"
            executable.parent.mkdir(parents=True)
            executable.write_text("fixture", encoding="utf-8")
            data_root = root / "profiles/hermes"
            data_root.mkdir(parents=True)
            target = HermesProfileExecutionTarget(
                profile_id="hermes", executable=executable,
                artifact_sha256="d" * 64, artifact_root=root, cwd=root,
                data_root=data_root, env_allowlist={"PATH": "/usr/bin"},
                child_artifact_refs={"artifact:resources:" + "e" * 64: "e" * 64},
            )
            class Profiles:
                def resolve_profile(self, profile_id):
                    return target if profile_id == "hermes" else None

            class Service:
                def __init__(self):
                    self.call = None
                def perform_delegated_effect(self, authorization, **kwargs):
                    self.call = (authorization, kwargs)
                    return {"status": "accepted"}

            service = Service()
            handlers = build_selected_resource_effect_handlers(
                selected_resources=SelectedResourceRegistry((selected,)),
                profile_targets=Profiles(), authority_service=service,
            )
            blockers = selected_resource_effect_blockers(
                SelectedResourceRegistry((selected,)), profile_targets=Profiles(),
            )
            self.assertIn("protected timer event issuer", blockers[(selected.operation, selected.target)])
            handler = handlers[(selected.operation, selected.target)]
            request = {"profile_id": "hermes", "scheduled_for": "2026-10-10T01:00:00Z"}
            payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
            authorization = type("Authorization", (), {
                "target": selected.target, "capability": selected.capability,
                "recipient": None, "request_digest": hashlib.sha256(payload).hexdigest(),
            })()

            authority_package = ModuleType("hermes_installer.authority")
            authority_package.__path__ = []
            authority_package.canonical_bytes = lambda value: json.dumps(
                value, sort_keys=True, separators=(",", ":"), default=str,
            ).encode()
            authority_client = ModuleType("hermes_installer.authority.client")
            authority_client.canonical_profile_target = lambda *args: "profile:hermes"
            def launch_envelope(**kwargs):
                return {
                    "target": kwargs["target"], "profile_id": kwargs["profile_id"],
                    "executable": str(kwargs["executable"].resolve()),
                    "artifact_sha256": kwargs["artifact_sha256"],
                    "artifact_root": str(kwargs["artifact_root"].resolve()),
                    "cwd": str(kwargs["cwd"].resolve()),
                    "data_root": str(kwargs["data_root"].resolve()),
                    "argv": list(kwargs["argv"]), "env_allowlist": dict(kwargs["env_allowlist"]),
                    "child_artifact_refs": dict(kwargs["child_artifact_refs"]),
                    "max_lifetime_seconds": kwargs["max_lifetime_seconds"],
                    "max_output_bytes": kwargs["max_output_bytes"],
                    "stdin_mode": kwargs["stdin_mode"],
                }
            authority_client.profile_launch_envelope = launch_envelope
            authority_package.client = authority_client
            with patch.dict("sys.modules", {
                "hermes_installer.authority": authority_package,
                "hermes_installer.authority.client": authority_client,
            }):
                result = handler(
                    context=object(), authorization=authorization, payload=payload,
                    timeout=60.0, peer_pid=123, cancelled=lambda: False,
                )
            self.assertEqual(result, {"status": "accepted"})
            self.assertEqual(service.call[1]["delegation_id"], "cron-to-profile")
            launch = json.loads(service.call[1]["payload"])
            self.assertEqual(launch["profile_id"], "hermes")
            self.assertEqual(launch["target"], "profile:hermes")
            self.assertEqual(launch["argv"][:3], [str(executable.resolve()), "-p", "hermes"])
            self.assertIn("Assess only the installer-owned", launch["argv"][4])
            self.assertIn(str(bundle.resolve()), launch["argv"][4])
            self.assertEqual(launch["child_artifact_refs"], target.child_artifact_refs)
            self.assertEqual(service.call[1]["peer_pid"], 123)
            self.assertLessEqual(service.call[1]["timeout"], 600.0)

            spoofed = {"profile_id": "other", "scheduled_for": "2026-10-10T01:00:00Z"}
            spoofed_bytes = json.dumps(spoofed, sort_keys=True, separators=(",", ":")).encode()
            spoofed_authorization = type("Authorization", (), {
                "target": selected.target, "capability": selected.capability,
                "recipient": None, "request_digest": hashlib.sha256(spoofed_bytes).hexdigest(),
            })()
            with self.assertRaisesRegex(ResourceRuntimeError, "differs from root selection"):
                handler(context=object(), authorization=spoofed_authorization, payload=spoofed_bytes,
                        timeout=60.0, peer_pid=123, cancelled=lambda: False)
            self.assertEqual(json.loads(service.call[1]["payload"]), launch)

    def test_candidate_assessment_rejects_partial_or_unpinned_bundle_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = root / "resources/vendor/hermes-agent-resources-2.3.1"
            bundle.mkdir(parents=True)
            target = HermesProfileExecutionTarget(
                profile_id="hermes", executable=root / "hermes",
                artifact_sha256="d" * 64, artifact_root=root, cwd=root,
                data_root=root / "profiles/hermes", env_allowlist={"PATH": "/usr/bin"},
            )
            pinned = load_bundled_source()
            source = {
                "catalogVersion": pinned.catalog_version,
                "revision": pinned.revision,
                "path": "resources/vendor/hermes-agent-resources-" + pinned.catalog_version,
            }
            with self.assertRaisesRegex(ResourceRuntimeError, "complete pinned Resources snapshot"):
                _verified_installed_resource_bundle(target, source)

    def test_selected_cron_without_reviewed_action_has_exact_pending_reason(self):
        identity = ResourceIdentity("sync", "crons", "1.0.0", "crons/sync.yaml", "a" * 40, "b" * 64)
        selected = SelectedResourceExecution(
            identity=identity, generation_digest="c" * 64,
            effective_spec={"action": {"type": "profile-run", "mode": "registry-update-check"}},
            capability="resource.cron.run", target="resource:crons/sync@1.0.0",
            operation="resource.cron.run", recipient=None, delegation_id="cron-to-profile",
            profile_id="hermes", enabled=True,
        )
        registry = SelectedResourceRegistry((selected,))
        self.assertEqual(registry.generation_digest, "c" * 64)
        key = (selected.operation, selected.target)
        self.assertNotIn(key, build_selected_resource_effect_handlers(
            selected_resources=registry, profile_targets=object(), authority_service=object(),
        ))
        self.assertIn("no reviewed local Hermes execution recipe",
                      selected_resource_effect_blockers(registry)[key])
        with self.assertRaisesRegex(ValueError, "active generation"):
            SelectedResourceRegistry((selected,), expected_generation_digest="d" * 64)

    def test_candidate_assessment_blocker_names_missing_full_packaged_source_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = root / "resources/vendor/hermes-agent-resources-2.3.1"
            bundle.mkdir(parents=True)
            pinned = load_bundled_source()
            target = HermesProfileExecutionTarget(
                profile_id="hermes", executable=root / "venv/bin/hermes",
                artifact_sha256="d" * 64, artifact_root=root, cwd=root,
                data_root=root / "profiles/hermes", env_allowlist={"PATH": "/usr/bin"},
            )
            class Profiles:
                def resolve_profile(self, profile_id):
                    return target if profile_id == "hermes" else None

            identity = ResourceIdentity(
                "resource-sync", "crons", "1.0.0", "crons/resource-sync.yaml",
                pinned.revision, "b" * 64,
            )
            selected = SelectedResourceExecution(
                identity=identity, generation_digest="c" * 64,
                effective_spec={
                    "schedule": "0 1 * * *", "timezone": "UTC",
                    "action": {
                        "type": "installer-resource-candidate-assessment",
                        "mode": "candidate-assessment", "profile": "hermes",
                        "source": {
                            "kind": "installer-bundle", "path": "resources/vendor/hermes-agent-resources-2.3.1",
                            "catalogVersion": pinned.catalog_version, "revision": pinned.revision,
                        },
                    },
                    "requires": {"profiles": ["hermes"]},
                    "runtime": {"engine": "hermes-cron", "profileSelection": "registry-action-profile"},
                    "policy": {"authorityFromSchedule": "deny", "staticRecipientListAsAuthority": "deny"},
                },
                capability="resource.cron.run", target="resource:crons/resource-sync@1.0.0",
                operation="resource.cron.run", recipient=None, delegation_id="cron-to-profile",
                profile_id="hermes", enabled=True,
            )
            reason = selected_resource_effect_blockers(
                SelectedResourceRegistry((selected,)), profile_targets=Profiles(),
            )[(selected.operation, selected.target)]
            self.assertIn("complete pinned Resources snapshot", reason)
            self.assertIn("stage the verified package-data bundle", reason)

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
            for relative in (
                "resource-overlays", "resource-overlays/hermes",
                "resource-overlays/hermes/record-1",
                "resource-overlays/hermes/record-1/revisions",
            ):
                info = (owned.root / relative).stat()
                self.assertEqual(info.st_uid, __import__("os").getuid())
                self.assertEqual(info.st_mode & 0o077, 0, relative)

    def test_overlay_registry_adapter_registers_and_invokes_real_profile_store(self):
        import base64

        with tempfile.TemporaryDirectory() as temp:
            owned = OwnedRoot(Path(temp) / "installer")
            owned.ensure()
            store = ResourceOverlayStore(owned, Journal(owned.path("state.sqlite3")))
            authority = _FakeAuthority()
            runtime = NativePluginRuntimeContext(
                identity=ResourceIdentity(
                    "resource-overlay-store", "plugins", "1.0.1", "plugins/resource-overlay-store.yaml",
                    "a" * 40, "b" * 64,
                ),
                declared_capabilities=("overlay.read", "overlay.write"),
                authority=authority,
                invocation_contexts=lambda **_: ("host-lineage",),
                selected_adapters=ReviewedPluginAdapterRegistry(),
                local_overlay_store=store.for_profile("hermes"),
            )

            class PluginContext:
                def __init__(self):
                    self.tools = {}

                def register_tool(self, *, name, schema, handler, **kwargs):
                    self.tools[name] = handler

            plugin = PluginContext()
            create_native_plugin_handler("resource-overlay-store", runtime)(plugin)
            write = plugin.tools["resource_overlay_write"]
            read = plugin.tools["resource_overlay_read"]
            history = plugin.tools["resource_overlay_history"]
            delete = plugin.tools["resource_overlay_delete"]
            first = write({"record_id": "memory-1", "value_base64": base64.b64encode(b"private").decode()})
            self.assertEqual(read({"record_id": "memory-1"})["value_base64"], base64.b64encode(b"private").decode())
            self.assertEqual(history({"record_id": "memory-1"})["revisions"], [first["revision"]])
            tombstone = delete({"record_id": "memory-1", "expected_revision": first["revision"]})
            self.assertEqual(len(tombstone["deleted_revision"]), 64)
            self.assertFalse(read({"record_id": "memory-1"})["found"])

    def test_overlay_read_refuses_expanded_parent_permissions(self):
        import os

        with tempfile.TemporaryDirectory() as temp:
            owned = OwnedRoot(Path(temp) / "installer")
            owned.ensure()
            store = ResourceOverlayStore(owned, Journal(owned.path("state.sqlite3")))
            view = store.for_profile("hermes")
            view.write("record-1", b"private", expected_revision=None)
            parent = owned.root / "resource-overlays/hermes"
            os.chmod(parent, 0o755)
            with self.assertRaisesRegex(ResourceRuntimeError, "unsafe ownership or permissions"):
                view.read("record-1")

    def test_reviewed_plugin_registry_runs_overlay_tools_against_scoped_store(self):
        """Prove the resolver returns an executable adapter over the real CAS store."""
        from hermes_installer.components.native_plugins import create_native_plugin_handler

        with tempfile.TemporaryDirectory() as temp:
            owned = OwnedRoot(Path(temp) / "installer")
            owned.ensure()
            store = ResourceOverlayStore(owned, Journal(owned.path("state.sqlite3")))
            identity = ResourceIdentity(
                "resource-overlay-store", "plugins", "1.0.1", "plugins/resource-overlay-store.yaml",
                "a" * 40, "b" * 64,
            )
            context = NativePluginRuntimeContext(
                identity=identity, declared_capabilities=(), authority=object(),
                invocation_contexts=lambda **_: (),
                selected_adapters=ReviewedPluginAdapterRegistry(),
                local_overlay_store=store.for_profile("hermes"),
            )

            class PluginContext:
                def __init__(self):
                    self.tools = {}

                def register_tool(self, *, name, toolset, schema, handler, **kwargs):
                    self.tools[name] = handler

            plugin = PluginContext()
            create_native_plugin_handler("resource-overlay-store", context)(plugin)
            self.assertEqual(set(plugin.tools), {
                "resource_overlay_read", "resource_overlay_write",
                "resource_overlay_history", "resource_overlay_delete",
            })
            first = plugin.tools["resource_overlay_write"]({
                "record_id": "source-proof", "value_base64": base64.b64encode(b"durable").decode(),
            })
            self.assertTrue(plugin.tools["resource_overlay_read"]({"record_id": "source-proof"})["found"])
            with self.assertRaisesRegex(ResourceRuntimeError, "compare-and-swap"):
                plugin.tools["resource_overlay_write"]({
                    "record_id": "source-proof", "value_base64": base64.b64encode(b"stale").decode(),
                    "expected_revision": "0" * 64,
                })
            self.assertEqual(plugin.tools["resource_overlay_history"]({"record_id": "source-proof"})["revisions"], [first["revision"]])


if __name__ == "__main__":
    unittest.main()
