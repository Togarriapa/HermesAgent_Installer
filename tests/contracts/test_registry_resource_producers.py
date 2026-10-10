"""Root-selected webhook route authentication and replay tests."""
from __future__ import annotations

import hashlib
import hmac
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
import pytest

from hermes_installer.registry.resource_producers import (
    AuthenticatedChannelIngress,
    CronTickObservation,
    ResourceObservationError,
    CronOccurrenceStore,
    RootSelectedCronProducer,
    RootSelectedResourceScheduler,
    SelectedWebhookIngress,
    WebhookRequestObservation,
    build_selected_webhook_protocol_schema_resolver,
)
from hermes_installer.registry.resources_runtime import (
    ResourceIdentity, SelectedResourceExecution, SelectedResourceRegistry,
)


class _ReplayStore:
    def __init__(self):
        self.seen = set()

    def claim(self, resource_id, event_id, expires_at):
        key = (resource_id, event_id)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


class _Bindings:
    def __init__(self, binding):
        self.binding = binding
        self.calls = []

    def resolve_resource_credential_binding(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.binding


class _Vault:
    def __init__(self, secret):
        self.secret = secret
        self.calls = []

    def resolve_reference(self, reference, **kwargs):
        self.calls.append((reference, kwargs))
        return self.secret


class SelectedWebhookIngressTests(unittest.TestCase):
    def _ingress(self, *, replay_store=None):
        resource_generation = "a" * 64
        service_generation = "c" * 64
        secret = "s" * 32
        effective_spec = {
            "path": "/hooks/github/push", "method": "POST",
            "authentication": {"type": "hmac-sha256",
                                "signatureHeader": "X-Hub-Signature-256",
                                "secret": "${GITHUB_WEBHOOK_SECRET}"},
                "event": {"header": "X-GitHub-Event", "allowed": ["push"]},
                "replayProtection": {"deliveryIdHeader": "X-GitHub-Delivery"},
                "action": {"type": "repository-change-review", "mutate": False},
                "policy": {"authorityFromWebhookReceipt": "deny"},
        }
        selected = SelectedResourceExecution(
            identity=ResourceIdentity(
                "github-push", "webhooks", "1.0.1", "webhooks/github-push.yaml",
                "b" * 40, "d" * 64,
            ),
            generation_digest=resource_generation,
            effective_spec=effective_spec,
            capability="resource.webhook.run",
            target="resource:webhooks/github-push@1.0.1",
            operation="resource.webhook.deliver", recipient=None,
            delegation_id="selected-webhook-route", profile_id="hermes", enabled=True,
        )
        registry = SelectedResourceRegistry((selected,), expected_generation_digest=resource_generation)
        backend = SimpleNamespace(
            backend_id="backend-github-push", resource_id="github-push", profile_id="hermes",
            generation=resource_generation, observer_enrollment_id="observer-github-push",
            scope_binding_id="scope-github-push",
            credential_reference_ids=frozenset({"credential-github-push"}),
        )
        enrollment = SimpleNamespace(
            resource_id="github-push", kind="webhooks", selected_enabled=True,
            generation=resource_generation, profile_id="hermes", profile_generation="e" * 64,
            principal_id="principal-hermes", observer_enrollment_id="observer-github-push",
            source_issuer_channel_id="issuer-github-push",
            max_payload_bytes=1_048_576,
            backends={backend.backend_id: backend},
            nodes=(SimpleNamespace(backend_enrollment_id=backend.backend_id),),
            scope_bindings={backend.scope_binding_id: SimpleNamespace(
                backend_enrollment_id=backend.backend_id,
                fixed_fields={"github_repository_id": 1234,
                              "github_repository_full_name": "example/project"},
            )},
        )
        binding = SimpleNamespace(credential_reference_id="credential-github-push")
        bindings, vault = _Bindings(binding), _Vault(secret)
        bindings.enrollment_catalog = SimpleNamespace(digest=service_generation)
        ingress = SelectedWebhookIngress(
            selected_resources=registry,
            job_enrollments={("github-push", resource_generation): enrollment},
            bindings=bindings, credential_vault=vault,
            replay_store=replay_store or _ReplayStore(),
            service_generation_digest=service_generation,
        )
        return ingress, bindings, vault, secret

    def test_selected_hmac_route_resolves_exact_secret_and_claims_replay(self):
        ingress, bindings, vault, secret = self._ingress()
        body = (b'{"ref":"refs/heads/main","before":"' + b"a" * 40
                + b'","after":"' + b"b" * 40
                + b'","repository":{"id":1234,"full_name":"example/project"}}')
        signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers = (
            ("Content-Type", "application/json"),
            ("X-Hub-Signature-256", signature),
            ("X-GitHub-Event", "push"),
            ("X-GitHub-Delivery", "delivery-1"),
        )
        receipt = ingress.accept_request("POST", "/hooks/github/push", headers, body)
        self.assertEqual(receipt.resource_id, "github-push")
        self.assertEqual(receipt.raw_payload, body)
        self.assertEqual(receipt.event_data["repository"]["id"], 1234)
        self.assertEqual(len(receipt.replay_key_sha256), 64)
        self.assertEqual(ingress._replay_store.seen, {("github-push", receipt.replay_key_sha256)})
        with self.assertRaises(TypeError):
            receipt.event_data["ref"] = "refs/heads/attacker"
        self.assertEqual(ingress.routes, ("/hooks/github/push",))
        self.assertEqual(bindings.calls[0][0], (
            "backend-github-push", "${GITHUB_WEBHOOK_SECRET}", "webhook-hmac-verify",
        ))
        self.assertEqual(bindings.calls[0][1]["service_generation_digest"], "c" * 64)
        self.assertEqual(vault.calls[0], (
            "credential-github-push",
            {"peer_uid": 0, "required_scope": "webhook-hmac-verify", "principal_id": "principal-hermes"},
        ))
        with self.assertRaisesRegex(Exception, "duplicate"):
            ingress.accept_request("POST", "/hooks/github/push", headers, body)

    def test_bad_signature_wrong_route_duplicate_headers_and_nonpost_fail_closed(self):
        ingress, _bindings, _vault, _secret = self._ingress()
        body = (b'{"ref":"refs/heads/main","before":"' + b"a" * 40
                + b'","after":"' + b"b" * 40
                + b'","repository":{"id":1234,"full_name":"example/project"}}')
        headers = (
            ("Content-Type", "application/json"),
            ("X-Hub-Signature-256", "sha256=" + "0" * 64),
            ("X-GitHub-Event", "push"),
            ("X-GitHub-Delivery", "delivery-2"),
        )
        with self.assertRaisesRegex(Exception, "signature verification failed"):
            ingress.accept_request("POST", "/hooks/github/push", headers, body)
        with self.assertRaisesRegex(ResourceObservationError, "not selected"):
            ingress.accept_request("POST", "/hooks/other", headers, body)
        with self.assertRaisesRegex(ResourceObservationError, "not selected"):
            ingress.accept_request("GET", "/hooks/github/push", headers, body)
        with self.assertRaisesRegex(ResourceObservationError, "duplicate"):
            ingress.accept_request("POST", "/hooks/github/push", headers + (("content-type", "application/json"),), body)

    def test_unselected_repository_fails_before_durable_replay_claim(self):
        ingress, _bindings, _vault, secret = self._ingress()
        body = (b'{"ref":"refs/heads/main","before":"' + b"a" * 40
                + b'","after":"' + b"b" * 40
                + b'","repository":{"id":99,"full_name":"attacker/project"}}')
        headers = (
            ("Content-Type", "application/json"),
            ("X-Hub-Signature-256", "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()),
            ("X-GitHub-Event", "push"),
            ("X-GitHub-Delivery", "delivery-outside-scope"),
        )
        with self.assertRaisesRegex(ResourceObservationError, "outside the selected repository"):
            ingress.accept_request("POST", "/hooks/github/push", headers, body)
        self.assertEqual(ingress._replay_store.seen, set())

    def test_selected_protocol_schema_resolver_is_identity_and_generation_bound(self):
        ingress, _bindings, _vault, _secret = self._ingress()
        selected = ingress._selected_resources.rows[0]
        enrollment = ingress._job_enrollments[("github-push", selected.generation_digest)]
        resolve = build_selected_webhook_protocol_schema_resolver(
            ingress._selected_resources, ingress._job_enrollments,
        )
        self.assertEqual(resolve(
            "github-push", selected.generation_digest,
            enrollment.source_issuer_channel_id, "webhook-event",
        ), ("resource-github-push-v1",
            "3b27135572adf4392f85b0f37a8dcce0e18dbac2aba811462416807c5e4733c8"))
        with self.assertRaisesRegex(ResourceObservationError, "source issuer"):
            resolve("github-push", selected.generation_digest,
                    "attacker-issuer", "webhook-event")
        with self.assertRaises(ResourceObservationError):
            resolve("github-push", "f" * 64,
                    enrollment.source_issuer_channel_id, "webhook-event")


def test_cron_observation_requires_explicit_due_order_and_positive_sequence():
    tick = CronTickObservation(
        "daily-review", "schedule-1", 3,
        "2026-10-09T07:23:00+01:00", "2026-10-09T07:23:01+01:00",
    )
    assert tick.sequence == 3
    with pytest.raises(ResourceObservationError, match="cannot precede"):
        CronTickObservation(
            "daily-review", "schedule-1", 3,
            "2026-10-09T07:23:02+01:00", "2026-10-09T07:23:01+01:00",
        )
    with pytest.raises(ResourceObservationError, match="timezone-aware"):
        CronTickObservation("daily-review", "schedule-1", 1, "2026-10-09T07:23:00", "2026-10-09T07:23:01Z")


def test_cron_occurrence_store_is_durable_monotone_and_replay_bounded():
    with tempfile.TemporaryDirectory() as temporary:
        parent = Path(temporary)
        parent.chmod(0o700)
        database = parent / "cron.sqlite3"
        store = CronOccurrenceStore(database, max_entries=2)

        def key(due):
            return hashlib.sha256(json_bytes({
                "resource_id": "daily-review", "resource_generation": "a" * 64,
                "schedule_enrollment_id": "schedule-daily", "scheduled_time_unix": due,
            })).hexdigest()

        first = key(1_800_000_000)
        assert store.claim_occurrence(
            resource_id="daily-review", resource_generation="a" * 64,
            schedule_enrollment_id="schedule-daily", scheduled_time_unix=1_800_000_000,
            replay_key_sha256=first,
        ) == 1
        assert store.claim_occurrence(
            resource_id="daily-review", resource_generation="a" * 64,
            schedule_enrollment_id="schedule-daily", scheduled_time_unix=1_800_000_000,
            replay_key_sha256=first,
        ) is None

        reopened = CronOccurrenceStore(database, max_entries=2)
        second = key(1_800_000_060)
        assert reopened.claim_occurrence(
            resource_id="daily-review", resource_generation="a" * 64,
            schedule_enrollment_id="schedule-daily", scheduled_time_unix=1_800_000_060,
            replay_key_sha256=second,
        ) == 2
        with pytest.raises(ResourceObservationError, match="ledger is full"):
            reopened.claim_occurrence(
                resource_id="daily-review", resource_generation="a" * 64,
                schedule_enrollment_id="schedule-daily", scheduled_time_unix=1_800_000_120,
                replay_key_sha256=key(1_800_000_120),
            )


def test_root_scheduler_has_no_unselected_callback_surface():
    import inspect

    assert tuple(inspect.signature(RootSelectedCronProducer.tick).parameters) == ("self",)
    scheduler = RootSelectedResourceScheduler((), poll_seconds=1)
    assert scheduler.tick_once() == ()
    with pytest.raises(ResourceObservationError, match="selected cron producers"):
        RootSelectedResourceScheduler((object(),))


def json_bytes(value):
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def test_webhook_observation_preserves_raw_body_and_rejects_duplicate_headers():
    observation = WebhookRequestObservation.from_headers(
        "github-push", [("Content-Type", "application/json"), ("X-GitHub-Delivery", "delivery-1")], b"{}",
    )
    assert observation.body == b"{}"
    with pytest.raises(ResourceObservationError, match="duplicate"):
        WebhookRequestObservation.from_headers(
            "github-push", [("X-Signature", "one"), ("x-signature", "two")], b"{}",
        )
    with pytest.raises(ResourceObservationError, match="malformed"):
        WebhookRequestObservation("github-push", (("X-Header", "bad\rvalue"),), b"{}")


def test_channel_values_do_not_accept_boolean_authentication_claims():
    ingress = AuthenticatedChannelIngress(
        "telegram", "official-telegram", "account-binding", "event-1", "conversation-1", b"hello",
    )
    assert ingress.content == b"hello"
    with pytest.raises(TypeError):
        AuthenticatedChannelIngress(
            "telegram", "official-telegram", "account-binding", "event-1", "conversation-1", b"hello",
            authenticated=True,
        )
    with pytest.raises(ResourceObservationError, match="one MiB"):
        AuthenticatedChannelIngress(
            "telegram", "official-telegram", "account-binding", "event-1", "conversation-1", b"",
        )


if __name__ == "__main__":
    unittest.main()
