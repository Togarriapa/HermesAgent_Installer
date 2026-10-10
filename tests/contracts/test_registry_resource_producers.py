"""Root-selected webhook route authentication and replay tests."""
from __future__ import annotations

import hashlib
import hmac
import unittest
from types import SimpleNamespace
import pytest

from hermes_installer.registry.resource_producers import (
    AuthenticatedChannelIngress,
    CronTickObservation,
    ResourceObservationError,
    SelectedWebhookIngress,
    WebhookRequestObservation,
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
            generation_digest=service_generation,
            effective_spec=effective_spec,
            capability="resource.webhook.run",
            target="resource:webhooks/github-push@1.0.1",
            operation="resource.webhook.deliver", recipient=None,
            delegation_id="selected-webhook-route", profile_id="hermes", enabled=True,
        )
        registry = SelectedResourceRegistry((selected,), expected_generation_digest=service_generation)
        backend = SimpleNamespace(
            backend_id="backend-github-push", resource_id="github-push", profile_id="hermes",
            generation=resource_generation, observer_enrollment_id="observer-github-push",
            credential_reference_ids=frozenset({"credential-github-push"}),
        )
        enrollment = SimpleNamespace(
            resource_id="github-push", kind="webhooks", selected_enabled=True,
            generation=resource_generation, profile_id="hermes", profile_generation="e" * 64,
            principal_id="principal-hermes", observer_enrollment_id="observer-github-push",
            backends={backend.backend_id: backend},
            nodes=(SimpleNamespace(backend_enrollment_id=backend.backend_id),),
        )
        # The runtime selection's resource generation is the active key for
        # job rows; use the protected enrollment generation in both domains.
        selected = SelectedResourceExecution(
            identity=selected.identity, generation_digest=resource_generation,
            effective_spec=effective_spec, capability=selected.capability,
            target=selected.target, operation=selected.operation, recipient=selected.recipient,
            delegation_id=selected.delegation_id, profile_id=selected.profile_id, enabled=True,
        )
        registry = SelectedResourceRegistry((selected,), expected_generation_digest=resource_generation)
        binding = SimpleNamespace(credential_reference_id="credential-github-push")
        bindings, vault = _Bindings(binding), _Vault(secret)
        ingress = SelectedWebhookIngress(
            selected_resources=registry,
            job_enrollments={("github-push", resource_generation): enrollment},
            bindings=bindings, credential_vault=vault,
            replay_store=replay_store or _ReplayStore(),
            service_generation_digest=resource_generation,
        )
        return ingress, bindings, vault, secret

    def test_selected_hmac_route_resolves_exact_secret_and_claims_replay(self):
        ingress, bindings, vault, secret = self._ingress()
        body = b'{"ref":"refs/heads/main"}'
        signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers = (
            ("Content-Type", "application/json"),
            ("X-Hub-Signature-256", signature),
            ("X-GitHub-Event", "push"),
            ("X-GitHub-Delivery", "delivery-1"),
        )
        receipt = ingress.accept_request("POST", "/hooks/github/push", headers, body)
        self.assertEqual(receipt.resource_id, "github-push")
        self.assertEqual(receipt.body, body)
        self.assertEqual(ingress.routes, ("/hooks/github/push",))
        self.assertEqual(bindings.calls[0][0], (
            "backend-github-push", "${GITHUB_WEBHOOK_SECRET}", "webhook-hmac-verify",
        ))
        self.assertEqual(vault.calls[0], (
            "credential-github-push",
            {"peer_uid": 0, "required_scope": "webhook-hmac-verify", "principal_id": "principal-hermes"},
        ))
        with self.assertRaisesRegex(Exception, "duplicate"):
            ingress.accept_request("POST", "/hooks/github/push", headers, body)

    def test_bad_signature_wrong_route_duplicate_headers_and_nonpost_fail_closed(self):
        ingress, _bindings, _vault, _secret = self._ingress()
        body = b'{"ref":"refs/heads/main"}'
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
