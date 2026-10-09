from __future__ import annotations

import pytest

from hermes_installer.registry.resource_producers import (
    AuthenticatedChannelIngress,
    CronTickObservation,
    ResourceObservationError,
    WebhookRequestObservation,
)


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
