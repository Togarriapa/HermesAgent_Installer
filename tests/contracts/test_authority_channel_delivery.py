from __future__ import annotations

import os

import pytest

from hermes_installer.authority.channel_peer_delivery import RootChannelInputDelivery
from hermes_installer.authority.service import AuthorityDenied, AuthorityService, PrincipalBinding
from hermes_installer.authority.resource_source_controllers import RootResourceEventHandle


def _service() -> AuthorityService:
    uid = os.getuid()
    binding = PrincipalBinding(uid, "principal-channel", "profile-channel", "namespace-channel", frozenset({"channel.input"}))
    return AuthorityService(
        signing_key=b"c" * 32, key_id="channel-delivery-test",
        bindings_by_uid={uid: binding}, rules={}, handlers={},
        profile_generations={binding.profile_id: "generation-channel"},
    )


def test_channel_signer_denies_until_exact_peer_source_and_context_registries_are_attached():
    service = _service()
    event = RootResourceEventHandle(
        handle="E" * 43, event_id="event-1", resource_id="resource-1",
        resource_generation="generation-1", source_kind="native-input",
        source_observer_enrollment_id="observer-1", source_receipt_ids=("R" * 43,),
        parent_closure_digest="a" * 64, payload_sha256="b" * 64,
        issued_monotonic=1.0, expires_monotonic=20.0, authority_epoch="epoch-1",
    )

    with pytest.raises(AuthorityDenied, match="root channel event or selected native peer is unavailable"):
        service.issue_root_channel_event_delivery(event, "ingress-1", object())


def test_caller_constructed_channel_delivery_is_not_a_registered_service_result():
    service = _service()
    forged = RootChannelInputDelivery(
        "D" * 43, "E" * 43, "B" * 43, "R" * 43, "C" * 43,
        "a" * 64, 1, 1.0, 20.0, object(),
    )

    assert service.validate_root_channel_input_delivery(object(), forged) is False
