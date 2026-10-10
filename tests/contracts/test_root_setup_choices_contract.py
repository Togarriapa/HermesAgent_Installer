from __future__ import annotations

import pytest

from hermes_installer.authority.root_setup_choices import (
    RootSetupChoiceSnapshot,
    _DOMAIN_PURPOSES,
)


def test_setup_choice_snapshot_cannot_be_constructed_without_registry_seal() -> None:
    with pytest.raises(TypeError, match="issued by the root choice registry"):
        RootSetupChoiceSnapshot(
            selection_handle="h" * 32,
            purpose="memory-service-enablement",
            key_id="key",
            setup_session_handle="s" * 64,
            transaction_handle="transaction",
            plan_id="plan",
            prepared_generation="generation",
            principal_selection_handle="principal",
            namespace_selection_handle="namespace",
            private_profile_selection_handle=None,
            source_member_receipt_handles=(),
            choice_payload={},
            choice_payload_sha256="0" * 64,
            signed_record_sha256="1" * 64,
            release_deployment_receipt_sha256="2" * 64,
            choice_epoch=1,
            revocation_epoch=1,
            issued_at_unix=1.0,
            setup_deadline_unix=2.0,
            adoption_publication_receipt_handle=None,
            _registry_seal=object(),
        )


def test_setup_choice_purposes_are_finite_and_separate() -> None:
    assert "memory-service-enablement" in _DOMAIN_PURPOSES
    assert "memory-capture-configuration" in _DOMAIN_PURPOSES
    assert "private-input-routes" in _DOMAIN_PURPOSES
    assert "public-free-web-read" in _DOMAIN_PURPOSES
    assert "native-policy-preparation" in _DOMAIN_PURPOSES
    assert "existing-model-selection" in _DOMAIN_PURPOSES
    assert "application-qualification" in _DOMAIN_PURPOSES
    assert "memory-capture" not in _DOMAIN_PURPOSES
    assert "public-web" not in _DOMAIN_PURPOSES
