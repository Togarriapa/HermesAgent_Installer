"""Contract checks for the separate v138 PUBLIC input permission receipt."""
from __future__ import annotations

from dataclasses import fields

import pytest

from hermes_installer.authority import root_public_input_permission as permission
from hermes_installer.authority.types import AuthorityDenied


def test_public_permission_claims_are_exact_v138_schema() -> None:
    receipt = permission.RootPublicInputPermission(
        receipt_handle="receipt-1", consent_id="consent-1", purpose="public-free-web-read",
        selection_handle="selection-1", principal_id="principal-1", profile_id="profile-1",
        namespace_id="namespace-1", profile_generation="generation-1",
        service_generation_digest="a" * 64, retained_input_selection_handle="input-selection-1",
        input_observation_handle="observation-1", input_sha256="b" * 64,
        web_scope_ids=("scope-1",), web_scope_sha256="c" * 64,
        public_recipient_ids=("recipient-1",), allowed_operations=("plugin.web.read",),
        additional_metered_budget_usd=0.0, revocation_epoch=1,
        issued_monotonic=10.0, expires_monotonic=20.0, signature="signature",
        _seal=permission._SEAL,
    )
    assert set(receipt.claims()) == {
        "receipt_handle", "consent_id", "purpose", "selection_handle", "principal_id",
        "profile_id", "namespace_id", "profile_generation", "service_generation_digest",
        "retained_input_selection_handle", "input_observation_handle", "input_sha256",
        "web_scope_ids", "web_scope_sha256", "public_recipient_ids", "allowed_operations",
        "additional_metered_budget_usd", "revocation_epoch", "issued_monotonic",
        "expires_monotonic",
    }
    assert "_seal" not in receipt.claims()
    assert set(receipt.claims()) == set(receipt.__dataclass_fields__) - {"signature", "_seal"}


@pytest.mark.parametrize("purpose,operations,budget,lease", [
    ("private-input", ("plugin.web.read",), 0.0, 10.0),
    ("public-free-web-read", ("provider.dispatch",), 0.0, 10.0),
    ("public-free-web-read", ("plugin.web.read",), 1.0, 10.0),
    ("public-free-web-read", ("plugin.web.read",), 0.0, 30.01),
])
def test_public_permission_rejects_wrong_purpose_route_budget_or_lease(
    purpose: str, operations: tuple[str, ...], budget: float, lease: float,
) -> None:
    values = {item.name: None for item in fields(permission.RootPublicInputPermission)
              if item.name not in {"_seal"}}
    values.update(
        receipt_handle="r", consent_id="c", purpose=purpose, selection_handle="s",
        principal_id="p", profile_id="f", namespace_id="n", profile_generation="g",
        service_generation_digest="a" * 64, retained_input_selection_handle="i",
        input_observation_handle="o", input_sha256="b" * 64, web_scope_ids=("w",),
        web_scope_sha256="c" * 64, public_recipient_ids=("r",), allowed_operations=operations,
        additional_metered_budget_usd=budget, revocation_epoch=1, issued_monotonic=10.0,
        expires_monotonic=10.0 + lease, signature="sig", _seal=permission._SEAL,
    )
    with pytest.raises(AuthorityDenied):
        permission.RootPublicInputPermission(**values)


def test_public_permission_cannot_be_constructed_from_wire_fields() -> None:
    values = {item.name: None for item in fields(permission.RootPublicInputPermission)
              if item.name != "_seal"}
    with pytest.raises(TypeError, match="minted by its root registry"):
        permission.RootPublicInputPermission(**values)
