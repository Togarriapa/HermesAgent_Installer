"""Controlled source/shape tests; none of these assert Linux enforcement effects."""
from __future__ import annotations

import hashlib
import hmac
from types import SimpleNamespace

import pytest

from hermes_installer.authority.committed_pm_executable import (
    CommittedPMExecutableUnavailable,
    RootActiveCommittedPMExecutableResolver,
    _canonical,
    _fresh_active_lease,
    _require_same_current_adoption,
    _require_not_revoked,
    _select_exact_adoption,
    _valid_active_adoption_window,
    _verify_revocation_index,
    _verify_signed_choice,
)
from hermes_installer.authority.root_setup_choices import _RECORD_FIELDS
from hermes_installer.authority.service import (
    _ROOT_SETUP_CHOICE_DOMAIN,
    _ROOT_SETUP_CHOICE_REVOCATION_DOMAIN,
)


def _signed_choice(key: bytes) -> dict[str, object]:
    payload = {
        "service_profile_id": "profile-a",
        "service_generation": "service-gen-a",
        "principal_binding_sha256": "1" * 64,
        "namespace_binding_sha256": "2" * 64,
        "selected_worker_recipe_records": [{
            "receipt_handle": "recipe-handle-a", "recipe_sha256": "3" * 64,
        }],
    }
    row: dict[str, object] = {
        "schema": 1,
        "selection_handle": "a" * 64,
        "purpose": "native-policy-preparation",
        "key_id": "authority-key-a",
        "release_deployment_receipt_sha256": "4" * 64,
        "setup_session_handle": "b" * 64,
        "transaction_handle": "c" * 64,
        "plan_id": "plan-a",
        "prepared_generation": "prepared-a",
        "principal_selection_handle": "d" * 64,
        "namespace_selection_handle": "e" * 64,
        "private_profile_selection_handle": None,
        "source_member_receipt_handles": ["source-a"],
        "choice_payload": payload,
        "choice_payload_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
        "choice_epoch": 1,
        "revocation_epoch": 1,
        "issued_at_unix": 10.0,
        "setup_deadline_unix": 20.0,
        "adoption_publication_receipt_handle": None,
    }
    assert set(row) == _RECORD_FIELDS - {"signature"}
    message = (_ROOT_SETUP_CHOICE_DOMAIN + b"native-policy-preparation\0"
               + _canonical(row))
    row["signature"] = hmac.new(key, message, hashlib.sha256).hexdigest()
    return row


def test_resolver_requires_exact_protected_source_types():
    with pytest.raises(CommittedPMExecutableUnavailable, match="exact protected"):
        RootActiveCommittedPMExecutableResolver.from_protected_runtime_sources(
            object(), object(), object(), object())


def test_signed_choice_source_uses_real_domain_and_rejects_tampering():
    key = b"k" * 32
    row = _signed_choice(key)
    _verify_signed_choice(row, key)
    row["choice_epoch"] = 2
    with pytest.raises(ValueError, match="HMAC"):
        _verify_signed_choice(row, key)


def test_revocation_index_is_verified_and_any_selected_record_remains_denied():
    key = b"r" * 32
    choice = _signed_choice(key)
    choice_digest = hashlib.sha256(_canonical(choice)).hexdigest()
    claims = {
        "schema": 1,
        "revocation_receipt_handle": "f" * 64,
        "selection_handle": "a" * 64,
        "purpose": "native-policy-preparation",
        "consent_id": None,
        "previous_choice_epoch": 1,
        "previous_revocation_epoch": 1,
        "revocation_epoch": 2,
        "source_choice_row_sha256": choice_digest,
        "revocation_observation_handle": "2" * 64,
        "displayed_payload_sha256": choice["choice_payload_sha256"],
        "key_id": "authority-key-a",
        "release_deployment_receipt_sha256": "4" * 64,
        "service_generation_digest": "5" * 64,
        "revoked_at_unix": 12.0,
    }
    record = dict(claims)
    record["signature"] = hmac.new(
        key, _ROOT_SETUP_CHOICE_REVOCATION_DOMAIN + _canonical(claims), hashlib.sha256,
    ).hexdigest()
    index = {claims["selection_handle"]: record}
    _verify_revocation_index(
        index, choices={claims["selection_handle"]: choice}, key=key,
        service_generation_digest="5" * 64,
        release_deployment_receipt_sha256="4" * 64,
    )
    _require_not_revoked(claims["selection_handle"], {})
    with pytest.raises(ValueError, match="durable revocation"):
        _require_not_revoked(claims["selection_handle"], index)
    record["signature"] = "0" * 64
    with pytest.raises(ValueError, match="signature"):
        _verify_revocation_index(
            index, choices={claims["selection_handle"]: choice}, key=key,
            service_generation_digest="5" * 64,
            release_deployment_receipt_sha256="4" * 64,
        )


def test_timely_adoption_remains_current_after_original_setup_deadline():
    # This signed setup window ended long ago; current active publication and
    # revocation checks, rather than that expired setup window, govern this lease.
    assert _valid_active_adoption_window(10.0, 20.0, 19.0)
    assert not _valid_active_adoption_window(10.0, 20.0, 20.01)
    assert not _valid_active_adoption_window(10.0, 20.0, 9.99)
    assert not _valid_active_adoption_window(None, 20.0, 19.0)
    lease = _fresh_active_lease(100.0)
    assert 0.0 < lease - 100.0 <= 30.0


def test_missing_duplicate_or_replaced_publication_adoption_is_denied():
    adoption = SimpleNamespace(
        selection_handle="a" * 64, purpose="native-policy-preparation",
        signed_record_sha256="1" * 64, publication_receipt_handle="publication-a",
    )
    assert _select_exact_adoption([adoption], "a" * 64) is adoption
    with pytest.raises(ValueError, match="unique signed native choice adoption"):
        _select_exact_adoption([], "a" * 64)
    with pytest.raises(ValueError, match="unique signed native choice adoption"):
        _select_exact_adoption([adoption, adoption], "a" * 64)
    current = SimpleNamespace(**vars(adoption))
    _require_same_current_adoption(current, adoption, "publication-a")
    current.publication_receipt_handle = "publication-b"
    with pytest.raises(ValueError, match="adoption changed"):
        _require_same_current_adoption(current, adoption, "publication-a")
