"""Controlled source/shape tests; none of these assert Linux enforcement effects."""
from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
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
    _IdentityCustody,
    RootVerifiedCommittedPMExecutableIdentity,
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


def test_identity_custody_is_idempotent_and_does_not_close_reused_fd(tmp_path, monkeypatch):
    target = tmp_path / "reused-fd.txt"
    target.write_text("keep-open")
    original = os.open(target, os.O_RDONLY)
    issued = {}
    owner_lock = threading.RLock()
    handle = "d" * 64
    resolver = object.__new__(RootActiveCommittedPMExecutableResolver)
    resolver._closed = False
    resolver._issuer = object()
    resolver._issued = issued
    resolver._identity_lock = owner_lock
    resolver._pending_resolutions = 0
    identity = RootVerifiedCommittedPMExecutableIdentity(
        identity_handle=handle, service_generation_digest="1" * 64,
        publication_receipt_handle="publication", publication_sha256="2" * 64,
        active_generation_id="generation", network_id="network", profile_id="profile",
        service_generation="service-generation", runtime_record_id="runtime",
        principal_id="principal", namespace_id="namespace",
        runtime_record_sha256="3" * 64, source_choice_selection_handle="choice",
        source_choice_signed_record_sha256="4" * 64,
        source_original_setup_deadline_unix=20.0, pm_runtime_receipt_handle="receipt",
        pm_receipt_sha256="5" * 64, pm_generation="pm-" + "a" * 32,
        source_commit="commit", runtime_relative="bin/python",
        runtime_venv_relative="venv", runtime_closure_sha256="6" * 64,
        executable_path=target, executable_sha256="7" * 64, executable_device=1,
        executable_inode=2, executable_uid=0, executable_gid=0, executable_mode=0o500,
        runtime_identity_sha256="8" * 64, runtime_member_fds=(("bin/python", original),),
        expires_monotonic=1000.0, member_fds=(original,),
        _custody=_IdentityCustody(handle, (original,), issued, owner_lock),
        _issuer=resolver._issuer,
    )
    issued[handle] = identity

    identity.close()
    assert handle not in issued
    reused = os.open(target, os.O_RDONLY)
    assert reused == original
    identity.close()
    resolver.close()
    assert os.read(reused, 1) == b"k"

    monkeypatch.setattr(RootActiveCommittedPMExecutableResolver, "_require_live", lambda _self: None)
    with pytest.raises(CommittedPMExecutableUnavailable, match="foreign or stale"):
        resolver.verify_current(identity)
    os.close(reused)


def test_resolver_bounds_outstanding_identity_observations(monkeypatch):
    resolver = object.__new__(RootActiveCommittedPMExecutableResolver)
    resolver._closed = False
    resolver._identity_lock = threading.RLock()
    resolver._pending_resolutions = 0
    resolver._issued = {
        str(index): SimpleNamespace(expires_monotonic=time.monotonic() + 60.0,
                                    close=lambda: None)
        for index in range(4)
    }
    monkeypatch.setattr(RootActiveCommittedPMExecutableResolver, "_require_live", lambda _self: None)
    with pytest.raises(CommittedPMExecutableUnavailable, match="too many outstanding"):
        resolver._begin_resolution()
    assert resolver._pending_resolutions == 0
