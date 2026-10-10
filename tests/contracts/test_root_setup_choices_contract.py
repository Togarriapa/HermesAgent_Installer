from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from hermes_installer.authority.root_setup_choices import (
    RootSetupChoiceSnapshot,
    _commit_revocation_index_entry,
    _DOMAIN_PURPOSES,
)
from hermes_installer.authority.root_private_input_consent import _ProtectedStore
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.protected_enrollment import RootJournalSelection


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


@pytest.mark.skipif(not (os.name == "posix" and os.uname().sysname == "Linux"
                          and os.geteuid() == 0),
                    reason="revocation store fixture requires isolated Linux root")
def test_runtime_revocation_journal_is_atomic_and_rejects_replay() -> None:
    # Use an actual private root-owned journal fixture; the test exercises
    # protected persistence/CAS only, not an invented signed receipt.
    with TemporaryDirectory(prefix="hermes-choice-revocation-", dir="/root") as temp:
        root = Path(temp) / "journal"
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        info = root.stat()
        journal = RootJournalSelection("authority-journal", root, info.st_dev,
                                       info.st_ino, "fixture-generation", "a" * 64)
        store = _ProtectedStore(journal, "setup-choice-revocations", None)
        handle = "b" * 64
        entry = {"schema": 1, "selection_handle": handle, "purpose": "public-free-web-read"}

        _commit_revocation_index_entry(store, handle, entry)
        assert store.load() == {handle: entry}
        with pytest.raises(AuthorityDenied, match="already has a committed revocation"):
            _commit_revocation_index_entry(store, handle, {**entry, "purpose": "memory-service-enablement"})
        assert store.load() == {handle: entry}
