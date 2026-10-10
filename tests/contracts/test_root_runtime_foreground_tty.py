from __future__ import annotations

import time

import pytest

from hermes_installer.authority.root_runtime_foreground_tty import (
    RootObservedAdoptedChoiceRevocation,
    RootRuntimeForegroundTTYDenied,
    RootRuntimeForegroundTTYObserver,
)


def _record(**overrides):
    fields = {
        "schema": 1,
        "revocation_observation_handle": "r" * 64,
        "selection_handle": "s" * 64,
        "purpose": "public-free-web-read",
        "consent_id": "c" * 48,
        "source_choice_row_sha256": "a" * 64,
        "choice_epoch": 1,
        "revocation_epoch": 0,
        "active_publication_receipt_handle": "p" * 64,
        "service_generation_digest": "b" * 64,
        "principal_id": "principal-1",
        "profile_id": "profile-1",
        "namespace_id": "namespace-1",
        "owner_generation": "profile-generation-1",
        "displayed_payload_sha256": "d" * 64,
        "root_actor_observation_handle": "actor-" + "e" * 64,
        "tty_controller_observation_handle": "tty-" + "f" * 64,
        "action": "revoke-adopted-choice",
        "issued_monotonic": time.monotonic(),
        "expires_monotonic": time.monotonic() + 10,
        "_seal": object(),
    }
    fields.update(overrides)
    return fields


def test_revocation_observation_cannot_be_caller_minted():
    with pytest.raises(TypeError, match="issued by the foreground root TTY"):
        RootObservedAdoptedChoiceRevocation(**_record())


def test_revocation_observation_requires_exact_finite_action():
    fields = _record(action="revoke-anything")
    with pytest.raises(TypeError, match="issued by the foreground root TTY"):
        RootObservedAdoptedChoiceRevocation(**fields)


def test_revocation_runtime_requires_installed_root_composition():
    # Runtime observers cannot be created around arbitrary caller-supplied
    # registries, even when the machine is not running the installed root actor.
    with pytest.raises(RootRuntimeForegroundTTYDenied):
        RootRuntimeForegroundTTYObserver.from_root_runtime(
            verified_installer_release=object(),
            current_installed_actor_verifier=object(),
            active_bindings=object(), root_journal=object())


def test_observer_attachment_is_exact_registry_and_binding_identity():
    observer = object.__new__(RootRuntimeForegroundTTYObserver)
    registry = object()
    bindings = object()
    observer._registry = registry
    observer._bindings = bindings

    assert observer.is_bound_to(registry, bindings)
    assert not observer.is_bound_to(object(), bindings)
    assert not observer.is_bound_to(registry, object())
