"""Protected fixture checks for the root consent registries' default-deny boundary."""
from __future__ import annotations

from pathlib import Path
from dataclasses import fields

import pytest

from hermes_installer.authority.root_memory_capture_consent import (
    RootMemoryCaptureConsent,
    RootMemoryCaptureConsentRegistry,
)
from hermes_installer.authority.root_private_input_consent import (
    RootPrivateInputConsent,
    RootPrivateInputConsentRegistry,
)
from hermes_installer.authority.service import AuthorityService, PrincipalBinding
from hermes_installer.authority.types import AuthorityDenied


class _NoChoiceRegistry:
    """An empty protected dependency: deliberately has no TTY choice issuer."""


class _NoSelectedCatalog:
    """An empty protected dependency: deliberately has no active route resolver."""


def _service() -> tuple[AuthorityService, PrincipalBinding]:
    binding = PrincipalBinding(
        uid=12001,
        principal_id="fixture-owner",
        profile_id="fixture-private-profile",
        namespace_id="fixture-owner-namespace",
        capabilities=frozenset({"provider-dispatch"}),
    )
    service = AuthorityService(
        signing_key=b"c" * 32,
        key_id="fixture-authority-key",
        bindings_by_uid={binding.uid: binding},
        rules={}, handlers={}, profile_generations={binding.profile_id: "profile-generation-1"},
    )
    return service, binding


def _protected_root(tmp_path: Path) -> Path:
    root = tmp_path / "authority-journal"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def test_private_input_consent_is_absent_by_default_and_survives_restart(tmp_path: Path) -> None:
    service, binding = _service()
    journal = _protected_root(tmp_path)
    first = RootPrivateInputConsentRegistry.from_authority_service(
        service, _NoChoiceRegistry(), _NoSelectedCatalog(), journal,
    )
    assert service.private_input_consent_registry is first

    assert first.selection_handle_for_current_profile(binding) is None
    with pytest.raises(AuthorityDenied, match="no committed active service generation"):
        first.issue_selected_private_input_consent("untrusted-handle", binding)

    restarted_service, restarted_binding = _service()
    second = RootPrivateInputConsentRegistry(
        restarted_service, _NoChoiceRegistry(), _NoSelectedCatalog(), journal,
    )
    assert second.selection_handle_for_current_profile(restarted_binding) is None


def test_memory_capture_is_separate_and_absent_by_default(tmp_path: Path) -> None:
    service, binding = _service()
    journal = _protected_root(tmp_path)
    registry = RootMemoryCaptureConsentRegistry.from_authority_service(
        service, _NoChoiceRegistry(), _NoSelectedCatalog(), journal,
    )

    assert getattr(service, "memory_capture_consent_registry") is registry
    with pytest.raises(AuthorityDenied, match="current protected memory enrollment resolver is unavailable"):
        registry.resolve_selected_memory_binding("memory-engine-fixture")
    with pytest.raises(AuthorityDenied, match="typed selected memory enrollment is required"):
        registry.issue_selected_capture_consent("untrusted-handle", object())
    assert not (journal / "memory-capture-consent" / "registry.json").exists()


def test_service_consent_attachments_are_exact_and_one_time(tmp_path: Path) -> None:
    service, _ = _service()
    journal = _protected_root(tmp_path)
    private = RootPrivateInputConsentRegistry(
        service, _NoChoiceRegistry(), _NoSelectedCatalog(), journal,
    )
    memory = RootMemoryCaptureConsentRegistry(
        service, _NoChoiceRegistry(), _NoSelectedCatalog(), journal,
    )
    service.attach_private_input_consent_registry(private)
    service.attach_memory_capture_consent_registry(memory)
    assert service.private_input_consent_registry is private
    assert service.memory_capture_consent_registry is memory

    with pytest.raises(AuthorityDenied, match="registry is invalid"):
        service.attach_private_input_consent_registry(private)
    with pytest.raises(AuthorityDenied, match="registry is invalid"):
        service.attach_memory_capture_consent_registry(memory)

    other_service, _ = _service()
    with pytest.raises(AuthorityDenied, match="registry is invalid"):
        other_service.attach_private_input_consent_registry(private)
    with pytest.raises(AuthorityDenied, match="registry is invalid"):
        other_service.attach_memory_capture_consent_registry(memory)


def test_consent_receipts_cannot_be_constructed_from_wire_values() -> None:
    with pytest.raises(TypeError, match="minted by its root registry"):
        RootPrivateInputConsent(**{item.name: None for item in fields(RootPrivateInputConsent) if item.name != "_seal"})
    with pytest.raises(TypeError, match="minted by its root registry"):
        RootMemoryCaptureConsent(**{item.name: None for item in fields(RootMemoryCaptureConsent) if item.name != "_seal"})
