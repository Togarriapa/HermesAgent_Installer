from __future__ import annotations

import time

import pytest

from hermes_installer.authority.native_policy_preparation import (
    NativePolicyCoverageRecord,
    NativePolicyPreparationDenied,
    RootNativePolicyConfigurationChoice,
    _issue_root_native_policy_configuration_choice,
    _validate_choice,
    _source_coverage,
    RootNativePolicyPreparationSelection,
    _SELECTION_SEAL,
)


def _choice(*, expires: float | None = None) -> RootNativePolicyConfigurationChoice:
    now = time.monotonic()
    return _issue_root_native_policy_configuration_choice(
        choice_handle="a" * 64,
        choice_observation_id="choice-1",
        setup_session_id="session-1",
        transaction_handle="transaction-1",
        plan_sha256="b" * 64,
        prepared_generation_id="generation-1",
        prepared_generation_digest="c" * 64,
        principal_selection_handle="d" * 64,
        principal_binding_sha256="e" * 64,
        namespace_selection_handle="f" * 64,
        namespace_binding_sha256="1" * 64,
        service_profile_id="profile-1",
        service_generation="service-generation-1",
        resource_profile_selection_handle=None,
        package_id="hermes-agent-native-package-v1",
        native_package_generation="package-generation-1",
        selected_component_ids=("local-overlay",),
        selected_registration_ids=("agent37-discovery:tool:agent37_discover_skills",),
        selected_action_binding_ids=(),
        controller_binding_handle="2" * 64,
        private_input_consent_selection_handle=None,
        issued_monotonic=now,
        expires_monotonic=expires if expires is not None else now + 60,
        revocation_epoch=0,
    )


def test_configuration_choice_is_sealed_and_finite() -> None:
    choice = _choice()
    _validate_choice(choice, time.monotonic())
    with pytest.raises(TypeError, match="root setup TTY"):
        RootNativePolicyConfigurationChoice(
            **{name: getattr(choice, name) for name in choice.__dataclass_fields__ if name != "_seal"},
            _seal=object(),
        )


def test_expired_configuration_choice_fails_closed() -> None:
    with pytest.raises(NativePolicyPreparationDenied, match="malformed or stale"):
        _validate_choice(_choice(expires=time.monotonic() - 1), time.monotonic())


def test_pending_coverage_requires_exact_resume_prerequisites() -> None:
    with pytest.raises(ValueError, match="exact prerequisites"):
        NativePolicyCoverageRecord("component-a", "registration-a", "configurable-pending", (),
                                   "configure-native-component-and-resume")
    row = NativePolicyCoverageRecord(
        "component-a", "registration-a", "configurable-pending",
        ("account-evidence", "target-permission"), "configure-native-component-and-resume")
    assert row.missing_prerequisite_ids == ("account-evidence", "target-permission")


def test_all_reviewed_registrations_remain_pending_until_real_joins_exist() -> None:
    now = time.monotonic()
    selection = RootNativePolicyPreparationSelection(
        "3" * 64, "choice-1", "session-1", "transaction-1", "b" * 64,
        "generation-1", "c" * 64, "d" * 64, "f" * 64, "e" * 64, "1" * 64,
        "profile-1", "service-generation-1", None, "hermes-agent-native-package-v1",
        None, ("some-selected-component",), (), (), (), (), None, "2" * 64,
        "4" * 64, now, now + 60, 0, _SELECTION_SEAL,
    )
    rows = _source_coverage(selection, {})
    assert len(rows) == 42
    assert len({row.registration_id for row in rows}) == 42
    assert {row.configuration_state for row in rows} == {"configurable-pending"}
    assert all(row.missing_prerequisite_ids for row in rows)
