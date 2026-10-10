from __future__ import annotations

import time
from dataclasses import replace

import pytest

from hermes_installer.authority.native_policy_preparation import (
    NativePolicyCoverageRecord,
    NativePolicyPreparationDenied,
    RootPreparedNativeCaptureProfile,
    RootNativePolicyConfigurationChoice,
    _issue_root_native_policy_configuration_choice,
    _validate_choice,
    _source_coverage,
    _selection_matches_choice_payload,
    _choice_payload,
    RootNativePolicyPreparationSelection,
    _SELECTION_SEAL,
)
from hermes_installer.authority.native_schema_derivation import (
    RootPreparedNativeActionSchemaDefinitions,
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
        selected_owner_overlay_registration_ids=(),
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


def test_capture_profile_record_cannot_be_constructed_from_caller_fields() -> None:
    fields = {
        "native_policy_selection_handle": "selection",
        "source_definition_receipt_handle": "definition-receipt",
        "artifact_id": "installer-native-input-capture-profile-v1",
        "relative_path": "plans/amendments/capture-profile.json",
        "sha256": "a" * 64,
        "size_bytes": 100,
        "capture_schema_id": "native-authenticated-input-v1",
        "source_kind": "native-input",
        "source_action_ids": ("authenticated-input",),
        "max_payload_bytes": 1024,
        "role_id": "hermes-native-invocations-v1",
        "call_site": "read_selected_native_input",
        "source_receipt_handle": "profile-receipt",
        "issued_monotonic": time.monotonic(),
        "expires_monotonic": time.monotonic() + 30,
    }
    with pytest.raises(TypeError, match="registry issued"):
        RootPreparedNativeCaptureProfile(**fields, _seal=object())


def test_schema_source_definition_bundle_cannot_be_caller_minted() -> None:
    with pytest.raises(TypeError, match="root registry issued"):
        RootPreparedNativeActionSchemaDefinitions(
            definition_handle="d" * 64,
            native_policy_selection_handle="s" * 64,
            selection_sha256="a" * 64,
            package_id="hermes-agent-native-package-v1",
            native_package_generation="b" * 64,
            service_profile_id="hermes-agent-native-v1",
            service_generation="service-generation",
            module_receipt_handles=(), definition_records=(),
            schema_artifact_receipts=(), schema_derivation_receipts=(),
            native_schema_records=(), schema_bytes=(),
            missing_prerequisite_ids=("native-action-schema-cas-child-receipt",),
            definitions_sha256="c" * 64, issued_monotonic=1.0,
            expires_monotonic=2.0, _seal=object(),
        )


def test_all_reviewed_registrations_remain_pending_until_real_joins_exist() -> None:
    now = time.monotonic()
    selection = RootNativePolicyPreparationSelection(
        "3" * 64, "choice-1", "session-1", "transaction-1", "b" * 64,
        "generation-1", "c" * 64, "d" * 64, "f" * 64, "e" * 64, "1" * 64,
        "profile-1", "service-generation-1", None, "hermes-agent-native-package-v1",
        None, ("some-selected-component",), (), (), (), (), (), None, "setup-choice-1", 1, "5" * 64,
        "2" * 64,
        "4" * 64, now, now + 60, 0, _SELECTION_SEAL,
    )
    rows = _source_coverage(selection, {})
    assert len(rows) == 42
    assert len({row.registration_id for row in rows}) == 42
    assert {row.configuration_state for row in rows} == {"configurable-pending"}
    assert all(row.missing_prerequisite_ids for row in rows)


def test_signed_choice_payload_must_match_every_selected_policy_field() -> None:
    now = time.monotonic()
    selection = RootNativePolicyPreparationSelection(
        "3" * 64, "choice-1", "session-1", "transaction-1", "b" * 64,
        "generation-1", "c" * 64, "d" * 64, "f" * 64, "e" * 64, "1" * 64,
        "profile-1", "service-generation-1", None, "hermes-agent-native-package-v1",
        "package-generation-1", ("some-selected-component",),
        ("agent37-discovery:tool:agent37_discover_skills",), (), (), (), (), None,
        "setup-choice-1", 1, "5" * 64, "2" * 64, "4" * 64,
        now, now + 60, 1, _SELECTION_SEAL,
    )
    payload = {
        "choice_observation_id": "choice-1",
        "setup_session_id": "session-1",
        "transaction_handle": "transaction-1",
        "plan_sha256": "b" * 64,
        "prepared_generation_id": "generation-1",
        "prepared_generation_digest": "c" * 64,
        "principal_selection_handle": "d" * 64,
        "principal_binding_sha256": "e" * 64,
        "namespace_selection_handle": "f" * 64,
        "namespace_binding_sha256": "1" * 64,
        "service_profile_id": "profile-1",
        "service_generation": "service-generation-1",
        "resource_profile_selection_handle": None,
        "package_id": "hermes-agent-native-package-v1",
        "native_package_generation": "package-generation-1",
        "selected_component_ids": ["some-selected-component"],
        "selected_registration_ids": ["agent37-discovery:tool:agent37_discover_skills"],
        "selected_action_binding_ids": [],
        "selected_owner_overlay_registration_ids": [],
        "controller_binding_handle": "2" * 64,
        "private_input_consent_selection_handle": None,
    }
    assert _selection_matches_choice_payload(selection, payload)
    payload["selected_action_binding_ids"] = ["unselected-action"]
    assert not _selection_matches_choice_payload(selection, payload)


def test_owner_overlay_choice_is_separate_from_backend_action_bindings() -> None:
    overlay_id = "resource-overlay-store:tool:resource_overlay_read"
    choice = _issue_root_native_policy_configuration_choice(
        **{name: getattr(_choice(), name) for name in _choice().__dataclass_fields__
           if name not in {"_seal", "selected_component_ids", "selected_registration_ids",
                           "selected_action_binding_ids", "selected_owner_overlay_registration_ids"}},
        selected_component_ids=("resource-overlay-store",),
        selected_registration_ids=(overlay_id,), selected_action_binding_ids=(),
        selected_owner_overlay_registration_ids=(overlay_id,),
    )
    payload = _choice_payload(choice)
    assert payload["selected_owner_overlay_registration_ids"] == [overlay_id]
    assert payload["selected_action_binding_ids"] == []
    assert payload["selected_registration_ids"] == [overlay_id]


def test_selected_owner_overlay_coverage_stays_pending_without_owned_view_joins() -> None:
    now = time.monotonic()
    selection = RootNativePolicyPreparationSelection(
        "3" * 64, "choice-1", "session-1", "transaction-1", "b" * 64,
        "generation-1", "c" * 64, "d" * 64, "f" * 64, "e" * 64, "1" * 64,
        "profile-1", "service-generation-1", None, "hermes-agent-native-package-v1",
        "package-generation-1", ("resource-overlay-store",),
        ("resource-overlay-store:tool:resource_overlay_read",), (),
        ("resource-overlay-store:tool:resource_overlay_read",), (), (), None,
        "setup-choice-1", 1, "5" * 64, "2" * 64, "4" * 64,
        now, now + 60, 1, _SELECTION_SEAL,
    )
    rows = _source_coverage(selection, {})
    read_row = next(row for row in rows if row.registration_id.endswith("resource_overlay_read"))
    assert read_row.configuration_state == "configurable-pending"
    assert "root-tty-selection" not in read_row.missing_prerequisite_ids
    assert "target-evidence" in read_row.missing_prerequisite_ids
    assert "permission-evidence" in read_row.missing_prerequisite_ids
