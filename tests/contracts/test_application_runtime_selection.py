"""The app selector accepts no caller-minted qualification or runtime DTOs."""
from __future__ import annotations

import pytest

from hermes_installer.authority.application_runtime_selection import (
    ApplicationRuntimeSelectionDenied,
    RootApplicationRuntimePreparationInputSelection,
    RootApplicationRuntimePreparationSelection,
    RootApplicationRuntimePreparationSelectionRegistry,
)


class _NoSelections:
    def resolve_application_setup_choice(self, _handle):
        raise AssertionError("unreviewed input reached the root choice resolver")


class _NoSourceRegistry:
    def resolve_selection(self, _handle):
        raise AssertionError("unreviewed input reached the source receipt resolver")

    def resolve_current_prepared_source_for_selection(self, _handle):
        raise AssertionError("unreviewed input reached the source receipt resolver")

    def resolve_current_lock_for_selection(self, _handle, _source):
        raise AssertionError("unreviewed input reached the lock receipt resolver")


def test_runtime_selection_dtos_cannot_be_caller_minted() -> None:
    with pytest.raises(TypeError, match="minted by the root factory"):
        RootApplicationRuntimePreparationInputSelection(
            schema=1, selection_handle="x", qualification_choice_handle="x",
            application_id="graphify", workflow_id="qualify-graphify-v1",
            runtime_kind="python", source_runtime_constraint=">=3.10",
            source_preparation_selection_handle="x", prepared_source_receipt_handle="x",
            selected_lock_receipt_handle="x", source_generation_manifest_sha256="a" * 64,
            lock_sha256="b" * 64, setup_session_id="x", transaction_handle="x",
            plan_sha256="c" * 64, prepared_generation_id="x",
            prepared_generation_digest="d" * 64, qualification_consent_receipt_handle="x",
            namespace_selection_receipt_handle="x", principal_selection_receipt_handle="x",
            principal_selection_handle="x", principal_binding_sha256="e" * 64,
            namespace_selection_handle="x", namespace_binding_sha256="f" * 64,
            controller_binding_handle="x", issued_monotonic=1.0, expires_monotonic=2.0,
        )
    with pytest.raises(TypeError, match="minted by the root factory"):
        RootApplicationRuntimePreparationSelection(
            **{field: None for field in RootApplicationRuntimePreparationSelection.__dataclass_fields__}
        )


def test_runtime_selector_rejects_unknown_or_malformed_choice_before_proof_lookup() -> None:
    registry = RootApplicationRuntimePreparationSelectionRegistry(
        selected_installation_binding=_NoSelections(),
        source_preparation_registry=_NoSourceRegistry(),
    )
    with pytest.raises(ApplicationRuntimeSelectionDenied, match="malformed"):
        registry.resolve_application_runtime_preparation_input("short", "graphify")
    with pytest.raises(ApplicationRuntimeSelectionDenied, match="outside the four reviewed"):
        registry.resolve_application_runtime_preparation_input(
            "qualification-choice-0000000000000000000000000000", "unknown-app")
