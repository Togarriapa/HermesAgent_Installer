"""Root-owned, preactive native policy preparation (HI-T137.1).

This module records finite setup intent and joins it to actual source-owned
registries.  It deliberately does not turn that intent into runtime grants:
missing targets, source receipts, role definitions, schemas, or permissions
remain explicit pending coverage.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping, Protocol

from .bootstrap_enrollment import BootstrapEnrollmentPending

_CHOICE_SEAL = object()
_SELECTION_SEAL = object()
_RECORDS_SEAL = object()
_CAPTURE_PROFILE_SEAL = object()
_TTL_SECONDS = 300.0
_MAX_RECORD_BYTES = 2 * 1024 * 1024


class NativePolicyPreparationDenied(PermissionError):
    """A policy choice or retained preactive record is stale or malformed."""


class NativePolicySourcePending(BootstrapEnrollmentPending):
    """A selected component is configurable but lacks source-backed proof."""

    def __init__(self, component_id: str, missing_prerequisite_ids: tuple[str, ...]):
        self.component_id = component_id
        self.missing_prerequisite_ids = tuple(missing_prerequisite_ids)
        super().__init__(f"native component {component_id} is pending required source evidence")


@dataclass(frozen=True, slots=True, repr=False)
class RootNativePolicyConfigurationChoice:
    """Opaque finite choice minted only by the guarded root setup TTY."""

    choice_handle: str
    choice_observation_id: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    principal_selection_handle: str
    principal_binding_sha256: str
    namespace_selection_handle: str
    namespace_binding_sha256: str
    service_profile_id: str
    service_generation: str
    resource_profile_selection_handle: str | None
    package_id: str
    native_package_generation: str | None
    selected_component_ids: tuple[str, ...]
    selected_registration_ids: tuple[str, ...]
    selected_action_binding_ids: tuple[str, ...]
    controller_binding_handle: str
    private_input_consent_selection_handle: str | None
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _CHOICE_SEAL:
            raise TypeError("native policy choices are issued by the root setup TTY")


def _issue_root_native_policy_configuration_choice(**values: Any) -> RootNativePolicyConfigurationChoice:
    """Private factory seam; called after RootBootstrapSession's TTY checks."""
    return RootNativePolicyConfigurationChoice(**values, _seal=_CHOICE_SEAL)


@dataclass(frozen=True, slots=True, repr=False)
class RootNativePolicyPreparationSelection:
    selection_handle: str
    choice_observation_id: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    principal_selection_handle: str
    namespace_selection_handle: str
    principal_binding_sha256: str
    namespace_binding_sha256: str
    service_profile_id: str
    service_generation: str
    resource_profile_selection_handle: str | None
    package_id: str
    native_package_generation: str | None
    selected_component_ids: tuple[str, ...]
    selected_registration_ids: tuple[str, ...]
    selected_action_binding_ids: tuple[str, ...]
    target_selection_handles: tuple[str, ...]
    source_role_selection_handles: tuple[str, ...]
    private_input_consent_selection_handle: str | None
    setup_choice_selection_handle: str
    choice_epoch: int
    choice_payload_sha256: str
    controller_binding_handle: str
    selection_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SELECTION_SEAL:
            raise TypeError("native policy selections are registry issued")


@dataclass(frozen=True, slots=True)
class NativePolicyCoverageRecord:
    component_id: str
    registration_id: str
    configuration_state: str
    missing_prerequisite_ids: tuple[str, ...]
    resume_operation_id: str

    def __post_init__(self) -> None:
        if self.configuration_state not in {"selected-complete", "configurable-pending"}:
            raise ValueError("invalid native policy coverage state")
        if self.configuration_state == "selected-complete" and self.missing_prerequisite_ids:
            raise ValueError("complete native coverage cannot have missing prerequisites")
        if self.configuration_state == "configurable-pending" and not self.missing_prerequisite_ids:
            raise ValueError("pending native coverage must name exact prerequisites")


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedNativePolicyRecords:
    records_handle: str
    native_policy_selection_handle: str
    selection_sha256: str
    definition_source_receipt_handles: tuple[str, ...]
    capture_profile_receipt_handles: tuple[str, ...]
    capture_profile_records: tuple["RootPreparedNativeCaptureProfile", ...]
    target_selection_handles: tuple[str, ...]
    effect_policy_receipt_handles: tuple[str, ...]
    source_role_selection_handles: tuple[str, ...]
    action_schema_definitions: Any | None
    action_records: tuple[Any, ...]
    registration_records: tuple[Any, ...]
    workflow_records: tuple[Any, ...]
    process_role_records: tuple[Any, ...]
    source_issuer_records: tuple[Any, ...]
    source_observer_policy_records: tuple[Any, ...]
    native_schema_records: tuple[Any, ...]
    native_schema_bytes: tuple[tuple[str, bytes], ...]
    coverage_records: tuple[NativePolicyCoverageRecord, ...]
    records_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _RECORDS_SEAL:
            raise TypeError("prepared native policy records are registry issued")


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedNativeCaptureProfile:
    """Current source-profile policy joined to its held amendment receipt.

    This row authenticates a bounded capture contract only. It is not a
    SourceReceipt, source observer enrollment, or permission to capture.
    """

    native_policy_selection_handle: str
    source_definition_receipt_handle: str
    artifact_id: str
    relative_path: str
    sha256: str
    size_bytes: int
    capture_schema_id: str
    source_kind: str
    source_action_ids: tuple[str, ...]
    max_payload_bytes: int
    role_id: str
    call_site: str
    source_receipt_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _CAPTURE_PROFILE_SEAL:
            raise TypeError("native capture profile rows are registry issued")


class _TargetRegistry(Protocol):
    def observe_selected_component_target(self, native_policy_selection_handle: str,
                                          component_id: str) -> Any: ...
    def resolve_current_target(self, target_selection_handle: str,
                               native_policy_selection_handle: str) -> Any: ...


class RootNativePolicyPreparationRegistry:
    """Seals root TTY intent and prepares records before first assembly."""

    def __init__(self, selected_installation_binding: Any,
                 root_principal_selection_registry: Any,
                 root_component_target_registry: _TargetRegistry,
                 root_release_module_registry: Any,
                 root_native_registration_projection_registry: Any,
                 root_schema_observation_registry: Any,
                 root_journal: Path) -> None:
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding

        if (type(selected_installation_binding) is not RootSelectedInstallationBinding
                or not isinstance(root_journal, Path) or not root_journal.is_absolute()
                or not callable(getattr(root_component_target_registry,
                                        "observe_selected_component_target", None))
                or not callable(getattr(root_component_target_registry, "resolve_current_target", None))
                or root_principal_selection_registry is None
                or root_release_module_registry is None
                or root_native_registration_projection_registry is None
                or root_schema_observation_registry is None
                or not callable(getattr(selected_installation_binding, "record_durable_setup_choice", None))
                or not callable(getattr(selected_installation_binding, "resolve_current_setup_choice", None))):
            raise ValueError("native policy preparation requires the exact root setup registries")
        self._binding = selected_installation_binding
        self._principal = root_principal_selection_registry
        self._targets = root_component_target_registry
        self._release = root_release_module_registry
        self._registration = root_native_registration_projection_registry
        self._schemas = root_schema_observation_registry
        self._journal = root_journal
        self._source_definitions: Any | None = None
        self._schema_derivations: Any | None = None
        self._source_definition_bundles: dict[str, Any] = {}
        self._schema_definition_bundles: dict[str, Any] = {}
        self._seal = secrets.token_bytes(32)
        self._selections: dict[str, RootNativePolicyPreparationSelection] = {}
        self._records: dict[str, RootPreparedNativePolicyRecords] = {}

    def attach_source_definition_registry(self, registry: Any) -> None:
        """Attach the sibling source-role producer during root composition.

        The pinned v137 constructor is kept unchanged; the factory may attach
        its separately sealed source producer exactly once before any TTY
        choice is recorded.
        """
        if (self._selections or self._source_definitions is not None
                or not callable(getattr(registry, "prepare_for_policy", None))
                or not callable(getattr(registry, "resolve_current", None))):
            raise NativePolicyPreparationDenied("source definition registry attachment is invalid or late")
        self._source_definitions = registry

    def attach_schema_derivation_registry(self, registry: Any) -> None:
        """Attach the root-held, non-executable backend schema derivation."""
        if (self._selections or self._schema_derivations is not None
                or not callable(getattr(registry, "derive_for_selection", None))
                or not callable(getattr(registry, "resolve_current", None))):
            raise NativePolicyPreparationDenied("schema derivation registry attachment is invalid or late")
        self._schema_derivations = registry

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        root_principal_selection_registry: Any,
                        root_component_target_registry: _TargetRegistry,
                        root_release_module_registry: Any,
                        root_native_registration_projection_registry: Any,
                        root_schema_observation_registry: Any,
                        root_journal: Path
                        ) -> "RootNativePolicyPreparationRegistry":
        return cls(selected_installation_binding, root_principal_selection_registry,
                   root_component_target_registry, root_release_module_registry,
                   root_native_registration_projection_registry,
                   root_schema_observation_registry, root_journal)

    def record_configuration(self, choice: RootNativePolicyConfigurationChoice
                             ) -> RootNativePolicyPreparationSelection:
        """Record a TTY-issued intent; do not interpret it as a permission."""
        if type(choice) is not RootNativePolicyConfigurationChoice:
            raise NativePolicyPreparationDenied("native policy configuration must come from the root TTY")
        now = time.monotonic()
        _validate_choice(choice, now)
        self._assert_binding_current()
        choice_resolver = getattr(self._binding, "resolve_current_native_policy_configuration_choice", None)
        if not callable(choice_resolver):
            raise NativePolicyPreparationDenied("root TTY native-policy choice resolver is unavailable")
        try:
            current_choice = choice_resolver(choice.choice_handle)
        except Exception:
            raise NativePolicyPreparationDenied("root TTY native-policy choice is no longer current") from None
        if current_choice is not choice:
            raise NativePolicyPreparationDenied("root TTY resolver did not return the exact retained choice")
        if (len(set(choice.selected_component_ids)) != len(choice.selected_component_ids)
                or len(set(choice.selected_registration_ids)) != len(choice.selected_registration_ids)
                or len(set(choice.selected_action_binding_ids)) != len(choice.selected_action_binding_ids)):
            raise NativePolicyPreparationDenied("native policy choice is empty or duplicates a selected identifier")
        component_ids, registration_components = _reviewed_native_choice_catalog()
        if (not set(choice.selected_component_ids) <= component_ids
                or not set(choice.selected_registration_ids) <= set(registration_components)
                or any(registration_components[item] not in set(choice.selected_component_ids)
                       for item in choice.selected_registration_ids)):
            raise NativePolicyPreparationDenied("native policy choice exceeds the held finite source catalog")
        try:
            durable_handle = self._binding.record_durable_setup_choice(choice)
            snapshot = self._binding.resolve_current_setup_choice(
                durable_handle, "native-policy-preparation")
        except Exception:
            raise NativePolicyPreparationDenied("durable signed native-policy choice could not be retained") from None
        payload = _choice_payload(choice)
        payload_digest = hashlib.sha256(_canonical(payload)).hexdigest()
        if (not isinstance(durable_handle, str) or not durable_handle
                or getattr(snapshot, "selection_handle", None) != durable_handle
                or getattr(snapshot, "purpose", None) != "native-policy-preparation"
                or getattr(snapshot, "choice_payload", None) != payload
                or getattr(snapshot, "choice_payload_sha256", None) != payload_digest
                or getattr(snapshot, "adoption_publication_receipt_handle", None) is not None
                or getattr(snapshot, "principal_selection_handle", None) != choice.principal_selection_handle
                or getattr(snapshot, "namespace_selection_handle", None) != choice.namespace_selection_handle
                or type(getattr(snapshot, "choice_epoch", None)) is not int
                or type(getattr(snapshot, "revocation_epoch", None)) is not int
                or snapshot.revocation_epoch != choice.revocation_epoch):
            raise NativePolicyPreparationDenied("signed setup-choice record does not match current root intent")
        body = {**payload, "setup_choice_selection_handle": durable_handle,
                "choice_payload_sha256": payload_digest,
                "choice_epoch": snapshot.choice_epoch,
                "revocation_epoch": snapshot.revocation_epoch}
        handle = secrets.token_hex(32)
        selection = RootNativePolicyPreparationSelection(
            handle, choice.choice_observation_id, choice.setup_session_id,
            choice.transaction_handle, choice.plan_sha256, choice.prepared_generation_id,
            choice.prepared_generation_digest, choice.principal_selection_handle,
            choice.namespace_selection_handle, choice.principal_binding_sha256,
            choice.namespace_binding_sha256, choice.service_profile_id,
            choice.service_generation, choice.resource_profile_selection_handle,
            choice.package_id, choice.native_package_generation,
            choice.selected_component_ids, choice.selected_registration_ids,
            choice.selected_action_binding_ids, (), (),
            choice.private_input_consent_selection_handle, durable_handle,
            snapshot.choice_epoch, payload_digest,
            choice.controller_binding_handle,
            "0" * 64, now, min(now + _TTL_SECONDS, choice.expires_monotonic),
            snapshot.revocation_epoch, _SELECTION_SEAL)
        digest = hashlib.sha256(_canonical(_selection_payload(selection))).hexdigest()
        selection = replace(selection, selection_sha256=digest)
        self._validate_selection_context(selection)
        self._selections[handle] = selection
        self._persist("selection", handle, {**body, "selection_sha256": digest,
                                             "selection_handle": handle,
                                             "expires_monotonic": selection.expires_monotonic})
        return selection

    def resolve_selection_current(self, selection_handle: str) -> RootNativePolicyPreparationSelection:
        selection = self._selections.get(selection_handle)
        if selection is None or selection.expires_monotonic <= time.monotonic():
            raise NativePolicyPreparationDenied("native policy selection is absent or expired")
        self._assert_binding_current()
        self._validate_selection_context(selection)
        payload = _selection_payload(selection)
        expected = hashlib.sha256(_canonical(payload)).hexdigest()
        if selection.selection_sha256 != expected:
            raise NativePolicyPreparationDenied("native policy selection digest is invalid")
        return selection

    def prepare_selected_policy(self, selection_handle: str) -> RootPreparedNativePolicyRecords:
        selection = self.resolve_selection_current(selection_handle)
        bind_selection = getattr(self._targets, "bind_policy_selection", None)
        if callable(bind_selection):
            bind_selection(selection)
        targets: list[Any] = []
        target_handles: list[str] = []
        missing_by_component: dict[str, tuple[str, ...]] = {}
        for component_id in selection.selected_component_ids:
            try:
                target = self._targets.observe_selected_component_target(selection_handle, component_id)
                handle = getattr(target, "selection_handle", None)
                current = self._targets.resolve_current_target(handle, selection_handle)
                if type(current) is not type(target) or current != target:
                    raise NativePolicyPreparationDenied("component target changed during preparation")
                targets.append(current)
                target_handles.append(handle)
            except PermissionError as exc:
                missing = tuple(getattr(exc, "missing_prerequisite_ids", ()))
                if not missing:
                    raise NativePolicyPreparationDenied("selected component target evidence is unavailable") from None
                missing_by_component[component_id] = missing

        # The handles are observations made after setup intent. Bind them back
        # to the retained selection digest so later assembly cannot swap a
        # target while keeping the same user choice.
        selection = replace(selection, target_selection_handles=tuple(target_handles),
                            selection_sha256=hashlib.sha256(_canonical({
                                **_selection_payload(selection),
                                "target_selection_handles": tuple(target_handles),
                            })).hexdigest())
        self._selections[selection_handle] = selection
        if callable(bind_selection):
            bind_selection(selection)

        source_bundle: Any | None = None
        source_missing: tuple[str, ...] = ()
        if self._source_definitions is None:
            source_missing = ("native-source-definition-registry",)
        else:
            try:
                source_bundle = self._source_definitions.prepare_for_policy(selection)
                if self._source_definitions.resolve_current(source_bundle) is not source_bundle:
                    raise NativePolicyPreparationDenied("source definition bundle changed during preparation")
                if (getattr(source_bundle, "selection_handle", None) != selection.selection_handle
                        or getattr(source_bundle, "selection_sha256", None) != selection.selection_sha256):
                    raise NativePolicyPreparationDenied("source definition bundle belongs to another policy choice")
                source_missing = tuple(getattr(source_bundle, "missing_prerequisite_ids", ()))
            except PermissionError:
                source_missing = ("native-source-definition-evidence",)
        if source_missing:
            for component_id in selection.selected_component_ids:
                missing_by_component[component_id] = tuple(sorted(
                    set(missing_by_component.get(component_id, ())) | set(source_missing)))

        action_schema_definitions: Any | None = None
        schema_missing: tuple[str, ...] = ()
        if self._schema_derivations is None:
            schema_missing = ("native-action-schema-source-derivation-registry",)
        else:
            try:
                action_schema_definitions = self._schema_derivations.derive_for_selection(selection)
                if self._schema_derivations.resolve_current(action_schema_definitions, selection) is not action_schema_definitions:
                    raise NativePolicyPreparationDenied("action schema derivation changed during preparation")
                schema_missing = tuple(action_schema_definitions.missing_prerequisite_ids)
            except PermissionError:
                schema_missing = ("native-action-schema-source-derivation",)
        if schema_missing:
            for component_id in selection.selected_component_ids:
                missing_by_component[component_id] = tuple(sorted(
                    set(missing_by_component.get(component_id, ())) | set(schema_missing)))
        # Source schemas are not executable action/effect joins. Until the
        # selected action/registration/workflow/permission records are present,
        # every selected component remains pending regardless of schema CAS.
        if not action_schema_definitions or not action_schema_definitions.native_schema_records:
            selected_policy_missing = ("selected-native-action-schema-records",)
        else:
            selected_policy_missing = ("selected-native-action-effect-policy-joins",
                                       "native-registration-projection")
        for component_id in selection.selected_component_ids:
            missing_by_component[component_id] = tuple(sorted(
                set(missing_by_component.get(component_id, ())) | set(selected_policy_missing)))

        # Read the fixed source map only to retain complete coverage. It never
        # supplies executable action, permission, source, or result records.
        coverage = _source_coverage(selection, missing_by_component)
        records_handle = secrets.token_hex(32)
        definition_source_receipt_handles: tuple[str, ...] = ()
        capture_profile_records: tuple[RootPreparedNativeCaptureProfile, ...] = ()
        capture_profile_receipt_handles: tuple[str, ...] = ()
        if source_bundle is not None:
            capture_profile_records = self._prepare_capture_profile_records(selection, source_bundle)
            capture_profile_receipt_handles = tuple(
                row.source_receipt_handle for row in capture_profile_records)
            source_receipts = ((source_bundle.definition_source_receipt,)
                               + tuple(source_bundle.role_module_receipts)
                               )
            # v158 capture profiles are held release members, separate from
            # the root-import definition receipt and worker role modules. Keep
            # only exact typed receipts in the durable bundle; a profile's
            # presence authenticates its policy bytes, never an event or role.
            from .bootstrap_runtime_factory import (
                RootPreparedReleaseMemberReceipt, RootReleaseModuleReceipt,
            )
            if (source_bundle.definition_source_receipt is not None
                    and type(source_bundle.definition_source_receipt) is not RootReleaseModuleReceipt):
                raise NativePolicyPreparationDenied("source definition receipt is not root-held")
            profile_receipts = tuple(getattr(source_bundle, "capture_profile_receipts", ()))
            if any(type(row) is not RootPreparedReleaseMemberReceipt
                   for row in tuple(source_bundle.role_module_receipts)):
                raise NativePolicyPreparationDenied("source role receipt is not a held worker release member")
            if any(type(row) not in {RootPreparedReleaseMemberReceipt, RootReleaseModuleReceipt}
                   for row in profile_receipts):
                raise NativePolicyPreparationDenied("capture profile receipt is not a held release member")
            definition_source_receipt_handles = tuple(
                row.source_receipt_handle for row in source_receipts if row is not None)
        body = {
            "selection": selection.selection_sha256,
            "targets": target_handles,
            "definitions": definition_source_receipt_handles,
            "capture_profiles": [_capture_profile_payload(row) for row in capture_profile_records],
            "action_schema_definitions": _schema_definitions_payload(action_schema_definitions),
            "coverage": [_coverage_payload(row) for row in coverage],
            "actions": [], "registrations": [], "workflows": [], "roles": [],
            "issuers": [], "observers": [],
            "schemas": ([dict(row) for row in action_schema_definitions.native_schema_records]
                        if action_schema_definitions is not None else []),
            "schema_bytes": ([(schema_id, content.decode("utf-8"))
                              for schema_id, content in action_schema_definitions.schema_bytes]
                             if action_schema_definitions is not None else []),
        }
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        now = time.monotonic()
        records = RootPreparedNativePolicyRecords(
            records_handle=records_handle,
            native_policy_selection_handle=selection_handle,
            selection_sha256=selection.selection_sha256,
            definition_source_receipt_handles=definition_source_receipt_handles,
            capture_profile_receipt_handles=capture_profile_receipt_handles,
            capture_profile_records=capture_profile_records,
            target_selection_handles=tuple(target_handles),
            effect_policy_receipt_handles=(),
            source_role_selection_handles=(),
            action_schema_definitions=action_schema_definitions,
            action_records=(), registration_records=(), workflow_records=(),
            process_role_records=(), source_issuer_records=(),
            source_observer_policy_records=(),
            native_schema_records=(action_schema_definitions.native_schema_records
                                   if action_schema_definitions is not None else ()),
            native_schema_bytes=(action_schema_definitions.schema_bytes
                                 if action_schema_definitions is not None else ()),
            coverage_records=tuple(coverage),
            records_sha256=digest, issued_monotonic=now,
            expires_monotonic=min(now + _TTL_SECONDS, selection.expires_monotonic),
            _seal=_RECORDS_SEAL)
        self._records[records_handle] = records
        if source_bundle is not None:
            self._source_definition_bundles[records_handle] = source_bundle
        if action_schema_definitions is not None:
            self._schema_definition_bundles[records_handle] = action_schema_definitions
        self._persist("records", records_handle, {**body, "records_sha256": digest,
                                                    "selection_handle": selection_handle,
                                                    "expires_monotonic": records.expires_monotonic})
        return records

    def _prepare_capture_profile_records(
            self, selection: RootNativePolicyPreparationSelection,
            source_bundle: Any) -> tuple[RootPreparedNativeCaptureProfile, ...]:
        from .bootstrap_runtime_factory import RootPreparedReleaseMemberReceipt, RootReleaseModuleReceipt
        from .native_source_definitions import NativeCaptureProfileDeclaration

        declarations = getattr(source_bundle, "capture_profiles", None)
        receipts = getattr(source_bundle, "capture_profile_receipts", None)
        definition_receipt = getattr(source_bundle, "definition_source_receipt", None)
        if (not isinstance(declarations, tuple) or not isinstance(receipts, tuple)
                or type(definition_receipt) is not RootReleaseModuleReceipt):
            raise NativePolicyPreparationDenied("held v158 capture profile bundle is malformed")
        by_artifact = {getattr(row, "artifact_id", None): row for row in receipts}
        if len(by_artifact) != len(receipts) or len(declarations) != len(receipts):
            raise NativePolicyPreparationDenied("held v158 profile receipts do not exactly cover declarations")
        rows: list[RootPreparedNativeCaptureProfile] = []
        for declaration in declarations:
            if type(declaration) is not NativeCaptureProfileDeclaration:
                raise NativePolicyPreparationDenied("capture profile is not a reviewed v158 declaration")
            receipt = by_artifact.get(declaration.artifact_id)
            if (type(receipt) not in {RootPreparedReleaseMemberReceipt, RootReleaseModuleReceipt}
                    or receipt.relative_path != declaration.relative_path
                    or receipt.artifact_id != declaration.artifact_id
                    or receipt.sha256 != declaration.sha256
                    or receipt.size_bytes != declaration.size_bytes):
                raise NativePolicyPreparationDenied("capture profile does not match its retained release receipt")
            raw = receipt.read_current()
            if (not isinstance(raw, bytes) or len(raw) != declaration.size_bytes
                    or hashlib.sha256(raw).hexdigest() != declaration.sha256):
                raise NativePolicyPreparationDenied("capture profile bytes changed after source resolution")
            try:
                document = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise NativePolicyPreparationDenied("capture profile artifact is not valid JSON") from None
            # Keep the byte-level contract closed. In particular, an extra
            # source-action field must not silently widen this profile into a
            # different action family, and the dynamic tool-result profile
            # must remain explicitly deferred to the selected schema join.
            expected_action = (declaration.source_action_ids[0]
                               if len(declaration.source_action_ids) == 1 else None)
            if (type(document) is not dict
                    or set(document) != {"artifact_id", "capture_schema_id", "max_payload_bytes",
                                         "payload", "schema", "source_action_id", "source_kind",
                                         "validator"}
                    or document.get("schema") != 1
                    or document.get("artifact_id") != declaration.artifact_id
                    or document.get("capture_schema_id") != declaration.capture_schema_id
                    or document.get("source_kind") != declaration.source_kind
                    or document.get("max_payload_bytes") != declaration.max_payload_bytes
                    or not isinstance(document.get("payload"), str)
                    or not isinstance(document.get("validator"), str)
                    or not document["validator"].strip()
                    or (expected_action is not None
                        and document.get("source_action_id") != expected_action)
                    or (expected_action is None
                        and (declaration.capture_schema_id != "native-registered-tool-result-v1"
                             or not document.get("source_action_id", "").startswith(
                                 "exact selected external registration ID")))):
                raise NativePolicyPreparationDenied("capture profile bytes differ from the reviewed declaration")
            now = time.monotonic()
            rows.append(RootPreparedNativeCaptureProfile(
                selection.selection_handle, definition_receipt.source_receipt_handle,
                declaration.artifact_id, declaration.relative_path, declaration.sha256,
                declaration.size_bytes, declaration.capture_schema_id, declaration.source_kind,
                declaration.source_action_ids, declaration.max_payload_bytes,
                declaration.role_id, declaration.call_site, receipt.source_receipt_handle,
                now, min(now + _TTL_SECONDS, selection.expires_monotonic),
                _CAPTURE_PROFILE_SEAL,
            ))
        if len(rows) != len(declarations) or len({row.artifact_id for row in rows}) != len(rows):
            raise NativePolicyPreparationDenied("capture profile rows are duplicate or incomplete")
        return tuple(rows)

    def resolve_prepared_policy(self, records_handle: str,
                                selected_installation_binding: Any
                                ) -> RootPreparedNativePolicyRecords:
        if selected_installation_binding is not self._binding:
            raise NativePolicyPreparationDenied("prepared native policy belongs to another root installation")
        records = self._records.get(records_handle)
        if type(records) is not RootPreparedNativePolicyRecords or records.expires_monotonic <= time.monotonic():
            raise NativePolicyPreparationDenied("prepared native policy records are absent or expired")
        selection = self.resolve_selection_current(records.native_policy_selection_handle)
        if records.selection_sha256 != selection.selection_sha256:
            raise NativePolicyPreparationDenied("prepared native policy selection digest changed")
        source_bundle = self._source_definition_bundles.get(records_handle)
        if self._source_definitions is not None and source_bundle is not None:
            if self._source_definitions.resolve_current(source_bundle) is not source_bundle:
                raise NativePolicyPreparationDenied("prepared native source definition bundle changed")
            source_receipts = ((source_bundle.definition_source_receipt,)
                               + tuple(source_bundle.role_module_receipts))
            current_handles = tuple(row.source_receipt_handle for row in source_receipts if row is not None)
            if current_handles != records.definition_source_receipt_handles:
                raise NativePolicyPreparationDenied("prepared native source receipt set changed")
            current_profiles = self._prepare_capture_profile_records(selection, source_bundle)
            if (tuple(_capture_profile_binding(row) for row in current_profiles)
                    != tuple(_capture_profile_binding(row) for row in records.capture_profile_records)
                    or tuple(row.source_receipt_handle for row in current_profiles)
                       != records.capture_profile_receipt_handles):
                raise NativePolicyPreparationDenied("prepared native capture profile receipt set changed")
        schema_bundle = self._schema_definition_bundles.get(records_handle)
        if self._schema_derivations is not None:
            if schema_bundle is None:
                raise NativePolicyPreparationDenied("prepared native action schema definitions are absent")
            if self._schema_derivations.resolve_current(schema_bundle, selection) is not schema_bundle:
                raise NativePolicyPreparationDenied("prepared native action schema definitions changed")
            if records.action_schema_definitions is not schema_bundle:
                raise NativePolicyPreparationDenied("prepared native action schema definition identity changed")
        for target_handle in records.target_selection_handles:
            target = self._targets.resolve_current_target(target_handle, selection.selection_handle)
            if getattr(target, "selection_handle", None) != target_handle:
                raise NativePolicyPreparationDenied("prepared native target is no longer current")
        return records

    def _assert_binding_current(self) -> None:
        session = self._binding._session
        if (self._binding._seal != getattr(session, "_seal", None)
                or getattr(session, "_closed", False)):
            raise NativePolicyPreparationDenied("root installation binding is no longer current")
        checker = getattr(session, "_check_live", None)
        if not callable(checker):
            raise NativePolicyPreparationDenied("root setup session has no currentness check")
        checker()

    def _validate_selection_context(self, selection: RootNativePolicyPreparationSelection) -> None:
        self._assert_binding_current()
        session = self._binding._session
        handle = getattr(session, "_handle", None)
        actual_session_id = getattr(handle, "session_id", None)
        transaction = getattr(session, "_transaction", None)
        actual_transaction = getattr(transaction, "transaction_handle", None)
        if actual_session_id is not None and actual_session_id != selection.setup_session_id:
            raise NativePolicyPreparationDenied("native policy setup session changed")
        if actual_transaction is not None and actual_transaction != selection.transaction_handle:
            raise NativePolicyPreparationDenied("native policy transaction changed")
        try:
            choice = self._binding.resolve_current_setup_choice(
                selection.setup_choice_selection_handle, "native-policy-preparation")
        except Exception:
            raise NativePolicyPreparationDenied("signed native-policy setup choice is stale or revoked") from None
        if (choice.selection_handle != selection.setup_choice_selection_handle
                or choice.purpose != "native-policy-preparation"
                or choice.choice_payload_sha256 != selection.choice_payload_sha256
                or choice.choice_epoch != selection.choice_epoch
                or choice.revocation_epoch != selection.revocation_epoch
                or not _selection_matches_choice_payload(selection, choice.choice_payload)
                or choice.principal_selection_handle != selection.principal_selection_handle
                or choice.namespace_selection_handle != selection.namespace_selection_handle
                or choice.prepared_generation != selection.prepared_generation_id
                or choice.adoption_publication_receipt_handle is not None):
            raise NativePolicyPreparationDenied("signed native-policy choice no longer matches selected intent")
        resolver = getattr(self._principal, "resolve_current_setup_identity", None)
        if not callable(resolver) or handle is None:
            raise NativePolicyPreparationDenied("current principal and namespace resolver is unavailable")
        current = resolver(selection.principal_selection_handle,
                           selection.namespace_selection_handle, handle)
        if (current.principal_selection_handle != selection.principal_selection_handle
                or current.namespace_selection_handle != selection.namespace_selection_handle
                or current.principal.binding_sha256 != selection.principal_binding_sha256
                or current.namespace.binding_sha256 != selection.namespace_binding_sha256
                or current.principal.service_profile_id != selection.service_profile_id):
            raise NativePolicyPreparationDenied("native policy principal or namespace changed")

    def _persist(self, kind: str, handle: str, payload: Mapping[str, Any]) -> None:
        if os.geteuid() != 0:
            # Development fixtures may exercise in-memory validation, while a
            # production root setup always journals durable intent.
            return
        root = self._journal / "native-policy-preparation"
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077):
            raise NativePolicyPreparationDenied("native policy journal is not root-private")
        raw = _canonical({"schema": 1, "kind": kind, "handle": handle,
                          "payload": dict(payload)})
        if len(raw) > _MAX_RECORD_BYTES:
            raise NativePolicyPreparationDenied("native policy record exceeds its bound")
        path = root / f"{kind}-{handle}.json"
        temp = root / f".{kind}-{handle}.{secrets.token_hex(8)}.tmp"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, path)
            directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass


def _validate_choice(choice: RootNativePolicyConfigurationChoice, now: float) -> None:
    required = (choice.choice_handle, choice.choice_observation_id, choice.setup_session_id,
                choice.transaction_handle, choice.prepared_generation_id, choice.principal_selection_handle,
                choice.namespace_selection_handle, choice.service_profile_id, choice.service_generation,
                choice.package_id, choice.controller_binding_handle)
    hashes = (choice.plan_sha256, choice.prepared_generation_digest,
              choice.principal_binding_sha256, choice.namespace_binding_sha256)
    if (any(not isinstance(value, str) or not value for value in required)
            or any(not isinstance(value, str) or len(value) != 64
                   or any(c not in "0123456789abcdef" for c in value) for value in hashes)
            or type(choice.issued_monotonic) not in (int, float)
            or type(choice.expires_monotonic) not in (int, float)
            or choice.issued_monotonic > now or choice.expires_monotonic <= now
            or choice.expires_monotonic - choice.issued_monotonic > 300.0
            or type(choice.revocation_epoch) is not int or choice.revocation_epoch < 0
            or not all(type(items) is tuple and all(isinstance(v, str) and v for v in items)
                       for items in (choice.selected_component_ids, choice.selected_registration_ids,
                                     choice.selected_action_binding_ids))):
        raise NativePolicyPreparationDenied("root TTY native policy choice is malformed or stale")


def _choice_payload(choice: RootNativePolicyConfigurationChoice) -> dict[str, Any]:
    payload = {name: getattr(choice, name) for name in (
        "choice_handle", "choice_observation_id", "setup_session_id", "transaction_handle",
        "plan_sha256", "prepared_generation_id", "prepared_generation_digest",
        "principal_selection_handle", "principal_binding_sha256", "namespace_selection_handle",
        "namespace_binding_sha256", "service_profile_id", "service_generation",
        "resource_profile_selection_handle", "package_id", "native_package_generation",
        "selected_component_ids", "selected_registration_ids", "selected_action_binding_ids",
        "controller_binding_handle", "private_input_consent_selection_handle",
        "issued_monotonic", "expires_monotonic", "revocation_epoch")}
    for name, value in tuple(payload.items()):
        if type(value) is tuple:
            payload[name] = list(value)
    return payload


def _selection_payload(selection: RootNativePolicyPreparationSelection) -> dict[str, Any]:
    return {name: getattr(selection, name) for name in (
        "choice_observation_id", "setup_session_id", "transaction_handle", "plan_sha256",
        "prepared_generation_id", "prepared_generation_digest", "principal_selection_handle",
        "namespace_selection_handle", "principal_binding_sha256", "namespace_binding_sha256",
        "service_profile_id", "service_generation", "resource_profile_selection_handle",
        "package_id", "native_package_generation", "selected_component_ids",
        "selected_registration_ids", "selected_action_binding_ids", "target_selection_handles",
        "source_role_selection_handles", "private_input_consent_selection_handle",
        "setup_choice_selection_handle", "choice_payload_sha256", "controller_binding_handle",
        "choice_epoch", "issued_monotonic", "expires_monotonic", "revocation_epoch")}


def _selection_matches_choice_payload(selection: RootNativePolicyPreparationSelection,
                                      payload: Mapping[str, Any]) -> bool:
    expected = {
        "choice_observation_id": selection.choice_observation_id,
        "setup_session_id": selection.setup_session_id,
        "transaction_handle": selection.transaction_handle,
        "plan_sha256": selection.plan_sha256,
        "prepared_generation_id": selection.prepared_generation_id,
        "prepared_generation_digest": selection.prepared_generation_digest,
        "principal_selection_handle": selection.principal_selection_handle,
        "principal_binding_sha256": selection.principal_binding_sha256,
        "namespace_selection_handle": selection.namespace_selection_handle,
        "namespace_binding_sha256": selection.namespace_binding_sha256,
        "service_profile_id": selection.service_profile_id,
        "service_generation": selection.service_generation,
        "resource_profile_selection_handle": selection.resource_profile_selection_handle,
        "package_id": selection.package_id,
        "native_package_generation": selection.native_package_generation,
        "selected_component_ids": list(selection.selected_component_ids),
        "selected_registration_ids": list(selection.selected_registration_ids),
        "selected_action_binding_ids": list(selection.selected_action_binding_ids),
        "controller_binding_handle": selection.controller_binding_handle,
        "private_input_consent_selection_handle": selection.private_input_consent_selection_handle,
    }
    return all(payload.get(name) == value for name, value in expected.items())


def _source_coverage(selection: RootNativePolicyPreparationSelection,
                     missing_by_component: Mapping[str, tuple[str, ...]]) -> tuple[NativePolicyCoverageRecord, ...]:
    # Imported source definitions are immutable mapping facts only. Coverage
    # remains complete for the finite reviewed 42-row source cohort.
    from .native_registration_projection import capture_actual_hermes_registrations
    captured = capture_actual_hermes_registrations()
    _components, registration_components = _reviewed_native_choice_catalog()
    rows: list[NativePolicyCoverageRecord] = []
    selected_registration_ids = set(selection.selected_registration_ids)
    selected_components = set(selection.selected_component_ids)
    for source in captured:
        registration_id = f"{source.adapter_id}:tool:{source.native_tool_name}"
        component_id = registration_components[registration_id]
        missing = set(missing_by_component.get(component_id, ()))
        # A TTY choice proves only intent. Each selected registration still
        # needs independent target, action/schema, permission and observer joins.
        if registration_id not in selected_registration_ids and component_id not in selected_components:
            missing.add("root-tty-selection")
        if registration_id in selected_registration_ids or component_id in selected_components:
            if not missing:
                missing.update(("target-evidence", "action-source-receipt", "permission-evidence",
                                "source-role-observer-definition", "schema-observation"))
            if selection.resource_profile_selection_handle is None:
                missing.add("resource-profile-selection")
            if selection.native_package_generation is None:
                missing.add("native-package-generation")
        if not missing:
            # A row is only complete when every independent proof producer has
            # joined it. Current HI-T137.1 provides none of those grants.
            missing.update(("target-evidence", "action-source-receipt", "permission-evidence"))
        rows.append(NativePolicyCoverageRecord(component_id, registration_id,
                                               "configurable-pending", tuple(sorted(missing)),
                                               "configure-native-component-and-resume"))
    if len(rows) != 42:
        # Preserve every exact source registration, including unselected ones,
        # as pending so no family silently disappears from the coverage ledger.
        known = {row.registration_id for row in rows}
        for source in captured:
            registration_id = f"{source.adapter_id}:tool:{source.native_tool_name}"
            if registration_id in known:
                continue
            component_id = registration_components[registration_id]
            rows.append(NativePolicyCoverageRecord(
                component_id, registration_id, "configurable-pending",
                ("root-tty-selection", "target-evidence", "source-role-observer-definition"),
                "select-native-component-and-resume"))
    return tuple(sorted(rows, key=lambda row: row.registration_id))


def _reviewed_native_choice_catalog() -> tuple[set[str], dict[str, str]]:
    from .native_registration_projection import (
        capture_actual_hermes_registrations, reviewed_native_registration_definitions,
    )
    captured = capture_actual_hermes_registrations()
    definitions = reviewed_native_registration_definitions(captured)
    component_set = {row.family for row in definitions}
    registrations = {f"{row.adapter_id}:tool:{row.native_tool_name}": row.family
                     for row in definitions}
    if len(captured) != 42 or len(registrations) != 42 or len(component_set) != 18:
        raise NativePolicyPreparationDenied("reviewed native source map does not cover exact 18/42 set")
    return component_set, registrations


def _coverage_payload(row: NativePolicyCoverageRecord) -> dict[str, Any]:
    return {"component_id": row.component_id, "registration_id": row.registration_id,
            "configuration_state": row.configuration_state,
            "missing_prerequisite_ids": row.missing_prerequisite_ids,
            "resume_operation_id": row.resume_operation_id}


def _capture_profile_payload(row: RootPreparedNativeCaptureProfile) -> dict[str, Any]:
    return {
        "native_policy_selection_handle": row.native_policy_selection_handle,
        "source_definition_receipt_handle": row.source_definition_receipt_handle,
        "artifact_id": row.artifact_id, "relative_path": row.relative_path,
        "sha256": row.sha256, "size_bytes": row.size_bytes,
        "capture_schema_id": row.capture_schema_id, "source_kind": row.source_kind,
        "source_action_ids": row.source_action_ids,
        "max_payload_bytes": row.max_payload_bytes, "role_id": row.role_id,
        "call_site": row.call_site, "source_receipt_handle": row.source_receipt_handle,
        "issued_monotonic": row.issued_monotonic,
        "expires_monotonic": row.expires_monotonic,
    }


def _schema_definitions_payload(bundle: Any | None) -> dict[str, Any] | None:
    if bundle is None:
        return None
    return {
        "definition_handle": bundle.definition_handle,
        "native_policy_selection_handle": bundle.native_policy_selection_handle,
        "selection_sha256": bundle.selection_sha256,
        "package_id": bundle.package_id,
        "native_package_generation": bundle.native_package_generation,
        "service_profile_id": bundle.service_profile_id,
        "service_generation": bundle.service_generation,
        "module_receipt_handles": bundle.module_receipt_handles,
        "definitions_sha256": bundle.definitions_sha256,
        "missing_prerequisite_ids": bundle.missing_prerequisite_ids,
        "definition_count": len(bundle.definition_records),
        "schema_count": len(bundle.schema_bytes),
        "issued_monotonic": bundle.issued_monotonic,
        "expires_monotonic": bundle.expires_monotonic,
    }


def _capture_profile_binding(row: RootPreparedNativeCaptureProfile) -> tuple[Any, ...]:
    return tuple(getattr(row, name) for name in (
        "native_policy_selection_handle", "source_definition_receipt_handle",
        "artifact_id", "relative_path", "sha256", "size_bytes", "capture_schema_id",
        "source_kind", "source_action_ids", "max_payload_bytes", "role_id", "call_site",
        "source_receipt_handle"))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


__all__ = ["NativePolicyCoverageRecord", "NativePolicyPreparationDenied",
           "NativePolicySourcePending", "RootNativePolicyConfigurationChoice",
           "RootNativePolicyPreparationRegistry", "RootNativePolicyPreparationSelection",
           "RootPreparedNativeCaptureProfile", "RootPreparedNativePolicyRecords"]
