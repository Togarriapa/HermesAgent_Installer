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
    target_selection_handles: tuple[str, ...]
    effect_policy_receipt_handles: tuple[str, ...]
    source_role_selection_handles: tuple[str, ...]
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
                 root_journal: Path, authority_service: Any) -> None:
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
                or authority_service is None):
            raise ValueError("native policy preparation requires the exact root setup registries")
        self._binding = selected_installation_binding
        self._principal = root_principal_selection_registry
        self._targets = root_component_target_registry
        self._release = root_release_module_registry
        self._registration = root_native_registration_projection_registry
        self._schemas = root_schema_observation_registry
        self._journal = root_journal
        self._authority = authority_service
        self._source_definitions: Any | None = None
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

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        root_principal_selection_registry: Any,
                        root_component_target_registry: _TargetRegistry,
                        root_release_module_registry: Any,
                        root_native_registration_projection_registry: Any,
                        root_schema_observation_registry: Any,
                        root_journal: Path, authority_service: Any
                        ) -> "RootNativePolicyPreparationRegistry":
        return cls(selected_installation_binding, root_principal_selection_registry,
                   root_component_target_registry, root_release_module_registry,
                   root_native_registration_projection_registry,
                   root_schema_observation_registry, root_journal, authority_service)

    def record_configuration(self, choice: RootNativePolicyConfigurationChoice
                             ) -> RootNativePolicyPreparationSelection:
        """Record a TTY-issued intent; do not interpret it as a permission."""
        if type(choice) is not RootNativePolicyConfigurationChoice:
            raise NativePolicyPreparationDenied("native policy configuration must come from the root TTY")
        now = time.monotonic()
        _validate_choice(choice, now)
        self._assert_binding_current()
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
        body = _choice_payload(choice)
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
            choice.private_input_consent_selection_handle, choice.controller_binding_handle,
            "0" * 64, now, min(now + _TTL_SECONDS, choice.expires_monotonic),
            choice.revocation_epoch, _SELECTION_SEAL)
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

        # Read the fixed source map only to retain complete coverage. It never
        # supplies executable action, permission, source, or result records.
        coverage = _source_coverage(selection, missing_by_component)
        records_handle = secrets.token_hex(32)
        body = {
            "selection": selection.selection_sha256,
            "targets": target_handles,
            "coverage": [_coverage_payload(row) for row in coverage],
            "actions": [], "registrations": [], "workflows": [], "roles": [],
            "issuers": [], "observers": [], "schemas": [], "schema_bytes": [],
        }
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        now = time.monotonic()
        records = RootPreparedNativePolicyRecords(
            records_handle, selection_handle, selection.selection_sha256, (),
            tuple(target_handles), (), (), (), (), (), (), (), (), tuple(coverage),
            digest, now, min(now + _TTL_SECONDS, selection.expires_monotonic),
            _RECORDS_SEAL)
        self._records[records_handle] = records
        self._persist("records", records_handle, {**body, "records_sha256": digest,
                                                    "selection_handle": selection_handle,
                                                    "expires_monotonic": records.expires_monotonic})
        return records

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
        resolver = getattr(self._principal, "resolve_current_setup_identity", None)
        if not callable(resolver) or handle is None:
            raise NativePolicyPreparationDenied("current principal and namespace resolver is unavailable")
        current = resolver(selection.principal_selection_handle,
                           selection.namespace_selection_handle, handle)
        if (current.principal_selection_handle != selection.principal_selection_handle
                or current.namespace_selection_handle != selection.namespace_selection_handle
                or current.principal.binding_sha256 != selection.principal_binding_sha256
                or current.namespace.binding_sha256 != selection.namespace_binding_sha256):
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
    return {name: getattr(choice, name) for name in (
        "choice_handle", "choice_observation_id", "setup_session_id", "transaction_handle",
        "plan_sha256", "prepared_generation_id", "prepared_generation_digest",
        "principal_selection_handle", "principal_binding_sha256", "namespace_selection_handle",
        "namespace_binding_sha256", "service_profile_id", "service_generation",
        "resource_profile_selection_handle", "package_id", "native_package_generation",
        "selected_component_ids", "selected_registration_ids", "selected_action_binding_ids",
        "controller_binding_handle", "private_input_consent_selection_handle",
        "issued_monotonic", "expires_monotonic", "revocation_epoch")}


def _selection_payload(selection: RootNativePolicyPreparationSelection) -> dict[str, Any]:
    return {name: getattr(selection, name) for name in (
        "choice_observation_id", "setup_session_id", "transaction_handle", "plan_sha256",
        "prepared_generation_id", "prepared_generation_digest", "principal_selection_handle",
        "namespace_selection_handle", "principal_binding_sha256", "namespace_binding_sha256",
        "service_profile_id", "service_generation", "resource_profile_selection_handle",
        "package_id", "native_package_generation", "selected_component_ids",
        "selected_registration_ids", "selected_action_binding_ids", "target_selection_handles",
        "source_role_selection_handles", "private_input_consent_selection_handle",
        "controller_binding_handle", "issued_monotonic", "expires_monotonic", "revocation_epoch")}


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


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


__all__ = ["NativePolicyCoverageRecord", "NativePolicyPreparationDenied",
           "NativePolicySourcePending", "RootNativePolicyConfigurationChoice",
           "RootNativePolicyPreparationRegistry", "RootNativePolicyPreparationSelection",
           "RootPreparedNativePolicyRecords"]
