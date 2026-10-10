"""Root-owned profile overlay view and preactive operation receipts.

The overlay is a fixed private child of the selected service data root.  Only
the root setup session may create or resolve its receipt; callers never supply
filesystem paths, owner IDs, targets, operations, or schema IDs.

This module deliberately keeps owner-overlay registrations outside
``PluginActionSchema``.  An operation row is emitted only after its exact
source, schema, selected target, observer/role, and current view receipts join.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


_VIEW_SEAL = object()
_BUNDLE_SEAL = object()
_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_REGISTRATIONS = {
    "resource-overlay-store:tool:resource_overlay_read": ("read", "plugin.resource-overlay-store.read"),
    "resource-overlay-store:tool:resource_overlay_history": ("history", "plugin.resource-overlay-store.read"),
    "resource-overlay-store:tool:resource_overlay_write": ("write", "plugin.resource-overlay-store.write"),
    "resource-overlay-store:tool:resource_overlay_delete": ("delete", "plugin.resource-overlay-store.write"),
}
_CAPABILITY = "plugin:resource-overlay-store"
_ENROLLMENT_SEAL = object()
_ARGUMENT_SCHEMA_SEAL = object()


class LocalProfileOverlayEffectsDenied(PermissionError):
    """A profile overlay request is stale, unselected, or not fully joined."""


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedOwnerOverlayEffectEnrollment:
    """One actual selected protected operation rule retained by root."""

    effect_enrollment_id: str
    native_policy_selection_handle: str
    view_selection_handle: str
    operation: str
    capability: str
    target_id: str
    recipient: None
    principal_id: str
    profile_id: str
    namespace_id: str
    generation: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _ENROLLMENT_SEAL
                or self.operation not in {"plugin.resource-overlay-store.read", "plugin.resource-overlay-store.write"}
                or self.capability != _CAPABILITY or self.recipient is not None
                or self.expires_monotonic <= self.issued_monotonic):
            raise TypeError("owner-overlay effect enrollments are root-issued fixed rules")


@dataclass(frozen=True, slots=True, repr=False)
class RootOwnerOverlayArgumentSchemaReceipt:
    """Root CAS receipt for one canonical schema captured from held source."""

    schema_id: str
    artifact_id: str
    schema_kind: str
    sha256: str
    size_bytes: int
    artifact_receipt_handle: str
    registration_id: str
    native_schema_sha256: str
    source_receipt_handle: str
    native_policy_selection_handle: str
    prepared_generation_id: str
    relative_path: str
    device: int
    inode: int
    _seal: object = field(repr=False, compare=False)
    _registry: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _ARGUMENT_SCHEMA_SEAL or self.schema_kind != "argument"
                or self.size_bytes <= 0 or self.size_bytes > 262_144
                or not re.fullmatch(r"[0-9a-f]{64}", self.sha256)
                or self.sha256 != self.native_schema_sha256):
            raise TypeError("owner-overlay argument schema receipt is root-issued")

    def read_current(self) -> bytes:
        return self._registry.read_current_argument_schema(self)

    def __repr__(self) -> str:
        return "RootOwnerOverlayArgumentSchemaReceipt(<root-private>)"


class RootOwnerOverlaySchemaReceiptRegistry:
    """Root CAS issuer joining original captured arguments to result schemas."""

    def __init__(self, selected_installation_binding: Any,
                 source_registration_registry: Any, root_journal: Path):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .native_registration_projection import RootNativeRegistrationProjectionRegistry

        if (type(selected_installation_binding) is not RootSelectedInstallationBinding
                or type(source_registration_registry) is not RootNativeRegistrationProjectionRegistry
                or source_registration_registry._binding is not selected_installation_binding
                or not isinstance(root_journal, Path) or not root_journal.is_absolute()):
            raise ValueError("owner-overlay schemas require the exact root source/CAS setup owners")
        self._binding = selected_installation_binding
        self._source = source_registration_registry
        self._journal = root_journal
        self._argument_store: Any | None = None
        self._arguments: dict[str, RootOwnerOverlayArgumentSchemaReceipt] = {}
        self._by_selection_registration: dict[tuple[str, str], str] = {}

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        source_registration_registry: Any,
                        root_journal: Path) -> "RootOwnerOverlaySchemaReceiptRegistry":
        return cls(selected_installation_binding, source_registration_registry, root_journal)

    def resolve_owner_overlay_schemas(self, registration_id: str, source: Any,
                                      capture: Any, selection: Any) -> tuple[Any, Any]:
        from .native_registration_projection import reviewed_packaged_registration_result_schemas

        current_selection = self._binding.resolve_current_native_policy_selection(
            selection.selection_handle)
        coverage = self._source.resolve_source_coverage()
        if (current_selection is not selection
                or registration_id not in tuple(getattr(selection, "selected_owner_overlay_registration_ids", ()))
                or coverage.prepared_generation_id != selection.prepared_generation_id):
            raise LocalProfileOverlayEffectsDenied("owner-overlay schema selection is not current")
        source_rows = {row.registration_id: row for row in coverage.source_observations}
        capture_rows = {f"{row.adapter_id}:tool:{row.native_tool_name}": row
                        for row in coverage.captured_registrations}
        current_source, current_capture = source_rows.get(registration_id), capture_rows.get(registration_id)
        if (current_source is None or current_capture is None
                or current_source != source or current_capture != capture
                or current_source.handler_kind != "owner-overlay"
                or current_source.registration_source_receipt_handle != source.registration_source_receipt_handle
                or _canonical(current_capture.argument_schema) != _canonical(current_source.argument_schema)
                or hashlib.sha256(_canonical(current_capture.argument_schema)).hexdigest()
                    != current_capture.native_schema_sha256):
            raise LocalProfileOverlayEffectsDenied("owner-overlay argument schema differs from held registration source")
        argument_receipt = self._argument_receipt(selection, registration_id, source, capture)
        reviewed = [row for row in reviewed_packaged_registration_result_schemas(
            coverage.captured_registrations) if row.native_tool_name == capture.native_tool_name]
        if len(reviewed) != 1:
            raise LocalProfileOverlayEffectsDenied("owner-overlay result schema is outside the reviewed local set")
        result_receipt = self._binding.mint_native_registration_schema_receipt(reviewed[0].artifact_id)
        if (result_receipt.artifact_id != reviewed[0].artifact_id
                or result_receipt.sha256 != reviewed[0].sha256
                or hashlib.sha256(result_receipt.read_current()).hexdigest() != reviewed[0].sha256):
            raise LocalProfileOverlayEffectsDenied("owner-overlay result schema receipt is stale or mismatched")
        return argument_receipt, result_receipt

    def read_current_argument_schema(self, receipt: RootOwnerOverlayArgumentSchemaReceipt) -> bytes:
        import os
        import stat
        from .native_schema_derivation import _NativeSchemaContentStore

        if (os.geteuid() != 0 or type(receipt) is not RootOwnerOverlayArgumentSchemaReceipt
                or receipt._seal is not _ARGUMENT_SCHEMA_SEAL
                or self._arguments.get(receipt.artifact_receipt_handle) is not receipt):
            raise LocalProfileOverlayEffectsDenied("owner-overlay argument schema receipt is absent or not root-issued")
        try:
            selection = self._binding.resolve_current_native_policy_selection(
                receipt.native_policy_selection_handle)
            coverage = self._source.resolve_source_coverage()
            source = next(row for row in coverage.source_observations
                          if row.registration_id == receipt.registration_id)
            capture = next(row for row in coverage.captured_registrations
                           if f"{row.adapter_id}:tool:{row.native_tool_name}" == receipt.registration_id)
            if (receipt.registration_id not in tuple(getattr(selection, "selected_owner_overlay_registration_ids", ()))
                    or selection.prepared_generation_id != receipt.prepared_generation_id
                    or coverage.prepared_generation_id != receipt.prepared_generation_id
                    or source.registration_source_receipt_handle != receipt.source_receipt_handle
                    or source.native_schema_sha256 != receipt.native_schema_sha256
                    or hashlib.sha256(_canonical(capture.argument_schema)).hexdigest()
                       != receipt.native_schema_sha256):
                raise ValueError
            if self._argument_store is None:
                self._argument_store = _NativeSchemaContentStore(self._journal)
            raw = self._argument_store.read(receipt.relative_path, receipt.device, receipt.inode,
                                            receipt.sha256, receipt.size_bytes)
            if raw != _canonical(capture.argument_schema):
                raise ValueError
            return raw
        except Exception:
            raise LocalProfileOverlayEffectsDenied("owner-overlay argument schema CAS/current source changed") from None

    def _argument_receipt(self, selection: Any, registration_id: str,
                          source: Any, capture: Any) -> RootOwnerOverlayArgumentSchemaReceipt:
        import os
        from .native_schema_derivation import _NativeSchemaContentStore

        key = (selection.selection_handle, registration_id)
        prior_handle = self._by_selection_registration.get(key)
        prior = self._arguments.get(prior_handle or "")
        if prior is not None:
            try:
                prior.read_current()
                return prior
            except Exception:
                self._arguments.pop(prior.artifact_receipt_handle, None)
        if os.geteuid() != 0:
            raise LocalProfileOverlayEffectsDenied("owner-overlay argument schema CAS requires root")
        raw = _canonical(capture.argument_schema)
        digest = hashlib.sha256(raw).hexdigest()
        if (digest != capture.native_schema_sha256 or digest != source.native_schema_sha256
                or not 1 <= len(raw) <= 262_144):
            raise LocalProfileOverlayEffectsDenied("captured owner-overlay argument schema is not bounded source")
        if self._argument_store is None:
            self._argument_store = _NativeSchemaContentStore(self._journal)
        storage = self._argument_store.put(raw, digest)
        schema_id = f"installer-native-owner-overlay-arguments-{capture.native_tool_name}-v1"
        handle = secrets.token_urlsafe(32)
        receipt = RootOwnerOverlayArgumentSchemaReceipt(
            schema_id, schema_id, "argument", digest, len(raw), handle,
            registration_id, digest, source.registration_source_receipt_handle,
            selection.selection_handle, selection.prepared_generation_id,
            storage.relative_path, storage.device, storage.inode,
            _ARGUMENT_SCHEMA_SEAL, self,
        )
        self._arguments[handle] = receipt
        self._by_selection_registration[key] = handle
        receipt.read_current()
        return receipt


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedOwnedProfileOverlayView:
    """Sealed observation of the exact root-owned profile overlay directory."""

    schema: int
    view_selection_handle: str
    native_policy_selection_handle: str
    profile_view_selection_handle: str
    setup_session_id: str
    transaction_handle: str
    prepared_generation_id: str
    prepared_generation_digest: str
    service_profile_id: str
    service_generation: str
    resource_profile_id: str
    resource_profile_receipt_handle: str
    resources_source_receipt_handle: str
    resources_source_artifact_id: str
    resources_source_sha256: str
    principal_selection_handle: str
    namespace_selection_handle: str
    principal_id: str
    namespace_id: str
    data_root_selection_handle: str
    data_root_receipt_handle: str
    data_root_id: str
    data_root_device: int
    data_root_inode: int
    data_root_owner_uid: int
    data_root_owner_gid: int
    target_id: str
    target_selection_handle: str
    target_receipt_handle: str
    effect_enrollment_ids: tuple[tuple[str, str], ...]
    view_device: int
    view_inode: int
    view_owner_uid: int
    view_owner_gid: int
    view_mode: int
    ownership_marker_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)
    _view: Any = field(repr=False, compare=False)
    _effect_rules: tuple[RootPreparedOwnerOverlayEffectEnrollment, ...] = field(repr=False, compare=False)
    _data_root_fd: int = field(repr=False, compare=False)
    _view_root_fd: int = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _VIEW_SEAL:
            raise TypeError("owned profile overlay views are root-issued")
        if (self.schema != 1 or not _PROFILE_ID.fullmatch(self.resource_profile_id)
                or not _PROFILE_ID.fullmatch(self.service_profile_id)
                or not re.fullmatch(r"[0-9a-f]{64}", self.prepared_generation_digest)
                or not re.fullmatch(r"[0-9a-f]{64}", self.resources_source_sha256)
                or not re.fullmatch(r"[0-9a-f]{64}", self.ownership_marker_sha256)
                or self.view_mode != 0o700 or self.expires_monotonic <= self.issued_monotonic
                or type(self._data_root_fd) is not int or self._data_root_fd < 0
                or type(self._view_root_fd) is not int or self._view_root_fd < 0):
            raise TypeError("owned profile overlay view receipt is malformed")
        if (not isinstance(self._effect_rules, tuple)
                or any(type(item) is not RootPreparedOwnerOverlayEffectEnrollment
                       or item._seal is not _ENROLLMENT_SEAL
                       or item.view_selection_handle != self.profile_view_selection_handle
                       or item.target_id != self.target_id for item in self._effect_rules)
                or tuple(sorted({(item.operation, item.effect_enrollment_id)
                                 for item in self._effect_rules})) != tuple(sorted(self.effect_enrollment_ids))):
            raise TypeError("profile overlay effect rules do not join the current view")

    def __repr__(self) -> str:
        return "RootPreparedOwnedProfileOverlayView(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedLocalProfileOperationBundle:
    """Retained owner-overlay joins for one exact current root selection."""

    schema: int
    bundle_handle: str
    setup_session_id: str
    transaction_handle: str
    prepared_generation_id: str
    native_policy_selection_handle: str
    profile_view_selection_handle: str
    operation_records: tuple[Mapping[str, Any], ...]
    operation_records_sha256: str
    pending_registration_records: tuple[Mapping[str, Any], ...]
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _BUNDLE_SEAL or self.schema != 1
                or not re.fullmatch(r"[0-9a-f]{64}", self.operation_records_sha256)
                or self.expires_monotonic <= self.issued_monotonic):
            raise TypeError("local profile operation bundles are root-issued")

    def __repr__(self) -> str:
        return "RootPreparedLocalProfileOperationBundle(<root-private>)"


class RootOwnedProfileOverlayViewRegistry:
    """Factory-backed issuer for an actual root-owned overlay directory.

    Directory creation and currentness are delegated to the sealed setup
    binding.  This registry only retains the returned typed receipt and checks
    object identity on every resolution.
    """

    def __init__(self, selected_installation_binding: Any, root_journal: Path):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding

        if (type(selected_installation_binding) is not RootSelectedInstallationBinding
                or not isinstance(root_journal, Path) or not root_journal.is_absolute()):
            raise ValueError("owned overlay registry requires the exact root setup binding and journal")
        self._binding = selected_installation_binding
        self._journal = root_journal
        self._views: dict[str, RootPreparedOwnedProfileOverlayView] = {}

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        root_journal: Path) -> "RootOwnedProfileOverlayViewRegistry":
        return cls(selected_installation_binding, root_journal)

    def prepare_selected_view(self, native_policy_selection_handle: str,
                              resource_profile_selection_handle: str) -> RootPreparedOwnedProfileOverlayView:
        if (not isinstance(native_policy_selection_handle, str) or not native_policy_selection_handle
                or not isinstance(resource_profile_selection_handle, str) or not resource_profile_selection_handle):
            raise LocalProfileOverlayEffectsDenied("a current root native policy/profile selection is required")
        try:
            receipt = self._binding.prepare_selected_profile_overlay_view(
                native_policy_selection_handle, resource_profile_selection_handle)
        except Exception:
            raise LocalProfileOverlayEffectsDenied("the selected root-owned profile overlay view is unavailable") from None
        if (type(receipt) is not RootPreparedOwnedProfileOverlayView
                or receipt.native_policy_selection_handle != native_policy_selection_handle
                or receipt.resource_profile_receipt_handle != resource_profile_selection_handle):
            raise LocalProfileOverlayEffectsDenied("factory returned an unbound profile overlay receipt")
        prior = self._views.get(receipt.profile_view_selection_handle)
        if prior is not None and prior is not receipt:
            raise LocalProfileOverlayEffectsDenied("profile overlay view handle was rebound")
        self._views[receipt.profile_view_selection_handle] = receipt
        return receipt

    def resolve_current(self, view_selection_handle: str,
                        native_policy_selection_handle: str) -> RootPreparedOwnedProfileOverlayView:
        receipt = self._views.get(view_selection_handle)
        if (receipt is None or receipt.native_policy_selection_handle != native_policy_selection_handle
                or receipt._seal is not _VIEW_SEAL):
            raise LocalProfileOverlayEffectsDenied("profile overlay view is not retained by this root registry")
        try:
            current = self._binding.resolve_current_profile_overlay_view(
                view_selection_handle, native_policy_selection_handle)
        except Exception:
            raise LocalProfileOverlayEffectsDenied("profile overlay view is stale or no longer owned") from None
        if current is not receipt:
            raise LocalProfileOverlayEffectsDenied("factory did not return the exact retained overlay view")
        return current

    def resolve_current_owner_overlay_target(self, native_policy_selection_handle: str,
                                             view: RootPreparedOwnedProfileOverlayView,
                                             operation: str) -> Any:
        current = self.resolve_current(view.profile_view_selection_handle,
                                       native_policy_selection_handle)
        if operation not in {"plugin.resource-overlay-store.read", "plugin.resource-overlay-store.write"}:
            raise LocalProfileOverlayEffectsDenied("owner-overlay operation is outside the fixed map")
        rows = [row for row in current._effect_rules if row.operation == operation]
        if (len(rows) != 1 or rows[0].expires_monotonic <= time.monotonic()
                or rows[0].principal_id != current.principal_id
                or rows[0].profile_id != current.service_profile_id
                or rows[0].namespace_id != current.namespace_id
                or rows[0].generation != current.service_generation):
            raise LocalProfileOverlayEffectsDenied("owner-overlay effect rule is not currently selected")
        return current, rows[0].effect_enrollment_id


class RootOwnerProfileOverlayEffects:
    """Compile only fully joined local profile-overlay operations.

    Owner-overlay registrations stay separate from backend action schemas.  A
    registration lacking any typed current receipt is retained as pending.
    """

    def __init__(self, selected_installation_binding: Any,
                 source_registration_registry: Any, schema_source_registry: Any,
                 owned_profile_view_registry: RootOwnedProfileOverlayViewRegistry,
                 selected_target_registry: Any, source_role_registry: Any,
                 root_journal: Path):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding

        if (type(selected_installation_binding) is not RootSelectedInstallationBinding
                or not isinstance(owned_profile_view_registry, RootOwnedProfileOverlayViewRegistry)
                or owned_profile_view_registry._binding is not selected_installation_binding
                or not isinstance(root_journal, Path) or not root_journal.is_absolute()):
            raise ValueError("owner overlay effects require current root source, schema, view, target, role and journal issuers")
        self._binding = selected_installation_binding
        self._source = source_registration_registry
        self._schemas = schema_source_registry
        self._views = owned_profile_view_registry
        self._targets = selected_target_registry
        self._roles = source_role_registry
        self._journal = root_journal
        self._bundles: dict[str, RootPreparedLocalProfileOperationBundle] = {}

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        source_registration_registry: Any,
                        schema_source_registry: Any,
                        owned_profile_view_registry: RootOwnedProfileOverlayViewRegistry,
                        selected_target_registry: Any, source_role_registry: Any,
                        root_journal: Path) -> "RootOwnerProfileOverlayEffects":
        return cls(selected_installation_binding, source_registration_registry,
                   schema_source_registry, owned_profile_view_registry,
                   selected_target_registry, source_role_registry, root_journal)

    def prepare_selected_operations(self, native_policy_selection_handle: str,
                                    profile_view_selection_handle: str
                                    ) -> RootPreparedLocalProfileOperationBundle:
        try:
            selection = self._binding.resolve_current_native_policy_selection(native_policy_selection_handle)
            selected = tuple(getattr(selection, "selected_owner_overlay_registration_ids", ()))
            view = self._views.resolve_current(profile_view_selection_handle, native_policy_selection_handle)
            coverage = self._source.resolve_source_coverage()
            if (view.profile_view_selection_handle != profile_view_selection_handle
                    or view.native_policy_selection_handle != native_policy_selection_handle
                    or view.prepared_generation_id != selection.prepared_generation_id
                    or view.setup_session_id != selection.setup_session_id
                    or view.transaction_handle != selection.transaction_handle
                    or view.service_profile_id != selection.service_profile_id
                    or view.service_generation != selection.service_generation
                    or view.resource_profile_receipt_handle != selection.resource_profile_selection_handle
                    or coverage.prepared_generation_id != selection.prepared_generation_id):
                raise ValueError
        except Exception:
            raise LocalProfileOverlayEffectsDenied("current overlay policy, profile, and source receipts do not join") from None
        if (len(selected) > 4 or len(set(selected)) != len(selected)
                or not set(selected) <= set(_REGISTRATIONS)):
            raise LocalProfileOverlayEffectsDenied("root policy selection exceeds the exact four owner-overlay registrations")

        captured = {f"{row.adapter_id}:tool:{row.native_tool_name}": row
                    for row in coverage.captured_registrations}
        observed = {row.registration_id: row for row in coverage.source_observations}
        definitions = {f"{row.adapter_id}:tool:{row.native_tool_name}": row
                       for row in coverage.reviewed_definitions}
        pending: list[Mapping[str, Any]] = []
        rows: list[Mapping[str, Any]] = []
        for registration_id in selected:
            method, operation = _REGISTRATIONS[registration_id]
            source = observed.get(registration_id)
            capture = captured.get(registration_id)
            definition = definitions.get(registration_id)
            missing: list[str] = []
            if source is None or capture is None or definition is None:
                missing.append("current-owner-overlay-registration-source-receipt")
            elif (source.handler_kind != "owner-overlay" or capture.adapter_id != "resource-overlay-store"
                  or source.native_tool_name != registration_id.rsplit(":", 1)[1]):
                raise LocalProfileOverlayEffectsDenied("owner-overlay source join differs from the pinned registration")
            schema_fields = self._resolve_schema_receipts(registration_id, source, capture, selection)
            if schema_fields is None:
                missing.append("current-owner-overlay-argument-and-result-schema-receipts")
            target = self._resolve_target(native_policy_selection_handle, view, operation)
            if target is None:
                missing.append("current-owner-overlay-target-and-effect-rule-receipt")
            role = self._resolve_source_role(native_policy_selection_handle, registration_id)
            if role is None:
                missing.append("selected-owner-overlay-source-role-observer-receipt")
            if missing:
                pending.append(MappingProxyType({
                    "registration_id": registration_id,
                    "configuration_state": "configurable-pending",
                    "missing_prerequisite_ids": tuple(missing),
                }))
                continue
            target_receipt, effect_enrollment_id = target
            schema_args, schema_result = schema_fields
            role_record = role
            row = {
                "registration_id": registration_id, "method": method,
                "operation": operation, "capability": _CAPABILITY,
                "target_id": view.target_id, "recipient": None,
                "effect_enrollment_id": effect_enrollment_id,
                "profile_id": view.service_profile_id,
                "profile_generation": view.service_generation,
                "principal_id": view.principal_id, "namespace_id": view.namespace_id,
                "package_id": selection.package_id,
                "package_generation": selection.native_package_generation,
                "argument_schema_id": schema_args[0],
                "argument_schema_sha256": schema_args[1],
                "argument_schema_receipt_handle": schema_args[2],
                "result_schema_id": schema_result[0], "result_schema_sha256": schema_result[1],
                "result_schema_receipt_handle": schema_result[2],
                "handler_artifact_id": source.registration_source_artifact_id,
                "handler_sha256": source.registration_source_sha256,
                "handler_source_receipt_handle": source.registration_source_receipt_handle,
                "profile_view_selection_handle": view.profile_view_selection_handle,
                "profile_view_receipt_handle": view.view_selection_handle,
                "data_root_selection_handle": view.data_root_selection_handle,
                "data_root_receipt_handle": view.data_root_receipt_handle,
                "target_selection_handle": target_receipt.selection_handle,
                "target_receipt_handle": view.target_receipt_handle,
                "prepared_source_observer_selection_handle": role_record[0],
                "source_observer_enrollment_ids": tuple(sorted(set(role_record[1]))),
                "process_role_id": role_record[2], "source_issuer_id": role_record[3],
            }
            rows.append(MappingProxyType(row))

        canonical_rows = tuple(dict(row) for row in rows)
        body = _canonical({"schema": 1, "rows": canonical_rows,
                           "pending": [dict(item) for item in pending]})
        now = time.monotonic()
        digest = hashlib.sha256(body).hexdigest()
        prior = next((item for item in self._bundles.values()
                      if item.native_policy_selection_handle == native_policy_selection_handle
                      and item.profile_view_selection_handle == profile_view_selection_handle
                      and item.operation_records_sha256 == digest
                      and item.expires_monotonic > now), None)
        if prior is not None:
            return prior
        bundle = RootPreparedLocalProfileOperationBundle(
            1, secrets.token_urlsafe(32), selection.setup_session_id,
            selection.transaction_handle, selection.prepared_generation_id,
            native_policy_selection_handle, profile_view_selection_handle,
            tuple(rows), hashlib.sha256(body).hexdigest(), tuple(pending), now,
            min(selection.expires_monotonic, view.expires_monotonic), _BUNDLE_SEAL,
        )
        self._bundles[bundle.bundle_handle] = bundle
        self._persist_bundle(bundle)
        return bundle

    def resolve_current(self, bundle_handle: str,
                        native_policy_selection_handle: str
                        ) -> RootPreparedLocalProfileOperationBundle:
        bundle = self._bundles.get(bundle_handle)
        if (bundle is None or bundle.native_policy_selection_handle != native_policy_selection_handle
                or bundle._seal is not _BUNDLE_SEAL or bundle.expires_monotonic <= time.monotonic()):
            raise LocalProfileOverlayEffectsDenied("owner-overlay operation bundle is absent, stale or unretained")
        try:
            selection = self._binding.resolve_current_native_policy_selection(native_policy_selection_handle)
            view = self._views.resolve_current(bundle.profile_view_selection_handle,
                                               native_policy_selection_handle)
            current = self.prepare_selected_operations(native_policy_selection_handle,
                                                       bundle.profile_view_selection_handle)
        except Exception:
            raise LocalProfileOverlayEffectsDenied("owner-overlay operation bundle currentness could not be revalidated") from None
        if (current.operation_records_sha256 != bundle.operation_records_sha256
                or current.operation_records != bundle.operation_records
                or current.pending_registration_records != bundle.pending_registration_records
                or selection.prepared_generation_id != bundle.prepared_generation_id
                or view.profile_view_selection_handle != bundle.profile_view_selection_handle):
            raise LocalProfileOverlayEffectsDenied("owner-overlay operation joins changed")
        return bundle

    def perform_selected_owner_overlay_operation(
            self, *, bundle_handle: str, native_policy_selection_handle: str,
            registration_id: str, canonical_argument_bytes: bytes,
            context: Any, authorization: Any,
    ) -> bytes:
        """Apply one root-selected CAS method after AuthorityService grant checks.

        The caller is the fixed root AuthorityService effect handler; it has
        already authenticated/consumed the signed grant and peer process.
        This method repeats the current selected-row, context, target, digest,
        and exact argument checks immediately before the effect.
        """
        bundle = self.resolve_current(bundle_handle, native_policy_selection_handle)
        row = next((item for item in bundle.operation_records
                    if item["registration_id"] == registration_id), None)
        if row is None or not isinstance(canonical_argument_bytes, bytes) or not canonical_argument_bytes:
            raise LocalProfileOverlayEffectsDenied("owner-overlay operation is not currently executable")
        try:
            from hermes_installer.authority.types import EffectAuthorization, HostContext, canonical_digest
            if (not isinstance(context, HostContext) or not isinstance(authorization, EffectAuthorization)
                    or context.principal_id != row["principal_id"]
                    or context.profile_id != row["profile_id"]
                    or authorization.operation != row["operation"]
                    or authorization.capability != row["capability"]
                    or authorization.target != row["target_id"]
                    or authorization.recipient is not None
                    or authorization.request_digest != canonical_digest(canonical_argument_bytes)):
                raise ValueError
            args = json.loads(canonical_argument_bytes)
            if not isinstance(args, dict) or _canonical(args) != canonical_argument_bytes:
                raise ValueError
            view = self._views.resolve_current(row["profile_view_selection_handle"],
                                               native_policy_selection_handle)
            if (view.service_profile_id != row["profile_id"]
                    or view.principal_id != context.principal_id
                    or view.namespace_id != context.namespace_id
                    or context.generation != row["profile_generation"]):
                raise ValueError
            result = _invoke_profile_view(view._view, row["method"], args)
            result_bytes = _canonical(result)
            coverage = self._source.resolve_source_coverage()
            source = next(item for item in coverage.source_observations
                          if item.registration_id == registration_id)
            capture = next(item for item in coverage.captured_registrations
                           if f"{item.adapter_id}:tool:{item.native_tool_name}" == registration_id)
            schema_receipts = self._resolve_schema_receipts(
                registration_id, source, capture,
                self._binding.resolve_current_native_policy_selection(native_policy_selection_handle),
            )
            if schema_receipts is None:
                raise ValueError
            result_schema = schema_receipts[1][3]
            parsed_result = json.loads(result_bytes)
            _validate_json_schema_instance(result_schema, parsed_result)
            if _canonical(parsed_result) != result_bytes:
                raise ValueError
            return result_bytes
        except LocalProfileOverlayEffectsDenied:
            raise
        except Exception:
            raise LocalProfileOverlayEffectsDenied("root-owned overlay method or grant validation failed") from None

    def _resolve_schema_receipts(self, registration_id: str, source: Any,
                                 capture: Any, selection: Any) -> Any | None:
        resolver = getattr(self._schemas, "resolve_owner_overlay_schemas", None)
        if not callable(resolver):
            return None
        try:
            args_receipt, result_receipt = resolver(registration_id, source, capture, selection)
            args_bytes = args_receipt.read_current()
            result_bytes = result_receipt.read_current()
            from .native_registration_projection import reviewed_packaged_registration_result_schemas
            reviewed_results = [row for row in reviewed_packaged_registration_result_schemas(
                self._source.resolve_source_coverage().captured_registrations)
                if row.native_tool_name == capture.native_tool_name]
            if len(reviewed_results) != 1:
                raise ValueError
            reviewed_result = reviewed_results[0]
            if (args_receipt.schema_kind != "argument"
                    or args_receipt.schema_id != f"installer-native-owner-overlay-arguments-{capture.native_tool_name}-v1"
                    or hashlib.sha256(args_bytes).hexdigest() != args_receipt.sha256
                    or json.loads(args_bytes) != capture.argument_schema
                    or args_receipt.registration_id != registration_id
                    or args_receipt.source_receipt_handle != source.registration_source_receipt_handle
                    or result_receipt.artifact_id != reviewed_result.artifact_id
                    or result_receipt.sha256 != reviewed_result.sha256
                    or hashlib.sha256(result_bytes).hexdigest() != reviewed_result.sha256
                    or json.loads(result_bytes) != reviewed_result.schema):
                raise ValueError
            return (args_receipt.schema_id, args_receipt.sha256,
                    args_receipt.artifact_receipt_handle, capture.argument_schema), (
                reviewed_result.schema_id, result_receipt.sha256,
                result_receipt.artifact_receipt_handle, reviewed_result.schema)
        except Exception:
            return None

    def _resolve_target(self, selection_handle: str,
                        view: RootPreparedOwnedProfileOverlayView,
                        operation: str) -> Any | None:
        resolver = getattr(self._targets, "resolve_current_owner_overlay_target", None)
        if not callable(resolver):
            resolver = self._views.resolve_current_owner_overlay_target
        if not callable(resolver):
            return None
        try:
            target, effect_id = resolver(selection_handle, view, operation)
            if (target.target_id != view.target_id or not isinstance(effect_id, str) or not effect_id):
                return None
            return target, effect_id
        except Exception:
            return None

    def _resolve_source_role(self, selection_handle: str, registration_id: str) -> Any | None:
        resolver = getattr(self._roles, "resolve_current_owner_overlay_role", None)
        if not callable(resolver):
            return None
        try:
            row = resolver(selection_handle, registration_id)
            if (not isinstance(row, tuple) or len(row) != 4
                    or any(not item for item in (row[0], row[2], row[3]))
                    or not isinstance(row[1], tuple) or not row[1]):
                return None
            return row
        except Exception:
            return None

    def _persist_bundle(self, bundle: RootPreparedLocalProfileOperationBundle) -> None:
        from hermes_installer.state import Journal
        try:
            Journal(self._journal / "native-owner-overlay-operations.sqlite3").event(
                "native-owner-overlay:" + bundle.bundle_handle,
                "bundle", "prepared", {
                    "bundle_sha256": bundle.operation_records_sha256,
                    "prepared_generation_id": bundle.prepared_generation_id,
                    "selected_operation_count": len(bundle.operation_records),
                    "pending_registration_count": len(bundle.pending_registration_records),
                })
        except Exception:
            raise LocalProfileOverlayEffectsDenied("root overlay operation journal is unavailable") from None


def _invoke_profile_view(view: Any, method: str, args: Mapping[str, Any]) -> Mapping[str, Any]:
    """Exact root method mapping; argument bytes remain the native payload."""
    from hermes_installer.components.native_plugins import _record_id, _tool_object
    if method in {"read", "history"}:
        fields = _tool_object(args, fields=frozenset({"record_id"}))
        record = _record_id(fields.get("record_id"))
        if method == "history":
            revisions = view.history(record)
            if (not isinstance(revisions, tuple) or len(revisions) > 256
                    or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                           for value in revisions)):
                raise ValueError("invalid overlay history")
            return {"record_id": record, "revisions": list(revisions)}
        value = view.read(record)
        if value is None or getattr(value, "deleted", False):
            return {"found": False, "record_id": record}
        body, revision = getattr(value, "value", None), getattr(value, "revision", None)
        if not isinstance(body, bytes) or len(body) > 1_048_576 or not isinstance(revision, str):
            raise ValueError("invalid overlay value")
        import base64
        return {"found": True, "record_id": record,
                "value_base64": base64.b64encode(body).decode("ascii"), "revision": revision}
    if method == "write":
        fields = _tool_object(args, fields=frozenset({"record_id", "expected_revision", "value_base64"}))
        record = _record_id(fields.get("record_id"))
        encoded = fields.get("value_base64")
        if not isinstance(encoded, str) or len(encoded) > 1_398_104:
            raise ValueError("overlay write exceeds its source bound")
        import base64
        body = base64.b64decode(encoded, validate=True)
        if len(body) > 1_048_576 or base64.b64encode(body).decode("ascii") != encoded:
            raise ValueError("overlay write value is not bounded canonical base64")
        expected = fields.get("expected_revision")
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise ValueError("overlay expected revision is invalid")
        revision = view.write(record, body, expected_revision=expected)
        return {"record_id": record, "revision": revision}
    if method == "delete":
        fields = _tool_object(args, fields=frozenset({"record_id", "expected_revision"}))
        record, expected = _record_id(fields.get("record_id")), fields.get("expected_revision")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("overlay delete requires an exact current revision")
        revision = view.delete(record, expected_revision=expected)
        return {"record_id": record, "deleted_revision": revision}
    raise ValueError("overlay method is not source-reviewed")


def _validate_json_schema_instance(schema: Mapping[str, Any], value: Any) -> None:
    """Validate the bounded JSON Schema subset used by the four local results."""
    if not isinstance(schema, Mapping) or len(schema) > 64:
        raise ValueError("overlay result schema is malformed")
    if "oneOf" in schema:
        choices = schema["oneOf"]
        if not isinstance(choices, list) or not choices or len(choices) > 4:
            raise ValueError("overlay result union schema is malformed")
        matches = 0
        for child in choices:
            try:
                _validate_json_schema_instance(child, value)
                matches += 1
            except (TypeError, ValueError):
                pass
        if matches != 1:
            raise ValueError("overlay result does not match exactly one result shape")
        return
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            raise TypeError("overlay result must be an object")
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if (not isinstance(properties, Mapping) or not isinstance(required, list)
                or not set(required) <= set(value)
                or schema.get("additionalProperties") is not False
                or set(value) - set(properties)):
            raise ValueError("overlay result object fields differ from its selected schema")
        for name, child_schema in properties.items():
            if name in value:
                _validate_json_schema_instance(child_schema, value[name])
        return
    if kind == "string":
        if not isinstance(value, str):
            raise TypeError("overlay result field must be text")
        if (len(value) < schema.get("minLength", 0)
                or len(value) > schema.get("maxLength", 2_000_000)):
            raise ValueError("overlay result text exceeds its selected schema bound")
        pattern = schema.get("pattern")
        if pattern is not None and (not isinstance(pattern, str) or re.fullmatch(pattern, value) is None):
            raise ValueError("overlay result text fails its selected schema pattern")
        if schema.get("contentEncoding") == "base64":
            import base64
            try:
                decoded = base64.b64decode(value, validate=True)
            except Exception:
                raise ValueError("overlay result base64 is invalid") from None
            if base64.b64encode(decoded).decode("ascii") != value:
                raise ValueError("overlay result base64 is not canonical")
        return
    if kind == "array":
        if (not isinstance(value, list) or len(value) > schema.get("maxItems", 256)
                or "items" not in schema):
            raise ValueError("overlay result array exceeds its selected schema")
        for item in value:
            _validate_json_schema_instance(schema["items"], item)
        return
    if kind == "boolean":
        if type(value) is not bool:
            raise TypeError("overlay result field must be boolean")
        return
    if "const" in schema:
        expected = schema["const"]
        if ((type(expected) is bool and type(value) is not bool)
                or type(value) is not type(expected) or value != expected):
            raise ValueError("overlay result field differs from its selected constant")
        return
    raise ValueError("overlay result schema uses an unsupported local keyword")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


_ACTIVE_LOCAL_OWNER_SEAL = object()


@dataclass(frozen=True, slots=True, repr=False)
class RootCurrentActiveLocalOwnerPrincipalSnapshot:
    """Short-lived current NSS and publication projection for a local owner."""

    snapshot_handle: str
    identity_kind: str
    source_choice_handle: str
    source_choice_sha256: str
    choice_epoch: int
    revocation_epoch: int
    owner_account_binding_sha256: str
    principal_id: str
    profile_id: str
    namespace_id: str
    service_uid: int
    service_gid: int
    profile_generation: str
    service_generation_digest: str
    active_publication_receipt_handle: str
    owner_instance: str
    observed_monotonic: float
    expires_monotonic: float
    adoption_sha256: str
    _seal: object = field(repr=False, compare=False)
    _issuer: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _ACTIVE_LOCAL_OWNER_SEAL
                or self.identity_kind != "linux-local-owner-v1"
                or self.expires_monotonic <= self.observed_monotonic):
            raise TypeError("active local-owner principal snapshots are root-issued")

    def verify_current(self, registry: Any) -> "RootCurrentActiveLocalOwnerPrincipalSnapshot":
        if registry is not self._issuer:
            raise LocalProfileOverlayEffectsDenied("active owner snapshot belongs to another root registry")
        return registry.verify_current(self)

    def __repr__(self) -> str:
        return "RootCurrentActiveLocalOwnerPrincipalSnapshot(<root-private>)"


class RootActiveLocalOwnerPrincipalRegistry:
    """Resolve a published local owner against current signed source, NSS and service custody.

    The registry holds no setup composer, setup view, or setup-session
    snapshot. Every issue and verification reopens the current publication and
    the fixed protected data-root/view recipe recorded in that publication.
    """

    def __init__(self, runtime: Any):
        from .runtime_composition import RootAuthorityRuntime
        from .root_setup_choices import RootSetupChoiceRegistry
        from .runtime_bindings import RootRuntimeBindings

        if (type(runtime) is not RootAuthorityRuntime
                or type(runtime.bindings) is not RootRuntimeBindings
                or type(runtime.root_setup_choice_registry) is not RootSetupChoiceRegistry
                or runtime.service.root_runtime_bindings is not runtime.bindings
                or runtime.boot_epoch != runtime.service.authority_epoch):
            raise LocalProfileOverlayEffectsDenied("active owner principal requires the attached root runtime")
        self._runtime = runtime
        self._boot_epoch = runtime.boot_epoch
        self._closed = False
        self._snapshots: dict[str, RootCurrentActiveLocalOwnerPrincipalSnapshot] = {}

    @classmethod
    def from_root_runtime(cls, runtime: Any) -> "RootActiveLocalOwnerPrincipalRegistry":
        return cls(runtime)

    def resolve_profile(self, profile_id: str) -> RootCurrentActiveLocalOwnerPrincipalSnapshot:
        if (self._closed or not isinstance(profile_id, str) or not profile_id
                or self._runtime.boot_epoch != self._boot_epoch):
            raise LocalProfileOverlayEffectsDenied("active local-owner profile selector is invalid or stale")
        from .setup_policy_publication import (
            PolicyPublicationReceiptResolver, PublishedSetupChoiceAdoption,
            _choice_adoption_value, validate_owner_overlay_adoption_row,
        )
        from hermes_installer.protected_enrollment import ProtectedEnrollmentCatalog
        try:
            receipt = PolicyPublicationReceiptResolver.resolve_current()
            if receipt.state != "active-committed" or not receipt.owner_overlay_adoption_records:
                raise ValueError
            rows = [validate_owner_overlay_adoption_row(row)
                    for row in receipt.owner_overlay_adoption_records]
            selected = [row for row in rows
                        if row["owner"].get("profile_id") == profile_id]
            if len(selected) != 1:
                raise ValueError
            row = selected[0]
            choice_handle = row["signed_choice"]["selection_handle"]
            choices = [item for item in receipt.choice_adoptions
                       if type(item) is PublishedSetupChoiceAdoption
                       and item.selection_handle == choice_handle
                       and item.purpose == "native-policy-preparation"]
            if len(choices) != 1:
                raise ValueError
            choice = choices[0]
            choice.verify_current(self._runtime.root_setup_choice_registry)
            choice_row = _choice_adoption_value(choice)
            choice_row = {key: value for key, value in choice_row.items()
                          if key not in {"publication_receipt_handle", "publication_sha256", "generation_id"}}
            if (choice_row != row["signed_choice"]
                    or choice.publication_receipt_handle != receipt.receipt_handle
                    or choice.publication_sha256 != receipt.publication_sha256
                    or choice.service_generation_digest != receipt.service_generation_digest
                    or row["owner"]["service_generation_digest"] != receipt.service_generation_digest):
                raise ValueError
            catalog = self._runtime.bindings.enrollment_catalog
            if (type(catalog) is not ProtectedEnrollmentCatalog
                    or catalog.digest != receipt.service_generation_digest):
                raise ValueError
            profiles = [item for item in catalog._records.values()
                        if item.profile_id == profile_id
                        and item.generation == row["owner"]["service_generation_id"]]
            if len(profiles) != 1:
                raise ValueError
            service = catalog.resolve(profiles[0].enrollment_id, profiles[0].generation)
            process_profile = self._runtime.bindings.process_profiles.get(profile_id)
            if (process_profile is None or process_profile.generation != service.generation
                    or process_profile.owner_uid != service.service_uid
                    or process_profile.owner_gid != service.service_gid
                    or process_profile.data_root != service.roots.data
                    or service.roots.data_id != row["view_custody"]["data_root_id"]
                    or service.service_uid != row["owner"]["service_uid"]
                    or service.service_gid != row["owner"]["service_gid"]):
                raise ValueError
            native_package = self._runtime.bindings.resolve_native_package(
                row["native_package"]["package_id"], row["native_package"]["generation"],
            )
            package_rows = getattr(native_package, "owner_overlay_operation_records", None)
            if (native_package.profile_id != profile_id
                    or native_package.profile_generation != service.generation
                    or not isinstance(package_rows, Mapping)
                    or _canonical([dict(item) for item in sorted(
                        package_rows.values(), key=lambda value: value["registration_id"])])
                       != _canonical(row["operation_records"])):
                raise ValueError
            import grp
            import os
            import pwd
            from hermes_installer.authority.bootstrap_runtime_factory import (
                _open_root_owned_profile_overlay_directory,
            )
            owner = row["owner"]
            account = pwd.getpwnam(owner["account_name"])
            group = grp.getgrgid(account.pw_gid)
            if (account.pw_uid != owner["account_uid"]
                    or account.pw_gid != owner["primary_gid"]
                    or group.gr_gid != owner["primary_gid"]
                    or account.pw_uid <= 0 or account.pw_uid == service.service_uid
                    or service.service_user != pwd.getpwuid(service.service_uid).pw_name):
                raise ValueError
            from hermes_installer.authority.bootstrap_enrollment import _read_machine_id
            account_digest = hashlib.sha256(_canonical({
                "name": account.pw_name, "uid": account.pw_uid,
                "primary_gid": account.pw_gid, "primary_group": group.gr_name,
            })).hexdigest()
            machine_target_digest = hashlib.sha256(_canonical({
                "machine_id": _read_machine_id(), "account_binding": account_digest,
            })).hexdigest()
            expected_principal_id = "linux-local-owner:" + hashlib.sha256(
                (machine_target_digest + "\0" + account_digest).encode()).hexdigest()
            expected_namespace_id = "hermes-native-" + hashlib.sha256(
                (expected_principal_id + "\0" + owner["profile_id"]).encode()).hexdigest()[:32]
            if (machine_target_digest != owner["machine_target_sha256"]
                    or expected_principal_id != owner["principal_id"]
                    or expected_namespace_id != owner["namespace_id"]):
                raise ValueError
            data_fd, view_fd, data_info, view_info, marker_info, marker = (
                _open_root_owned_profile_overlay_directory(
                    service.roots.data, service.service_uid, service.service_gid,
                    profile_id, row["view_custody"]["resource_profile_id"],
                ))
            try:
                view = row["view_custody"]
                if ((data_info.st_dev, data_info.st_ino, data_info.st_uid, data_info.st_gid)
                        != (view["data_root_device"], view["data_root_inode"],
                            view["data_root_owner_uid"], view["data_root_owner_gid"])
                        or (view_info.st_dev, view_info.st_ino, view_info.st_uid, view_info.st_gid,
                            __import__("stat").S_IMODE(view_info.st_mode))
                        != (view["view_device"], view["view_inode"], view["view_owner_uid"],
                            view["view_owner_gid"], view["view_mode"])
                        or hashlib.sha256(marker).hexdigest() != view["ownership_marker_sha256"]
                        or not __import__("stat").S_ISREG(marker_info.st_mode)):
                    raise ValueError
            finally:
                os.close(data_fd)
                os.close(view_fd)
            now = time.monotonic()
            snapshot = RootCurrentActiveLocalOwnerPrincipalSnapshot(
                secrets.token_urlsafe(32), "linux-local-owner-v1", choice_handle,
                choice.signed_record_sha256, choice.choice_epoch, choice.revocation_epoch,
                account_digest, owner["principal_id"], owner["profile_id"], owner["namespace_id"],
                service.service_uid, service.service_gid, service.generation,
                receipt.service_generation_digest, receipt.receipt_handle, self._boot_epoch,
                now, now + 30.0, row["adoption_sha256"], _ACTIVE_LOCAL_OWNER_SEAL, self,
            )
            for handle, prior in tuple(self._snapshots.items()):
                if prior.expires_monotonic <= now:
                    self._snapshots.pop(handle, None)
            if len(self._snapshots) >= 256:
                raise ValueError("active local-owner snapshot capacity is exhausted")
            self._snapshots[snapshot.snapshot_handle] = snapshot
            return snapshot
        except LocalProfileOverlayEffectsDenied:
            raise
        except Exception:
            raise LocalProfileOverlayEffectsDenied(
                "current publication, signed owner source, NSS, service enrollment, or held view did not revalidate",
            ) from None

    def verify_current(self, snapshot: RootCurrentActiveLocalOwnerPrincipalSnapshot
                       ) -> RootCurrentActiveLocalOwnerPrincipalSnapshot:
        if (self._closed or type(snapshot) is not RootCurrentActiveLocalOwnerPrincipalSnapshot
                or snapshot._issuer is not self or snapshot._seal is not _ACTIVE_LOCAL_OWNER_SEAL
                or self._snapshots.get(snapshot.snapshot_handle) is not snapshot
                or snapshot.expires_monotonic <= time.monotonic()
                or snapshot.owner_instance != self._boot_epoch):
            raise LocalProfileOverlayEffectsDenied("active local-owner snapshot is expired or unretained")
        current = self.resolve_profile(snapshot.profile_id)
        stable_fields = (
            "identity_kind", "source_choice_handle", "source_choice_sha256", "choice_epoch",
            "revocation_epoch", "owner_account_binding_sha256", "principal_id", "profile_id",
            "namespace_id", "service_uid", "service_gid", "profile_generation",
            "service_generation_digest", "active_publication_receipt_handle", "owner_instance",
            "adoption_sha256",
        )
        if any(getattr(current, name) != getattr(snapshot, name) for name in stable_fields):
            self._snapshots.pop(current.snapshot_handle, None)
            raise LocalProfileOverlayEffectsDenied("active local-owner principal or publication changed")
        self._snapshots.pop(current.snapshot_handle, None)
        self._snapshots[snapshot.snapshot_handle] = snapshot
        return snapshot

    def close(self) -> None:
        self._closed = True
        self._snapshots.clear()


_ACTIVE_OWNER_OVERLAY_SELECTION_SEAL = object()
_ACTIVE_OWNER_OVERLAY_SOURCE_OBSERVER_SEAL = object()
_ACTIVE_OWNER_OVERLAY_RESULT_OBSERVER_SEAL = object()
_OWNER_OVERLAY_GRANT_SEAL = object()
_OWNER_OVERLAY_PEER_SEAL = object()
_OWNER_OVERLAY_EFFECT_SEAL = object()


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedOwnerOverlayEffectGrant:
    invocation_handle: str
    selection_handle: str
    registration_id: str
    method: str
    arguments_sha256: str
    adoption_sha256: str
    operation_row_sha256: str
    nonce: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str
    _seal: object = field(repr=False, compare=False)
    _issuer: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _OWNER_OVERLAY_GRANT_SEAL
                or not _HEX.fullmatch(self.arguments_sha256)
                or not _HEX.fullmatch(self.adoption_sha256)
                or not _HEX.fullmatch(self.operation_row_sha256)
                or self.expires_monotonic <= self.issued_monotonic):
            raise TypeError("owner-overlay effect grants are root-issued typed records")

    def __repr__(self) -> str:
        return "RootSelectedOwnerOverlayEffectGrant(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootVerifiedOwnerOverlayPeer:
    uid: int
    pid: int
    pidfd: int = field(repr=False, compare=False)
    process_identity: Any = field(repr=False, compare=False)
    loaded_role_proof: Any = field(repr=False, compare=False)
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)
    _issuer: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _OWNER_OVERLAY_PEER_SEAL or self.uid <= 0 or self.pid <= 0
                or self.pidfd < 0 or self.expires_monotonic <= 0):
            raise TypeError("owner-overlay peers are root-issued live PIDFD records")


@dataclass(frozen=True, slots=True, repr=False)
class RootVerifiedOwnerOverlayEffect:
    invocation: Any = field(repr=False, compare=False)
    selection: Any = field(repr=False, compare=False)
    peer: RootVerifiedOwnerOverlayPeer = field(repr=False, compare=False)
    canonical_arguments: bytes = field(repr=False, compare=False)
    consumed_grant_nonce: str
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _OWNER_OVERLAY_EFFECT_SEAL:
            raise TypeError("verified owner-overlay effects are root-issued")


@dataclass(frozen=True, slots=True, repr=False)
class RootActiveOwnerOverlayInvocationSelection:
    """Root-only join of a published operation to a READY loaded registration."""

    selection_handle: str
    principal_snapshot: RootCurrentActiveLocalOwnerPrincipalSnapshot
    registration_id: str
    operation_record: Mapping[str, Any]
    adoption_sha256: str
    package_id: str
    package_generation: str
    process_identity: Any
    loaded_role_proof: Any
    peer_pid: int
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)
    _issuer: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _ACTIVE_OWNER_OVERLAY_SELECTION_SEAL
                or self.registration_id not in _REGISTRATIONS
                or self.expires_monotonic <= self.issued_monotonic):
            raise TypeError("active owner-overlay selections are root-issued")
        object.__setattr__(self, "operation_record", MappingProxyType(dict(self.operation_record)))

    def __repr__(self) -> str:
        return "RootActiveOwnerOverlayInvocationSelection(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootActiveOwnerOverlaySourceObserver:
    """Current, typed local source observer projected from a signed adoption."""

    observer_row: Mapping[str, Any]
    selection: RootActiveOwnerOverlayInvocationSelection
    capture_schemas: Mapping[str, tuple[bytes, str]]
    release_commit: str
    _seal: object = field(repr=False, compare=False)
    _issuer: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _ACTIVE_OWNER_OVERLAY_SOURCE_OBSERVER_SEAL
                or type(self.selection) is not RootActiveOwnerOverlayInvocationSelection
                or not isinstance(self.release_commit, str) or not self.release_commit):
            raise TypeError("owner-overlay source observers are root-issued active records")
        object.__setattr__(self, "observer_row", MappingProxyType(dict(self.observer_row)))
        object.__setattr__(self, "capture_schemas", MappingProxyType(dict(self.capture_schemas)))

    def __repr__(self) -> str:
        return "RootActiveOwnerOverlaySourceObserver(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootActiveOwnerOverlayResultSourceObserver:
    """Current signed tool-result selector plus held root-handler source."""

    observer_row: Mapping[str, Any]
    selection: RootActiveOwnerOverlayInvocationSelection
    invocation_source_observer: RootActiveOwnerOverlaySourceObserver
    enrollment: Any = field(repr=False, compare=False)
    result_handler_sha256: str
    result_handler_size_bytes: int
    release_commit: str
    _seal: object = field(repr=False, compare=False)
    _issuer: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _ACTIVE_OWNER_OVERLAY_RESULT_OBSERVER_SEAL
                or type(self.selection) is not RootActiveOwnerOverlayInvocationSelection
                or type(self.invocation_source_observer) is not RootActiveOwnerOverlaySourceObserver
                or self.invocation_source_observer._issuer is not self._issuer
                or not _HEX.fullmatch(self.result_handler_sha256)
                or type(self.result_handler_size_bytes) is not int
                or self.result_handler_size_bytes <= 0
                or not isinstance(self.release_commit, str) or not self.release_commit):
            raise TypeError("owner-overlay result observers are root-issued active records")
        object.__setattr__(self, "observer_row", MappingProxyType(dict(self.observer_row)))

    def __repr__(self) -> str:
        return "RootActiveOwnerOverlayResultSourceObserver(<root-private>)"


class RootActiveOwnerOverlayEffectAuthority:
    """Paired typed grant issuer/one-use journal for local owner operations."""

    def __init__(self, registry: Any):
        self._registry = registry
        self._grants: dict[str, tuple[RootSelectedOwnerOverlayEffectGrant, Any, Any, bytes]] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _claims(invocation: Any, selection: Any, peer: RootVerifiedOwnerOverlayPeer,
                arguments: bytes, nonce: str, issued: float, expires: float) -> dict[str, Any]:
        operation = selection.operation_record
        return {
            "domain": "native.owner-overlay.effect-grant.v1",
            "schema": 1, "invocation_handle": invocation.invocation_handle,
            "selection_handle": selection.selection_handle,
            "registration_id": selection.registration_id, "method": operation["method"],
            "arguments_sha256": hashlib.sha256(arguments).hexdigest(),
            "adoption_sha256": selection.adoption_sha256,
            "operation_row_sha256": hashlib.sha256(_canonical(dict(operation))).hexdigest(),
            "peer_uid": peer.uid, "peer_pid": peer.pid,
            "service_generation_digest": selection.principal_snapshot.service_generation_digest,
            "nonce": nonce, "issued_monotonic": issued, "expires_monotonic": expires,
        }

    def issue_selected_invocation(self, invocation: Any, selection: Any,
                                  canonical_argument_bytes: bytes,
                                  observed_peer: RootVerifiedOwnerOverlayPeer
                                  ) -> RootSelectedOwnerOverlayEffectGrant:
        from .native_runtime_observer import RootNativeOwnerOverlayInvocation
        registry = self._registry
        if (type(invocation) is not RootNativeOwnerOverlayInvocation
                or invocation._issuer is not registry._runtime.service.native_invocation_registry
                or type(selection) is not RootActiveOwnerOverlayInvocationSelection
                or selection._issuer is not registry
                or type(observed_peer) is not RootVerifiedOwnerOverlayPeer
                or observed_peer._seal is not _OWNER_OVERLAY_PEER_SEAL
                or observed_peer._issuer is not registry
                or not isinstance(canonical_argument_bytes, bytes)
                or invocation.canonical_arguments != canonical_argument_bytes
                or invocation.registration_id != selection.registration_id
                or invocation.source_observer.selection.adoption_sha256 != selection.adoption_sha256
                or observed_peer.pid != invocation.producer_pid
                or observed_peer.process_identity != invocation.producer_identity):
            raise LocalProfileOverlayEffectsDenied("owner-overlay invocation has no exact root peer grant")
        now = time.monotonic()
        expiry = min(now + 30.0, selection.expires_monotonic,
                     invocation.expires_monotonic, observed_peer.expires_monotonic)
        if expiry <= now:
            raise LocalProfileOverlayEffectsDenied("owner-overlay invocation grant is expired")
        nonce = secrets.token_urlsafe(32)
        claims = self._claims(invocation, selection, observed_peer,
                              canonical_argument_bytes, nonce, now, expiry)
        signature = registry._runtime.service._sign(claims)
        grant = RootSelectedOwnerOverlayEffectGrant(
            invocation.invocation_handle, selection.selection_handle,
            selection.registration_id, selection.operation_record["method"],
            hashlib.sha256(canonical_argument_bytes).hexdigest(),
            selection.adoption_sha256, claims["operation_row_sha256"], nonce,
            now, expiry, signature, _OWNER_OVERLAY_GRANT_SEAL, self,
        )
        with self._lock:
            if len(self._grants) >= 1024 or nonce in self._grants:
                raise LocalProfileOverlayEffectsDenied("owner-overlay grant issuer is at capacity")
            self._grants[nonce] = (grant, invocation, selection, bytes(canonical_argument_bytes))
        return grant

    def consume_selected_grant(self, grant: RootSelectedOwnerOverlayEffectGrant,
                               canonical_argument_bytes: bytes,
                               observed_peer: RootVerifiedOwnerOverlayPeer
                               ) -> RootVerifiedOwnerOverlayEffect:
        registry = self._registry
        with self._lock:
            retained = self._grants.get(getattr(grant, "nonce", None))
            if (type(grant) is not RootSelectedOwnerOverlayEffectGrant
                    or grant._seal is not _OWNER_OVERLAY_GRANT_SEAL or grant._issuer is not self
                    or retained is None or retained[0] is not grant
                    or retained[3] != canonical_argument_bytes
                    or type(observed_peer) is not RootVerifiedOwnerOverlayPeer
                    or observed_peer._issuer is not registry
                    or observed_peer._seal is not _OWNER_OVERLAY_PEER_SEAL
                    or observed_peer.pid != retained[1].producer_pid
                    or observed_peer.uid != retained[1].bridge.producer_uid
                    or observed_peer.process_identity != retained[1].producer_identity
                    or grant.expires_monotonic <= time.monotonic()):
                raise LocalProfileOverlayEffectsDenied("owner-overlay grant is unknown, stale, or consumed")
            invocation, selection = retained[1], retained[2]
            claims = self._claims(invocation, selection, observed_peer,
                                  canonical_argument_bytes, grant.nonce,
                                  grant.issued_monotonic, grant.expires_monotonic)
            if (registry._runtime.service._sign(claims) != grant.signature
                    or hashlib.sha256(canonical_argument_bytes).hexdigest() != grant.arguments_sha256
                    or grant.registration_id != selection.registration_id
                    or grant.adoption_sha256 != selection.adoption_sha256
                    or grant.operation_row_sha256 != claims["operation_row_sha256"]):
                raise LocalProfileOverlayEffectsDenied("owner-overlay grant signature or row binding changed")
            registry.verify_current(selection)
            try:
                journal = registry._effect_journal()
                with journal._transaction() as db:
                    db.execute("CREATE TABLE IF NOT EXISTS owner_overlay_grants (nonce TEXT PRIMARY KEY, invocation_handle TEXT NOT NULL, registration_id TEXT NOT NULL, arguments_sha256 TEXT NOT NULL, adoption_sha256 TEXT NOT NULL, issued_monotonic REAL NOT NULL, expires_monotonic REAL NOT NULL)")
                    db.execute(
                        "INSERT INTO owner_overlay_grants VALUES(?,?,?,?,?,?,?)",
                        (grant.nonce, grant.invocation_handle, grant.registration_id,
                         grant.arguments_sha256, grant.adoption_sha256,
                         grant.issued_monotonic, grant.expires_monotonic),
                    )
            except Exception:
                raise LocalProfileOverlayEffectsDenied("owner-overlay one-use journal rejected the grant") from None
            self._grants.pop(grant.nonce, None)
            return RootVerifiedOwnerOverlayEffect(
                invocation, selection, observed_peer, bytes(canonical_argument_bytes),
                grant.nonce, _OWNER_OVERLAY_EFFECT_SEAL,
            )

    def issue_selected_result_capture(self, verified_effect: RootVerifiedOwnerOverlayEffect,
                                      result_observer: RootActiveOwnerOverlayResultSourceObserver,
                                      canonical_result_bytes: bytes) -> str:
        """Delegate the separate result capture through this effect authority."""
        return self._registry._issue_selected_result_capture(
            verified_effect, result_observer, canonical_result_bytes)

    def record_completed_effect(self, effect: RootVerifiedOwnerOverlayEffect,
                                canonical_result_bytes: bytes) -> str:
        """Durably record the actual CAS/read result before source capture."""
        registry = self._registry
        if (type(effect) is not RootVerifiedOwnerOverlayEffect
                or effect._seal is not _OWNER_OVERLAY_EFFECT_SEAL
                or effect.selection._issuer is not registry
                or effect.invocation.invocation_handle == ""
                or not isinstance(canonical_result_bytes, bytes) or not canonical_result_bytes):
            raise LocalProfileOverlayEffectsDenied("owner-overlay completion lacks its consumed effect")
        digest = hashlib.sha256(canonical_result_bytes).hexdigest()
        try:
            journal = registry._effect_journal()
            with journal._transaction() as db:
                db.execute("CREATE TABLE IF NOT EXISTS owner_overlay_effect_completions (nonce TEXT PRIMARY KEY, invocation_handle TEXT NOT NULL, registration_id TEXT NOT NULL, arguments_sha256 TEXT NOT NULL, adoption_sha256 TEXT NOT NULL, result_sha256 TEXT NOT NULL, completed_monotonic REAL NOT NULL, result_receipt_handle TEXT)")
                db.execute(
                    "INSERT INTO owner_overlay_effect_completions VALUES(?,?,?,?,?,?,?,NULL)",
                    (effect.consumed_grant_nonce, effect.invocation.invocation_handle,
                     effect.selection.registration_id, hashlib.sha256(effect.canonical_arguments).hexdigest(),
                     effect.selection.adoption_sha256, digest, time.monotonic()),
                )
        except Exception:
            raise LocalProfileOverlayEffectsDenied(
                "completed owner-overlay operation could not be journaled for reconciliation") from None
        return digest

    def verify_completed_effect(self, effect: RootVerifiedOwnerOverlayEffect,
                                result_sha256: str) -> bool:
        registry = self._registry
        if (type(effect) is not RootVerifiedOwnerOverlayEffect
                or effect._seal is not _OWNER_OVERLAY_EFFECT_SEAL
                or effect.selection._issuer is not registry
                or not _HEX.fullmatch(result_sha256)):
            raise LocalProfileOverlayEffectsDenied("owner-overlay completion proof is malformed")
        registry.verify_current(effect.selection)
        try:
            journal = registry._effect_journal()
            with journal._lock:
                row = journal._connection.execute(
                    "SELECT invocation_handle,registration_id,arguments_sha256,adoption_sha256,result_sha256 FROM owner_overlay_effect_completions WHERE nonce=?",
                    (effect.consumed_grant_nonce,),
                ).fetchone()
        except Exception:
            row = None
        expected = (effect.invocation.invocation_handle, effect.selection.registration_id,
                    hashlib.sha256(effect.canonical_arguments).hexdigest(),
                    effect.selection.adoption_sha256, result_sha256)
        if row != expected:
            raise LocalProfileOverlayEffectsDenied("owner-overlay CAS completion is not journaled")
        return True

    def record_result_capture(self, effect: RootVerifiedOwnerOverlayEffect,
                              receipt_handle: str) -> None:
        if (not isinstance(receipt_handle, str) or not receipt_handle
                or not self.verify_completed_effect(
                    effect, self._completed_result_digest(effect.consumed_grant_nonce))):
            raise LocalProfileOverlayEffectsDenied("owner-overlay result receipt has no completed effect")
        journal = self._registry._effect_journal()
        with journal._transaction() as db:
            cursor = db.execute(
                "UPDATE owner_overlay_effect_completions SET result_receipt_handle=? WHERE nonce=? AND result_receipt_handle IS NULL",
                (receipt_handle, effect.consumed_grant_nonce),
            )
            if cursor.rowcount != 1:
                raise LocalProfileOverlayEffectsDenied("owner-overlay result receipt is already recorded")

    def _completed_result_digest(self, nonce: str) -> str:
        journal = self._registry._effect_journal()
        with journal._lock:
            row = journal._connection.execute(
                "SELECT result_sha256 FROM owner_overlay_effect_completions WHERE nonce=?", (nonce,)
            ).fetchone()
        if row is None or not isinstance(row[0], str):
            raise LocalProfileOverlayEffectsDenied("owner-overlay completion record is unavailable")
        return row[0]


class RootActiveOwnerOverlayRegistry:
    """Rejoin signed owner adoption, current NSS/view, package and READY role.

    This registry deliberately does not consume setup composer/view objects.
    Its selections are provenance and invocation inputs only; effect issuance
    still requires the separate typed service grant and one-use CAS proxy.
    """

    def __init__(self, runtime: Any, principal_registry: RootActiveLocalOwnerPrincipalRegistry):
        from .runtime_composition import RootAuthorityRuntime
        from .runtime_bindings import RootRuntimeBindings
        from .native_custody_proof import RootNativeLoaderObservationStore

        if (type(runtime) is not RootAuthorityRuntime
                or type(runtime.bindings) is not RootRuntimeBindings
                or type(principal_registry) is not RootActiveLocalOwnerPrincipalRegistry
                or principal_registry._runtime is not runtime
                or runtime.native_loader_observation_store is None
                or type(runtime.native_loader_observation_store) is not RootNativeLoaderObservationStore
                or not callable(getattr(runtime.process_manager, "resolve_native_package_for_peer", None))
                or not callable(getattr(runtime.process_manager, "resolve_live_peer", None))):
            raise LocalProfileOverlayEffectsDenied("active owner-overlay runtime dependencies are incomplete")
        self._runtime = runtime
        self._principals = principal_registry
        self._closed = False
        self._selections: dict[str, RootActiveOwnerOverlayInvocationSelection] = {}
        self._peer_fds: dict[str, int] = {}
        self._lock = threading.RLock()
        self._effect_authority = RootActiveOwnerOverlayEffectAuthority(self)

    @classmethod
    def from_root_runtime(cls, runtime: Any,
                          principal_registry: RootActiveLocalOwnerPrincipalRegistry
                          ) -> "RootActiveOwnerOverlayRegistry":
        return cls(runtime, principal_registry)

    def _effect_journal(self) -> Any:
        from .runtime_composition import _root_resource_job_ledger_path
        from hermes_installer.state import Journal
        path = _root_resource_job_ledger_path(self._runtime.bindings, self._runtime.enrollment)
        return Journal(path.parent / "native-owner-overlay-cas.sqlite3")

    def resolve_selected_operation(self, registration_id: str, peer_pid: int,
                                   peer_pidfd: int) -> RootActiveOwnerOverlayInvocationSelection:
        """Resolve one operation only for the actual peer with a later READY event."""
        from .setup_policy_publication import PolicyPublicationReceiptResolver, validate_owner_overlay_adoption_row
        from .native_custody_proof import LivePeerProcess, RootActiveOwnerOverlayLoaderObserver

        if (self._closed or registration_id not in _REGISTRATIONS
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0):
            raise LocalProfileOverlayEffectsDenied("active owner-overlay peer or method is invalid")
        try:
            receipt = PolicyPublicationReceiptResolver.resolve_current()
            if receipt.state != "active-committed":
                raise ValueError
            rows = [validate_owner_overlay_adoption_row(row)
                    for row in receipt.owner_overlay_adoption_records]
            matches = [(row, operation) for row in rows
                       for operation in row["operation_records"]
                       if operation["registration_id"] == registration_id]
            candidates = []
            for row, operation in matches:
                principal = self._principals.resolve_profile(row["owner"]["profile_id"])
                if (principal.identity_kind == row["identity_kind"]
                        and principal.principal_id == row["owner"]["principal_id"]
                        and principal.namespace_id == row["owner"]["namespace_id"]
                        and principal.adoption_sha256 == row["adoption_sha256"]):
                    candidates.append((row, operation, principal))
            if len(candidates) != 1:
                raise ValueError
            adoption, operation, principal = candidates[0]
            package = self._runtime.bindings.resolve_native_package(
                adoption["native_package"]["package_id"], adoption["native_package"]["generation"],
            )
            package_operations = getattr(package, "owner_overlay_operation_records", None)
            if (package.profile_id != principal.profile_id
                    or package.generation != adoption["native_package"]["generation"]
                    or not isinstance(package_operations, Mapping)
                    or _canonical([dict(item) for _, item in sorted(package_operations.items())])
                       != _canonical(adoption["operation_records"])):
                raise ValueError
            manager = self._runtime.process_manager
            mount_proof = manager.resolve_native_package_for_peer(peer_pid, peer_pidfd)
            if (mount_proof is None
                    or mount_proof.profile_id != principal.profile_id
                    or mount_proof.generation != principal.profile_generation
                    or mount_proof.mount.package_id != package.package_id
                    or mount_proof.mount.compiled_closure_sha256
                       != adoption["native_package"]["compiled_closure_sha256"]
                    or mount_proof.mount.entrypoint_sha256 != adoption["native_package"]["entrypoint_sha256"]
                    or mount_proof.mount.resolver_sha256 != adoption["native_package"]["resolver_sha256"]):
                raise ValueError
            identity = manager.resolve_live_peer(
                peer_pid, peer_pidfd, profile_id=principal.profile_id,
                generation=principal.profile_generation,
            )
            if (identity is None or identity.kernel_uid != principal.service_uid
                    or identity != (self._runtime.native_loader_observation_store
                                    .custody_resolver.resolve_live_peer(
                                        peer_pid, peer_pidfd, profile_id=principal.profile_id,
                                        generation=principal.profile_generation))):
                raise ValueError
            roles = getattr(package, "process_role_records", None)
            role = roles.get(operation["process_role_id"]) if isinstance(roles, Mapping) else None
            observer_ids = tuple(operation["source_observer_enrollment_ids"])
            owner_observer_rows = [item for item in adoption["owner_overlay_observer_records"]
                                   if item["registration_id"] == registration_id]
            if len(owner_observer_rows) != 1:
                raise ValueError
            invocation_observer_id = owner_observer_rows[0]["observer_enrollment_id"]
            source_members = [item for item in adoption["source_members"]
                              if item["role"] == "native-source-module"
                              and item["artifact_id"] == getattr(role, "role_artifact_id", None)]
            if (role is None or invocation_observer_id not in observer_ids
                    or invocation_observer_id not in getattr(role, "observer_enrollment_ids", ())
                    or registration_id not in getattr(role, "registration_ids", ())
                    or len(source_members) != 1
                    or source_members[0]["sha256"] != role.role_sha256
                    or source_members[0]["receipt_handle"] != role.role_source_receipt_handle):
                raise ValueError
            observer = RootActiveOwnerOverlayLoaderObserver._issue(
                observer_enrollment_id=invocation_observer_id, profile_id=principal.profile_id,
                generation=principal.profile_generation, package_id=package.package_id,
                native_package_generation=package.generation, role_id=role.role_id,
                role_artifact_id=role.role_artifact_id, role_sha256=role.role_sha256,
                role_source_receipt_handle=role.role_source_receipt_handle,
                role_module_name=role.module_name, role_closure_member_path=role.closure_member_path,
                role_source_revision=role.role_source_revision,
                role_source_tree_sha256=role.role_source_tree_sha256,
                registration_id=registration_id, lease_seconds=30,
            )
            loaded = self._runtime.native_loader_observation_store.resolve_loaded_package_closure(
                LivePeerProcess(peer_pid, peer_pidfd, identity), observer,
            )
            if (loaded.package_id != package.package_id or loaded.profile_id != principal.profile_id
                    or loaded.generation != principal.profile_generation
                    or loaded.role_id != role.role_id
                    or registration_id not in loaded.observed_registration_ids):
                raise ValueError
            view = adoption["view_custody"]
            data_fd, view_fd, data_info, view_info, marker_info, marker = (
                __import__("hermes_installer.authority.bootstrap_runtime_factory",
                           fromlist=["_open_root_owned_profile_overlay_directory"])
                ._open_root_owned_profile_overlay_directory(
                    self._runtime.bindings.process_profiles[principal.profile_id].data_root,
                    principal.service_uid, principal.service_gid, principal.profile_id,
                    view["resource_profile_id"],
                ))
            try:
                if ((data_info.st_dev, data_info.st_ino, data_info.st_uid, data_info.st_gid)
                        != (view["data_root_device"], view["data_root_inode"],
                            view["data_root_owner_uid"], view["data_root_owner_gid"])
                        or (view_info.st_dev, view_info.st_ino, view_info.st_uid, view_info.st_gid,
                            stat.S_IMODE(view_info.st_mode))
                        != (view["view_device"], view["view_inode"], view["view_owner_uid"],
                            view["view_owner_gid"], view["view_mode"])
                        or hashlib.sha256(marker).hexdigest() != view["ownership_marker_sha256"]
                        or not stat.S_ISREG(marker_info.st_mode)
                        or operation["target_id"] != view["target_id"]
                        or operation["target_receipt_handle"] != view["target_receipt_handle"]
                        or [operation["operation"], operation["effect_enrollment_id"]]
                           not in view["effect_enrollment_ids"]):
                    raise ValueError
            finally:
                os.close(data_fd)
                os.close(view_fd)
            now = time.monotonic()
            expires = min(now + 30.0, principal.expires_monotonic, loaded.expires_monotonic)
            if expires <= now:
                raise ValueError
            selection = RootActiveOwnerOverlayInvocationSelection(
                secrets.token_urlsafe(32), principal, registration_id, operation,
                adoption["adoption_sha256"], package.package_id, package.generation,
                identity, loaded, peer_pid, now, expires,
                _ACTIVE_OWNER_OVERLAY_SELECTION_SEAL, self,
            )
            retained_fd = os.dup(peer_pidfd)
            with self._lock:
                if self._closed:
                    os.close(retained_fd)
                    raise ValueError
                for handle, prior in tuple(self._selections.items()):
                    if prior.expires_monotonic <= now:
                        self._retire(handle)
                if len(self._selections) >= 128:
                    os.close(retained_fd)
                    raise ValueError
                self._selections[selection.selection_handle] = selection
                self._peer_fds[selection.selection_handle] = retained_fd
            return selection
        except LocalProfileOverlayEffectsDenied:
            raise
        except Exception:
            raise LocalProfileOverlayEffectsDenied(
                "active publication, operation row, live peer, READY role or held view did not revalidate",
            ) from None

    def verify_current(self, selection: RootActiveOwnerOverlayInvocationSelection
                       ) -> RootActiveOwnerOverlayInvocationSelection:
        if (self._closed or type(selection) is not RootActiveOwnerOverlayInvocationSelection
                or selection._seal is not _ACTIVE_OWNER_OVERLAY_SELECTION_SEAL
                or selection._issuer is not self
                or self._selections.get(selection.selection_handle) is not selection
                or selection.expires_monotonic <= time.monotonic()):
            raise LocalProfileOverlayEffectsDenied("active owner-overlay selection is expired or unretained")
        pidfd = self._peer_fds.get(selection.selection_handle)
        if pidfd is None:
            raise LocalProfileOverlayEffectsDenied("active owner-overlay peer descriptor is not retained")
        current = self.resolve_selected_operation(selection.registration_id, selection.peer_pid, pidfd)
        if (current.operation_record != selection.operation_record
                or current.adoption_sha256 != selection.adoption_sha256
                or current.loaded_role_proof != selection.loaded_role_proof
                or current.process_identity != selection.process_identity):
            self._retire(selection.selection_handle)
            raise LocalProfileOverlayEffectsDenied("active owner-overlay selection changed")
        self._retire(current.selection_handle)
        return selection

    def execute_selected(self, grant: RootSelectedOwnerOverlayEffectGrant,
                         canonical_argument_bytes: bytes,
                         observed_peer: RootVerifiedOwnerOverlayPeer) -> bytes:
        """Consume a typed one-use grant and perform only the four root CAS calls."""
        from .native_runtime_observer import RootNativeOwnerOverlayInvocation
        from .setup_policy_publication import PolicyPublicationReceiptResolver, validate_owner_overlay_adoption_row
        from .runtime_composition import _native_json_schema_matches
        from .types import strict_json_loads
        from hermes_installer.mcp.native_schema_catalog import NativeMCPProtectedSchemaCatalog
        from hermes_installer.registry.resources_runtime import RootAnchoredProfileOverlayView

        if (type(grant) is not RootSelectedOwnerOverlayEffectGrant
                or type(observed_peer) is not RootVerifiedOwnerOverlayPeer
                or type(canonical_argument_bytes) is not bytes):
            raise LocalProfileOverlayEffectsDenied("owner-overlay execution inputs are not root typed")
        with self._lock:
            effect = self._effect_authority.consume_selected_grant(
                grant, canonical_argument_bytes, observed_peer)
            if type(effect.invocation) is not RootNativeOwnerOverlayInvocation:
                raise LocalProfileOverlayEffectsDenied("owner-overlay grant has no captured invocation")
            selection = self.verify_current(effect.selection)
            operation = selection.operation_record
            if (operation["registration_id"] != effect.invocation.registration_id
                    or operation["method"] != effect.invocation.method
                    or hashlib.sha256(canonical_argument_bytes).hexdigest()
                       != effect.invocation.arguments_sha256):
                raise LocalProfileOverlayEffectsDenied("owner-overlay invocation changed before CAS")
            owner_source = self.resolve_current_source_observer(
                selection.registration_id, observed_peer.pid, observed_peer.pidfd)
            if (owner_source.selection.adoption_sha256 != selection.adoption_sha256
                    or owner_source.observer_row["operation_row_sha256"]
                       != hashlib.sha256(_canonical(dict(operation))).hexdigest()):
                self._retire(owner_source.selection.selection_handle)
                raise LocalProfileOverlayEffectsDenied("owner-overlay signed source row changed before CAS")
            catalog = getattr(getattr(self._runtime.service.native_invocation_registry,
                                      "action_resolver", None), "schema_catalog", None)
            if type(catalog) is not NativeMCPProtectedSchemaCatalog:
                self._retire(owner_source.selection.selection_handle)
                raise LocalProfileOverlayEffectsDenied("current owner operation schema catalog is unavailable")
            try:
                args = strict_json_loads(canonical_argument_bytes.decode("utf-8", errors="strict"))
                argument_schema = catalog.resolve(
                    operation["argument_schema_id"], native_package_id=selection.package_id,
                    native_package_generation=selection.package_generation,
                    adapter_id="resource-overlay-store", action_id=selection.registration_id,
                    schema_kind="arguments")
                if (not _native_json_schema_matches(args, argument_schema)
                        or json.dumps(args, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False, allow_nan=False).encode("utf-8")
                           != canonical_argument_bytes):
                    raise ValueError
                receipt = PolicyPublicationReceiptResolver.resolve_current()
                adoptions = [validate_owner_overlay_adoption_row(item)
                             for item in receipt.owner_overlay_adoption_records
                             if item.get("adoption_sha256") == selection.adoption_sha256]
                if len(adoptions) != 1:
                    raise ValueError
                adoption = adoptions[0]
                observer = self._resolve_owner_result_observer(selection, operation, owner_source)
                view_row = adoption["view_custody"]
                profile = self._runtime.bindings.process_profiles[selection.principal_snapshot.profile_id]
                data_fd, view_fd, data_info, view_info, marker_info, marker = (
                    __import__("hermes_installer.authority.bootstrap_runtime_factory",
                               fromlist=["_open_root_owned_profile_overlay_directory"])
                    ._open_root_owned_profile_overlay_directory(
                        profile.data_root, selection.principal_snapshot.service_uid,
                        selection.principal_snapshot.service_gid,
                        selection.principal_snapshot.profile_id, view_row["resource_profile_id"],
                    ))
                try:
                    if ((data_info.st_dev, data_info.st_ino, data_info.st_uid, data_info.st_gid)
                            != (view_row["data_root_device"], view_row["data_root_inode"],
                                view_row["data_root_owner_uid"], view_row["data_root_owner_gid"])
                            or (view_info.st_dev, view_info.st_ino, view_info.st_uid,
                                view_info.st_gid, stat.S_IMODE(view_info.st_mode))
                            != (view_row["view_device"], view_row["view_inode"],
                                view_row["view_owner_uid"], view_row["view_owner_gid"],
                                view_row["view_mode"])
                            or hashlib.sha256(marker).hexdigest() != view_row["ownership_marker_sha256"]
                            or not stat.S_ISREG(marker_info.st_mode)):
                        raise ValueError
                    from .runtime_composition import _root_resource_job_ledger_path
                    from hermes_installer.state import Journal
                    journal_path = _root_resource_job_ledger_path(
                        self._runtime.bindings, self._runtime.enrollment)
                    view = RootAnchoredProfileOverlayView(
                        view_fd, view_row["resource_profile_id"],
                        Journal(journal_path.parent / "native-owner-overlay-cas.sqlite3"),
                    )
                    result_value = _invoke_profile_view(view, operation["method"], args)
                finally:
                    os.close(data_fd)
                    os.close(view_fd)
                result_bytes = json.dumps(result_value, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=False, allow_nan=False).encode("utf-8")
                self._effect_authority.record_completed_effect(effect, result_bytes)
                result_schema = catalog.resolve(
                    operation["result_schema_id"], native_package_id=selection.package_id,
                    native_package_generation=selection.package_generation,
                    adapter_id="resource-overlay-store", action_id=selection.registration_id,
                    schema_kind="result")
                result_artifact = catalog._by_id[operation["result_schema_id"]]
                if (result_artifact.sha256 != operation["result_schema_sha256"]
                        or not _native_json_schema_matches(result_value, result_schema)):
                    raise ValueError
            except Exception:
                self._retire(owner_source.selection.selection_handle)
                raise LocalProfileOverlayEffectsDenied(
                    "current view custody, target, schema, or CAS operation rejected",
                ) from None
            finally:
                self._retire(owner_source.selection.selection_handle)
            result_digest = hashlib.sha256(result_bytes).hexdigest()
            parent_handles = tuple(dict.fromkeys(effect.invocation.parent_source_receipt_handles))
            if not parent_handles or len(parent_handles) > 64:
                raise LocalProfileOverlayEffectsDenied("owner-overlay result has no bounded source parent closure")
            self._effect_authority.issue_selected_result_capture(effect, observer, result_bytes)
            return result_bytes

    def _resolve_owner_result_observer(self, selection: RootActiveOwnerOverlayInvocationSelection,
                                       operation: Mapping[str, Any],
                                       invocation_source_observer: RootActiveOwnerOverlaySourceObserver
                                       ) -> RootActiveOwnerOverlayResultSourceObserver:
        return self.resolve_current_result_source_observer(selection, invocation_source_observer)

    def resolve_current_result_source_observer(
            self, selection: RootActiveOwnerOverlayInvocationSelection,
            invocation_source_observer: RootActiveOwnerOverlaySourceObserver
            ) -> RootActiveOwnerOverlayResultSourceObserver:
        """Resolve only the separately signed v188 result enrollment and root handler."""
        from .setup_policy_publication import PolicyPublicationReceiptResolver, validate_owner_overlay_adoption_row
        from .source_observers import SourceObserverEnrollment
        from .installer_release import InstalledRootReleaseVerifier
        from .owner_overlay_capture_schemas import RESULT_SCHEMA_ID

        try:
            if (type(selection) is not RootActiveOwnerOverlayInvocationSelection
                    or selection._issuer is not self
                    or type(invocation_source_observer) is not RootActiveOwnerOverlaySourceObserver
                    or invocation_source_observer._issuer is not self
                    or invocation_source_observer.selection.adoption_sha256 != selection.adoption_sha256
                    or invocation_source_observer.observer_row["registration_id"] != selection.registration_id):
                raise ValueError
            self.verify_current(selection)
            receipt = PolicyPublicationReceiptResolver.resolve_current()
            if receipt.state != "active-committed":
                raise ValueError
            adoptions = [validate_owner_overlay_adoption_row(item)
                         for item in receipt.owner_overlay_adoption_records
                         if item.get("adoption_sha256") == selection.adoption_sha256]
            if len(adoptions) != 1:
                raise ValueError
            adoption = adoptions[0]
            rows = [dict(row) for row in adoption["owner_overlay_observer_records"]
                    if row.get("registration_id") == selection.registration_id]
            if len(rows) != 1:
                raise ValueError
            row = rows[0]
            invocation_row = invocation_source_observer.observer_row
            observer_id = row["result_observer_enrollment_id"]
            if (invocation_row["observer_enrollment_id"] != row["observer_enrollment_id"]
                    or row["result_observer_enrollment_id"] == row["observer_enrollment_id"]
                    or row["result_capture_schema_id"] != RESULT_SCHEMA_ID
                    or row["result_handler_artifact_id"]
                       != "installer-module:hermes_installer.authority.local_resource_effects"
                    or row["result_handler_module_name"]
                       != "hermes_installer.authority.local_resource_effects"
                    or row["result_handler_closure_member_path"]
                       != "lib/python/hermes_installer/authority/local_resource_effects.py"):
                raise ValueError
            observer = getattr(self._runtime.service.source_observer_registry,
                               "observers", {}).get(observer_id)
            if type(observer) is not SourceObserverEnrollment:
                raise ValueError
            operation = selection.operation_record
            if (observer.observer_enrollment_id != observer_id
                    or observer.source_kind != "tool-result"
                    or observer.source_action_id != "registered-tool-result"
                    or observer.capture_schema_id != RESULT_SCHEMA_ID
                    or observer.channel_id != row["result_channel_id"]
                    or observer.profile_id != selection.principal_snapshot.profile_id
                    or observer.principal_id != selection.principal_snapshot.principal_id
                    or observer.namespace_id != selection.principal_snapshot.namespace_id
                    or observer.enrollment_id != row["service_enrollment_id"]
                    or observer.generation != selection.principal_snapshot.profile_generation
                    or observer.native_package_generation != selection.package_generation
                    or observer.package_id != selection.package_id
                    or observer.role_id != operation["process_role_id"]
                    or operation["registration_id"] not in observer.source_registration_ids
                    or observer.target_id != operation["target_id"]
                    or observer.recipient != operation["recipient"]):
                raise ValueError
            joins = getattr(self._runtime.bindings.enrollment_catalog,
                            "source_observer_joins", {})
            join = joins.get(observer_id) if isinstance(joins, Mapping) else None
            issuer = getattr(join, "issuer", None)
            package = getattr(join, "package", None)
            role = getattr(join, "process_role", None)
            if (join is None or issuer is None or package is None or role is None
                    or issuer.observer_enrollment_id != observer_id
                    or issuer.issuer_channel_id != row["result_source_issuer_id"]
                    or issuer.capture_schema_id != RESULT_SCHEMA_ID
                    or issuer.generation != selection.principal_snapshot.profile_generation
                    or "registered-tool-result" not in issuer.source_action_ids
                    or package.package_id != selection.package_id
                    or package.generation != selection.package_generation
                    or role.role_id != operation["process_role_id"]
                    or role.role_artifact_id != row["role_artifact_id"]
                    or role.role_sha256 != row["role_sha256"]):
                raise ValueError
            members = [member for member in adoption["source_members"]
                       if member["role"] == "native-source-module"
                       and member["artifact_id"] == row["result_handler_artifact_id"]
                       and member["receipt_handle"] == row["result_handler_source_receipt_handle"]
                       and member["relative_path"] == row["result_handler_closure_member_path"]
                       and member["sha256"] == row["result_handler_sha256"]]
            if len(members) != 1:
                raise ValueError
            release = InstalledRootReleaseVerifier.verify_installed_release()
            try:
                handler = release.resolve_reviewed_source_module(row["result_handler_artifact_id"])
                fd = release.open_file(handler.artifact_id)
                try:
                    chunks = []
                    remaining = handler.size_bytes
                    while remaining:
                        block = os.read(fd, min(65_536, remaining))
                        if not block:
                            raise ValueError
                        chunks.append(block)
                        remaining -= len(block)
                    raw = b"".join(chunks)
                finally:
                    os.close(fd)
                member = members[0]
                if (handler.relative_path != row["result_handler_closure_member_path"]
                        or handler.sha256 != row["result_handler_sha256"]
                        or handler.size_bytes != member["size_bytes"]
                        or len(raw) != handler.size_bytes
                        or hashlib.sha256(raw).hexdigest() != handler.sha256):
                    raise ValueError
                return RootActiveOwnerOverlayResultSourceObserver(
                    row, selection, invocation_source_observer, observer, handler.sha256,
                    handler.size_bytes, release.release_commit,
                    _ACTIVE_OWNER_OVERLAY_RESULT_OBSERVER_SEAL, self,
                )
            finally:
                release.close()
        except LocalProfileOverlayEffectsDenied:
            raise
        except Exception:
            raise LocalProfileOverlayEffectsDenied(
                "signed owner result selector, current source issuer or held root handler is unavailable",
            ) from None

    def _issue_selected_result_capture(self, verified_effect: RootVerifiedOwnerOverlayEffect,
                                       result_observer: RootActiveOwnerOverlayResultSourceObserver,
                                       canonical_result_bytes: bytes) -> str:
        """Capture only the completed current effect through its signed result observer."""
        from .owner_overlay_capture_schemas import RESULT_SCHEMA_ID
        if (type(verified_effect) is not RootVerifiedOwnerOverlayEffect
                or verified_effect._seal is not _OWNER_OVERLAY_EFFECT_SEAL
                or verified_effect.selection._issuer is not self
                or type(result_observer) is not RootActiveOwnerOverlayResultSourceObserver
                or result_observer._seal is not _ACTIVE_OWNER_OVERLAY_RESULT_OBSERVER_SEAL
                or result_observer._issuer is not self
                or result_observer.selection is not verified_effect.selection
                or result_observer.invocation_source_observer.selection.adoption_sha256
                   != verified_effect.selection.adoption_sha256
                or not isinstance(canonical_result_bytes, bytes)
                or not canonical_result_bytes):
            raise LocalProfileOverlayEffectsDenied("owner result capture lacks its exact completed effect")
        current = self.resolve_current_result_source_observer(
            verified_effect.selection, result_observer.invocation_source_observer)
        if (current.observer_row != result_observer.observer_row
                or current.enrollment != result_observer.enrollment
                or hashlib.sha256(canonical_result_bytes).hexdigest() == ""):
            raise LocalProfileOverlayEffectsDenied("signed owner result source changed before capture")
        observer_id = current.observer_row["result_observer_enrollment_id"]
        registry = self._runtime.service.source_observer_registry
        capture = getattr(registry, "record_owner_overlay_result", None)
        if not callable(capture):
            raise LocalProfileOverlayEffectsDenied("typed root owner result capture is unavailable")
        receipt = capture(
            verified_effect=verified_effect, result_observer=current,
            canonical_result_bytes=canonical_result_bytes, observer_enrollment_id=observer_id,
        )
        if not isinstance(receipt, str) or not receipt:
            raise LocalProfileOverlayEffectsDenied("root owner result source receipt was not issued")
        return receipt

    def execute_rpc(self, *, invocation_handle: str, canonical_argument_bytes: bytes,
                    peer_uid: int, peer_pid: int, peer_pidfd: int) -> Mapping[str, Any]:
        """Fixed native.owner-overlay.execute entrypoint from authenticated IPC."""
        from .native_runtime_observer import RootNativeOwnerOverlayInvocation
        registry = self._runtime.service.native_invocation_registry
        resolve = getattr(registry, "resolve_current_owner_overlay_invocation", None)
        if not callable(resolve):
            raise LocalProfileOverlayEffectsDenied("native owner invocation registry is unavailable")
        invocation = resolve(
            invocation_handle, canonical_argument_bytes,
            peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
        )
        if type(invocation) is not RootNativeOwnerOverlayInvocation:
            raise LocalProfileOverlayEffectsDenied("native owner invocation is not a typed captured call")
        selection = self.resolve_selected_operation(invocation.registration_id, peer_pid, peer_pidfd)
        identity = self._runtime.process_manager.resolve_live_peer(
            peer_pid, peer_pidfd, profile_id=selection.principal_snapshot.profile_id,
            generation=selection.principal_snapshot.profile_generation,
        )
        if (identity is None or identity != invocation.producer_identity
                or identity.kernel_uid != peer_uid or selection.adoption_sha256
                   != invocation.source_observer.selection.adoption_sha256):
            self._retire(selection.selection_handle)
            raise LocalProfileOverlayEffectsDenied("authenticated owner peer or selected package changed")
        peer = RootVerifiedOwnerOverlayPeer(
            peer_uid, peer_pid, peer_pidfd, identity, selection.loaded_role_proof,
            min(selection.expires_monotonic, invocation.expires_monotonic),
            _OWNER_OVERLAY_PEER_SEAL, self,
        )
        grant = self._effect_authority.issue_selected_invocation(
            invocation, selection, canonical_argument_bytes, peer)
        result_bytes = self.execute_selected(grant, canonical_argument_bytes, peer)
        import base64
        return {
            "schema": 1, "invocation_handle": invocation_handle,
            "registration_id": invocation.registration_id,
            "result_schema_id": invocation.source_observer.selection.operation_record["result_schema_id"],
            "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
            "canonical_result_b64": base64.b64encode(result_bytes).decode("ascii"),
        }

    def resolve_current_source_observer(self, registration_id: str, peer_pid: int,
                                        peer_pidfd: int) -> RootActiveOwnerOverlaySourceObserver:
        """Rejoin one signed observer row, loaded owner role and installed source bytes."""
        from .setup_policy_publication import PolicyPublicationReceiptResolver, validate_owner_overlay_adoption_row
        from .owner_overlay_capture_schemas import (
            CAPTURE_SCHEMAS, INVOCATION_SCHEMA_ID, RESULT_SCHEMA_ID,
        )
        from .installer_release import InstalledRootReleaseVerifier

        selection = self.resolve_selected_operation(registration_id, peer_pid, peer_pidfd)
        try:
            receipt = PolicyPublicationReceiptResolver.resolve_current()
            rows = [validate_owner_overlay_adoption_row(item)
                    for item in receipt.owner_overlay_adoption_records]
            adoptions = [row for row in rows
                         if row["adoption_sha256"] == selection.adoption_sha256]
            if len(adoptions) != 1:
                raise ValueError
            adoption = adoptions[0]
            observers = [row for row in adoption["owner_overlay_observer_records"]
                         if row["registration_id"] == registration_id]
            if len(observers) != 1:
                raise ValueError
            observer = dict(observers[0])
            operation = dict(selection.operation_record)
            enrolled = self._runtime.service.source_observer_registry
            source_row = (getattr(enrolled, "observers", {}).get(observer["observer_enrollment_id"])
                          if enrolled is not None else None)
            if (observer["operation_row_sha256"] != hashlib.sha256(_canonical(operation)).hexdigest()
                    or observer["observer_enrollment_id"] not in operation["source_observer_enrollment_ids"]
                    or source_row is None
                    or source_row.observer_enrollment_id != observer["observer_enrollment_id"]
                    or source_row.source_kind != "provider-result"
                    or source_row.channel_id != observer["channel_id"]
                    or source_row.enrollment_id != observer["service_enrollment_id"]
                    or source_row.profile_id != observer["profile_id"]
                    or source_row.principal_id != observer["principal_id"]
                    or source_row.namespace_id != observer["namespace_id"]
                    or source_row.generation != observer["profile_generation"]
                    or source_row.package_id != observer["package_id"]
                    or source_row.native_package_generation != observer["package_generation"]
                    or source_row.role_id != observer["role_id"]
                    or source_row.role_artifact_id != observer["role_artifact_id"]
                    or source_row.role_sha256 != observer["role_sha256"]
                    or source_row.role_source_receipt_handle != observer["role_source_receipt_handle"]
                    or source_row.role_module_name != observer["role_module_name"]
                    or source_row.role_closure_member_path != observer["role_closure_member_path"]
                    or source_row.role_source_revision != observer["role_source_revision"]
                    or source_row.role_source_tree_sha256 != observer["role_source_tree_sha256"]
                    or registration_id not in source_row.source_registration_ids
                    or observer["role_id"] != selection.loaded_role_proof.role_id
                    or observer["role_sha256"] != selection.loaded_role_proof.role_sha256
                    or observer["role_source_receipt_handle"]
                       != selection.loaded_role_proof.role_source_receipt_handle
                    or observer["package_id"] != selection.package_id
                    or observer["package_generation"] != selection.package_generation
                    or observer["source_choice_selection_handle"] != adoption["signed_choice"]["selection_handle"]):
                raise ValueError
            release = InstalledRootReleaseVerifier.verify_installed_release()
            try:
                source = release.resolve_reviewed_source_module(
                    "installer-module:hermes_installer.authority.owner_overlay_capture_schemas")
                source_fd = release.open_file(source.artifact_id)
                try:
                    chunks = []
                    remaining = source.size_bytes
                    while remaining:
                        block = os.read(source_fd, min(65_536, remaining))
                        if not block:
                            raise ValueError
                        chunks.append(block)
                        remaining -= len(block)
                    source_bytes = b"".join(chunks)
                finally:
                    os.close(source_fd)
                member = [row for row in adoption["source_members"]
                          if row["role"] == "owner-overlay-capture-schema-source"
                          and row["artifact_id"] == source.artifact_id]
                if (len(member) != 1 or member[0]["sha256"] != source.sha256
                        or member[0]["relative_path"] != source.relative_path
                        or hashlib.sha256(source_bytes).hexdigest() != source.sha256):
                    raise ValueError
                for schema_id in (INVOCATION_SCHEMA_ID, RESULT_SCHEMA_ID):
                    schema_bytes, schema_digest = CAPTURE_SCHEMAS[schema_id]
                    if (not schema_bytes or not re.fullmatch(r"[0-9a-f]{64}", schema_digest)
                            or hashlib.sha256(schema_bytes).hexdigest() != schema_digest):
                        raise ValueError
                issued = RootActiveOwnerOverlaySourceObserver(
                    observer, selection, CAPTURE_SCHEMAS, release.release_commit,
                    _ACTIVE_OWNER_OVERLAY_SOURCE_OBSERVER_SEAL, self,
                )
                return issued
            finally:
                release.close()
        except LocalProfileOverlayEffectsDenied:
            self._retire(selection.selection_handle)
            raise
        except Exception:
            self._retire(selection.selection_handle)
            raise LocalProfileOverlayEffectsDenied(
                "owner-overlay signed observer, held capture schemas or loaded source role is unavailable",
            ) from None

    def resolve_provider_tool_call(self, tool_name: str, peer_pid: int, peer_pidfd: int,
                                   package_id: str, profile_id: str, generation: str,
                                   package_generation: str, arguments: bytes
                                   ) -> RootActiveOwnerOverlaySourceObserver:
        """Resolve one provider tool only through the four signed owner rows.

        This is deliberately separate from ``_ProtectedNativeActionResolver``:
        local Resources calls are not backend actions and must not be coerced
        into the backend action/workflow catalog.
        """
        from hermes_installer.mcp.native_schema_catalog import NativeMCPProtectedSchemaCatalog
        from .runtime_composition import _native_json_schema_matches
        from .types import strict_json_loads

        names = {
            "resource_overlay_read": "resource-overlay-store:tool:resource_overlay_read",
            "resource_overlay_history": "resource-overlay-store:tool:resource_overlay_history",
            "resource_overlay_write": "resource-overlay-store:tool:resource_overlay_write",
            "resource_overlay_delete": "resource-overlay-store:tool:resource_overlay_delete",
        }
        registration_id = names.get(tool_name)
        if registration_id is None or not isinstance(arguments, bytes):
            raise LocalProfileOverlayEffectsDenied("provider tool is not a selected local owner operation")
        source = self.resolve_current_source_observer(registration_id, peer_pid, peer_pidfd)
        selection = source.selection
        operation = selection.operation_record
        if ((selection.package_id, selection.principal_snapshot.profile_id,
             selection.principal_snapshot.profile_generation, selection.package_generation)
                != (package_id, profile_id, generation, package_generation)
                or operation.get("registration_id") != registration_id):
            self._retire(selection.selection_handle)
            raise LocalProfileOverlayEffectsDenied("owner operation differs from provider package selection")
        registry = getattr(self._runtime.service, "native_invocation_registry", None)
        resolver = getattr(registry, "action_resolver", None)
        catalog = getattr(resolver, "schema_catalog", None)
        if type(catalog) is not NativeMCPProtectedSchemaCatalog:
            self._retire(selection.selection_handle)
            raise LocalProfileOverlayEffectsDenied("current protected owner operation schema catalog is unavailable")
        try:
            argument_schema = catalog.resolve(
                operation["argument_schema_id"], native_package_id=selection.package_id,
                native_package_generation=selection.package_generation,
                adapter_id="resource-overlay-store", action_id=registration_id,
                schema_kind="arguments",
            )
            result_schema = catalog.resolve(
                operation["result_schema_id"], native_package_id=selection.package_id,
                native_package_generation=selection.package_generation,
                adapter_id="resource-overlay-store", action_id=registration_id,
                schema_kind="result",
            )
            argument_artifact = catalog._by_id[operation["argument_schema_id"]]
            result_artifact = catalog._by_id[operation["result_schema_id"]]
            value = strict_json_loads(arguments.decode("utf-8", errors="strict"))
            canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False, allow_nan=False).encode("utf-8")
            valid = (_native_json_schema_matches(value, argument_schema)
                     and canonical == arguments)
            if (not valid or argument_artifact.sha256 != operation["argument_schema_sha256"]
                    or result_artifact.sha256 != operation["result_schema_sha256"]
                    or not isinstance(result_schema, Mapping)):
                raise ValueError
            return source
        except Exception:
            self._retire(selection.selection_handle)
            raise LocalProfileOverlayEffectsDenied(
                "owner operation arguments or current held schema do not match the signed row",
            ) from None

    def _retire(self, handle: str) -> None:
        with self._lock:
            self._selections.pop(handle, None)
            fd = self._peer_fds.pop(handle, None)
        if fd is not None:
            os.close(fd)

    def close(self) -> None:
        self._closed = True
        for handle in tuple(self._peer_fds):
            self._retire(handle)
        self._selections.clear()
