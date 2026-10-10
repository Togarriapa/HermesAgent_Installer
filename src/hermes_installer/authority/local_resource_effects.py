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
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


_VIEW_SEAL = object()
_BUNDLE_SEAL = object()
_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
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
        prior = self._views.get(receipt.view_selection_handle)
        if prior is not None and prior is not receipt:
            raise LocalProfileOverlayEffectsDenied("profile overlay view handle was rebound")
        self._views[receipt.view_selection_handle] = receipt
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
                "source_observer_enrollment_ids": tuple(role_record[1]),
                "process_role_id": role_record[2], "source_issuer_id": role_record[3],
            }
            rows.append(MappingProxyType(row))

        canonical_rows = tuple(dict(row) for row in rows)
        body = _canonical({"schema": 1, "rows": canonical_rows,
                           "pending": [dict(item) for item in pending]})
        now = time.monotonic()
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
                or view.view_selection_handle != bundle.profile_view_selection_handle):
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
            Journal(self._journal).event(
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
