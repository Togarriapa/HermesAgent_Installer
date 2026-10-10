"""Join available selected source owners without inventing unavailable effects.

HI-T178.1/HI-T179.1: local owner overlays have their own current operation
issuer. Backend actions and workflows remain pending until their independent
native target/effect issuers exist. No row here is loaded-process evidence.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from .local_resource_effects import (
    RootOwnedProfileOverlayViewRegistry, RootOwnerOverlaySchemaReceiptRegistry,
    RootOwnerProfileOverlayEffects,
)


def freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(item) for item in value)
    return value


def plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class SelectedNativeSourceComposition:
    registration_records: tuple[Any, ...]
    native_schema_records: tuple[Any, ...]
    native_schema_bytes: tuple[tuple[str, bytes], ...]
    process_role_records: tuple[Any, ...]
    source_issuer_records: tuple[Any, ...]
    source_observer_policy_records: tuple[Any, ...]
    source_role_selection_handles: tuple[str, ...]
    effect_policy_receipt_handles: tuple[str, ...]
    result_schema_receipts: tuple[Any, ...]
    operation_bundle: Any
    schema_receipts: tuple[Any, ...]


class RootSelectedNativeSourceComposer:
    """Uses existing guarded root source/schema/view/target/effect producers."""

    def __init__(self, binding: Any, source: Any, roles: Any, targets: Any, journal: Any):
        self._binding, self._source, self._roles = binding, source, roles
        self._schemas = RootOwnerOverlaySchemaReceiptRegistry.from_root_setup(binding, source, journal)
        self._views = RootOwnedProfileOverlayViewRegistry.from_root_setup(binding, journal)
        self._effects = RootOwnerProfileOverlayEffects.from_root_setup(
            binding, source, self._schemas, self._views, targets, roles, journal)
        self._rows: dict[str, SelectedNativeSourceComposition] = {}

    def prepare(self, selection: Any) -> SelectedNativeSourceComposition | None:
        if not selection.selected_owner_overlay_registration_ids:
            return None
        view = self._views.prepare_selected_view(selection.selection_handle,
                                                 selection.resource_profile_selection_handle)
        operations = self._effects.prepare_selected_operations(selection.selection_handle,
                                                                view.profile_view_selection_handle)
        # Pending operations never silently become executable registrations.
        required = set(selection.selected_owner_overlay_registration_ids)
        if operations.pending_registration_records or {row['registration_id'] for row in operations.operation_records} != required:
            return None
        coverage = self._source.resolve_source_coverage()
        captured = {f'{row.adapter_id}:tool:{row.native_tool_name}': row
                    for row in coverage.captured_registrations}
        observed = {row.registration_id: row for row in coverage.source_observations}
        reviewed = {f'{row.adapter_id}:tool:{row.native_tool_name}': row
                    for row in coverage.reviewed_definitions}
        roles, issuers, observers, role_handles = self._roles.selected_owner_overlay_source_rows(selection)
        registrations, schemas, schema_bytes, receipts, result_receipts = [], [], {}, [], []
        for operation in operations.operation_records:
            registration_id = operation['registration_id']
            source, capture, definition = observed[registration_id], captured[registration_id], reviewed[registration_id]
            arguments, result = self._schemas.resolve_owner_overlay_schemas(registration_id, source, capture, selection)
            receipts.extend((arguments, result))
            result_receipts.append(result)
            for receipt, kind in ((arguments, 'arguments'), (result, 'result')):
                content = receipt.read_current()
                schema_id = arguments.schema_id if kind == 'arguments' else result.artifact_id
                old = schema_bytes.get(schema_id)
                if old is not None and old != content:
                    raise PermissionError('selected native schema ID has conflicting bytes')
                schema_bytes[schema_id] = content
                schemas.append(freeze({
                    'id': schema_id, 'artifact_id': receipt.artifact_id,
                    'sha256': hashlib.sha256(content).hexdigest(), 'schema_kind': kind,
                    'native_package_id': selection.package_id,
                    'native_package_generation': selection.native_package_generation,
                    'adapter_id': source.adapter_id, 'action_id': registration_id,
                    'source_receipt_handle': (source.registration_source_receipt_handle
                                              if kind == 'arguments' else result.artifact_receipt_handle),
                    'size_bytes': len(content),
                    'derivation_receipt_handle': arguments.artifact_receipt_handle if kind == 'arguments'
                                                else result.artifact_receipt_handle,
                }))
            registrations.append(freeze({
                'registration_id': registration_id, 'native_tool_name': source.native_tool_name,
                'toolset': source.toolset, 'family': source.family, 'adapter_id': source.adapter_id,
                'argument_schema_id': arguments.schema_id, 'result_schema_id': result.artifact_id,
                'native_schema_sha256': source.native_schema_sha256,
                'registration_source_artifact_id': source.registration_source_artifact_id,
                'registration_source_sha256': source.registration_source_sha256,
                'registration_source_receipt_handle': source.registration_source_receipt_handle,
                'handler_kind': source.handler_kind, 'handler_id': source.handler_id,
                'selector_fields': definition.selector_fields,
                'action_bindings': tuple({
                    'selector_values': dict(row.selector_values), 'action_binding_id': None,
                    'argument_projection': tuple({'name': name, 'source_field': field}
                                                for name, field in row.argument_projection),
                    'workflow_id': None,
                } for row in definition.action_bindings),
                'observer_enrollment_ids': operation['source_observer_enrollment_ids'],
                'generation': selection.native_package_generation,
            }))
        result = SelectedNativeSourceComposition(
            tuple(registrations), tuple(schemas), tuple(sorted(schema_bytes.items())),
            freeze(roles), freeze(issuers), freeze(observers), role_handles,
            tuple(sorted({row['effect_enrollment_id'] for row in operations.operation_records})),
            tuple(result_receipts), operations, tuple(receipts))
        self._rows[selection.selection_handle] = result
        return result

    def resolve_current(self, selection: Any) -> SelectedNativeSourceComposition:
        row = self._rows.get(selection.selection_handle)
        if row is None:
            raise PermissionError('selected source composition is not retained')
        self._effects.resolve_current(row.operation_bundle.bundle_handle, selection.selection_handle)
        for receipt in row.schema_receipts:
            receipt.read_current()
        roles, issuers, observers, handles = self._roles.selected_owner_overlay_source_rows(selection)
        if (roles != row.process_role_records or issuers != row.source_issuer_records
                or observers != row.source_observer_policy_records or handles != row.source_role_selection_handles):
            raise PermissionError('selected source role declaration changed')
        return row
