"""Digest-covered local-owner overlay adoption projections.

The projection is a durable statement of which root-observed source and CAS
view entered one signed active generation.  It is provenance only; the active
runtime must independently reopen all referenced objects before authorizing an
effect.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping


_SEAL = object()
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_FIELDS = frozenset({
    "schema", "identity_kind", "adoption_handle", "signed_choice",
    "adopted_at_unix", "setup_deadline_unix", "owner", "resources",
    "native_package", "operation_records", "view_custody", "source_members",
    "owner_overlay_observer_records",
})
_OBSERVER_FIELDS = frozenset({
    "schema", "observer_kind", "observer_enrollment_id", "profile_id",
    "profile_generation", "principal_id", "namespace_id", "service_enrollment_id",
    "package_id", "package_generation", "registration_id", "method",
    "operation_row_sha256", "source_choice_selection_handle",
    "source_choice_signed_record_sha256", "choice_epoch", "revocation_epoch",
    "role_id", "role_artifact_id", "role_sha256", "role_source_receipt_handle",
    "role_module_name", "role_closure_member_path", "role_source_revision",
    "role_source_tree_sha256", "source_issuer_id", "channel_id",
    "invocation_capture_schema_id", "result_capture_schema_id",
    "argument_schema_id", "argument_schema_sha256", "result_schema_id",
    "result_schema_sha256", "lease_seconds",
})
_OPERATIONS = {
    "resource-overlay-store:tool:resource_overlay_read": ("read", "plugin.resource-overlay-store.read"),
    "resource-overlay-store:tool:resource_overlay_history": ("history", "plugin.resource-overlay-store.read"),
    "resource-overlay-store:tool:resource_overlay_write": ("write", "plugin.resource-overlay-store.write"),
    "resource-overlay-store:tool:resource_overlay_delete": ("delete", "plugin.resource-overlay-store.write"),
}
_OWNER_FIELDS = frozenset({
    "principal_id", "profile_id", "namespace_id", "principal_binding_sha256",
    "namespace_binding_sha256", "account_name", "account_uid", "primary_gid",
    "machine_target_sha256", "service_uid", "service_gid", "service_generation_id",
    "service_generation_digest",
})
_RESOURCE_FIELDS = frozenset({
    "resources_profile_id", "source_receipt_handle", "source_artifact_id", "source_sha256",
    "member_receipt_handles", "member_sha256s", "resource_profile_selection_handle",
    "resource_profile_selection_sha256",
})
_PACKAGE_FIELDS = frozenset({
    "package_id", "profile_id", "generation", "compiled_closure_sha256",
    "entrypoint_sha256", "resolver_sha256", "owner_overlay_operation_records_sha256",
    "native_cas_transition_receipt_handle", "native_cas_transition_sha256",
})
_VIEW_FIELDS = frozenset({
    "service_profile_id", "resource_profile_id",
    "data_root_id", "data_root_selection_handle", "data_root_receipt_handle",
    "data_root_device", "data_root_inode", "data_root_owner_uid", "data_root_owner_gid",
    "relative_path", "view_device", "view_inode", "view_owner_uid", "view_owner_gid",
    "view_mode", "ownership_marker_sha256", "profile_view_selection_handle",
    "profile_view_receipt_handle", "target_id", "target_selection_handle",
    "target_receipt_handle", "effect_enrollment_ids",
})
_MEMBER_FIELDS = frozenset({
    "role", "artifact_id", "receipt_handle", "relative_path", "sha256", "size_bytes", "mode",
})
_CHOICE_FIELDS = frozenset({
    "selection_handle", "purpose", "key_id", "signed_record_sha256", "choice_payload_sha256",
    "choice_epoch", "revocation_epoch", "issued_at_unix", "setup_deadline_unix",
    "release_deployment_receipt_sha256", "setup_session_handle", "transaction_handle", "plan_id",
    "prepared_generation", "principal_selection_handle", "namespace_selection_handle",
    "private_profile_selection_handle", "source_member_receipt_handles", "principal_id", "profile_id",
    "namespace_id", "principal_binding_sha256", "namespace_binding_sha256", "service_generation_id",
    "service_generation_digest", "selection_catalog_sha256",
})
_OPERATION_FIELDS = frozenset({
    "registration_id", "method", "operation", "capability", "target_id", "recipient",
    "effect_enrollment_id", "profile_id", "profile_generation", "principal_id", "namespace_id",
    "package_id", "package_generation", "argument_schema_id", "argument_schema_sha256",
    "argument_schema_receipt_handle", "result_schema_id", "result_schema_sha256",
    "result_schema_receipt_handle", "handler_artifact_id", "handler_sha256",
    "handler_source_receipt_handle", "profile_view_selection_handle", "profile_view_receipt_handle",
    "data_root_selection_handle", "data_root_receipt_handle", "target_selection_handle",
    "target_receipt_handle", "prepared_source_observer_selection_handle",
    "source_observer_enrollment_ids", "process_role_id", "source_issuer_id",
})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True, slots=True, repr=False)
class RootPublishedLocalOwnerAdoption:
    """Compiler-sealed source/view projection to be covered by publication CAS."""

    adoption_handle: str
    identity_kind: str
    signed_choice: Mapping[str, Any]
    adopted_at_unix: float | None
    setup_deadline_unix: float
    owner: Mapping[str, Any]
    resources: Mapping[str, Any]
    native_package: Mapping[str, Any]
    operation_records: tuple[Mapping[str, Any], ...]
    view_custody: Mapping[str, Any]
    source_members: tuple[Mapping[str, Any], ...]
    owner_overlay_observer_records: tuple[Mapping[str, Any], ...]
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("published local-owner adoptions are root-issued")
        object.__setattr__(self, "signed_choice", _freeze(self.signed_choice))
        object.__setattr__(self, "owner", _freeze(self.owner))
        object.__setattr__(self, "resources", _freeze(self.resources))
        object.__setattr__(self, "native_package", _freeze(self.native_package))
        object.__setattr__(self, "operation_records", tuple(_freeze(row) for row in self.operation_records))
        object.__setattr__(self, "view_custody", _freeze(self.view_custody))
        object.__setattr__(self, "source_members", tuple(_freeze(row) for row in self.source_members))
        object.__setattr__(self, "owner_overlay_observer_records",
                           tuple(_freeze(row) for row in self.owner_overlay_observer_records))
        _validate_projection(self.to_claim_row(include_digest=False))

    def to_claim_row(self, *, include_digest: bool = True) -> dict[str, Any]:
        row = {
            "schema": 1,
            "identity_kind": self.identity_kind,
            "adoption_handle": self.adoption_handle,
            "signed_choice": _plain(self.signed_choice),
            "adopted_at_unix": self.adopted_at_unix,
            "setup_deadline_unix": self.setup_deadline_unix,
            "owner": _plain(self.owner),
            "resources": _plain(self.resources),
            "native_package": _plain(self.native_package),
            "operation_records": _plain(self.operation_records),
            "view_custody": _plain(self.view_custody),
            "source_members": _plain(self.source_members),
            "owner_overlay_observer_records": _plain(self.owner_overlay_observer_records),
        }
        if include_digest:
            row["adoption_sha256"] = hashlib.sha256(_canonical(row)).hexdigest()
        return row

    def __repr__(self) -> str:
        return "RootPublishedLocalOwnerAdoption(<root-private>)"


def _mint_published_local_owner_adoption(**values: Any) -> RootPublishedLocalOwnerAdoption:
    """Private constructor used only by the active root compiler collector."""
    expected = {
        "adoption_handle", "identity_kind", "signed_choice", "adopted_at_unix",
        "setup_deadline_unix", "owner", "resources", "native_package",
        "operation_records", "view_custody", "source_members",
        "owner_overlay_observer_records",
    }
    if set(values) != expected:
        raise TypeError("local-owner adoption projection fields differ from the fixed contract")
    return RootPublishedLocalOwnerAdoption(**values, _seal=_SEAL)


def validate_owner_overlay_adoption_row(value: Any) -> dict[str, Any]:
    """Validate the public canonical row before descriptor signing or loading."""
    if not isinstance(value, Mapping):
        raise ValueError("owner-overlay adoption must be a mapping")
    row = _plain(value)
    if set(row) != _FIELDS | {"adoption_sha256"}:
        raise ValueError("owner-overlay adoption row has an unexpected schema")
    digest = row.pop("adoption_sha256")
    _validate_projection(row)
    if (row["adopted_at_unix"] is None or not isinstance(digest, str)
            or not _HEX.fullmatch(digest) or digest != hashlib.sha256(_canonical(row)).hexdigest()):
        raise ValueError("owner-overlay adoption digest does not cover its exact projection")
    return {**row, "adoption_sha256": digest}


def collect_owner_overlay_adoptions(
        session: Any, prepared_bundle: Any, principal: Any,
        choice_adoptions: tuple[Any, ...], materialization_receipts: Any,
        reservation: Any, role_closure: Any) -> tuple[RootPublishedLocalOwnerAdoption, ...]:
    """Collect the real setup-owned source/view/package closure before signing.

    This deliberately reuses the exact source composer and retained file
    descriptors created during native assembly. Missing target/root/schema or
    reserved-output facts deny the adoption; the collector does not normalize
    empty optional resolver references into authority.
    """
    from .bootstrap_enrollment import BootstrapEnrollmentPending
    from .setup_principal import RootSetupLocalOwnerIdentityRegistry

    registry = session._adopted_principal_registry
    if type(registry) is not RootSetupLocalOwnerIdentityRegistry:
        if getattr(principal, "identity_kind", None) == "linux-local-owner-v1":
            raise BootstrapEnrollmentPending("local-owner adoption requires its concrete setup registry")
        return ()
    ceiling = tuple(getattr(principal, "selected_capability_ceiling", ()))
    if not ceiling:
        return ()
    if (not 1 <= len(ceiling) <= 4 or len(set(ceiling)) != len(ceiling)
            or not set(ceiling) <= set(_OPERATIONS)):
        raise BootstrapEnrollmentPending("local-owner capability ceiling exceeds the fixed four-method lane")
    try:
        current_identity = session.resolve_current_setup_identity()
        current_identity = registry.resolve_current_snapshot(
            session._handle, current_identity.snapshot_handle)
        if (current_identity.identity_kind != "linux-local-owner-v1"
                or current_identity.principal is not principal
                or current_identity.expires_monotonic <= __import__("time").monotonic()
                or current_identity.namespace is None):
            raise ValueError
        selection_handle = session._current_native_policy_selection_handle
        selection = session.selected_installation.resolve_current_native_policy_selection(selection_handle)
        if (selection.principal_selection_handle != principal.receipt_handle
                or selection.principal_binding_sha256 != principal.principal_binding_sha256
                or selection.namespace_selection_handle != current_identity.namespace_selection_handle
                or selection.namespace_binding_sha256 != current_identity.namespace_binding_sha256
                or tuple(selection.selected_owner_overlay_registration_ids) != tuple(sorted(ceiling))):
            raise ValueError
        source_registry = session._native_policy_preparation_registry
        composer = source_registry._selected_source_composer
        composition = composer.resolve_current(selection)
        operations = composition.operation_bundle
        if (tuple(row["registration_id"] for row in operations.operation_records) != tuple(sorted(ceiling))
                or operations.pending_registration_records
                or operations.expires_monotonic <= __import__("time").monotonic()):
            raise ValueError
        view = composer._effects._views.resolve_current(
            operations.profile_view_selection_handle, selection.selection_handle)
        binding = session.selected_installation
        assembly = binding.resolve_current_native_bootstrap_assembly(
            reservation.assembly_selection_handle)
        definitions = binding.resolve_native_assembly_definitions(assembly.selection_handle)
        current_reservation = materialization_receipts.resolve_current_precompile_reservation(
            reservation.reservation_handle)
        closure_output_handles = {
            item.receipt_handle for item in role_closure.role_rows
            if item.role != "official-pm-runtime"
        }
        if (current_reservation != reservation
                or reservation.prepared_generation_id != prepared_bundle.prepared_generation_id
                or reservation.assembly_selection_handle != assembly.selection_handle
                or set(reservation.receipt_ids) != closure_output_handles):
            raise ValueError
        output_records = [materialization_receipts._get_record(handle)
                          for handle in reservation.receipt_ids]
        output_by_role = {row["artifact_role"]: row for row in output_records}
        if len(output_by_role) != 5 or set(output_by_role) != {
                "native-compiled-closure", "native-entrypoint-manifest", "native-action-resolver",
                "native-boundary-overlay", "native-candidate-index"}:
            raise ValueError
        for record in output_records:
            materialization_receipts._verify_record_current(record)
        resolver_record = output_by_role["native-action-resolver"]
        resolver = json.loads(materialization_receipts._read_record_payload(resolver_record))
        rows = [_plain(row) for row in operations.operation_records]
        if (not isinstance(resolver, dict)
                or resolver.get("owner_overlay_operation_records") != rows
                or resolver.get("package_id") != assembly.package_id
                or resolver.get("profile_id") != assembly.service_profile_id
                or resolver.get("generation") != assembly.native_package_generation):
            raise ValueError
        profile = session.resolve_selected_resource_profile(prepared_bundle.resource_profile_selection_receipt_handle)
        verified_source = session._verified_resources[profile.resources_source_receipt_handle][0]
        profile_member = verified_source.files.get(profile.profile_member_path)
        if (hashlib.sha256(profile_member).hexdigest() != profile.profile_member_sha256
                or len(profile_member) <= 0 or profile.profile_id != view.resource_profile_id):
            raise ValueError
        resource_source_record = materialization_receipts._get_record(
            profile.resources_source_receipt_handle)
        from .native_output_receipts import _archive_manifest
        archive_members = {item.relative_path: item for item in _archive_manifest(
            materialization_receipts._read_record_payload(resource_source_record), source_archive=True)}
        resource_member = archive_members.get(profile.profile_member_path)
        if (resource_member is None or resource_member.sha256 != profile.profile_member_sha256
                or resource_member.size_bytes != len(profile_member)):
            raise ValueError
        owner_identity = current_identity.owner_identity
        choice = next((row for row in choice_adoptions
                       if row.selection_handle == selection.setup_choice_selection_handle
                       and row.purpose == "native-policy-preparation"), None)
        if (choice is None or choice.choice_epoch != selection.choice_epoch
                or choice.revocation_epoch != selection.revocation_epoch
                or choice.choice_payload_sha256 != selection.choice_payload_sha256):
            raise ValueError
        from .active_policy_compiler import _choice_projection_record
        signed_choice = _choice_projection_record(choice)
        owner = {
            "principal_id": current_identity.principal_id,
            "profile_id": current_identity.service_profile_id,
            "namespace_id": current_identity.namespace_id,
            "principal_binding_sha256": current_identity.principal_binding_sha256,
            "namespace_binding_sha256": current_identity.namespace_binding_sha256,
            "account_name": owner_identity.target_account_name,
            "account_uid": owner_identity.observed_uid,
            "primary_gid": owner_identity.observed_primary_gid,
            "machine_target_sha256": owner_identity.machine_target_binding_digest,
            "service_uid": view.data_root_owner_uid,
            "service_gid": view.data_root_owner_gid,
            "service_generation_id": view.service_generation,
            "service_generation_digest": prepared_bundle.prepared_generation_digest,
        }
        data_root_info = __import__("os").fstat(view._data_root_fd)
        view_info = __import__("os").fstat(view._view_root_fd)
        view_custody = {
            "service_profile_id": view.service_profile_id,
            "resource_profile_id": view.resource_profile_id,
            "data_root_id": view.data_root_id,
            "data_root_selection_handle": view.data_root_selection_handle,
            "data_root_receipt_handle": view.data_root_receipt_handle,
            "data_root_device": data_root_info.st_dev,
            "data_root_inode": data_root_info.st_ino,
            "data_root_owner_uid": data_root_info.st_uid,
            "data_root_owner_gid": data_root_info.st_gid,
            "relative_path": f"native-profile-overlays/{view.service_profile_id}/{view.resource_profile_id}",
            "view_device": view_info.st_dev,
            "view_inode": view_info.st_ino,
            "view_owner_uid": view_info.st_uid,
            "view_owner_gid": view_info.st_gid,
            "view_mode": __import__("stat").S_IMODE(view_info.st_mode),
            "ownership_marker_sha256": view.ownership_marker_sha256,
            "profile_view_selection_handle": view.profile_view_selection_handle,
            "profile_view_receipt_handle": view.view_selection_handle,
            "target_id": view.target_id,
            "target_selection_handle": view.target_selection_handle,
            "target_receipt_handle": view.target_receipt_handle,
            "effect_enrollment_ids": list(view.effect_enrollment_ids),
        }
        package = {
            "package_id": assembly.package_id,
            "profile_id": assembly.service_profile_id,
            "generation": assembly.native_package_generation,
            "compiled_closure_sha256": output_by_role["native-compiled-closure"]["compiled_closure_sha256"],
            "entrypoint_sha256": output_by_role["native-entrypoint-manifest"]["sha256"],
            "resolver_sha256": resolver_record["sha256"],
            "owner_overlay_operation_records_sha256": hashlib.sha256(_canonical(rows)).hexdigest(),
            "native_cas_transition_receipt_handle": reservation.reservation_handle,
            "native_cas_transition_sha256": reservation.output_closure_sha256,
        }
        resources = {
            "resources_profile_id": profile.profile_id,
            "source_receipt_handle": profile.resources_source_receipt_handle,
            "source_artifact_id": profile.resources_source_artifact_id,
            "source_sha256": profile.resources_source_sha256,
            "member_receipt_handles": [profile.resources_source_receipt_handle],
            "member_sha256s": [profile.profile_member_sha256],
            "resource_profile_selection_handle": profile.receipt_handle,
            "resource_profile_selection_sha256": hashlib.sha256(_canonical({
                "profile_id": profile.profile_id, "member_path": profile.profile_member_path,
                "member_sha256": profile.profile_member_sha256,
                "resources_revision": profile.resources_revision,
            })).hexdigest(),
        }
        members: list[dict[str, Any]] = []
        for member in definitions.closure_members:
            source_bytes = binding.resolve_native_assembly_member(
                assembly.selection_handle, member.artifact_receipt_handle)
            if (hashlib.sha256(source_bytes).hexdigest() != member.sha256
                    or len(source_bytes) != member.size_bytes):
                raise ValueError
            owner = session._factory._native_assembly_member_owners[
                assembly.selection_handle].get(member.artifact_receipt_handle)
            if owner is None:
                raise ValueError
            members.append({
                "role": "native-source-module", "artifact_id": owner.artifact_id,
                "receipt_handle": member.artifact_receipt_handle, "relative_path": member.relative_path,
                "sha256": member.sha256, "size_bytes": member.size_bytes, "mode": member.mode,
            })
        for receipt in composition.schema_receipts:
            content = receipt.read_current()
            artifact_id = getattr(receipt, "artifact_id", None)
            handle = getattr(receipt, "artifact_receipt_handle", None)
            path = getattr(receipt, "relative_path", None)
            size = getattr(receipt, "size_bytes", None)
            if (not isinstance(artifact_id, str) or not isinstance(handle, str)
                    or not isinstance(path, str) or type(size) is not int or len(content) != size
                    or hashlib.sha256(content).hexdigest() != receipt.sha256):
                raise ValueError
            import os
            if hasattr(receipt, "_registry") and getattr(receipt, "_registry", None) is not None:
                store = receipt._registry._argument_store
                schema_path = store._root.joinpath(*receipt.relative_path.split("/"))
                fd = os.open(schema_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_CLOEXEC", 0))
            else:
                fd = receipt._schema_receipt._observation.open_blob()
            try:
                schema_mode = __import__("stat").S_IMODE(os.fstat(fd).st_mode)
            finally:
                os.close(fd)
            members.append({"role": "native-schema", "artifact_id": artifact_id,
                            "receipt_handle": handle, "relative_path": path,
                            "sha256": receipt.sha256, "size_bytes": size, "mode": schema_mode})
        from .owner_overlay_capture_schemas import (
            INVOCATION_SCHEMA_ID, RESULT_SCHEMA_ID, verify_held_capture_schema,
        )
        capture_module_id = (
            "installer-module:hermes_installer.authority.owner_overlay_capture_schemas")
        capture_resolver = getattr(
            binding, "resolve_prepared_owner_overlay_capture_schema_module_receipt", None)
        capture_receipt = capture_resolver() if callable(capture_resolver) else None
        if (capture_receipt is None
                or getattr(capture_receipt, "artifact_id", None) != capture_module_id):
            raise ValueError("fixed owner-overlay capture schemas lack one held release receipt")
        verify_held_capture_schema(capture_receipt, INVOCATION_SCHEMA_ID)
        verify_held_capture_schema(capture_receipt, RESULT_SCHEMA_ID)
        members.append({
            "role": "owner-overlay-capture-schema-source", "artifact_id": capture_receipt.artifact_id,
            "receipt_handle": capture_receipt.source_receipt_handle,
            "relative_path": capture_receipt.relative_path,
            "sha256": capture_receipt.sha256, "size_bytes": capture_receipt.size_bytes,
            "mode": 0o400,
        })
        members.append({
            "role": "resources-profile-member", "artifact_id": profile.resources_source_artifact_id,
            "receipt_handle": profile.resources_source_receipt_handle,
            "relative_path": profile.profile_member_path,
            "sha256": profile.profile_member_sha256,
            "size_bytes": len(profile_member), "mode": resource_member.mode,
        })
        members.append({
            "role": "resources-source-archive", "artifact_id": resource_source_record["artifact_id"],
            "receipt_handle": profile.resources_source_receipt_handle,
            "relative_path": "resources-source-bundle", "sha256": resource_source_record["sha256"],
            "size_bytes": resource_source_record["size_bytes"], "mode": 0o400,
        })
        rows_digest = hashlib.sha256(_canonical(rows)).hexdigest()
        if (rows_digest != package["owner_overlay_operation_records_sha256"]
                or any(not operation["data_root_selection_handle"]
                       or not operation["data_root_receipt_handle"]
                       or not operation["target_receipt_handle"] for operation in rows)):
            raise ValueError
        adoption_handle = hashlib.sha256(_canonical({
            "choice": signed_choice["signed_record_sha256"],
            "principal": current_identity.principal_binding_sha256,
            "operations": rows_digest,
            "view": view.ownership_marker_sha256,
        })).hexdigest()
        source_members = tuple(sorted(members, key=lambda row: (
            row["relative_path"], row["artifact_id"], row["receipt_handle"])))
        issuer_rows = {item.get("observer_enrollment_id"): item
                       for item in definitions.source_issuer_records}
        role_rows = {item.get("role_id"): item for item in definitions.process_role_records}
        observer_rows: list[dict[str, Any]] = []
        for operation in rows:
            registration = operation["registration_id"]
            candidates = [observer_id for observer_id in operation["source_observer_enrollment_ids"]
                          if observer_id == operation["source_issuer_id"]
                          and observer_id in issuer_rows]
            role = role_rows.get(operation["process_role_id"])
            if len(candidates) != 1 or role is None:
                raise ValueError("owner-overlay source observer does not join one held issuer and role")
            observer_id = candidates[0]
            issuer = issuer_rows[observer_id]
            role_member = next((member for member in source_members
                                if member["role"] == "native-source-module"
                                and member["artifact_id"] == role["role_artifact_id"]
                                and member["receipt_handle"] == role["role_source_receipt_handle"]
                                and member["sha256"] == role["role_sha256"]
                                and member["relative_path"] == role["closure_member_path"]), None)
            if (role_member is None or observer_id not in role["observer_enrollment_ids"]
                    or registration not in role["registration_ids"]
                    or issuer.get("generation") != assembly.native_package_generation
                    or issuer.get("producer_role_artifact_id") != role["role_artifact_id"]
                    or issuer.get("producer_role_sha256") != role["role_sha256"]
                    or not isinstance(issuer.get("issuer_channel_id"), str)
                    or not issuer["issuer_channel_id"]):
                raise ValueError("owner-overlay observer role/issuer/channel membership changed")
            observer_rows.append({
                "schema": 1, "observer_kind": "owner-overlay-registration-v1",
                "observer_enrollment_id": observer_id,
                "profile_id": owner["profile_id"], "profile_generation": operation["profile_generation"],
                "principal_id": owner["principal_id"], "namespace_id": owner["namespace_id"],
                "service_enrollment_id": assembly.enrollment_id,
                "package_id": operation["package_id"], "package_generation": operation["package_generation"],
                "registration_id": registration, "method": operation["method"],
                "operation_row_sha256": hashlib.sha256(_canonical(operation)).hexdigest(),
                "source_choice_selection_handle": signed_choice["selection_handle"],
                "source_choice_signed_record_sha256": signed_choice["signed_record_sha256"],
                "choice_epoch": signed_choice["choice_epoch"],
                "revocation_epoch": signed_choice["revocation_epoch"],
                "role_id": role["role_id"], "role_artifact_id": role["role_artifact_id"],
                "role_sha256": role["role_sha256"],
                "role_source_receipt_handle": role["role_source_receipt_handle"],
                "role_module_name": role["module_name"],
                "role_closure_member_path": role["closure_member_path"],
                "role_source_revision": role["role_source_revision"],
                "role_source_tree_sha256": role["role_source_tree_sha256"],
                "source_issuer_id": operation["source_issuer_id"],
                "channel_id": issuer["issuer_channel_id"],
                "invocation_capture_schema_id": INVOCATION_SCHEMA_ID,
                "result_capture_schema_id": RESULT_SCHEMA_ID,
                "argument_schema_id": operation["argument_schema_id"],
                "argument_schema_sha256": operation["argument_schema_sha256"],
                "result_schema_id": operation["result_schema_id"],
                "result_schema_sha256": operation["result_schema_sha256"], "lease_seconds": 30,
            })
        projection = _mint_published_local_owner_adoption(
            adoption_handle=adoption_handle, identity_kind="linux-local-owner-v1",
            signed_choice=signed_choice, adopted_at_unix=None,
            setup_deadline_unix=signed_choice["setup_deadline_unix"], owner=owner,
            resources=resources, native_package=package,
            operation_records=tuple(rows), view_custody=view_custody,
            source_members=source_members,
            owner_overlay_observer_records=tuple(observer_rows),
        )
        return (projection,)
    except BootstrapEnrollmentPending:
        raise
    except Exception:
        raise BootstrapEnrollmentPending(
            "selected local-owner overlay lacks a complete current source, target, schema, view, or CAS adoption join") from None


def _validate_projection(row: Mapping[str, Any]) -> None:
    if set(row) != _FIELDS:
        raise TypeError("local-owner adoption row has an unexpected schema")
    if (row["schema"] != 1 or row["identity_kind"] != "linux-local-owner-v1"
            or not isinstance(row["adoption_handle"], str)
            or not _HANDLE.fullmatch(row["adoption_handle"])
            or type(row["setup_deadline_unix"]) not in {int, float}
            or not math.isfinite(row["setup_deadline_unix"])
            or (row["adopted_at_unix"] is not None and
                (type(row["adopted_at_unix"]) not in {int, float}
                 or not math.isfinite(row["adopted_at_unix"])
                 or row["adopted_at_unix"] > row["setup_deadline_unix"]))):
        raise TypeError("local-owner adoption identity, handle, or deadline is invalid")
    if any(not isinstance(row[name], Mapping) for name in
           ("signed_choice", "owner", "resources", "native_package", "view_custody")):
        raise TypeError("local-owner adoption subprojection is malformed")
    for name in ("signed_choice", "owner", "resources", "native_package", "view_custody"):
        if not row[name]:
            raise TypeError(f"local-owner adoption {name} projection is empty")
    choice = row["signed_choice"]
    if set(choice) != _CHOICE_FIELDS:
        raise TypeError("signed owner-overlay choice projection differs from the exact choice row")
    for name in ("selection_handle", "purpose", "signed_record_sha256", "choice_payload_sha256",
                 "principal_id", "profile_id", "namespace_id", "principal_binding_sha256",
                 "namespace_binding_sha256", "service_generation_digest"):
        if not isinstance(choice.get(name), str) or not choice[name]:
            raise TypeError("signed owner-overlay choice projection is incomplete")
    for name in ("signed_record_sha256", "choice_payload_sha256", "principal_binding_sha256",
                 "namespace_binding_sha256", "service_generation_digest",
                 "release_deployment_receipt_sha256", "selection_catalog_sha256"):
        if not _HEX.fullmatch(choice[name]):
            raise TypeError("signed owner-overlay choice digest is malformed")
    for name, fields in (("owner", _OWNER_FIELDS), ("resources", _RESOURCE_FIELDS),
                         ("native_package", _PACKAGE_FIELDS), ("view_custody", _VIEW_FIELDS)):
        if set(row[name]) != fields:
            raise TypeError(f"local-owner adoption {name} projection fields differ from the fixed contract")
    owner = row["owner"]
    for name in ("principal_binding_sha256", "namespace_binding_sha256",
                 "machine_target_sha256", "service_generation_digest"):
        if not isinstance(owner.get(name), str) or not _HEX.fullmatch(owner[name]):
            raise TypeError("owner/account binding digest is malformed")
    if (type(owner["account_uid"]) is not int or owner["account_uid"] <= 0
            or type(owner["primary_gid"]) is not int or owner["primary_gid"] <= 0
            or type(owner["service_uid"]) is not int or owner["service_uid"] <= 0
            or type(owner["service_gid"]) is not int or owner["service_gid"] <= 0
            or owner["principal_id"] != choice["principal_id"]
            or owner["profile_id"] != choice["profile_id"]
            or owner["namespace_id"] != choice["namespace_id"]
            or owner["principal_binding_sha256"] != choice["principal_binding_sha256"]
            or owner["namespace_binding_sha256"] != choice["namespace_binding_sha256"]
            or owner["service_generation_id"] != choice["service_generation_id"]
            or owner["service_generation_digest"] != choice["service_generation_digest"]):
        raise TypeError("local owner projection differs from the signed choice identity")
    if (not isinstance(owner["account_name"], str) or not owner["account_name"]
            or not _HEX.fullmatch(owner["machine_target_sha256"])):
        raise TypeError("local owner NSS or machine target binding is malformed")
    for block, names in (
        (row["resources"], ("source_sha256", "resource_profile_selection_sha256")),
        (row["native_package"], ("compiled_closure_sha256", "entrypoint_sha256", "resolver_sha256",
                                 "owner_overlay_operation_records_sha256", "native_cas_transition_sha256")),
        (row["view_custody"], ("ownership_marker_sha256",)),
    ):
        for name in names:
            if not isinstance(block[name], str) or not _HEX.fullmatch(block[name]):
                raise TypeError("owner-overlay adoption contains a malformed digest")
    if (type(row["resources"]["member_receipt_handles"]) not in {list, tuple}
            or type(row["resources"]["member_sha256s"]) not in {list, tuple}
            or len(row["resources"]["member_receipt_handles"]) != len(row["resources"]["member_sha256s"])
            or not row["resources"]["member_receipt_handles"]):
        raise TypeError("Resources source member closure is incomplete")
    if (not isinstance(row["native_package"]["native_cas_transition_receipt_handle"], str)
            or not _HANDLE.fullmatch(row["native_package"]["native_cas_transition_receipt_handle"])):
        raise TypeError("native CAS transition receipt handle is malformed")
    if (not isinstance(row["view_custody"]["relative_path"], str)
            or row["view_custody"]["relative_path"] != (
                "native-profile-overlays/" + row["view_custody"]["service_profile_id"] + "/"
                + row["view_custody"]["resource_profile_id"])):
        raise TypeError("owner-overlay view path recipe differs from its fixed relative subroot")
    view = row["view_custody"]
    if (view["view_mode"] != 0o700 or view["view_owner_uid"] != 0 or view["view_owner_gid"] != 0
            or view["data_root_owner_uid"] != owner["service_uid"]
            or view["data_root_owner_gid"] != owner["service_gid"]
            or any(type(view[name]) is not int or view[name] <= 0 for name in
                   ("data_root_device", "data_root_inode", "view_device", "view_inode"))):
        raise TypeError("owner-overlay data-root or view custody is not the exact current root view")
    for name in ("data_root_selection_handle", "data_root_receipt_handle", "profile_view_selection_handle",
                 "profile_view_receipt_handle", "target_id", "target_selection_handle", "target_receipt_handle"):
        if not isinstance(view[name], str) or not view[name]:
            raise TypeError("owner-overlay view custody reference is absent")
    if (not isinstance(view["effect_enrollment_ids"], (list, tuple))
            or not view["effect_enrollment_ids"]):
        raise TypeError("owner-overlay effect enrollment rows are absent")
    if (not isinstance(row["operation_records"], (tuple, list))
            or not 1 <= len(row["operation_records"]) <= 4):
        raise TypeError("owner-overlay adoption needs one to four selected operation rows")
    operations = []
    for operation in row["operation_records"]:
        if not isinstance(operation, Mapping):
            raise TypeError("owner-overlay operation row is malformed")
        item = _plain(operation)
        registration = item.get("registration_id")
        expected = _OPERATIONS.get(registration)
        if (set(item) != _OPERATION_FIELDS or expected is None or item.get("method") != expected[0]
                or item.get("operation") != expected[1]
                or item.get("capability") != "plugin:resource-overlay-store"
                or item.get("recipient") is not None
                or item.get("identity_kind", "linux-local-owner-v1") != "linux-local-owner-v1"):
            raise TypeError("owner-overlay adoption includes an unselected operation")
        required_references = (
            "effect_enrollment_id", "target_id", "profile_id", "profile_generation",
            "principal_id", "namespace_id", "package_id", "package_generation",
            "argument_schema_id", "argument_schema_receipt_handle", "result_schema_id",
            "result_schema_receipt_handle", "handler_artifact_id", "handler_source_receipt_handle",
            "profile_view_selection_handle", "profile_view_receipt_handle", "data_root_selection_handle",
            "data_root_receipt_handle", "target_selection_handle", "target_receipt_handle",
            "prepared_source_observer_selection_handle", "process_role_id", "source_issuer_id",
        )
        if any(not isinstance(item.get(name), str) or not item[name] for name in required_references):
            raise TypeError("selected owner-overlay operation has an absent source or custody reference")
        for name in ("argument_schema_sha256", "result_schema_sha256", "handler_sha256"):
            if not isinstance(item.get(name), str) or not _HEX.fullmatch(item[name]):
                raise TypeError("selected owner-overlay operation digest is malformed")
        if (item.get("principal_id") != owner["principal_id"]
                or item.get("namespace_id") != owner["namespace_id"]
                or item.get("profile_id") != owner["profile_id"]
                or item.get("profile_generation") != owner["service_generation_id"]
                or item.get("package_id") != row["native_package"]["package_id"]
                or item.get("package_generation") != row["native_package"]["generation"]
                or item.get("target_id") != row["view_custody"]["target_id"]
                or item.get("profile_view_selection_handle") != row["view_custody"]["profile_view_selection_handle"]):
            raise TypeError("selected owner-overlay operation differs from its active identity/view/package")
        if (not isinstance(item["source_observer_enrollment_ids"], (list, tuple))
                or not item["source_observer_enrollment_ids"]
                or list(item["source_observer_enrollment_ids"])
                   != sorted(set(item["source_observer_enrollment_ids"]))):
            raise TypeError("owner-overlay source role enrollment set is incomplete")
        operations.append(registration)
    if operations != sorted(set(operations)):
        raise TypeError("owner-overlay adoption operations are duplicated or unordered")
    if (not isinstance(row["source_members"], (tuple, list)) or not row["source_members"]
            or any(not isinstance(member, Mapping) for member in row["source_members"])):
        raise TypeError("owner-overlay adoption source closure is absent")
    for member in row["source_members"]:
        if (set(member) != _MEMBER_FIELDS
                or not isinstance(member.get("sha256"), str) or not _HEX.fullmatch(member["sha256"])
                or not isinstance(member.get("receipt_handle"), str)
                or not _HANDLE.fullmatch(member["receipt_handle"])):
            raise TypeError("owner-overlay adoption source member row is malformed")
        if (type(member["size_bytes"]) is not int or member["size_bytes"] <= 0
                or member["mode"] not in {0o400, 0o444, 0o600, 0o644, 0o755}
                or not isinstance(member["relative_path"], str) or not member["relative_path"]
                or not isinstance(member["role"], str) or not member["role"]):
            raise TypeError("owner-overlay adoption source member metadata is malformed")
    observers = row["owner_overlay_observer_records"]
    if (not isinstance(observers, (tuple, list)) or len(observers) != len(row["operation_records"])
            or len(observers) > 4):
        raise TypeError("owner-overlay observer rows must cover the exact selected operation set")
    by_registration = {item.get("registration_id"): item for item in observers
                       if isinstance(item, Mapping)}
    if len(by_registration) != len(observers):
        raise TypeError("owner-overlay observer registration IDs are duplicated")
    for operation in row["operation_records"]:
        observer = by_registration.get(operation["registration_id"])
        if not isinstance(observer, Mapping) or set(observer) != _OBSERVER_FIELDS:
            raise TypeError("owner-overlay observer row has an unexpected schema")
        digest_fields = ("operation_row_sha256", "source_choice_signed_record_sha256",
                         "role_sha256", "role_source_tree_sha256", "argument_schema_sha256",
                         "result_schema_sha256")
        if (observer["schema"] != 1 or observer["observer_kind"] != "owner-overlay-registration-v1"
                or any(not isinstance(observer.get(name), str) or not observer[name]
                       for name in _OBSERVER_FIELDS - {"schema", "choice_epoch", "revocation_epoch", "lease_seconds"})
                or any(not isinstance(observer.get(name), str) or not _HEX.fullmatch(observer[name])
                       for name in digest_fields)
                or any(type(observer.get(name)) is not int or observer[name] < 0
                       for name in ("choice_epoch", "revocation_epoch"))
                or type(observer.get("lease_seconds")) is not int or observer["lease_seconds"] != 30):
            raise TypeError("owner-overlay observer identity or digest is malformed")
        if (observer["registration_id"] != operation["registration_id"]
                or observer["method"] != operation["method"]
                or observer["operation_row_sha256"] != hashlib.sha256(_canonical(_plain(operation))).hexdigest()
                or observer["profile_id"] != owner["profile_id"]
                or observer["profile_generation"] != operation["profile_generation"]
                or observer["principal_id"] != owner["principal_id"]
                or observer["namespace_id"] != owner["namespace_id"]
                or observer["package_id"] != operation["package_id"]
                or observer["package_generation"] != operation["package_generation"]
                or observer["source_choice_selection_handle"] != choice["selection_handle"]
                or observer["source_choice_signed_record_sha256"] != choice["signed_record_sha256"]
                or observer["choice_epoch"] != choice["choice_epoch"]
                or observer["revocation_epoch"] != choice["revocation_epoch"]
                or observer["role_id"] != operation["process_role_id"]
                or observer["source_issuer_id"] != operation["source_issuer_id"]
                or observer["argument_schema_id"] != operation["argument_schema_id"]
                or observer["argument_schema_sha256"] != operation["argument_schema_sha256"]
                or observer["result_schema_id"] != operation["result_schema_id"]
                or observer["result_schema_sha256"] != operation["result_schema_sha256"]
                or observer["invocation_capture_schema_id"] != "native-owner-overlay-invocation-v1"
                or observer["result_capture_schema_id"] != "native-owner-overlay-result-v1"
                or observer["observer_enrollment_id"] not in operation["source_observer_enrollment_ids"]):
            raise TypeError("owner-overlay observer does not join its signed operation and choice")
        if not any(member.get("artifact_id") == observer["role_artifact_id"]
                   and member.get("receipt_handle") == observer["role_source_receipt_handle"]
                   and member.get("sha256") == observer["role_sha256"]
                   and member.get("relative_path") == observer["role_closure_member_path"]
                   for member in row["source_members"]):
            raise TypeError("owner-overlay observer role is not a held source member")
        if not any(member.get("role") == "owner-overlay-capture-schema-source"
                   and member.get("artifact_id") == (
                       "installer-module:hermes_installer.authority.owner_overlay_capture_schemas")
                   for member in row["source_members"]):
            raise TypeError("owner-overlay capture schema module lacks a held release source member")
