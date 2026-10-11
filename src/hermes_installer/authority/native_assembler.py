"""Deterministic compiler for one root-selected native package generation.

The public-facing inputs are opaque setup selection handles. The sealed root
binding resolves all definition rows and file bytes; this module never accepts
paths, catalogs, or caller-authored action/schema records.
"""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from hermes_installer.authority.native_output_receipts import (
    NativeOutputMember,
    RootMaterializationReceiptRegistry,
    RuntimeArtifactReceipt,
)


class NativeAssemblyDenied(PermissionError):
    """A selected native package cannot be compiled from current root proofs."""


class _Selection(Protocol):
    selection_handle: str
    package_id: str
    service_profile_id: str
    resource_profile_id: str
    native_package_generation: str
    compiler_artifact_id: str
    compiler_sha256: str


class _Binding(Protocol):
    def resolve_current_native_bootstrap_assembly(self, selection_handle: str) -> _Selection: ...
    def resolve_native_assembly_definitions(self, selection_handle: str) -> Any: ...
    def resolve_native_assembly_member(self, selection_handle: str,
                                      artifact_receipt_handle: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class NativePackageBytes:
    """Finite compiler outputs before root CAS publication."""

    entrypoint_manifest: bytes
    action_resolver: bytes
    boundary_overlay: bytes
    compiled_closure: bytes
    candidate_index: bytes
    closure_members: tuple[NativeOutputMember, ...]


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise NativeAssemblyDenied("selected native definitions are not canonical JSON") from None


def assemble_native_package(selection: _Selection, definitions: Any,
                            member_bytes: Mapping[str, bytes]) -> NativePackageBytes:
    """Compile exact typed rows and retained member bytes into the five roles.

    Definitions are produced by the sealed setup factory and contain the
    actual Hermes registration names/schema joins, not adapter-name guesses.
    """
    try:
        package_id = selection.package_id
        profile_id = selection.service_profile_id
        generation = selection.native_package_generation
        adapters = [_thaw(row) for row in definitions.adapter_records]
        dependencies = [_thaw(row) for row in getattr(definitions, "dependency_records", ())]
        issuer_rows = [_thaw(row) for row in definitions.source_issuer_records]
        schema_rows = [_thaw(row) for row in definitions.native_schema_records]
        registrations = [_thaw(row) for row in definitions.action_registration_records]
        native_registrations = [_thaw(row) for row in definitions.registration_records]
        candidates = [_thaw(row) for row in definitions.candidate_records]
        process_roles = [_thaw(row) for row in definitions.process_role_records]
        overlay = definitions.boundary_overlay_bytes
        overlay_source = definitions.boundary_overlay_source_commit
        closure_defs = tuple(definitions.closure_members)
        schema_bytes = dict(definitions.native_schema_bytes)
        owner_overlay_records = [_thaw(row) for row in definitions.owner_overlay_operation_records]
    except (AttributeError, TypeError, ValueError):
        raise NativeAssemblyDenied("root-selected native definition projection is incomplete") from None
    if (package_id != "hermes-agent-native-package-v1"
            or profile_id != "hermes-agent-native-v1"
            or not isinstance(generation, str) or len(generation) != 64
            or not isinstance(overlay, bytes) or not overlay
            or not isinstance(overlay_source, str) or len(overlay_source) != 40
            or not isinstance(member_bytes, Mapping)):
        raise NativeAssemblyDenied("native package identity or selected overlay is invalid")
    # RootNativeAssemblyDefinitions uses the strict projection's canonical
    # schema key `id`. Do not accept a second alias here: the same row set is
    # consumed by native_registration_projection before compilation.
    if (any(not isinstance(row, Mapping) or not isinstance(row.get("id"), str)
            or "schema_id" in row for row in schema_rows)
            or set(schema_bytes) != {row["id"] for row in schema_rows}):
        raise NativeAssemblyDenied("native schema documents do not match selected schema records")
    _validate_process_role_records(selection, process_roles, closure_defs)
    _validate_owner_overlay_records(selection, owner_overlay_records, native_registrations,
                                    schema_rows, closure_defs)
    process_roles_sha256 = hashlib.sha256(_canonical(process_roles)).hexdigest()

    resolver = {
        "schema": 1,
        "package_id": package_id,
        "profile_id": profile_id,
        "generation": generation,
        "adapters": adapters,
        "actions": registrations,
        "source_issuers": issuer_rows,
        "native_schemas": schema_rows,
        "process_role_records_sha256": process_roles_sha256,
        "effect_selection_receipt_handles": list(definitions.effect_selection_receipt_handles),
        "owner_overlay_operation_records": owner_overlay_records,
    }
    resolver_bytes = _canonical(resolver)
    resolver_sha = hashlib.sha256(resolver_bytes).hexdigest()
    # v113 source definitions retain schema IDs; the emitted registration also
    # carries the exact server selected by the strict candidate projector.
    candidates_by_id = {row.get("registration_id"): row for row in candidates}
    for registration in native_registrations:
        if "argument_schema_id" in registration:
            candidate = candidates_by_id.get(registration.get("registration_id"))
            if candidate is None or not isinstance(candidate.get("native_server_name"), str):
                raise NativeAssemblyDenied("selected registration has no exact projected native server")
            registration["native_server_name"] = candidate["native_server_name"]
    registration_projection_sha = hashlib.sha256(_canonical(native_registrations)).hexdigest()
    candidate_index = {
        "schema": 1,
        "package_id": package_id,
        "profile_id": profile_id,
        "generation": generation,
        "resolver_sha256": resolver_sha,
        "registration_projection_sha256": registration_projection_sha,
        "registrations": native_registrations,
        "candidates": candidates,
    }
    candidate_bytes = _canonical(candidate_index)

    closure: dict[str, tuple[bytes, int]] = {}
    for row in closure_defs:
        path = row.relative_path
        content = member_bytes.get(row.artifact_receipt_handle)
        if (not isinstance(content, bytes) or len(content) != row.size_bytes
                or hashlib.sha256(content).hexdigest() != row.sha256
                or path in closure):
            raise NativeAssemblyDenied("retained native closure member differs from its source receipt")
        closure[path] = (content, row.mode)
    # Schema bytes are source-receipt-backed factory projections. Place them in
    # the package catalog so a future runtime can resolve without ambient files.
    for schema_id, content in schema_bytes.items():
        if not isinstance(schema_id, str) or not isinstance(content, bytes):
            raise NativeAssemblyDenied("retained native schema document is malformed")
        path = f"catalog/schemas/{schema_id}.json"
        if path in closure:
            raise NativeAssemblyDenied("native schema path collides with another selected member")
        closure[path] = (content, 0o644)

    overlay_doc = _json_object(overlay)
    if (set(overlay_doc) != {"schema", "source_commit", "compiler_artifact_id", "compiler_sha256", "members"}
            or overlay_doc["source_commit"] != overlay_source
            or overlay_doc["compiler_artifact_id"] != selection.compiler_artifact_id
            or overlay_doc["compiler_sha256"] != selection.compiler_sha256):
        raise NativeAssemblyDenied("boundary overlay receipt differs from the selected compiler")
    # The factory's retained closure includes every exact patched overlay file;
    # verify the overlay manifest against those byte identities before bundling.
    for member in overlay_doc["members"]:
        path = member["path"]
        found = closure.get(path)
        if found is None or hashlib.sha256(found[0]).hexdigest() != member["sha256"] or len(found[0]) != member["size_bytes"]:
            raise NativeAssemblyDenied("boundary overlay member is absent from the selected closure")
    closure["overlay/manifest.json"] = (overlay, 0o644)
    closure["resolver/resolver"] = (resolver_bytes, 0o644)
    closure["catalog/native-candidates.json"] = (candidate_bytes, 0o644)

    closure_rows = [
        {"relative_path": path, "sha256": hashlib.sha256(content).hexdigest(),
         "size_bytes": len(content), "mode": mode}
        for path, (content, mode) in sorted(closure.items())
    ]
    manifest = {
        "schema": 1, "package_id": package_id, "profile_id": profile_id,
        "generation": generation, "closure_files": closure_rows,
        "adapters": adapters, "dependencies": dependencies,
        "process_role_records": process_roles,
        "process_role_records_sha256": process_roles_sha256,
        "resolver_sha256": resolver_sha,
        "candidate_index": {
            "artifact_id": f"native-candidate-index:{package_id}:{generation}",
            "relative_path": "catalog/native-candidates.json",
            "sha256": hashlib.sha256(candidate_bytes).hexdigest(),
            "size_bytes": len(candidate_bytes),
        },
    }
    manifest_bytes = _canonical(manifest)
    closure_digest = hashlib.sha256(_canonical(closure_rows)).hexdigest()
    tar_files = {"manifest.json": (manifest_bytes, 0o644)}
    tar_files.update({f"closure/{path}": value for path, value in closure.items()})
    tar_files["overlay/manifest.json"] = (overlay, 0o644)
    tar_files["resolver/resolver"] = (resolver_bytes, 0o644)
    tar_files["catalog/native-candidates.json"] = (candidate_bytes, 0o644)
    archive_bytes, archive_members = _deterministic_tar(tar_files)
    return NativePackageBytes(manifest_bytes, resolver_bytes, overlay,
                              archive_bytes, candidate_bytes, archive_members)


_OWNER_OVERLAY_FIELDS = frozenset({
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
_OWNER_OVERLAY_METHODS = {
    "resource-overlay-store:tool:resource_overlay_read": ("read", "plugin.resource-overlay-store.read", "read"),
    "resource-overlay-store:tool:resource_overlay_history": ("history", "plugin.resource-overlay-store.read", "read"),
    "resource-overlay-store:tool:resource_overlay_write": ("write", "plugin.resource-overlay-store.write", "write"),
    "resource-overlay-store:tool:resource_overlay_delete": ("delete", "plugin.resource-overlay-store.write", "write"),
}


def _validate_owner_overlay_records(selection: _Selection, rows: list[dict[str, Any]],
                                    registrations: list[dict[str, Any]],
                                    schemas: list[dict[str, Any]],
                                    closure: tuple[Any, ...]) -> None:
    """Validate the separate four-operation lane against genuine selected source rows."""
    if not isinstance(rows, list) or len(rows) > 4:
        raise NativeAssemblyDenied("owner-overlay operation lane exceeds its fixed row bound")
    ids = [row.get("registration_id") if isinstance(row, dict) else None for row in rows]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise NativeAssemblyDenied("owner-overlay operation rows are not uniquely canonical")
    by_registration = {row.get("registration_id"): row for row in registrations}
    schema_ids = {row.get("id") for row in schemas}
    closure_digests = {row.sha256 for row in closure}
    shared_bindings: dict[str, Any] | None = None
    shared_keys = ("profile_id", "profile_generation",
                   "principal_id", "namespace_id", "package_id", "package_generation",
                   "profile_view_selection_handle", "profile_view_receipt_handle",
                   "data_root_selection_handle", "data_root_receipt_handle")
    for row in rows:
        if set(row) != _OWNER_OVERLAY_FIELDS:
            raise NativeAssemblyDenied("owner-overlay operation row fields differ from v172")
        fixed = _OWNER_OVERLAY_METHODS.get(row["registration_id"])
        if (fixed is None or (row["method"], row["operation"], row["capability"])
                != (fixed[0], fixed[1], "plugin:resource-overlay-store")
                or row["recipient"] is not None
                or row["package_id"] != selection.package_id
                or row["package_generation"] != selection.native_package_generation
                or row["argument_schema_id"] not in schema_ids
                or row["result_schema_id"] not in schema_ids
                or row["handler_sha256"] not in closure_digests
                or not isinstance(row["source_observer_enrollment_ids"], list)
                or not row["source_observer_enrollment_ids"]):
            raise NativeAssemblyDenied("owner-overlay operation row does not join its fixed selected source")
        registration = by_registration.get(row["registration_id"])
        references = (
            "target_id", "effect_enrollment_id", "profile_id", "profile_generation", "principal_id",
            "namespace_id", "argument_schema_receipt_handle", "result_schema_receipt_handle",
            "handler_artifact_id", "handler_source_receipt_handle", "profile_view_selection_handle",
            "profile_view_receipt_handle", "data_root_selection_handle", "data_root_receipt_handle",
            "target_selection_handle", "target_receipt_handle",
            "prepared_source_observer_selection_handle", "process_role_id", "source_issuer_id",
        )
        digests = ("argument_schema_sha256", "result_schema_sha256", "handler_sha256")
        invalid = []
        if registration is None or registration.get("handler_kind") != "owner-overlay": invalid.append("registration-kind")
        elif registration.get("argument_schema_id") != row["argument_schema_id"]: invalid.append("argument-schema-id")
        elif registration.get("result_schema_id") != row["result_schema_id"]: invalid.append("result-schema-id")
        elif registration.get("registration_source_sha256") != row["handler_sha256"]: invalid.append("source-digest")
        elif registration.get("registration_source_receipt_handle") != row["handler_source_receipt_handle"]: invalid.append("source-receipt")
        optional_references = {"data_root_selection_handle", "data_root_receipt_handle",
                               "target_receipt_handle"}
        bad_references = [key for key in references
                          if ((row.get(key) is None and key not in optional_references)
                              or (row.get(key) not in (None, "")
                                  and (not isinstance(row[key], str) or not row[key]
                                       or len(row[key]) > 256))
                              or (row.get(key) == "" and key not in optional_references))]
        if bad_references:
            invalid.append("reference")
        if row.get("recipient") is not None:
            invalid.append("recipient")
        if (any(not isinstance(row.get(key), str) or len(row[key]) != 64
                or any(char not in "0123456789abcdef" for char in row[key]) for key in digests)):
            invalid.append("digest")
        observer_ids = row["source_observer_enrollment_ids"]
        if (not isinstance(observer_ids, (list, tuple))
                or any(not isinstance(item, str) or not item for item in observer_ids)
                or list(observer_ids) != sorted(set(observer_ids))):
            invalid.append("observer-order")
        current_bindings = {key: row[key] for key in shared_keys}
        if shared_bindings is None:
            shared_bindings = current_bindings
        elif current_bindings != shared_bindings:
            invalid.append("shared-current-selection")
        if (registration is None or registration.get("handler_kind") != "owner-overlay"
                or registration.get("argument_schema_id") != row["argument_schema_id"]
                or registration.get("result_schema_id") != row["result_schema_id"]
                or registration.get("registration_source_sha256") != row["handler_sha256"]
                or registration.get("registration_source_receipt_handle") != row["handler_source_receipt_handle"]
                or invalid):
            raise NativeAssemblyDenied("owner-overlay source operation differs from its registration projection: "
                                       + ",".join(invalid or ["source-join"]))


class RootNativePackageAssembler:
    """Root-only bridge from factory-sealed definitions to five CAS receipts."""

    def __init__(self, binding: _Binding, output_registry: RootMaterializationReceiptRegistry):
        if (not callable(getattr(binding, "resolve_current_native_bootstrap_assembly", None))
                or not callable(getattr(binding, "resolve_native_assembly_definitions", None))
                or not callable(getattr(binding, "resolve_native_assembly_member", None))
                or not callable(getattr(output_registry, "publish_selected", None))):
            raise NativeAssemblyDenied("native assembler requires root binding and receipt registry")
        self._binding = binding
        self._outputs = output_registry

    def compile_selected(self, selection: _Selection) -> tuple[RuntimeArtifactReceipt, ...]:
        if not isinstance(getattr(selection, "selection_handle", None), str):
            raise NativeAssemblyDenied("native assembly selection is not a root-issued handle")
        try:
            current = self._binding.resolve_current_native_bootstrap_assembly(selection.selection_handle)
            if current != selection:
                raise NativeAssemblyDenied("native assembly selection is stale or altered")
            definitions = self._binding.resolve_native_assembly_definitions(selection.selection_handle)
            if (definitions.selection_handle != selection.selection_handle
                    or definitions.definitions_sha256 != selection.definitions_sha256):
                raise NativeAssemblyDenied("native assembly definitions do not match the selection")
            resolved = {
                row.artifact_receipt_handle: self._binding.resolve_native_assembly_member(
                    selection.selection_handle, row.artifact_receipt_handle)
                for row in definitions.closure_members
            }
            # Currentness is checked again immediately before compilation/CAS.
            package = assemble_native_package(selection, definitions, resolved)
            if self._binding.resolve_current_native_bootstrap_assembly(selection.selection_handle) != selection:
                raise NativeAssemblyDenied("native selection changed during compilation")
            closure_rows = _manifest_rows(package.compiled_closure)
            tree_digest = hashlib.sha256(_canonical(closure_rows)).hexdigest()
            # Publish closure first; subsequent role publications cross-check
            # every previously stored counterpart and exact embedded bytes.
            values = (
                ("native-compiled-closure", "compiled-closure", package.compiled_closure,
                 package.closure_members),
                ("native-entrypoint-manifest", "entrypoint-json", package.entrypoint_manifest,
                 (NativeOutputMember("manifest.json", hashlib.sha256(package.entrypoint_manifest).hexdigest(), len(package.entrypoint_manifest), 0o644),)),
                ("native-action-resolver", "resolver-json", package.action_resolver,
                 (NativeOutputMember("resolver/resolver", hashlib.sha256(package.action_resolver).hexdigest(), len(package.action_resolver), 0o644),)),
                ("native-boundary-overlay", "boundary-overlay", package.boundary_overlay,
                 (NativeOutputMember("overlay/manifest.json", hashlib.sha256(package.boundary_overlay).hexdigest(), len(package.boundary_overlay), 0o644),)),
                ("native-candidate-index", "candidate-index-json", package.candidate_index,
                 (NativeOutputMember("catalog/native-candidates.json", hashlib.sha256(package.candidate_index).hexdigest(), len(package.candidate_index), 0o644),)),
            )
            receipts = tuple(self._outputs.publish_selected(
                artifact_role=role, output_kind=kind, payload=payload, members=members,
                assembly_selection_handle=selection.selection_handle,
            ) for role, kind, payload, members in values)
            if self._binding.resolve_current_native_bootstrap_assembly(selection.selection_handle) != selection:
                raise NativeAssemblyDenied("native selection changed while outputs were published")
            if hashlib.sha256(_canonical(closure_rows)).hexdigest() != tree_digest:
                raise NativeAssemblyDenied("compiled closure changed during publication")
            return receipts
        except NativeAssemblyDenied:
            raise
        except Exception:
            raise NativeAssemblyDenied("root-selected native package compilation failed closed") from None


def _manifest_rows(archive: bytes) -> list[dict[str, Any]]:
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
            row = stream.extractfile("manifest.json")
            if row is None:
                raise ValueError
            value = json.loads(row.read())
            return value["closure_files"]
    except Exception:
        raise NativeAssemblyDenied("compiled closure lacks its canonical manifest") from None


def _deterministic_tar(files: Mapping[str, tuple[bytes, int]]) -> tuple[bytes, tuple[NativeOutputMember, ...]]:
    output = io.BytesIO()
    members = []
    try:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path, (content, mode) in sorted(files.items()):
                info = tarfile.TarInfo(path)
                info.size = len(content)
                info.mode = mode
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(content))
                members.append(NativeOutputMember(path, hashlib.sha256(content).hexdigest(), len(content), mode))
    except (OSError, ValueError, tarfile.TarError):
        raise NativeAssemblyDenied("deterministic native closure archive failed") from None
    return output.getvalue(), tuple(members)


def _json_object(payload: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8", errors="strict"))
        if not isinstance(value, dict) or _canonical(value) != payload:
            raise ValueError
        return value
    except (ValueError, UnicodeError):
        raise NativeAssemblyDenied("selected native JSON bytes are not canonical") from None


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw(item) for item in value]
    return value


def _validate_process_role_records(selection: _Selection, rows: list[dict[str, Any]],
                                   closure_members: Sequence[Any]) -> None:
    """Require explicit source-backed role/module joins for every new package."""
    import re
    fields = {
        "role_id", "package_id", "native_package_generation", "profile_id",
        "profile_generation", "role_artifact_id", "role_sha256",
        "role_source_receipt_handle", "module_name", "closure_member_path",
        "role_source_revision", "role_source_tree_sha256", "observer_enrollment_ids",
        "registration_ids", "action_binding_ids", "workflow_ids",
    }
    sha = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
    module = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z", re.ASCII)
    safe_id = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z", re.ASCII)
    if not isinstance(rows, list) or not rows:
        raise NativeAssemblyDenied("selected package has no reviewed process-role records")
    member_by_path = {row.relative_path: row for row in closure_members}
    identifiers: set[str] = set()
    modules: set[str] = set()
    paths: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields:
            raise NativeAssemblyDenied("selected process-role row has unknown or missing fields")
        role_id = row["role_id"]
        path = row["closure_member_path"]
        if (not isinstance(role_id, str) or not safe_id.fullmatch(role_id) or role_id in identifiers
                or row["package_id"] != selection.package_id
                or row["native_package_generation"] != selection.native_package_generation
                or row["profile_id"] != selection.service_profile_id
                or row["profile_generation"] != selection.service_generation
                or not isinstance(row["role_artifact_id"], str) or not safe_id.fullmatch(row["role_artifact_id"])
                or not isinstance(row["role_sha256"], str) or not sha.fullmatch(row["role_sha256"])
                or not isinstance(row["role_source_receipt_handle"], str)
                or not safe_id.fullmatch(row["role_source_receipt_handle"])
                or not isinstance(row["module_name"], str) or not module.fullmatch(row["module_name"])
                or not isinstance(path, str) or not _safe_closure_path(path)
                or not isinstance(row["role_source_revision"], str)
                or not re.fullmatch(r"[0-9a-f]{40,64}", row["role_source_revision"], re.ASCII)
                or not isinstance(row["role_source_tree_sha256"], str)
                or not sha.fullmatch(row["role_source_tree_sha256"])):
            raise NativeAssemblyDenied("selected process-role identity or generation is invalid")
        member = member_by_path.get(path)
        if member is None or member.sha256 != row["role_sha256"]:
            raise NativeAssemblyDenied("process-role module is not its exact source-receipted closure member")
        if row["module_name"] in modules or path in paths:
            raise NativeAssemblyDenied("selected process-role module identity collides")
        for key in ("observer_enrollment_ids", "registration_ids", "action_binding_ids", "workflow_ids"):
            values = row[key]
            if (not isinstance(values, list) or any(not isinstance(value, str) for value in values)
                    or len(values) != len(set(values))
                    or any(not safe_id.fullmatch(value) for value in values)
                    or values != sorted(values)):
                raise NativeAssemblyDenied("selected process-role foreign-key list is invalid")
        if not row["observer_enrollment_ids"]:
            raise NativeAssemblyDenied("selected process role has no enrolled observers")
        identifiers.add(role_id)
        modules.add(row["module_name"])
        paths.add(path)
    if rows != sorted(rows, key=lambda row: row["role_id"]):
        raise NativeAssemblyDenied("process-role rows are not canonically ordered")


def _safe_closure_path(value: str) -> bool:
    from pathlib import PurePosixPath
    path = PurePosixPath(value)
    return (not path.is_absolute() and bool(path.parts)
            and all(part not in {"", ".", ".."} for part in path.parts)
            and "\\" not in value and "\x00" not in value)
