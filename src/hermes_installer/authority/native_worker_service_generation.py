"""Root-issued schema-2 service-generation rows for a selected native worker.

This producer accepts only current sealed source choices and recipe handles.
It never accepts row mappings or turns a static recipe into authority.  Until
the selected runtime tree has actual root-owned member receipts, issuance stays
pending rather than emitting incomplete catalogs.
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
from types import MappingProxyType
from typing import Any, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentPending
from .native_worker_recipes import (
    NativeWorkerRecipeUnavailable, RootPreparedNativeWorkerRecipe,
    RootSetupNativeWorkerRecipeRegistry,
)

_MAX_TTL = 300.0
_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class NativeServiceGenerationUnavailable(BootstrapEnrollmentPending):
    """Selected worker rows lack exact current source/runtime custody."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _freeze_json(value: Any) -> Any:
    if value is None or type(value) in (str, int, float, bool):
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise NativeServiceGenerationUnavailable("generation row has a non-string JSON key")
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_json(item) for item in value)
    raise NativeServiceGenerationUnavailable("generation row contains a non-JSON value")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedNativeServiceGeneration:
    """Immutable five-catalog generation payload; no container digest is embedded."""

    schema: int
    receipt_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    source_choice_selection_handle: str
    source_choice_signed_record_sha256: str
    worker_recipe_receipt_handle: str
    worker_recipe_sha256: str
    service_generation_id: str
    generation_id: str
    service_records: tuple[Mapping[str, Any], ...]
    process_profile_records: tuple[Mapping[str, Any], ...]
    native_worker_network_records: tuple[Mapping[str, Any], ...]
    active_network_generation_records: tuple[Mapping[str, Any], ...]
    native_worker_runtime_records: tuple[Mapping[str, Any], ...]
    source_member_receipt_handles: tuple[str, ...]
    root_journal_id: str
    root_journal_generation: str
    output_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _issuer: object = field(repr=False, compare=False)
    _recipe: RootPreparedNativeWorkerRecipe = field(repr=False, compare=False)
    _selection: Any = field(repr=False, compare=False)
    _runtime_materialization: Any = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootPreparedNativeServiceGeneration(<root-held>)"


class RootPreparedNativeServiceGenerationProducer:
    """Join one signed source recipe to actual generated runtime member rows."""

    def __init__(self, binding: Any, recipe_registry: RootSetupNativeWorkerRecipeRegistry,
                 active_compiler: Any, prepared_enrollment_store: Any):
        from .active_policy_compiler import RootActivePolicyCompilationRegistry
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .bootstrap_enrollment import RootBootstrapEnrollment
        if (type(binding) is not RootSelectedInstallationBinding
                or type(recipe_registry) is not RootSetupNativeWorkerRecipeRegistry
                or recipe_registry.binding is not binding
                or type(active_compiler) is not RootActivePolicyCompilationRegistry
                or active_compiler.factory is not binding._session._factory
                or type(prepared_enrollment_store) is not RootBootstrapEnrollment
                or prepared_enrollment_store is not binding._session._transaction):
            raise ValueError("native service-generation producer requires exact retained setup authorities")
        self.binding = binding
        self.recipe_registry = recipe_registry
        self.active_compiler = active_compiler
        self.prepared_enrollment_store = prepared_enrollment_store
        self._issuer = object()
        self._issued: dict[str, RootPreparedNativeServiceGeneration] = {}

    @classmethod
    def from_root_setup(cls, current_binding: Any,
                        recipe_registry: RootSetupNativeWorkerRecipeRegistry,
                        active_compiler: Any,
                        prepared_enrollment_store: Any) -> "RootPreparedNativeServiceGenerationProducer":
        return cls(current_binding, recipe_registry, active_compiler,
                   prepared_enrollment_store)

    def build_selected(self, recipe_handles: tuple[str, ...],
                       native_policy_selection: Any, *,
                       base_policy: Any) -> RootPreparedNativeServiceGeneration:
        session = self.binding._session
        session._check_live()
        from .bootstrap_enrollment import EnrollmentPolicy
        from .native_policy_preparation import RootNativePolicyPreparationSelection
        if type(base_policy) is not EnrollmentPolicy:
            raise NativeServiceGenerationUnavailable(
                "selected native generation requires the exact root factory-expanded enrollment policy")
        if type(native_policy_selection) is not RootNativePolicyPreparationSelection:
            raise NativeServiceGenerationUnavailable("a current signed native policy selection is required")
        if (not isinstance(recipe_handles, tuple) or len(recipe_handles) != 1
                or any(not isinstance(handle, str) or not handle for handle in recipe_handles)):
            raise NativeServiceGenerationUnavailable("first native worker generation requires one selected recipe")
        current_handle = getattr(session, "_current_native_policy_selection_handle", None)
        if current_handle != native_policy_selection.selection_handle:
            raise NativeServiceGenerationUnavailable("native policy selection handle is not current")
        current_selection = self.binding.resolve_current_native_policy_selection(current_handle)
        if current_selection is not native_policy_selection:
            raise NativeServiceGenerationUnavailable("native policy selection changed before generation build")
        signed_handles = getattr(current_selection, "selected_worker_recipe_handles", None)
        signed_records = getattr(current_selection, "selected_worker_recipe_records", None)
        signed_digests = getattr(current_selection, "selected_worker_recipe_digests", None)
        if (not isinstance(signed_handles, tuple) or signed_handles != recipe_handles
                or not isinstance(signed_records, tuple) or len(signed_records) != 1
                or not isinstance(signed_digests, tuple) or len(signed_digests) != 1):
            raise NativeServiceGenerationUnavailable(
                "signed native-policy choice lacks the closed selected worker recipe projection")
        recipe = self.recipe_registry.resolve_current_recipe(recipe_handles[0])
        signed_record = signed_records[0]
        if not isinstance(signed_record, Mapping) or _plain(recipe.public_projection()) != _plain(signed_record):
            raise NativeServiceGenerationUnavailable("selected source recipe differs from signed choice bytes")
        if signed_digests[0] != recipe.complete_recipe_sha256:
            raise NativeServiceGenerationUnavailable("signed recipe digest differs from current held source recipe")
        closure = self.recipe_registry.resolve_current_runnable_closure(current_selection)
        materializer = session.resolve_current_native_worker_runtime_materialization_registry()
        materialization = materializer.materialize_selected(
            recipe, closure, current_selection)
        if materializer.verify_current(materialization) is not materialization:
            raise NativeServiceGenerationUnavailable(
                "native runtime materialization is not the exact current root-held receipt")
        service_row, process_row = self._selected_service_and_process_rows(
            base_policy, recipe, materialization)
        endpoint = self.recipe_registry.endpoint_observer.verify_current(recipe._endpoint)
        identity = self.binding.resolve_current_setup_identity()
        selection_snapshot = self.binding.resolve_current_setup_choice(
            current_selection.setup_choice_selection_handle, "native-policy-preparation")
        if (selection_snapshot.selection_handle != current_selection.setup_choice_selection_handle
                or selection_snapshot.purpose != "native-policy-preparation"
                or selection_snapshot.choice_payload_sha256 != current_selection.choice_payload_sha256
                or selection_snapshot.signed_record_sha256 == ""
                or selection_snapshot.setup_deadline_unix <= 0
                or selection_snapshot.choice_epoch != current_selection.choice_epoch
                or selection_snapshot.revocation_epoch != current_selection.revocation_epoch
                or tuple(selection_snapshot.source_member_receipt_handles)
                   != tuple(current_selection.source_member_receipt_handles)
                or identity.principal.principal_id != current_selection.principal_id
                or identity.namespace.namespace_id != current_selection.namespace_id
                or identity.principal_binding_sha256 != recipe.principal_binding_sha256
                or identity.namespace_binding_sha256 != recipe.namespace_binding_sha256):
            raise NativeServiceGenerationUnavailable(
                "signed setup choice or current principal/namespace identity changed before row production")
        journal = session._current_root_journal_selection()
        if (journal.device != session._authorization.root_journal_root.get("device")
                or journal.inode != session._authorization.root_journal_root.get("inode")
                or journal.generation != session._authorization.root_journal_root.get("generation")):
            raise NativeServiceGenerationUnavailable("root journal custody changed before row production")
        from .private_loopback_network import POLICY_ID as PRIVATE_LOOPBACK_POLICY_ID
        from .private_loopback_network import POLICY_SHA256 as PRIVATE_LOOPBACK_POLICY_SHA256
        native_network = {
            "schema": 1,
            "id": recipe.network_id,
            "generation": recipe.profile_generation,
            "namespace_identity": identity.namespace.namespace_id,
            "worker_enrollment_id": recipe.service_enrollment_id,
            "worker_profile_id": recipe.service_profile_id,
            "role": "af-unix",
            "authority_endpoint_id": endpoint.endpoint_id,
            "endpoint_root_id": endpoint.endpoint_root_id,
            "endpoint_relative_socket": endpoint.endpoint_relative_socket,
            "endpoint_receipt_handle": endpoint.receipt_handle,
            "endpoint_receipt_sha256": endpoint.endpoint_sha256,
            # This is the finite AF_UNIX worker network policy asset, not the
            # unrelated bootstrap-policy artifact used to authorize setup.
            "policy_artifact_id": PRIVATE_LOOPBACK_POLICY_ID,
            "policy_sha256": PRIVATE_LOOPBACK_POLICY_SHA256,
        }
        runtime_id = f"{recipe.recipe_id}:{recipe.profile_generation}"
        source_handles = tuple(sorted(selection_snapshot.source_member_receipt_handles))
        if (not source_handles or len(set(source_handles)) != len(source_handles)):
            raise NativeServiceGenerationUnavailable(
                "selected source/member receipt handles are empty or duplicated")
        source_definition_records = self._source_definition_member_records(recipe)
        if tuple(sorted(row["receipt_handle"] for row in source_definition_records)) != source_handles:
            raise NativeServiceGenerationUnavailable(
                "held source-definition member rows do not exactly cover the signed choice handles")
        runtime_row = {
            "schema": 1,
            "id": runtime_id,
            "generation_id": base_policy.generation_id,
            "recipe_id": recipe.recipe_id,
            "recipe_sha256": recipe.complete_recipe_sha256,
            "source_choice_selection_handle": selection_snapshot.selection_handle,
            "profile_id": recipe.service_profile_id,
            "profile_generation": recipe.profile_generation,
            "service_enrollment_id": recipe.service_enrollment_id,
            "hermes_source_receipt_handle": session._prepared_native_bundle.hermes_source_receipt_handle,
            "hermes_source_artifact_id": recipe._start_recipe.source_artifact_id,
            "hermes_source_sha256": recipe._start_recipe.source_archive_sha256,
            "pm_runtime_receipt_handle": materialization.pm_runtime_receipt_handle,
            "pm_base_closure_sha256": materialization.pm_base_closure_sha256,
            "pm_executable_relative_path": materialization.pm_executable_relative_path,
            "pm_executable_member_sha256": materialization.pm_executable_member_sha256,
            "pm_runtime_member_records": [_plain(row) for row in materialization.pm_runtime_member_records],
            "native_output_member_records": [_plain(row) for row in materialization.native_output_member_records],
            "source_member_receipt_handles": list(source_handles),
            "source_definition_member_records": source_definition_records,
            "owned_runtime_root_receipt_handle": materialization.receipt_handle,
            "owned_runtime_root_receipt_sha256": materialization.receipt_sha256,
            "native_package_id": current_selection.package_id,
            "native_package_generation": current_selection.native_package_generation,
        }
        network_sha = _digest(native_network)
        runtime_sha = _digest(runtime_row)
        service_sha = _digest(service_row)
        process_sha = _digest(process_row)
        active_row = {
            "schema": 1,
            "id": f"active:{base_policy.generation_id}:{recipe.network_id}",
            "generation_id": base_policy.generation_id,
            "recipe_id": recipe.recipe_id,
            "recipe_sha256": recipe.complete_recipe_sha256,
            "recipe_definition_receipt_handle": recipe.definition_member_receipt_handle,
            "recipe_definition_sha256": recipe.definition_member_sha256,
            "source_choice_selection_handle": selection_snapshot.selection_handle,
            "source_choice_purpose": selection_snapshot.purpose,
            "source_choice_signed_record_sha256": selection_snapshot.signed_record_sha256,
            "source_choice_payload_sha256": selection_snapshot.choice_payload_sha256,
            "source_choice_epoch": selection_snapshot.choice_epoch,
            "source_choice_revocation_epoch": selection_snapshot.revocation_epoch,
            "source_original_setup_deadline_unix": selection_snapshot.setup_deadline_unix,
            "source_member_receipt_handles": list(source_handles),
            "identity_kind": identity.principal.identity_kind,
            "principal_id": identity.principal.principal_id,
            "namespace_id": identity.namespace.namespace_id,
            "principal_binding_sha256": identity.principal_binding_sha256,
            "namespace_binding_sha256": identity.namespace_binding_sha256,
            "service_enrollment_id": recipe.service_enrollment_id,
            "service_generation": recipe.profile_generation,
            "service_row_sha256": service_sha,
            "process_profile_id": recipe.process_profile_id,
            "process_profile_generation": recipe.profile_generation,
            "process_row_sha256": process_sha,
            "network_catalog": "native_worker_network_records",
            "network_id": recipe.network_id,
            "network_generation": recipe.profile_generation,
            "network_row_sha256": network_sha,
            "root_journal_id": journal.root_id,
            "root_journal_generation": journal.generation,
            "worker_runtime_record_id": runtime_id,
            "worker_runtime_record_sha256": runtime_sha,
        }
        from .native_worker_generation_schema import validate_row
        try:
            validate_row(native_network, "native_worker_network_record", path="native_worker_network_record")
            validate_row(active_row, "active_network_generation_record",
                         path="active_network_generation_record")
            validate_row(runtime_row, "native_worker_runtime_record",
                         path="native_worker_runtime_record")
        except ValueError as exc:
            raise NativeServiceGenerationUnavailable(
                "selected native service generation differs from the closed v184 row schema") from exc
        if (process_row.get("profile_id") != recipe.process_profile_id
                or process_row.get("generation") != recipe.profile_generation
                or service_row.get("profile_id") != recipe.service_profile_id
                or service_row.get("generation") != recipe.profile_generation
                or service_row.get("enrollment_id") != recipe.service_enrollment_id
                or native_network.get("id") != recipe.network_id
                or native_network.get("generation") != recipe.profile_generation
                or native_network.get("worker_profile_id") != recipe.service_profile_id
                or runtime_row.get("id") != runtime_id
                or runtime_row.get("generation_id") != base_policy.generation_id
                or runtime_row.get("source_member_receipt_handles") != list(source_handles)
                or [row.get("receipt_handle") for row in runtime_row["source_definition_member_records"]]
                   != list(source_handles)
                or active_row.get("service_row_sha256") != _digest(service_row)
                or active_row.get("process_row_sha256") != _digest(process_row)
                or active_row.get("network_row_sha256") != _digest(native_network)
                or active_row.get("worker_runtime_record_sha256") != _digest(runtime_row)):
            raise NativeServiceGenerationUnavailable(
                "selected native service-generation rows do not satisfy their exact cross-catalog joins")
        if current_selection.native_package_generation is None:
            raise NativeServiceGenerationUnavailable(
                "selected source/member and native package generation closure is incomplete")
        issued = time.monotonic()
        expiry = min(recipe.expires_monotonic, materialization.expires_monotonic,
                     current_selection.expires_monotonic, identity.expires_monotonic,
                     issued + _MAX_TTL)
        if expiry <= issued:
            raise NativeServiceGenerationUnavailable("selected service generation lease expired")
        body = {
            "service_generation_id": recipe.profile_generation,
            "generation_id": base_policy.generation_id,
            "service_records": [service_row],
            "process_profile_records": [process_row],
            "native_worker_network_records": [native_network],
            "active_network_generation_records": [active_row],
            "native_worker_runtime_records": [runtime_row],
            "source_choice_selection_handle": selection_snapshot.selection_handle,
            "source_choice_signed_record_sha256": selection_snapshot.signed_record_sha256,
            "worker_recipe_receipt_handle": recipe.receipt_handle,
            "worker_recipe_sha256": recipe.complete_recipe_sha256,
            "source_member_receipt_handles": list(source_handles),
        }
        generation = RootPreparedNativeServiceGeneration(
            schema=1, receipt_handle=secrets.token_urlsafe(36),
            setup_session_id=recipe.setup_session_id, transaction_handle=recipe.transaction_handle,
            plan_sha256=current_selection.plan_sha256,
            prepared_generation_id=recipe.prepared_generation_id,
            prepared_generation_digest=recipe.prepared_generation_digest,
            source_choice_selection_handle=selection_snapshot.selection_handle,
            source_choice_signed_record_sha256=selection_snapshot.signed_record_sha256,
            worker_recipe_receipt_handle=recipe.receipt_handle,
            worker_recipe_sha256=recipe.complete_recipe_sha256,
            service_generation_id=recipe.profile_generation,
            generation_id=base_policy.generation_id,
            service_records=(_freeze_json(service_row),),
            process_profile_records=(_freeze_json(process_row),),
            native_worker_network_records=(_freeze_json(native_network),),
            active_network_generation_records=(_freeze_json(active_row),),
            native_worker_runtime_records=(_freeze_json(runtime_row),),
            source_member_receipt_handles=source_handles,
            root_journal_id=journal.root_id, root_journal_generation=journal.generation,
            output_sha256=_digest(body), issued_monotonic=issued, expires_monotonic=expiry,
            _issuer=self._issuer, _recipe=recipe, _selection=current_selection,
            _runtime_materialization=materialization,
        )
        self._issued[generation.receipt_handle] = generation
        if self.verify_current(generation) is not generation:
            self._issued.pop(generation.receipt_handle, None)
            raise NativeServiceGenerationUnavailable("selected native service generation failed currentness")
        return generation

    def _selected_service_and_process_rows(self, base_policy: Any,
                                           recipe: RootPreparedNativeWorkerRecipe,
                                           materialization: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        service_rows = [row for row in base_policy.records
                        if isinstance(row, Mapping)
                        and row.get("enrollment_id") == recipe.service_enrollment_id
                        and row.get("profile_id") == recipe.service_profile_id]
        if len(service_rows) != 1:
            raise NativeServiceGenerationUnavailable(
                "factory-expanded service policy lacks one exact selected worker row")
        service = dict(service_rows[0])
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        if type(self.binding) is not RootSelectedInstallationBinding:
            raise NativeServiceGenerationUnavailable("service generation lost its selected installation binding")
        profiles = base_policy.authority_base.get("process_profiles") if isinstance(
            base_policy.authority_base, Mapping) else None
        template = profiles.get(recipe.process_profile_id) if isinstance(profiles, Mapping) else None
        if not isinstance(template, Mapping):
            raise NativeServiceGenerationUnavailable(
                "factory-expanded root authority lacks the exact selected process profile template")
        service_fields = {
            "enrollment_id", "generation", "profile_id", "principal_id", "service_uid",
            "service_gid", "service_user", "device_enrollment_id", "expected_device_generation",
            "executable", "executable_sha256", "runtime_artifact_ids", "package_runtime_records",
            "roots", "authority_endpoint_id", "namespace_identity", "socket_policy_id",
            "target_route_ids", "operation_targets", "operation_recipes", "argv_recipe",
            "environment", "max_lifetime_seconds", "memory_max_bytes", "cpu_quota_percent", "io_weight",
        }
        process_fields = {
            "profile_id", "owner_uid", "owner_gid", "service_user", "executable",
            "artifact_sha256", "artifact_root", "data_root", "generation", "memory_max_bytes",
            "cpu_quota_percent", "io_weight", "max_lifetime_seconds", "child_artifact_refs", "argv_recipe",
        }
        process = dict(template)
        if set(service) != service_fields or set(process) != process_fields:
            raise NativeServiceGenerationUnavailable(
                "selected service or process template differs from the closed legacy row contract")
        recipe = self.recipe_registry.verify_current(recipe)
        identity = recipe._identity
        if (service["service_uid"] != identity.service_uid
                or service["service_gid"] != identity.service_gid
                or service["service_user"] != identity.service_user
                or service["executable_sha256"] != materialization.pm_executable_member_sha256
                or process["owner_uid"] != identity.service_uid
                or process["owner_gid"] != identity.service_gid
                or process["service_user"] != identity.service_user
                or process["executable"] != service["executable"]
                or process["artifact_sha256"] != service["executable_sha256"]
                or process["profile_id"] != recipe.process_profile_id
                or service["authority_endpoint_id"] != recipe._endpoint.endpoint_id
                or service["namespace_identity"] != self.binding.resolve_current_setup_identity().namespace.namespace_id
                or process["data_root"] != service["roots"].get("data")):
            raise NativeServiceGenerationUnavailable(
                "factory service/process rows do not match current identity, endpoint, PM executable or roots")
        start = recipe._start_recipe
        argv = [service["executable"], *start.argv_suffix]
        generation = recipe.profile_generation
        service["generation"] = generation
        service["argv_recipe"] = list(argv)
        process["generation"] = generation
        process["argv_recipe"] = list(argv)
        if (process["memory_max_bytes"] != service["memory_max_bytes"]
                or process["cpu_quota_percent"] != service["cpu_quota_percent"]
                or process["io_weight"] != service["io_weight"]
                or process["max_lifetime_seconds"] != service["max_lifetime_seconds"]):
            raise NativeServiceGenerationUnavailable(
                "selected service and process resource limits differ")
        return service, process

    def _source_definition_member_records(self, recipe: RootPreparedNativeWorkerRecipe
                                          ) -> list[dict[str, Any]]:
        from .bootstrap_runtime_factory import RootPreparedReleaseMemberReceipt
        session = self.binding._session
        start = recipe._start_recipe
        handles = set(start.installer_member_receipt_handles)
        handles.update(start.worker_member_receipt_handles)
        handles.add(recipe.definition_member_receipt_handle)
        receipts = (
            tuple(self.binding.resolve_prepared_native_worker_start_source_module_receipts())
            + tuple(self.binding.resolve_prepared_worker_role_module_receipts())
        )
        by_handle = {row.source_receipt_handle: row for row in receipts
                     if type(row) is RootPreparedReleaseMemberReceipt}
        if len(by_handle) != len(receipts) or set(by_handle) != handles:
            raise NativeServiceGenerationUnavailable(
                "exact source-definition receipts do not match the signed start-recipe member closure")
        release = session._factory._release
        actor = session._factory._actor
        actor.verify_current(release)
        release_rows = {row.artifact_id: row for row in release.files}
        projected = []
        for handle in sorted(handles):
            receipt = by_handle[handle]
            content = receipt.read_current()
            release_row = release_rows.get(receipt.artifact_id)
            if (release_row is None or release_row.relative_path != receipt.relative_path
                    or release_row.sha256 != receipt.sha256 or release_row.size_bytes != receipt.size_bytes):
                raise NativeServiceGenerationUnavailable(
                    "source-definition receipt is outside the current held release")
            fd = release.open_file(receipt.artifact_id)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                        or info.st_size != receipt.size_bytes
                        or stat.S_IMODE(info.st_mode) != release_row.mode
                        or hashlib.sha256(content).hexdigest() != receipt.sha256
                        or _hash_fd(fd) != receipt.sha256):
                    raise NativeServiceGenerationUnavailable(
                        "source-definition bytes or actual held file identity changed")
                projected.append({
                    "artifact_id": receipt.artifact_id,
                    "receipt_handle": receipt.source_receipt_handle,
                    "relative_path": receipt.relative_path,
                    "kind": "regular-file", "sha256": receipt.sha256,
                    "size_bytes": receipt.size_bytes, "mode": stat.S_IMODE(info.st_mode),
                    "owner_uid": info.st_uid, "owner_gid": info.st_gid,
                    "device": info.st_dev, "inode": info.st_ino,
                    "link_target": None, "output_role": None,
                })
            finally:
                os.close(fd)
        return projected

    def verify_current(self, generation: RootPreparedNativeServiceGeneration) -> RootPreparedNativeServiceGeneration:
        if (type(generation) is not RootPreparedNativeServiceGeneration
                or generation._issuer is not self._issuer
                or self._issued.get(generation.receipt_handle) is not generation
                or generation.expires_monotonic <= time.monotonic()):
            raise NativeServiceGenerationUnavailable("prepared native generation is foreign, stale, or expired")
        recipe = self.recipe_registry.verify_current(generation._recipe)
        materializer = self.binding._session.resolve_current_native_worker_runtime_materialization_registry()
        if materializer.verify_current(generation._runtime_materialization) is not generation._runtime_materialization:
            raise NativeServiceGenerationUnavailable("native runtime materialization changed")
        selection = self.binding.resolve_current_native_policy_selection(
            generation.source_choice_selection_handle)
        if (selection is not generation._selection
                or selection.selection_handle != generation.source_choice_selection_handle
                or getattr(selection, "selected_worker_recipe_handles", None)
                   != (recipe.receipt_handle,)
                or recipe.complete_recipe_sha256 != generation.worker_recipe_sha256):
            self._issued.pop(generation.receipt_handle, None)
            raise NativeServiceGenerationUnavailable("prepared generation source selection changed")
        body = {
            "service_generation_id": generation.service_generation_id,
            "generation_id": generation.generation_id,
            "service_records": _plain(generation.service_records),
            "process_profile_records": _plain(generation.process_profile_records),
            "native_worker_network_records": _plain(generation.native_worker_network_records),
            "active_network_generation_records": _plain(generation.active_network_generation_records),
            "native_worker_runtime_records": _plain(generation.native_worker_runtime_records),
            "source_choice_selection_handle": generation.source_choice_selection_handle,
            "source_choice_signed_record_sha256": generation.source_choice_signed_record_sha256,
            "worker_recipe_receipt_handle": generation.worker_recipe_receipt_handle,
            "worker_recipe_sha256": generation.worker_recipe_sha256,
            "source_member_receipt_handles": list(generation.source_member_receipt_handles),
        }
        if _digest(body) != generation.output_sha256:
            self._issued.pop(generation.receipt_handle, None)
            raise NativeServiceGenerationUnavailable("prepared generation projection digest changed")
        return generation

    def resolve_current_selected_generation(
            self, selection_handle: str) -> RootPreparedNativeServiceGeneration:
        """Return the one issuer-held DTO joined to the still-current choice."""
        if not isinstance(selection_handle, str) or not selection_handle:
            raise NativeServiceGenerationUnavailable("selected generation lookup requires a signed choice handle")
        selection = self.binding.resolve_current_native_policy_selection(selection_handle)
        matches = [row for row in self._issued.values()
                   if row.source_choice_selection_handle == selection_handle]
        if len(matches) != 1:
            raise NativeServiceGenerationUnavailable(
                "the current native choice does not have exactly one issued service-generation receipt")
        result = self.verify_current(matches[0])
        if result._selection is not selection:
            raise NativeServiceGenerationUnavailable("selected generation no longer joins its current choice")
        return result


__all__ = ["NativeServiceGenerationUnavailable", "RootPreparedNativeServiceGeneration",
           "RootPreparedNativeServiceGenerationProducer"]
