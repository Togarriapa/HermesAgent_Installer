"""Daemon-side producer for committed native Hermes health evidence.

This module never converts setup-local proof to daemon authority.  It resolves
the distinct daemon commit proof through its issuer, then joins the current
signed health definition to the exact protected native-worker generation and
the held installer release.  The run/input registries are intentionally
separate from setup's start-material and from user-facing RPC handlers.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .types import AuthorityDenied, canonical_bytes

_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FIXTURE_IDS = (
    "hermes-agent-health-fixture-v1",
    "hermes-agent-health-request-v1",
    "hermes-agent-health-seed-v1",
    "hermes-agent-health-expected-result-v1",
    "hermes-agent-health-overlay-read-result-v1",
)
_HEALTH_PROFILE = "hermes-agent-native-v1"
_HEALTH_OPERATION = "hermes-agent-health-v1"
_MAX_LEASE = 30.0


def _strict_json(data: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class RootDaemonNativeHealthSourceBinding:
    """Exact active source/generation projection retained by the daemon issuer."""

    worker_runtime_record_id: str
    recipe_sha256: str
    source_choice_selection_handle: str
    source_choice_signed_record_sha256: str
    health_definition_sha256: str
    native_package_id: str
    native_package_generation: str
    native_closure_sha256: str
    profile_id: str
    profile_generation: str
    service_enrollment_id: str
    source_member_receipt_handles: tuple[str, ...]
    source_definition_member_records: tuple[Mapping[str, Any], ...]
    _release: Any = field(repr=False, compare=False)
    _runtime_record: Mapping[str, Any] = field(repr=False, compare=False)
    _active_row: Mapping[str, Any] = field(repr=False, compare=False)
    _source_choice: Any = field(repr=False, compare=False)
    _health_definition: Mapping[str, Any] = field(repr=False, compare=False)
    _member_bytes: Mapping[str, bytes] = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootDaemonNativeHealthSourceBinding(<root-held>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootDaemonNativeHealthStartMaterial:
    """Finite daemon-side health source material for the v191 issuer."""

    schema: int
    committed_transaction_id: str
    bootstrap_transaction_handle: str
    generation_id: str
    service_generation_digest: str
    commit_proof: Any = field(repr=False, compare=False)
    publication_receipt_handle: str
    publication_sha256: str
    source_choice_selection_handle: str
    source_choice_signed_record_sha256: str
    health_definition_sha256: str
    health_provider_required: bool
    enrollment_id: str
    profile_id: str
    principal_id: str
    process_generation: str
    operation_id: str
    recipe_sha256: str
    parameter_schema_id: str
    parameter_schema_sha256: str
    process_recipe_sha256: str
    health_fixture_artifact_id: str
    health_fixture_sha256: str
    health_fixture_receipt_handle: str
    health_request_artifact_id: str
    health_request_sha256: str
    health_request_receipt_handle: str
    health_seed_artifact_id: str
    health_seed_sha256: str
    health_seed_receipt_handle: str
    health_expected_result_artifact_id: str
    health_expected_result_sha256: str
    health_expected_result_receipt_handle: str
    health_result_schema_id: str
    health_result_schema_sha256: str
    health_result_schema_receipt_handle: str
    native_package_id: str
    native_package_generation: str
    native_closure_sha256: str
    controller_binding_handle: str
    namespace_identity: str
    issued_monotonic: float
    expires_monotonic: float
    _issuer_seal: object = field(repr=False, compare=False)
    _registry: Any = field(repr=False, compare=False)
    _commit_proof: Any = field(repr=False, compare=False)
    _source_projection: Any = field(repr=False, compare=False)
    _health_definition: Mapping[str, Any] = field(repr=False, compare=False)
    _source_binding: RootDaemonNativeHealthSourceBinding = field(repr=False, compare=False)
    _service_profile: Any = field(repr=False, compare=False)
    _process_operation: Any = field(repr=False, compare=False)
    _controller_lease: Any = field(repr=False, compare=False)
    _fixture_bytes: bytes = field(repr=False, compare=False)
    _request_bytes: bytes = field(repr=False, compare=False)
    _seed_bytes: bytes = field(repr=False, compare=False)
    _expected_result_bytes: bytes = field(repr=False, compare=False)
    _result_schema_bytes: bytes = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootDaemonNativeHealthStartMaterial(<root-private>)"

    def public_projection(self) -> Mapping[str, Any]:
        return MappingProxyType({
            name: getattr(self, name) for name in (
                "schema", "committed_transaction_id", "bootstrap_transaction_handle",
                "generation_id", "service_generation_digest", "commit_proof",
                "publication_receipt_handle",
                "publication_sha256", "source_choice_selection_handle",
                "source_choice_signed_record_sha256", "health_definition_sha256",
                "health_provider_required", "enrollment_id", "profile_id", "principal_id",
                "process_generation", "operation_id", "recipe_sha256", "parameter_schema_id",
                "parameter_schema_sha256", "process_recipe_sha256",
                "health_fixture_artifact_id", "health_fixture_sha256", "health_fixture_receipt_handle",
                "health_request_artifact_id", "health_request_sha256", "health_request_receipt_handle",
                "health_seed_artifact_id", "health_seed_sha256", "health_seed_receipt_handle",
                "health_expected_result_artifact_id", "health_expected_result_sha256",
                "health_expected_result_receipt_handle", "health_result_schema_id",
                "health_result_schema_sha256", "health_result_schema_receipt_handle",
                "native_package_id", "native_package_generation", "native_closure_sha256",
                "controller_binding_handle", "namespace_identity", "issued_monotonic",
                "expires_monotonic",
            )
        })


class RootDaemonNativeHealthMaterialRegistry:
    """Reopen daemon commit/source state and issue finite health material."""

    def __init__(self, runtime: Any, commit_registry: Any):
        from .runtime_composition import RootAuthorityRuntime
        if type(runtime) is not RootAuthorityRuntime:
            raise AuthorityDenied("native.health.daemon_runtime", "exact root daemon runtime is required")
        self.runtime = runtime
        self.commit_registry = commit_registry
        self._issuer = object()
        self._materials: dict[str, RootDaemonNativeHealthStartMaterial] = {}
        self._lock = threading.RLock()

    @classmethod
    def from_root_runtime(cls, runtime: Any, commit_registry: Any
                          ) -> "RootDaemonNativeHealthMaterialRegistry":
        return cls(runtime, commit_registry)

    def resolve_current_health_material(self, commit_proof: Any
                                        ) -> RootDaemonNativeHealthStartMaterial:
        proof_type, projection_type = self._commit_types()
        if (type(commit_proof) is not proof_type
                or getattr(commit_proof, "_registry", None) is not self.commit_registry
                or not self.commit_registry.is_current_commit(commit_proof)):
            raise AuthorityDenied("native.health.daemon_commit", "current daemon-issued health commit proof is required")
        try:
            projection = self.commit_registry.resolve_health_source_projection(commit_proof)
            if type(projection) is not projection_type:
                raise ValueError
            material = self._build(commit_proof, projection)
        except Exception:
            raise AuthorityDenied("native.health.daemon_sources", "current committed source material is unavailable") from None
        with self._lock:
            prior = self._materials.get(material._commit_proof.proof_handle)
            if prior is not None and prior._commit_proof is commit_proof:
                # A current proof has one live issuer object; do not mint a
                # second independently consumable representation.
                return self.verify_current(prior)
            self._materials[commit_proof.proof_handle] = material
        return material

    def _commit_types(self) -> tuple[type, type]:
        from .native_health_observer import RootDaemonCommittedHealthProof, _RootDaemonCommittedHealthProjection
        return RootDaemonCommittedHealthProof, _RootDaemonCommittedHealthProjection

    def _build(self, proof: Any, projection: Any) -> RootDaemonNativeHealthStartMaterial:
        now = self.runtime.service.monotonic()
        release = self.runtime.controller_release_receipt
        from .installer_release import VerifiedInstallerReleaseReceipt
        if type(release) is not VerifiedInstallerReleaseReceipt:
            raise ValueError("current installed release receipt is unavailable")
        release.verify_current()
        source_choice = projection.source_choice
        runtime_row = projection.worker_runtime_record
        active_row = projection.active_worker_row
        catalog = self.runtime.bindings.enrollment_catalog
        if (getattr(catalog, "digest", None) != proof.service_generation_digest
                or projection.current_generation_id != proof.generation_id
                or projection.current_generation_digest != proof.service_generation_digest
                or projection.transaction_id != proof.committed_transaction_id
                or source_choice.selection_handle != proof.source_choice_selection_handle
                or source_choice.signed_record_sha256 != proof.source_choice_signed_record_sha256
                or source_choice.service_generation_digest != proof.service_generation_digest
                or source_choice.active_publication_receipt_handle != proof.publication_receipt_handle
                or projection.publication_receipt.receipt_handle != proof.publication_receipt_handle
                or projection.publication_receipt.publication_sha256 != proof.publication_sha256
                or not isinstance(runtime_row, Mapping) or not isinstance(active_row, Mapping)):
            raise ValueError("daemon commit, active publication, and worker rows differ")
        payload = source_choice.choice_payload
        recipe_rows = payload.get("selected_worker_recipe_records")
        recipe_digests = payload.get("selected_worker_recipe_digests")
        if (not isinstance(recipe_rows, (tuple, list)) or len(recipe_rows) != 1
                or not isinstance(recipe_digests, (tuple, list)) or len(recipe_digests) != 1
                or type(recipe_rows[0]) is not dict):
            raise ValueError("active signed source choice has no unique worker recipe")
        recipe = recipe_rows[0]
        definition = recipe.get("health_definition")
        definition_sha = recipe.get("health_definition_sha256")
        if (type(definition) is not dict or _digest(definition) != definition_sha
                or definition_sha != proof.health_definition_sha256
                or _digest(definition) != proof.health_definition_sha256
                or recipe.get("complete_recipe_sha256") != recipe_digests[0]
                or runtime_row.get("recipe_sha256") != recipe_digests[0]
                or runtime_row.get("source_choice_selection_handle") != source_choice.selection_handle
                or runtime_row.get("source_choice_signed_record_sha256") not in (None, source_choice.signed_record_sha256)
                or runtime_row.get("profile_id") != recipe.get("service_profile_id")
                or runtime_row.get("profile_generation") != recipe.get("profile_generation")
                or runtime_row.get("generation_id") != proof.generation_id
                or runtime_row.get("id") != active_row.get("worker_runtime_record_id")):
            raise ValueError("signed source recipe differs from current protected runtime row")
        member_bytes = self._read_health_members(release, definition)
        self._validate_health_definition(definition, member_bytes)
        profile_id = runtime_row["profile_id"]
        profile_generation = runtime_row["profile_generation"]
        profile = catalog.resolve_profile_generation(profile_id, profile_generation)
        process_operation = self.runtime.bindings.resolve_selected_operation(
            profile.enrollment_id, profile.generation, "process.start", _HEALTH_OPERATION,
        )
        if (profile.profile_id != _HEALTH_PROFILE
                or process_operation.profile_id != profile.profile_id
                or process_operation.generation != profile.generation
                or process_operation.enrollment_id != profile.enrollment_id
                or process_operation.operation_id != _HEALTH_OPERATION
                or profile.package_runtime_records
                or self._service_requires_package_runtime(profile.operation_targets)):
            raise ValueError("selected health process profile or package-set closure is not the reviewed fixed row")
        operation_recipe = profile.operation_recipes.get(_HEALTH_OPERATION)
        parameter_schema = profile.parameter_schemas.get("no-caller-parameters-v1")
        from .protected_enrollment import OperationLaunchRecipe, OperationParameterSchema
        if (type(operation_recipe) is not OperationLaunchRecipe
                or type(parameter_schema) is not OperationParameterSchema
                or parameter_schema.schema_id != "no-caller-parameters-v1"
                or parameter_schema.fields):
            raise ValueError("signed health operation recipe digest is unavailable")
        operation_recipe_body = {
            "operation_id": operation_recipe.operation_id,
            "executable_artifact_id": operation_recipe.executable_artifact_id,
            "executable_sha256": operation_recipe.executable_sha256,
            "argv_recipe": [dict(row) for row in operation_recipe.argv_recipe],
            "cwd_root_id": operation_recipe.cwd_root_id,
            "cwd_subpath": operation_recipe.cwd_subpath,
            "environment": dict(operation_recipe.environment),
            "child_artifact_refs": dict(operation_recipe.child_artifact_refs),
            "max_lifetime_seconds": operation_recipe.max_lifetime_seconds,
            "max_output_bytes": operation_recipe.max_output_bytes,
            "stdin_mode": operation_recipe.stdin_mode,
            "parameter_schema_id": operation_recipe.parameter_schema_id,
        }
        parameter_schema_body = {"id": parameter_schema.schema_id, "fields": []}
        process_recipe_sha256 = hashlib.sha256(canonical_bytes(operation_recipe_body)).hexdigest()
        parameter_schema_sha256 = hashlib.sha256(canonical_bytes(parameter_schema_body)).hexdigest()
        from .bootstrap_runtime_factory import _service_requires_package_runtime
        if _service_requires_package_runtime(profile.operation_targets):
            raise ValueError("selected health worker has a package-set install requirement without attestation")
        if (definition.get("parameter_schema_id") != "no-caller-parameters-v1"
                or definition.get("parameter_schema_sha256") != parameter_schema_sha256):
            raise ValueError("signed health parameter schema differs from the active process profile")
        package_id = runtime_row["native_package_id"]
        package_generation = runtime_row["native_package_generation"]
        package = self.runtime.bindings.resolve_native_package(package_id, package_generation)
        if (package.profile_id != profile.profile_id
                or package.generation != profile.generation
                or package.compiled_closure_sha256 != active_row.get("compiled_closure_sha256")
                or package.package_id != active_row.get("package_id")):
            raise ValueError("active native package does not match the selected health profile")
        member_rows = tuple(self._health_release_rows(release, definition))
        handles = tuple(sorted(str(row["receipt_handle"]) for row in member_rows))
        definition_handles = tuple(sorted(str(definition[name]) for name in (
            "health_recipe_receipt_handle", "health_request_receipt_handle",
            "health_seed_receipt_handle", "health_expected_result_receipt_handle",
            "health_result_schema_receipt_handle",
        )))
        if handles != definition_handles:
            raise ValueError("health definition member handles differ from protected runtime source rows")
        committed_members = runtime_row.get("source_definition_member_records")
        if not isinstance(committed_members, (tuple, list)):
            raise ValueError("committed runtime row has no finite source-definition member catalog")
        committed_health_members = tuple(
            row for row in committed_members
            if isinstance(row, Mapping) and row.get("artifact_id") in _FIXTURE_IDS
        )
        # The active row carries setup's source lineage.  The daemon does not
        # trust its receipt handles as authority: it independently opens the
        # reviewed release member above, then requires every actual stat/hash
        # fact to equal the committed row for precisely the five fixed files.
        if (len(committed_health_members) != len(_FIXTURE_IDS)
                or {row.get("artifact_id") for row in committed_health_members} != set(_FIXTURE_IDS)
                or {row.get("receipt_handle") for row in committed_health_members} != set(handles)
                or {row.get("artifact_id"): dict(row) for row in committed_health_members}
                   != {row["artifact_id"]: row for row in member_rows}):
            raise ValueError("committed source-definition rows do not join all five held health files")
        source_binding = RootDaemonNativeHealthSourceBinding(
            worker_runtime_record_id=runtime_row["id"],
            recipe_sha256=runtime_row["recipe_sha256"],
            source_choice_selection_handle=source_choice.selection_handle,
            source_choice_signed_record_sha256=source_choice.signed_record_sha256,
            health_definition_sha256=definition_sha,
            native_package_id=package_id,
            native_package_generation=package_generation,
            native_closure_sha256=package.compiled_closure_sha256,
            profile_id=profile.profile_id,
            profile_generation=profile.generation,
            service_enrollment_id=profile.enrollment_id,
            source_member_receipt_handles=handles,
            source_definition_member_records=tuple(MappingProxyType(dict(row)) for row in member_rows),
            _release=release, _runtime_record=MappingProxyType(dict(runtime_row)),
            _active_row=MappingProxyType(dict(active_row)), _source_choice=source_choice,
            _health_definition=MappingProxyType(dict(definition)),
            _member_bytes=MappingProxyType(dict(member_bytes)), _issuer=self._issuer,
        )
        from .native_health_observer import RootDaemonHealthControllerLease
        controller = getattr(projection, "controller_lease", None)
        if (type(controller) is not RootDaemonHealthControllerLease
                or controller is not getattr(proof, "_commit_projection", None).controller_lease
                or not controller.is_current()):
            raise ValueError("daemon fixed-unit controller lease is unavailable")
        expiry = min(now + _MAX_LEASE, proof.expires_monotonic, controller.expires_monotonic)
        if not now < expiry:
            raise ValueError("daemon health source lease is expired")
        handles_by_id = {row["artifact_id"]: row["receipt_handle"] for row in member_rows}
        material = RootDaemonNativeHealthStartMaterial(
            schema=1,
            committed_transaction_id=proof.committed_transaction_id,
            bootstrap_transaction_handle=proof.bootstrap_transaction_handle,
            generation_id=proof.generation_id,
            service_generation_digest=proof.service_generation_digest,
            commit_proof=proof,
            publication_receipt_handle=proof.publication_receipt_handle,
            publication_sha256=proof.publication_sha256,
            source_choice_selection_handle=proof.source_choice_selection_handle,
            source_choice_signed_record_sha256=proof.source_choice_signed_record_sha256,
            health_definition_sha256=definition_sha,
            health_provider_required=definition["provider_required"],
            enrollment_id=profile.enrollment_id, profile_id=profile.profile_id,
            principal_id=profile.principal_id, process_generation=profile.generation,
            operation_id=definition["operation_id"], recipe_sha256=runtime_row["recipe_sha256"],
            parameter_schema_id=definition["parameter_schema_id"],
            parameter_schema_sha256=parameter_schema_sha256,
            process_recipe_sha256=process_recipe_sha256,
            health_fixture_artifact_id=definition["health_recipe_artifact_id"],
            health_fixture_sha256=definition["health_recipe_sha256"],
            health_fixture_receipt_handle=handles_by_id[definition["health_recipe_artifact_id"]],
            health_request_artifact_id=definition["health_request_artifact_id"],
            health_request_sha256=definition["health_request_sha256"],
            health_request_receipt_handle=handles_by_id[definition["health_request_artifact_id"]],
            health_seed_artifact_id=definition["health_seed_artifact_id"],
            health_seed_sha256=definition["health_seed_sha256"],
            health_seed_receipt_handle=handles_by_id[definition["health_seed_artifact_id"]],
            health_expected_result_artifact_id=definition["health_expected_result_artifact_id"],
            health_expected_result_sha256=definition["health_expected_result_sha256"],
            health_expected_result_receipt_handle=handles_by_id[definition["health_expected_result_artifact_id"]],
            health_result_schema_id=definition["health_result_schema_id"],
            health_result_schema_sha256=definition["health_result_schema_sha256"],
            health_result_schema_receipt_handle=handles_by_id["hermes-agent-health-overlay-read-result-v1"],
            native_package_id=package.package_id,
            native_package_generation=package.generation,
            native_closure_sha256=package.compiled_closure_sha256,
            controller_binding_handle=controller.proof_handle,
            namespace_identity=profile.namespace_identity,
            issued_monotonic=now, expires_monotonic=expiry,
            _issuer_seal=self._issuer, _registry=self, _commit_proof=proof,
            _source_projection=projection, _health_definition=MappingProxyType(dict(definition)),
            _source_binding=source_binding, _service_profile=profile,
            _process_operation=process_operation, _controller_lease=controller,
            _fixture_bytes=member_bytes[definition["health_recipe_artifact_id"]],
            _request_bytes=member_bytes[definition["health_request_artifact_id"]],
            _seed_bytes=member_bytes[definition["health_seed_artifact_id"]],
            _expected_result_bytes=member_bytes[definition["health_expected_result_artifact_id"]],
            _result_schema_bytes=member_bytes["hermes-agent-health-overlay-read-result-v1"],
        )
        return material

    @staticmethod
    def _health_release_rows(release: Any, definition: Mapping[str, Any]) -> list[dict[str, Any]]:
        from .installer_release import VerifiedReleaseFile
        fields = {
            "hermes-agent-health-fixture-v1": ("health_recipe_artifact_id", "health_recipe_sha256", "health_recipe_receipt_handle"),
            "hermes-agent-health-request-v1": ("health_request_artifact_id", "health_request_sha256", "health_request_receipt_handle"),
            "hermes-agent-health-seed-v1": ("health_seed_artifact_id", "health_seed_sha256", "health_seed_receipt_handle"),
            "hermes-agent-health-expected-result-v1": ("health_expected_result_artifact_id", "health_expected_result_sha256", "health_expected_result_receipt_handle"),
            "hermes-agent-health-overlay-read-result-v1": (None, "health_result_schema_sha256", "health_result_schema_receipt_handle"),
        }
        rows: list[dict[str, Any]] = []
        for artifact_id in _FIXTURE_IDS:
            id_field, sha_field, handle_field = fields[artifact_id]
            if id_field is not None and definition.get(id_field) != artifact_id:
                raise ValueError("signed health definition changed a fixed source artifact")
            member = release.resolve_reviewed_source_artifact(artifact_id)
            if (type(member) is not VerifiedReleaseFile or member.roles != ("native-health-fixture",)
                    or definition.get(sha_field) != member.sha256
                    or not isinstance(definition.get(handle_field), str)
                    or not _OPAQUE.fullmatch(definition[handle_field])):
                raise ValueError("health source member differs from the held release")
            rows.append({
                "artifact_id": artifact_id, "receipt_handle": definition[handle_field],
                "relative_path": member.relative_path, "kind": "regular-file",
                "sha256": member.sha256, "size_bytes": member.size_bytes,
                "mode": member.mode, "owner_uid": 0, "owner_gid": 0,
                "device": member.device, "inode": member.inode,
                "link_target": None, "output_role": None,
            })
        return rows

    @classmethod
    def _read_health_members(cls, release: Any, definition: Mapping[str, Any]) -> dict[str, bytes]:
        rows = cls._health_release_rows(release, definition)
        output: dict[str, bytes] = {}
        release.verify_current()
        for row in rows:
            if type(row) is not dict or row.get("kind") != "regular-file":
                raise ValueError("health source row is not an exact regular release file")
            artifact_id = row["artifact_id"]
            release_member = release.resolve_reviewed_source_artifact(artifact_id)
            if (type(release_member) is not VerifiedReleaseFile
                    or row["relative_path"] != release_member.relative_path
                    or row["sha256"] != release_member.sha256
                    or row["size_bytes"] != release_member.size_bytes
                    or row["mode"] != release_member.mode
                    or row["owner_uid"] != 0 or row["owner_gid"] != 0
                    or row["device"] != release_member.device or row["inode"] != release_member.inode
                    or row["link_target"] is not None or row["output_role"] is not None
                    or not _OPAQUE.fullmatch(row["receipt_handle"])):
                raise ValueError("health source member differs from the current protected generation")
            fd = release.open_reviewed_source_artifact(artifact_id)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                        or stat.S_IMODE(info.st_mode) != row["mode"]
                        or (info.st_dev, info.st_ino) != (row["device"], row["inode"])
                        or info.st_size != row["size_bytes"]):
                    raise ValueError("held health release descriptor identity changed")
                data = bytearray()
                while True:
                    block = os.read(fd, 65536)
                    if not block:
                        break
                    data.extend(block)
                body = bytes(data)
                if hashlib.sha256(body).hexdigest() != row["sha256"]:
                    raise ValueError("held health source bytes changed")
                output[artifact_id] = body
            finally:
                os.close(fd)
        return output

    @staticmethod
    def _validate_health_definition(definition: Mapping[str, Any], bodies: Mapping[str, bytes]) -> None:
        recipe = _strict_json(bodies["hermes-agent-health-fixture-v1"])
        if (type(recipe) is not dict or recipe.get("artifact_id") != "hermes-agent-health-fixture-v1"
                or recipe.get("fixture_id") != _HEALTH_OPERATION
                or recipe.get("provider") != {"additional_budget": 0, "required": True,
                                              "route_class": "private-zero-additional-budget"}
                or recipe.get("action_id") != definition.get("health_action_id")
                or recipe.get("result_schema_id") != definition.get("health_result_schema_id")
                or recipe.get("request_asset") != "request.txt"
                or recipe.get("result_source_asset") != "expected-tool-result.json"
                or recipe.get("result_schema_asset") != "tool-result.schema.json"
                or recipe.get("tool_name") != "resource_overlay_read"
                or definition.get("operation_id") != _HEALTH_OPERATION
                or definition.get("provider_required") is not True
                or definition.get("health_request_sha256") != hashlib.sha256(
                    bodies["hermes-agent-health-request-v1"]).hexdigest()
                or definition.get("health_seed_sha256") != hashlib.sha256(
                    bodies["hermes-agent-health-seed-v1"]).hexdigest()
                or definition.get("health_expected_result_sha256") != hashlib.sha256(
                    bodies["hermes-agent-health-expected-result-v1"]).hexdigest()
                or definition.get("health_result_schema_sha256") != hashlib.sha256(
                    bodies["hermes-agent-health-overlay-read-result-v1"]).hexdigest()):
            raise ValueError("held health source definition differs from the fixed source contract")
        result = _strict_json(bodies["hermes-agent-health-expected-result-v1"])
        schema = _strict_json(bodies["hermes-agent-health-overlay-read-result-v1"])
        seed = bodies["hermes-agent-health-seed-v1"]
        seed_spec = recipe.get("seed")
        if (type(seed_spec) is not dict
                or seed_spec.get("source_asset") != "seed-value.txt"
                or seed_spec.get("size_bytes") != len(seed)
                or seed_spec.get("sha256") != hashlib.sha256(seed).hexdigest()
                or type(result) is not dict or type(schema) is not dict
                or result.get("record_id") != "hermes-health-probe-v1"
                or result.get("found") is not True
                or result.get("revision") != seed_spec.get("revision")
                or schema.get("properties", {}).get("revision", {}).get("const") != seed_spec.get("revision")
                or result.get("value_base64") != schema.get("properties", {}).get("value_base64", {}).get("const")
                or result != {
                    "found": True, "record_id": "hermes-health-probe-v1",
                    "revision": seed_spec["revision"],
                    "value_base64": schema["properties"]["value_base64"]["const"],
                }):
            raise ValueError("held expected result/schema/seed semantic contract differs")

    def verify_current(self, material: RootDaemonNativeHealthStartMaterial
                       ) -> RootDaemonNativeHealthStartMaterial:
        if (type(material) is not RootDaemonNativeHealthStartMaterial
                or material._registry is not self or material._issuer_seal is not self._issuer
                or material._source_binding._issuer is not self._issuer
                or self._materials.get(material._commit_proof.proof_handle) is not material
                or self.runtime.service.monotonic() >= material.expires_monotonic
                or not material._controller_lease.is_current()):
            raise AuthorityDenied("native.health.daemon_material", "daemon health material is stale")
        proof_type, projection_type = self._commit_types()
        if (type(material._commit_proof) is not proof_type
                or not self.commit_registry.is_current_commit(material._commit_proof)):
            raise AuthorityDenied("native.health.daemon_material", "daemon health commit is no longer current")
        try:
            projection = self.commit_registry.resolve_health_source_projection(material._commit_proof)
            if (type(projection) is not projection_type or projection is not material._source_projection
                    or material._source_binding._source_choice is not projection.source_choice
                    or material._source_binding._release is not self.runtime.controller_release_receipt):
                raise ValueError
            projection._source_choice  # assert the retained private join remains reachable
            self.runtime.controller_release_receipt.verify_current()
            current_bytes = self._read_health_members(
                self.runtime.controller_release_receipt, material._health_definition,
            )
            self._validate_health_definition(material._health_definition, current_bytes)
        except Exception:
            raise AuthorityDenied("native.health.daemon_material", "current source members or committed projection changed") from None
        return material


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedHealthInputDelivery:
    """One-use, source-backed input event prepared for the manager's stdin."""

    delivery_handle: str
    control_handle: str
    observation_handle: str
    input_event: Any = field(repr=False, compare=False)
    loader_ready_event_id: str
    payload_sha256: str
    payload_size_bytes: int
    _payload: bytes = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)
    _registry: Any = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootSelectedHealthInputDelivery(<root-private>)"


class RootHealthInputDeliveryRegistry:
    """Seal the exact captured health input event and its selected bytes."""

    def __init__(self, runtime: Any, material_registry: RootDaemonNativeHealthMaterialRegistry,
                 native_input_observer: Any, manager: Any):
        from .native_input_observer import RootNativeInputObserver
        if (type(material_registry) is not RootDaemonNativeHealthMaterialRegistry
                or type(native_input_observer) is not RootNativeInputObserver
                or manager is not runtime.process_manager):
            raise AuthorityDenied("native.health.input", "root runtime input observers are unavailable")
        self.runtime, self.material_registry = runtime, material_registry
        self.native_input_observer, self.manager = native_input_observer, manager
        self._issuer = object()
        self._deliveries: dict[str, RootSelectedHealthInputDelivery] = {}
        # Membership is retained by this issuer at the point where the exact
        # input observer returns the event.  Manager consumers never inspect
        # the observer's private event dictionary.
        self._input_events: dict[str, Any] = {}
        self._consumed: set[str] = set()
        self._lock = threading.RLock()

    @classmethod
    def from_root_runtime(cls, runtime: Any,
                          material_registry: RootDaemonNativeHealthMaterialRegistry
                          ) -> "RootHealthInputDeliveryRegistry":
        service = runtime.service
        observer = getattr(service, "native_input_observer", None)
        if observer is None:
            observer = getattr(getattr(service, "native_input_delivery_registry", None), "input_observer", None)
        if observer is None:
            raise AuthorityDenied("native.health.input", "daemon has no attached root native input observer")
        return cls(runtime, material_registry, observer, runtime.process_manager)

    def prepare_selected_health_input(self, control_handle: str) -> RootSelectedHealthInputDelivery:
        if not _OPAQUE.fullmatch(control_handle):
            raise AuthorityDenied("native.health.input", "selected health control handle is malformed")
        try:
            control = self.manager.resolve_selected_health_control(control_handle)
            if type(control) is not RootSelectedHealthControl:
                raise ValueError
            observation_handle = self.manager.resolve_selected_health_observation_handle(control_handle)
            ready_event_id = self.manager.resolve_selected_health_loader_ready_event(control_handle)
            process = self.manager.resolve_selected_health_process(control_handle)
            admission = self.manager.resolve_selected_health_admission(control_handle)
            if not self.manager.native_health_start_authority.is_current(admission):
                raise ValueError
            artifact_id = admission.health_fixture_artifact_id
            event = self.native_input_observer.record_selected_health_input(
                observation_handle, process, artifact_id,
            )
            self._verify_input_event_current(control_handle, observation_handle, event)
            material = admission._source_material
            payload = material._request_bytes
            if (type(event) is not RootNativeInputEvent
                    or event.payload_sha256 != hashlib.sha256(payload).hexdigest()
                    or event.payload_size_bytes != len(payload)
                    or event.producer_profile_id != control.profile_id
                    or event.producer_generation != control.process_generation
                    or event.native_loader_ready_event_id != ready_event_id):
                raise ValueError
            delivery = RootSelectedHealthInputDelivery(
                delivery_handle=secrets.token_urlsafe(32),
                control_handle=control_handle,
                observation_handle=observation_handle,
                input_event=event,
                loader_ready_event_id=ready_event_id,
                payload_sha256=event.payload_sha256,
                payload_size_bytes=event.payload_size_bytes,
                _payload=payload,
                _issuer=self._issuer,
                _registry=self,
            )
        except Exception:
            raise AuthorityDenied("native.health.input", "source-backed selected health input is unavailable") from None
        with self._lock:
            self._deliveries[delivery.delivery_handle] = delivery
            self._input_events[delivery.input_event.input_event_id] = delivery.input_event
        return delivery

    def consume_for_manager(self, control_handle: str,
                            delivery: RootSelectedHealthInputDelivery) -> bytes:
        from .managed_process_custodian import RootSelectedHealthControl
        from .native_input_observer import RootNativeInputEvent
        if type(delivery) is not RootSelectedHealthInputDelivery:
            raise AuthorityDenied("native.health.input", "sealed health input delivery is required")
        with self._lock:
            if (delivery._registry is not self or delivery._issuer is not self._issuer
                    or self._deliveries.get(delivery.delivery_handle) is not delivery
                    or delivery.delivery_handle in self._consumed
                    or delivery.control_handle != control_handle):
                raise AuthorityDenied("native.health.input", "health input delivery is stale or replayed")
        try:
            control = self.manager.resolve_selected_health_control(control_handle)
            ready = self.manager.resolve_selected_health_loader_ready_event(control_handle)
            observation = self.manager.resolve_selected_health_observation_handle(control_handle)
            if (type(control) is not RootSelectedHealthControl
                    or delivery.loader_ready_event_id != ready
                    or delivery.observation_handle != observation
                    or type(delivery.input_event) is not RootNativeInputEvent
                    or self._input_events.get(delivery.input_event.input_event_id) is not delivery.input_event
                    or delivery.payload_sha256 != hashlib.sha256(delivery._payload).hexdigest()
                    or delivery.payload_size_bytes != len(delivery._payload)
                    or self.runtime.service.monotonic() >= control.expires_monotonic):
                raise ValueError
            self._verify_input_event_current(
                control_handle, observation, delivery.input_event,
            )
            authority = self.manager.native_health_start_authority
            admission = self.manager.resolve_selected_health_admission(control_handle)
            if not authority.is_current(admission):
                raise ValueError
            current_payload = admission._source_material._request_bytes
            if current_payload != delivery._payload:
                raise ValueError
        except Exception:
            raise AuthorityDenied("native.health.input", "health input source, READY, or process changed") from None
        with self._lock:
            if delivery.delivery_handle in self._consumed:
                raise AuthorityDenied("native.health.input", "health input delivery was already consumed")
            self._consumed.add(delivery.delivery_handle)
        return bytes(delivery._payload)

    def _verify_input_event_current(self, control_handle: str, observation_handle: str,
                                    event: Any) -> Any:
        from .native_input_observer import RootNativeInputEvent
        if type(event) is not RootNativeInputEvent:
            raise AuthorityDenied("native.health.input", "root input observer returned an untyped event")
        run = self.manager.resolve_selected_health_run(control_handle)
        try:
            if (event.producer_profile_id != run.profile_id
                    or event.producer_generation != run.process_generation
                    or event.native_loader_ready_event_id
                       != self.manager.resolve_selected_health_loader_ready_event(control_handle)):
                raise AuthorityDenied("native.health.input", "input event does not join the selected process and READY")
            resolver = getattr(self.native_input_observer, "resolve_current_health_event", None)
            if not callable(resolver):
                raise AuthorityDenied("native.health.input", "current health input event resolver is unavailable")
            current = resolver(event.input_event_id, observation_handle, run.process_identity)
            if current is not event:
                raise AuthorityDenied("native.health.input", "health input event issuer identity changed")
            return current
        finally:
            try:
                os.close(run.process_pidfd)
            except OSError:
                pass

    def verify_current(self, delivery: RootSelectedHealthInputDelivery,
                       control_handle: str) -> RootSelectedHealthInputDelivery:
        """Revalidate the exact issued delivery without consuming its bytes."""
        if type(delivery) is not RootSelectedHealthInputDelivery:
            raise AuthorityDenied("native.health.input", "sealed health input delivery is required")
        with self._lock:
            if (delivery._registry is not self or delivery._issuer is not self._issuer
                    or self._deliveries.get(delivery.delivery_handle) is not delivery
                    or delivery.delivery_handle in self._consumed
                    or delivery.control_handle != control_handle):
                raise AuthorityDenied("native.health.input", "health input delivery is stale or replayed")
        # The manager-facing consumption path performs the complete current
        # control, READY, observer-event, source material, and byte rejoin.
        control = self.manager.resolve_selected_health_control(control_handle)
        ready = self.manager.resolve_selected_health_loader_ready_event(control_handle)
        observation = self.manager.resolve_selected_health_observation_handle(control_handle)
        with self._lock:
            event_is_current = (
                self._input_events.get(delivery.input_event.input_event_id) is delivery.input_event)
        if (not control.is_current() or ready != delivery.loader_ready_event_id
                or observation != delivery.observation_handle or not event_is_current
                or delivery.payload_size_bytes != len(delivery._payload)
                or delivery.payload_sha256 != hashlib.sha256(delivery._payload).hexdigest()):
            raise AuthorityDenied("native.health.input", "selected health input delivery is no longer current")
        self._verify_input_event_current(control_handle, observation, delivery.input_event)
        return delivery


class RootDaemonNativeHealthRunRegistry:
    """Concrete selected control/event producer for RootNativeHealthObserver."""

    def __init__(self, runtime: Any,
                 material_registry: RootDaemonNativeHealthMaterialRegistry):
        from .runtime_composition import RootAuthorityRuntime
        from .native_health_observer import RootNativeHealthObserver
        if (type(runtime) is not RootAuthorityRuntime
                or type(material_registry) is not RootDaemonNativeHealthMaterialRegistry
                or material_registry.runtime is not runtime
                or not callable(getattr(runtime.process_manager, "resolve_live_peer", None))):
            raise AuthorityDenied("native.health.run", "current root health manager/issuer is unavailable")
        self.runtime, self.material_registry = runtime, material_registry
        self.manager = runtime.process_manager
        # The observer is created before the start authority to avoid a
        # construction cycle.  Every adapter is a bound method on this exact
        # issuer; no caller-provided event/source callback is accepted.
        self.observer = RootNativeHealthObserver(
            selected_health_resolver=self._resolve_selected_run,
            event_resolver=self._resolve_event,
            process_resolver=self._resolve_process,
            loaded_package_proof_resolver=self._resolve_loaded_package,
            result_validator=self._validate_result,
            selected_run_canceller=self._cancel_selected_run,
            monotonic=runtime.service.monotonic,
        )
        self.start_authority: Any | None = None
        self.input_delivery = RootHealthInputDeliveryRegistry.from_root_runtime(runtime, material_registry)
        self._events: dict[tuple[str, str], Any] = {}
        self._controls: dict[str, str] = {}
        self._expected_results: dict[tuple[str, str], bytes] = {}
        self._pending_run_pidfds: set[int] = set()
        self._lock = threading.RLock()

    @classmethod
    def from_root_runtime(cls, runtime: Any,
                          material_registry: RootDaemonNativeHealthMaterialRegistry
                          ) -> "RootDaemonNativeHealthRunRegistry":
        return cls(runtime, material_registry)

    def bind_start_authority(self, start_authority: Any) -> None:
        """Bind the exact authority after it has been built with our observer."""
        from .native_health_observer import RootNativeHealthStartAuthority
        if (type(start_authority) is not RootNativeHealthStartAuthority
                or start_authority.managed_process_custody is not self.manager
                or start_authority.health_observer is not self.observer):
            raise AuthorityDenied("native.health.run", "health start authority has a different observer or manager")
        with self._lock:
            if self.start_authority is not None and self.start_authority is not start_authority:
                raise AuthorityDenied("native.health.run", "health start authority was already bound")
            self.start_authority = start_authority

    def _resolve_selected_run(self, control_handle: str) -> Any:
        from .native_health_observer import RootSelectedNativeHealthRun
        if self.start_authority is None:
            raise AuthorityDenied("native.health.run", "health start authority is not bound")
        run = self.manager.resolve_selected_health_run(control_handle)
        if type(run) is not RootSelectedNativeHealthRun:
            raise AuthorityDenied("native.health.run", "manager returned an untyped health run")
        if not self.manager.resolve_selected_health_control(control_handle).is_current():
            try:
                os.close(run.process_pidfd)
            except OSError:
                pass
            raise AuthorityDenied("native.health.run", "selected health process is stale")
        with self._lock:
            self._controls[run.process_id] = control_handle
            self._pending_run_pidfds.add(run.process_pidfd)
            admission = self.manager.resolve_selected_health_admission(control_handle)
            material = getattr(admission, "_source_material", None)
            if (type(material) is not RootDaemonNativeHealthStartMaterial
                    or self.material_registry.is_current(material) is not True
                    or run.health_action_id != material._health_definition.get("health_action_id")
                    or run.result_schema_id != material.health_result_schema_id
                    or run.provider_required is not material.health_provider_required
                    or run.package_id != material.native_package_id
                    or run.compiled_closure_sha256 != material.native_closure_sha256):
                try:
                    os.close(run.process_pidfd)
                except OSError:
                    pass
                raise AuthorityDenied("native.health.run", "health run differs from committed source material")
            self._expected_results[(run.process_id, run.result_schema_id)] = material._expected_result_bytes
        return run

    def _resolve_process(self, pid: int, pidfd: int, *, profile_id: str,
                         generation: str) -> Any:
        return self.manager.resolve_live_peer(
            pid, pidfd, profile_id=profile_id, generation=generation,
        )

    def _resolve_loaded_package(self, run: Any) -> Any:
        return self.manager.resolve_loaded_native_package(run.process_id, run.process_generation)

    def _resolve_event(self, observation_handle: str, event_id: str) -> Any:
        from .native_health_observer import RootNativeHealthEvent
        with self._lock:
            event = self._events.get((observation_handle, event_id))
        if type(event) is not RootNativeHealthEvent:
            raise AuthorityDenied("native.health.event", "actual selected-run event is not retained")
        return event

    def _validate_result(self, schema_id: str, payload: bytes) -> Any:
        from .native_health_observer import RootValidatedNativeHealthResult
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= 65_536:
            raise AuthorityDenied("native.health.result", "health result is outside its bounded schema")
        with self._lock:
            matches = tuple(expected for (_process_id, selected_schema), expected
                            in self._expected_results.items() if selected_schema == schema_id)
        if len(matches) != 1 or payload != matches[0]:
            raise AuthorityDenied("native.health.result", "captured result differs from selected signed expected result")
        return RootValidatedNativeHealthResult(
            schema_id, hashlib.sha256(payload).hexdigest(), "passed",
        )

    def _cancel_selected_run(self, run: Any) -> None:
        with self._lock:
            control_handle = self._controls.get(run.process_id)
        if control_handle is None:
            raise AuthorityDenied("native.health.cancel", "selected control is no longer retained")
        self.manager.cancel_selected_health(control_handle)

    def start_selected_health(self, admission_handle: str) -> Any:
        if self.start_authority is None:
            raise AuthorityDenied("native.health.run", "health start authority is not bound")
        control = None
        try:
            # The manager begins the exact observer run while this call is in
            # progress.  The resolver DTO owns a temporary duplicate PIDFD;
            # RootNativeHealthObserver retains its own duplicate before this
            # method closes the resolver's copy.
            control = self.manager.start_selected_native_health(admission_handle)
            self._retain_control(control)
            observation = self.manager.resolve_selected_health_observation_handle(control.control_handle)
            if not _OPAQUE.fullmatch(observation):
                raise ValueError
            with self._lock:
                self._controls[control.process_id] = control.control_handle
            return control
        except Exception:
            if control is not None:
                self.manager.cancel_selected_health(control.control_handle)
            raise AuthorityDenied("native.health.run", "selected worker control could not start a current health run") from None
        finally:
            with self._lock:
                pending = tuple(self._pending_run_pidfds)
                self._pending_run_pidfds.clear()
            for pidfd in pending:
                try:
                    os.close(pidfd)
                except OSError:
                    pass

    def _retain_control(self, control: Any) -> None:
        from .managed_process_custodian import RootSelectedHealthControl
        if type(control) is not RootSelectedHealthControl or not control.is_current():
            raise ValueError("manager did not issue a current selected health control")

    def run_selected_health(self, control_handle: str) -> str:
        """Drive exact root input and return only an observer-issued receipt ID.

        Native request/provider/tool events are resolved from the existing
        request, invocation, source-result and manager terminal registries.
        If any current typed source event is absent, the run is cancelled and
        remains unavailable; no stdout or fixture-derived event is invented.
        """
        if self.start_authority is None or not _OPAQUE.fullmatch(control_handle):
            raise AuthorityDenied("native.health.run", "selected daemon health run is unavailable")
        # Refuse before source input or other effects until the concrete native
        # request/invocation/result event graph can be re-resolved for this
        # control.  The manager starts the process and emits READY; this
        # preflight never fabricates the remaining event kinds from stdout or
        # expected fixture bytes.
        observation = self.manager.resolve_selected_health_observation_handle(control_handle)
        self.observer.resolve_current_run_for_observation(observation)
        raise AuthorityDenied(
            "native.health.events_unavailable",
            "selected native request, provider, invocation, and result event registries are not yet joined",
        )

    def resolve_current_health_material(self, proof: Any) -> RootDaemonNativeHealthStartMaterial:
        return self.material_registry.resolve_current_health_material(proof)

    def is_current_health_material(self, material: RootDaemonNativeHealthStartMaterial) -> bool:
        try:
            return self.material_registry.verify_current(material) is material
        except Exception:
            return False

    def is_current(self, material: RootDaemonNativeHealthStartMaterial) -> bool:
        """Exact issuer-facing currentness method used by daemon admission."""
        return self.is_current_health_material(material)


__all__ = [
    "RootDaemonNativeHealthMaterialRegistry", "RootDaemonNativeHealthRunRegistry",
    "RootDaemonNativeHealthSourceBinding", "RootDaemonNativeHealthStartMaterial",
    "RootHealthInputDeliveryRegistry", "RootSelectedHealthInputDelivery",
]
