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


@dataclass(frozen=True, slots=True, repr=False)
class _HealthEventSource:
    kind: str
    control_handle: str
    input_event: Any = field(default=None, repr=False, compare=False)
    request: Any = field(default=None, repr=False, compare=False)
    selected_call: Any = field(default=None, repr=False, compare=False)
    completion: Any = field(default=None, repr=False, compare=False)
    result: Any = field(default=None, repr=False, compare=False)
    terminal: Any = field(default=None, repr=False, compare=False)


class RootHealthInputDeliveryRegistry:
    """Seal the exact captured health input event and its selected bytes."""

    def __init__(self, runtime: Any, material_registry: RootDaemonNativeHealthMaterialRegistry,
                 manager: Any):
        from .native_input_observer import RootNativeInputObserver
        from .source_observers import SourceObserverRegistry
        source_observers = getattr(runtime.service, "source_observer_registry", None)
        loader = getattr(runtime.service, "native_loader_observation_store", None)
        loaded_resolver = getattr(loader, "source_observer_loaded_package_resolver", None)
        if (type(material_registry) is not RootDaemonNativeHealthMaterialRegistry
                or manager is not runtime.process_manager
                or type(source_observers) is not SourceObserverRegistry
                or not callable(loaded_resolver)):
            raise AuthorityDenied("native.health.input", "root health source/input issuers are unavailable")
        self.runtime, self.material_registry = runtime, material_registry
        self.source_observers, self.manager = source_observers, manager
        self._issuer = object()
        self._deliveries: dict[str, RootSelectedHealthInputDelivery] = {}
        # Membership is retained by this issuer at the point where the exact
        # input observer returns the event.  Manager consumers never inspect
        # the observer's private event dictionary.
        self._input_events: dict[str, Any] = {}
        self._input_event_bindings: dict[str, tuple[str, Any]] = {}
        self._control_by_observation: dict[str, str] = {}
        self._consumed: set[str] = set()
        self._lock = threading.RLock()
        self.native_input_observer = RootNativeInputObserver(
            service=runtime.service, source_observers=source_observers,
            task_input_resolver=None, health_input_resolver=self._resolve_health_input,
            desktop_input_resolver=None,
            process_resolver=manager.resolve_live_peer,
            loaded_package_proof_resolver=loaded_resolver,
            monotonic=runtime.service.monotonic,
        )

    @classmethod
    def from_root_runtime(cls, runtime: Any,
                          material_registry: RootDaemonNativeHealthMaterialRegistry
                          ) -> "RootHealthInputDeliveryRegistry":
        return cls(runtime, material_registry, runtime.process_manager)

    def _resolve_health_input(self, observation_handle: str, process_handle: Any,
                              fixture_artifact_id: str) -> Any:
        from .native_input_observer import RootNativeInputSelection
        from .managed_process_custodian import ManagedProcessIdentityLease
        from .types import HostContext, canonical_digest

        if (not _OPAQUE.fullmatch(observation_handle)
                or type(process_handle) is not ManagedProcessIdentityLease
                or not isinstance(fixture_artifact_id, str)):
            raise AuthorityDenied("native.health.input", "root-selected health input selector is malformed")
        with self._lock:
            control_handle = self._control_by_observation.get(observation_handle)
        if control_handle is None:
            raise AuthorityDenied("native.health.input", "health input has no current selected control")
        try:
            control = self.manager.resolve_selected_health_control(control_handle)
            current_observation = self.manager.resolve_selected_health_observation_handle(control_handle)
            admission = self.manager.resolve_selected_health_admission(control_handle)
            authority = self.manager.native_health_start_authority
            material = getattr(admission, "_source_material", None)
            if (current_observation != observation_handle or type(admission) is not RootNativeHealthStartAdmission
                    or type(material) is not RootDaemonNativeHealthStartMaterial
                    or not authority.is_current(admission)
                    or self.material_registry.verify_current(material) is not material
                    or control.process_id != process_handle.process_id
                    or control.profile_id != process_handle.profile_id
                    or control.process_generation != process_handle.generation
                    or process_handle.uid <= 0 or process_handle.pid <= 0
                    or process_handle.expires_monotonic <= self.runtime.service.monotonic()
                    # The manager admission is bound to the selected health
                    # recipe artifact (the fixed fixture identity).  The
                    # request bytes are a distinct member of that recipe and
                    # remain selected below from the signed material.
                    or fixture_artifact_id != material.health_fixture_artifact_id):
                raise ValueError
            identity = self.manager.resolve_live_peer(
                process_handle.pid, process_handle.pidfd,
                profile_id=process_handle.profile_id, generation=process_handle.generation,
            )
            package = self.manager.resolve_loaded_native_package(
                control.process_id, control.process_generation,
            )
            now = self.runtime.service.monotonic()
            if (identity is None or identity.kernel_uid != process_handle.uid
                    or package is None or package.package_id != material.native_package_id
                    or package.compiled_closure_sha256 != material.native_closure_sha256
                    or package.profile_id != control.profile_id
                    or package.generation != control.process_generation
                    or package.service_generation_digest != control.service_generation_digest):
                raise ValueError
            matches = tuple(
                row for row in self.source_observers.observers.values()
                if row.source_kind == "native-input"
                and row.profile_id == control.profile_id
                and row.generation == control.process_generation
                and row.producer_uid == process_handle.uid
                and row.package_id == material.native_package_id
                and row.native_package_generation == material.native_package_generation
            )
            if len(matches) != 1:
                raise ValueError
            observer = matches[0]
            lease = min(
                float(control.expires_monotonic), float(process_handle.expires_monotonic),
                float(material.expires_monotonic), now + observer.lease_seconds,
            )
            if lease <= now:
                raise ValueError
            payload = bytes(material._request_bytes)
            context_wire = self.runtime.service._issue_context(process_handle.uid, {
                "purpose": "hermes-native-health-input",
                "intent": f"health:{control.control_handle}:{fixture_artifact_id}",
                "trace_id": secrets.token_urlsafe(32), "lease_seconds": lease - now,
                "source_contexts": [], "source_receipts": [],
                "final_payload_digest": canonical_digest(payload),
                "operation": "native.request.dispatch",
            }, peer_pid=process_handle.pid)
            context = HostContext.from_wire(context_wire)
            if (context.uid != process_handle.uid
                    or context.profile_id != control.profile_id
                    or context.generation != control.process_generation
                    or context.native_process_identity != self.runtime.service._native_process_identity(
                        process_handle.pid, process_handle.uid)):
                raise ValueError
            selected = RootNativeInputSelection(
                source_path="selected-health-fixture",
                observer_enrollment_id=observer.observer_enrollment_id,
                payload_bytes=payload, parent_context=context, parent_receipt_handles=(),
                peer_pid=process_handle.pid, peer_pidfd=os.dup(process_handle.pidfd),
                peer_uid=process_handle.uid, peer_identity=identity,
                profile_id=control.profile_id, generation=control.process_generation,
                package_id=material.native_package_id,
                compiled_closure_sha256=material.native_closure_sha256,
                expires_monotonic=lease, invocation_id=context.grant_id,
            )
            return selected
        except Exception:
            raise AuthorityDenied("native.health.input", "current signed fixture, source role, or worker identity is unavailable") from None

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
            with self._lock:
                prior = self._control_by_observation.get(observation_handle)
                if prior is not None and prior != control_handle:
                    raise ValueError
                self._control_by_observation[observation_handle] = control_handle
            event = self.native_input_observer.record_selected_health_input(
                observation_handle, process, artifact_id,
            )
            self._verify_input_event_current(control_handle, observation_handle, event)
            identity = self.manager.resolve_live_peer(
                process.pid, process.pidfd, profile_id=process.profile_id,
                generation=process.generation,
            )
            if identity is None or identity.kernel_uid != process.uid:
                raise ValueError
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
        finally:
            if "process" in locals():
                process.close()
        with self._lock:
            self._deliveries[delivery.delivery_handle] = delivery
            self._input_events[delivery.input_event.input_event_id] = delivery.input_event
            self._input_event_bindings[delivery.input_event.input_event_id] = (
                observation_handle, identity,
            )
        return delivery

    def current_events_for_native_request(self) -> tuple[Any, ...]:
        """Return only held input events that still re-resolve to this run."""
        with self._lock:
            rows = tuple((event_id, event, *self._input_event_bindings[event_id])
                         for event_id, event in self._input_events.items()
                         if event_id in self._input_event_bindings)
        current: list[Any] = []
        for event_id, event, observation_handle, identity in rows:
            try:
                resolved = self.native_input_observer.resolve_current_health_event(
                    event_id, observation_handle, identity,
                )
            except Exception:
                continue
            if resolved is event:
                current.append(event)
        return tuple(current)

    def verify_current_event_for_native_request(self, event: Any) -> Any:
        from .native_input_observer import RootNativeInputEvent
        if type(event) is not RootNativeInputEvent:
            raise AuthorityDenied("native.health.input", "typed selected health input event is required")
        with self._lock:
            retained = self._input_events.get(event.input_event_id)
            binding = self._input_event_bindings.get(event.input_event_id)
        if retained is not event or binding is None:
            raise AuthorityDenied("native.health.input", "selected health input event is not retained")
        current = self.native_input_observer.resolve_current_health_event(
            event.input_event_id, binding[0], binding[1],
        )
        if current is not event:
            raise AuthorityDenied("native.health.input", "selected health input event changed")
        return event

    def verify_completed_event_for_native_request(self, event: Any,
                                                  completed_terminal_proof: Any) -> Any:
        from .managed_process_custodian import RootCompletedSelectedHealthTerminalProof
        from .native_input_observer import RootNativeInputEvent
        if (type(event) is not RootNativeInputEvent
                or type(completed_terminal_proof) is not RootCompletedSelectedHealthTerminalProof
                or completed_terminal_proof.is_current() is not True):
            raise AuthorityDenied("native.health.input", "completed selected input proof is malformed")
        with self._lock:
            retained = self._input_events.get(event.input_event_id)
            binding = self._input_event_bindings.get(event.input_event_id)
        if (retained is not event or binding is None
                or event.producer_profile_id != completed_terminal_proof.profile_id
                or event.producer_generation != completed_terminal_proof.process_generation):
            raise AuthorityDenied("native.health.input", "completed input event is no longer retained")
        current = self.native_input_observer.resolve_completed_health_event(
            event.input_event_id, binding[0], completed_terminal_proof,
        )
        material = completed_terminal_proof.source_material
        admission = completed_terminal_proof.admission
        if (current is not event
                or self.manager.native_health_start_authority.is_current(admission) is not True
                or self.material_registry.is_current(material) is not True
                or event.payload_sha256 != hashlib.sha256(material._request_bytes).hexdigest()
                or event.payload_size_bytes != len(material._request_bytes)
                or event.native_loader_ready_event_id != completed_terminal_proof.loader_ready_event_id
                or completed_terminal_proof.is_current() is not True):
            raise AuthorityDenied("native.health.input", "completed input no longer matches current source material")
        return event

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
            completed_event_resolver=self._resolve_completed_event,
            process_resolver=self._resolve_process,
            loaded_package_proof_resolver=self._resolve_loaded_package,
            result_validator=self._validate_result,
            selected_run_canceller=self._cancel_selected_run,
            terminal_proof_resolver=self._resolve_completed_terminal,
            monotonic=runtime.service.monotonic,
        )
        self.start_authority: Any | None = None
        self.input_delivery = RootHealthInputDeliveryRegistry.from_root_runtime(runtime, material_registry)
        broker = getattr(runtime, "native_bridge_broker", None)
        request_observer = getattr(broker, "native_request_observer", None)
        from .native_request_observation import NativeRequestObservationRegistry
        if type(request_observer) is not NativeRequestObservationRegistry:
            raise AuthorityDenied("native.health.run", "current native request observer is unavailable")
        request_observer.attach_health_input_delivery_registry(self.input_delivery)
        self.request_observer = request_observer
        self._events: dict[tuple[str, str], Any] = {}
        self._event_sources: dict[tuple[str, str], _HealthEventSource] = {}
        self._controls: dict[str, str] = {}
        self._control_by_observation: dict[str, str] = {}
        self._started_runs: set[str] = set()
        self._finished_runs: set[str] = set()
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
        return self.manager.resolve_loaded_selected_health_package(
            run.process_id, run.process_generation,
        )

    def _resolve_event(self, observation_handle: str, event_id: str) -> Any:
        from .native_health_observer import RootNativeHealthEvent
        with self._lock:
            event = self._events.get((observation_handle, event_id))
            source = self._event_sources.get((observation_handle, event_id))
        if type(event) is not RootNativeHealthEvent or type(source) is not _HealthEventSource:
            raise AuthorityDenied("native.health.event", "actual selected-run event is not retained")
        self._verify_event_source(observation_handle, event, source)
        return event

    def _resolve_completed_event(self, observation_handle: str, event_id: str,
                                 completed_terminal_proof: Any) -> Any:
        """Reopen an exact event after worker cleanup without resolving a dead PID.

        The successful manager postmortem proof binds the original live process,
        loaded package, source material, and verified terminal cleanup. Source
        owners below revalidate their retained records and receipts against
        that proof; this path never calls the process or package live resolvers.
        """
        from .managed_process_custodian import RootCompletedSelectedHealthTerminalProof
        from .native_health_observer import RootNativeHealthEvent
        if (type(completed_terminal_proof) is not RootCompletedSelectedHealthTerminalProof
                or completed_terminal_proof.is_current() is not True
                or not _OPAQUE.fullmatch(observation_handle)
                or not _OPAQUE.fullmatch(event_id)):
            raise AuthorityDenied("native.health.completed_event", "exact completed-run proof is required")
        proof = completed_terminal_proof
        with self._lock:
            event = self._events.get((observation_handle, event_id))
            source = self._event_sources.get((observation_handle, event_id))
            control_handle = self._control_by_observation.get(observation_handle)
        material = proof.source_material
        admission = proof.admission
        if (type(event) is not RootNativeHealthEvent or type(source) is not _HealthEventSource
                or control_handle != proof.control_handle
                or source.control_handle != proof.control_handle
                or event.event_id != event_id or event.event_kind != source.kind
                or event.expires_monotonic <= self.runtime.service.monotonic()
                or (event.process_id, event.process_pid, event.process_uid,
                    event.profile_id, event.process_generation,
                    event.service_generation_digest, event.package_id,
                    event.compiled_closure_sha256)
                   != (proof.process_id, proof.process_pid, proof.process_uid,
                       proof.profile_id, proof.process_generation,
                       proof.service_generation_digest, material.native_package_id,
                       material.native_closure_sha256)
                or material is not admission._source_material
                or self.start_authority is None
                or self.start_authority.is_current(admission) is not True
                or self.material_registry.is_current(material) is not True):
            raise AuthorityDenied("native.health.completed_event", "retained event or committed source join changed")
        try:
            if source.kind == "loader-ready":
                launch = proof.launch_proof
                loaded = proof.loaded_package_proof
                if (source.control_handle != proof.control_handle
                        or event.native_event_handle != launch.launch_handle
                        or event.native_event_sha256 != self._launch_event_digest(launch)
                        or event.loader_ready_event_id != proof.loader_ready_event_id
                        or event.loaded_proof_id != proof.loaded_package_proof_id
                        or getattr(loaded, "proof_id", None) != event.loaded_proof_id):
                    raise ValueError
            elif source.kind == "native-request":
                if source.input_event is None or source.request is None:
                    raise ValueError
                self.input_delivery.verify_completed_event_for_native_request(
                    source.input_event, proof,
                )
                registry = source.request._registry
                current = registry.resolve_completed_health_request_for_input(
                    source.request, source.input_event, proof,
                )
                handles, ids = self._canonical_source_pairs(
                    tuple(current.observation.parent_source_receipt_handles),
                    tuple(row.receipt_id for row in current.parent_source_receipts),
                )
                if (current is not source.request
                        or current.observation.native_request_handle != event.native_event_handle
                        or current.observation.parent_closure_digest != event.parent_closure_digest
                        or handles != event.source_receipt_handles or ids != event.source_receipt_ids
                        or self._request_event_digest(current) != event.native_event_sha256
                        or event.native_request_event_id != event.event_id):
                    raise ValueError
            elif source.kind in {"provider-result", "tool-invocation"}:
                if source.input_event is None or source.request is None or source.selected_call is None:
                    raise ValueError
                self.input_delivery.verify_completed_event_for_native_request(
                    source.input_event, proof,
                )
                request_registry = source.request._registry
                current_request = request_registry.resolve_completed_health_request_for_input(
                    source.request, source.input_event, proof,
                )
                from .native_runtime_observer import NativeInvocationRegistry
                invocation_registry = self.runtime.native_invocation_registry
                if type(invocation_registry) is not NativeInvocationRegistry:
                    raise ValueError
                current_call = invocation_registry.resolve_completed_health_owner_invocation(
                    source.selected_call, current_request, source.input_event, proof,
                )
                if source.kind == "provider-result":
                    handles, ids = self._canonical_source_pairs(
                        current_call.provider_source_receipt_handles,
                        current_call.provider_source_receipt_ids,
                    )
                    if (current_call is not source.selected_call
                            or current_call.provider_response.handle != event.native_event_handle
                            or handles != event.source_receipt_handles
                            or ids != event.source_receipt_ids
                            or event.parent_closure_digest != _digest(list(ids))
                            or self._provider_event_digest(current_call) != event.native_event_sha256
                            or event.provider_result_event_id != event.event_id):
                        raise ValueError
                else:
                    handles, ids = self._canonical_source_pairs(
                        current_call.source_receipt_handles, current_call.source_receipt_ids,
                    )
                    if (current_call is not source.selected_call
                            or current_call.owner_invocation.invocation_handle != event.native_event_handle
                            or handles != event.source_receipt_handles
                            or ids != event.source_receipt_ids
                            or event.parent_closure_digest != _digest(list(ids))
                            or self._invocation_event_digest(current_call) != event.native_event_sha256
                            or event.tool_invocation_event_id != event.event_id):
                        raise ValueError
            elif source.kind == "tool-result":
                current = self.runtime.service.source_observer_registry.resolve_completed_owner_overlay_health_result(
                    source.completion, proof,
                )
                if (current is not source.result
                        or current.receipt_handle != event.native_event_handle
                        or current.source_receipt_handles != event.source_receipt_handles
                        or current.source_receipt_ids != event.source_receipt_ids
                        or current.capsule.parent_closure_digest != event.parent_closure_digest
                        or hashlib.sha256(current.capture_payload).hexdigest() != event.native_event_sha256
                        or event.tool_result_event_id != event.event_id):
                    raise ValueError
            elif source.kind == "terminal":
                current = self._resolve_completed_terminal(
                    source.control_handle, source.terminal.terminal_receipt.terminal_receipt_handle,
                )
                terminal = current.terminal_receipt
                if (current is not proof or source.terminal is not proof
                        or event.native_event_handle != terminal.terminal_receipt_handle
                        or event.terminal_receipt_handle != terminal.terminal_receipt_handle
                        or event.terminal_status != "succeeded" or event.cleanup_verified is not True
                        or self._terminal_event_digest(terminal) != event.native_event_sha256):
                    raise ValueError
            else:
                raise ValueError
        except Exception:
            raise AuthorityDenied("native.health.completed_event", "retained source event no longer verifies") from None
        if proof.is_current() is not True:
            raise AuthorityDenied("native.health.completed_event", "completed manager proof changed during event verification")
        return event

    def _verify_event_source(self, observation_handle: str, event: Any,
                             source: _HealthEventSource) -> None:
        """Re-resolve an event from its current native owner before each use."""
        now = self.runtime.service.monotonic()
        if event.expires_monotonic <= now:
            raise AuthorityDenied("native.health.event", "selected native event has expired")
        if source.kind == "loader-ready":
            ready = self.manager.resolve_selected_health_loader_ready_event(source.control_handle)
            launch = self.manager.resolve_selected_health_launch_proof(source.control_handle)
            run = self.manager.resolve_selected_health_run(source.control_handle)
            try:
                if (ready != event.event_id or ready != event.loader_ready_event_id
                        or launch.launch_handle != event.native_event_handle
                        or getattr(run.loaded_package_proof, "proof_id", None) != event.loaded_proof_id
                        or self._launch_event_digest(launch) != event.native_event_sha256):
                    raise ValueError
            finally:
                try:
                    os.close(run.process_pidfd)
                except OSError:
                    pass
            return
        if source.kind in {"native-request", "provider-result", "tool-invocation"}:
            process = self.manager.resolve_selected_health_process(source.control_handle)
            try:
                identity = self.manager.resolve_live_peer(
                    process.pid, process.pidfd, profile_id=process.profile_id,
                    generation=process.generation,
                )
                if identity is None:
                    raise ValueError
                self.input_delivery.verify_current_event_for_native_request(source.input_event)
                request = self._resolve_request_for_input(
                    source.control_handle, source.input_event, process, identity,
                )
                if source.kind == "native-request":
                    handles, ids = self._canonical_source_pairs(
                        tuple(request.observation.parent_source_receipt_handles),
                        tuple(row.receipt_id for row in request.parent_source_receipts),
                    )
                    if (request.observation is not source.request.observation
                            or request.canonical_request_bytes != source.request.canonical_request_bytes
                            or event.native_event_handle != request.observation.native_request_handle
                            or event.parent_closure_digest != request.observation.parent_closure_digest
                            or event.source_receipt_handles != handles
                            or event.source_receipt_ids != ids
                            or self._request_event_digest(request) != event.native_event_sha256):
                        raise ValueError
                    return
                selected_call = self._resolve_owner_invocation(
                    source.control_handle, source.input_event, request, process, identity,
                )
                if source.kind == "provider-result":
                    handles, ids = self._canonical_source_pairs(
                        selected_call.provider_source_receipt_handles,
                        selected_call.provider_source_receipt_ids,
                    )
                    if (selected_call.provider_response is not source.selected_call.provider_response
                            or selected_call.provider_response.handle != event.native_event_handle
                            or event.source_receipt_handles != handles
                            or event.source_receipt_ids != ids
                            or event.parent_closure_digest != _digest(list(ids))
                            or self._provider_event_digest(selected_call) != event.native_event_sha256):
                        raise ValueError
                else:
                    handles, ids = self._canonical_source_pairs(
                        selected_call.source_receipt_handles, selected_call.source_receipt_ids,
                    )
                    if (selected_call.owner_invocation is not source.selected_call.owner_invocation
                            or selected_call.owner_invocation.invocation_handle != event.native_event_handle
                            or event.source_receipt_handles != handles
                            or event.source_receipt_ids != ids
                            or event.parent_closure_digest != _digest(list(ids))
                            or self._invocation_event_digest(selected_call) != event.native_event_sha256):
                        raise ValueError
            finally:
                process.close()
            return
        if source.kind == "tool-result":
            current = self.runtime.service.source_observer_registry.resolve_current_owner_overlay_health_result(
                source.completion,
            )
            if (current.receipt is not source.result.receipt
                    or current._completion is not source.completion
                    or current.capture_payload != source.result.capture_payload
                    or current.result_payload != source.result.result_payload
                    or current.source_receipt_ids != source.result.source_receipt_ids
                    or current.receipt_handle != event.native_event_handle
                    or current.source_receipt_handles != event.source_receipt_handles
                    or current.source_receipt_ids != event.source_receipt_ids
                    or current.capsule.parent_closure_digest != event.parent_closure_digest
                    or hashlib.sha256(current.capture_payload).hexdigest() != event.native_event_sha256):
                raise AuthorityDenied("native.health.event", "current tool-result source changed")
            return
        if source.kind == "terminal":
            current = self._resolve_completed_terminal(
                source.control_handle, source.terminal.terminal_receipt_handle,
            )
            terminal = current.terminal_receipt
            if (current is not source.terminal or current.is_current() is not True
                    or terminal.terminal_receipt_handle != event.native_event_handle
                    or terminal.terminal_receipt_handle != event.terminal_receipt_handle
                    or self._terminal_event_digest(terminal) != event.native_event_sha256):
                raise AuthorityDenied("native.health.event", "selected process terminal cleanup changed")
            return
        raise AuthorityDenied("native.health.event", "unknown selected health event source")

    def _resolve_completed_terminal(self, control_handle: str,
                                    terminal_receipt_handle: str) -> Any:
        """Use manager postmortem proof after cleanup, never live PID checks."""
        from .managed_process_custodian import RootCompletedSelectedHealthTerminalProof
        proof = self.manager.resolve_completed_selected_health_terminal(
            control_handle, terminal_receipt_handle,
        )
        if (type(proof) is not RootCompletedSelectedHealthTerminalProof
                or proof.control_handle != control_handle
                or proof.terminal_receipt.terminal_receipt_handle != terminal_receipt_handle
                or proof.is_current() is not True):
            raise AuthorityDenied("native.health.terminal", "completed manager terminal proof is stale")
        return proof

    @staticmethod
    def _launch_event_digest(proof: Any) -> str:
        names = (
            "launch_handle", "profile_id", "profile_generation", "service_generation_digest",
            "publication_receipt_handle", "publication_sha256", "active_generation_id",
            "source_choice_signed_record_sha256", "runtime_record_id", "runtime_record_sha256",
            "pm_runtime_receipt_handle", "pm_runtime_closure_sha256", "executable_sha256",
            "executable_device", "executable_inode", "executable_uid", "executable_gid",
            "executable_mode", "native_output_root_device", "native_output_root_inode",
            "listener_activation_id", "listener_invocation_id", "listener_pid",
            "listener_start_ticks", "listener_socket_device", "listener_socket_inode",
            "selected_view_sha256",
        )
        return _digest({"schema": 1, "kind": "native-worker-loader-ready-v1",
                        **{name: getattr(proof, name) for name in names}})

    @staticmethod
    def _request_event_digest(selected: Any) -> str:
        observation = selected.observation
        return _digest({
            "schema": 1, "native_request_handle": observation.native_request_handle,
            "request_sha256": observation.request_sha256,
            "request_size_bytes": observation.request_size_bytes,
            "parent_closure_digest": observation.parent_closure_digest,
            "source_receipt_ids": [row.receipt_id for row in selected.parent_source_receipts],
            "context_digest": observation.context_digest,
        })

    @staticmethod
    def _provider_event_digest(selected: Any) -> str:
        response = selected.provider_response
        return _digest({
            "schema": 1, "provider_response_handle": response.handle,
            "native_request_handle": response.native_request_handle,
            "response_digest": response.response_digest,
            "response_status": response.response_status,
            "source_receipt_ids": list(selected.provider_source_receipt_ids),
            "profile_id": response.profile_id, "generation": response.generation,
            "package_id": response.package_id,
            "native_package_generation": response.native_package_generation,
        })

    @staticmethod
    def _invocation_event_digest(selected: Any) -> str:
        invocation = selected.owner_invocation
        return _digest({
            "schema": 1, "invocation_handle": invocation.invocation_handle,
            "registration_id": invocation.registration_id, "method": invocation.method,
            "action_id": invocation.registration_id,
            "arguments_sha256": invocation.arguments_sha256,
            "parent_closure_digest": invocation.parent_closure_digest,
            "source_receipt_ids": list(selected.source_receipt_ids),
        })

    @staticmethod
    def _terminal_event_digest(terminal: Any) -> str:
        names = (
            "schema", "terminal_receipt_handle", "control_handle", "process_id",
            "profile_id", "generation", "service_generation_digest", "process_uid",
            "process_gid", "unit", "cgroup", "start_ticks", "exit_code", "timed_out",
            "cancelled", "stdout_size_bytes", "stderr_size_bytes", "stdout_sha256",
            "stderr_sha256", "output_overflow", "loader_ready_event_id", "cgroup_empty",
            "main_pidfd_gone", "launcher_reaped", "cleanup_verified",
        )
        return _digest({name: getattr(terminal, name) for name in names})

    @staticmethod
    def _not_cancelled() -> bool:
        return False

    def _wait_current(self, resolver: Any, control_handle: str, deadline: float) -> Any:
        """Poll only exact not-yet-arrived registry events within the run lease."""
        while self.runtime.service.monotonic() < deadline:
            try:
                return resolver()
            except AuthorityDenied as exc:
                if exc.code not in {
                    "native.request_health_pending", "native.health.invocation_pending",
                    "native.health.result_pending",
                }:
                    raise
            time.sleep(0.025)
        raise AuthorityDenied("native.health.events_unavailable", "native event did not arrive before the run lease")

    def _resolve_request_for_input(self, control_handle: str, input_event: Any,
                                   process: Any, identity: Any) -> Any:
        admission = self.manager.resolve_selected_health_admission(control_handle)
        if not self.start_authority.is_current(admission):
            raise AuthorityDenied("native.health.request", "selected health admission is stale")
        return self.request_observer.resolve_current_health_request_for_input(
            input_event, live_producer_identity=identity, producer_pid=process.pid,
            producer_profile_id=process.profile_id, producer_generation=process.generation,
            native_package_generation=admission.native_package_generation,
        )

    def _resolve_owner_invocation(self, control_handle: str, input_event: Any,
                                  request: Any, process: Any, identity: Any) -> Any:
        from .native_runtime_observer import NativeInvocationRegistry
        registry = self.runtime.native_invocation_registry
        if type(registry) is not NativeInvocationRegistry:
            raise AuthorityDenied("native.health.invocation", "native invocation registry is unavailable")
        admission = self.manager.resolve_selected_health_admission(control_handle)
        if not self.start_authority.is_current(admission):
            raise AuthorityDenied("native.health.invocation", "selected health admission is stale")
        return registry.resolve_current_health_owner_invocation(
            request, input_event, peer_uid=process.uid, peer_pid=process.pid,
            peer_pidfd=process.pidfd, live_producer_identity=identity,
            expected_profile_id=process.profile_id, expected_generation=process.generation,
            expected_package_id=admission.native_package_id,
            expected_package_generation=admission.native_package_generation,
            expected_service_generation_digest=admission.service_generation_digest,
            expected_action_id=admission._source_material._health_definition["health_action_id"],
        )

    def _record_health_event(self, observation_handle: str, control_handle: str,
                             run: Any, *, kind: str, native_handle: str,
                             native_digest: str, ancestry_kind: str,
                             parent_closure_digest: str | None,
                             source_handles: tuple[str, ...] = (),
                             source_ids: tuple[str, ...] = (),
                             causal_parents: tuple[str, ...] = (),
                             self_reference_fields: tuple[str, ...] = (),
                             event_id: str | None = None,
                             **fields: Any) -> Any:
        from .native_health_observer import RootNativeHealthEvent
        event_id = event_id or secrets.token_urlsafe(32)
        if not _OPAQUE.fullmatch(event_id):
            raise AuthorityDenied("native.health.event", "native event source supplied a malformed identifier")
        for field_name in self_reference_fields:
            if field_name in fields:
                raise AuthorityDenied("native.health.event", "self-referential event field was already supplied")
            fields[field_name] = event_id
        now = self.runtime.service.monotonic()
        expires = min(float(run.expires_monotonic), now + _MAX_LEASE,
                      float(fields.pop("source_expires_monotonic", run.expires_monotonic)))
        private_source = _HealthEventSource(
            kind=kind, control_handle=control_handle,
            input_event=fields.pop("_input_event", None),
            request=fields.pop("_request", None),
            selected_call=fields.pop("_selected_call", None),
            completion=fields.pop("_completion", None), result=fields.pop("_result", None),
            terminal=fields.pop("_terminal", None),
        )
        event = RootNativeHealthEvent(
            event_id=event_id, event_kind=kind, operation_id=run.operation_id,
            enrollment_id=run.enrollment_id, profile_id=run.profile_id,
            process_generation=run.process_generation,
            service_generation_digest=run.service_generation_digest,
            process_id=run.process_id, process_pid=run.process_pid,
            process_uid=run.process_uid, package_id=run.package_id,
            compiled_closure_sha256=run.compiled_closure_sha256,
            parent_closure_digest=parent_closure_digest,
            observed_monotonic=now, expires_monotonic=expires,
            ancestry_kind=ancestry_kind, native_event_handle=native_handle,
            native_event_sha256=native_digest,
            causal_parent_event_ids=causal_parents,
            source_receipt_handles=source_handles,
            source_receipt_ids=source_ids, **fields,
        )
        key = (observation_handle, event_id)
        with self._lock:
            if key in self._events or any(existing_id == event_id for _, existing_id in self._events):
                raise AuthorityDenied("native.health.event", "health event identifier was replayed")
            self._events[key] = event
            self._event_sources[key] = private_source
        try:
            self.observer.observe_health_event(observation_handle, event_id)
        except Exception:
            with self._lock:
                self._events.pop(key, None)
                self._event_sources.pop(key, None)
            raise
        return event

    def _canonical_source_pairs(self, handles: tuple[str, ...], expected_ids: tuple[str, ...]
                                ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        service = self.runtime.service
        with service._lock:
            rows = tuple(service._source_receipt_handles.get(handle) for handle in handles)
        if (not rows or any(row is None for row in rows)
                or len({row.receipt_id for row in rows if row is not None}) != len(rows)
                or tuple(sorted(row.receipt_id for row in rows if row is not None))
                   != tuple(sorted(expected_ids))):
            raise AuthorityDenied("native.health.lineage", "native source receipt handle and ID join is incomplete")
        pairs = sorted(((row.receipt_id, handle) for handle, row in zip(handles, rows, strict=True)),
                       key=lambda pair: pair[0])
        return tuple(handle for _receipt_id, handle in pairs), tuple(receipt_id for receipt_id, _handle in pairs)

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
        self._cancel_control(control_handle)

    def _cancel_control(self, control_handle: str) -> None:
        """Cancel through the exact observer already bound into the manager."""
        if self.start_authority is None:
            raise AuthorityDenied("native.health.cancel", "health start authority is unavailable")
        try:
            observation_handle = self.manager.resolve_selected_health_observation_handle(
                control_handle,
            )
            if not _OPAQUE.fullmatch(observation_handle):
                raise ValueError
            observer = self.start_authority.health_observer
            if observer is not self.observer:
                raise ValueError
            observer.cancel_selected_health(observation_handle)
        except Exception:
            raise AuthorityDenied("native.health.cancel", "selected health observation cannot be cancelled") from None

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
                self._control_by_observation[observation] = control.control_handle
            return control
        except Exception:
            if control is not None:
                try:
                    self._cancel_control(control.control_handle)
                except AuthorityDenied:
                    pass
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
        with self._lock:
            if control_handle in self._started_runs:
                raise AuthorityDenied("native.health.replay", "selected health control already has a run attempt")
            self._started_runs.add(control_handle)
        try:
            observation = self.manager.resolve_selected_health_observation_handle(control_handle)
            run = self.observer.resolve_current_run_for_observation(observation)
            admission = self.manager.resolve_selected_health_admission(control_handle)
            if not self.start_authority.is_current(admission):
                raise AuthorityDenied("native.health.run", "selected health admission is stale")
            deadline = min(float(run.expires_monotonic), self.runtime.service.monotonic() + 12.0)

            ready_id = self.manager.resolve_selected_health_loader_ready_event(control_handle)
            launch = self.manager.resolve_selected_health_launch_proof(control_handle)
            fresh_run = self.manager.resolve_selected_health_run(control_handle)
            try:
                if (fresh_run.process_id != run.process_id
                        or getattr(fresh_run.loaded_package_proof, "proof_id", None)
                           != getattr(run.loaded_package_proof, "proof_id", None)):
                    raise AuthorityDenied("native.health.run", "selected runtime changed before READY event")
                loader = self._record_health_event(
                    observation, control_handle, run, kind="loader-ready",
                    native_handle=launch.launch_handle,
                    native_digest=self._launch_event_digest(launch),
                    ancestry_kind="custody-event-v1", parent_closure_digest=None,
                    event_id=ready_id,
                    self_reference_fields=("loader_ready_event_id",),
                    loaded_proof_id=fresh_run.loaded_package_proof.proof_id,
                    source_expires_monotonic=min(launch.expires_monotonic, deadline),
                )
                if loader.loader_ready_event_id != ready_id:
                    raise AuthorityDenied("native.health.run", "manager READY event differs from retained loader event")
            finally:
                os.close(fresh_run.process_pidfd)

            delivery = self.input_delivery.prepare_selected_health_input(control_handle)
            self.input_delivery.verify_current(delivery, control_handle)
            input_write = self.manager.write_selected_health_input(
                control_handle, delivery, self.input_delivery,
            )
            from .managed_process_custodian import RootSelectedHealthInputWriteReceipt
            if (type(input_write) is not RootSelectedHealthInputWriteReceipt
                    or input_write.input_event_id != delivery.input_event.input_event_id
                    or input_write.loader_ready_event_id != ready_id
                    or input_write.payload_sha256 != delivery.payload_sha256
                    or input_write.payload_size_bytes != delivery.payload_size_bytes
                    or input_write.process_id != run.process_id
                    or input_write.process_generation != run.process_generation):
                raise AuthorityDenied("native.health.input", "manager did not confirm the exact selected input write")

            def resolve_request() -> Any:
                process = self.manager.resolve_selected_health_process(control_handle)
                try:
                    identity = self.manager.resolve_live_peer(
                        process.pid, process.pidfd, profile_id=process.profile_id,
                        generation=process.generation,
                    )
                    if identity is None:
                        raise AuthorityDenied("native.health.request", "selected request peer is stale")
                    self.input_delivery.verify_current_event_for_native_request(delivery.input_event)
                    return self._resolve_request_for_input(control_handle, delivery.input_event,
                                                           process, identity)
                finally:
                    process.close()

            request = self._wait_current(resolve_request, control_handle, deadline)
            request_source_handles, request_source_ids = self._canonical_source_pairs(
                tuple(request.observation.parent_source_receipt_handles),
                tuple(row.receipt_id for row in request.parent_source_receipts),
            )
            request_event = self._record_health_event(
                observation, control_handle, run, kind="native-request",
                native_handle=request.observation.native_request_handle,
                native_digest=self._request_event_digest(request),
                ancestry_kind="host-context-lineage-v1",
                parent_closure_digest=request.observation.parent_closure_digest,
                source_handles=request_source_handles,
                source_ids=request_source_ids,
                causal_parents=(loader.event_id,),
                self_reference_fields=("native_request_event_id",),
                loader_ready_event_id=loader.event_id,
                _input_event=delivery.input_event, _request=request,
                source_expires_monotonic=request.observation.expires_monotonic,
            )

            def resolve_call() -> Any:
                process = self.manager.resolve_selected_health_process(control_handle)
                try:
                    identity = self.manager.resolve_live_peer(
                        process.pid, process.pidfd, profile_id=process.profile_id,
                        generation=process.generation,
                    )
                    if identity is None:
                        raise AuthorityDenied("native.health.invocation", "selected call peer is stale")
                    return self._resolve_owner_invocation(control_handle, delivery.input_event,
                                                          request, process, identity)
                finally:
                    process.close()

            selected_call = self._wait_current(resolve_call, control_handle, deadline)
            provider_event = None
            if run.provider_required:
                provider = selected_call.provider_response
                provider_handles, provider_ids = self._canonical_source_pairs(
                    selected_call.provider_source_receipt_handles,
                    selected_call.provider_source_receipt_ids,
                )
                provider_event = self._record_health_event(
                    observation, control_handle, run, kind="provider-result",
                    native_handle=provider.handle,
                    native_digest=self._provider_event_digest(selected_call),
                    ancestry_kind="source-receipt-ids-v1",
                    parent_closure_digest=_digest(list(provider_ids)),
                    source_handles=provider_handles,
                    source_ids=provider_ids,
                    causal_parents=(request_event.event_id,),
                    self_reference_fields=("provider_result_event_id",),
                    native_request_event_id=request_event.event_id,
                    provider_result_reference=provider.handle,
                    _input_event=delivery.input_event, _request=request,
                    _selected_call=selected_call,
                    source_expires_monotonic=provider.expires_monotonic,
                )
            invocation = selected_call.owner_invocation
            invocation_handles, invocation_ids = self._canonical_source_pairs(
                selected_call.source_receipt_handles, selected_call.source_receipt_ids,
            )
            invocation_event = self._record_health_event(
                observation, control_handle, run, kind="tool-invocation",
                native_handle=invocation.invocation_handle,
                native_digest=self._invocation_event_digest(selected_call),
                ancestry_kind="source-receipt-ids-v1",
                parent_closure_digest=_digest(list(invocation_ids)),
                source_handles=invocation_handles,
                source_ids=invocation_ids,
                causal_parents=((provider_event.event_id,) if provider_event else (request_event.event_id,)),
                self_reference_fields=("tool_invocation_event_id",),
                native_request_event_id=request_event.event_id,
                provider_result_reference=(provider_event.event_id if provider_event else None),
                provider_result_event_id=(provider_event.event_id if provider_event else None),
                invocation_handle=invocation.invocation_handle,
                action_id=run.health_action_id,
                _input_event=delivery.input_event, _request=request,
                _selected_call=selected_call,
                source_expires_monotonic=invocation.expires_monotonic,
            )

            def resolve_result() -> Any:
                process = self.manager.resolve_selected_health_process(control_handle)
                try:
                    identity = self.manager.resolve_live_peer(
                        process.pid, process.pidfd, profile_id=process.profile_id,
                        generation=process.generation,
                    )
                    if identity is None:
                        raise AuthorityDenied("native.health.result", "selected result peer is stale")
                    active = self.runtime.service.active_owner_overlay_registry
                    completion = active._effect_authority.resolve_current_health_result(
                        selected_call, delivery.input_event,
                        peer_uid=process.uid, peer_pid=process.pid, peer_pidfd=process.pidfd,
                        live_producer_identity=identity,
                        expected_profile_id=process.profile_id,
                        expected_generation=process.generation,
                        expected_package_id=run.package_id,
                        expected_package_generation=admission.native_package_generation,
                        expected_service_generation_digest=run.service_generation_digest,
                        expected_action_id=run.health_action_id,
                    )
                    return self.runtime.service.source_observer_registry.resolve_current_owner_overlay_health_result(
                        completion,
                    )
                finally:
                    process.close()

            result = self._wait_current(resolve_result, control_handle, deadline)
            completion = result._completion
            result_handles, result_ids = self._canonical_source_pairs(
                result.source_receipt_handles, result.source_receipt_ids,
            )
            result_event = self._record_health_event(
                observation, control_handle, run, kind="tool-result",
                native_handle=result.receipt_handle,
                native_digest=hashlib.sha256(result.capture_payload).hexdigest(),
                ancestry_kind="source-receipt-ids-v1",
                parent_closure_digest=result.capsule.parent_closure_digest,
                source_handles=result_handles,
                source_ids=result_ids,
                causal_parents=(invocation_event.event_id,),
                self_reference_fields=("tool_result_event_id",),
                tool_invocation_event_id=invocation_event.event_id,
                invocation_handle=invocation.invocation_handle,
                result_schema_id=run.result_schema_id,
                result_bytes=result.result_payload,
                _input_event=delivery.input_event, _request=request,
                _selected_call=selected_call, _completion=completion, _result=result,
                source_expires_monotonic=min(result.capsule.expires_monotonic,
                                             completion.expires_monotonic),
            )
            terminal = self.manager.wait_selected_health_terminal(
                control_handle, deadline_monotonic=deadline, cancelled=self._not_cancelled,
            )
            terminal_proof = self._resolve_completed_terminal(
                control_handle, terminal.terminal_receipt_handle,
            )
            terminal = terminal_proof.terminal_receipt
            if (terminal.exit_code != 0 or terminal.timed_out or terminal.cancelled
                    or not terminal.cgroup_empty or not terminal.main_pidfd_gone
                    or not terminal.launcher_reaped or not terminal.cleanup_verified
                    or terminal.loader_ready_event_id != ready_id):
                raise AuthorityDenied("native.health.terminal", "selected worker cleanup did not verify")
            self._record_health_event(
                observation, control_handle, run, kind="terminal",
                native_handle=terminal.terminal_receipt_handle,
                native_digest=self._terminal_event_digest(terminal),
                ancestry_kind="custody-event-v1", parent_closure_digest=None,
                causal_parents=(result_event.event_id,),
                terminal_receipt_handle=terminal.terminal_receipt_handle,
                terminal_status="succeeded", cleanup_verified=True,
                _terminal=terminal_proof,
            )
            receipt = self.observer.finish_selected_health(observation)
            with self._lock:
                self._finished_runs.add(control_handle)
            return receipt.health_receipt_handle
        except Exception:
            # A started journal remains started and one-use.  Stop the exact
            # selected observation on every unsuccessful run; never turn an
            # absent native event into a completion or retryable admission.
            try:
                self._cancel_control(control_handle)
            except Exception:
                pass
            raise

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
