"""Root-owned compilation claims for active bootstrap policy publication.

The compiler does not accept policy JSON, paths, identities, or hashes from a
setup client.  It reuses the currently verified strict installed policy,
catalog, and selection documents and binds those bytes to the current prepared
transaction, adopted principal, PM runtime receipts, and native output closure.
The publisher remains the only component that changes the selected generation.
"""
from __future__ import annotations

import fcntl
import copy
import hashlib
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from .bootstrap_enrollment import (
    BootstrapEnrollmentError,
    BootstrapEnrollmentPending,
    EnrollmentReceipt,
    RootSetupSessionHandle,
    VerifiedCommittedEnrollment,
)

_JOURNAL = Path("/var/lib/hermes-installer/authority-journal")
_CLAIM_DIR = "active-policy-compilation"
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_MAX_DOCUMENT = 2 * 1024 * 1024
_NATIVE_PROFILE_HOME_CROSSWALK_PATH = "authority/native-profile-home-crosswalk-v213.json"
_SETUP_CHOICE_PURPOSES = frozenset({
    "memory-service-enablement", "memory-capture-configuration", "private-input-routes",
    "public-free-web-read", "existing-model-selection", "native-policy-preparation",
    "application-qualification",
})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _parse_canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise BootstrapEnrollmentPending(f"compiled {label} is not strict JSON") from None
    if not isinstance(value, dict):
        raise BootstrapEnrollmentPending(f"compiled {label} is not a JSON object")
    return value


def _ordered_unique_receipt_handles(handles: Sequence[str], label: str) -> tuple[str, ...]:
    """Return one stable receipt order while rejecting malformed source handles."""
    result: list[str] = []
    seen: set[str] = set()
    for handle in handles:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise BootstrapEnrollmentPending(f"{label} receipt closure contains a malformed handle")
        if handle not in seen:
            seen.add(handle)
            result.append(handle)
    return tuple(result)


def _owner_overlay_adoption_rows(values: tuple[Any, ...]) -> list[dict[str, Any]]:
    if not isinstance(values, tuple) or len(values) > 4:
        raise BootstrapEnrollmentPending("active claim owner-overlay adoption list is malformed")
    if not values:
        return []
    from .owner_overlay_publication import RootPublishedLocalOwnerAdoption
    expected = {"schema", "identity_kind", "adoption_handle", "signed_choice",
                "adopted_at_unix", "setup_deadline_unix", "owner", "resources",
                "native_package", "operation_records", "view_custody", "source_members",
                "owner_overlay_observer_records"}
    rows: list[dict[str, Any]] = []
    for value in values:
        if type(value) is not RootPublishedLocalOwnerAdoption:
            raise BootstrapEnrollmentPending("active claim contains a foreign owner-overlay adoption")
        row = value.to_claim_row()
        if (not isinstance(row, Mapping) or set(row) != expected | {"adoption_sha256"}
                or row.get("identity_kind") != "linux-local-owner-v1"
                or not isinstance(row.get("adoption_handle"), str)
                or not _HANDLE.fullmatch(row["adoption_handle"])
                or not isinstance(row.get("adoption_sha256"), str)
                or not _HEX.fullmatch(row["adoption_sha256"])):
            raise BootstrapEnrollmentPending("owner-overlay adoption claim row has an invalid schema")
        rows.append(dict(row))
    return rows


def _owner_overlay_adoption_source_handles(values: tuple[Any, ...]) -> tuple[str, ...]:
    """Return the exact receipt ancestry carried by sealed local-owner rows.

    The claim manifest already covers the full row.  Also include its typed
    source/custody receipts in the claim's source closure so publication cannot
    accidentally sever the row from the compilation evidence that produced it.
    """
    rows = _owner_overlay_adoption_rows(values)
    handles: list[str] = []
    for row in rows:
        choice = row["signed_choice"]
        handles.extend(choice["source_member_receipt_handles"])
        resources = row["resources"]
        handles.append(resources["source_receipt_handle"])
        handles.extend(resources["member_receipt_handles"])
        handles.append(row["native_package"]["native_cas_transition_receipt_handle"])
        view = row["view_custody"]
        handles.extend((view["data_root_receipt_handle"],
                        view["profile_view_receipt_handle"],
                        view["target_receipt_handle"]))
        handles.extend(member["receipt_handle"] for member in row["source_members"])
        for operation in row["operation_records"]:
            handles.extend(value for key, value in operation.items()
                           if key.endswith("_receipt_handle") and value is not None)
    return _ordered_unique_receipt_handles(handles, "owner-overlay source")


def _verify_recovered_owner_overlay_join(manifest: Mapping[str, Any], inputs: Mapping[str, Any],
                                         descriptor: Mapping[str, Any]) -> None:
    """Join pre-CAS claim rows to publisher-timestamped descriptor rows."""
    from .owner_overlay_publication import validate_owner_overlay_adoption_row

    claim_rows = manifest.get("owner_overlay_adoptions")
    raw_rows = descriptor.get("owner_overlay_adoption_records")
    if not isinstance(claim_rows, list) or not isinstance(raw_rows, list) or len(raw_rows) > 4:
        raise BootstrapEnrollmentPending("recovered owner-overlay adoption rows are malformed")
    try:
        published = [validate_owner_overlay_adoption_row(row) for row in raw_rows]
    except (TypeError, ValueError):
        raise BootstrapEnrollmentPending("recovered owner-overlay adoption rows are invalid") from None
    if (len(claim_rows) != len(published)
            or inputs.get("owner_overlay_adoption_sha256") != _sha(_canonical(published))):
        raise BootstrapEnrollmentPending("recovered owner-overlay adoption digest differs from publication")
    if not claim_rows:
        if published:
            raise BootstrapEnrollmentPending("publication introduced an unclaimed local-owner adoption")
        return
    if manifest.get("principal_identity_kind") != "linux-local-owner-v1":
        raise BootstrapEnrollmentPending("recovered owner-overlay adoption crossed the active identity domain")
    source_handles = manifest.get("source_receipt_handles")
    choice_rows = manifest.get("choice_adoptions")
    published_choices = inputs.get("choice_projections")
    if not isinstance(source_handles, list) or not isinstance(choice_rows, list) or not isinstance(published_choices, list):
        raise BootstrapEnrollmentPending("recovered owner-overlay claim ancestry is malformed")
    by_handle = {row.get("selection_handle"): row for row in published_choices
                 if isinstance(row, Mapping) and isinstance(row.get("selection_handle"), str)}
    if len(by_handle) != len(published_choices):
        raise BootstrapEnrollmentPending("published choice projections are ambiguous")
    for claimed, adopted in zip(claim_rows, published):
        if not isinstance(claimed, Mapping) or claimed.get("identity_kind") != "linux-local-owner-v1":
            raise BootstrapEnrollmentPending("durable owner-overlay claim row has an invalid identity domain")
        unsigned_claim = dict(claimed)
        claim_digest = unsigned_claim.pop("adoption_sha256", None)
        if not isinstance(claim_digest, str) or claim_digest != _sha(_canonical(unsigned_claim)):
            raise BootstrapEnrollmentPending("durable owner-overlay claim digest is invalid")
        expected_published = dict(claimed)
        expected_published["adopted_at_unix"] = adopted["adopted_at_unix"]
        expected_published["adoption_sha256"] = adopted["adoption_sha256"]
        signed = claimed.get("signed_choice")
        owner = claimed.get("owner")
        if not isinstance(signed, Mapping) or not isinstance(owner, Mapping):
            raise BootstrapEnrollmentPending("durable owner-overlay identity binding is malformed")
        choice = by_handle.get(signed.get("selection_handle"))
        normalized_choice = ({key: value for key, value in choice.items()
                              if key not in {"adopted_at_unix", "publication_receipt_handle",
                                             "publication_sha256", "generation_id"}}
                             if isinstance(choice, Mapping) else None)
        timestamp = adopted["adopted_at_unix"]
        signed_projection = ({key: signed.get(key) for key in normalized_choice}
                             if normalized_choice is not None else None)
        if (adopted != expected_published
                or normalized_choice != signed_projection
                or not isinstance(choice, Mapping)
                or choice.get("adopted_at_unix") != timestamp
                or not isinstance(timestamp, (int, float))
                or not signed.get("issued_at_unix") <= timestamp <= claimed.get("setup_deadline_unix", -1)
                or owner.get("principal_binding_sha256") != manifest.get("principal_binding_sha256")
                or owner.get("namespace_binding_sha256") != manifest.get("namespace_binding_sha256")
                or signed.get("principal_selection_handle") != manifest.get("principal_selection_receipt_handle")
                or signed.get("namespace_selection_handle") != manifest.get("namespace_selection_handle")
                or signed.get("principal_binding_sha256") != manifest.get("principal_binding_sha256")
                or signed.get("namespace_binding_sha256") != manifest.get("namespace_binding_sha256")
                or owner.get("service_generation_id") != manifest.get("prepared_generation_id")
                or owner.get("service_generation_digest") != manifest.get("expected_service_generation_digest")):
            raise BootstrapEnrollmentPending("published owner-overlay row differs from its signed local-owner claim")
        choice_handles = signed.get("source_member_receipt_handles", [])
        resources = claimed.get("resources", {})
        package = claimed.get("native_package", {})
        view = claimed.get("view_custody", {})
        members = claimed.get("source_members", [])
        operations = claimed.get("operation_records", [])
        ancestry = [*choice_handles, resources.get("source_receipt_handle"),
                    *resources.get("member_receipt_handles", []),
                    package.get("native_cas_transition_receipt_handle"),
                    view.get("data_root_receipt_handle"), view.get("profile_view_receipt_handle"),
                    view.get("target_receipt_handle"),
                    *(row.get("receipt_handle") for row in members),
                    *(value for row in operations for key, value in row.items()
                      if key.endswith("_receipt_handle") and value is not None)]
        if not set(_ordered_unique_receipt_handles(ancestry, "recovered owner-overlay")).issubset(source_handles):
            raise BootstrapEnrollmentPending("recovered owner-overlay ancestry is outside the claim source closure")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _read_json(path: Path, *, maximum: int = 64 * 1024) -> Mapping[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        path_info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or stat.S_ISLNK(path_info.st_mode)
                or info.st_dev != path_info.st_dev or info.st_ino != path_info.st_ino
                or info.st_size > maximum):
            raise BootstrapEnrollmentPending("active compilation journal custody is invalid")
        chunks = bytearray()
        while len(chunks) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > maximum:
            raise BootstrapEnrollmentPending("active compilation journal record exceeds its bound")
        value = json.loads(chunks.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict):
            raise ValueError("journal record must be an object")
        return value
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise BootstrapEnrollmentPending("active compilation journal record is malformed") from None
    finally:
        os.close(fd)


def _write_json(path: Path, value: Mapping[str, Any], *, exclusive: bool = False) -> None:
    payload = _canonical(dict(value))
    if len(payload) > 64 * 1024:
        raise BootstrapEnrollmentError("active compilation journal record exceeds its bound")
    target = path
    if not exclusive:
        target = path.with_name("." + path.name + "." + secrets.token_hex(12) + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        with os.fdopen(os.dup(fd), "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(fd)
    finally:
        os.close(fd)
    if not exclusive:
        try:
            os.replace(target, path)
        except Exception:
            try:
                target.unlink()
            except OSError:
                pass
            raise
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _write_immutable_bytes(path: Path, payload: bytes) -> None:
    if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_DOCUMENT:
        raise BootstrapEnrollmentError("compiled active policy output is empty or oversized")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                 | getattr(os, "O_NOFOLLOW", 0), 0o400)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o400)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short active compilation output write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_immutable_bytes(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        path_info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o400 or stat.S_ISLNK(path_info.st_mode)
                or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
                or info.st_size <= 0 or info.st_size > _MAX_DOCUMENT):
            raise BootstrapEnrollmentPending("persisted compiled policy output custody is invalid")
        chunks = bytearray()
        while len(chunks) <= _MAX_DOCUMENT:
            block = os.read(fd, min(131072, _MAX_DOCUMENT + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > _MAX_DOCUMENT:
            raise BootstrapEnrollmentPending("persisted compiled policy output exceeds its bound")
        return bytes(chunks)
    finally:
        os.close(fd)


def _ensure_private_directory(path: Path) -> None:
    if os.geteuid() != 0 or path != _JOURNAL / _CLAIM_DIR:
        raise BootstrapEnrollmentPending("active compilation registry is available only to the fixed root journal")
    try:
        path.mkdir(mode=0o700)
        os.chown(path, 0, 0)
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except FileExistsError:
        pass
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
        raise BootstrapEnrollmentPending("active compilation journal directory custody is invalid")


def _manifest(claim: "RootActivePolicyCompilationClaim") -> dict[str, Any]:
    """Public immutable claim domain. Private live objects and byte bodies are excluded."""
    owner_rows = _owner_overlay_adoption_rows(claim.owner_overlay_adoptions)
    if owner_rows:
        if claim.principal_identity_kind != "linux-local-owner-v1":
            raise BootstrapEnrollmentPending("owner-overlay adoption crossed the active identity domain")
        choices = [_choice_projection_record(row) for row in claim.choice_adoptions]
        sources = set(claim.source_receipt_handles)
        required_sources = set(_owner_overlay_adoption_source_handles(
            claim.owner_overlay_adoptions))
        for row in owner_rows:
            owner = row["owner"]
            choice = row["signed_choice"]
            if (owner["principal_binding_sha256"] != claim.principal_binding_sha256
                    or owner["namespace_binding_sha256"] != claim.namespace_binding_sha256
                    or choice not in choices
                    or choice["principal_selection_handle"] != claim.principal_selection_receipt_handle
                    or choice["namespace_selection_handle"] != claim.namespace_selection_handle
                    or choice["principal_binding_sha256"] != claim.principal_binding_sha256
                    or choice["namespace_binding_sha256"] != claim.namespace_binding_sha256
                    or owner["service_generation_id"] != claim.prepared_generation_id
                    or owner["service_generation_digest"] != claim.expected_service_generation_digest):
                raise BootstrapEnrollmentPending("owner-overlay adoption differs from its signed current claim identity")
        if not required_sources.issubset(sources):
            raise BootstrapEnrollmentPending("owner-overlay receipts are absent from the active source closure")
    return {
        "schema": claim.schema,
        "publication_handle": claim.publication_handle,
        "setup_session_id": claim.setup_session_id,
        "transaction_handle": claim.transaction_handle,
        "plan_sha256": claim.plan_sha256,
        "prepared_generation_id": claim.prepared_generation_id,
        "expected_selection_catalog_sha256": claim.expected_selection_catalog_sha256,
        "expected_service_generation_digest": claim.expected_service_generation_digest,
        "policy_template_artifact_id": claim.policy_template_artifact_id,
        "policy_template_sha256": claim.policy_template_sha256,
        "principal_selection_receipt_handle": claim.principal_selection_receipt_handle,
        "principal_identity_kind": claim.principal_identity_kind,
        "principal_binding_sha256": claim.principal_binding_sha256,
        "namespace_selection_handle": claim.namespace_selection_handle,
        "namespace_binding_sha256": claim.namespace_binding_sha256,
        "owner_overlay_adoptions": owner_rows,
        "runtime_receipt_handles": list(claim.runtime_receipt_handles),
        "materialization_receipt_handles": list(claim.materialization_receipt_handles),
        "precompile_reservation_handle": claim._reservation_handle,
        "role_closure_sha256": claim.role_closure_sha256,
        "compiled_policy_sha256": claim.compiled_policy_sha256,
        "compiled_artifact_catalog_sha256": claim.compiled_artifact_catalog_sha256,
        "compiled_selection_sha256": claim.compiled_selection_sha256,
        "selection_catalog_sha256": claim.selection_catalog_sha256,
        "authority_core_sha256": claim.authority_core_sha256,
        "authority_core_size_bytes": claim.authority_core_size_bytes,
        "authority_core_schema": claim.authority_core_schema,
        "native_profile_home_crosswalk": {
            "schema": claim.native_profile_home_crosswalk_schema,
            "relative_path": _NATIVE_PROFILE_HOME_CROSSWALK_PATH,
            "sha256": claim.native_profile_home_crosswalk_sha256,
            "size_bytes": claim.native_profile_home_crosswalk_size_bytes,
        },
        "observed_root_receipt_handle": claim.observed_root_receipt_handle,
        "plan_artifact_id": claim.plan_artifact_id,
        "release_commit": claim.release_commit,
        "source_receipt_handles": list(claim.source_receipt_handles),
        "choice_adoptions": [_choice_projection_record(row) for row in claim.choice_adoptions],
        "issued_monotonic": claim.issued_monotonic,
        "expires_monotonic": claim.expires_monotonic,
    }


def _choice_projection_record(row: "ActiveSetupChoiceProjection") -> dict[str, Any]:
    return {
        "selection_handle": row.selection_handle,
        "purpose": row.purpose,
        "key_id": row.key_id,
        "signed_record_sha256": row.signed_record_sha256,
        "choice_payload_sha256": row.choice_payload_sha256,
        "choice_epoch": row.choice_epoch,
        "revocation_epoch": row.revocation_epoch,
        "issued_at_unix": row.issued_at_unix,
        "setup_deadline_unix": row.setup_deadline_unix,
        "release_deployment_receipt_sha256": row.release_deployment_receipt_sha256,
        "setup_session_handle": row.setup_session_handle,
        "transaction_handle": row.transaction_handle,
        "plan_id": row.plan_id,
        "prepared_generation": row.prepared_generation,
        "principal_selection_handle": row.principal_selection_handle,
        "namespace_selection_handle": row.namespace_selection_handle,
        "private_profile_selection_handle": row.private_profile_selection_handle,
        "source_member_receipt_handles": list(row.source_member_receipt_handles),
        "principal_id": row.principal_id,
        "profile_id": row.profile_id,
        "namespace_id": row.namespace_id,
        "principal_binding_sha256": row.principal_binding_sha256,
        "namespace_binding_sha256": row.namespace_binding_sha256,
        "service_generation_id": row.service_generation_id,
        "service_generation_digest": row.service_generation_digest,
        "selection_catalog_sha256": row.selection_catalog_sha256,
    }


@dataclass(frozen=True, slots=True, repr=False)
class ActiveSetupChoiceProjection:
    """Typed source projection for one root-signed setup choice.

    This contains no choice payload or runtime authority. Its private seal ties
    the normalized projection to the exact active compiler claim.
    """

    selection_handle: str
    purpose: str
    key_id: str
    signed_record_sha256: str
    choice_payload_sha256: str
    choice_epoch: int
    revocation_epoch: int
    issued_at_unix: float
    setup_deadline_unix: float
    release_deployment_receipt_sha256: str
    setup_session_handle: str
    transaction_handle: str
    plan_id: str
    prepared_generation: str
    principal_selection_handle: str
    namespace_selection_handle: str
    private_profile_selection_handle: str | None
    source_member_receipt_handles: tuple[str, ...]
    principal_id: str
    profile_id: str
    namespace_id: str
    principal_binding_sha256: str
    namespace_binding_sha256: str
    service_generation_id: str
    service_generation_digest: str
    selection_catalog_sha256: str
    _compiler_seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootActivePolicyPrecompile:
    """Compiler-retained capability for one genuine precompile reservation."""

    schema: int
    publication_handle: str
    reservation_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_digest: str
    prepared_generation_id: str
    assembly_selection_handle: str
    assembly_selection_sha256: str
    receipt_ids: tuple[str, ...]
    output_closure_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _root_setup_session: Any = field(repr=False, compare=False)
    _root_prepared_native_bundle: Any = field(repr=False, compare=False)
    _root_reservation: Any = field(repr=False, compare=False)
    _root_role_closure: Any = field(repr=False, compare=False)
    _compiler_seal: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootActivePolicyPrecompile(<root-private>)"


def _validate_claim_output_hashes(claim: "RootActivePolicyCompilationClaim") -> None:
    if (type(claim.schema) is not int or claim.schema != 2
            or not isinstance(claim.policy_bytes, bytes) or _sha(claim.policy_bytes) != claim.compiled_policy_sha256
            or not isinstance(claim.artifact_catalog_bytes, bytes)
            or _sha(claim.artifact_catalog_bytes) != claim.compiled_artifact_catalog_sha256
            or not isinstance(claim.authority_core_bytes, bytes)
            or not claim.authority_core_bytes
            or _sha(claim.authority_core_bytes) != claim.authority_core_sha256
            or len(claim.authority_core_bytes) != claim.authority_core_size_bytes
            or type(claim.authority_core_schema) is not int
            or claim.authority_core_schema != 1
            or _canonical(_parse_canonical_object(claim.authority_core_bytes, "authority core"))
               != claim.authority_core_bytes
            or not isinstance(claim.native_profile_home_crosswalk_bytes, bytes)
            or not claim.native_profile_home_crosswalk_bytes
            or _sha(claim.native_profile_home_crosswalk_bytes)
               != claim.native_profile_home_crosswalk_sha256
            or len(claim.native_profile_home_crosswalk_bytes)
               != claim.native_profile_home_crosswalk_size_bytes
            or type(claim.native_profile_home_crosswalk_schema) is not int
            or claim.native_profile_home_crosswalk_schema != 1
            or _canonical(_parse_canonical_object(
                claim.native_profile_home_crosswalk_bytes, "native profile-home crosswalk"))
               != claim.native_profile_home_crosswalk_bytes
            or not isinstance(claim.selection_document, Mapping)
            or not isinstance(claim.source_receipt_handles, tuple)
            or _ordered_unique_receipt_handles(claim.source_receipt_handles, "active claim")
            != claim.source_receipt_handles
            or not isinstance(claim.role_closure_sha256, str)
            or not _HEX.fullmatch(claim.role_closure_sha256)
            or not isinstance(claim.principal_identity_kind, str)
            or claim.principal_identity_kind not in {"authentik-subject-v1", "linux-local-owner-v1"}
            or not isinstance(claim.principal_binding_sha256, str)
            or not _HEX.fullmatch(claim.principal_binding_sha256)
            or not isinstance(claim.namespace_selection_handle, str)
            or not _HANDLE.fullmatch(claim.namespace_selection_handle)
            or not isinstance(claim.namespace_binding_sha256, str)
            or not _HEX.fullmatch(claim.namespace_binding_sha256)
            or not isinstance(claim._reservation_handle, str)
            or not _HANDLE.fullmatch(claim._reservation_handle)
            or not set(claim.runtime_receipt_handles).issubset(claim.source_receipt_handles)
            or not set(claim.materialization_receipt_handles).issubset(claim.source_receipt_handles)
            or claim.principal_selection_receipt_handle not in claim.source_receipt_handles
            or claim.namespace_selection_handle not in claim.source_receipt_handles):
        raise BootstrapEnrollmentPending("active policy claim output bytes changed")
    from .setup_policy_publication import _parse_native_profile_home_crosswalk
    _parse_native_profile_home_crosswalk(claim.native_profile_home_crosswalk_bytes)
    document = dict(claim.selection_document)
    catalog_digest = document.get("catalog_sha256")
    unsigned = {key: value for key, value in document.items() if key != "catalog_sha256"}
    if (not isinstance(catalog_digest, str) or catalog_digest != claim.selection_catalog_sha256
            or not _HEX.fullmatch(catalog_digest)
            or _sha(_canonical(unsigned)) != catalog_digest
            or _sha(_canonical(document)) != claim.compiled_selection_sha256):
        raise BootstrapEnrollmentPending("active policy selection output hashes changed")


@dataclass(frozen=True, slots=True, repr=False)
class RootActivePolicyCompilationClaim:
    """Sealed output DTO consumed only by the active policy publisher."""

    schema: int
    plan_artifact_id: str
    release_commit: str
    publication_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    expected_selection_catalog_sha256: str | None
    expected_service_generation_digest: str
    policy_template_artifact_id: str
    policy_template_sha256: str
    principal_selection_receipt_handle: str
    principal_identity_kind: str
    principal_binding_sha256: str
    namespace_selection_handle: str
    namespace_binding_sha256: str
    runtime_receipt_handles: tuple[str, ...]
    materialization_receipt_handles: tuple[str, ...]
    source_receipt_handles: tuple[str, ...]
    compiled_policy_sha256: str
    compiled_artifact_catalog_sha256: str
    compiled_selection_sha256: str
    selection_catalog_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    claim_digest: str
    policy_bytes: bytes
    artifact_catalog_bytes: bytes
    selection_document: Mapping[str, Any]
    observed_root_receipt_handle: str
    _root_journal_root: Path = field(repr=False, compare=False)
    _root_setup_session: Any = field(repr=False, compare=False)
    _reservation_handle: str = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)
    _root_prepared_native_bundle: Any = field(default=None, repr=False, compare=False)
    choice_adoptions: tuple[ActiveSetupChoiceProjection, ...] = ()
    role_closure_sha256: str = ""
    owner_overlay_adoptions: tuple[Any, ...] = ()
    authority_core_bytes: bytes = b""
    authority_core_sha256: str = ""
    authority_core_size_bytes: int = 0
    authority_core_schema: int = 1
    native_profile_home_crosswalk_bytes: bytes = b""
    native_profile_home_crosswalk_sha256: str = ""
    native_profile_home_crosswalk_size_bytes: int = 0
    native_profile_home_crosswalk_schema: int = 1


class RootActivePolicyTemplateResolver:
    """Typed join of the installed strict policy resolver and principal issuer."""

    def __init__(self, policy_resolver: Any, principal_registry: Any):
        from .bootstrap_runtime_factory import InstalledBootstrapPolicyResolver
        from .setup_principal import (RootSetupLocalOwnerIdentityRegistry,
                                      RootSetupPrincipalSelectionRegistry)
        if (not isinstance(policy_resolver, InstalledBootstrapPolicyResolver)
                or type(principal_registry) not in {
                    RootSetupPrincipalSelectionRegistry,
                    RootSetupLocalOwnerIdentityRegistry,
                }):
            raise ValueError("active policy templates require the installed resolver and principal registry")
        if isinstance(principal_registry, RootSetupLocalOwnerIdentityRegistry):
            # This property is intentionally unavailable until a genuine normal
            # publication adoption has been revalidated, including its current
            # local owner and namespace/prepared-generation joins.
            from .bootstrap_enrollment import RootSetupSessionStore
            if not isinstance(principal_registry.setup_session_store, RootSetupSessionStore):
                raise ValueError("local-owner active policy requires an adopted normal root session")
        self.policy_resolver = policy_resolver
        self.principal_registry = principal_registry


class RootActivePolicyCompilationRegistry:
    """Compile and hold one active-policy publication for a live prepared session.

    The first dependency is the concrete installed root runtime factory rather
    than the lower-level session store: only the factory retains the typed
    ``RootBootstrapSession`` facade and can resolve its live PIDFD-backed
    handle. Its ``session_store`` is checked by identity and is used for the
    primitive journal/proof operations.
    """

    def __init__(self, setup_runtime_factory: Any, verified_policy_template_resolver: Any,
                 runtime_receipt_registry: Any, materialization_receipt_registry: Any,
                 root_journal: Path):
        from .bootstrap_runtime_factory import RootBootstrapRuntimeFactory
        from .setup_principal import (RootSetupLocalOwnerIdentityRegistry,
                                      RootSetupPrincipalSelectionRegistry)
        from .native_output_receipts import RootMaterializationReceiptRegistry
        from .pm_runtime import RootPMRuntimeReceiptRegistry
        if (not isinstance(setup_runtime_factory, RootBootstrapRuntimeFactory)
                or not isinstance(root_journal, Path) or root_journal != _JOURNAL
                or setup_runtime_factory.session_store is None
                or not isinstance(verified_policy_template_resolver, RootActivePolicyTemplateResolver)
                or verified_policy_template_resolver.policy_resolver is not setup_runtime_factory.resolver
                or not isinstance(runtime_receipt_registry, RootPMRuntimeReceiptRegistry)
                or not isinstance(materialization_receipt_registry, RootMaterializationReceiptRegistry)):
            raise ValueError("active compiler requires the concrete root runtime, selected policy, PM and output registries")
        principal_registry = verified_policy_template_resolver.principal_registry
        if type(principal_registry) not in {
                RootSetupPrincipalSelectionRegistry, RootSetupLocalOwnerIdentityRegistry}:
            raise ValueError("active compiler requires a concrete tagged root principal registry")
        if (principal_registry.setup_session_store is not setup_runtime_factory.session_store
                or principal_registry.root_journal != root_journal):
            raise ValueError("active compiler principal registry is outside this root setup custody")
        if (getattr(runtime_receipt_registry, "setup_session", None) is not None
                and runtime_receipt_registry.setup_session._factory is not setup_runtime_factory):
            raise ValueError("PM receipt registry belongs to another live root setup factory")
        if getattr(materialization_receipt_registry, "_journal_root", root_journal) != root_journal:
            raise ValueError("native output receipts belong to another authority journal")
        self.factory = setup_runtime_factory
        self.sessions = setup_runtime_factory.session_store
        self.resolver = verified_policy_template_resolver.policy_resolver
        self.template_resolver = verified_policy_template_resolver
        self.runtime_receipts = runtime_receipt_registry
        self.materialization_receipts = materialization_receipt_registry
        self.principal_registry = principal_registry
        self.root_journal = root_journal
        self._claim_root = root_journal / _CLAIM_DIR
        self._seal = object()
        self._claims: dict[str, RootActivePolicyCompilationClaim] = {}
        self._states: dict[str, str] = {}
        self._locks: dict[str, int] = {}
        self._precompile_caps: dict[str, RootActivePolicyPrecompile] = {}
        self._precompile_reservations: dict[tuple[str, str], Any] = {}
        self._native_claims: dict[str, Any] = {}

    @classmethod
    def from_root_setup(cls, setup_runtime_factory: Any,
                        verified_policy_template_resolver: Any,
                        runtime_receipt_registry: Any,
                        materialization_receipt_registry: Any,
                        root_journal: Path) -> "RootActivePolicyCompilationRegistry":
        return cls(setup_runtime_factory, verified_policy_template_resolver,
                   runtime_receipt_registry, materialization_receipt_registry,
                   root_journal)

    def begin_active_policy_precompile(
            self, setup_session_handle: RootSetupSessionHandle,
            prepared_bundle: Any) -> RootActivePolicyPrecompile:
        """Reserve selected native CAS outputs before compiling active documents.

        The factory supplies the current native assembly and its five genuine
        output receipts from the retained prepared bundle. This registry then
        allocates its publication handle, reserves those receipts, and asks the
        factory to derive and retain the matching runnable-role projection.
        """
        self._require_root()
        session = self.factory.resolve_live_session(setup_session_handle)
        prepared = self._verify_prepared_native_bundle(session, prepared_bundle)
        output_binding = getattr(self.materialization_receipts, "_binding", None)
        if getattr(output_binding, "_session", None) is not session:
            raise BootstrapEnrollmentPending("native output registry is not bound to this exact live setup session")
        session._refresh_authorization()
        binding = session.selected_installation
        assembly_selection = binding.resolve_current_native_bootstrap_assembly_for_bundle(prepared_bundle)
        from .bootstrap_runtime_factory import RootNativeBootstrapAssemblySelection
        if type(assembly_selection) is not RootNativeBootstrapAssemblySelection:
            raise BootstrapEnrollmentPending("factory returned no typed current root native assembly selection")
        current_assembly = binding.resolve_current_native_bootstrap_assembly(
            assembly_selection.selection_handle)
        if current_assembly is not assembly_selection:
            raise BootstrapEnrollmentPending("native assembly selection is not the current retained root selection")
        if (assembly_selection.setup_session_id != setup_session_handle.session_id
                or assembly_selection.transaction_handle != session._authorization.transaction_handle
                or assembly_selection.plan_digest != session._authorization.plan_digest
                or assembly_selection.prepared_generation_id != prepared.generation_id
                or assembly_selection.pm_runtime_receipt_handle != prepared_bundle.pm_runtime_receipt_handle
                or assembly_selection.materialization_receipt_handle != prepared_bundle.materialization_receipt_handle):
            raise BootstrapEnrollmentPending("native assembly selection does not join the current prepared bundle")
        assembly_key = (setup_session_handle.session_id, assembly_selection.selection_handle)
        retained = [cap for cap in self._precompile_caps.values()
                    if (cap.setup_session_id, cap.assembly_selection_handle) == assembly_key]
        if retained:
            if (len(retained) != 1
                    or retained[0]._root_prepared_native_bundle is not prepared_bundle):
                raise BootstrapEnrollmentPending("this setup assembly already has another retained precompile")
            return self.verify_current_precompile_capability(retained[0])
        reservation = self._precompile_reservations.get(assembly_key)
        if reservation is None:
            selected_outputs = binding.compile_selected_native_package(prepared_bundle)
            if not isinstance(selected_outputs, tuple) or len(selected_outputs) != 5:
                raise BootstrapEnrollmentPending("factory did not produce the exact five selected native output receipts")
            output_handles = tuple(sorted(self._handles(
                tuple(getattr(row, "receipt_id", None) for row in selected_outputs),
                "native output receipt")))
            if len(output_handles) != 5:
                raise BootstrapEnrollmentPending("precompile requires the complete five-role native output receipt set")
            publication_handle = secrets.token_urlsafe(36)
            reservation = self.materialization_receipts.reserve_for_precompile(
                assembly_selection.selection_handle, output_handles, publication_handle)
            # Retain the durable reservation immediately. If the following
            # role projection is interrupted, a same-session retry resumes
            # this reservation instead of reserving or consuming another set.
            self._precompile_reservations[assembly_key] = reservation
        else:
            reservation = self.materialization_receipts.resolve_current_precompile_reservation(
                reservation.reservation_handle)
        current_reservation = self.materialization_receipts.resolve_current_precompile_reservation(
            reservation.reservation_handle)
        if (type(current_reservation) is not type(reservation)
                or current_reservation != reservation
                or reservation.setup_session_id != setup_session_handle.session_id
                or reservation.transaction_handle != session._authorization.transaction_handle
                or reservation.plan_digest != session._authorization.plan_digest
                or reservation.prepared_generation_id != prepared.generation_id
                or reservation.assembly_selection_handle != assembly_selection.selection_handle
                or reservation.receipt_ids != self._handles(reservation.receipt_ids, "reserved native output")):
            raise BootstrapEnrollmentPending("native precompile reservation differs from its current root selection")
        projection_registry = binding.resolve_current_runnable_role_projection_registry()
        closure = projection_registry.resolve_selected_runnable_roles(
            prepared_bundle.pm_runtime_receipt_handle, reservation.reservation_handle)
        closure = projection_registry.verify_current(closure)
        self._validate_runnable_role_closure(closure, reservation, session, prepared)
        now = time.monotonic()
        live = self.sessions._live(setup_session_handle)
        expires = min(reservation.expires_monotonic, closure.expires_monotonic,
                      float(live.expires_monotonic), now + 120.0)
        if expires <= now:
            raise BootstrapEnrollmentPending("precompile capability lease expired")
        capability = RootActivePolicyPrecompile(
            schema=1, publication_handle=reservation.publication_handle,
            reservation_handle=reservation.reservation_handle,
            setup_session_id=reservation.setup_session_id,
            transaction_handle=reservation.transaction_handle,
            plan_digest=reservation.plan_digest,
            prepared_generation_id=reservation.prepared_generation_id,
            assembly_selection_handle=reservation.assembly_selection_handle,
            assembly_selection_sha256=reservation.assembly_selection_sha256,
            receipt_ids=reservation.receipt_ids,
            output_closure_sha256=reservation.output_closure_sha256,
            issued_monotonic=now, expires_monotonic=expires,
            _root_setup_session=session, _root_prepared_native_bundle=prepared_bundle,
            _root_reservation=reservation, _root_role_closure=closure,
            _compiler_seal=self._seal)
        existing = self._precompile_caps.get(capability.reservation_handle)
        if existing is not None:
            raise BootstrapEnrollmentPending("native precompile reservation was already retained")
        self._precompile_caps[capability.reservation_handle] = capability
        return capability

    def verify_current_precompile_capability(
            self, capability: RootActivePolicyPrecompile) -> RootActivePolicyPrecompile:
        from .native_output_receipts import RootNativePrecompileOutputReservation
        if (type(capability) is not RootActivePolicyPrecompile
                or capability._compiler_seal is not self._seal
                or self._precompile_caps.get(capability.reservation_handle) is not capability
                or capability.expires_monotonic <= time.monotonic()
                or capability.issued_monotonic > time.monotonic()):
            raise BootstrapEnrollmentPending("active precompile capability is stale, altered, or unsealed")
        session = self.factory.resolve_live_session(capability._root_setup_session._handle)
        if session is not capability._root_setup_session:
            raise BootstrapEnrollmentPending("precompile capability belongs to another live setup session")
        session._refresh_authorization()
        prepared = self._verify_prepared_native_bundle(session, capability._root_prepared_native_bundle)
        reservation = self.materialization_receipts.resolve_current_precompile_reservation(
            capability.reservation_handle)
        reservation_key = (capability.setup_session_id, capability.assembly_selection_handle)
        if (type(reservation) is not RootNativePrecompileOutputReservation
                or self._precompile_reservations.get(reservation_key) != capability._root_reservation
                or reservation != capability._root_reservation
                or reservation.publication_handle != capability.publication_handle
                or reservation.setup_session_id != capability.setup_session_id
                or reservation.transaction_handle != capability.transaction_handle
                or reservation.plan_digest != capability.plan_digest
                or reservation.prepared_generation_id != capability.prepared_generation_id
                or reservation.assembly_selection_handle != capability.assembly_selection_handle
                or reservation.assembly_selection_sha256 != capability.assembly_selection_sha256
                or reservation.receipt_ids != capability.receipt_ids
                or reservation.output_closure_sha256 != capability.output_closure_sha256
                or prepared.generation_id != capability.prepared_generation_id):
            raise BootstrapEnrollmentPending("precompile reservation no longer matches the retained root capability")
        binding = session.selected_installation
        projection_registry = binding.resolve_current_runnable_role_projection_registry()
        closure = projection_registry.verify_current(capability._root_role_closure)
        self._validate_runnable_role_closure(closure, reservation, session, prepared)
        return capability

    @staticmethod
    def _validate_runnable_role_closure(closure: Any, reservation: Any,
                                        session: Any, prepared: EnrollmentReceipt) -> None:
        from .bootstrap_runtime_factory import RootSelectedRunnableRoleClosure
        expected = {"official-pm-runtime", "native-compiled-closure",
                    "native-entrypoint-manifest", "native-action-resolver",
                    "native-candidate-index", "native-boundary-overlay"}
        if (type(closure) is not RootSelectedRunnableRoleClosure
                or closure.setup_session_id != session._handle.session_id
                or closure.transaction_handle != session._authorization.transaction_handle
                or closure.plan_digest != session._authorization.plan_digest
                or closure.prepared_generation_id != prepared.generation_id
                or closure.pm_runtime_receipt_handle is None
                or closure.pm_runtime_receipt_handle != getattr(session, "_pm_runtime_handle", None)
                or closure.native_output_claim_handle != reservation.reservation_handle
                or not isinstance(closure.role_rows, tuple)
                or len(closure.role_rows) != len(expected)):
            raise BootstrapEnrollmentPending("precompile role closure does not join current session and reservation")
        by_role: dict[str, Any] = {}
        for row in closure.role_rows:
            if getattr(row, "role", None) in by_role:
                raise BootstrapEnrollmentPending("precompile role closure duplicates a runtime role")
            by_role[getattr(row, "role", "")] = row
        if set(by_role) != expected:
            raise BootstrapEnrollmentPending("precompile role closure has missing or unexpected runtime roles")
        native_rows = [row for role, row in by_role.items() if role != "official-pm-runtime"]
        if {row.receipt_handle for row in native_rows} != set(reservation.receipt_ids):
            raise BootstrapEnrollmentPending("precompile role rows do not bind the exact reserved output receipts")
        if any(row.receipt_kind != "native-output-cas" for row in native_rows):
            raise BootstrapEnrollmentPending("native role closure contains another receipt kind")
        pm_row = by_role["official-pm-runtime"]
        if (pm_row.receipt_kind != "pm-runtime"
                or pm_row.receipt_handle != closure.pm_runtime_receipt_handle
                or pm_row.output_kind != "pm-runtime"):
            raise BootstrapEnrollmentPending("PM role row differs from its exact selected runtime receipt")
        expected_kinds = {
            "native-compiled-closure": "compiled-closure",
            "native-entrypoint-manifest": "entrypoint-json",
            "native-action-resolver": "resolver-json",
            "native-boundary-overlay": "boundary-overlay",
            "native-candidate-index": "candidate-index-json",
        }
        for role, kind in expected_kinds.items():
            row = by_role[role]
            if (row.output_kind != kind or not isinstance(row.artifact_id, str)
                    or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", row.artifact_id)
                    or not isinstance(row.sha256, str) or not _HEX.fullmatch(row.sha256)
                    or type(row.size_bytes) is not int or row.size_bytes <= 0
                    or not isinstance(row.source_receipt_handles, tuple)
                    or _ordered_unique_receipt_handles(row.source_receipt_handles, "role source")
                       != row.source_receipt_handles):
                raise BootstrapEnrollmentPending("native role row is malformed or has the wrong output kind")
        row_data = [{
            "role": row.role, "receipt_kind": row.receipt_kind,
            "receipt_handle": row.receipt_handle, "artifact_id": row.artifact_id,
            "sha256": row.sha256, "size_bytes": row.size_bytes,
            "output_kind": row.output_kind,
            "source_receipt_handles": list(row.source_receipt_handles),
        } for row in closure.role_rows]
        if (not isinstance(closure.role_closure_sha256, str)
                or not _HEX.fullmatch(closure.role_closure_sha256)
                or _sha(_canonical(row_data)) != closure.role_closure_sha256):
            raise BootstrapEnrollmentPending("runnable role closure digest differs from its exact rows")

    def compile_active_policy(
            self, setup_session_handle: RootSetupSessionHandle,
            prepared_bundle: Any,
            precompile: RootActivePolicyPrecompile | None = None) -> str:
        self._require_root()
        if precompile is None:
            precompile = self.begin_active_policy_precompile(
                setup_session_handle, prepared_bundle)
        capability = self.verify_current_precompile_capability(precompile)
        session = capability._root_setup_session
        if setup_session_handle is not session._handle:
            raise BootstrapEnrollmentPending("active compilation handle differs from the retained setup session")
        prepared = self._verify_prepared_native_bundle(session, prepared_bundle)
        if prepared_bundle is not capability._root_prepared_native_bundle:
            raise BootstrapEnrollmentPending("active compile bundle differs from the retained precompile capability")
        if getattr(self.runtime_receipts, "setup_session", None) is not session:
            raise BootstrapEnrollmentPending("PM runtime registry is not bound to this exact live setup session")
        closure = capability._root_role_closure
        runtime_handles = (closure.pm_runtime_receipt_handle,)
        output_handles = capability.receipt_ids
        resolved_runtime = tuple(self.runtime_receipts.resolve_runtime(
            handle, session._authorization.transaction_handle, prepared.generation_id)
            for handle in runtime_handles)
        if any(not self._runtime_joins(item, session, prepared) for item in resolved_runtime):
            raise BootstrapEnrollmentPending("PM runtime receipt does not match the current prepared session")

        principal = self._resolve_current_principal(session)
        identity_binding, namespace_selector, namespace_binding, identity_sources = \
            self._resolve_principal_publication_binding(session, principal)
        principal_handle = getattr(principal, "receipt_id", None)
        if not isinstance(principal_handle, str) or not re.fullmatch(r"[0-9a-f]{64}", principal_handle):
            raise BootstrapEnrollmentPending("adopted principal registry returned an invalid root receipt")
        policy_bytes, catalog_bytes, selection_document, selection_digest = self._compile_documents(
            session, closure)
        reservation = self.materialization_receipts.resolve_current_precompile_reservation(
            capability.reservation_handle)
        from .bootstrap_runtime_factory import RootPreparedNativeProfileHomeSourceSet
        home_sources = session.resolve_prepared_native_profile_home_sources(reservation)
        if type(home_sources) is not RootPreparedNativeProfileHomeSourceSet:
            raise BootstrapEnrollmentPending("root setup did not issue typed Jarvis profile-home inputs")
        home_sources.verify_current()
        crosswalk_bytes = home_sources.public_member_bytes()
        if (not isinstance(crosswalk_bytes, bytes)
                or _sha(crosswalk_bytes) != home_sources.member_sha256
                or home_sources.precompile_output_closure_sha256 != reservation.output_closure_sha256):
            raise BootstrapEnrollmentPending("Jarvis home inputs differ from their current precompile reservation")
        from .setup_policy_publication import _parse_native_profile_home_crosswalk
        _parse_native_profile_home_crosswalk(crosswalk_bytes)
        crosswalk_sha256 = _sha(crosswalk_bytes)
        choice_adoptions = self._compile_choice_adoptions(
            session, prepared, selection_document["catalog_sha256"])
        from .owner_overlay_publication import collect_owner_overlay_adoptions
        owner_overlay_adoptions = collect_owner_overlay_adoptions(
            session, prepared_bundle, principal, choice_adoptions,
            self.materialization_receipts, reservation, closure)
        if (principal.identity_kind == "linux-local-owner-v1"
                and principal.selected_capability_ceiling
                and not owner_overlay_adoptions):
            raise BootstrapEnrollmentPending(
                "selected local-owner overlay capabilities have no current publication adoption")
        issued = time.monotonic()
        live = self.sessions._live(setup_session_handle)
        expires = min(issued + 120.0, float(live.expires_monotonic), capability.expires_monotonic)
        if expires <= issued:
            raise BootstrapEnrollmentPending("active policy compilation lease expired")
        publication_handle = capability.publication_handle
        observed_handle = self._mint_actor_observation(session, prepared, expires)
        source_receipt_handles = _ordered_unique_receipt_handles((
            prepared_bundle.hermes_source_receipt_handle,
            prepared_bundle.pm_runtime_receipt_handle,
            prepared_bundle.resources_source_receipt_handle,
            prepared_bundle.resource_profile_selection_receipt_handle,
            prepared_bundle.materialization_receipt_handle,
            *runtime_handles, *output_handles, principal_handle,
            *identity_sources, namespace_selector,
            *(handle for role_row in closure.role_rows
              for handle in role_row.source_receipt_handles),
            *(handle for row in choice_adoptions
              for handle in row.source_member_receipt_handles),
            *_owner_overlay_adoption_source_handles(owner_overlay_adoptions)),
            "active source")
        provisional = RootActivePolicyCompilationClaim(
            schema=2, plan_artifact_id=session._authorization.plan_artifact_id,
            release_commit=session._factory._release.release_commit,
            publication_handle=publication_handle, setup_session_id=setup_session_handle.session_id,
            transaction_handle=session._authorization.transaction_handle,
            plan_sha256=session._authorization.plan_digest,
            prepared_generation_id=prepared.generation_id,
            expected_selection_catalog_sha256=selection_digest,
            expected_service_generation_digest=prepared.generation_digest,
            policy_template_artifact_id=session._policy.artifact_id,
            policy_template_sha256=session._policy.sha256,
            principal_selection_receipt_handle=principal_handle,
            principal_identity_kind=principal.identity_kind,
            principal_binding_sha256=identity_binding,
            namespace_selection_handle=namespace_selector,
            namespace_binding_sha256=namespace_binding,
            runtime_receipt_handles=runtime_handles,
            materialization_receipt_handles=output_handles,
            source_receipt_handles=source_receipt_handles,
            compiled_policy_sha256=_sha(policy_bytes),
            compiled_artifact_catalog_sha256=_sha(catalog_bytes),
            compiled_selection_sha256=_sha(_canonical(dict(selection_document))),
            selection_catalog_sha256=selection_document["catalog_sha256"],
            issued_monotonic=issued, expires_monotonic=expires,
            claim_digest="0" * 64, policy_bytes=policy_bytes,
            artifact_catalog_bytes=catalog_bytes, selection_document=selection_document,
            observed_root_receipt_handle=observed_handle,
            _root_journal_root=self.root_journal, _root_setup_session=session,
            _reservation_handle=capability.reservation_handle, _seal=self._seal,
            _root_prepared_native_bundle=prepared_bundle,
            choice_adoptions=choice_adoptions,
            role_closure_sha256=closure.role_closure_sha256,
            owner_overlay_adoptions=owner_overlay_adoptions,
            native_profile_home_crosswalk_bytes=crosswalk_bytes,
            native_profile_home_crosswalk_sha256=crosswalk_sha256,
            native_profile_home_crosswalk_size_bytes=len(crosswalk_bytes),
            native_profile_home_crosswalk_schema=1,
        )
        claim_digest = _sha(_canonical(_manifest(provisional)))
        claim = RootActivePolicyCompilationClaim(
            schema=provisional.schema, plan_artifact_id=provisional.plan_artifact_id,
            release_commit=provisional.release_commit,
            publication_handle=provisional.publication_handle,
            setup_session_id=provisional.setup_session_id,
            transaction_handle=provisional.transaction_handle, plan_sha256=provisional.plan_sha256,
            prepared_generation_id=provisional.prepared_generation_id,
            expected_selection_catalog_sha256=provisional.expected_selection_catalog_sha256,
            expected_service_generation_digest=provisional.expected_service_generation_digest,
            policy_template_artifact_id=provisional.policy_template_artifact_id,
            policy_template_sha256=provisional.policy_template_sha256,
            principal_selection_receipt_handle=provisional.principal_selection_receipt_handle,
            principal_identity_kind=provisional.principal_identity_kind,
            principal_binding_sha256=provisional.principal_binding_sha256,
            namespace_selection_handle=provisional.namespace_selection_handle,
            namespace_binding_sha256=provisional.namespace_binding_sha256,
            runtime_receipt_handles=provisional.runtime_receipt_handles,
            materialization_receipt_handles=provisional.materialization_receipt_handles,
            source_receipt_handles=provisional.source_receipt_handles,
            compiled_policy_sha256=provisional.compiled_policy_sha256,
            compiled_artifact_catalog_sha256=provisional.compiled_artifact_catalog_sha256,
            compiled_selection_sha256=provisional.compiled_selection_sha256,
            selection_catalog_sha256=provisional.selection_catalog_sha256,
            issued_monotonic=provisional.issued_monotonic,
            expires_monotonic=provisional.expires_monotonic, claim_digest=claim_digest,
            policy_bytes=provisional.policy_bytes,
            artifact_catalog_bytes=provisional.artifact_catalog_bytes,
            selection_document=provisional.selection_document,
            observed_root_receipt_handle=provisional.observed_root_receipt_handle,
            _root_journal_root=provisional._root_journal_root,
            _root_setup_session=provisional._root_setup_session,
            _reservation_handle=capability.reservation_handle, _seal=self._seal,
            _root_prepared_native_bundle=provisional._root_prepared_native_bundle,
            choice_adoptions=provisional.choice_adoptions,
            role_closure_sha256=provisional.role_closure_sha256,
            owner_overlay_adoptions=provisional.owner_overlay_adoptions,
            native_profile_home_crosswalk_bytes=provisional.native_profile_home_crosswalk_bytes,
            native_profile_home_crosswalk_sha256=provisional.native_profile_home_crosswalk_sha256,
            native_profile_home_crosswalk_size_bytes=provisional.native_profile_home_crosswalk_size_bytes,
            native_profile_home_crosswalk_schema=provisional.native_profile_home_crosswalk_schema,
        )
        # Fail before claim journaling or native-output binding if the actual
        # selected-role authority producer is unavailable. Do not reserve a
        # consumable active claim around schema-only or guessed core bytes.
        _validate_claim_output_hashes(claim)
        home_sources.verify_current()
        # Durable claim record reserves the transaction before the publisher can
        # create any generation. Same-transaction replay remains denied until
        # explicit release or committed active state.
        lock_fd = -1
        state_path = self._claim_root / ("transaction-" + session._authorization.transaction_handle + ".json")
        durable = False
        try:
            _ensure_private_directory(self._claim_root)
            lock_path = self._claim_root / ("transaction-" + session._authorization.transaction_handle + ".lock")
            lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.fchown(lock_fd, 0, 0)
            os.fchmod(lock_fd, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if state_path.exists():
                state = _read_json(state_path)
                if state.get("state") not in {"released"}:
                    raise BootstrapEnrollmentPending("prepared transaction already has an active policy claim")
            self._persist_claim_bundle(claim)
            record = self._claim_record(claim, "claimed")
            _write_json(state_path, record)
            durable = True
            self._claims[publication_handle] = claim
            self._states[publication_handle] = "claimed"
            self._locks[publication_handle] = lock_fd
            lock_fd = -1
            output_claim = self.materialization_receipts.bind_compiled_policy_claim(
                capability.reservation_handle, publication_handle)
            from .native_output_receipts import RootNativeOutputClaim
            if (type(output_claim) is not RootNativeOutputClaim
                    or output_claim.compiled_active_policy_handle != publication_handle
                    or output_claim.claim_digest != claim.claim_digest
                    or output_claim.reservation.reservation_handle != capability.reservation_handle
                    or output_claim.reservation.receipt_ids != claim.materialization_receipt_handles):
                raise BootstrapEnrollmentPending("native output registry bound another compiled claim")
            self._native_claims[publication_handle] = output_claim
            self.verify_current_active_policy_claim(claim)
            return publication_handle
        except Exception:
            if durable:
                # A binding call may have committed before an interruption. Keep
                # the immutable claim and reservation for same-handle retry.
                raise
            # If persistence failed after some immutable files were written,
            # retain the precompile reservation; it is never released or
            # reconstructed from caller metadata on a failed compile.
            try:
                for suffix in (".policy", ".catalog", ".selection", ".authority",
                               ".native-profile-home-crosswalk", ".claim.json"):
                    path = self._claim_root / (publication_handle + suffix)
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
                if self._claim_root.exists():
                    directory = os.open(self._claim_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
            except Exception:
                pass
            raise
        finally:
            if lock_fd >= 0:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

    def claim_active_policy(self, publication_handle: str,
                            expected_selection_catalog_sha256: str | None = None
                            ) -> RootActivePolicyCompilationClaim:
        claim = self._get_claim(publication_handle)
        if expected_selection_catalog_sha256 != claim.expected_selection_catalog_sha256:
            raise BootstrapEnrollmentPending("active policy predecessor does not match the sealed claim")
        self.verify_current_active_policy_claim(claim)
        return claim

    def resolve_current_active_policy_predecessor(self, publication_handle: str) -> str:
        """Return the predecessor only from a fully revalidated retained claim."""
        claim = self._get_claim(publication_handle)
        self.verify_current_active_policy_claim(claim)
        if (not isinstance(claim.expected_selection_catalog_sha256, str)
                or not _HEX.fullmatch(claim.expected_selection_catalog_sha256)):
            raise BootstrapEnrollmentPending("active claim has no canonical predecessor selection digest")
        return claim.expected_selection_catalog_sha256

    def resolve_current_active_policy_claim(self, publication_handle: str) -> RootActivePolicyCompilationClaim:
        """Resolve a sealed current claim for root-owned adjacent projections."""
        claim = self._get_claim(publication_handle)
        return self.verify_current_active_policy_claim(claim)

    def verify_current_active_policy_claim(
            self, claim: RootActivePolicyCompilationClaim) -> RootActivePolicyCompilationClaim:
        if (not isinstance(claim, RootActivePolicyCompilationClaim)
                or claim._seal is not self._seal
                or self._claims.get(claim.publication_handle) is not claim
                or self._states.get(claim.publication_handle) != "claimed"
                or claim.expires_monotonic <= time.monotonic()
                or not secrets.compare_digest(claim.claim_digest, _sha(_canonical(_manifest(claim))))):
            raise BootstrapEnrollmentPending("active policy claim is stale, altered, replayed, or unsealed")
        _validate_claim_output_hashes(claim)
        self._verify_claim_bundle(claim)
        self._verify_choice_projection_seals(claim)
        session = self.factory.resolve_live_session(claim._root_setup_session._handle)
        session._refresh_authorization()
        retained = session._last_receipt
        if retained is None or not isinstance(retained.provision_receipt_handle, str):
            raise BootstrapEnrollmentPending("prepared receipt was lost during active policy compilation")
        prepared = session.resolve_prepared_receipt(retained.provision_receipt_handle)
        self._validate_prepared(session, prepared)
        bundle = claim._root_prepared_native_bundle
        if bundle is None or self._verify_prepared_native_bundle(session, bundle) is not prepared:
            raise BootstrapEnrollmentPending("prepared native bundle changed during active policy publication")
        if (session is not claim._root_setup_session
                or session._handle.session_id != claim.setup_session_id
                or session._authorization.transaction_handle != claim.transaction_handle
                or session._authorization.plan_digest != claim.plan_sha256
                or prepared.generation_id != claim.prepared_generation_id
                or prepared.generation_digest != claim.expected_service_generation_digest):
            raise BootstrapEnrollmentPending("active policy claim no longer matches the live prepared session")
        current = self.resolver._load_selection()
        if current.selection_digest != claim.expected_selection_catalog_sha256:
            raise BootstrapEnrollmentPending("root selection changed during active policy compilation")
        self._verify_claim_principal_join(claim, session)
        for handle in claim.runtime_receipt_handles:
            resolved = self.runtime_receipts.resolve_runtime(
                handle, claim.transaction_handle, claim.prepared_generation_id)
            if not self._runtime_joins(resolved, session, prepared):
                raise BootstrapEnrollmentPending("PM runtime closure changed during active policy compilation")
        if self._native_claims.get(claim.publication_handle) is None:
            capability = self._precompile_caps.get(claim._reservation_handle)
            if (capability is None or capability.publication_handle != claim.publication_handle
                    or capability.receipt_ids != claim.materialization_receipt_handles
                    or capability.output_closure_sha256 == ""):
                raise BootstrapEnrollmentPending("active claim has no same-reservation precompile binding")
            self.verify_current_precompile_capability(capability)
        else:
            outputs = self.materialization_receipts.verify_active_compilation(
                claim._reservation_handle, prepared_generation_id=claim.prepared_generation_id,
                publication_handle=claim.publication_handle, claim_digest=claim.claim_digest)
            if tuple(item.receipt_id for item in outputs) != claim.materialization_receipt_handles:
                raise BootstrapEnrollmentPending("native output closure changed during active policy compilation")
        self._verify_actor_observation(claim.observed_root_receipt_handle, claim)
        if claim._root_prepared_native_bundle is None:
            raise BootstrapEnrollmentPending("active claim lost its typed runnable role closure")
        capability = self._precompile_caps.get(claim._reservation_handle)
        if capability is None:
            raise BootstrapEnrollmentPending("active claim lost its typed precompile capability")
        reservation = self.materialization_receipts.resolve_current_precompile_reservation(
            capability.reservation_handle)
        from .bootstrap_runtime_factory import RootPreparedNativeProfileHomeSourceSet
        home_sources = session.resolve_prepared_native_profile_home_sources(reservation)
        if (type(home_sources) is not RootPreparedNativeProfileHomeSourceSet
                or home_sources.verify_current() is not home_sources
                or home_sources.precompile_output_closure_sha256 != reservation.output_closure_sha256
                or home_sources.public_member_bytes() != claim.native_profile_home_crosswalk_bytes
                or home_sources.member_sha256 != claim.native_profile_home_crosswalk_sha256):
            raise BootstrapEnrollmentPending(
                "prepared native profile-home source set changed after active claim issuance")
        policy_bytes, catalog_bytes, selection, predecessor = self._compile_documents(
            session, capability._root_role_closure)
        if (predecessor != claim.expected_selection_catalog_sha256
                or policy_bytes != claim.policy_bytes or catalog_bytes != claim.artifact_catalog_bytes
                or _canonical(dict(selection)) != _canonical(dict(claim.selection_document))):
            raise BootstrapEnrollmentPending("active policy compiler inputs changed after claim issuance")
        if self._compile_choice_adoptions(session, prepared, claim.selection_catalog_sha256) != claim.choice_adoptions:
            raise BootstrapEnrollmentPending("signed setup-choice projection changed after claim issuance")
        return claim

    def complete_active_publication(self, receipt: Any) -> None:
        from .setup_policy_publication import (
            PolicyPublicationReceiptResolver,
            RootSetupPublicationReceipt,
        )
        if not isinstance(receipt, RootSetupPublicationReceipt):
            raise BootstrapEnrollmentError("active compilation completion requires the typed root publication receipt")
        publication_handle = getattr(receipt, "publication_handle", None)
        claim_digest = getattr(receipt, "claim_digest", None)
        try:
            claim = self._get_claim(publication_handle)
        except BootstrapEnrollmentPending:
            # A publisher recovery call after process restart has no live claim
            # object. Reconstruct only from the durable claim bundle/current
            # typed publication and native registry's exact reservation join.
            return self.recover_active_publication_receipt(receipt)
        claim_state = self._states.get(publication_handle)
        if claim_state == "claimed":
            self._verify_postpublication_claim(claim)
        elif claim_state == "active-committed":
            self._verify_committed_claim(claim)
        else:
            raise BootstrapEnrollmentPending("active compilation claim is not eligible for publication completion")
        current_receipt = PolicyPublicationReceiptResolver.verify_current_active_claim(
            publication_handle=claim.publication_handle,
            claim_digest=claim.claim_digest,
            prepared_generation_id=claim.prepared_generation_id,
            transaction_handle=claim.transaction_handle,
            expected_materialization_receipt_handles=claim.materialization_receipt_handles,
        )
        if (receipt.state != "active-committed"
                or receipt != current_receipt
                or receipt.transaction_handle != claim.transaction_handle
                or receipt.publication_handle != claim.publication_handle
                or receipt.prepared_generation_id != claim.prepared_generation_id
                or claim_digest != claim.claim_digest
                or receipt.service_generation_digest != claim.expected_service_generation_digest
                or receipt.previous_selection_catalog_sha256 != claim.expected_selection_catalog_sha256
                or receipt.policy_sha256 != claim.compiled_policy_sha256
                or receipt.artifact_catalog_sha256 != claim.compiled_artifact_catalog_sha256
                or receipt.runtime_receipt_handles != claim.runtime_receipt_handles
                or receipt.materialization_receipt_handles != claim.materialization_receipt_handles
                or receipt.input_receipt_handles != _ordered_unique_receipt_handles(
                    (claim.observed_root_receipt_handle, *claim.source_receipt_handles),
                    "published input")):
            raise BootstrapEnrollmentPending("active publication receipt does not bind the compiled claim outputs")
        # Publication is already the atomic externally visible commit. Persist
        # that fact before consuming output capabilities so a later local CAS
        # failure cannot make the selected generation look releasable/replayable.
        state_path = self._claim_root / ("transaction-" + claim.transaction_handle + ".json")
        if claim_state == "claimed":
            self._write_state(claim, "active-committed", receipt.receipt_handle)
            state_record = dict(_read_json(state_path))
            state_record["active_selection_catalog_sha256"] = receipt.current_selection_catalog_sha256
            state_record["publication_sha256"] = receipt.publication_sha256
            state_record["descriptor_sha256"] = receipt.descriptor_sha256
            state_record["publication_generation_id"] = receipt.generation_id
            state_record["publication_generation_device"] = receipt.generation_device
            state_record["publication_generation_inode"] = receipt.generation_inode
            _write_json(state_path, state_record)
            self._states[publication_handle] = "active-committed"
            self._close_lock(publication_handle)
        else:
            state_record = _read_json(state_path)
            expected_state = {
                "state": "active-committed",
                "publication_handle": claim.publication_handle,
                "claim_digest": claim.claim_digest,
                "publication_receipt_handle": receipt.receipt_handle,
                "active_selection_catalog_sha256": receipt.current_selection_catalog_sha256,
                "publication_sha256": receipt.publication_sha256,
                "descriptor_sha256": receipt.descriptor_sha256,
                "publication_generation_id": receipt.generation_id,
                "publication_generation_device": receipt.generation_device,
                "publication_generation_inode": receipt.generation_inode,
            }
            if any(state_record.get(key) != value for key, value in expected_state.items()):
                raise BootstrapEnrollmentPending("durable active publication completion record changed")
        self.materialization_receipts.complete_active_compilation(
            claim._reservation_handle, receipt,
            prepared_generation_id=claim.prepared_generation_id,
            publication_handle=claim.publication_handle, claim_digest=claim.claim_digest)

    def _verify_committed_claim(self, claim: RootActivePolicyCompilationClaim) -> None:
        """Verify retained compiler bytes for retry after the selection CAS."""
        if (not isinstance(claim, RootActivePolicyCompilationClaim)
                or claim._seal is not self._seal
                or self._claims.get(claim.publication_handle) is not claim
                or not secrets.compare_digest(claim.claim_digest, _sha(_canonical(_manifest(claim))))):
            raise BootstrapEnrollmentPending("committed active policy claim is altered or unsealed")
        _validate_claim_output_hashes(claim)
        self._verify_claim_bundle(claim)

    def recover_active_publication_receipt(self, receipt: Any) -> Any:
        """Finalize a committed publication after compiler-process restart.

        Recovery consumes only the fixed root journal, the publication resolver's
        current typed receipt, immutable compiler outputs and the native registry's
        unique current reservation lookup. It does not reattach setup-session,
        actor, principal, namespace or choice-selection authority.
        """
        self._require_root()
        from .setup_policy_publication import (
            PolicyPublicationReceiptResolver,
            RootSetupPublicationReceipt,
            _SEAL as _PUBLICATION_SEAL,
            _read_generation_descriptor,
        )
        from .native_output_receipts import NativeOutputReservation

        if (type(receipt) is not RootSetupPublicationReceipt
                or receipt._seal is not _PUBLICATION_SEAL
                or receipt.state != "active-committed"):
            raise BootstrapEnrollmentPending("restart recovery requires a sealed active publication receipt")
        current = PolicyPublicationReceiptResolver.resolve_current()
        if current != receipt:
            raise BootstrapEnrollmentPending("restart recovery receipt is not the current selected publication")
        publication_handle = receipt.publication_handle
        if not isinstance(publication_handle, str) or not _HANDLE.fullmatch(publication_handle):
            raise BootstrapEnrollmentPending("current publication handle is malformed")

        prefix = self._claim_root / publication_handle
        claim_path = prefix.with_suffix(".claim.json")
        claim_record = _read_json(claim_path)
        required_record_fields = {
            "schema", "publication_handle", "claim_digest", "manifest",
            "policy_sha256", "artifact_catalog_sha256", "selection_sha256",
            "authority_core_sha256", "authority_core_size_bytes", "authority_core_schema",
            "native_profile_home_crosswalk",
        }
        manifest = claim_record.get("manifest")
        if (set(claim_record) != required_record_fields or claim_record.get("schema") != 1
                or claim_record.get("publication_handle") != publication_handle
                or claim_record.get("claim_digest") != receipt.claim_digest
                or not isinstance(manifest, dict)
                or _sha(_canonical(manifest)) != receipt.claim_digest):
            raise BootstrapEnrollmentPending("durable compiler claim manifest does not bind the active receipt")
        expected_manifest_fields = {
            "schema", "publication_handle", "setup_session_id", "transaction_handle",
            "plan_sha256", "prepared_generation_id", "expected_selection_catalog_sha256",
            "expected_service_generation_digest", "policy_template_artifact_id",
            "policy_template_sha256", "principal_selection_receipt_handle",
            "principal_identity_kind", "principal_binding_sha256",
            "namespace_selection_handle", "namespace_binding_sha256",
            "owner_overlay_adoptions",
            "runtime_receipt_handles", "materialization_receipt_handles",
            "precompile_reservation_handle", "role_closure_sha256",
            "compiled_policy_sha256", "compiled_artifact_catalog_sha256",
            "compiled_selection_sha256", "selection_catalog_sha256",
            "authority_core_sha256", "authority_core_size_bytes", "authority_core_schema",
            "native_profile_home_crosswalk",
            "observed_root_receipt_handle", "plan_artifact_id", "release_commit",
            "source_receipt_handles", "choice_adoptions", "issued_monotonic",
            "expires_monotonic",
        }
        if manifest.get("schema") != 2 or set(manifest) != expected_manifest_fields:
            raise BootstrapEnrollmentPending("durable compiler claim manifest has an invalid schema")
        source_handles = manifest.get("source_receipt_handles")
        runtime_handles = manifest.get("runtime_receipt_handles")
        output_handles = manifest.get("materialization_receipt_handles")
        observed_handle = manifest.get("observed_root_receipt_handle")
        if (not isinstance(source_handles, list) or not source_handles
                or len(source_handles) > 128
                or _ordered_unique_receipt_handles(source_handles, "recovered source") != tuple(source_handles)
                or not isinstance(runtime_handles, list) or len(runtime_handles) != 1
                or not isinstance(output_handles, list) or len(output_handles) != 5
                or not isinstance(manifest.get("choice_adoptions"), list)
                or len(manifest["choice_adoptions"]) > len(_SETUP_CHOICE_PURPOSES)
                or not isinstance(manifest.get("owner_overlay_adoptions"), list)
                or len(manifest["owner_overlay_adoptions"]) > 4
                or not isinstance(observed_handle, str) or not _HANDLE.fullmatch(observed_handle)
                or manifest.get("principal_identity_kind") not in {
                    "authentik-subject-v1", "linux-local-owner-v1"}
                or not isinstance(manifest.get("principal_binding_sha256"), str)
                or not _HEX.fullmatch(manifest["principal_binding_sha256"])
                or not isinstance(manifest.get("namespace_selection_handle"), str)
                or not _HANDLE.fullmatch(manifest["namespace_selection_handle"])
                or not isinstance(manifest.get("namespace_binding_sha256"), str)
                or not _HEX.fullmatch(manifest["namespace_binding_sha256"])
                or not set(runtime_handles).issubset(source_handles)
                or not set(output_handles).issubset(source_handles)
                or manifest.get("principal_selection_receipt_handle") not in source_handles):
            raise BootstrapEnrollmentPending("durable compiler receipt closure is malformed or incomplete")
        expected_identity = {
            "publication_handle": publication_handle,
            "transaction_handle": receipt.transaction_handle,
            "prepared_generation_id": receipt.prepared_generation_id,
            "expected_service_generation_digest": receipt.service_generation_digest,
            "expected_selection_catalog_sha256": receipt.previous_selection_catalog_sha256,
            "compiled_policy_sha256": receipt.policy_sha256,
            "compiled_artifact_catalog_sha256": receipt.artifact_catalog_sha256,
            "authority_core_sha256": receipt.authority_core_sha256,
            "authority_core_size_bytes": receipt.authority_core_size_bytes,
            "authority_core_schema": receipt.authority_core_schema,
            "native_profile_home_crosswalk": dict(receipt.native_profile_home_crosswalk or {}),
            "runtime_receipt_handles": list(receipt.runtime_receipt_handles),
            "materialization_receipt_handles": list(receipt.materialization_receipt_handles),
        }
        if any(manifest.get(key) != value for key, value in expected_identity.items()):
            raise BootstrapEnrollmentPending("durable compiler claim differs from the active publication receipt")
        expected_claim_record = {
            "schema": 1,
            "publication_handle": publication_handle,
            "claim_digest": receipt.claim_digest,
            "manifest": manifest,
            "policy_sha256": manifest["compiled_policy_sha256"],
            "artifact_catalog_sha256": manifest["compiled_artifact_catalog_sha256"],
            "selection_sha256": manifest["compiled_selection_sha256"],
            "authority_core_sha256": manifest["authority_core_sha256"],
            "authority_core_size_bytes": manifest["authority_core_size_bytes"],
            "authority_core_schema": manifest["authority_core_schema"],
            "native_profile_home_crosswalk": manifest["native_profile_home_crosswalk"],
        }
        if claim_record != expected_claim_record:
            raise BootstrapEnrollmentPending("durable compiler output record differs from its manifest")
        expected_inputs = (observed_handle, *source_handles)
        if receipt.input_receipt_handles != expected_inputs:
            raise BootstrapEnrollmentPending("active publication receipt differs from canonical compiler closure")

        policy = _read_immutable_bytes(prefix.with_suffix(".policy"))
        catalog = _read_immutable_bytes(prefix.with_suffix(".catalog"))
        selection_bytes = _read_immutable_bytes(prefix.with_suffix(".selection"))
        authority_core = _read_immutable_bytes(prefix.with_suffix(".authority"))
        crosswalk = _read_immutable_bytes(prefix.with_suffix(".native-profile-home-crosswalk"))
        if (_sha(policy) != manifest["compiled_policy_sha256"]
                or _sha(catalog) != manifest["compiled_artifact_catalog_sha256"]
                or _sha(selection_bytes) != manifest["compiled_selection_sha256"]
                or _sha(authority_core) != manifest["authority_core_sha256"]
                or len(authority_core) != manifest["authority_core_size_bytes"]
                or _sha(crosswalk) != manifest["native_profile_home_crosswalk"]["sha256"]
                or len(crosswalk) != manifest["native_profile_home_crosswalk"]["size_bytes"]):
            raise BootstrapEnrollmentPending("durable compiler output bytes differ from the claim manifest")
        try:
            core_document = json.loads(authority_core.decode("utf-8"), object_pairs_hook=_unique_pairs,
                                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (UnicodeError, ValueError, json.JSONDecodeError):
            raise BootstrapEnrollmentPending("durable compiled authority core is malformed") from None
        if (not isinstance(core_document, dict)
                or core_document.get("schema") != manifest["authority_core_schema"]
                or _canonical(core_document) != authority_core):
            raise BootstrapEnrollmentPending("durable compiled authority core is not canonical")
        try:
            selection = json.loads(selection_bytes.decode("utf-8"), object_pairs_hook=_unique_pairs,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (UnicodeError, ValueError, json.JSONDecodeError):
            raise BootstrapEnrollmentPending("durable compiler selection document is malformed") from None
        if (not isinstance(selection, dict)
                or selection.get("catalog_sha256") != manifest["selection_catalog_sha256"]
                or _sha(_canonical({key: value for key, value in selection.items()
                                    if key != "catalog_sha256"})
                        ) != manifest["selection_catalog_sha256"]):
            raise BootstrapEnrollmentPending("durable compiler selection digest is inconsistent")

        descriptor, _file_digests, file_bytes = _read_generation_descriptor(receipt, 0)
        inputs = descriptor.get("inputs")
        if isinstance(inputs, Mapping):
            _verify_recovered_owner_overlay_join(manifest, inputs, descriptor)
        if (not isinstance(inputs, Mapping)
                or inputs.get("source_receipt_handles") != source_handles
                or inputs.get("observed_root_receipt_handle") != observed_handle
                or inputs.get("selection_catalog_sha256") != manifest["selection_catalog_sha256"]
                or inputs.get("choice_projections") != manifest.get("choice_adoptions")
                or descriptor.get("authority_core") != {
                    "relative_path": "authority/enrollment.json",
                    "sha256": receipt.authority_core_sha256,
                    "size_bytes": receipt.authority_core_size_bytes,
                    "authority_schema": receipt.authority_core_schema,
                }
                or descriptor.get("native_profile_home_crosswalk")
                   != receipt.native_profile_home_crosswalk
                or any(inputs.get(key) != value for key, value in {
                    "publication_handle": publication_handle,
                    "claim_digest": receipt.claim_digest,
                    "prepared_generation_id": receipt.prepared_generation_id,
                    "expected_service_generation_digest": receipt.service_generation_digest,
                    "transaction_handle": receipt.transaction_handle,
                    "runtime_receipt_handles": runtime_handles,
                    "materialization_receipt_handles": output_handles,
                }.items())
                or file_bytes.get("plans/bootstrap-policy-v1.json") != policy
                or file_bytes.get("catalog/artifacts.json") != catalog
                or file_bytes.get("authority/enrollment.json") != authority_core):
            raise BootstrapEnrollmentPending("active descriptor differs from durable compiler inputs")
        if (file_bytes.get("authority/native-profile-home-crosswalk-v213.json") != crosswalk
                or descriptor.get("native_profile_home_crosswalk")
                   != manifest["native_profile_home_crosswalk"]):
            raise BootstrapEnrollmentPending("active descriptor differs from durable compiler inputs")

        state_path = self._claim_root / ("transaction-" + receipt.transaction_handle + ".json")
        state = _read_json(state_path)
        expected_state_identity = {
            "schema": 1,
            "publication_handle": publication_handle,
            "claim_digest": receipt.claim_digest,
            "transaction_handle": receipt.transaction_handle,
            "setup_session_id": manifest["setup_session_id"],
            "prepared_generation_id": receipt.prepared_generation_id,
            "expected_selection_catalog_sha256": receipt.previous_selection_catalog_sha256,
            "expected_service_generation_digest": receipt.service_generation_digest,
            "policy_sha256": receipt.policy_sha256,
            "artifact_catalog_sha256": receipt.artifact_catalog_sha256,
            "selection_sha256": manifest["compiled_selection_sha256"],
            "observed_root_receipt_handle": observed_handle,
            "principal_selection_receipt_handle": manifest["principal_selection_receipt_handle"],
            "principal_identity_kind": manifest["principal_identity_kind"],
            "principal_binding_sha256": manifest["principal_binding_sha256"],
            "namespace_selection_handle": manifest["namespace_selection_handle"],
            "namespace_binding_sha256": manifest["namespace_binding_sha256"],
            "authority_core_sha256": manifest["authority_core_sha256"],
            "authority_core_size_bytes": manifest["authority_core_size_bytes"],
            "authority_core_schema": manifest["authority_core_schema"],
            "native_profile_home_crosswalk": manifest["native_profile_home_crosswalk"],
            "owner_overlay_adoptions": manifest["owner_overlay_adoptions"],
            "runtime_receipt_handles": runtime_handles,
            "materialization_receipt_handles": output_handles,
        }
        if (state.get("state") not in {"claimed", "active-committed"}
                or any(state.get(key) != value for key, value in expected_state_identity.items())):
            raise BootstrapEnrollmentPending("durable compiler transaction is not recoverable")

        reservation = self.materialization_receipts.resolve_active_compilation_reservation(receipt)
        if (type(reservation) is not NativeOutputReservation
                or reservation.publication_handle != publication_handle
                or reservation.reservation_handle != manifest.get("precompile_reservation_handle")
                or reservation.claim_digest != receipt.claim_digest
                or reservation.prepared_generation_id != receipt.prepared_generation_id
                or reservation.receipt_ids != tuple(output_handles)):
            raise BootstrapEnrollmentPending("native output registry returned another durable reservation")
        completed = self.materialization_receipts.complete_active_compilation(
            reservation.reservation_handle, receipt,
            prepared_generation_id=receipt.prepared_generation_id,
            publication_handle=publication_handle, claim_digest=receipt.claim_digest)
        if (not isinstance(completed, tuple)
                or tuple(item.receipt_id for item in completed) != tuple(output_handles)):
            raise BootstrapEnrollmentPending("recovered native completion returned another output closure")

        recovered = dict(state)
        recovered.update({
            "state": "active-committed",
            "publication_receipt_handle": receipt.receipt_handle,
            "active_selection_catalog_sha256": receipt.current_selection_catalog_sha256,
            "publication_sha256": receipt.publication_sha256,
            "descriptor_sha256": receipt.descriptor_sha256,
            "publication_generation_id": receipt.generation_id,
            "publication_generation_device": receipt.generation_device,
            "publication_generation_inode": receipt.generation_inode,
        })
        _write_json(state_path, recovered)
        self._states[publication_handle] = "active-committed"
        return receipt

    def release_active_policy(self, publication_handle: str) -> None:
        claim = self._get_claim(publication_handle)
        if self._states.get(publication_handle) in {"released", "active-committed"}:
            return
        if self._states.get(publication_handle) != "claimed":
            raise BootstrapEnrollmentPending("only an uncommitted active policy claim can be released")
        self.materialization_receipts.release_active_compilation(
            claim._reservation_handle, prepared_generation_id=claim.prepared_generation_id,
            publication_handle=claim.publication_handle, claim_digest=claim.claim_digest)
        self._write_state(claim, "released", None)
        self._states[publication_handle] = "released"
        self._close_lock(publication_handle)

    def resolve_active_state(self, setup_session_handle: RootSetupSessionHandle) -> Mapping[str, Any]:
        from .setup_policy_publication import PolicyPublicationReceiptResolver
        session = self.factory.resolve_live_session(setup_session_handle)
        transaction_handle = session._authorization.transaction_handle
        path = self._claim_root / ("transaction-" + transaction_handle + ".json")
        row = _read_json(path)
        if row.get("state") != "active-committed":
            raise BootstrapEnrollmentPending("active policy publication is not committed for this transaction")
        handles = row.get("materialization_receipt_handles")
        if not isinstance(handles, list) or not handles:
            raise BootstrapEnrollmentPending("active policy journal lacks its native output receipt closure")
        receipt = PolicyPublicationReceiptResolver.verify_current_active_claim(
            publication_handle=row.get("publication_handle"),
            claim_digest=row.get("claim_digest"),
            prepared_generation_id=row.get("prepared_generation_id"),
            transaction_handle=transaction_handle,
            expected_materialization_receipt_handles=tuple(handles),
        )
        if (receipt.state != "active-committed"
                or receipt.current_selection_catalog_sha256 != row.get("active_selection_catalog_sha256")
                or receipt.publication_sha256 != row.get("publication_sha256")
                or receipt.descriptor_sha256 != row.get("descriptor_sha256")
                or receipt.generation_id != row.get("publication_generation_id")
                or receipt.generation_device != row.get("publication_generation_device")
                or receipt.generation_inode != row.get("publication_generation_inode")):
            raise BootstrapEnrollmentPending("active policy journal differs from the current selected publication")
        return row

    def _compile_documents(self, session: Any, role_closure: Any
                           ) -> tuple[bytes, bytes, dict[str, Any], str]:
        # Re-read and revalidate the exact current loader inputs. This avoids
        # serializing caller objects or reconstructing source facts from IDs.
        path = self.resolver.selection_path
        # The fixed root selection has its own secure reader; release-file
        # readers are only used for the pinned policy and catalog artifacts.
        from .bootstrap_runtime_factory import _read_secure_root_bytes
        raw = _read_secure_root_bytes(path, _MAX_DOCUMENT, 0o600)
        current_doc = self.resolver._json(raw, "current active selection")
        current = self.resolver._load_selection()
        if (not isinstance(current_doc, dict) or raw != _canonical(current_doc)
                or current_doc.get("catalog_sha256") != current.selection_digest
                or current_doc.get("installer_release_commit") != session._factory._release.release_commit):
            raise BootstrapEnrollmentPending("current root selection changed or differs from the verified release")
        policy_rows = [row for row in current.bootstrap_policies
                       if row.get("artifact_id") == "installer-bootstrap-policy-v1"]
        if len(policy_rows) != 1:
            raise BootstrapEnrollmentPending("current root policy selection is absent or ambiguous")
        policy_row = policy_rows[0]
        policy_fd = self.resolver._open_policy_generation(current)
        try:
            policy_path = self.resolver._verified_relative(
                policy_row, "installer-bootstrap-policy-v1", current.policy_root, policy_fd)
        finally:
            os.close(policy_fd)
        policy_bytes = self.resolver._read_release_file(
            policy_path, maximum=_MAX_DOCUMENT, expected_sha256=policy_row["sha256"])
        policy_doc = self.resolver._json(policy_bytes, "current selected bootstrap policy")
        if policy_bytes != _canonical(policy_doc):
            raise BootstrapEnrollmentPending("current selected policy bytes are not canonical")
        verified_policy = self.resolver.resolve_policy(session._authorization.plan_artifact_id)
        if (verified_policy.artifact_id != policy_row["artifact_id"]
                or verified_policy.sha256 != policy_row["sha256"]
                or verified_policy != session._policy):
            raise BootstrapEnrollmentPending("live setup policy differs from the selected strict policy bytes")
        principal = self._resolve_current_principal(session)
        identity = verified_policy.identity_policy
        principal_kind = getattr(principal, "identity_kind", None)
        from .setup_principal import (RootSetupLocalOwnerIdentityRegistry,
                                      RootSetupPrincipalSelectionRegistry)
        if (not isinstance(identity, Mapping)
                or identity.get("identity_kind") != principal_kind
                or identity.get("principal_id") != principal.principal_id
                or identity.get("service_profile_id") != principal.service_profile_id):
            raise BootstrapEnrollmentPending("selected active policy identity does not match the current tagged principal")
        if principal_kind == "linux-local-owner-v1":
            if (type(self.principal_registry) is not RootSetupLocalOwnerIdentityRegistry
                    or identity.get("owner_binding_sha256")
                       != principal.principal_binding_sha256
                    or identity.get("uid_allocation") != "root-dedicated-account"):
                raise BootstrapEnrollmentPending("local-owner policy binding is absent or belongs to another principal")
        elif principal_kind == "authentik-subject-v1":
            if (type(self.principal_registry) is not RootSetupPrincipalSelectionRegistry
                    or not principal.principal_id.startswith("authentik:")
                    or identity.get("uid_allocation") != "root-dedicated-account"):
                raise BootstrapEnrollmentPending("Authentik policy identity lost its strict principal domain")
        else:
            raise BootstrapEnrollmentPending("active policy has no supported tagged principal domain")
        capability = self._precompile_caps.get(role_closure.native_output_claim_handle)
        if capability is None:
            raise BootstrapEnrollmentPending("active documents have no retained compiler precompile capability")
        reservation = self.materialization_receipts.resolve_current_precompile_reservation(
            capability.reservation_handle)
        prepared = self._verify_prepared_native_bundle(session, capability._root_prepared_native_bundle)
        self._validate_runnable_role_closure(role_closure, reservation, session, prepared)
        role_by_name = {row.role: row for row in role_closure.role_rows}
        role_kinds = {
            "official-pm-runtime": "pm-runtime",
            "native-compiled-closure": "compiled-closure",
            "native-entrypoint-manifest": "entrypoint-json",
            "native-action-resolver": "resolver-json",
            "native-boundary-overlay": "boundary-overlay",
            "native-candidate-index": "candidate-index-json",
        }
        policy_doc = copy.deepcopy(policy_doc)
        rules = policy_doc.get("receipt_binding_rules")
        if not isinstance(rules, list):
            raise BootstrapEnrollmentPending("selected policy has no strict receipt binding rules")
        for role, output_kind in role_kinds.items():
            selected = role_by_name[role]
            rule_rows = [row for row in rules
                         if isinstance(row, dict) and row.get("receipt_role") == role]
            if (len(rule_rows) != 1 or rule_rows[0].get("required_phase") != "runnable"
                    or rule_rows[0].get("allowed_output_kinds") != [output_kind]
                    or rule_rows[0].get("allowed_artifact_ids") != []
                    or selected.output_kind != output_kind):
                raise BootstrapEnrollmentPending(
                    "prepared policy receipt rule does not exactly match the selected runnable role")
            rule_rows[0]["allowed_artifact_ids"] = [selected.artifact_id]
        policy_bytes = _canonical(policy_doc)
        from .bootstrap_enrollment import _open_immutable_release_root
        release_fd = _open_immutable_release_root(
            current.release_root, current.release_device, current.release_inode)
        try:
            catalog_path = self.resolver._verified_relative(
                current.artifact_catalog, "installer-protected-artifact-catalog-v1",
                Path(current.release_root), release_fd)
        finally:
            os.close(release_fd)
        catalog_bytes = self.resolver._read_release_file(
            catalog_path, maximum=_MAX_DOCUMENT, expected_sha256=current.artifact_catalog["sha256"])
        catalog_doc = self.resolver._json(catalog_bytes, "current artifact catalog")
        if catalog_bytes != _canonical(catalog_doc):
            raise BootstrapEnrollmentPending("current artifact catalog bytes are not canonical")

        selection = {key: value for key, value in current_doc.items()
                     if key not in {"policy_generation", "catalog_sha256"}}
        selection["artifact_catalog"] = dict(current_doc["artifact_catalog"])
        selection["artifact_catalog"]["relative_path"] = "catalog/artifacts.json"
        selection["bootstrap_policies"] = [dict(row) for row in current_doc["bootstrap_policies"]]
        for row in selection["bootstrap_policies"]:
            if row["artifact_id"] == "installer-bootstrap-policy-v1":
                row["relative_path"] = "plans/bootstrap-policy-v1.json"
                row["sha256"] = _sha(policy_bytes)
        unsigned_digest = _sha(_canonical(selection))
        selection["catalog_sha256"] = unsigned_digest
        # The strict loader must accept the exact compiled active policy before
        # the publisher is allowed to switch the root selection pointer. This
        # rejects prepared-empty catalogs and any incomplete active projection.
        plan_rows = [row for row in current.plans
                     if row.get("artifact_id") == session._authorization.plan_artifact_id]
        if len(plan_rows) != 1:
            raise BootstrapEnrollmentPending("selected setup plan is absent or ambiguous during active compilation")
        self.resolver._parse_policy(
            policy_doc, _sha(policy_bytes), plan_rows[0], current,
            compilation_phase="active")
        return policy_bytes, catalog_bytes, selection, current.selection_digest

    def _compile_choice_adoptions(
            self, session: Any, prepared: EnrollmentReceipt,
            selection_catalog_sha256: str) -> tuple[ActiveSetupChoiceProjection, ...]:
        """Project only current signed choices retained by the root registry."""
        from .root_setup_choices import RootSetupChoiceRegistry, RootSetupChoiceSnapshot

        binding = session.selected_installation
        registry = binding.resolve_setup_choice_registry()
        if type(registry) is not RootSetupChoiceRegistry:
            raise BootstrapEnrollmentPending("current setup has no concrete root signed-choice registry")
        snapshots = registry.resolve_current_session_choices(binding)
        if not isinstance(snapshots, tuple) or len(snapshots) > len(_SETUP_CHOICE_PURPOSES):
            raise BootstrapEnrollmentPending("root setup-choice registry returned an unbounded choice set")

        identity = binding.resolve_current_setup_identity()
        principal_selector = binding.resolve_adopted_principal_selector()
        namespace_selector = binding.resolve_adopted_namespace_selector()
        session_handle = binding.resolve_current_setup_session_handle()
        release = session._factory._release
        release.verify_current()
        release_digest = getattr(release, "deployment_receipt_sha256", None)
        principal_id = getattr(identity.principal, "principal_id", None)
        namespace_id = getattr(identity.namespace, "namespace_id", None)
        if (getattr(identity, "expires_monotonic", 0) <= time.monotonic()
                or identity.principal_selection_handle != principal_selector.selection_handle
                or identity.namespace_selection_handle != namespace_selector.selection_handle
                or principal_selector.setup_session_id != session_handle.session_id
                or namespace_selector.setup_session_id != session_handle.session_id
                or principal_selector.transaction_handle != session._authorization.transaction_handle
                or namespace_selector.transaction_handle != session._authorization.transaction_handle
                or principal_selector.plan_sha256 != session._authorization.plan_digest
                or namespace_selector.plan_sha256 != session._authorization.plan_digest
                or namespace_selector.prepared_generation_id != prepared.generation_id
                or namespace_selector.prepared_generation_digest != prepared.generation_digest
                or not isinstance(release_digest, str) or not _HEX.fullmatch(release_digest)
                or not isinstance(principal_id, str) or not principal_id
                or not isinstance(namespace_id, str) or not namespace_id):
            raise BootstrapEnrollmentPending("fresh setup identity does not match active choice projection")

        projections: list[ActiveSetupChoiceProjection] = []
        for snapshot in snapshots:
            if type(snapshot) is not RootSetupChoiceSnapshot:
                raise BootstrapEnrollmentPending("choice registry returned an untyped signed choice")
            purpose = snapshot.purpose
            if purpose not in _SETUP_CHOICE_PURPOSES:
                raise BootstrapEnrollmentPending("signed setup choice purpose is outside the finite contract")
            payload = dict(snapshot.choice_payload)
            expected = {
                "setup_session_handle": session_handle.session_id,
                "transaction_handle": session._authorization.transaction_handle,
                "plan_id": session._authorization.plan_artifact_id,
                "prepared_generation": prepared.generation_id,
                "principal_selection_handle": principal_selector.selection_handle,
                "namespace_selection_handle": namespace_selector.selection_handle,
                "principal_id": principal_id,
                "namespace_id": namespace_id,
                "principal_binding_sha256": principal_selector.binding_sha256,
                "namespace_binding_sha256": namespace_selector.binding_sha256,
                "release_deployment_receipt_sha256": release_digest,
            }
            if any(getattr(snapshot, name, None) != value for name, value in expected.items()):
                raise BootstrapEnrollmentPending("signed setup choice belongs to another active subject or generation")
            if (not isinstance(snapshot.selection_handle, str)
                    or not _HANDLE.fullmatch(snapshot.selection_handle)
                    or not isinstance(snapshot.key_id, str)
                    or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", snapshot.key_id)
                    or not _HEX.fullmatch(snapshot.signed_record_sha256)
                    or not _HEX.fullmatch(snapshot.choice_payload_sha256)
                    or snapshot.choice_payload_sha256 != _sha(_canonical(payload))
                    or type(snapshot.choice_epoch) is not int or snapshot.choice_epoch < 1
                    or type(snapshot.revocation_epoch) is not int or snapshot.revocation_epoch != 1
                    or type(snapshot.issued_at_unix) not in (int, float)
                    or type(snapshot.setup_deadline_unix) not in (int, float)
                    or snapshot.issued_at_unix >= snapshot.setup_deadline_unix
                    or snapshot.adoption_publication_receipt_handle is not None):
                raise BootstrapEnrollmentPending("signed setup choice digest, epoch, or lease is invalid")
            if (not isinstance(snapshot.source_member_receipt_handles, tuple)
                    or not snapshot.source_member_receipt_handles
                    or len(set(snapshot.source_member_receipt_handles)) != len(snapshot.source_member_receipt_handles)
                    or any(not isinstance(handle, str) or not _HANDLE.fullmatch(handle)
                           for handle in snapshot.source_member_receipt_handles)):
                raise BootstrapEnrollmentPending("signed setup choice source receipt closure is invalid")

            private_profile_id: str | None = None
            if snapshot.private_profile_selection_handle is not None:
                if purpose not in {"memory-service-enablement", "existing-model-selection"}:
                    raise BootstrapEnrollmentPending("choice purpose cannot use a private profile selector")
                private_profile = binding.resolve_current_private_profile(
                    snapshot.private_profile_selection_handle, purpose)
                private_profile_id = getattr(private_profile, "profile_id", None)
                if not isinstance(private_profile_id, str) or not private_profile_id:
                    raise BootstrapEnrollmentPending("current private profile selector has no profile identity")

            if purpose == "memory-service-enablement":
                profile_id = payload.get("profile_id")
                if (private_profile_id is None or profile_id != private_profile_id
                        or not isinstance(payload.get("enabled"), bool)):
                    raise BootstrapEnrollmentPending("memory choice profile differs from its current private selection")
            elif purpose == "existing-model-selection":
                profile_id = payload.get("profile_id", private_profile_id)
                if private_profile_id is None or profile_id != private_profile_id:
                    raise BootstrapEnrollmentPending("model choice profile differs from its current private selection")
            elif purpose == "native-policy-preparation":
                profile_id = payload.get("service_profile_id")
                if (not isinstance(profile_id, str)
                        or profile_id != getattr(identity.principal, "service_profile_id", None)):
                    raise BootstrapEnrollmentPending("native policy choice profile differs from the current principal")
            elif purpose == "application-qualification":
                profile_id = payload.get("target_profile_id")
                if (not isinstance(profile_id, str)
                        or profile_id != getattr(identity.namespace, "target_profile_id", None)):
                    raise BootstrapEnrollmentPending("application choice profile differs from the current namespace")
            else:
                # The signed choice registry may eventually issue the other
                # v143 purposes, but each needs a dedicated typed selector join
                # before it can enter a published generation.
                raise BootstrapEnrollmentPending("setup-choice purpose has no installed root profile join")
            if (not isinstance(profile_id, str) or not profile_id
                    or profile_id != principal_selector.service_profile_id
                    or profile_id != namespace_selector.target_profile_id):
                raise BootstrapEnrollmentPending("signed setup choice profile differs from current principal/namespace selectors")

            projections.append(ActiveSetupChoiceProjection(
                selection_handle=snapshot.selection_handle,
                purpose=purpose,
                key_id=snapshot.key_id,
                signed_record_sha256=snapshot.signed_record_sha256,
                choice_payload_sha256=snapshot.choice_payload_sha256,
                choice_epoch=snapshot.choice_epoch,
                revocation_epoch=snapshot.revocation_epoch,
                issued_at_unix=snapshot.issued_at_unix,
                setup_deadline_unix=snapshot.setup_deadline_unix,
                release_deployment_receipt_sha256=snapshot.release_deployment_receipt_sha256,
                setup_session_handle=snapshot.setup_session_handle,
                transaction_handle=snapshot.transaction_handle,
                plan_id=snapshot.plan_id,
                prepared_generation=snapshot.prepared_generation,
                principal_selection_handle=snapshot.principal_selection_handle,
                namespace_selection_handle=snapshot.namespace_selection_handle,
                private_profile_selection_handle=snapshot.private_profile_selection_handle,
                source_member_receipt_handles=tuple(sorted(snapshot.source_member_receipt_handles)),
                principal_id=principal_id,
                profile_id=profile_id,
                namespace_id=namespace_id,
                principal_binding_sha256=principal_selector.binding_sha256,
                namespace_binding_sha256=namespace_selector.binding_sha256,
                service_generation_id=prepared.generation_id,
                service_generation_digest=prepared.generation_digest,
                selection_catalog_sha256=selection_catalog_sha256,
                _compiler_seal=self._seal,
            ))
        projections.sort(key=lambda row: (row.purpose, row.selection_handle))
        return tuple(projections)

    def _verify_choice_projection_seals(self, claim: RootActivePolicyCompilationClaim) -> None:
        rows = claim.choice_adoptions
        if (not isinstance(rows, tuple) or len(rows) > len(_SETUP_CHOICE_PURPOSES)
                or any(type(row) is not ActiveSetupChoiceProjection
                       or row._compiler_seal is not self._seal
                       or row.selection_catalog_sha256 != claim.selection_catalog_sha256
                       or row.service_generation_id != claim.prepared_generation_id
                       or row.service_generation_digest != claim.expected_service_generation_digest
                       for row in rows)
                or rows != tuple(sorted(rows, key=lambda row: (row.purpose, row.selection_handle)))):
            raise BootstrapEnrollmentPending("active setup-choice projection is stale, altered, or unsealed")

    def _mint_actor_observation(self, session: Any, prepared: EnrollmentReceipt,
                                expires: float) -> str:
        session._check_live()
        session._factory._actor.verify_current(session._factory._release)
        handle = secrets.token_hex(32)
        _ensure_private_directory(self._claim_root)
        actor = session._authorization.root_actor_identity
        actor_digest = _sha(_canonical(dict(actor)))
        _write_json(self._claim_root / ("actor-" + handle + ".json"), {
            "schema": 1, "receipt_handle": handle,
            "setup_session_id": session._handle.session_id,
            "transaction_handle": session._authorization.transaction_handle,
            "plan_sha256": session._authorization.plan_digest,
            "prepared_generation_id": prepared.generation_id,
            "prepared_generation_digest": prepared.generation_digest,
            "actor_identity_sha256": actor_digest,
            "issued_monotonic": time.monotonic(), "expires_monotonic": expires,
        }, exclusive=True)
        return handle

    def _verify_actor_observation(self, handle: str,
                                  claim: RootActivePolicyCompilationClaim) -> None:
        if not isinstance(handle, str) or not re.fullmatch(r"[0-9a-f]{64}", handle):
            raise BootstrapEnrollmentPending("root actor observation handle is malformed")
        row = _read_json(self._claim_root / ("actor-" + handle + ".json"))
        session = claim._root_setup_session
        session._check_live()
        session._factory._actor.verify_current(session._factory._release)
        expected = {
            "schema": 1, "receipt_handle": handle,
            "setup_session_id": claim.setup_session_id,
            "transaction_handle": claim.transaction_handle,
            "plan_sha256": claim.plan_sha256,
            "prepared_generation_id": claim.prepared_generation_id,
            "prepared_generation_digest": claim.expected_service_generation_digest,
            "actor_identity_sha256": _sha(_canonical(dict(session._authorization.root_actor_identity))),
        }
        if (any(row.get(key) != value for key, value in expected.items())
                or row.get("expires_monotonic", 0) <= time.monotonic()
                or row.get("expires_monotonic") != claim.expires_monotonic):
            raise BootstrapEnrollmentPending("root actor observation receipt is stale or mismatched")

    def _validate_prepared(self, session: Any, receipt: EnrollmentReceipt) -> None:
        live = self.sessions._live(session._handle)
        proof = self.sessions._proof(live)
        if (not isinstance(receipt, EnrollmentReceipt) or receipt.state != "prepared"
                or receipt.enrollment_ids or receipt.setup_session_id != proof.setup_session_id
                or receipt.transaction_handle != proof.transaction_handle
                or receipt.plan_digest != proof.plan_digest
                or receipt.generation_digest is None or not _HEX.fullmatch(receipt.generation_digest)
                or receipt.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("active policy compiler requires the live empty prepared-generation receipt")
        committed = self.sessions.verify_committed_receipt(receipt, proof)
        if (not isinstance(committed, VerifiedCommittedEnrollment)
                or committed.receipt != receipt
                or committed.setup_session_id != proof.setup_session_id
                or committed.plan_digest != proof.plan_digest):
            raise BootstrapEnrollmentPending("prepared receipt is not the exact durable root commit")

    def _verify_prepared_native_bundle(self, session: Any, bundle: Any) -> EnrollmentReceipt:
        """Use the factory's typed currentness resolver for the prepared bundle."""
        from .bootstrap_runtime_factory import RootPreparedNativeBundle
        if (type(bundle) is not RootPreparedNativeBundle
                or not isinstance(getattr(bundle, "_session_seal", None), str)
                or not secrets.compare_digest(bundle._session_seal, session._seal)):
            raise BootstrapEnrollmentPending("active compilation requires the root-prepared native bundle")
        session._check_live()
        session._refresh_authorization()
        retained = session._last_receipt
        if (not isinstance(retained, EnrollmentReceipt) or retained.state != "prepared"
                or not retained.provision_receipt_handle or retained.enrollment_ids):
            raise BootstrapEnrollmentPending("prepared native bundle no longer has an empty current generation")
        prepared = session.resolve_prepared_receipt(retained.provision_receipt_handle)
        self._validate_prepared(session, prepared)
        current = session.selected_installation.resolve_current_prepared_native_bundle(bundle)
        if (current is not bundle
                or (bundle.setup_session_id, bundle.transaction_handle,
                    bundle.prepared_generation_id, bundle.prepared_generation_digest)
                != (session._handle.session_id, session._authorization.transaction_handle,
                    prepared.generation_id, prepared.generation_digest)):
            raise BootstrapEnrollmentPending("prepared native bundle belongs to another setup transaction")
        pm_runtime = session.selected_installation.resolve_current_pm_runtime()
        if (getattr(pm_runtime, "receipt_handle", None) != bundle.pm_runtime_receipt_handle
                or getattr(pm_runtime, "prepared_generation_id", None) != prepared.generation_id
                or getattr(pm_runtime, "transaction_handle", None) != session._authorization.transaction_handle):
            raise BootstrapEnrollmentPending("prepared native bundle PM receipt is stale")
        source = session.selected_installation.resolve_current_hermes_source()
        if getattr(source, "receipt_handle", None) != bundle.hermes_source_receipt_handle:
            raise BootstrapEnrollmentPending("prepared native bundle Hermes source receipt is stale")
        return prepared

    def _verify_postpublication_claim(self,
                                      claim: RootActivePolicyCompilationClaim) -> None:
        if (not isinstance(claim, RootActivePolicyCompilationClaim)
                or claim._seal is not self._seal
                or self._claims.get(claim.publication_handle) is not claim
                or self._states.get(claim.publication_handle) != "claimed"
                or claim.expires_monotonic <= time.monotonic()
                or not secrets.compare_digest(claim.claim_digest, _sha(_canonical(_manifest(claim))))):
            raise BootstrapEnrollmentPending("active policy claim is stale, altered, replayed, or unsealed")
        _validate_claim_output_hashes(claim)
        self._verify_claim_bundle(claim)
        session = self.factory.resolve_live_session(claim._root_setup_session._handle)
        session._refresh_authorization()
        retained = session._last_receipt
        if (retained is None or not isinstance(retained.provision_receipt_handle, str)):
            raise BootstrapEnrollmentPending("prepared receipt was lost after active publication")
        prepared = session.resolve_prepared_receipt(retained.provision_receipt_handle)
        self._validate_prepared(session, prepared)
        bundle = claim._root_prepared_native_bundle
        if bundle is None or self._verify_prepared_native_bundle(session, bundle) is not prepared:
            raise BootstrapEnrollmentPending("prepared native bundle changed after active publication")
        if (session is not claim._root_setup_session
                or session._authorization.transaction_handle != claim.transaction_handle
                or session._authorization.plan_digest != claim.plan_sha256
                or prepared.generation_id != claim.prepared_generation_id
                or prepared.generation_digest != claim.expected_service_generation_digest):
            raise BootstrapEnrollmentPending("active publication no longer joins the prepared setup session")
        self._verify_choice_projection_seals(claim)
        if self._compile_choice_adoptions(session, prepared, claim.selection_catalog_sha256) != claim.choice_adoptions:
            raise BootstrapEnrollmentPending("signed setup-choice projection changed during active publication")
        self._verify_claim_principal_join(claim, session)
        self._verify_actor_observation(claim.observed_root_receipt_handle, claim)
        for handle in claim.runtime_receipt_handles:
            runtime = self.runtime_receipts.resolve_runtime(
                handle, claim.transaction_handle, claim.prepared_generation_id)
            if not self._runtime_joins(runtime, session, prepared):
                raise BootstrapEnrollmentPending("PM runtime receipt changed after active publication")
        outputs = self.materialization_receipts.verify_active_compilation(
            claim._reservation_handle, prepared_generation_id=claim.prepared_generation_id,
            publication_handle=claim.publication_handle, claim_digest=claim.claim_digest)
        if {item.receipt_id for item in outputs} != set(claim.materialization_receipt_handles):
            raise BootstrapEnrollmentPending("native output reservation changed after active publication")

    @staticmethod
    def _runtime_joins(receipt: Any, session: Any, prepared: EnrollmentReceipt) -> bool:
        return (getattr(receipt, "setup_session_id", None) == session._handle.session_id
                and getattr(receipt, "transaction_handle", None) == session._authorization.transaction_handle
                and getattr(receipt, "prepared_generation_id", None) == prepared.generation_id
                and getattr(receipt, "source_artifact_id", None) == session._policy.source_artifact_id
                and getattr(receipt, "expires_monotonic", 0) > time.monotonic())

    def _resolve_current_principal(self, session: Any) -> Any:
        """Resolve the current principal through its concrete tagged issuer."""
        registry = self.principal_registry
        from .setup_principal import (RootSetupLocalOwnerIdentityRegistry,
                                      RootSetupPrincipalSelectionRegistry)
        if type(registry) is RootSetupPrincipalSelectionRegistry:
            principal = registry.resolve_adopted_initial_principal(self.sessions, session._handle)
            if (getattr(principal, "identity_kind", None) != "authentik-subject-v1"
                    or not isinstance(getattr(principal, "principal_id", None), str)
                    or not principal.principal_id.startswith("authentik:")):
                raise BootstrapEnrollmentPending("adopted Authentik principal crossed identity domains")
            return principal
        if type(registry) is RootSetupLocalOwnerIdentityRegistry:
            principal = registry.resolve_adopted_initial_principal(self.sessions, session._handle)
            selector = registry.resolve_adopted_namespace_selector(self.sessions, session._handle)
            snapshot = registry.resolve_current_setup_identity(
                principal.receipt_handle, selector.selection_handle, session._handle)
            current = registry.resolve_current_snapshot(session._handle, snapshot.snapshot_handle)
            if (current is not snapshot
                    or current.identity_kind != "linux-local-owner-v1"
                    or current.principal.principal_binding_sha256 != principal.principal_binding_sha256
                    or current.namespace_selection_handle != selector.selection_handle
                    or current.namespace_binding_sha256 != selector.binding_sha256
                    or current.namespace is None
                    or current.namespace.namespace_id != principal.namespace_id
                    or current.namespace.prepared_generation_id != session._last_receipt.generation_id):
                raise BootstrapEnrollmentPending("adopted local-owner principal or namespace is not current")
            return principal
        raise BootstrapEnrollmentPending("active compiler principal registry has no supported concrete identity domain")

    def _resolve_principal_publication_binding(
            self, session: Any, principal: Any) -> tuple[str, str, str, tuple[str, ...]]:
        """Bind a claim to the issuer's current principal and namespace selectors."""
        registry = self.principal_registry
        from .setup_principal import (RootSetupLocalOwnerIdentityRegistry,
                                      RootSetupPrincipalSelectionRegistry)
        if type(registry) is RootSetupPrincipalSelectionRegistry:
            principal_selector = registry.resolve_adopted_principal_selector(
                self.sessions, session._handle)
            namespace_selector = registry.resolve_adopted_namespace_selector(
                self.sessions, session._handle)
            snapshot = registry.resolve_current_setup_identity(
                principal_selector.selection_handle, namespace_selector.selection_handle,
                session._handle)
            if (snapshot.principal.principal_id != principal.principal_id
                    or snapshot.principal.namespace_id != principal.namespace_id
                    or snapshot.principal_binding_sha256 != principal_selector.binding_sha256
                    or snapshot.namespace_binding_sha256 != namespace_selector.binding_sha256
                    or snapshot.namespace.namespace_id != principal.namespace_id):
                raise BootstrapEnrollmentPending("current Authentik principal and namespace snapshot changed")
            return (principal_selector.binding_sha256, namespace_selector.selection_handle,
                    namespace_selector.binding_sha256,
                    (principal.identity_receipt_handle, principal_selector.selection_handle))
        if type(registry) is RootSetupLocalOwnerIdentityRegistry:
            principal_selector = registry.resolve_adopted_principal_selector(
                self.sessions, session._handle)
            namespace_selector = registry.resolve_adopted_namespace_selector(
                self.sessions, session._handle)
            snapshot = registry.resolve_current_setup_identity(
                principal.receipt_handle, namespace_selector.selection_handle,
                session._handle)
            current = registry.resolve_current_snapshot(session._handle, snapshot.snapshot_handle)
            if (current is not snapshot
                    or principal_selector.identity_kind != "linux-local-owner-v1"
                    or principal_selector.binding_sha256 != principal.principal_binding_sha256
                    or principal_selector.selection_handle != principal.receipt_handle
                    or current.principal.principal_id != principal.principal_id
                    or current.principal.namespace_id != principal.namespace_id
                    or current.namespace_selection_handle != namespace_selector.selection_handle
                    or current.namespace_binding_sha256 != namespace_selector.binding_sha256
                    or current.namespace.namespace_id != principal.namespace_id):
                raise BootstrapEnrollmentPending("current local-owner principal and namespace snapshot changed")
            return (principal.principal_binding_sha256, namespace_selector.selection_handle,
                    namespace_selector.binding_sha256,
                    (principal.owner_identity_receipt_handle,
                     principal.capability_selection_handle))
        raise BootstrapEnrollmentPending("active compiler has no supported principal publication binding")

    def _verify_claim_principal_join(self, claim: RootActivePolicyCompilationClaim,
                                     session: Any) -> None:
        principal = self._resolve_current_principal(session)
        binding, namespace_handle, namespace_binding, _sources = \
            self._resolve_principal_publication_binding(session, principal)
        if (principal.receipt_id != claim.principal_selection_receipt_handle
                or principal.identity_kind != claim.principal_identity_kind
                or binding != claim.principal_binding_sha256
                or namespace_handle != claim.namespace_selection_handle
                or namespace_binding != claim.namespace_binding_sha256):
            raise BootstrapEnrollmentPending("active claim principal or namespace identity binding changed")
        self._verify_owner_overlay_adoptions(claim, session, principal)

    def _verify_owner_overlay_adoptions(self, claim: RootActivePolicyCompilationClaim,
                                        session: Any, principal: Any) -> None:
        from .owner_overlay_publication import collect_owner_overlay_adoptions
        capability = self._precompile_caps.get(claim._reservation_handle)
        if (capability is None or capability._compiler_seal is not self._seal
                or capability._root_setup_session is not session
                or capability._root_prepared_native_bundle is not claim._root_prepared_native_bundle
                or capability.receipt_ids != claim.materialization_receipt_handles):
            raise BootstrapEnrollmentPending("owner-overlay verification lost its exact precompile capability")
        reservation = self.materialization_receipts.resolve_current_precompile_reservation(
            capability.reservation_handle)
        if (reservation != capability._root_reservation
                or reservation.prepared_generation_id != claim.prepared_generation_id
                or reservation.assembly_selection_handle != capability.assembly_selection_handle):
            raise BootstrapEnrollmentPending("owner-overlay verification lost its current native reservation")
        current = collect_owner_overlay_adoptions(
            session, claim._root_prepared_native_bundle, principal,
            claim.choice_adoptions, self.materialization_receipts, reservation,
            capability._root_role_closure)
        if current != claim.owner_overlay_adoptions:
            raise BootstrapEnrollmentPending("owner-overlay source, package, view, or capability adoption changed")
        if (principal.identity_kind == "linux-local-owner-v1"
                and principal.selected_capability_ceiling and not current):
            raise BootstrapEnrollmentPending("selected local-owner capability adoption is absent")
        if (principal.identity_kind != "linux-local-owner-v1" and current):
            raise BootstrapEnrollmentPending("owner-overlay adoption crossed the local-owner identity domain")

    @staticmethod
    def _handles(values: Sequence[str], label: str) -> tuple[str, ...]:
        if (not isinstance(values, (tuple, list)) or not values or len(values) > 128
                or any(not isinstance(item, str) or not _HANDLE.fullmatch(item) for item in values)
                or len(set(values)) != len(values)):
            raise BootstrapEnrollmentError(f"{label} handles are malformed or duplicated")
        return tuple(sorted(values))

    def _get_claim(self, handle: str) -> RootActivePolicyCompilationClaim:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise BootstrapEnrollmentError("active policy publication handle is malformed")
        claim = self._claims.get(handle)
        if claim is None:
            raise BootstrapEnrollmentPending("active policy compilation claim is absent or belongs to another registry")
        return claim

    @staticmethod
    def _claim_record(claim: RootActivePolicyCompilationClaim, state: str,
                      publication_receipt_handle: str | None = None) -> dict[str, Any]:
        return {"schema": 1, "publication_handle": claim.publication_handle,
                "claim_digest": claim.claim_digest, "transaction_handle": claim.transaction_handle,
                "setup_session_id": claim.setup_session_id,
                "prepared_generation_id": claim.prepared_generation_id,
                "expected_selection_catalog_sha256": claim.expected_selection_catalog_sha256,
                "expected_service_generation_digest": claim.expected_service_generation_digest,
                "policy_sha256": claim.compiled_policy_sha256,
                "artifact_catalog_sha256": claim.compiled_artifact_catalog_sha256,
                "selection_sha256": claim.compiled_selection_sha256,
                "authority_core_sha256": claim.authority_core_sha256,
                "authority_core_size_bytes": claim.authority_core_size_bytes,
                "authority_core_schema": claim.authority_core_schema,
                "native_profile_home_crosswalk": _manifest(claim)["native_profile_home_crosswalk"],
                "selection_catalog_sha256": claim.selection_catalog_sha256,
                "observed_root_receipt_handle": claim.observed_root_receipt_handle,
                "principal_selection_receipt_handle": claim.principal_selection_receipt_handle,
                "principal_identity_kind": claim.principal_identity_kind,
                "principal_binding_sha256": claim.principal_binding_sha256,
                "namespace_selection_handle": claim.namespace_selection_handle,
                "namespace_binding_sha256": claim.namespace_binding_sha256,
                "owner_overlay_adoptions": _owner_overlay_adoption_rows(
                    claim.owner_overlay_adoptions),
                "runtime_receipt_handles": list(claim.runtime_receipt_handles),
                "materialization_receipt_handles": list(claim.materialization_receipt_handles),
                "publication_receipt_handle": publication_receipt_handle,
                "issued_monotonic": claim.issued_monotonic,
                "expires_monotonic": claim.expires_monotonic,
                "state": state}

    def _persist_claim_bundle(self, claim: RootActivePolicyCompilationClaim) -> None:
        prefix = self._claim_root / claim.publication_handle
        selection_bytes = _canonical(dict(claim.selection_document))
        self._write_immutable_bytes(prefix.with_suffix(".policy"), claim.policy_bytes)
        self._write_immutable_bytes(prefix.with_suffix(".catalog"), claim.artifact_catalog_bytes)
        self._write_immutable_bytes(prefix.with_suffix(".selection"), selection_bytes)
        self._write_immutable_bytes(prefix.with_suffix(".authority"), claim.authority_core_bytes)
        self._write_immutable_bytes(prefix.with_suffix(".native-profile-home-crosswalk"),
                                    claim.native_profile_home_crosswalk_bytes)
        _write_json(prefix.with_suffix(".claim.json"), {
            "schema": 1,
            "publication_handle": claim.publication_handle,
            "claim_digest": claim.claim_digest,
            "manifest": _manifest(claim),
            "policy_sha256": claim.compiled_policy_sha256,
            "artifact_catalog_sha256": claim.compiled_artifact_catalog_sha256,
            "selection_sha256": claim.compiled_selection_sha256,
            "authority_core_sha256": claim.authority_core_sha256,
            "authority_core_size_bytes": claim.authority_core_size_bytes,
            "authority_core_schema": claim.authority_core_schema,
            "native_profile_home_crosswalk": _manifest(claim)["native_profile_home_crosswalk"],
        }, exclusive=True)

    def _verify_claim_bundle(self, claim: RootActivePolicyCompilationClaim) -> None:
        prefix = self._claim_root / claim.publication_handle
        policy = _read_immutable_bytes(prefix.with_suffix(".policy"))
        catalog = _read_immutable_bytes(prefix.with_suffix(".catalog"))
        selection = _read_immutable_bytes(prefix.with_suffix(".selection"))
        authority_core = _read_immutable_bytes(prefix.with_suffix(".authority"))
        crosswalk = _read_immutable_bytes(prefix.with_suffix(".native-profile-home-crosswalk"))
        record = _read_json(prefix.with_suffix(".claim.json"))
        expected = {
            "schema": 1, "publication_handle": claim.publication_handle,
            "claim_digest": claim.claim_digest, "manifest": _manifest(claim),
            "policy_sha256": _sha(policy), "artifact_catalog_sha256": _sha(catalog),
            "selection_sha256": _sha(selection),
            "authority_core_sha256": _sha(authority_core),
            "authority_core_size_bytes": len(authority_core),
            "authority_core_schema": claim.authority_core_schema,
            "native_profile_home_crosswalk": _manifest(claim)["native_profile_home_crosswalk"],
        }
        if (policy != claim.policy_bytes or catalog != claim.artifact_catalog_bytes
                or selection != _canonical(dict(claim.selection_document))
                or crosswalk != claim.native_profile_home_crosswalk_bytes or record != expected):
            raise BootstrapEnrollmentPending("durable active compilation claim or output bytes changed")

    def _write_state(self, claim: RootActivePolicyCompilationClaim, state: str,
                     publication_receipt_handle: str | None) -> None:
        path = self._claim_root / ("transaction-" + claim.transaction_handle + ".json")
        prior = _read_json(path)
        if (prior.get("publication_handle") != claim.publication_handle
                or prior.get("claim_digest") != claim.claim_digest
                or prior.get("state") != "claimed"):
            raise BootstrapEnrollmentPending("durable active policy claim state changed")
        _write_json(path, self._claim_record(claim, state, publication_receipt_handle))

    def _close_lock(self, handle: str) -> None:
        fd = self._locks.pop(handle, None)
        if fd is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @staticmethod
    def _require_root() -> None:
        if os.geteuid() != 0 or os.getuid() != 0 or not sys_platform_linux():
            raise BootstrapEnrollmentPending("active policy compilation requires installed Linux root authority")


def sys_platform_linux() -> bool:
    import sys
    return sys.platform.startswith("linux") and Path("/proc/sys/kernel/ostype").exists()
