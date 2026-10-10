"""Root-only immutable CAS publication of finite native materialization outputs.

This registry is deliberately separate from downloaded ``RootArtifactReceipt``
records and from ``NativeMaterializationReceipt`` discovery evidence. A sealed
setup binding selects output roles and artifact identities; this module stores
the exact bytes it is given under a root-owned content-addressed object and
issues a transaction-scoped, path-free receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import tarfile
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol, Sequence


_ROLE_KINDS = {
    "resources-source-bundle": "source-archive",
    "native-compiled-closure": "compiled-closure",
    "native-entrypoint-manifest": "entrypoint-json",
    "native-action-resolver": "resolver-json",
    "native-boundary-overlay": "boundary-overlay",
    "native-candidate-index": "candidate-index-json",
}
_HEX = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_ARTIFACT_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
_PACKAGE_GENERATION = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_HANDLE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_MAX_OUTPUT_BYTES = {
    "resources-source-bundle": 1_000_000,
    "native-compiled-closure": 128 * 1024 * 1024,
    "native-entrypoint-manifest": 2 * 1024 * 1024,
    "native-action-resolver": 2 * 1024 * 1024,
    "native-boundary-overlay": 2 * 1024 * 1024,
    "native-candidate-index": 2 * 1024 * 1024,
}
_RESOURCES_ARTIFACT_ID = "resources-source-113f42d33be9e0c8f0f47f5ca998e687323dec83"
_RESOURCES_ARCHIVE_SHA256 = "b09459b609676cff30f151ac7db1fc405039b8871486b483af563ba7f63e7cd1"
_RESOURCES_ARCHIVE_SIZE = 295_368
_GENERATED_ROLES = frozenset(_ROLE_KINDS) - {"resources-source-bundle"}
_ROOT_FACTORY_SEAL = object()


class NativeOutputReceiptDenied(PermissionError):
    """A fixed native output could not be published or resolved safely."""


@dataclass(frozen=True, slots=True)
class NativeOutputMember:
    path: str
    sha256: str
    size_bytes: int
    mode: int


@dataclass(frozen=True, slots=True)
class NativeOutputSelection:
    """Root-resolved transaction fields; no paths or caller-selected IDs."""

    artifact_id: str
    artifact_role: str
    output_kind: str
    package_id: str
    profile_id: str
    generation: str
    setup_session_id: str
    transaction_handle: str
    plan_digest: str
    prepared_generation_id: str
    compiler_artifact_id: str | None
    compiler_sha256: str | None
    producer_artifact_id: str
    producer_sha256: str
    source_receipt_handles: tuple[str, ...]
    member_tree_sha256: str
    output_sha256: str
    output_size_bytes: int
    compiled_closure_sha256: str | None
    expires_monotonic: float


class RootNativeOutputBinding(Protocol):
    """Sealed root setup capability that revalidates role and current plan."""

    def authorize_native_output(
        self, *, artifact_role: str, output_kind: str,
        member_tree_sha256: str, output_sha256: str,
        output_size_bytes: int,
    ) -> NativeOutputSelection: ...

    def revalidate_native_output(self, selection: NativeOutputSelection) -> bool: ...

    def resolve_packaged_resources_source(
        self, *, prepared_setup_receipt_handle: str,
        verified_installer_release_receipt: Any,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True)
class RuntimeArtifactReceipt:
    """Path-free immutable receipt matching the v27 runtime artifact contract."""

    schema: int
    artifact_id: str
    artifact_role: str
    sha256: str
    size_bytes: int
    store_id: str
    receipt_id: str
    setup_session_id: str
    transaction_handle: str
    plan_digest: str
    prepared_generation_id: str
    compiler_artifact_id: str | None
    compiler_sha256: str | None
    producer_artifact_id: str
    producer_sha256: str
    source_receipt_handles: tuple[str, ...]
    output_kind: str
    issued_monotonic: float
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class NativeOutputReservation:
    """Non-publication state held while the active policy CAS is prepared."""

    reservation_handle: str
    publication_handle: str
    claim_digest: str
    prepared_generation_id: str
    receipt_ids: tuple[str, ...]


class RootMaterializationReceiptRegistry:
    """Publish exact root-compiled output bytes to an immutable local CAS.

    ``cas_root`` and ``journal_root`` are supplied by the setup factory from
    current installed policy. Public methods take no filesystem paths.
    """

    def __init__(self, binding: RootNativeOutputBinding, *, cas_root: Path,
                 journal_root: Path, authority_uid: int = 0,
                 monotonic=time.monotonic, _factory_seal: object | None = None):
        if _factory_seal is not _ROOT_FACTORY_SEAL:
            raise NativeOutputReceiptDenied("native output registry construction is restricted to the root setup factory")
        if (authority_uid != 0 or not callable(getattr(binding, "authorize_native_output", None))
                or not callable(getattr(binding, "revalidate_native_output", None))):
            raise NativeOutputReceiptDenied("native output registry requires the root setup binding")
        self._binding = binding
        self._cas_root = _absolute_directory(cas_root)
        self._journal_root = _absolute_directory(journal_root)
        if self._cas_root == self._journal_root or self._cas_root in self._journal_root.parents:
            raise NativeOutputReceiptDenied("native output CAS and receipt journal roots must be distinct")
        self._authority_uid = authority_uid
        self._monotonic = monotonic
        self._database = self._journal_root / "native-output-receipts.sqlite3"
        self._initialize()

    @classmethod
    def _from_root_factory(cls, *, binding: RootNativeOutputBinding,
                           cas_root: Path, journal_root: Path):
        """Root-private constructor; the caller resolves all roots from policy."""
        return cls(binding, cas_root=cas_root, journal_root=journal_root,
                   authority_uid=0, _factory_seal=_ROOT_FACTORY_SEAL)

    def publish_selected(self, *, artifact_role: str, output_kind: str,
                         payload: bytes,
                         members: Sequence[NativeOutputMember]) -> RuntimeArtifactReceipt:
        """Store a fixed native output and mint its path-free one-use receipt."""
        self._require_root()
        if _ROLE_KINDS.get(artifact_role) != output_kind:
            raise NativeOutputReceiptDenied("native output role and output kind are incompatible")
        if not isinstance(payload, bytes) or not payload:
            raise NativeOutputReceiptDenied("native output payload is empty or not immutable bytes")
        if len(payload) > _MAX_OUTPUT_BYTES[artifact_role]:
            raise NativeOutputReceiptDenied("native output exceeds its role-specific byte bound")
        if artifact_role == "resources-source-bundle" and (
                hashlib.sha256(payload).hexdigest() != _RESOURCES_ARCHIVE_SHA256
                or len(payload) != _RESOURCES_ARCHIVE_SIZE):
            raise NativeOutputReceiptDenied("packaged Resources bundle differs from its immutable source pin")
        normalized_members = _normalize_members(members, allow_source_modes=(artifact_role == "resources-source-bundle"))
        member_digest = _member_manifest_digest(normalized_members)
        payload_digest = hashlib.sha256(payload).hexdigest()
        _verify_payload(artifact_role, output_kind, payload, normalized_members)
        selection = self._binding.authorize_native_output(
            artifact_role=artifact_role, output_kind=output_kind,
            member_tree_sha256=member_digest, output_sha256=payload_digest,
            output_size_bytes=len(payload),
        )
        self._validate_selection(selection, artifact_role, output_kind,
                                 member_digest, payload_digest, len(payload))
        _validate_role_selection_payload(selection, artifact_role, payload)
        self._require_current(selection)
        if artifact_role != "resources-source-bundle":
            self._assert_output_relations(selection, artifact_role, payload)
        store_id = f"artifact:{selection.artifact_id}:{payload_digest}"
        receipt_id = secrets.token_urlsafe(36)
        now = self._monotonic()
        receipt = RuntimeArtifactReceipt(
            1, selection.artifact_id, selection.artifact_role, payload_digest,
            len(payload), store_id, receipt_id, selection.setup_session_id,
            selection.transaction_handle, selection.plan_digest,
            selection.prepared_generation_id, selection.compiler_artifact_id,
            selection.compiler_sha256, selection.producer_artifact_id,
            selection.producer_sha256, selection.source_receipt_handles,
            selection.output_kind, now, selection.expires_monotonic,
        )
        receipt_id = self._begin_record(receipt, member_digest, selection)
        self._publish_cas(payload, payload_digest)
        self._require_current(selection)
        self._mark_issued(receipt_id)
        return self._receipt_from_id(receipt_id)

    def mint_packaged_resources_source(
        self, prepared_setup_receipt_handle: str,
        verified_installer_release_receipt: Any,
    ) -> str:
        """Mint the fixed checked-in Resources source receipt from a verified release.

        The source bytes are resolved by the sealed root setup binding from the
        current verified installer release; this method accepts no archive path
        or arbitrary source identifier.
        """
        self._require_root()
        if not _valid_handle(prepared_setup_receipt_handle):
            raise NativeOutputReceiptDenied("prepared setup receipt handle is malformed")
        try:
            payload = self._binding.resolve_packaged_resources_source(
                prepared_setup_receipt_handle=prepared_setup_receipt_handle,
                verified_installer_release_receipt=verified_installer_release_receipt,
            )
        except Exception:
            raise NativeOutputReceiptDenied("verified installer release has no selected Resources archive") from None
        if (not isinstance(payload, bytes) or len(payload) != _RESOURCES_ARCHIVE_SIZE
                or hashlib.sha256(payload).hexdigest() != _RESOURCES_ARCHIVE_SHA256):
            raise NativeOutputReceiptDenied("root Resources source resolver returned bytes outside the fixed source pin")
        members = _archive_manifest(payload, source_archive=True)
        _verify_resources_source(payload)
        receipt = self.publish_selected(
            artifact_role="resources-source-bundle", output_kind="source-archive",
            payload=payload, members=members,
        )
        if receipt.artifact_id != _RESOURCES_ARTIFACT_ID:
            raise NativeOutputReceiptDenied("Resources source receipt is bound to an unexpected artifact identity")
        return receipt.receipt_id

    def resolve_for_activation(self, receipt_id: str, *, artifact_role: str,
                               prepared_generation_id: str) -> RuntimeArtifactReceipt:
        """Resolve and consume one current output receipt exactly once."""
        self._require_root()
        if artifact_role not in _ROLE_KINDS or not _valid_handle(receipt_id):
            raise NativeOutputReceiptDenied("native output receipt lookup is malformed")
        record = self._get_record(receipt_id)
        if (record["artifact_role"] != artifact_role
                or record["prepared_generation_id"] != prepared_generation_id
                or record["state"] != "issued"
                or record["expires_monotonic"] <= self._monotonic()):
            raise NativeOutputReceiptDenied("native output receipt is stale, spent, or for another role")
        selection = self._binding.authorize_native_output(
            artifact_role=record["artifact_role"], output_kind=record["output_kind"],
            member_tree_sha256=record["member_tree_sha256"],
            output_sha256=record["sha256"], output_size_bytes=record["size_bytes"],
        )
        self._validate_selection(
            selection, record["artifact_role"], record["output_kind"],
            record["member_tree_sha256"], record["sha256"], record["size_bytes"])
        if record["compiled_closure_sha256"] != selection.compiled_closure_sha256:
            raise NativeOutputReceiptDenied("native output selection closure-tree digest changed")
        self._require_current(selection)
        self._verify_cas(record["sha256"], record["size_bytes"])
        path = self._cas_root / record["sha256"][:2] / record["sha256"]
        payload = _read_private_file(path, _MAX_OUTPUT_BYTES[record["artifact_role"]])
        members = _stored_member_manifest(record["artifact_role"], payload)
        _verify_payload(record["artifact_role"], record["output_kind"], payload, members)
        if _member_manifest_digest(members) != record["member_tree_sha256"]:
            raise NativeOutputReceiptDenied("native CAS member tree digest changed")
        _validate_role_selection_payload(selection, record["artifact_role"], payload)
        if record["artifact_role"] != "resources-source-bundle":
            self._assert_output_relations(selection, record["artifact_role"], payload,
                                          resolving=True)
        with self._connect() as db:
            changed = db.execute(
                "UPDATE outputs SET state='consumed' WHERE receipt_id=? AND state='issued' AND expires_monotonic>?",
                (receipt_id, self._monotonic()),
            ).rowcount
        if changed != 1:
            raise NativeOutputReceiptDenied("native output receipt was consumed concurrently")
        return _receipt_from_record(record)

    def reserve_for_active_compilation(
        self, receipt_ids: Sequence[str], *, prepared_generation_id: str,
        publication_handle: str, claim_digest: str,
    ) -> NativeOutputReservation:
        """Reserve every generated receipt for one active-policy publication.

        This is deliberately non-consuming: the compiler may revalidate while
        atomically publishing policy, and must call ``release`` on rollback or
        ``complete`` after it has a typed root publication receipt.
        """
        self._require_root()
        role_ids = _normalize_reservation_ids(receipt_ids)
        if (not _valid_identifier(prepared_generation_id)
                or not _valid_handle(publication_handle)
                or not isinstance(claim_digest, str) or not _HEX.fullmatch(claim_digest)):
            raise NativeOutputReceiptDenied("active compilation reservation identity is malformed")
        records = [self._get_record(receipt_id) for receipt_id in role_ids]
        if {record["artifact_role"] for record in records} != _GENERATED_ROLES:
            raise NativeOutputReceiptDenied("active compilation requires the complete fixed native output role set")
        first = records[0]
        for record in records:
            if (record["state"] != "issued"
                    or record["prepared_generation_id"] != prepared_generation_id
                    or record["transaction_handle"] != first["transaction_handle"]
                    or record["setup_session_id"] != first["setup_session_id"]
                    or record["plan_digest"] != first["plan_digest"]
                    or record["compiled_closure_sha256"] != first["compiled_closure_sha256"]
                    or record["expires_monotonic"] <= self._monotonic()):
                raise NativeOutputReceiptDenied("active compilation receipts are stale or span selections")
            self._verify_record_current(record)
        selection = self._selection_for_record(first)
        for record in records:
            if record["artifact_role"] != "resources-source-bundle":
                payload = self._read_record_payload(record)
                self._assert_output_relations(selection, record["artifact_role"], payload)
        reservation = NativeOutputReservation(
            secrets.token_urlsafe(36), publication_handle, claim_digest,
            prepared_generation_id, role_ids)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                for receipt_id in role_ids:
                    changed = db.execute(
                        "UPDATE outputs SET state='reserved' WHERE receipt_id=? AND state='issued' AND expires_monotonic>?",
                        (receipt_id, self._monotonic()),
                    ).rowcount
                    if changed != 1:
                        raise NativeOutputReceiptDenied("native output changed during active compilation reservation")
                db.execute(
                    "INSERT INTO reservations VALUES(?,?,?,?,?,?,?)",
                    (reservation.reservation_handle, publication_handle, claim_digest,
                     prepared_generation_id, json.dumps(role_ids), first["transaction_handle"],
                     min(record["expires_monotonic"] for record in records)),
                )
            except Exception:
                db.rollback()
                raise
            else:
                db.commit()
        return reservation

    def verify_active_compilation(
        self, reservation_handle: str, *, prepared_generation_id: str,
        publication_handle: str, claim_digest: str,
    ) -> tuple[RuntimeArtifactReceipt, ...]:
        """Revalidate a reservation without consuming its output receipts."""
        reservation = self._get_reservation(
            reservation_handle, prepared_generation_id=prepared_generation_id,
            publication_handle=publication_handle, claim_digest=claim_digest,
        )
        records = [self._get_record(receipt_id) for receipt_id in reservation.receipt_ids]
        for record in records:
            if record["state"] != "reserved":
                raise NativeOutputReceiptDenied("active compilation output reservation is no longer held")
            self._verify_record_current(record)
        if {record["artifact_role"] for record in records} != _GENERATED_ROLES:
            raise NativeOutputReceiptDenied("active compilation reservation lost a fixed output role")
        selection = self._selection_for_record(records[0])
        for record in records:
            payload = self._read_record_payload(record)
            self._assert_output_relations(selection, record["artifact_role"], payload,
                                          resolving=True)
        return tuple(_receipt_from_record(record) for record in records)

    def complete_active_compilation(
        self, reservation_handle: str, publication_receipt: Any, *,
        prepared_generation_id: str, publication_handle: str,
        claim_digest: str,
    ) -> tuple[RuntimeArtifactReceipt, ...]:
        """Consume the reserved output closure after root policy publication.

        The publication object remains opaque here. The sealed setup binding
        must verify its concrete type and bind it to this reservation before
        any receipt is spent.
        """
        reservation = self._get_reservation(
            reservation_handle, prepared_generation_id=prepared_generation_id,
            publication_handle=publication_handle, claim_digest=claim_digest,
        )
        verifier = getattr(self._binding, "verify_native_publication_receipt", None)
        if not callable(verifier):
            raise NativeOutputReceiptDenied("root binding cannot verify active publication receipts")
        receipt_handles = getattr(publication_receipt, "materialization_receipt_handles", None)
        if (getattr(publication_receipt, "publication_handle", None) != publication_handle
                or getattr(publication_receipt, "claim_digest", None) != claim_digest
                or getattr(publication_receipt, "prepared_generation_id", None) != prepared_generation_id
                or getattr(publication_receipt, "state", None) not in {"active-committed", "active", "committed"}
                or not isinstance(receipt_handles, tuple)
                or not set(reservation.receipt_ids).issubset(receipt_handles)):
            raise NativeOutputReceiptDenied("typed active publication receipt does not bind reserved native outputs")
        try:
            verified = verifier(reservation, publication_receipt)
        except Exception:
            verified = False
        if verified is not True:
            raise NativeOutputReceiptDenied("active policy publication receipt does not bind this reservation")
        receipts = self.verify_active_compilation(
            reservation_handle, prepared_generation_id=prepared_generation_id,
            publication_handle=publication_handle, claim_digest=claim_digest)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                for receipt in receipts:
                    changed = db.execute(
                        "UPDATE outputs SET state='consumed' WHERE receipt_id=? AND state='reserved' AND expires_monotonic>?",
                        (receipt.receipt_id, self._monotonic()),
                    ).rowcount
                    if changed != 1:
                        raise NativeOutputReceiptDenied("active compilation receipt changed before commit")
                changed = db.execute(
                    "UPDATE reservations SET state='completed' WHERE reservation_handle=? AND state='reserved'",
                    (reservation_handle,),
                ).rowcount
                if changed != 1:
                    raise NativeOutputReceiptDenied("active compilation reservation was already completed")
            except Exception:
                db.rollback()
                raise
            else:
                db.commit()
        return receipts

    def release_active_compilation(
        self, reservation_handle: str, *, prepared_generation_id: str,
        publication_handle: str, claim_digest: str,
    ) -> None:
        """Release an uncommitted reservation for compiler rollback/retry."""
        reservation = self._get_reservation(
            reservation_handle, prepared_generation_id=prepared_generation_id,
            publication_handle=publication_handle, claim_digest=claim_digest,
        )
        with self._connect() as db:
            state = db.execute("SELECT state FROM reservations WHERE reservation_handle=?",
                               (reservation_handle,)).fetchone()["state"]
        if state == "released":
            return
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                for receipt_id in reservation.receipt_ids:
                    db.execute("UPDATE outputs SET state='issued' WHERE receipt_id=? AND state='reserved'",
                               (receipt_id,))
                changed = db.execute(
                    "UPDATE reservations SET state='released' WHERE reservation_handle=? AND state='reserved'",
                    (reservation_handle,),
                ).rowcount
                if changed != 1:
                    raise NativeOutputReceiptDenied("active compilation reservation is no longer held")
            except Exception:
                db.rollback()
                raise
            else:
                db.commit()

    def _verify_record_current(self, record: Mapping[str, Any]) -> None:
        selection = self._selection_for_record(record)
        self._require_current(selection)
        self._verify_cas(record["sha256"], record["size_bytes"])
        payload = self._read_record_payload(record)
        members = _stored_member_manifest(record["artifact_role"], payload)
        _verify_payload(record["artifact_role"], record["output_kind"], payload, members)
        if _member_manifest_digest(members) != record["member_tree_sha256"]:
            raise NativeOutputReceiptDenied("native CAS member tree digest changed")
        _validate_role_selection_payload(selection, record["artifact_role"], payload)

    def _selection_for_record(self, record: Mapping[str, Any]) -> NativeOutputSelection:
        selection = self._binding.authorize_native_output(
            artifact_role=record["artifact_role"], output_kind=record["output_kind"],
            member_tree_sha256=record["member_tree_sha256"],
            output_sha256=record["sha256"], output_size_bytes=record["size_bytes"],
        )
        self._validate_selection(selection, record["artifact_role"], record["output_kind"],
                                 record["member_tree_sha256"], record["sha256"],
                                 record["size_bytes"])
        return selection

    def _read_record_payload(self, record: Mapping[str, Any]) -> bytes:
        path = self._cas_root / record["sha256"][:2] / record["sha256"]
        return _read_private_file(path, _MAX_OUTPUT_BYTES[record["artifact_role"]])

    def _get_reservation(self, handle: str, *, prepared_generation_id: str,
                         publication_handle: str, claim_digest: str) -> NativeOutputReservation:
        self._require_root()
        if not _valid_handle(handle):
            raise NativeOutputReceiptDenied("active compilation reservation handle is malformed")
        with self._connect() as db:
            row = db.execute("SELECT * FROM reservations WHERE reservation_handle=?", (handle,)).fetchone()
        if row is None or row["state"] not in {"reserved", "released"}:
            raise NativeOutputReceiptDenied("active compilation reservation is stale or spent")
        if row["expires_monotonic"] <= self._monotonic():
            raise NativeOutputReceiptDenied("active compilation reservation is expired")
        if (row["prepared_generation_id"] != prepared_generation_id
                or row["publication_handle"] != publication_handle
                or row["claim_digest"] != claim_digest):
            raise NativeOutputReceiptDenied("active compilation reservation belongs to another claim")
        return NativeOutputReservation(handle, publication_handle, claim_digest,
                                       prepared_generation_id, tuple(json.loads(row["receipt_ids"])))

    def _validate_selection(self, selection: NativeOutputSelection,
                            role: str, kind: str, member_digest: str,
                            output_digest: str, output_size: int) -> None:
        if (not isinstance(selection, NativeOutputSelection)
                or selection.artifact_role != role
                or selection.output_kind != kind
                or not isinstance(selection.artifact_id, str)
                or not _ARTIFACT_ID.fullmatch(selection.artifact_id)
                or not isinstance(selection.package_id, str)
                or not _PACKAGE_GENERATION.fullmatch(selection.package_id)
                or not isinstance(selection.profile_id, str)
                or not _PACKAGE_GENERATION.fullmatch(selection.profile_id)
                or not isinstance(selection.generation, str)
                or not _PACKAGE_GENERATION.fullmatch(selection.generation)
                or not _valid_identifier(selection.setup_session_id)
                or not _valid_handle(selection.transaction_handle)
                or not _HEX.fullmatch(selection.plan_digest)
                or not _valid_identifier(selection.prepared_generation_id)
                or (role == "resources-source-bundle" and
                    (selection.compiler_artifact_id is not None or selection.compiler_sha256 is not None))
                or (role != "resources-source-bundle" and
                    (not _valid_identifier(selection.compiler_artifact_id)
                     or not isinstance(selection.compiler_sha256, str)
                     or not _HEX.fullmatch(selection.compiler_sha256)))
                or (role == "resources-source-bundle" and selection.compiled_closure_sha256 is not None)
                or (role != "resources-source-bundle" and
                    (not isinstance(selection.compiled_closure_sha256, str)
                     or not _HEX.fullmatch(selection.compiled_closure_sha256)))
                or not _valid_identifier(selection.producer_artifact_id)
                or not isinstance(selection.producer_sha256, str)
                or not _HEX.fullmatch(selection.producer_sha256)
                or (not selection.source_receipt_handles and role != "resources-source-bundle")
                or len(selection.source_receipt_handles) > 8
                or len(set(selection.source_receipt_handles)) != len(selection.source_receipt_handles)
                or any(not _valid_handle(handle) for handle in selection.source_receipt_handles)
                or selection.member_tree_sha256 != member_digest
                or selection.output_sha256 != output_digest
                or selection.output_size_bytes != output_size
                or type(selection.expires_monotonic) not in (int, float)
                or selection.expires_monotonic <= self._monotonic()):
            raise NativeOutputReceiptDenied("sealed setup binding rejected or malformed the fixed output selection")
        expected_id = _expected_artifact_id(role, selection.package_id, selection.generation)
        if selection.artifact_id != expected_id:
            raise NativeOutputReceiptDenied("sealed setup binding returned an unexpected fixed artifact identity")

    def _require_current(self, selection: NativeOutputSelection) -> None:
        self._require_root()
        try:
            current = self._binding.revalidate_native_output(selection)
        except Exception:
            raise NativeOutputReceiptDenied("native output selection is no longer current") from None
        if current is not True:
            raise NativeOutputReceiptDenied("native output selection is no longer current")

    def _initialize(self) -> None:
        _verify_private_directory(self._cas_root, self._authority_uid)
        _verify_private_directory(self._journal_root, self._authority_uid)
        if self._database.exists() or self._database.is_symlink():
            info = self._database.lstat()
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != self._authority_uid or stat.S_IMODE(info.st_mode) != 0o600):
                raise NativeOutputReceiptDenied("native output journal custody is invalid")
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS outputs(
                    receipt_id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL,
                    artifact_role TEXT NOT NULL, sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL, store_id TEXT NOT NULL,
                    setup_session_id TEXT NOT NULL, transaction_handle TEXT NOT NULL,
                    plan_digest TEXT NOT NULL, prepared_generation_id TEXT NOT NULL,
                    compiler_artifact_id TEXT, compiler_sha256 TEXT,
                    producer_artifact_id TEXT NOT NULL, producer_sha256 TEXT NOT NULL,
                    source_receipt_handles TEXT NOT NULL, output_kind TEXT NOT NULL,
                    member_tree_sha256 TEXT NOT NULL,
                    compiled_closure_sha256 TEXT,
                    issued_monotonic REAL NOT NULL, expires_monotonic REAL NOT NULL,
                    state TEXT NOT NULL,
                    UNIQUE(transaction_handle, artifact_role));
                CREATE TABLE IF NOT EXISTS reservations(
                    reservation_handle TEXT PRIMARY KEY,
                    publication_handle TEXT NOT NULL,
                    claim_digest TEXT NOT NULL,
                    prepared_generation_id TEXT NOT NULL,
                    receipt_ids TEXT NOT NULL,
                    transaction_handle TEXT NOT NULL,
                    expires_monotonic REAL NOT NULL,
                    state TEXT NOT NULL);
            """)
            columns = tuple(row["name"] for row in db.execute("PRAGMA table_info(outputs)"))
            reservation_columns = tuple(row["name"] for row in db.execute("PRAGMA table_info(reservations)"))
        expected_columns = (
            "receipt_id", "artifact_id", "artifact_role", "sha256", "size_bytes",
            "store_id", "setup_session_id", "transaction_handle", "plan_digest",
            "prepared_generation_id", "compiler_artifact_id", "compiler_sha256",
            "producer_artifact_id", "producer_sha256", "source_receipt_handles",
            "output_kind", "member_tree_sha256", "compiled_closure_sha256", "issued_monotonic",
            "expires_monotonic", "state",
        )
        if columns != expected_columns:
            raise NativeOutputReceiptDenied("native output journal schema is not the reviewed version")
        if reservation_columns != ("reservation_handle", "publication_handle", "claim_digest",
                                   "prepared_generation_id", "receipt_ids", "transaction_handle",
                                   "expires_monotonic", "state"):
            raise NativeOutputReceiptDenied("native output reservation journal schema is not the reviewed version")
        self._database.chmod(0o600)

    def _connect(self):
        return _connection(self._database)

    def _publish_cas(self, payload: bytes, digest: str) -> None:
        shard = self._cas_root / digest[:2]
        _ensure_private_child(shard, self._authority_uid)
        final = shard / digest
        if final.exists() or final.is_symlink():
            self._verify_cas(digest, len(payload))
            return
        fd, temporary_name = tempfile.mkstemp(prefix=".native-output-", dir=shard)
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, 0o400)
            os.fchown(fd, self._authority_uid, 0)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, final, follow_symlinks=False)
            except FileExistsError:
                self._verify_cas(digest, len(payload))
            _fsync_directory(shard)
        except OSError:
            raise NativeOutputReceiptDenied("root native CAS publication failed") from None
        finally:
            try:
                temporary.unlink()
            except OSError:
                pass

    def _verify_cas(self, digest: str, size: int) -> None:
        path = self._cas_root / digest[:2] / digest
        try:
            info = path.lstat()
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != self._authority_uid or info.st_gid != 0 or info.st_size != size
                    or stat.S_IMODE(info.st_mode) != 0o400):
                raise NativeOutputReceiptDenied("root native CAS object custody is invalid")
            actual = _hash_path_nofollow(path)
        except OSError:
            raise NativeOutputReceiptDenied("root native CAS object is unavailable") from None
        if actual != digest:
            raise NativeOutputReceiptDenied("root native CAS object digest changed")

    def _begin_record(self, receipt: RuntimeArtifactReceipt, manifest_digest: str,
                      selection: NativeOutputSelection) -> str:
        with self._connect() as db:
            existing = db.execute(
                "SELECT * FROM outputs WHERE transaction_handle=? AND artifact_role=?",
                (receipt.transaction_handle, receipt.artifact_role),
            ).fetchone()
            if existing is not None:
                row = dict(existing)
                same = (row["artifact_id"] == receipt.artifact_id
                        and row["sha256"] == receipt.sha256
                        and row["size_bytes"] == receipt.size_bytes
                        and row["member_tree_sha256"] == manifest_digest
                        and row["setup_session_id"] == receipt.setup_session_id
                        and row["transaction_handle"] == receipt.transaction_handle
                        and row["plan_digest"] == receipt.plan_digest
                        and row["prepared_generation_id"] == receipt.prepared_generation_id
                        and row["compiler_artifact_id"] == receipt.compiler_artifact_id
                        and row["compiler_sha256"] == receipt.compiler_sha256
                        and row["producer_artifact_id"] == receipt.producer_artifact_id
                        and row["producer_sha256"] == receipt.producer_sha256
                        and row["source_receipt_handles"] == json.dumps(receipt.source_receipt_handles)
                        and row["output_kind"] == receipt.output_kind
                        and row["compiled_closure_sha256"] == selection.compiled_closure_sha256)
                if not same:
                    raise NativeOutputReceiptDenied("a fixed output role already has a receipt in this transaction")
                if row["state"] != "pending":
                    raise NativeOutputReceiptDenied("a fixed output role already has a receipt in this transaction")
                if row["expires_monotonic"] <= self._monotonic():
                    changed = db.execute(
                        "UPDATE outputs SET receipt_id=?,store_id=?,issued_monotonic=?,expires_monotonic=? "
                        "WHERE receipt_id=? AND state='pending' AND expires_monotonic<=?",
                        (receipt.receipt_id, receipt.store_id, receipt.issued_monotonic,
                         receipt.expires_monotonic, row["receipt_id"], self._monotonic()),
                    ).rowcount
                    if changed != 1:
                        raise NativeOutputReceiptDenied("expired native output publication changed concurrently")
                    return receipt.receipt_id
                return row["receipt_id"]
            try:
                db.execute("""INSERT INTO outputs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (receipt.receipt_id, receipt.artifact_id, receipt.artifact_role,
                     receipt.sha256, receipt.size_bytes, receipt.store_id,
                     receipt.setup_session_id, receipt.transaction_handle,
                     receipt.plan_digest, receipt.prepared_generation_id,
                     receipt.compiler_artifact_id, receipt.compiler_sha256,
                     receipt.producer_artifact_id, receipt.producer_sha256,
                     json.dumps(receipt.source_receipt_handles), receipt.output_kind,
                     manifest_digest, selection.compiled_closure_sha256, receipt.issued_monotonic,
                     receipt.expires_monotonic, "pending"))
            except sqlite3.IntegrityError:
                raise NativeOutputReceiptDenied("a fixed output role already has a receipt in this transaction") from None
        return receipt.receipt_id

    def _mark_issued(self, receipt_id: str) -> None:
        with self._connect() as db:
            changed = db.execute("UPDATE outputs SET state='issued' WHERE receipt_id=? AND state='pending'",
                                 (receipt_id,)).rowcount
        if changed != 1:
            raise NativeOutputReceiptDenied("native output receipt publication state changed")

    def _receipt_from_id(self, receipt_id: str) -> RuntimeArtifactReceipt:
        return _receipt_from_record(self._get_record(receipt_id))

    def _assert_output_relations(self, selection: NativeOutputSelection, role: str,
                                 payload: bytes, *, resolving: bool = False) -> None:
        roles = set(_ROLE_KINDS) - {"resources-source-bundle"}
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM outputs WHERE transaction_handle=? AND artifact_role IN (%s)" %
                ",".join("?" for _ in roles),
                (selection.transaction_handle, *sorted(roles)),
            ).fetchall()
        records = {row["artifact_role"]: dict(row) for row in rows}
        if resolving and not roles.issubset(records):
            raise NativeOutputReceiptDenied("all native output roles must be published before activation")
        payloads = {role: payload}
        for other_role, record in records.items():
            if other_role == role:
                continue
            states = {"issued", "reserved", "consumed"} if resolving else {"issued", "reserved"}
            same_selection = (
                record["setup_session_id"] == selection.setup_session_id
                and record["transaction_handle"] == selection.transaction_handle
                and record["plan_digest"] == selection.plan_digest
                and record["prepared_generation_id"] == selection.prepared_generation_id
                and record["compiler_artifact_id"] == selection.compiler_artifact_id
                and record["compiler_sha256"] == selection.compiler_sha256
                and record["producer_artifact_id"] == selection.producer_artifact_id
                and record["producer_sha256"] == selection.producer_sha256
                and record["compiled_closure_sha256"] == selection.compiled_closure_sha256
                and record["source_receipt_handles"] == json.dumps(selection.source_receipt_handles)
                and record["artifact_id"] == _expected_artifact_id(
                    other_role, selection.package_id, selection.generation)
            )
            if (not same_selection or record["state"] not in states
                    or record["expires_monotonic"] <= self._monotonic()):
                raise NativeOutputReceiptDenied("native output counterpart receipt is not current")
            self._verify_cas(record["sha256"], record["size_bytes"])
            path = self._cas_root / record["sha256"][:2] / record["sha256"]
            payloads[other_role] = _read_private_file(path, _MAX_OUTPUT_BYTES[other_role])
        closure = payloads.get("native-compiled-closure")
        if closure is None:
            if resolving:
                raise NativeOutputReceiptDenied("compiled closure receipt is required for native outputs")
            return
        embedded_index = _read_archive_member(closure, "catalog/native-candidates.json")
        candidate = payloads.get("native-candidate-index")
        if candidate is not None and candidate != embedded_index:
            raise NativeOutputReceiptDenied("standalone candidate index differs from the selected closure member")
        manifest = payloads.get("native-entrypoint-manifest")
        if manifest is not None:
            embedded_manifest = _read_archive_member(closure, "manifest.json")
            if manifest != embedded_manifest:
                raise NativeOutputReceiptDenied("entrypoint receipt differs from the selected closure manifest")
            _verify_closure_tree_manifest(manifest, closure)
            pin = _parse_canonical_json(manifest)["candidate_index"]
            if (pin["sha256"] != hashlib.sha256(embedded_index).hexdigest()
                    or pin["size_bytes"] != len(embedded_index)):
                raise NativeOutputReceiptDenied("entrypoint candidate pin differs from the closure member")
        resolver = payloads.get("native-action-resolver")
        if resolver is not None and resolver != _read_archive_member(closure, "resolver/resolver"):
            raise NativeOutputReceiptDenied("resolver receipt differs from the selected closure resolver")
        overlay = payloads.get("native-boundary-overlay")
        if overlay is not None:
            overlay_doc = _verify_boundary_overlay(overlay)
            archive_members = {row.path: row for row in _archive_manifest(closure)}
            for row in overlay_doc["members"]:
                member = archive_members.get("closure/" + row["path"])
                if (member is None or member.sha256 != row["sha256"]
                        or member.size_bytes != row["size_bytes"] or member.mode != row["mode"]):
                    raise NativeOutputReceiptDenied("boundary overlay member differs from the compiled closure")
            try:
                embedded_overlay = _read_archive_member(closure, "overlay/manifest.json")
            except NativeOutputReceiptDenied:
                embedded_overlay = None
            if embedded_overlay is not None and embedded_overlay != overlay:
                raise NativeOutputReceiptDenied("embedded boundary overlay differs from its separate receipt")

    def _get_record(self, receipt_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute("SELECT * FROM outputs WHERE receipt_id=?", (receipt_id,)).fetchone()
        if row is None:
            raise NativeOutputReceiptDenied("native output receipt is unknown")
        value = dict(row)
        value["source_receipt_handles"] = tuple(json.loads(value["source_receipt_handles"]))
        return value

    def _require_root(self) -> None:
        if os.geteuid() != self._authority_uid or self._authority_uid != 0:
            raise NativeOutputReceiptDenied("native output receipt operations require root authority")
        _verify_private_directory(self._cas_root, self._authority_uid)
        _verify_private_directory(self._journal_root, self._authority_uid)


def _normalize_members(members: Sequence[NativeOutputMember], *,
                       allow_source_modes: bool = False) -> tuple[NativeOutputMember, ...]:
    if not isinstance(members, Sequence) or not members or len(members) > 50_000:
        raise NativeOutputReceiptDenied("native output member manifest is empty or oversized")
    result = []
    seen = set()
    for item in members:
        if (not isinstance(item, NativeOutputMember)
                or not isinstance(item.path, str)
                or not _safe_relative(item.path)
                or item.path in seen
                or not isinstance(item.sha256, str) or not _HEX.fullmatch(item.sha256)
                or type(item.size_bytes) is not int or item.size_bytes < 0
                or type(item.mode) is not int or item.mode & ~0o777
                or (not allow_source_modes and item.mode not in {0o644, 0o755})):
            raise NativeOutputReceiptDenied("native output member manifest is malformed")
        seen.add(item.path)
        result.append(item)
    return tuple(sorted(result, key=lambda row: row.path))


def _member_manifest_digest(members: Sequence[NativeOutputMember]) -> str:
    raw = [{"path": item.path, "sha256": item.sha256,
            "size_bytes": item.size_bytes, "mode": item.mode} for item in members]
    return hashlib.sha256(_canonical(raw)).hexdigest()


def _verify_payload(role: str, kind: str, payload: bytes,
                    members: Sequence[NativeOutputMember]) -> None:
    if role in {"resources-source-bundle", "native-compiled-closure"}:
        try:
            archive_mode = "r:*" if role == "resources-source-bundle" else "r:"
            with tarfile.open(fileobj=BytesIO(payload), mode=archive_mode) as archive:
                observed = {}
                seen_paths = set()
                total_uncompressed = 0
                member_count = 0
                previous_path = ""
                for member in archive:
                    member_count += 1
                    if member_count > 100_000:
                        raise NativeOutputReceiptDenied("native archive has too many file and directory records")
                    normalized_name = member.name.rstrip("/")
                    if (not normalized_name or not _safe_relative(normalized_name)
                            or normalized_name in seen_paths):
                        raise NativeOutputReceiptDenied("native CAS archive has unsafe or duplicate paths")
                    if role == "native-compiled-closure":
                        if normalized_name <= previous_path:
                            raise NativeOutputReceiptDenied("compiled closure archive paths are not lexicographically ordered")
                        previous_path = normalized_name
                        if (member.mtime != 0 or member.uid != 0 or member.gid != 0
                                or member.uname or member.gname
                                or set(member.pax_headers) - {"path", "size"}):
                            raise NativeOutputReceiptDenied("compiled closure archive metadata is not deterministic")
                    seen_paths.add(normalized_name)
                    if member.isdir():
                        if role != "resources-source-bundle" and (member.mode & 0o777) != 0o755:
                            raise NativeOutputReceiptDenied("compiled closure directory mode is not fixed at 0755")
                        continue
                    if not member.isfile() or member.issym() or member.islnk():
                        raise NativeOutputReceiptDenied("native CAS archive contains a non-regular or unsafe member")
                    if member.name in observed:
                        raise NativeOutputReceiptDenied("native CAS archive has duplicate member paths")
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise NativeOutputReceiptDenied("native CAS archive member cannot be read")
                    digest = hashlib.sha256()
                    size = 0
                    while block := stream.read(65536):
                        digest.update(block)
                        size += len(block)
                        total_uncompressed += len(block)
                        if total_uncompressed > 512 * 1024 * 1024:
                            raise NativeOutputReceiptDenied("native archive exceeds its uncompressed byte bound")
                    file_mode = member.mode & 0o777
                    if role == "native-compiled-closure" and file_mode not in {0o644, 0o755}:
                        raise NativeOutputReceiptDenied("compiled closure file mode is not a reviewed executable/data mode")
                    observed[member.name] = NativeOutputMember(member.name, digest.hexdigest(), size,
                                                               file_mode)
        except (OSError, tarfile.TarError):
            raise NativeOutputReceiptDenied("native CAS archive is invalid") from None
        if tuple(sorted(observed.values(), key=lambda row: row.path)) != tuple(members):
            raise NativeOutputReceiptDenied("native CAS archive differs from its exact finite member manifest")
        if role == "native-compiled-closure":
            candidate = next((row for row in members
                              if row.path == "catalog/native-candidates.json"), None)
            required = {"manifest.json", "resolver/resolver", "catalog/native-candidates.json"}
            if (candidate is None or candidate.size_bytes > 2 * 1024 * 1024
                    or not required.issubset({row.path for row in members})
                    or not any(row.path.startswith("closure/") for row in members)):
                raise NativeOutputReceiptDenied("compiled closure lacks a required native member")
            _verify_candidate_index(_read_archive_member(payload, candidate.path))
    else:
        if len(members) != 1 or members[0].sha256 != hashlib.sha256(payload).hexdigest() or members[0].size_bytes != len(payload):
            raise NativeOutputReceiptDenied("native output bytes differ from the one-file manifest")
        if members[0].mode != 0o644:
            raise NativeOutputReceiptDenied("native output document mode must be fixed at 0644")
        if kind in {"entrypoint-json", "resolver-json", "candidate-index-json", "boundary-overlay"}:
            value = _parse_canonical_json(payload)
            if not isinstance(value, dict):
                raise NativeOutputReceiptDenied("native JSON output must be an object")
        if role == "native-entrypoint-manifest" and members[0].path != "manifest.json":
            raise NativeOutputReceiptDenied("entrypoint manifest must use its fixed closure member path")
        if role == "native-action-resolver" and members[0].path != "resolver/resolver":
            raise NativeOutputReceiptDenied("native action resolver must use its fixed member path")
        if role == "native-candidate-index":
            if members[0].path != "catalog/native-candidates.json":
                raise NativeOutputReceiptDenied("native candidate index must use its fixed closure member path")
            _verify_candidate_index(payload)
        if role == "native-boundary-overlay":
            _verify_boundary_overlay(payload)
            if members[0].path != "overlay/manifest.json":
                raise NativeOutputReceiptDenied("boundary overlay manifest must use its fixed member path")


def _read_archive_member(payload: bytes, path: str) -> bytes:
    try:
        with tarfile.open(fileobj=BytesIO(payload), mode="r:") as archive:
            member = archive.getmember(path)
            stream = archive.extractfile(member)
            if not member.isfile() or stream is None:
                raise NativeOutputReceiptDenied("native candidate index member is not a regular file")
            return stream.read(2 * 1024 * 1024 + 1)
    except (OSError, KeyError, tarfile.TarError):
        raise NativeOutputReceiptDenied("native candidate index member is unavailable") from None


def _verify_candidate_index(payload: bytes) -> None:
    value = _parse_canonical_json(payload)
    legacy = {"schema", "package_id", "profile_id", "generation", "resolver_sha256", "candidates"}
    projected = legacy | {"registration_projection_sha256", "registrations"}
    if (not isinstance(value, dict) or frozenset(value) not in {frozenset(legacy), frozenset(projected)}
            or value.get("schema") != 1):
        raise NativeOutputReceiptDenied("native candidate index schema is unsupported")
    if (not isinstance(value["package_id"], str) or not _PACKAGE_GENERATION.fullmatch(value["package_id"])
            or not isinstance(value["profile_id"], str) or not _PACKAGE_GENERATION.fullmatch(value["profile_id"])
            or not isinstance(value["generation"], str) or not _PACKAGE_GENERATION.fullmatch(value["generation"])
            or not isinstance(value["resolver_sha256"], str) or not _HEX.fullmatch(value["resolver_sha256"])
            or not isinstance(value["candidates"], list) or len(value["candidates"]) > 1024):
        raise NativeOutputReceiptDenied("native candidate index identity fields are malformed")
    is_projected = set(value) == projected
    registration_rows = value.get("registrations", [])
    if is_projected:
        projection_digest = value["registration_projection_sha256"]
        if (not isinstance(projection_digest, str) or not _HEX.fullmatch(projection_digest)
                or not isinstance(registration_rows, list) or not 1 <= len(registration_rows) <= 1024
                or hashlib.sha256(_canonical(registration_rows)).hexdigest() != projection_digest
                or len(registration_rows) != len(value["candidates"])):
            raise NativeOutputReceiptDenied("native registration projection digest or cardinality is invalid")
        registration_fields = {
            "registration_id", "native_tool_name", "native_server_name", "toolset", "family",
            "adapter_id", "argument_schema", "result_schema", "native_schema_sha256",
            "registration_source_artifact_id", "registration_source_sha256",
            "registration_source_receipt_handle", "handler_kind", "handler_id",
            "selector_fields", "action_bindings", "observer_enrollment_ids",
        }
        registration_ids = set()
        for row in registration_rows:
            if not isinstance(row, dict) or set(row) != registration_fields:
                raise NativeOutputReceiptDenied("native registration projection row is malformed")
            reg_id = row["registration_id"]
            if (not isinstance(reg_id, str) or not _valid_identifier(reg_id)
                    or reg_id in registration_ids or not isinstance(row["argument_schema"], dict)
                    or not isinstance(row["result_schema"], dict)
                    or row["native_schema_sha256"] != hashlib.sha256(_canonical(row["argument_schema"])).hexdigest()
                    or not isinstance(row["registration_source_sha256"], str)
                    or not _HEX.fullmatch(row["registration_source_sha256"])
                    or not isinstance(row["registration_source_receipt_handle"], str)
                    or not _valid_identifier(row["registration_source_receipt_handle"])
                    or not isinstance(row["observer_enrollment_ids"], list)
                    or not row["observer_enrollment_ids"]):
                raise NativeOutputReceiptDenied("native registration identity or root source/observer proof is invalid")
            registration_ids.add(reg_id)
    candidate_fields = {"native_tool_name", "adapter_id", "action_id", "argument_schema",
                        "result_schema", "native_schema_sha256", "observer_enrollment_ids",
                        "native_server_name", "description"}
    if is_projected:
        candidate_fields |= {"registration_id", "toolset", "family", "handler_kind"}
    names, actions = set(), set()
    for index, candidate in enumerate(value["candidates"]):
        if not isinstance(candidate, dict) or set(candidate) != candidate_fields:
            raise NativeOutputReceiptDenied("native candidate row schema is malformed")
        string_limits = {"native_tool_name": 256, "adapter_id": 128, "action_id": 128,
                         "native_server_name": 256, "description": 4096}
        for field, limit in string_limits.items():
            item = candidate[field]
            if not isinstance(item, str) or (field != "native_server_name" and not item) or len(item) > limit:
                raise NativeOutputReceiptDenied("native candidate scalar field is malformed")
        if (not isinstance(candidate["argument_schema"], dict)
                or not isinstance(candidate["result_schema"], dict)
                or len(_canonical(candidate["argument_schema"])) > 256 * 1024
                or len(_canonical(candidate["result_schema"])) > 256 * 1024
                or not isinstance(candidate["native_schema_sha256"], str)
                or not _HEX.fullmatch(candidate["native_schema_sha256"])
                or candidate["native_schema_sha256"] != hashlib.sha256(
                    _canonical(candidate["argument_schema"])).hexdigest()):
            raise NativeOutputReceiptDenied("native candidate schemas or schema digest are invalid")
        observers = candidate["observer_enrollment_ids"]
        if (not isinstance(observers, list) or len(observers) > 64
                or any(not isinstance(item, str) or not _valid_identifier(item) for item in observers)
                or len(set(observers)) != len(observers)):
            raise NativeOutputReceiptDenied("native candidate observer enrollment list is invalid")
        name = candidate["native_tool_name"]
        action = candidate["adapter_id"], candidate["action_id"]
        if name in names or action in actions:
            raise NativeOutputReceiptDenied("native candidate tool and adapter/action identities must be unique")
        if is_projected:
            registration = registration_rows[index]
            if (candidate["registration_id"] != registration["registration_id"]
                    or any(candidate.get(key) != registration.get(key) for key in (
                        "native_tool_name", "adapter_id", "native_server_name", "toolset", "family",
                        "argument_schema", "result_schema", "native_schema_sha256",
                        "observer_enrollment_ids", "handler_kind"))):
                raise NativeOutputReceiptDenied("native candidate differs from its projected registration")
        names.add(name)
        actions.add(action)


def _verify_boundary_overlay(payload: bytes) -> Mapping[str, Any]:
    value = _parse_canonical_json(payload)
    expected = {"schema", "source_commit", "compiler_artifact_id", "compiler_sha256", "members"}
    if (not isinstance(value, dict) or set(value) != expected or value.get("schema") != 1
            or not isinstance(value["source_commit"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", value["source_commit"])
            or not isinstance(value["compiler_artifact_id"], str)
            or not _valid_identifier(value["compiler_artifact_id"])
            or not isinstance(value["compiler_sha256"], str)
            or not _HEX.fullmatch(value["compiler_sha256"])
            or not isinstance(value["members"], list) or len(value["members"]) > 50_000):
        raise NativeOutputReceiptDenied("native boundary overlay manifest is malformed")
    rows = []
    for row in value["members"]:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "size_bytes", "mode"}:
            raise NativeOutputReceiptDenied("native boundary overlay member row is malformed")
        try:
            rows.append(NativeOutputMember(row["path"], row["sha256"], row["size_bytes"], row["mode"]))
        except Exception:
            raise NativeOutputReceiptDenied("native boundary overlay member row is malformed") from None
    normalized = _normalize_members(rows)
    if tuple(rows) != normalized:
        raise NativeOutputReceiptDenied("native boundary overlay member rows are not sorted and unique")
    if any(row.mode not in {0o644, 0o755} for row in normalized):
        raise NativeOutputReceiptDenied("native boundary overlay member mode is unsupported")
    return value


def _validate_role_selection_payload(selection: NativeOutputSelection, role: str,
                                     payload: bytes) -> None:
    if role in {"native-candidate-index", "native-compiled-closure"}:
        candidate = (payload if role == "native-candidate-index" else
                    _read_archive_member(payload, "catalog/native-candidates.json"))
        value = _parse_canonical_json(candidate)
        if (value.get("package_id") != selection.package_id
                or value.get("profile_id") != selection.profile_id
                or value.get("generation") != selection.generation):
            raise NativeOutputReceiptDenied("candidate index does not match the selected package generation")
        if role == "native-compiled-closure":
            embedded_manifest = _read_archive_member(payload, "manifest.json")
            _validate_role_selection_payload(selection, "native-entrypoint-manifest", embedded_manifest)
            _verify_closure_tree_manifest(embedded_manifest, payload)
            tree_rows = _parse_canonical_json(embedded_manifest)["closure_files"]
            if hashlib.sha256(_canonical(tree_rows)).hexdigest() != selection.compiled_closure_sha256:
                raise NativeOutputReceiptDenied("selected compiled closure tree digest differs from its entrypoint")
            resolver = _parse_canonical_json(_read_archive_member(payload, "resolver/resolver"))
            if not isinstance(resolver, dict):
                raise NativeOutputReceiptDenied("compiled closure resolver document is malformed")
    if role == "native-entrypoint-manifest":
        value = _parse_canonical_json(payload)
        expected_top = {"schema", "package_id", "profile_id", "generation",
                        "closure_files", "adapters", "dependencies", "candidate_index"}
        if (set(value) != expected_top or value.get("schema") != 1
                or value.get("package_id") != selection.package_id
                or value.get("profile_id") != selection.profile_id
                or value.get("generation") != selection.generation
                or not isinstance(value.get("adapters"), list)
                or not isinstance(value.get("dependencies"), list)):
            raise NativeOutputReceiptDenied("entrypoint manifest identity or top-level schema is invalid")
        candidate_pin = value.get("candidate_index")
        if not isinstance(candidate_pin, dict) or set(candidate_pin) != {
                "artifact_id", "relative_path", "sha256", "size_bytes"}:
            raise NativeOutputReceiptDenied("entrypoint manifest lacks its exact candidate index pin")
        candidate_id = f"native-candidate-index:{selection.package_id}:{selection.generation}"
        if (candidate_pin["artifact_id"] != candidate_id
                or candidate_pin["relative_path"] != "catalog/native-candidates.json"
                or not isinstance(candidate_pin["sha256"], str)
                or not _HEX.fullmatch(candidate_pin["sha256"])
                or type(candidate_pin["size_bytes"]) is not int
                or not 0 <= candidate_pin["size_bytes"] <= 2 * 1024 * 1024):
            raise NativeOutputReceiptDenied("entrypoint candidate index pin differs from the selected package")
        closure_files = value.get("closure_files")
        if not isinstance(closure_files, list) or len(closure_files) > 50_000:
            raise NativeOutputReceiptDenied("entrypoint closure file manifest is missing or oversized")
        normalized = []
        for row in closure_files:
            if not isinstance(row, dict) or set(row) != {"relative_path", "sha256", "size_bytes", "mode"}:
                raise NativeOutputReceiptDenied("entrypoint closure row schema is invalid")
            normalized.append(dict(row))
        if normalized != sorted(normalized, key=lambda row: row["relative_path"]):
            raise NativeOutputReceiptDenied("entrypoint closure rows are not canonically ordered")
        if len({row["relative_path"] for row in normalized}) != len(normalized):
            raise NativeOutputReceiptDenied("entrypoint closure rows contain duplicate paths")
        _validate_member_rows(normalized)
        if hashlib.sha256(_canonical(closure_files)).hexdigest() != selection.compiled_closure_sha256:
            raise NativeOutputReceiptDenied("entrypoint closure tree differs from selected package binding")
    if role == "native-boundary-overlay":
        value = _verify_boundary_overlay(payload)
        if (value["compiler_artifact_id"] != selection.compiler_artifact_id
                or value["compiler_sha256"] != selection.compiler_sha256):
            raise NativeOutputReceiptDenied("boundary overlay compiler identity differs from the selected compiler")


def _validate_member_rows(rows: Sequence[Mapping[str, Any]]) -> None:
    for row in rows:
        if (not _safe_relative(row["relative_path"])
                or not isinstance(row["sha256"], str) or not _HEX.fullmatch(row["sha256"])
                or type(row["size_bytes"]) is not int or row["size_bytes"] < 0
                or type(row["mode"]) is not int or row["mode"] not in {0o644, 0o755}):
            raise NativeOutputReceiptDenied("entrypoint closure member fields are malformed")


def _stored_member_manifest(role: str, payload: bytes) -> tuple[NativeOutputMember, ...]:
    if role in {"resources-source-bundle", "native-compiled-closure"}:
        return _archive_manifest(payload, source_archive=(role == "resources-source-bundle"))
    path = {"native-entrypoint-manifest": "manifest.json",
            "native-action-resolver": "resolver/resolver",
            "native-boundary-overlay": "overlay/manifest.json",
            "native-candidate-index": "catalog/native-candidates.json"}.get(role)
    if path is None:
        raise NativeOutputReceiptDenied("native output role has no fixed member path")
    return (NativeOutputMember(path, hashlib.sha256(payload).hexdigest(), len(payload), 0o644),)


def _parse_canonical_json(payload: bytes) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise ValueError("non-standard JSON constant")

    try:
        value = json.loads(payload.decode("utf-8", errors="strict"),
                           object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        raise NativeOutputReceiptDenied("native JSON output is malformed") from None
    if _canonical(value) != payload:
        raise NativeOutputReceiptDenied("native JSON output is not canonical UTF-8 JSON")
    return value


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return (not path.is_absolute() and bool(path.parts)
            and all(part not in {"", ".", ".."} for part in path.parts)
            and "\\" not in value and "\x00" not in value)


def _valid_identifier(value: str) -> bool:
    return isinstance(value, str) and bool(_ID.fullmatch(value))


def _valid_handle(value: str) -> bool:
    return isinstance(value, str) and bool(_HANDLE.fullmatch(value))


def _normalize_reservation_ids(receipt_ids: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(receipt_ids, Sequence) or isinstance(receipt_ids, (str, bytes)):
        raise NativeOutputReceiptDenied("active compilation receipt handles must be a sequence")
    normalized = tuple(receipt_ids)
    if (len(normalized) != len(_GENERATED_ROLES)
            or len(set(normalized)) != len(normalized)
            or any(not _valid_handle(value) for value in normalized)):
        raise NativeOutputReceiptDenied("active compilation receipt handle set is malformed")
    return normalized


def _expected_artifact_id(role: str, package_id: str, generation: str) -> str:
    if role == "resources-source-bundle":
        return _RESOURCES_ARTIFACT_ID
    if role == "native-candidate-index":
        return f"native-candidate-index:{package_id}:{generation}"
    return f"native-output:{role}:{package_id}:{generation}"


def _absolute_directory(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise NativeOutputReceiptDenied("root native output directory is not factory-selected")
    return path


def _verify_private_directory(path: Path, owner: int) -> None:
    try:
        info = path.lstat()
    except OSError:
        raise NativeOutputReceiptDenied("root native output directory is unavailable") from None
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != owner or stat.S_IMODE(info.st_mode) & 0o077):
        raise NativeOutputReceiptDenied("root native output directory custody is invalid")
    cursor = path.parent
    while cursor != Path(cursor.anchor):
        try:
            parent = cursor.lstat()
        except OSError:
            raise NativeOutputReceiptDenied("root native output parent is unavailable") from None
        sticky_shared_tmp = (parent.st_uid == 0 and parent.st_mode & stat.S_ISVTX
                             and parent.st_mode & 0o002)
        if (stat.S_ISLNK(parent.st_mode) or parent.st_uid != 0
                or (parent.st_mode & 0o022 and not sticky_shared_tmp)):
            raise NativeOutputReceiptDenied("root native output parent is writable or linked")
        cursor = cursor.parent


def _ensure_private_child(path: Path, owner: int) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError:
        raise NativeOutputReceiptDenied("root CAS shard could not be created") from None
    try:
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != owner or stat.S_IMODE(info.st_mode) & 0o077):
            raise NativeOutputReceiptDenied("root CAS shard custody is invalid")
    except OSError:
        raise NativeOutputReceiptDenied("root CAS shard is unavailable") from None


@contextmanager
def _connection(database: Path):
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(database, flags, 0o600)
    os.close(fd)
    db = sqlite3.connect(database, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def _hash_path_nofollow(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        digest = hashlib.sha256()
        while block := os.read(fd, 65536):
            digest.update(block)
        return digest.hexdigest()
    finally:
        os.close(fd)


def _read_private_file(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
        try:
            chunks = []
            total = 0
            while block := os.read(fd, min(65536, limit + 1 - total)):
                total += len(block)
                if total > limit:
                    raise NativeOutputReceiptDenied("native CAS object exceeds its read bound")
                chunks.append(block)
            return b"".join(chunks)
        finally:
            os.close(fd)
    except OSError:
        raise NativeOutputReceiptDenied("native CAS object cannot be opened without following links") from None


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _receipt_from_record(record: Mapping[str, Any]) -> RuntimeArtifactReceipt:
    return RuntimeArtifactReceipt(
        1, record["artifact_id"], record["artifact_role"], record["sha256"],
        record["size_bytes"], record["store_id"], record["receipt_id"],
        record["setup_session_id"], record["transaction_handle"],
        record["plan_digest"], record["prepared_generation_id"],
        record["compiler_artifact_id"], record["compiler_sha256"],
        record["producer_artifact_id"], record["producer_sha256"],
        tuple(record["source_receipt_handles"]), record["output_kind"],
        record["issued_monotonic"], record["expires_monotonic"],
    )


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _archive_manifest(payload: bytes, *, source_archive: bool = False) -> tuple[NativeOutputMember, ...]:
    try:
        with tarfile.open(fileobj=BytesIO(payload), mode="r:*" if source_archive else "r:") as archive:
            result = []
            for member in archive.getmembers():
                if member.isdir():
                    continue
                if not member.isfile() or not _safe_relative(member.name):
                    raise NativeOutputReceiptDenied("Resources archive contains an unsafe file member")
                stream = archive.extractfile(member)
                if stream is None:
                    raise NativeOutputReceiptDenied("Resources archive member cannot be read")
                digest = hashlib.sha256()
                size = 0
                while block := stream.read(65536):
                    digest.update(block)
                    size += len(block)
                result.append(NativeOutputMember(member.name, digest.hexdigest(), size,
                                                 member.mode & 0o777))
    except (OSError, tarfile.TarError):
        raise NativeOutputReceiptDenied("Resources archive is invalid") from None
    members = _normalize_members(result, allow_source_modes=source_archive)
    if source_archive and len(members) != 739:
        raise NativeOutputReceiptDenied("packaged Resources archive has the wrong file count")
    return members


def _verify_closure_tree_manifest(manifest_payload: bytes, closure_payload: bytes) -> None:
    value = _parse_canonical_json(manifest_payload)
    rows = value.get("closure_files")
    if not isinstance(rows, list):
        raise NativeOutputReceiptDenied("entrypoint closure manifest is missing")
    expected = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"relative_path", "sha256", "size_bytes", "mode"}:
            raise NativeOutputReceiptDenied("entrypoint closure row schema is invalid")
        expected.append({"relative_path": row["relative_path"], "sha256": row["sha256"],
                         "size_bytes": row["size_bytes"], "mode": row["mode"]})
    _validate_member_rows(expected)
    actual = []
    for row in _archive_manifest(closure_payload):
        if row.path.startswith("closure/"):
            actual.append({"relative_path": row.path.removeprefix("closure/"),
                           "sha256": row.sha256, "size_bytes": row.size_bytes, "mode": row.mode})
    actual.sort(key=lambda item: item["relative_path"])
    if expected != actual:
        raise NativeOutputReceiptDenied("entrypoint closure files differ from the compiled closure members")


def _verify_resources_source(payload: bytes) -> None:
    try:
        from importlib.resources import files
        from hermes_installer.registry.native import NativeRegistry
        from hermes_installer.registry.source import BundledRegistrySource, PinnedSource

        pin_path = files("hermes_installer.registry.bundle_data").joinpath(
            "hermes-agent-resources.pin.json")
        pin = PinnedSource.from_mapping(json.loads(pin_path.read_text(encoding="utf-8")))
        if (pin.commit != "113f42d33be9e0c8f0f47f5ca998e687323dec83"
                or pin.archive_sha256 != _RESOURCES_ARCHIVE_SHA256
                or pin.archive_size != _RESOURCES_ARCHIVE_SIZE):
            raise ValueError("packaged Resources source pin differs")
        verified = BundledRegistrySource(pin).load(payload)
        registry = NativeRegistry.from_verified_source(verified)
        if len(verified.files) != 739 or sum(registry.root_counts.values()) != 692:
            raise ValueError("packaged Resources source inventory differs")
    except Exception:
        raise NativeOutputReceiptDenied("packaged Resources archive failed full pinned source verification") from None
