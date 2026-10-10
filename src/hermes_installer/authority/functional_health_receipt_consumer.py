"""Consume genuine committed native-health receipts into the root lifecycle journal.

This module is deliberately narrow: it joins the setup-store commit, current
source and publication, current health admission, observer receipt and selected
root journal. It does not issue health receipts or turn presentation fields
into authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import threading
import base64
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .types import AuthorityDenied, canonical_bytes

_JOURNAL_ID = "installer-authority-journal-v1"
_DIGEST = frozenset("0123456789abcdef")
_COMPLETION_SEAL = object()
_MAX_COMPLETION_BYTES = 128 * 1024
_TEMP_RECORD = re.compile(r"\.health-[0-9a-f]{32}\.tmp\Z")


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in _DIGEST for char in value)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _record_filename(transaction_id: str) -> str:
    if not isinstance(transaction_id, str) or not 1 <= len(transaction_id) <= 128:
        raise AuthorityDenied("native.health.journal", "journal transaction ID is malformed")
    return hashlib.sha256(transaction_id.encode("utf-8")).hexdigest() + ".json"


def _read_health_record_at(directory_fd: int, transaction_id: str) -> tuple[str, bytes] | None:
    filename = _record_filename(transaction_id)
    try:
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError:
        raise AuthorityDenied("native.health.journal", "health completion record cannot be opened without following links") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_nlink not in (1, 2) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > _MAX_COMPLETION_BYTES):
            raise AuthorityDenied("native.health.journal", "health completion record custody is invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 16 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_COMPLETION_BYTES:
                raise AuthorityDenied("native.health.journal", "health completion record exceeds its byte bound")
            chunks.append(chunk)
        raw = b"".join(chunks)
        if info.st_nlink == 2:
            _recover_linked_temporary(directory_fd, filename, fd, info, raw)
        elif info.st_nlink != 1:
            raise AuthorityDenied("native.health.journal", "health completion record link count changed")
    finally:
        os.close(fd)
    try:
        row = json.loads(raw, object_pairs_hook=_unique_object)
        from .native_health_observer import RootNativeHealthReceipt
        expected_fields = {
            "schema", "journal_transaction_id", "transaction_handle", "enrollment_id",
            "profile_id", "process_generation", "service_generation_digest",
            "health_receipt_handle", "health_receipt", "publication_receipt_handle",
        }
        if (not isinstance(row, dict) or row.get("schema") != 1
                or set(row) != expected_fields or row.get("journal_transaction_id") != transaction_id
                or not isinstance(row.get("health_receipt"), dict)
                or set(row["health_receipt"]) != set(RootNativeHealthReceipt.__dataclass_fields__)
                or row["health_receipt"].get("schema") != 2
                or row["health_receipt"].get("status") != "passed"
                or not _valid_digest(row["health_receipt"].get("health_run_proof_sha256"))
                or row["health_receipt"].get("health_receipt_handle") != row.get("health_receipt_handle")
                or row["health_receipt"].get("service_generation_digest") != row.get("service_generation_digest")
                or not _valid_digest(row.get("service_generation_digest"))
                or canonical_bytes(row) != raw):
            raise ValueError
        return filename, raw
    except Exception:
        raise AuthorityDenied("native.health.journal", "health completion record is malformed") from None


def _recover_linked_temporary(directory_fd: int, filename: str, record_fd: int,
                              record_info: os.stat_result, record_bytes: bytes) -> None:
    """Finish link/unlink after a crash between atomic publish and temp cleanup."""
    candidates: list[str] = []
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if _TEMP_RECORD.fullmatch(entry.name):
                info = entry.stat(follow_symlinks=False)
                if (info.st_dev, info.st_ino) == (record_info.st_dev, record_info.st_ino):
                    candidates.append(entry.name)
                    if len(candidates) > 1:
                        break
    if len(candidates) != 1:
        raise AuthorityDenied("native.health.journal", "published health record has an unexplained hard link")
    temp_fd = os.open(candidates[0], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                      dir_fd=directory_fd)
    try:
        temp_info = os.fstat(temp_fd)
        if (temp_info.st_ino != record_info.st_ino or not stat.S_ISREG(temp_info.st_mode)
                or temp_info.st_uid != 0 or temp_info.st_nlink != 2
                or stat.S_IMODE(temp_info.st_mode) != 0o600):
            raise AuthorityDenied("native.health.journal", "health temporary changed during recovery")
        temp_bytes = bytearray()
        while len(temp_bytes) <= _MAX_COMPLETION_BYTES:
            chunk = os.read(temp_fd, 16 * 1024)
            if not chunk:
                break
            temp_bytes.extend(chunk)
        if bytes(temp_bytes) != record_bytes:
            raise AuthorityDenied("native.health.journal", "health temporary differs from published record")
    finally:
        os.close(temp_fd)
    os.unlink(candidates[0], dir_fd=directory_fd)
    os.fsync(directory_fd)
    if os.fstat(record_fd).st_nlink != 1:
        raise AuthorityDenied("native.health.journal", "health record link recovery was incomplete")


def _append_health_record_at(directory_fd: int, transaction_id: str, encoded: bytes) -> None:
    if not isinstance(encoded, bytes) or not 1 <= len(encoded) <= _MAX_COMPLETION_BYTES:
        raise AuthorityDenied("native.health.journal", "health completion encoding exceeds its byte bound")
    info = os.fstat(directory_fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise AuthorityDenied("native.health.journal", "health completion directory custody is invalid")
    # Validate canonical bytes and transaction binding before creating any file.
    try:
        parsed = json.loads(encoded, object_pairs_hook=_unique_object)
        from .native_health_observer import RootNativeHealthReceipt
        expected_fields = {
            "schema", "journal_transaction_id", "transaction_handle", "enrollment_id",
            "profile_id", "process_generation", "service_generation_digest",
            "health_receipt_handle", "health_receipt", "publication_receipt_handle",
        }
        if (not isinstance(parsed, dict) or set(parsed) != expected_fields
                or parsed.get("schema") != 1
                or parsed.get("journal_transaction_id") != transaction_id
                or not isinstance(parsed.get("health_receipt"), dict)
                or set(parsed["health_receipt"]) != set(RootNativeHealthReceipt.__dataclass_fields__)
                or parsed["health_receipt"].get("schema") != 2
                or parsed["health_receipt"].get("status") != "passed"
                or not _valid_digest(parsed["health_receipt"].get("health_run_proof_sha256"))
                or parsed["health_receipt"].get("health_receipt_handle") != parsed.get("health_receipt_handle")
                or parsed["health_receipt"].get("service_generation_digest") != parsed.get("service_generation_digest")
                or not _valid_digest(parsed.get("service_generation_digest"))
                or canonical_bytes(parsed) != encoded):
            raise ValueError
    except Exception:
        raise AuthorityDenied("native.health.journal", "health completion encoding is not canonical or bound")
    filename = _record_filename(transaction_id)
    temporary = ".health-" + secrets.token_hex(16) + ".tmp"
    fd = -1
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if type(written) is not int or written <= 0 or written > len(view):
                raise OSError("health completion write made no forward progress")
            view = view[written:]
        os.fsync(fd)
        temp_info = os.fstat(fd)
        if (not stat.S_ISREG(temp_info.st_mode) or temp_info.st_uid != 0
                or temp_info.st_nlink != 1 or stat.S_IMODE(temp_info.st_mode) != 0o600):
            raise OSError("health completion temporary file custody is invalid")
        os.close(fd)
        fd = -1
        try:
            os.link(temporary, filename, src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd, follow_symlinks=False)
        except FileExistsError:
            previous = _read_health_record_at(directory_fd, transaction_id)
            if previous is None or previous[1] != encoded:
                raise AuthorityDenied("native.health.replay", "health completion transaction is already recorded")
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            # A concurrent replay may have completed recovery of this linked inode.
            pass
        os.fsync(directory_fd)
    except AuthorityDenied:
        raise
    except Exception:
        raise AuthorityDenied("native.health.journal", "atomic health completion journal write failed") from None
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass


@dataclass(frozen=True, slots=True)
class RootFunctionalHealthCompletion:
    schema: int
    journal_transaction_id: str
    transaction_handle: str
    enrollment_id: str
    profile_id: str
    process_generation: str
    service_generation_digest: str
    health_receipt_handle: str
    health_receipt: Mapping[str, Any]
    publication_receipt_handle: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _COMPLETION_SEAL or type(self.schema) is not int
                or self.schema != 1 or not _valid_digest(self.service_generation_digest)
                or not isinstance(self.health_receipt, Mapping)):
            raise TypeError("functional health completions are issued by the root journal")
        object.__setattr__(self, "health_receipt", MappingProxyType(dict(self.health_receipt)))


def _completion(row: Mapping[str, Any]) -> RootFunctionalHealthCompletion:
    return RootFunctionalHealthCompletion(**row, _seal=_COMPLETION_SEAL)


class RootFunctionalHealthJournal:
    """Append-only, no-follow completion records beneath the selected root journal."""

    def __init__(self, *, start_authority: Any, health_observer: Any,
                 publication_resolver: Any, root_journal: Any):
        from hermes_installer.protected_enrollment import RootJournalSelection
        from .native_health_observer import RootNativeHealthObserver, RootNativeHealthStartAuthority
        from .setup_policy_publication import PolicyPublicationReceiptResolver

        if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or os.geteuid() != 0
                or type(start_authority) is not RootNativeHealthStartAuthority
                or type(health_observer) is not RootNativeHealthObserver
                or start_authority.health_observer is not health_observer
                or publication_resolver is not PolicyPublicationReceiptResolver
                or type(root_journal) is not RootJournalSelection
                or root_journal.root_id != _JOURNAL_ID
                or root_journal != start_authority.root_journal
                or root_journal != start_authority.committed_enrollment_registry.root_journal
                or not _valid_digest(root_journal.service_generation_digest)):
            raise AuthorityDenied("native.health.journal", "root-selected health journal dependencies are unavailable")
        self.start_authority = start_authority
        self.health_observer = health_observer
        self.publication_resolver = publication_resolver
        self.root_journal = root_journal
        self._lock = threading.RLock()
        self._root_fd = -1
        self._records_fd = -1
        try:
            self._root_fd = os.open(root_journal.path, os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW | os.O_CLOEXEC)
            self._verify_root_fd()
            try:
                os.mkdir("functional-health-v1", 0o700, dir_fd=self._root_fd)
                os.fsync(self._root_fd)
            except FileExistsError:
                pass
            self._records_fd = os.open("functional-health-v1", os.O_RDONLY | os.O_DIRECTORY |
                                       os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._root_fd)
            info = os.fstat(self._records_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise OSError("health journal directory custody is invalid")
            self._records_identity = (info.st_dev, info.st_ino)
            self._verify_current_selection()
        except Exception:
            self.close()
            raise AuthorityDenied("native.health.journal", "selected root health journal is not safely held") from None

    @classmethod
    def from_root_committed_health(cls, *, start_authority: Any,
                                   health_observer: Any,
                                   publication_resolver: Any,
                                   root_journal: Any) -> "RootFunctionalHealthJournal":
        return cls(start_authority=start_authority, health_observer=health_observer,
                   publication_resolver=publication_resolver,
                   root_journal=root_journal)

    def close(self) -> None:
        for attr in ("_records_fd", "_root_fd"):
            fd = getattr(self, attr, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, attr, -1)

    def _verify_root_fd(self) -> None:
        info = os.fstat(self._root_fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (self.root_journal.device,
                                                    self.root_journal.inode)):
            raise OSError("selected root journal identity changed")

    def _verify_current_selection(self) -> None:
        bindings = self.start_authority.active_bindings
        digest = getattr(bindings, "service_generation_digest", None)
        if not _valid_digest(digest) or digest != self.root_journal.service_generation_digest:
            raise AuthorityDenied("native.health.journal", "active service generation differs from journal")
        try:
            current = bindings.resolve_root_journal(
                self.root_journal.root_id, expected_active_generation_digest=digest)
        except Exception:
            raise AuthorityDenied("native.health.journal", "protected root journal selection is stale") from None
        if current != self.root_journal:
            raise AuthorityDenied("native.health.journal", "protected root journal identity changed")
        self._verify_root_fd()
        records_info = os.fstat(self._records_fd)
        records_path_info = os.stat("functional-health-v1", dir_fd=self._root_fd,
                                    follow_symlinks=False)
        if (not stat.S_ISDIR(records_info.st_mode) or records_info.st_uid != 0
                or stat.S_IMODE(records_info.st_mode) != 0o700
                or (records_info.st_dev, records_info.st_ino) != self._records_identity
                or (records_path_info.st_dev, records_path_info.st_ino) != self._records_identity):
            raise AuthorityDenied("native.health.journal", "health completion directory identity changed")
        root_info = self.root_journal.path.stat(follow_symlinks=False)
        if ((root_info.st_dev, root_info.st_ino) != (self.root_journal.device,
                                                      self.root_journal.inode)
                or root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) != 0o700):
            raise AuthorityDenied("native.health.journal", "selected root journal path was replaced")

    def _resolve_current(self, active_receipt: Any) -> tuple[Any, Any, Any, Any]:
        from .bootstrap_enrollment import EnrollmentReceipt, VerifiedCommittedEnrollment
        from .native_health_observer import RootNativeHealthStartMaterial
        from .setup_policy_publication import PolicyPublicationReceiptResolver, RootSetupPublicationReceipt

        if type(active_receipt) is not EnrollmentReceipt or active_receipt.state != "committed":
            raise AuthorityDenied("native.health.commit", "functional health requires the exact committed receipt")
        authority = self.start_authority
        registry = authority.committed_enrollment_registry
        try:
            material = registry.resolve_current_health_material_for_receipt(
                active_receipt, authority.active_bindings, authority.verified_installer_release,
                authority.current_installed_actor_verifier,
            )
            publication = PolicyPublicationReceiptResolver.resolve_current()
        except Exception:
            raise AuthorityDenied("native.health.current", "current committed source or publication is unavailable") from None
        if type(material) is not RootNativeHealthStartMaterial:
            raise AuthorityDenied("native.health.sources", "health source proof is not typed")
        commit = material.verified_commit
        if (type(commit) is not VerifiedCommittedEnrollment
                or commit.receipt is not active_receipt
                or not registry.is_current_commit(commit)):
            raise AuthorityDenied("native.health.commit", "setup-store commit is no longer current")
        try:
            admission = authority.resolve_current_health_admission_for_commit(commit)
        except Exception:
            raise AuthorityDenied("native.health.admission", "current selected health admission is unavailable") from None
        digest = authority.active_bindings.service_generation_digest
        if (type(publication) is not RootSetupPublicationReceipt
                or publication.state != "active-committed"
                or publication.service_generation_digest != digest
                or active_receipt.generation_digest != digest
                or material.service_generation_digest != digest
                or admission.service_generation_digest != digest):
            raise AuthorityDenied("native.health.generation", "commit, source, admission, publication, or active digest differs")
        self._verify_current_selection()
        return commit, material, admission, publication

    @staticmethod
    def _receipt_record(receipt: Any) -> dict[str, Any]:
        from .native_health_observer import RootNativeHealthReceipt
        if type(receipt) is not RootNativeHealthReceipt:
            raise AuthorityDenied("native.health.receipt", "observer did not retain a typed health receipt")
        return {name: getattr(receipt, name) for name in receipt.__dataclass_fields__}

    def _record_for(self, transaction_id: str) -> tuple[str, bytes] | None:
        return _read_health_record_at(self._records_fd, transaction_id)

    def reconcile(self, active_receipt: Any, health_receipt_handle: str) -> RootFunctionalHealthCompletion | None:
        with self._lock:
            commit, material, admission, publication = self._resolve_current(active_receipt)
            prior = self._record_for(commit.journal_transaction_id)
            self._verify_current_selection()
            if prior is None:
                return None
            try:
                row = json.loads(prior[1])
                if (row["health_receipt_handle"] != health_receipt_handle
                        or row["service_generation_digest"] != commit.receipt.generation_digest
                        or row["transaction_handle"] != commit.receipt.transaction_handle
                        or row["enrollment_id"] != material.enrollment_id
                        or row["profile_id"] != material.profile_id
                        or row["process_generation"] != material.process_generation
                        or row["publication_receipt_handle"] != publication.receipt_handle):
                    raise ValueError
                result = _completion(row)
            except Exception:
                raise AuthorityDenied("native.health.replay", "existing completion does not match this current health run") from None
            self._resolve_current(active_receipt)
            self._verify_current_selection()
            return result

    def persist_consumed_receipt(self, ticket: Any) -> RootFunctionalHealthCompletion:
        with self._lock:
            try:
                health_receipt, active_receipt, expected_service_generation_digest = (
                    self.health_observer._resolve_pending_consumption_ticket(ticket))
            except Exception:
                raise AuthorityDenied("native.health.receipt", "journal requires this observer's live consumption ticket") from None
            commit, material, admission, publication = self._resolve_current(active_receipt)
            from .native_health_observer import RootNativeHealthReceipt
            if type(health_receipt) is not RootNativeHealthReceipt:
                raise AuthorityDenied("native.health.receipt", "health completion requires the observer's typed receipt")
            digest = commit.receipt.generation_digest
            if (health_receipt.status != "passed"
                    or health_receipt.service_generation_digest != expected_service_generation_digest
                    or health_receipt.service_generation_digest != digest
                    or digest != self.start_authority.active_bindings.service_generation_digest
                    or health_receipt.bootstrap_transaction_handle != commit.receipt.transaction_handle
                    or health_receipt.committed_enrollment_receipt_id != commit.journal_transaction_id
                    or health_receipt.enrollment_id != material.enrollment_id
                    or health_receipt.enrollment_id not in active_receipt.enrollment_ids
                    or health_receipt.profile_id != material.profile_id
                    or health_receipt.profile_id != admission.profile_id
                    or health_receipt.process_generation != material.process_generation
                    or health_receipt.process_generation != admission.process_generation
                    or health_receipt.operation_id != admission.operation_id
                    or health_receipt.result_schema_id != admission.health_result_schema_id):
                raise AuthorityDenied("native.health.binding", "health receipt differs from the current committed admission")
            handle = health_receipt.health_receipt_handle
            prior = self._record_for(commit.journal_transaction_id)
            receipt_row = self._receipt_record(health_receipt)
            row = {
                "schema": 1,
                "journal_transaction_id": commit.journal_transaction_id,
                "transaction_handle": commit.receipt.transaction_handle,
                "enrollment_id": material.enrollment_id,
                "profile_id": material.profile_id,
                "process_generation": material.process_generation,
                "service_generation_digest": digest,
                "health_receipt_handle": handle,
                "health_receipt": receipt_row,
                "publication_receipt_handle": publication.receipt_handle,
            }
            encoded = canonical_bytes(row)
            if prior is not None:
                if prior[1] != encoded:
                    raise AuthorityDenied("native.health.replay", "a different completion already owns this commit")
                return _completion(row)
            fresh_commit, fresh_material, fresh_admission, fresh_publication = self._resolve_current(active_receipt)
            if (fresh_commit is not commit or fresh_admission is not admission
                    or fresh_material.verified_commit is not commit
                    or fresh_material.enrollment_id != material.enrollment_id
                    or fresh_material.profile_id != material.profile_id
                    or fresh_material.process_generation != material.process_generation
                    or fresh_material.service_generation_digest != digest
                    or fresh_publication != publication):
                raise AuthorityDenied("native.health.current", "health authority changed before durable completion")
            self._verify_current_selection()
            self._write_once(commit.journal_transaction_id, encoded)
            completed_commit, completed_material, completed_admission, completed_publication = (
                self._resolve_current(active_receipt))
            if (completed_commit is not commit or completed_admission is not admission
                    or completed_material.verified_commit is not commit
                    or completed_material.service_generation_digest != digest
                    or completed_publication != publication):
                raise AuthorityDenied("native.health.current", "health authority changed after durable completion")
            return _completion(row)

    def _write_once(self, transaction_id: str, encoded: bytes) -> None:
        self._verify_current_selection()
        _append_health_record_at(self._records_fd, transaction_id, encoded)


class RootFunctionalHealthReceiptConsumer:
    """Single lifecycle consumer for selected root-observed health receipts."""

    def __init__(self, *, registry: Any, start_authority: Any,
                 health_observer: Any, publication_resolver: Any,
                 root_journal: Any):
        from .native_health_observer import RootCommittedHealthEnrollmentRegistry, RootNativeHealthObserver, RootNativeHealthStartAuthority
        if (type(registry) is not RootCommittedHealthEnrollmentRegistry
                or type(start_authority) is not RootNativeHealthStartAuthority
                or type(health_observer) is not RootNativeHealthObserver
                or start_authority.committed_enrollment_registry is not registry
                or start_authority.health_observer is not health_observer
                or root_journal != start_authority.root_journal
                or root_journal != registry.root_journal):
            raise AuthorityDenied("native.health.consumer", "health consumer requires the composed root registry, start authority, and observer")
        self.registry = registry
        self.start_authority = start_authority
        self.health_observer = health_observer
        self.publication_resolver = publication_resolver
        self._journal = RootFunctionalHealthJournal.from_root_committed_health(
            start_authority=start_authority, health_observer=health_observer,
            publication_resolver=publication_resolver,
            root_journal=root_journal)

    @classmethod
    def from_root_committed_health(cls, registry: Any, start_authority: Any,
                                   health_observer: Any, publication_resolver: Any,
                                   root_journal: Any) -> "RootFunctionalHealthReceiptConsumer":
        return cls(registry=registry, start_authority=start_authority,
                   health_observer=health_observer,
                   publication_resolver=publication_resolver, root_journal=root_journal)

    def record_functional_health(self, active_receipt: Any,
                                 health_receipt_handle: str) -> RootFunctionalHealthCompletion:
        if (not isinstance(health_receipt_handle, str)
                or not 32 <= len(health_receipt_handle) <= 128):
            raise AuthorityDenied("native.health.receipt", "health receipt handle is malformed")
        prior = self._journal.reconcile(active_receipt, health_receipt_handle)
        if prior is not None:
            return prior
        commit, material, admission, _publication = self._journal._resolve_current(active_receipt)
        return self.health_observer.consume_selected_health_receipt(
            health_receipt_handle, commit.journal_transaction_id,
            material.service_generation_digest,
            completion_journal=self._journal, active_receipt=active_receipt,
        )

    def close(self) -> None:
        self._journal.close()


class RootDaemonFunctionalHealthCompletionWriter:
    """Concrete bridge from one observer consumption ticket to the daemon CAS."""

    def __init__(self, *, consumer: "RootDaemonFunctionalHealthReceiptConsumer",
                 intent: Any, proof: Any, admission: Any):
        self.consumer = consumer
        self.health_observer = consumer.health_observer
        self.intent = intent
        self.daemon_commit_proof = proof
        self.daemon_admission = admission

    def persist_consumed_receipt(self, ticket: Any) -> tuple[str, str, Mapping[str, Any]]:
        from .native_health_observer import (
            RootDaemonCommittedHealthProof, RootDaemonHealthControllerLease,
            RootNativeHealthReceipt, RootNativeHealthStartAdmission,
        )
        if (type(self.daemon_commit_proof) is not RootDaemonCommittedHealthProof
                or type(self.daemon_admission) is not RootNativeHealthStartAdmission
                or self.daemon_admission.authority_branch != "daemon-committed"
                or self.daemon_admission._verified_commit is not self.daemon_commit_proof):
            raise AuthorityDenied("native.health.daemon_proof", "completion writer is not bound to the exact daemon admission")
        try:
            receipt, active_receipt, expected_digest = self.health_observer._resolve_pending_consumption_ticket(ticket)
            if (ticket.daemon_proof is not self.daemon_commit_proof
                    or ticket.daemon_admission is not self.daemon_admission
                    or active_receipt is not self.consumer.active_receipt
                    or type(receipt) is not RootNativeHealthReceipt):
                raise ValueError
            run_receipt, run, events, run_proof_sha256 = self.health_observer.resolve_current_daemon_receipt(
                receipt.health_receipt_handle, self.daemon_commit_proof, self.daemon_admission)
            projection = self.consumer.commit_registry.resolve_health_source_projection(self.daemon_commit_proof)
            journal = self.consumer.intent_journal
            accepted = journal.resolve_current_accepted_intent_for_handle(
                self.intent.intent_handle, self.consumer.receiver, self.consumer.active_receipt)
            controller = self.daemon_admission._controller_lease
            if (run_receipt is not receipt or accepted.intent_sha256 != self.intent.intent_sha256
                    or accepted.body != self.intent.body
                    or type(controller) is not RootDaemonHealthControllerLease
                    or not controller.is_current()
                    or self.consumer.start_authority.is_current(self.daemon_admission) is not True
                    or expected_digest != self.daemon_commit_proof.service_generation_digest
                    or receipt.service_generation_digest != expected_digest
                    or receipt.status != "passed"
                    or receipt.committed_enrollment_receipt_id != self.daemon_commit_proof.committed_transaction_id
                    or receipt.bootstrap_transaction_handle != self.daemon_commit_proof.bootstrap_transaction_handle
                    or run.profile_id != self.daemon_admission.profile_id
                    or run.operation_id != self.daemon_admission.operation_id
                    or run.result_schema_id != self.daemon_admission.health_result_schema_id
                    or projection.current_generation_digest != receipt.service_generation_digest
                    or projection.transaction_id != receipt.committed_enrollment_receipt_id):
                raise ValueError
            if self.consumer.material_registry.is_current(self.daemon_admission._source_material) is not True:
                raise ValueError
        except Exception:
            raise AuthorityDenied("native.health.current", "observer receipt or daemon source is no longer current") from None

        receipt_body = {name: getattr(receipt, name) for name in receipt.__dataclass_fields__}
        receipt_sha256 = hashlib.sha256(canonical_bytes(receipt_body)).hexdigest()
        event_rows: list[dict[str, Any]] = []
        event_order = ("loader-ready", "native-request", "provider-result",
                       "tool-invocation", "tool-result", "terminal")
        for event in sorted(events.values(), key=lambda item: event_order.index(item.event_kind)):
            row = {name: getattr(event, name) for name in event.__dataclass_fields__}
            if row.get("result_bytes") is not None:
                row["result_bytes"] = base64.b64encode(row["result_bytes"]).decode("ascii")
            event_rows.append(row)

        intent_body = self.intent.body
        completion = {
            "schema": 2,
            "completion_handle": secrets.token_urlsafe(32),
            "intent_handle": self.intent.intent_handle,
            "intent_sha256": self.intent.intent_sha256,
            "committed_transaction_id": self.daemon_commit_proof.committed_transaction_id,
            "bootstrap_transaction_handle": self.daemon_commit_proof.bootstrap_transaction_handle,
            "generation_id": self.daemon_commit_proof.generation_id,
            "service_generation_digest": self.daemon_commit_proof.service_generation_digest,
            "publication_receipt_handle": self.daemon_commit_proof.publication_receipt_handle,
            "publication_sha256": self.daemon_commit_proof.publication_sha256,
            "source_choice_signed_record_sha256": self.daemon_commit_proof.source_choice_signed_record_sha256,
            "health_definition_sha256": self.daemon_commit_proof.health_definition_sha256,
            "health_receipt_handle": receipt.health_receipt_handle,
            "health_receipt_sha256": receipt_sha256,
            "health_run_proof_sha256": run_proof_sha256,
            "result_schema_id": receipt.result_schema_id,
            "result_sha256": receipt.result_sha256,
            "parent_closure_digest": receipt.parent_closure_digest,
            "terminal_receipt_handle": receipt.terminal_receipt_handle,
            "daemon_unit_id": controller.unit_id,
            "daemon_invocation_id": controller.invocation_id,
            "daemon_pid": controller.pid,
            "daemon_start_ticks": controller.start_ticks,
            "daemon_actor_witness_sha256": controller.proof_sha256,
            "completed_monotonic": self.consumer.monotonic(),
        }
        try:
            self.consumer.commit_registry.resolve_health_source_projection(self.daemon_commit_proof)
            if (self.consumer.start_authority.is_current(self.daemon_admission) is not True
                    or not controller.is_current()
                    or intent_body.get("intent_handle") != self.intent.intent_handle):
                raise ValueError
            completion_handle, completion_sha256 = self.consumer.intent_journal.commit_completion(
                self.intent.intent_handle, self.intent.intent_sha256, completion,
                health_receipt_body=receipt_body, health_event_proof=event_rows)
            self.consumer.commit_registry.resolve_health_source_projection(self.daemon_commit_proof)
            if (self.consumer.start_authority.is_current(self.daemon_admission) is not True
                    or not controller.is_current()):
                raise ValueError
            body, _receipt, _events = self.consumer.intent_journal.resolve_current_completed_health_proof(
                self.intent.intent_handle, completion_handle)
            if body != completion or hashlib.sha256(canonical_bytes(body)).hexdigest() != completion_sha256:
                raise ValueError
            return completion_handle, completion_sha256, MappingProxyType(dict(body))
        except Exception:
            raise AuthorityDenied("native.health.completion", "durable current health completion could not be committed") from None


class RootDaemonFunctionalHealthReceiptConsumer:
    """Consume exact daemon-admitted native health into its protected intent CAS."""

    def __init__(self, *, runtime: Any, commit_registry: Any, material_registry: Any,
                 start_authority: Any, health_observer: Any, run_registry: Any):
        from .listener_activation import RootSetupHealthIntentJournal, RootAuthorityListenerActivationReceiver
        from .runtime_composition import RootAuthorityRuntime
        from .native_health_observer import (
            RootDaemonCommittedHealthEnrollmentRegistry, RootNativeHealthObserver,
            RootNativeHealthStartAuthority,
        )
        service = getattr(runtime, "service", None)
        journal = getattr(service, "root_setup_health_intent_journal", None)
        receiver = getattr(service, "root_authority_listener_activation_receiver", None)
        if (type(commit_registry) is not RootDaemonCommittedHealthEnrollmentRegistry
                or type(runtime) is not RootAuthorityRuntime
                or type(start_authority) is not RootNativeHealthStartAuthority
                or type(health_observer) is not RootNativeHealthObserver
                or not start_authority.daemon_mode
                or start_authority.committed_enrollment_registry is not commit_registry
                or start_authority.daemon_material_registry is not material_registry
                or start_authority.health_observer is not health_observer
                or start_authority.daemon_run_registry is not run_registry
                or service.root_authority_runtime is not runtime
                or type(journal) is not RootSetupHealthIntentJournal
                or journal.root_journal != commit_registry.root_journal
                or type(receiver) is not RootAuthorityListenerActivationReceiver
                or journal.receiver is not receiver):
            raise AuthorityDenied("native.health.consumer", "daemon health consumer needs exact composed root owners")
        self.runtime = runtime
        self.commit_registry = commit_registry
        self.material_registry = material_registry
        self.start_authority = start_authority
        self.health_observer = health_observer
        self.run_registry = run_registry
        self.receiver = receiver
        self.intent_journal = journal
        self.monotonic = start_authority.monotonic
        self.active_receipt = self.receiver.current_active_receipt()

    @classmethod
    def from_root_runtime(cls, runtime: Any, commit_registry: Any,
                          material_registry: Any, start_authority: Any,
                          health_observer: Any, run_registry: Any
                          ) -> "RootDaemonFunctionalHealthReceiptConsumer":
        return cls(runtime=runtime, commit_registry=commit_registry,
                   material_registry=material_registry, start_authority=start_authority,
                   health_observer=health_observer, run_registry=run_registry)

    def admit_daemon_selected_health(self, intent_handle: str) -> Any:
        from .listener_activation import RootAcceptedHealthIntent
        if not isinstance(intent_handle, str) or not 32 <= len(intent_handle) <= 128:
            raise AuthorityDenied("native.health.intent", "health intent handle is malformed")
        try:
            self.intent_journal.resolve_current_completed_for_intent(intent_handle)
        except Exception:
            pass
        else:
            raise AuthorityDenied("native.health.replay", "health intent already has a durable completion")
        admission = self.start_authority.admit_daemon_selected_health(intent_handle)
        self.active_receipt = self.receiver.current_active_receipt()
        return admission

    def record_daemon_functional_health(self, intent_handle: str,
                                        health_receipt_handle: str) -> tuple[str, str]:
        if not isinstance(health_receipt_handle, str) or not 32 <= len(health_receipt_handle) <= 128:
            raise AuthorityDenied("native.health.receipt", "health receipt handle is malformed")
        try:
            completion_handle, completion_sha256, _body = (
                self.intent_journal.resolve_current_completed_for_intent(intent_handle))
            return completion_handle, completion_sha256
        except Exception:
            pass
        intent = self.intent_journal.resolve_current_accepted_intent_for_handle(
            intent_handle, self.receiver, self.receiver.current_active_receipt())
        admission = self.start_authority.resolve_current_daemon_health_admission_for_intent(intent_handle)
        proof = admission._verified_commit
        if (admission._verified_commit is not proof
                or self.start_authority.is_current(admission) is not True):
            raise AuthorityDenied("native.health.admission", "receipt has no current matching daemon admission")
        writer = RootDaemonFunctionalHealthCompletionWriter(
            consumer=self, intent=intent, proof=proof, admission=admission)
        self.health_observer.consume_selected_health_receipt(
            health_receipt_handle, proof.committed_transaction_id,
            proof.service_generation_digest, completion_journal=writer,
            active_receipt=self.receiver.current_active_receipt(),
            daemon_commit_proof=proof, daemon_admission=admission)
        completion_handle, completion_sha256, _body = (
            self.intent_journal.resolve_current_completed_for_intent(intent_handle))
        return completion_handle, completion_sha256
