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
import secrets
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .types import AuthorityDenied, canonical_bytes

_JOURNAL_ID = "installer-authority-journal-v1"
_DIGEST = frozenset("0123456789abcdef")
_COMPLETION_SEAL = object()


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in _DIGEST for char in value)


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

    def __init__(self, *, start_authority: Any, publication_resolver: Any,
                 root_journal: Any):
        from hermes_installer.protected_enrollment import RootJournalSelection
        from .native_health_observer import RootNativeHealthStartAuthority
        from .setup_policy_publication import PolicyPublicationReceiptResolver

        if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or os.geteuid() != 0
                or type(start_authority) is not RootNativeHealthStartAuthority
                or publication_resolver is not PolicyPublicationReceiptResolver
                or type(root_journal) is not RootJournalSelection
                or root_journal.root_id != _JOURNAL_ID
                or root_journal != start_authority.root_journal
                or root_journal != start_authority.committed_enrollment_registry.root_journal
                or not _valid_digest(root_journal.service_generation_digest)):
            raise AuthorityDenied("native.health.journal", "root-selected health journal dependencies are unavailable")
        self.start_authority = start_authority
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
                                   publication_resolver: Any,
                                   root_journal: Any) -> "RootFunctionalHealthJournal":
        return cls(start_authority=start_authority,
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
        filename = hashlib.sha256(transaction_id.encode("utf-8")).hexdigest() + ".json"
        try:
            fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=self._records_fd)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > 128 * 1024):
                raise AuthorityDenied("native.health.journal", "health completion record custody is invalid")
            chunks = []
            while True:
                chunk = os.read(fd, 16 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(fd)
        try:
            row = json.loads(raw)
            from .native_health_observer import RootNativeHealthReceipt
            fields = {
                "schema", "journal_transaction_id", "transaction_handle", "enrollment_id",
                "profile_id", "process_generation", "service_generation_digest",
                "health_receipt_handle", "health_receipt", "publication_receipt_handle",
            }
            if (not isinstance(row, dict) or row.get("schema") != 1
                    or set(row) != fields or row.get("journal_transaction_id") != transaction_id
                    or not isinstance(row.get("health_receipt"), dict)
                    or set(row["health_receipt"]) != set(RootNativeHealthReceipt.__dataclass_fields__)
                    or row["health_receipt"].get("status") != "passed"
                    or row["health_receipt"].get("health_receipt_handle") != row.get("health_receipt_handle")
                    or not _valid_digest(row.get("service_generation_digest"))):
                raise ValueError
            return filename, raw
        except Exception:
            raise AuthorityDenied("native.health.journal", "health completion record is malformed") from None

    def reconcile(self, active_receipt: Any, health_receipt_handle: str) -> RootFunctionalHealthCompletion | None:
        with self._lock:
            commit, material, admission, publication = self._resolve_current(active_receipt)
            prior = self._record_for(commit.journal_transaction_id)
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
                return _completion(row)
            except Exception:
                raise AuthorityDenied("native.health.replay", "existing completion does not match this current health run") from None

    def persist_consumed_receipt(self, active_receipt: Any, health_receipt: Any,
                                 expected_service_generation_digest: str) -> RootFunctionalHealthCompletion:
        with self._lock:
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
            return _completion(row)

    def _write_once(self, transaction_id: str, encoded: bytes) -> None:
        filename = hashlib.sha256(transaction_id.encode("utf-8")).hexdigest() + ".json"
        temporary = ".health-" + secrets.token_hex(16) + ".tmp"
        fd = -1
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self._records_fd)
            view = memoryview(encoded)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise OSError("health completion temporary file custody is invalid")
            os.close(fd)
            fd = -1
            self._verify_current_selection()
            try:
                os.link(temporary, filename, src_dir_fd=self._records_fd,
                        dst_dir_fd=self._records_fd, follow_symlinks=False)
            except FileExistsError:
                prior = self._record_for(transaction_id)
                if prior is None or prior[1] != encoded:
                    raise AuthorityDenied("native.health.replay", "health completion transaction is already recorded")
            os.unlink(temporary, dir_fd=self._records_fd)
            os.fsync(self._records_fd)
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("native.health.journal", "atomic health completion journal write failed") from None
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=self._records_fd)
            except OSError:
                pass


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
        self.journal = RootFunctionalHealthJournal.from_root_committed_health(
            start_authority=start_authority, publication_resolver=publication_resolver,
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
        prior = self.journal.reconcile(active_receipt, health_receipt_handle)
        if prior is not None:
            return prior
        commit, material, admission, _publication = self.journal._resolve_current(active_receipt)
        return self.health_observer.consume_selected_health_receipt(
            health_receipt_handle, commit.journal_transaction_id,
            material.service_generation_digest,
            completion_journal=self.journal, active_receipt=active_receipt,
        )

    def close(self) -> None:
        self.journal.close()
