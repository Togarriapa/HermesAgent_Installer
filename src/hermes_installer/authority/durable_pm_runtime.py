"""Fresh current PM runtime proof for a published Jarvis source home.

The setup PM registry is intentionally not used here: it belongs to a setup
session and expires with that session. This adapter starts from the immutable
current publication row and asks the already protected committed-PM resolver
to reopen the current signed runtime, receipt and complete venv closure.
"""
from __future__ import annotations

import os
import stat
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .committed_pm_executable import (
    CommittedPMExecutableUnavailable,
    RootActiveCommittedPMExecutableResolver,
    RootVerifiedCommittedPMExecutableIdentity,
)
from .setup_policy_publication import (
    RootPublishedAuthorityCore,
    RootPublishedNativeProfileHomeCrosswalk,
    RootPublishedNativeProfileHomeRow,
)

_PROOF_TTL_SECONDS = 30.0


class PublishedPMRuntimeUnavailable(CommittedPMExecutableUnavailable):
    """The selected published home has no exact current PM runtime lineage."""

    def __init__(self, message: str):
        super().__init__(message)


@dataclass(frozen=True, slots=True, repr=False)
class RootVerifiedPublishedProfileHomePMRuntime:
    """Short-lived row-bound proof holding the actual current PM venv FDs."""

    proof_handle: str
    source_profile_id: str
    home_binding_id: str
    publication_handle: str
    service_generation_digest: str
    crosswalk_member_sha256: str
    source_output_claim_sha256: str
    runtime_record_id: str
    runtime_record_sha256: str
    pm_runtime_receipt_handle: str
    pm_receipt_sha256: str
    pm_generation: str
    pm_source_commit: str
    venv_closure_sha256: str
    runtime_identity_sha256: str
    executable_sha256: str
    executable_device: int
    executable_inode: int
    executable_uid: int
    executable_gid: int
    executable_mode: int
    issued_monotonic: float
    expires_monotonic: float
    identity: RootVerifiedCommittedPMExecutableIdentity = field(repr=False, compare=False)
    _resolver: "RootPublishedProfileHomePMRuntimeResolver" = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootVerifiedPublishedProfileHomePMRuntime(<root-private>)"

    def close(self) -> None:
        self._resolver._release(self)


class RootPublishedProfileHomePMRuntimeResolver:
    """Join a current published home row to a fresh, descriptor-held PM proof."""

    def __init__(self, core: RootPublishedAuthorityCore,
                 pm_resolver: RootActiveCommittedPMExecutableResolver,
                 root_journal_catalog: Any, *, _seal: object):
        from hermes_installer.protected_enrollment import ProtectedRootJournalCatalog

        if (_seal is not _RESOLVER_SEAL
                or type(core) is not RootPublishedAuthorityCore
                or type(pm_resolver) is not RootActiveCommittedPMExecutableResolver
                or type(root_journal_catalog) is not ProtectedRootJournalCatalog
                or pm_resolver._journals is not root_journal_catalog
                or core.service_generation_digest != pm_resolver._catalog.digest
                or core.service_generation_digest != root_journal_catalog.generation_digest):
            raise PublishedPMRuntimeUnavailable(
                "published PM runtime resolver requires the exact current core and protected PM sources")
        self._core = core
        self._pm_resolver = pm_resolver
        self._journal_catalog = root_journal_catalog
        self._issuer = object()
        self._issued: dict[str, RootVerifiedPublishedProfileHomePMRuntime] = {}
        self._duplicates: dict[str, dict[int, tuple[int, int]]] = {}
        self._lock = threading.RLock()
        self._closed = False

    @classmethod
    def from_root_runtime(cls, published_authority_core: RootPublishedAuthorityCore,
                          active_committed_pm_executable_resolver: RootActiveCommittedPMExecutableResolver,
                          root_journal_catalog: Any) -> "RootPublishedProfileHomePMRuntimeResolver":
        return cls(published_authority_core, active_committed_pm_executable_resolver,
                   root_journal_catalog, _seal=_RESOLVER_SEAL)

    def resolve_current_profile_home_runtime(
            self, row: RootPublishedNativeProfileHomeRow
            ) -> RootVerifiedPublishedProfileHomePMRuntime:
        self._require_live()
        crosswalk = self._current_crosswalk()
        identity: RootVerifiedCommittedPMExecutableIdentity | None = None
        try:
            current = self._match_row(crosswalk, row)
            identity = self._pm_resolver.resolve_selected()
            if (identity.service_generation_digest != crosswalk.service_generation_digest
                    or identity.pm_runtime_receipt_handle != current.runtime_receipt_handle
                    or identity.runtime_identity_sha256 != current.runtime_identity_sha256
                    or identity.principal_id != current.principal_id
                    or identity.namespace_id != current.namespace_id):
                raise ValueError("published home PM identity differs from current committed runtime")
            after = self._current_crosswalk()
            try:
                after_row = self._match_row(after, row)
                if (after.publication_handle != crosswalk.publication_handle
                        or after.service_generation_digest != crosswalk.service_generation_digest
                        or after.crosswalk_member_sha256 != crosswalk.crosswalk_member_sha256
                        or after.source_output_claim_sha256 != crosswalk.source_output_claim_sha256
                        or after_row != current):
                    raise ValueError("published home changed during PM runtime observation")
            finally:
                after.close()
            issued = time.monotonic()
            expires = min(issued + _PROOF_TTL_SECONDS, identity.expires_monotonic)
            if expires <= issued:
                raise ValueError("current PM runtime proof has no remaining lease")
            import secrets
            proof = RootVerifiedPublishedProfileHomePMRuntime(
                proof_handle=secrets.token_hex(32),
                source_profile_id=current.source_profile_id,
                home_binding_id=current.home_binding_id,
                publication_handle=crosswalk.publication_handle,
                service_generation_digest=crosswalk.service_generation_digest,
                crosswalk_member_sha256=crosswalk.crosswalk_member_sha256,
                source_output_claim_sha256=crosswalk.source_output_claim_sha256,
                runtime_record_id=identity.runtime_record_id,
                runtime_record_sha256=identity.runtime_record_sha256,
                pm_runtime_receipt_handle=identity.pm_runtime_receipt_handle,
                pm_receipt_sha256=identity.pm_receipt_sha256,
                pm_generation=identity.pm_generation,
                pm_source_commit=identity.source_commit,
                venv_closure_sha256=identity.runtime_closure_sha256,
                runtime_identity_sha256=identity.runtime_identity_sha256,
                executable_sha256=identity.executable_sha256,
                executable_device=identity.executable_device,
                executable_inode=identity.executable_inode,
                executable_uid=identity.executable_uid,
                executable_gid=identity.executable_gid,
                executable_mode=identity.executable_mode,
                issued_monotonic=issued,
                expires_monotonic=expires,
                identity=identity,
                _resolver=self,
                _issuer=self._issuer,
            )
            with self._lock:
                if self._closed:
                    raise ValueError("published PM runtime resolver is closed")
                self._issued[proof.proof_handle] = proof
                self._duplicates[proof.proof_handle] = {}
            return proof
        except PublishedPMRuntimeUnavailable:
            if identity is not None:
                identity.close()
            raise
        except Exception:
            if identity is not None:
                identity.close()
            raise PublishedPMRuntimeUnavailable(
                "current published profile-home PM runtime is absent or changed") from None
        finally:
            crosswalk.close()

    def verify_current(self, proof: RootVerifiedPublishedProfileHomePMRuntime,
                       row: RootPublishedNativeProfileHomeRow) -> bool:
        self._require_owned(proof)
        try:
            crosswalk = self._current_crosswalk()
        except Exception:
            self._release(proof)
            raise PublishedPMRuntimeUnavailable(
                "current published profile-home PM runtime is unavailable") from None
        try:
            current = self._match_row(crosswalk, row)
            if (proof.source_profile_id != current.source_profile_id
                    or proof.home_binding_id != current.home_binding_id
                    or proof.publication_handle != crosswalk.publication_handle
                    or proof.service_generation_digest != crosswalk.service_generation_digest
                    or proof.crosswalk_member_sha256 != crosswalk.crosswalk_member_sha256
                    or proof.source_output_claim_sha256 != crosswalk.source_output_claim_sha256
                    or proof.pm_runtime_receipt_handle != current.runtime_receipt_handle
                    or proof.runtime_identity_sha256 != current.runtime_identity_sha256
                    or proof.identity.principal_id != current.principal_id
                    or proof.identity.namespace_id != current.namespace_id):
                proof.identity.close()
                raise ValueError("published PM runtime home row changed")
        except Exception:
            proof.identity.close()
            self._release(proof)
            raise PublishedPMRuntimeUnavailable(
                "published profile-home PM runtime proof is stale") from None
        finally:
            crosswalk.close()
        try:
            self._pm_resolver.verify_current(proof.identity)
            current = self._current_crosswalk()
            try:
                current_row = self._match_row(current, row)
                if (current_row != row
                        or current.publication_handle != proof.publication_handle
                        or current.service_generation_digest != proof.service_generation_digest
                        or current.crosswalk_member_sha256 != proof.crosswalk_member_sha256
                        or current.source_output_claim_sha256 != proof.source_output_claim_sha256):
                    raise ValueError("published home changed during PM currentness verification")
            finally:
                current.close()
            return True
        except Exception:
            self._release(proof)
            raise PublishedPMRuntimeUnavailable(
                "current committed PM runtime changed after profile-home proof") from None

    def duplicate_executable_fd(self, proof: RootVerifiedPublishedProfileHomePMRuntime,
                                row: RootPublishedNativeProfileHomeRow) -> int:
        """Return a proof-owned FD; call release_duplicate_fd before closing it."""
        self.verify_current(proof, row)
        for fd in proof.identity.member_fds:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev == proof.executable_device and info.st_ino == proof.executable_inode
                    and stat.S_ISREG(info.st_mode)):
                duplicate = os.dup(fd)
                duplicate_info = os.fstat(duplicate)
                if (duplicate_info.st_dev, duplicate_info.st_ino) != (
                        proof.executable_device, proof.executable_inode):
                    os.close(duplicate)
                    break
                self._track_duplicate(proof, duplicate)
                return duplicate
        raise PublishedPMRuntimeUnavailable("held current PM executable descriptor is absent")

    def duplicate_runtime_member_fd(self, proof: RootVerifiedPublishedProfileHomePMRuntime,
                                   row: RootPublishedNativeProfileHomeRow,
                                   member_id: str) -> int:
        """Return a proof-owned FD; call release_duplicate_fd before closing it."""
        self.verify_current(proof, row)
        matches = [fd for path, fd in proof.identity.runtime_member_fds if path == member_id]
        if len(matches) != 1:
            raise PublishedPMRuntimeUnavailable("requested PM runtime member is not in the held closure")
        try:
            info = os.fstat(matches[0])
            if not stat.S_ISREG(info.st_mode):
                raise ValueError
            duplicate = os.dup(matches[0])
            duplicate_info = os.fstat(duplicate)
            if (duplicate_info.st_dev, duplicate_info.st_ino) != (info.st_dev, info.st_ino):
                os.close(duplicate)
                raise ValueError
            self._track_duplicate(proof, duplicate)
            return duplicate
        except Exception:
            raise PublishedPMRuntimeUnavailable("held PM runtime member is unavailable") from None

    def release_duplicate_fd(self, proof: RootVerifiedPublishedProfileHomePMRuntime,
                             row: RootPublishedNativeProfileHomeRow,
                             descriptor: int) -> int:
        """Transfer one still-open duplicate to the caller for caller-managed close.

        Until transfer, callers must not close or replace the descriptor. The
        device/inode check also prevents a stale tracked descriptor number from
        being closed if a caller already violated that ownership rule.
        """
        self.verify_current(proof, row)
        if type(descriptor) is not int or descriptor < 0:
            raise PublishedPMRuntimeUnavailable("PM duplicate descriptor is malformed")
        with self._lock:
            owned = self._duplicates.get(proof.proof_handle, {})
            expected = owned.get(descriptor)
            if expected is None:
                raise PublishedPMRuntimeUnavailable("PM duplicate descriptor is not owned by this proof")
            try:
                info = os.fstat(descriptor)
            except OSError:
                owned.pop(descriptor, None)
                raise PublishedPMRuntimeUnavailable("PM duplicate descriptor was already closed") from None
            if (info.st_dev, info.st_ino) != expected:
                owned.pop(descriptor, None)
                raise PublishedPMRuntimeUnavailable("PM duplicate descriptor number was reused")
            owned.pop(descriptor)
        return descriptor

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            proofs = tuple(self._issued.values())
            duplicates = tuple((fd, identity) for owned in self._duplicates.values()
                               for fd, identity in owned.items())
            self._issued.clear()
            self._duplicates.clear()
        self._close_owned_duplicates(duplicates)
        for proof in proofs:
            proof.identity.close()

    def _current_crosswalk(self) -> RootPublishedNativeProfileHomeCrosswalk:
        getter = getattr(self._core, "resolve_current_native_profile_home_crosswalk", None)
        if not callable(getter):
            raise PublishedPMRuntimeUnavailable("current published home crosswalk getter is unavailable")
        crosswalk = getter()
        if (type(crosswalk) is not RootPublishedNativeProfileHomeCrosswalk
                or crosswalk._core is not self._core
                or crosswalk.service_generation_digest != self._core.service_generation_digest):
            close = getattr(crosswalk, "close", None)
            if callable(close):
                close()
            raise PublishedPMRuntimeUnavailable("current published home crosswalk is foreign")
        return crosswalk

    @staticmethod
    def _match_row(crosswalk: RootPublishedNativeProfileHomeCrosswalk,
                   row: RootPublishedNativeProfileHomeRow) -> RootPublishedNativeProfileHomeRow:
        if type(row) is not RootPublishedNativeProfileHomeRow:
            raise ValueError("published profile-home row is not a typed current row")
        matches = [current for current in crosswalk.rows
                   if current.source_profile_id == row.source_profile_id]
        if len(matches) != 1 or matches[0] != row:
            raise ValueError("profile-home row is absent or changed in current publication")
        return matches[0]

    def _require_owned(self, proof: RootVerifiedPublishedProfileHomePMRuntime) -> None:
        self._require_live()
        with self._lock:
            owned = (type(proof) is RootVerifiedPublishedProfileHomePMRuntime
                     and proof._issuer is self._issuer
                     and self._issued.get(proof.proof_handle) is proof)
        if not owned:
            raise PublishedPMRuntimeUnavailable("published profile-home PM proof is stale or foreign")
        if (proof.expires_monotonic <= time.monotonic()
                or proof.identity.expires_monotonic <= time.monotonic()):
            self._release(proof)
            raise PublishedPMRuntimeUnavailable("published profile-home PM proof is stale or foreign")

    def _require_live(self) -> None:
        if self._closed:
            raise PublishedPMRuntimeUnavailable("published PM runtime resolver is closed")

    def _release(self, proof: RootVerifiedPublishedProfileHomePMRuntime) -> None:
        with self._lock:
            if self._issued.get(proof.proof_handle) is proof:
                self._issued.pop(proof.proof_handle, None)
                duplicates = self._duplicates.pop(proof.proof_handle, {})
            else:
                duplicates = {}
        self._close_owned_duplicates(tuple(duplicates.items()))
        proof.identity.close()

    def _track_duplicate(self, proof: RootVerifiedPublishedProfileHomePMRuntime,
                         fd: int) -> None:
        with self._lock:
            if self._issued.get(proof.proof_handle) is not proof:
                os.close(fd)
                raise PublishedPMRuntimeUnavailable("published PM proof was released during descriptor duplication")
            info = os.fstat(fd)
            self._duplicates[proof.proof_handle][fd] = (info.st_dev, info.st_ino)

    @staticmethod
    def _close_owned_duplicates(duplicates: tuple[tuple[int, tuple[int, int]], ...]) -> None:
        for fd, expected_identity in duplicates:
            try:
                current = os.fstat(fd)
                if (current.st_dev, current.st_ino) == expected_identity:
                    os.close(fd)
            except OSError:
                pass


_RESOLVER_SEAL = object()
