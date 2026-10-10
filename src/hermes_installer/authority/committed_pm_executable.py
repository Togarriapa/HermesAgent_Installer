"""Pre-profile source and executable resolver for the selected Hermes worker.

This is a read-only authority owner. It deliberately does not depend on the
authority service or process manager, both of which are built from the
process profiles that consume the executable identity issued here.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from hermes_installer.protected_enrollment import (
    ProtectedEnrollmentCatalog, ProtectedRootJournalCatalog,
)
from .types import AuthorityDenied

_MAX_PM_IDENTITIES = 4


class CommittedPMExecutableUnavailable(AuthorityDenied):
    """The protected current worker has no complete PM executable identity."""

    def __init__(self, message: str):
        super().__init__("native_worker.pm_executable", message)


@dataclass(frozen=True, slots=True, repr=False)
class RootVerifiedCommittedPMExecutableIdentity:
    """Short-lived sealed observation of one selected PM committed venv."""

    identity_handle: str
    service_generation_digest: str
    publication_receipt_handle: str
    publication_sha256: str
    active_generation_id: str
    network_id: str
    profile_id: str
    service_generation: str
    runtime_record_id: str
    runtime_record_sha256: str
    source_choice_selection_handle: str
    source_choice_signed_record_sha256: str
    source_original_setup_deadline_unix: float
    pm_runtime_receipt_handle: str
    pm_receipt_sha256: str
    pm_generation: str
    source_commit: str
    runtime_relative: str
    runtime_venv_relative: str
    runtime_closure_sha256: str
    executable_path: Path
    executable_sha256: str
    executable_device: int
    executable_inode: int
    executable_uid: int
    executable_gid: int
    executable_mode: int
    expires_monotonic: float
    member_fds: tuple[int, ...] = field(repr=False)
    _custody: "_IdentityCustody" = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootVerifiedCommittedPMExecutableIdentity(<root-private>)"

    def close(self) -> None:
        self._custody.release(self)


class _IdentityCustody:
    """Idempotent descriptor owner shared by identity and resolver registry."""

    def __init__(self, handle: str, fds: tuple[int, ...],
                 issued: dict[str, RootVerifiedCommittedPMExecutableIdentity],
                 owner_lock: threading.RLock):
        self.handle = handle
        self.fds = tuple(set(fds))
        self.issued = issued
        self.owner_lock = owner_lock
        self.closed = False
        self.lock = threading.Lock()

    def release(self, identity: RootVerifiedCommittedPMExecutableIdentity) -> None:
        with self.lock:
            if self.closed:
                return
            self.closed = True
            fds = self.fds
            self.fds = ()
        _close_fds(list(fds))
        with self.owner_lock:
            if self.issued.get(self.handle) is identity:
                self.issued.pop(self.handle, None)


class RootActiveCommittedPMExecutableResolver:
    """Reopen the selected active choice, PM receipt and full venv before profiles."""

    def __init__(self, catalog: ProtectedEnrollmentCatalog,
                 root_journal_catalog: ProtectedRootJournalCatalog,
                 release: Any, actor: Any, *, _seal: object):
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        if (_seal is not _RESOLVER_SEAL or type(catalog) is not ProtectedEnrollmentCatalog
                or type(root_journal_catalog) is not ProtectedRootJournalCatalog
                or type(release) is not VerifiedInstallerReleaseReceipt
                or type(actor) is not RootActorObservation
                or catalog.digest != root_journal_catalog.generation_digest):
            raise CommittedPMExecutableUnavailable(
                "pre-profile PM resolver requires exact protected catalog, journal, release and actor receipts")
        self._catalog = catalog
        self._journals = root_journal_catalog
        self._release = release
        self._actor = actor
        self._issuer = object()
        self._issued: dict[str, RootVerifiedCommittedPMExecutableIdentity] = {}
        self._identity_lock = threading.RLock()
        self._pending_resolutions = 0
        self._closed = False

    @classmethod
    def from_protected_runtime_sources(
            cls, enrollment_catalog: ProtectedEnrollmentCatalog,
            root_journal_catalog: ProtectedRootJournalCatalog,
            installed_release: Any, current_actor: Any
            ) -> "RootActiveCommittedPMExecutableResolver":
        return cls(enrollment_catalog, root_journal_catalog, installed_release,
                   current_actor, _seal=_RESOLVER_SEAL)

    def resolve_selected(self) -> RootVerifiedCommittedPMExecutableIdentity:
        """Select and independently observe the unique active native worker."""
        self._begin_resolution()
        try:
            from .setup_policy_publication import PolicyPublicationReceiptResolver
            publication = PolicyPublicationReceiptResolver.resolve_current()
            if (publication.state != "active-committed"
                    or publication.service_generation_digest != self._catalog.digest):
                raise ValueError("published generation differs from protected enrollment")
            candidates = self._catalog.resolve_selected_native_worker_generation_candidates(
                publication.service_generation_digest)
            if len(candidates) != 1:
                raise ValueError("current native worker candidate is absent or ambiguous")
            network, active, runtime, _process_profile, service = candidates[0]
            self._verify_rows(network, active, runtime, service, publication)
            choice = self._verify_current_choice(active, runtime, publication)
            root_journal = self._journals.resolve(
                active["root_journal_id"],
                expected_active_generation_digest=self._catalog.digest,
            )
            if root_journal.generation != active["root_journal_generation"]:
                raise ValueError("current runtime row selects a stale root journal")
            row_digest = _digest(_plain(runtime))
            member_fds = self._observe_source_members(runtime)
            identity: RootVerifiedCommittedPMExecutableIdentity | None = None
            try:
                observed, pm_fds = self._observe_pm(runtime, root_journal.path)
                member_fds.extend(pm_fds)
                current_publication = PolicyPublicationReceiptResolver.resolve_current()
                if (current_publication.receipt_handle != publication.receipt_handle
                        or current_publication.publication_sha256 != publication.publication_sha256
                        or current_publication.service_generation_digest != publication.service_generation_digest):
                    raise ValueError("active publication changed during PM observation")
                current_choice = self._verify_current_choice(active, runtime, current_publication)
                if (current_choice["signed_record_sha256"] != choice["signed_record_sha256"]
                        or current_choice["setup_deadline_unix"] != choice["setup_deadline_unix"]):
                    raise ValueError("signed worker choice changed during PM observation")
                current_candidates = self._catalog.resolve_selected_native_worker_generation_candidates(
                    current_publication.service_generation_digest)
                if (len(current_candidates) != 1
                        or _digest(_plain(current_candidates[0][2])) != row_digest):
                    raise ValueError("selected PM runtime row changed during observation")
                self._require_live()
                identity_handle = os.urandom(32).hex()
                identity = RootVerifiedCommittedPMExecutableIdentity(
                    identity_handle=identity_handle,
                    service_generation_digest=self._catalog.digest,
                    publication_receipt_handle=publication.receipt_handle,
                    publication_sha256=publication.publication_sha256,
                    active_generation_id=active["generation_id"],
                    network_id=network["id"], profile_id=service.profile_id,
                    service_generation=service.generation,
                    runtime_record_id=runtime["id"], runtime_record_sha256=row_digest,
                    source_choice_selection_handle=choice["selection_handle"],
                    source_choice_signed_record_sha256=choice["signed_record_sha256"],
                    source_original_setup_deadline_unix=choice["setup_deadline_unix"],
                    pm_runtime_receipt_handle=observed["receipt_handle"],
                    pm_receipt_sha256=observed["receipt_sha256"],
                    pm_generation=observed["generation"], source_commit=observed["source_commit"],
                    runtime_relative=observed["runtime_relative"],
                    runtime_venv_relative=observed["runtime_venv_relative"],
                    runtime_closure_sha256=observed["runtime_closure_sha256"],
                    executable_path=observed["executable_path"],
                    executable_sha256=observed["executable_sha256"],
                    executable_device=observed["executable_device"],
                    executable_inode=observed["executable_inode"],
                    executable_uid=observed["executable_uid"],
                    executable_gid=observed["executable_gid"],
                    executable_mode=observed["executable_mode"],
                    # Adoption was required to occur before the original
                    # setup deadline. Once adopted and currently published,
                    # the active proof gets its own short lease.
                    expires_monotonic=min(_fresh_active_lease(time.monotonic()),
                                          choice["active_lease_expires_monotonic"]),
                    member_fds=tuple(member_fds),
                    _custody=_IdentityCustody(identity_handle, tuple(member_fds), self._issued,
                                               self._identity_lock),
                    _issuer=self._issuer,
                )
                if identity.expires_monotonic <= time.monotonic():
                    raise ValueError("original adopted setup deadline has expired")
                with self._identity_lock:
                    if self._closed:
                        identity.close()
                        raise CommittedPMExecutableUnavailable("pre-profile PM resolver is closed")
                    self._issued[identity.identity_handle] = identity
                return identity
            except BaseException:
                if identity is not None:
                    identity.close()
                else:
                    _close_fds(member_fds)
                raise
        except CommittedPMExecutableUnavailable:
            raise
        except Exception:
            raise CommittedPMExecutableUnavailable(
                "current signed worker source or committed PM executable is unavailable") from None
        finally:
            self._end_resolution()

    def verify_current(self, identity: RootVerifiedCommittedPMExecutableIdentity
                       ) -> RootVerifiedCommittedPMExecutableIdentity:
        self._require_live()
        if (type(identity) is not RootVerifiedCommittedPMExecutableIdentity
                or identity._issuer is not self._issuer):
            raise CommittedPMExecutableUnavailable("PM executable identity is foreign or stale")
        with self._identity_lock:
            owned = self._issued.get(identity.identity_handle) is identity
        if not owned or identity._custody.closed:
            raise CommittedPMExecutableUnavailable("PM executable identity is foreign or stale")
        if identity.expires_monotonic <= time.monotonic():
            identity.close()
            raise CommittedPMExecutableUnavailable("PM executable identity is foreign or stale")
        current = self.resolve_selected()
        try:
            if _identity_values(current) != _identity_values(identity):
                identity.close()
                raise CommittedPMExecutableUnavailable("current PM executable identity changed")
        finally:
            current.close()
            self._issued.pop(current.identity_handle, None)
        return identity

    def close(self) -> None:
        with self._identity_lock:
            self._closed = True
            identities = tuple(self._issued.values())
        for identity in identities:
            identity.close()

    def _begin_resolution(self) -> None:
        self._require_live()
        with self._identity_lock:
            expired = tuple(identity for identity in self._issued.values()
                            if identity.expires_monotonic <= time.monotonic())
            for identity in expired:
                identity.close()
            if len(self._issued) + self._pending_resolutions >= _MAX_PM_IDENTITIES:
                raise CommittedPMExecutableUnavailable(
                    "too many outstanding PM executable observations; close or verify an existing identity")
            self._pending_resolutions += 1

    def _end_resolution(self) -> None:
        with self._identity_lock:
            self._pending_resolutions = max(0, self._pending_resolutions - 1)

    def _require_live(self) -> None:
        if self._closed:
            raise CommittedPMExecutableUnavailable("pre-profile PM resolver is closed")
        try:
            self._release.verify_current()
            self._actor.verify_current(self._release)
            _read_authority_key()
        except Exception:
            self.close()
            raise CommittedPMExecutableUnavailable(
                "held installer release, root actor, or authority key is no longer current") from None

    def _verify_rows(self, network: Mapping[str, Any], active: Mapping[str, Any],
                     runtime: Mapping[str, Any], service: Any, publication: Any) -> None:
        descriptor = runtime.get("committed_venv_identity")
        if (network.get("role") != "af-unix"
                or runtime.get("execution_mode") != "native-hermes-cli-module-v1"
                or active.get("worker_runtime_record_id") != runtime.get("id")
                or active.get("worker_runtime_record_sha256") != _digest(_plain(runtime))
                or active.get("generation_id") != publication.generation_id
                or active.get("source_choice_selection_handle") is None
                or not isinstance(descriptor, Mapping)
                or descriptor.get("executable_identity_id") != "observed:pm-committed-venv-python"
                or service.generation != active.get("service_generation")
                or service.profile_id != active.get("process_profile_id")
                or service.enrollment_id != active.get("service_enrollment_id")
                or service.principal_id != active.get("principal_id")
                or service.namespace_identity != active.get("namespace_id")):
            raise ValueError("selected network, runtime and service profile do not join the finite PM recipe")

    def _observe_source_members(self, runtime: Mapping[str, Any]) -> list[int]:
        """Reopen exact recipe/adapter release members represented in the row."""
        records = runtime.get("source_definition_member_records")
        handles = runtime.get("source_member_receipt_handles")
        if (not isinstance(records, (list, tuple)) or not records
                or not isinstance(handles, (list, tuple))
                or tuple(handles) != tuple(sorted(set(handles)))
                or len(handles) != len(records) or len(records) > 128):
            raise ValueError("active worker source member rows are malformed")
        indexed = {item.artifact_id: item for item in self._release.files}
        if len(indexed) != len(self._release.files):
            raise ValueError("held release has duplicate source artifact identities")
        held: list[int] = []
        observed_handles: list[str] = []
        seen_rows: set[tuple[str, str]] = set()
        seen_handles: set[str] = set()
        try:
            self._release.verify_current()
            for item in records:
                if not isinstance(item, Mapping):
                    raise ValueError("active source member row is not typed data")
                key = (item["artifact_id"], item["relative_path"])
                if key in seen_rows or item["receipt_handle"] in seen_handles:
                    raise ValueError("active source member row or receipt handle is duplicated")
                seen_rows.add(key)
                seen_handles.add(item["receipt_handle"])
                observed_handles.append(item["receipt_handle"])
                member = indexed.get(item["artifact_id"])
                if (member is None or member.relative_path != item["relative_path"]
                        or member.sha256 != item["sha256"]
                        or member.size_bytes != item["size_bytes"]
                        or member.roles not in {("module",), ("source-module",)}):
                    raise ValueError("active source member is outside the exact held release")
                fd = self._release.open_file(member.artifact_id)
                held.append(fd)
                info = os.fstat(fd)
                digest = hashlib.sha256()
                offset = 0
                while offset < info.st_size:
                    block = os.pread(fd, min(1024 * 1024, info.st_size - offset), offset)
                    if not block:
                        raise ValueError("held source member shortened while hashing")
                    digest.update(block)
                    offset += len(block)
                if ((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_size,
                     info.st_dev, info.st_ino, digest.hexdigest())
                        != (item["owner_uid"], item["owner_gid"], item["mode"],
                            item["size_bytes"], item["device"], item["inode"], item["sha256"])):
                    raise ValueError("held source member differs from the active signed source row")
            if tuple(sorted(observed_handles)) != tuple(handles):
                raise ValueError("source member receipt handles differ from held row closure")
            self._release.verify_current()
            return held
        except BaseException:
            _close_fds(held)
            raise

    def _verify_current_choice(self, active: Mapping[str, Any], runtime: Mapping[str, Any],
                               publication: Any) -> dict[str, Any]:
        from .setup_policy_publication import PolicyPublicationReceiptResolver
        from .service import _ROOT_SETUP_CHOICE_DOMAIN

        handle = active["source_choice_selection_handle"]
        adoption = _select_exact_adoption(publication.choice_adoptions, handle)
        row, revoked = _read_choice_rows(
            self._journals.resolve(active["root_journal_id"],
                                   expected_active_generation_digest=self._catalog.digest).path)
        if handle not in row:
            raise ValueError("signed setup choice source row is absent")
        key = _read_authority_key()
        for choice_handle, choice_row in row.items():
            if (not isinstance(choice_row, dict)
                    or choice_row.get("selection_handle") != choice_handle):
                raise ValueError("protected setup choice store key does not match its row")
        _verify_revocation_index(
            revoked, choices=row, key=key, service_generation_digest=self._catalog.digest,
            release_deployment_receipt_sha256=self._release.deployment_receipt_sha256,
        )
        _require_not_revoked(handle, revoked)
        signed = row[handle]
        _verify_signed_choice(signed, key)
        canonical = _canonical(signed)
        row_sha = hashlib.sha256(canonical).hexdigest()
        payload = signed["choice_payload"]
        if (signed["selection_handle"] != handle
                or signed["purpose"] != "native-policy-preparation"
                or row_sha != adoption.signed_record_sha256
                or row_sha != active.get("source_choice_signed_record_sha256")
                or signed["choice_payload_sha256"] != adoption.choice_payload_sha256
                or signed["choice_payload_sha256"] != active.get("source_choice_payload_sha256")
                or signed["choice_epoch"] != adoption.choice_epoch
                or signed["choice_epoch"] != active.get("source_choice_epoch")
                or signed["revocation_epoch"] != adoption.revocation_epoch
                or signed["revocation_epoch"] != active.get("source_choice_revocation_epoch")
                or signed["key_id"] != adoption.key_id
                or signed["release_deployment_receipt_sha256"] != self._release.deployment_receipt_sha256
                or tuple(signed["source_member_receipt_handles"]) != adoption.source_member_receipt_handles
                or tuple(signed["source_member_receipt_handles"])
                   != tuple(runtime.get("source_member_receipt_handles", ()))
                or tuple(signed["source_member_receipt_handles"])
                   != tuple(active.get("source_member_receipt_handles", ()))
                or signed["setup_session_handle"] != adoption.setup_session_handle
                or signed["transaction_handle"] != adoption.transaction_handle
                or signed["plan_id"] != adoption.plan_id
                or signed["prepared_generation"] != adoption.prepared_generation
                or signed["principal_selection_handle"] != adoption.principal_selection_handle
                or signed["namespace_selection_handle"] != adoption.namespace_selection_handle
                or signed["private_profile_selection_handle"] != adoption.private_profile_selection_handle
                or adoption.publication_receipt_handle != publication.receipt_handle
                or adoption.publication_sha256 != publication.publication_sha256
                or adoption.service_generation_digest != self._catalog.digest
                or adoption.generation_id != publication.generation_id
                or adoption.profile_id != active["process_profile_id"]
                or adoption.principal_id != active["principal_id"]
                or adoption.namespace_id != active["namespace_id"]
                or adoption.principal_binding_sha256 != active["principal_binding_sha256"]
                or adoption.namespace_binding_sha256 != active["namespace_binding_sha256"]
                or signed["setup_deadline_unix"] != active.get("source_original_setup_deadline_unix")
                or payload.get("service_profile_id") != active["process_profile_id"]
                or payload.get("service_generation") != active["process_profile_generation"]
                or payload.get("principal_binding_sha256") != active["principal_binding_sha256"]
                or payload.get("namespace_binding_sha256") != active["namespace_binding_sha256"]
                or not _valid_active_adoption_window(
                    signed.get("issued_at_unix"), signed.get("setup_deadline_unix"),
                    adoption.adopted_at_unix)):
            raise ValueError("current publisher adoption no longer matches signed choice source")
        selected = [item for item in payload.get("selected_worker_recipe_records", [])
                    if isinstance(item, Mapping)
                    and item.get("receipt_handle") == active.get("recipe_definition_receipt_handle")
                    and item.get("recipe_sha256") == active.get("recipe_sha256")]
        if len(selected) != 1:
            raise ValueError("signed choice does not select the active worker recipe")
        # Re-resolve the publisher projection to close the descriptor/current
        # pointer race. The signed row and revocation index are independently
        # reopened on each call.
        current = PolicyPublicationReceiptResolver.resolve_current_choice_adoption(handle)
        _require_same_current_adoption(current, adoption, publication.receipt_handle)
        return {
            "selection_handle": handle,
            "signed_record_sha256": row_sha,
            "setup_deadline_unix": signed["setup_deadline_unix"],
            "active_lease_expires_monotonic": _fresh_active_lease(time.monotonic()),
        }

    def _observe_pm(self, runtime: Mapping[str, Any], journal_path: Path
                    ) -> tuple[dict[str, Any], list[int]]:
        from .pm_runtime import SOURCE_COMMIT, PYTHON_ID, PYTHON_SHA256
        root_fd = _open_owned_directory(journal_path / "pm-runtimes", 0o700)
        fds = [root_fd]
        try:
            receipts_fd = os.open("receipts", os.O_RDONLY | os.O_DIRECTORY
                                  | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
            fds.append(receipts_fd)
            receipts_info = os.fstat(receipts_fd)
            if (receipts_info.st_uid != 0 or receipts_info.st_gid != 0
                    or stat.S_IMODE(receipts_info.st_mode) != 0o700):
                raise ValueError("PM receipt directory is not protected")
            handle = runtime["pm_runtime_receipt_handle"]
            if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle):
                raise ValueError("PM receipt handle is malformed")
            receipt_fd = os.open(handle + ".json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=receipts_fd)
            fds.append(receipt_fd)
            receipt_info = os.fstat(receipt_fd)
            if (not stat.S_ISREG(receipt_info.st_mode) or receipt_info.st_uid != 0
                    or receipt_info.st_gid != 0 or stat.S_IMODE(receipt_info.st_mode) != 0o600
                    or receipt_info.st_nlink != 1):
                raise ValueError("PM receipt file custody is unsafe")
            raw = _read_fd(receipt_fd, 64 * 1024)
            receipt = _strict_json(raw)
            descriptor = runtime["committed_venv_identity"]
            if (receipt.get("handle") != handle or receipt.get("schema") != 1
                    or receipt.get("source_commit") != SOURCE_COMMIT
                    or receipt.get("base_python_artifact_id") != PYTHON_ID
                    or receipt.get("base_python_sha256") != PYTHON_SHA256
                    or receipt.get("pm_sync_outcome") != "succeeded"
                    or receipt.get("generation") != descriptor.get("pm_generation")
                    or receipt.get("source_commit") != descriptor.get("source_commit")
                    or receipt.get("runtime_relative") != descriptor.get("runtime_relative")
                    or receipt.get("runtime_venv_relative") != descriptor.get("runtime_venv_relative")
                    or receipt.get("runtime_closure_sha256") != descriptor.get("runtime_closure_sha256")
                    or hashlib.sha256(raw).hexdigest() != descriptor.get("pm_receipt_sha256")):
                raise ValueError("PM receipt bytes differ from the selected signed descriptor")
            generation = receipt["generation"]
            if not re.fullmatch(r"pm-[0-9a-f]{32}", generation):
                raise ValueError("PM runtime generation is malformed")
            base = Path(journal_path) / "pm-runtimes" / generation
            generation_fd = _open_owned_directory(base, 0o700)
            fds.append(generation_fd)
            executable = base / receipt["runtime_relative"]
            venv_root = base / receipt["runtime_venv_relative"]
            from .pm_runtime import (_observe_runtime, _match_receipt,
                                     observe_committed_pm_venv_tree)
            identity = _observe_runtime(executable, expected_uid=0, expected_root=base)
            _match_receipt(receipt, executable, identity, executable.parent.parent)
            tree = observe_committed_pm_venv_tree(
                venv_root, expected_closure_sha256=receipt["runtime_closure_sha256"],
            )
            fds.append(tree.root_fd)
            fds.extend(member.fd for member in tree.members if member.fd is not None)
            resolved_executable = executable.resolve(strict=True)
            executable_member_rel = resolved_executable.relative_to(venv_root.resolve(strict=True)).as_posix()
            executable_member = next((member for member in tree.members
                                      if member.relative_path == executable_member_rel
                                      and member.kind == "file"), None)
            expected_executable = {
                "sha256": identity["sha256"], "device": identity["device"],
                "inode": identity["inode"], "uid": identity["uid"], "gid": identity["gid"],
                "mode": identity["mode"],
            }
            if (executable_member is None
                    or (executable_member.sha256, executable_member.device,
                        executable_member.inode, executable_member.uid,
                        executable_member.gid, executable_member.mode)
                       != (identity["sha256"], identity["device"], identity["inode"],
                           identity["uid"], identity["gid"], identity["mode"])):
                raise ValueError("observed executable is not a held member of its complete venv")
            if ({"schema": 1, "identity_kind": "pm-committed-hermes-venv-v1",
                 "pm_runtime_receipt_handle": handle,
                 "pm_receipt_sha256": hashlib.sha256(raw).hexdigest(),
                 "pm_generation": generation, "source_commit": receipt["source_commit"],
                 "runtime_relative": receipt["runtime_relative"],
                 "runtime_venv_relative": receipt["runtime_venv_relative"],
                 "runtime_closure_sha256": receipt["runtime_closure_sha256"],
                 "executable_identity_id": "observed:pm-committed-venv-python",
                 "executable_sha256": expected_executable["sha256"],
                 "executable_device": expected_executable["device"],
                 "executable_inode": expected_executable["inode"],
                 "executable_uid": expected_executable["uid"],
                 "executable_gid": expected_executable["gid"],
                 "executable_mode": expected_executable["mode"]}
                    != dict(descriptor)):
                raise ValueError("descriptor differs from actual current PM executable")
            return ({"receipt_handle": handle, "receipt_sha256": hashlib.sha256(raw).hexdigest(),
                     "generation": generation, "source_commit": receipt["source_commit"],
                     "runtime_relative": receipt["runtime_relative"],
                     "runtime_venv_relative": receipt["runtime_venv_relative"],
                     "runtime_closure_sha256": receipt["runtime_closure_sha256"],
                     "executable_path": resolved_executable,
                     "executable_sha256": identity["sha256"],
                     "executable_device": identity["device"],
                     "executable_inode": identity["inode"],
                     "executable_uid": identity["uid"],
                     "executable_gid": identity["gid"],
                     "executable_mode": identity["mode"]}, fds)
        except BaseException:
            _close_fds(fds)
            raise


_RESOLVER_SEAL = object()


def _verify_signed_choice(row: Any, key: bytes) -> None:
    from .root_setup_choices import _RECORD_FIELDS
    from .service import _ROOT_SETUP_CHOICE_DOMAIN
    if not isinstance(row, dict) or set(row) != _RECORD_FIELDS:
        raise ValueError("signed choice row fields are invalid")
    unsigned = {name: value for name, value in row.items() if name != "signature"}
    purpose = row.get("purpose")
    if (purpose != "native-policy-preparation"
            or not isinstance(row.get("signature"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", row["signature"])):
        raise ValueError("signed native choice row is malformed")
    from .service import _validate_setup_choice_record_bytes
    payload = _canonical(unsigned)
    _validate_setup_choice_record_bytes(purpose, payload, expected_key_id=row.get("key_id"))
    expected = hmac.new(key, _ROOT_SETUP_CHOICE_DOMAIN + purpose.encode("ascii") + b"\0" + payload,
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, row["signature"]):
        raise ValueError("signed native choice HMAC is invalid")


def _valid_active_adoption_window(issued_at: Any, setup_deadline: Any,
                                  adopted_at: Any) -> bool:
    """The original deadline constrains adoption, not later active use."""
    values = (issued_at, setup_deadline, adopted_at)
    if any(type(value) not in (int, float) or not math.isfinite(value) for value in values):
        return False
    return issued_at <= adopted_at <= setup_deadline


def _require_same_current_adoption(current: Any, adopted: Any,
                                   publication_handle: str) -> None:
    if (current.signed_record_sha256 != adopted.signed_record_sha256
            or current.publication_receipt_handle != publication_handle
            or adopted.publication_receipt_handle != publication_handle):
        raise ValueError("publisher choice adoption changed during source verification")


def _select_exact_adoption(rows: Any, selection_handle: str) -> Any:
    selected = [row for row in rows
                if row.selection_handle == selection_handle
                and row.purpose == "native-policy-preparation"]
    if len(selected) != 1:
        raise ValueError("current active publication has no unique signed native choice adoption")
    return selected[0]


def _fresh_active_lease(now_monotonic: float) -> float:
    return now_monotonic + 30.0


def _require_not_revoked(selection_handle: str, revocations: Mapping[str, Any]) -> None:
    if selection_handle in revocations:
        raise ValueError("signed setup choice has a durable revocation")


def _verify_revocation_index(index: Any, *, choices: Mapping[str, Any], key: bytes,
                             service_generation_digest: str,
                             release_deployment_receipt_sha256: str) -> None:
    from .service import _ROOT_SETUP_CHOICE_REVOCATION_DOMAIN
    claims_fields = {
        "schema", "revocation_receipt_handle", "selection_handle", "purpose", "consent_id",
        "previous_choice_epoch", "previous_revocation_epoch", "revocation_epoch",
        "source_choice_row_sha256", "revocation_observation_handle", "displayed_payload_sha256",
        "key_id", "release_deployment_receipt_sha256", "service_generation_digest", "revoked_at_unix",
    }
    if not isinstance(index, dict):
        raise ValueError("protected choice revocation index is malformed")
    for handle, record in index.items():
        if (not isinstance(handle, str) or not isinstance(record, dict)
                or set(record) != claims_fields | {"signature"}):
            raise ValueError("protected choice revocation row has invalid fields")
        claims = {name: value for name, value in record.items() if name != "signature"}
        if (record.get("selection_handle") != handle
                or record.get("schema") != 1
                or record.get("service_generation_digest") != service_generation_digest
                or record.get("release_deployment_receipt_sha256") != release_deployment_receipt_sha256
                or type(record.get("previous_choice_epoch")) is not int
                or type(record.get("previous_revocation_epoch")) is not int
                or type(record.get("revocation_epoch")) is not int
                or record["revocation_epoch"] != record["previous_revocation_epoch"] + 1
                or type(record.get("revoked_at_unix")) not in (int, float)
                or not isinstance(record.get("signature"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["signature"])):
            raise ValueError("protected choice revocation row is malformed")
        payload = _canonical(claims)
        expected = hmac.new(key, _ROOT_SETUP_CHOICE_REVOCATION_DOMAIN + payload,
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, record["signature"]):
            raise ValueError("protected choice revocation signature is invalid")
        source = choices.get(handle)
        if (not isinstance(source, dict)
                or record["purpose"] != source.get("purpose")
                or record["previous_choice_epoch"] != source.get("choice_epoch")
                or record["previous_revocation_epoch"] != source.get("revocation_epoch")
                or record["source_choice_row_sha256"] != hashlib.sha256(_canonical(source)).hexdigest()
                or record["displayed_payload_sha256"] != source.get("choice_payload_sha256")
                or record["key_id"] != source.get("key_id")):
            raise ValueError("protected revocation does not join its current signed choice row")


def _read_authority_key() -> bytes:
    from .enrollment import AUTHORITY_KEY_PATH, read_protected_file
    key = read_protected_file(AUTHORITY_KEY_PATH, expected_uid=0, maximum=64)
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("protected authority key has invalid size")
    return key


def _read_choice_rows(journal_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    return (_read_protected_index(journal_path, "setup-choices"),
            _read_protected_index(journal_path, "setup-choice-revocations"))


def _read_protected_index(journal_path: Path, directory_name: str) -> dict[str, Any]:
    root_fd = _open_owned_directory(journal_path, None)
    directory_fd = -1
    file_fd = -1
    try:
        directory_fd = os.open(directory_name, os.O_RDONLY | os.O_DIRECTORY
                               | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        directory = os.fstat(directory_fd)
        if (directory.st_uid != 0 or directory.st_gid != 0
                or stat.S_IMODE(directory.st_mode) != 0o700
                or directory.st_dev != os.fstat(root_fd).st_dev):
            raise ValueError("setup choice index directory is unsafe")
        file_fd = os.open("registry.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=directory_fd)
        info = os.fstat(file_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > 1_048_576):
            raise ValueError("setup choice index file custody is unsafe")
        data = _read_fd(file_fd, 1_048_576)
        outer = _strict_json(data)
        profiles = outer.get("profiles")
        if outer.get("schema") != 1 or not isinstance(profiles, dict):
            raise ValueError("setup choice index schema is invalid")
        return profiles
    finally:
        for fd in (file_fd, directory_fd, root_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _open_owned_directory(path: Path, mode: int | None) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or (mode is not None and stat.S_IMODE(info.st_mode) != mode)):
        os.close(fd)
        raise ValueError("selected root directory is not protected")
    return fd


def _read_fd(fd: int, ceiling: int) -> bytes:
    info = os.fstat(fd)
    if info.st_size > ceiling:
        raise ValueError("protected file exceeds its size bound")
    chunks: list[bytes] = []
    total = 0
    while True:
        block = os.read(fd, min(65536, ceiling + 1 - total))
        if not block:
            return b"".join(chunks)
        chunks.append(block)
        total += len(block)
        if total > ceiling:
            raise ValueError("protected file exceeds its size bound")


def _strict_json(data: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    value = json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                       parse_constant=lambda _item: (_ for _ in ()).throw(ValueError()))
    if not isinstance(value, dict) or _canonical(value) != data:
        raise ValueError("protected record is not canonical JSON")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _close_fds(fds: list[int]) -> None:
    for fd in set(fds):
        try:
            os.close(fd)
        except OSError:
            pass


def _identity_values(value: RootVerifiedCommittedPMExecutableIdentity) -> tuple[Any, ...]:
    return tuple(getattr(value, name) for name in (
        "service_generation_digest", "publication_receipt_handle", "publication_sha256",
        "active_generation_id", "network_id", "profile_id", "service_generation",
        "runtime_record_id", "runtime_record_sha256", "source_choice_selection_handle",
        "source_choice_signed_record_sha256", "source_original_setup_deadline_unix",
        "pm_runtime_receipt_handle", "pm_receipt_sha256", "pm_generation", "source_commit",
        "runtime_relative", "runtime_venv_relative", "runtime_closure_sha256",
        "executable_path", "executable_sha256", "executable_device", "executable_inode",
        "executable_uid", "executable_gid", "executable_mode",
    ))
