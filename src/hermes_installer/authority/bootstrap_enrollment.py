"""Transactional root bootstrap for a dedicated Hermes service identity.

This module is the sole writer for a new protected service-generation snapshot.
All selection policy and artifact receipt resolution are supplied by root-owned
adapters; callers submit only opaque artifact receipt handles and an intent.
"""
from __future__ import annotations

import hashlib
import json
import os
import pwd
import grp
import secrets
import stat
import subprocess
import re
import fcntl
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol


MAX_AUTHORITY_BYTES = 8 * 1024 * 1024
SERVICE_NAME = "hermes-installer"


class BootstrapEnrollmentError(RuntimeError):
    """Bootstrap failed safely; message text is suitable for a diagnostic."""


class BootstrapEnrollmentPending(BootstrapEnrollmentError):
    """A required root-enrolled artifact or account prerequisite is absent."""


@dataclass(frozen=True, slots=True)
class BootstrapEnrollmentRequest:
    artifact_receipt_handles: tuple[str, ...]
    operation_intent: str


@dataclass(frozen=True, slots=True)
class ServiceIdentity:
    name: str
    uid: int
    gid: int
    created: bool = False


@dataclass(frozen=True, slots=True)
class VerifiedArtifactReceipt:
    """Root resolver output. ``source`` is never accepted from a request."""
    receipt_id: str
    artifact_id: str
    sha256: str
    source: Path
    maximum_bytes: int


@dataclass(frozen=True, slots=True)
class EnrollmentPolicy:
    """Root-selected complete protected service catalog and private root layout."""
    service_profile_id: str
    principal_id: str
    generation_id: str
    source_artifact_id: str
    records: tuple[Mapping[str, Any], ...]
    protected_devices: tuple[Mapping[str, Any], ...] = ()
    protected_build_records: tuple[Mapping[str, Any], ...] = ()
    native_packages: tuple[Mapping[str, Any], ...] = ()
    memory_enrollments: tuple[Mapping[str, Any], ...] = ()
    operation_parameter_schemas: tuple[Mapping[str, Any], ...] = ()
    source_issuers: tuple[Mapping[str, Any], ...] = ()
    resource_jobs: tuple[Mapping[str, Any], ...] = ()
    remote_session_enrollments: tuple[Mapping[str, Any], ...] = ()
    authority_base: Mapping[str, Any] | None = None
    home_root: Path = Path("/var/lib/hermes-installer/services/default/home")
    work_root: Path = Path("/var/lib/hermes-installer/services/default/work")
    data_root: Path = Path("/var/lib/hermes-installer/services/default/data")


@dataclass(frozen=True, slots=True)
class EnrollmentReceipt:
    schema: int
    transaction_handle: str
    provision_receipt_handle: str
    generation_id: str
    generation_digest: str
    previous_generation_digest: str | None
    state: str
    enrollment_ids: tuple[str, ...]
    issued_monotonic: float
    expires_monotonic: float


class IdentityAdapter(Protocol):
    def ensure(self) -> ServiceIdentity: ...
    def remove_if_created(self, identity: ServiceIdentity) -> None: ...


class ReceiptResolver(Protocol):
    def resolve(self, handle: str) -> VerifiedArtifactReceipt: ...


class SystemIdentityAdapter:
    """Create an unprivileged system account, accepting reuse only with our marker."""
    def __init__(self, marker: Path, *, name: str = SERVICE_NAME):
        self.marker = marker
        self.name = name

    def ensure(self) -> ServiceIdentity:
        if os.geteuid() != 0 or not _linux():
            raise BootstrapEnrollmentPending("dedicated service identity enrollment requires Linux root")
        marker = _read_json_if_owned(self.marker)
        try:
            account = pwd.getpwnam(self.name)
        except KeyError:
            account = None
        try:
            group = grp.getgrnam(self.name)
        except KeyError:
            group = None
        if account is not None or group is not None:
            if (marker is None or account is None or group is None
                    or marker != {"schema": 1, "name": self.name,
                                  "uid": account.pw_uid, "gid": account.pw_gid}
                    or account.pw_gid != group.gr_gid or account.pw_dir not in {"/nonexistent", "/"}
                    or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}):
                raise BootstrapEnrollmentError("existing service account conflicts with installer ownership")
            return ServiceIdentity(self.name, account.pw_uid, account.pw_gid)
        _ensure_root_chain(self.marker.parent, ceiling=Path("/var/lib/hermes-installer"))
        try:
            subprocess.run(["/usr/sbin/groupadd", "--system", self.name], check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=15)
            subprocess.run(["/usr/sbin/useradd", "--system", "--gid", self.name,
                            "--no-create-home", "--home-dir", "/nonexistent",
                            "--shell", "/usr/sbin/nologin", self.name], check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=15)
            account = pwd.getpwnam(self.name)
            group = grp.getgrnam(self.name)
            if account.pw_gid != group.gr_gid:
                raise BootstrapEnrollmentError("created service account has an unexpected group")
            _atomic_root_file(self.marker, _canonical({"schema": 1, "name": self.name,
                                                       "uid": account.pw_uid, "gid": account.pw_gid}), 0o600)
            return ServiceIdentity(self.name, account.pw_uid, account.pw_gid, True)
        except Exception:
            # Preserve partial/ambiguous OS account state for explicit recovery.
            raise BootstrapEnrollmentError("dedicated service account creation failed; inspect the root transaction journal") from None

    def remove_if_created(self, identity: ServiceIdentity) -> None:
        if not identity.created:
            return
        try:
            current = pwd.getpwnam(identity.name)
            group = grp.getgrnam(identity.name)
        except KeyError:
            return
        marker = _read_json_if_owned(self.marker)
        expected = {"schema": 1, "name": identity.name, "uid": identity.uid, "gid": identity.gid}
        if (marker != expected or current.pw_uid != identity.uid or current.pw_gid != identity.gid
                or group.gr_gid != identity.gid):
            raise BootstrapEnrollmentError("service identity ownership changed; rollback refused")
        subprocess.run(["/usr/sbin/userdel", identity.name], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15)
        subprocess.run(["/usr/sbin/groupdel", identity.name], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15)
        self.marker.unlink()


class RootBootstrapEnrollment:
    """Prepare service-owned roots and atomically publish a digest-bound snapshot."""
    def __init__(self, *, policy_resolver: Callable[[BootstrapEnrollmentRequest], EnrollmentPolicy],
                 receipt_resolver: ReceiptResolver, identity: IdentityAdapter,
                 record_builder: Callable[[EnrollmentPolicy, ServiceIdentity], tuple[Mapping[str, Any], ...]] | None = None,
                 authority_builder: Callable[[Mapping[str, Any] | None, EnrollmentPolicy, ServiceIdentity], Mapping[str, Any]] | None = None,
                 authority_path: Path = Path("/etc/hermes-installer/authority.json"),
                 transaction_root: Path = Path("/var/lib/hermes-installer/bootstrap-transactions"),
                 artifact_root: Path = Path("/var/lib/hermes-installer/artifacts"),
                 authority_loader: Callable[[Path], Mapping[str, Any]] | None = None,
                 authority_writer: Callable[[Path, bytes], None] | None = None):
        self.policy_resolver = policy_resolver
        self.receipt_resolver = receipt_resolver
        self.identity = identity
        self.record_builder = record_builder
        self.authority_builder = authority_builder
        self.authority_path = authority_path
        self.transaction_root = transaction_root
        self.artifact_root = artifact_root
        self.authority_loader = authority_loader or _load_authority
        self.authority_writer = authority_writer or _atomic_root_file

    def enroll(self, request: BootstrapEnrollmentRequest) -> EnrollmentReceipt:
        _validate_request(request)
        if os.geteuid() != 0:
            raise BootstrapEnrollmentPending("service-generation enrollment requires the root authority process")
        _ensure_root_directory(self.transaction_root)
        with _transaction_lock(self.transaction_root / "enrollment.lock"):
            return self._enroll_locked(request)

    def _enroll_locked(self, request: BootstrapEnrollmentRequest) -> EnrollmentReceipt:
        _validate_request(request)
        if os.geteuid() != 0:
            raise BootstrapEnrollmentPending("service-generation enrollment requires the root authority process")
        policy = self.policy_resolver(request)
        _validate_policy(policy, records_required=self.record_builder is None)
        receipts = tuple(self.receipt_resolver.resolve(handle) for handle in request.artifact_receipt_handles)
        _validate_receipts(receipts)
        if not receipts or not any(item.artifact_id == policy.source_artifact_id for item in receipts):
            raise BootstrapEnrollmentPending("verified pinned Hermes source artifact receipt is not enrolled")
        if self.authority_path.exists():
            if not _root_file_ok(self.authority_path):
                raise BootstrapEnrollmentError("existing authority file is not root-owned mode 0600")
            from .enrollment import read_protected_file
            previous = read_protected_file(self.authority_path, expected_uid=0, maximum=MAX_AUTHORITY_BYTES)
            authority = dict(self.authority_loader(self.authority_path))
        else:
            previous = None
            if policy.authority_base is None and self.authority_builder is None:
                raise BootstrapEnrollmentPending("root-selected base authority enrollment policy is required")
            authority = None if policy.authority_base is None else dict(policy.authority_base)
            if authority is not None:
                _validate_authority_base(authority)
        previous_generation_digest = (
            authority.get("service_generations", {}).get("generation_digest")
            if previous is not None and isinstance(authority.get("service_generations"), dict) else None
        )
        if "service_generations" not in authority:
            raise BootstrapEnrollmentError("root authority file does not accept service-generation publication")
        transaction_id = secrets.token_hex(16)
        candidate_roots = tuple(root for root in (policy.home_root, policy.work_root, policy.data_root)
                                if not _exists_without_following(root))
        _ensure_root_directory(self.transaction_root)
        journal = self.transaction_root / f"{transaction_id}.json"
        backup = self.transaction_root / f"{transaction_id}.authority.previous"
        identity: ServiceIdentity | None = None
        created_roots: list[Path] = []
        staged_artifacts: list[Path] = []
        previous_authority: bytes | None = None
        published_generation_digest: str | None = None
        provision_receipt_handle = secrets.token_hex(24)
        request_digest = hashlib.sha256(_canonical({
            "schema": 1, "artifact_receipt_handles": list(request.artifact_receipt_handles),
            "operation_intent": request.operation_intent,
        })).hexdigest()
        artifact_receipt_digests = tuple(hashlib.sha256(_canonical({
            "receipt_id": item.receipt_id, "artifact_id": item.artifact_id,
            "sha256": item.sha256, "maximum_bytes": item.maximum_bytes,
        })).hexdigest() for item in receipts)
        if previous is not None:
            _atomic_root_file(backup, previous, 0o600)
        _write_journal(journal, transaction_id, "preparing", created_roots, staged_artifacts,
                       roots=candidate_roots,
                       backup=backup if previous is not None else None, identity=identity,
                       provision_receipt_handle=provision_receipt_handle,
                       request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests)
        try:
            identity = self.identity.ensure()
            _write_journal(journal, transaction_id, "preparing", created_roots, staged_artifacts,
                           roots=candidate_roots,
                           backup=backup if previous is not None else None, identity=identity,
                           provision_receipt_handle=provision_receipt_handle,
                           request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests)
            for root in (policy.home_root, policy.work_root, policy.data_root):
                if root in created_roots or not root.is_absolute():
                    raise BootstrapEnrollmentError("service roots are invalid or duplicated")
                if _create_service_root(root, identity):
                    created_roots.append(root)
                _verify_service_root(root, identity)
                _write_journal(journal, transaction_id, "preparing", created_roots, staged_artifacts,
                               roots=candidate_roots,
                               backup=backup if previous is not None else None,
                               identity=identity, provision_receipt_handle=provision_receipt_handle,
                               request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests)
            if self.record_builder is not None:
                policy = replace(policy, records=tuple(self.record_builder(policy, identity)))
                _validate_policy(policy)
            service = _verify_service_records(policy, identity)
            if self.authority_builder is not None:
                authority = dict(self.authority_builder(authority, policy, identity))
                _validate_authority_base(authority)
            if authority is None:
                raise BootstrapEnrollmentPending("root-selected base authority enrollment policy is required")
            # Artifacts remain root-owned and content-addressed. Receipt source paths
            # come only from the root resolver; bytes are rehashed during copy.
            _ensure_root_directory(self.artifact_root)
            installed = []
            for receipt in receipts:
                target = self.artifact_root / receipt.sha256
                if target.exists():
                    _verify_root_artifact(target, receipt)
                else:
                    _copy_verified_artifact(receipt, target)
                    staged_artifacts.append(target)
                    _write_journal(journal, transaction_id, "preparing", created_roots, staged_artifacts,
                                   roots=candidate_roots,
                                   backup=backup if previous is not None else None,
                                   identity=identity, provision_receipt_handle=provision_receipt_handle,
                                   request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests)
                installed.append({"receipt_id": receipt.receipt_id,
                                  "artifact_id": receipt.artifact_id,
                                  "sha256": receipt.sha256,
                                  "size_bytes": target.stat().st_size,
                                  "store_id": f"artifact:{receipt.artifact_id}:{receipt.sha256}"})
            service_generations = _generation(policy)
            previous_authority = previous
            authority["service_generations"] = service_generations
            encoded = _canonical(authority)
            if len(encoded) > MAX_AUTHORITY_BYTES:
                raise BootstrapEnrollmentError("authority snapshot exceeds the protected file size limit")
            published_generation_digest = service_generations["generation_digest"]
            _write_journal(journal, transaction_id, "committing", created_roots, staged_artifacts,
                           roots=candidate_roots,
                           backup=backup if previous is not None else None,
                           identity=identity, generation_digest=published_generation_digest,
                           provision_receipt_handle=provision_receipt_handle,
                           request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests)
            self.authority_writer(self.authority_path, encoded)
            _write_journal(journal, transaction_id, "committed", created_roots, staged_artifacts,
                           roots=candidate_roots,
                           backup=backup if previous is not None else None,
                           identity=identity, generation_digest=published_generation_digest,
                           provision_receipt_handle=provision_receipt_handle,
                           request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests)
            if previous is not None:
                backup.unlink()
            issued = time.monotonic()
            return EnrollmentReceipt(
                    schema=1, transaction_handle=request.operation_intent,
                    provision_receipt_handle=provision_receipt_handle,
                    generation_id=service_generations["generation_id"],
                    generation_digest=service_generations["generation_digest"],
                    previous_generation_digest=previous_generation_digest,
                    state="committed", enrollment_ids=(service.enrollment_id,),
                    issued_monotonic=issued, expires_monotonic=issued + 300.0,
                )
        except Exception:
            if (published_generation_digest is not None
                    and _current_generation_digest(self.authority_path) == published_generation_digest):
                if previous_authority is not None:
                    self.authority_writer(self.authority_path, previous_authority)
                else:
                    self.authority_path.unlink()
            for path in reversed(staged_artifacts):
                _unlink_only_owned(path, uid=0, expected_sha256=path.name)
            roots_removed = True
            for root in reversed(created_roots):
                roots_removed = _remove_empty_service_root(root, identity) and roots_removed
            if identity is not None and roots_removed:
                self.identity.remove_if_created(identity)
            _write_journal(journal, transaction_id, "rolled_back", created_roots, staged_artifacts,
                           roots=candidate_roots,
                           backup=backup if previous is not None else None,
                           identity=identity, generation_digest=published_generation_digest,
                           provision_receipt_handle=provision_receipt_handle,
                           request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests)
            if backup.exists() and _root_file_ok(backup):
                backup.unlink()
            raise

    def recover(self, transaction_id: str) -> str:
        """Roll back an interrupted transaction using its root-owned recovery journal."""
        if (os.geteuid() != 0 or not re.fullmatch(r"[0-9a-f]{32}", transaction_id)):
            raise BootstrapEnrollmentError("recovery requires root and a valid transaction ID")
        path = self.transaction_root / f"{transaction_id}.json"
        with _transaction_lock(self.transaction_root / "enrollment.lock"):
            try:
                if not _root_file_ok(path):
                    raise BootstrapEnrollmentError("transaction journal is absent or not root-owned")
                journal = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
            except (OSError, ValueError, UnicodeError):
                raise BootstrapEnrollmentError("transaction journal is malformed") from None
            if (not isinstance(journal, dict) or journal.get("schema") != 1
                    or journal.get("transaction_id") != transaction_id
                    or journal.get("state") not in {"preparing", "committing", "committed", "rolled_back"}):
                raise BootstrapEnrollmentError("transaction journal does not match recovery request")
            if journal["state"] in {"committed", "rolled_back"}:
                return journal["state"]
            if journal["state"] == "committing":
                backup_text = journal.get("backup", "")
                expected = journal.get("generation_digest")
                current = _current_generation_digest(self.authority_path)
                if current == expected:
                    if backup_text:
                        backup = Path(backup_text)
                        if backup.parent != self.transaction_root or not _root_file_ok(backup):
                            raise BootstrapEnrollmentError("prior authority snapshot is unavailable; recovery stopped")
                        self.authority_writer(self.authority_path, backup.read_bytes())
                    else:
                        self.authority_path.unlink()
                elif current is None:
                    raise BootstrapEnrollmentError("authority state changed during interrupted enrollment")
            identity_value = journal.get("identity")
            identity = None
            if isinstance(identity_value, dict) and set(identity_value) == {"name", "uid", "gid", "created"}:
                identity = ServiceIdentity(identity_value["name"], identity_value["uid"],
                                           identity_value["gid"], identity_value["created"])
            for artifact in journal.get("artifacts", []):
                candidate = Path(artifact)
                if candidate.parent != self.artifact_root or candidate.name != candidate.stem:
                    raise BootstrapEnrollmentError("journal artifact path is outside the enrolled store")
                if candidate.exists() and hashlib.sha256(candidate.read_bytes()).hexdigest() != candidate.name:
                    raise BootstrapEnrollmentError("journal artifact content changed; recovery preserved it")
                _unlink_only_owned(candidate, uid=0, expected_sha256=candidate.name)
            if identity is not None:
                roots_removed = True
                for root in journal.get("roots", []):
                    candidate = Path(root)
                    if candidate.is_absolute():
                        roots_removed = _remove_empty_service_root(candidate, identity) and roots_removed
                if roots_removed:
                    self.identity.remove_if_created(identity)
            _write_journal(path, transaction_id, "rolled_back", [], [],
                           roots=tuple(Path(p) for p in journal.get("roots", [])),
                           backup=Path(journal["backup"]) if journal.get("backup") else None,
                           identity=identity,
                           generation_digest=journal.get("generation_digest"),
                           provision_receipt_handle=journal.get("provision_receipt_handle"),
                           request_digest=journal.get("request_digest"),
                           artifact_receipt_digests=tuple(journal.get("artifact_receipt_digests", [])))
            backup_text = journal.get("backup", "")
            if backup_text:
                backup = Path(backup_text)
                if backup.parent == self.transaction_root and _root_file_ok(backup):
                    backup.unlink()
            return "rolled_back"


def _generation(policy: EnrollmentPolicy) -> dict[str, Any]:
    value = {"schema": 1, "generation_id": policy.generation_id,
             "service_records": [dict(row) for row in policy.records],
             "protected_devices": [dict(row) for row in policy.protected_devices],
             "protected_build_records": [dict(row) for row in policy.protected_build_records],
             "native_packages": [dict(row) for row in policy.native_packages],
             "memory_enrollments": [dict(row) for row in policy.memory_enrollments],
             "operation_parameter_schemas": [dict(row) for row in policy.operation_parameter_schemas]}
    value["generation_digest"] = hashlib.sha256(_canonical(value, ensure_ascii=False)).hexdigest()
    from .enrollment import _validate_service_generations
    try:
        return _validate_service_generations(value)
    except Exception:
        raise BootstrapEnrollmentError("root-selected protected service catalog failed schema or digest validation") from None


def _verify_service_records(policy: EnrollmentPolicy, identity: ServiceIdentity):
    """Parse and join the selected record through the same decoder as runtime."""
    snapshot = _generation(policy)
    from .protected_enrollment import ProtectedEnrollmentCatalog
    try:
        catalog = ProtectedEnrollmentCatalog.from_verified_records(
            snapshot["service_records"], protected_digest=snapshot["generation_digest"],
            expected_uid=0, native_packages=snapshot["native_packages"],
            parameter_schemas=snapshot["operation_parameter_schemas"],
        )
        matches = [record for record in catalog._records.values()
                   if record.profile_id == policy.service_profile_id]
        if len(matches) != 1:
            raise ValueError("selected service profile is not unique")
        service = matches[0]
        if (service.generation != policy.generation_id or service.principal_id != policy.principal_id
                or service.service_uid != identity.uid
                or service.service_gid != identity.gid or service.service_user != identity.name
                or service.roots.home != policy.home_root or service.roots.work != policy.work_root
                or service.roots.data != policy.data_root):
            raise ValueError("selected service identity or roots do not match root bootstrap")
        return service
    except Exception:
        raise BootstrapEnrollmentError("root-selected service records do not bind the verified identity and private roots") from None


def _canonical(value: Any, *, ensure_ascii: bool = True) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=ensure_ascii, allow_nan=False).encode("utf-8")


@contextmanager
def _transaction_lock(path: Path):
    _assert_secure_parent(path.parent)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise BootstrapEnrollmentError("bootstrap lock ownership or mode is invalid")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _current_generation_digest(path: Path) -> str | None:
    try:
        value = _load_authority(path)
        generation = value.get("service_generations")
        return generation.get("generation_digest") if isinstance(generation, dict) else None
    except BootstrapEnrollmentError:
        return None


def _validate_request(request: BootstrapEnrollmentRequest) -> None:
    if (not isinstance(request, BootstrapEnrollmentRequest)
            or not isinstance(request.artifact_receipt_handles, tuple)
            or len(request.artifact_receipt_handles) > 64
            or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", value)
                   for value in request.artifact_receipt_handles)
            or not isinstance(request.operation_intent, str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", request.operation_intent)):
        raise BootstrapEnrollmentError("bootstrap enrollment request is malformed")


def _validate_policy(policy: EnrollmentPolicy, *, records_required: bool = True) -> None:
    if (not isinstance(policy, EnrollmentPolicy) or not policy.service_profile_id
            or not policy.principal_id or not policy.generation_id
            or records_required and not policy.records
            or not policy.source_artifact_id
            or len(policy.records) > 1024 or len({policy.home_root, policy.work_root, policy.data_root}) != 3):
        raise BootstrapEnrollmentError("root service enrollment policy is missing or malformed")


def _validate_authority_base(value: Mapping[str, Any]) -> None:
    required = {"schema", "key_id", "principals", "rules", "authentik", "process_profiles",
                "provider_enrollments", "mcp_services", "mcp_http_bindings", "memory_providers",
                "native_bridges", "normalization_policies", "delegations", "service_generations"}
    if not isinstance(value, Mapping) or set(value) != required or value.get("schema") != 1:
        raise BootstrapEnrollmentError("root-selected base authority document does not match the strict authority schema")
    from .enrollment import _reject_secret_material
    try:
        _reject_secret_material(dict(value))
    except Exception:
        raise BootstrapEnrollmentError("base authority documents may contain credential references only") from None


def _validate_receipts(receipts: tuple[VerifiedArtifactReceipt, ...]) -> None:
    seen = set()
    for item in receipts:
        if (not isinstance(item, VerifiedArtifactReceipt) or not item.receipt_id
                or not item.artifact_id or len(item.sha256) != 64
                or any(char not in "0123456789abcdef" for char in item.sha256)
                or type(item.maximum_bytes) is not int or not 1 <= item.maximum_bytes <= 8 * 1024**3
                or item.receipt_id in seen):
            raise BootstrapEnrollmentError("root artifact receipt is invalid or duplicated")
        seen.add(item.receipt_id)


def _linux() -> bool:
    return os.name == "posix" and Path("/proc/sys/kernel/ostype").exists()


def _assert_secure_parent(path: Path) -> None:
    if not path.is_absolute():
        raise BootstrapEnrollmentError("protected path must be absolute")
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise BootstrapEnrollmentError("protected parent directory ownership or mode is invalid")


def _ensure_root_chain(path: Path, *, ceiling: Path) -> None:
    """Create only root-owned parents under an explicit fixed data-area prefix."""
    try:
        suffix = path.relative_to(ceiling)
    except ValueError:
        raise BootstrapEnrollmentError("protected directory is outside the enrolled data area") from None
    _assert_secure_parent(ceiling.parent)
    cursor = ceiling.parent
    for part in (ceiling.name, *suffix.parts):
        cursor = cursor / part
        try:
            cursor.mkdir(mode=0o700)
        except FileExistsError:
            info = cursor.lstat()
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != 0 or info.st_mode & 0o022):
                raise BootstrapEnrollmentError("protected directory ancestor has foreign ownership or unsafe mode")
        else:
            os.chown(cursor, 0, 0)
            os.chmod(cursor, 0o700)


def _ensure_root_directory(path: Path) -> None:
    _ensure_root_chain(path.parent, ceiling=Path("/var/lib/hermes-installer"))
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
            raise BootstrapEnrollmentError("root-private transaction directory conflicts with existing data")
    os.chown(path, 0, 0)
    os.chmod(path, 0o700)


def _create_service_root(path: Path, identity: ServiceIdentity) -> bool:
    _ensure_root_chain(path.parent, ceiling=Path("/var/lib/hermes-installer/services"))
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        return False
    os.chown(path, identity.uid, identity.gid)
    os.chmod(path, 0o700)
    return True


def _verify_service_root(path: Path, identity: ServiceIdentity) -> None:
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != identity.uid or info.st_gid != identity.gid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise BootstrapEnrollmentError("existing service root has foreign ownership or unsafe mode")


def _copy_verified_artifact(receipt: VerifiedArtifactReceipt, target: Path) -> None:
    _assert_secure_parent(target.parent)
    source_info = receipt.source.lstat()
    if stat.S_ISLNK(source_info.st_mode) or not stat.S_ISREG(source_info.st_mode):
        raise BootstrapEnrollmentError("artifact receipt source is not a regular file")
    if source_info.st_size > receipt.maximum_bytes:
        raise BootstrapEnrollmentError("artifact receipt exceeds its enrolled size bound")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(receipt.source, flags)
    temp = target.with_name("." + target.name + "." + secrets.token_hex(8) + ".tmp")
    out = -1
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (source_info.st_dev, source_info.st_ino):
            raise BootstrapEnrollmentError("artifact receipt source changed during verification")
        out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            if total > receipt.maximum_bytes:
                raise BootstrapEnrollmentError("artifact receipt exceeds its enrolled size bound")
            digest.update(block)
            offset = 0
            while offset < len(block):
                offset += os.write(out, block[offset:])
        if digest.hexdigest() != receipt.sha256:
            raise BootstrapEnrollmentError("artifact receipt bytes do not match the enrolled digest")
        os.fchmod(out, 0o444)
        os.fchown(out, 0, 0)
        os.fsync(out)
        os.close(out)
        out = -1
        os.replace(temp, target)
        directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(fd)
        if out >= 0:
            os.close(out)
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _verify_root_artifact(path: Path, receipt: VerifiedArtifactReceipt) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o444:
        raise BootstrapEnrollmentError("content-addressed artifact store has foreign content")
    if info.st_size > receipt.maximum_bytes or hashlib.sha256(path.read_bytes()).hexdigest() != receipt.sha256:
        raise BootstrapEnrollmentError("content-addressed artifact store digest is invalid")


def _atomic_root_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    if os.geteuid() != 0:
        raise BootstrapEnrollmentPending("protected authority updates require Linux root")
    _assert_secure_parent(path.parent)
    if path.exists() and not _root_file_ok(path):
        raise BootstrapEnrollmentError("existing protected file ownership or mode is invalid")
    temp = path.with_name("." + path.name + "." + secrets.token_hex(8) + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, 0, 0)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _root_file_ok(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600


def _exists_without_following(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def _load_authority(path: Path) -> Mapping[str, Any]:
    from .enrollment import read_protected_file
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    try:
        raw = read_protected_file(path, expected_uid=0, maximum=MAX_AUTHORITY_BYTES)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (OSError, ValueError, UnicodeError):
        raise BootstrapEnrollmentError("existing root authority file is malformed") from None
    if not isinstance(value, dict):
        raise BootstrapEnrollmentError("existing root authority file is malformed")
    return value


def _read_json_if_owned(path: Path):
    try:
        if not _root_file_ok(path) or path.stat().st_size > 4096:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None


def _write_journal(path: Path, transaction_id: str, state: str,
                   created_roots: list[Path], artifacts: list[Path], *,
                   roots: tuple[Path, ...] = (),
                   backup: Path | None = None, identity: ServiceIdentity | None = None,
                   generation_digest: str | None = None,
                   provision_receipt_handle: str | None = None,
                   request_digest: str | None = None,
                   artifact_receipt_digests: tuple[str, ...] = ()) -> None:
    _atomic_root_file(path, _canonical({"schema": 1, "transaction_id": transaction_id,
                                        "state": state, "created_roots": [str(p) for p in created_roots],
                                        "roots": [str(p) for p in roots],
                                        "artifacts": [str(p) for p in artifacts],
                                        "backup": str(backup) if backup else "",
                                        "identity": None if identity is None else {
                                            "name": identity.name, "uid": identity.uid,
                                            "gid": identity.gid, "created": identity.created},
                                        "generation_digest": generation_digest,
                                        "provision_receipt_handle": provision_receipt_handle,
                                        "request_digest": request_digest,
                                        "artifact_receipt_digests": list(artifact_receipt_digests)}))


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _unlink_only_owned(path: Path, *, uid: int, expected_sha256: str | None = None) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (stat.S_ISREG(info.st_mode) and info.st_uid == uid
            and (expected_sha256 is None or hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha256)):
        path.unlink()
    else:
        raise BootstrapEnrollmentError("rollback encountered a changed artifact; preserved it")


def _remove_empty_service_root(path: Path, identity: ServiceIdentity | None) -> bool:
    if identity is None:
        return False
    try:
        _verify_service_root(path, identity)
        path.rmdir()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        # Preserve nonempty user data; the journal remains the recovery record.
        return False
