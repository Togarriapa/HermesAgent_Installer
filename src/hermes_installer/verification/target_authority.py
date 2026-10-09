"""Root-issued, one-use acceptance admissions and durable observations.

This module is intentionally a root-process boundary. It derives target and
principal identity from the active protected runtime, and candidate identity
from the installed release verifier. Caller-authored leases and EvidenceRecord
objects never become trusted merely by passing schema checks.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import base64
import hashlib
import hmac
import inspect
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import tempfile
from typing import Any, Callable, Mapping
from uuid import uuid4

from ..authority.runtime_composition import RootAuthorityRuntime
from ..evidence import EvidenceClass, EvidenceRecord, EvidenceState
from .acceptance import AuthorizedTarget, WorkflowResult
from .profiles import profile_for


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_RESULT = 2_097_152
# Observations are retained as base64 inside a signed journal envelope. Allow
# for the 4/3 expansion plus JSON/signature overhead while keeping the result
# itself independently bounded by _MAX_RESULT.
_MAX_RECEIPT = 3_145_728
_ROOT_UID = 0
_SEAL = object()


class TargetAuthorityError(PermissionError):
    """An enrolled target, current release, or trusted observation is absent."""


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _root_runtime(runtime: object) -> RootAuthorityRuntime:
    if os.geteuid() != _ROOT_UID or not isinstance(runtime, RootAuthorityRuntime):
        raise TargetAuthorityError("acceptance receipts require the installed root authority runtime")
    service = runtime.service
    enrollment = runtime.enrollment
    if (service.service_generation_digest != enrollment.protected_enrollment_digest
            or runtime.bindings.enrollment_catalog.digest != service.service_generation_digest
            or not service.authority_epoch):
        raise TargetAuthorityError("root authority runtime is stale or inconsistent")
    if not callable(getattr(runtime, "resolve_selected_native_principal", None)):
        raise TargetAuthorityError("active runtime cannot resolve the selected enrolled principal")
    return runtime


def _host_facts() -> tuple[str, str, str]:
    """Return stable target ID, machine identity digest, and supported platform."""
    if platform.system() != "Linux" or platform.machine().lower() not in {"aarch64", "arm64"}:
        raise TargetAuthorityError("acceptance target must be an identified Linux ARM64 host")
    machine_id_path = Path("/etc/machine-id")
    try:
        info = machine_id_path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or machine_id_path.is_symlink() or info.st_size > 128):
            raise TargetAuthorityError("host machine identity file has invalid custody")
        raw = machine_id_path.read_bytes().strip()
    except OSError:
        raise TargetAuthorityError("host machine identity is unavailable") from None
    if not re.fullmatch(rb"[0-9a-fA-F]{32}", raw):
        raise TargetAuthorityError("host machine identity is malformed")
    model = ""
    try:
        model_path = Path("/proc/device-tree/model")
        model_info = model_path.lstat()
        if (stat.S_ISREG(model_info.st_mode) and model_info.st_uid == 0
                and not model_path.is_symlink() and model_info.st_size <= 256):
            model = model_path.read_bytes().replace(b"\x00", b"").decode("ascii", "strict").strip()
    except (OSError, UnicodeError):
        model = ""
    facts = {
        "machine_id_sha256": _hash(raw.lower()),
        "architecture": platform.machine().lower(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "device_model": model,
    }
    digest = _hash(_canonical(facts))
    # The identifier is derived locally; callers cannot nominate a host label.
    platform_id = "raspberry-pi-5-arm64" if model.startswith("Raspberry Pi 5 Model B") else "linux-arm64"
    return f"host-{digest[:32]}", digest, platform_id


def _resolve_journal_root(runtime: RootAuthorityRuntime, *, expected_uid: int = _ROOT_UID) -> Path:
    records = runtime.enrollment.root_journal_root_records
    roots = [row.get("root_id") for row in records if isinstance(row, Mapping)
             and row.get("purpose") == "authority-journal"]
    if len(roots) != 1 or not isinstance(roots[0], str):
        raise TargetAuthorityError("active protected enrollment must select exactly one authority journal root")
    try:
        selection = runtime.resolve_root_journal(
            roots[0], expected_active_generation_digest=runtime.enrollment.protected_enrollment_digest,
        )
    except Exception as exc:
        raise TargetAuthorityError("protected authority journal root could not be re-resolved") from exc
    path = selection.path
    info = path.lstat()
    if (path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_dev != selection.device or info.st_ino != selection.inode):
        raise TargetAuthorityError("protected authority journal root custody changed")
    return path


class _RootReceiptJournal:
    """Append-only signed files inside the already-selected protected journal."""

    def __init__(self, runtime: RootAuthorityRuntime, *, test_uid: int | None = None):
        # test_uid exists only for isolated unit fixtures. Production callers
        # cannot override the effective UID check through any public factory.
        expected_uid = _ROOT_UID if test_uid is None else test_uid
        if os.geteuid() != expected_uid:
            raise TargetAuthorityError("root receipt journal requires the selected journal owner")
        self.runtime = runtime
        self.root = _resolve_journal_root(runtime, expected_uid=expected_uid)
        self.directory = self.root / "acceptance-receipts"
        if not self.directory.exists():
            self.directory.mkdir(mode=0o700)
        self._check_directory(self.directory, expected_uid)
        self.expected_uid = expected_uid

    def _check_directory(self, path: Path, expected_uid: int) -> None:
        info = path.lstat()
        if (path.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o700):
            raise TargetAuthorityError("acceptance receipt directory custody is invalid")

    def _kind_dir(self, kind: str) -> Path:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", kind):
            raise ValueError("invalid receipt kind")
        directory = self.directory / kind
        if not directory.exists():
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
        self._check_directory(directory, self.expected_uid)
        return directory

    def _lock(self, kind_dir: Path):
        path = kind_dir / ".lock"
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags, 0o600)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                or stat.S_IMODE(info.st_mode) != 0o600):
            os.close(fd)
            raise TargetAuthorityError("acceptance receipt lock custody is invalid")
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def put_once(self, kind: str, handle: str, claims: Mapping[str, Any]) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", handle):
            raise ValueError("receipt handle is malformed")
        identity_field = {
            "admissions": "workflow_handle", "results": "result_receipt_handle",
            "assertions": "assertion_receipt_handle",
        }.get(kind)
        if identity_field is not None and claims.get(identity_field) != handle:
            raise ValueError("receipt handle does not match its signed claims")
        envelope = {"schema": 1, "claims": dict(claims)}
        signature = self.runtime.service._sign(envelope)
        row = {**envelope, "key_id": self.runtime.service.key_id,
               "signature": signature}
        raw = _canonical(row)
        if len(raw) > _MAX_RECEIPT:
            raise ValueError("acceptance receipt exceeds its byte limit")
        directory = self._kind_dir(kind)
        lock_fd = self._lock(directory)
        try:
            destination = directory / f"{handle}.json"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(destination, flags, 0o600)
            try:
                with os.fdopen(fd, "wb", closefd=True) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                dir_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except BaseException:
                destination.unlink(missing_ok=True)
                raise
        except FileExistsError:
            raise TargetAuthorityError("acceptance receipt handle was already used") from None
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        return _hash(raw)

    def get(self, kind: str, handle: str) -> tuple[dict[str, Any], str]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", handle):
            raise TargetAuthorityError("receipt handle is malformed")
        directory = self._kind_dir(kind)
        path = directory / f"{handle}.json"
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > _MAX_RECEIPT):
                    raise TargetAuthorityError("acceptance receipt file custody is invalid")
                raw = os.read(fd, _MAX_RECEIPT + 1)
            finally:
                os.close(fd)
        except OSError:
            raise TargetAuthorityError("root acceptance receipt is absent") from None
        if len(raw) > _MAX_RECEIPT:
            raise TargetAuthorityError("root acceptance receipt exceeds its byte limit")
        try:
            row = json.loads(raw.decode("ascii"))
        except (UnicodeError, json.JSONDecodeError):
            raise TargetAuthorityError("root acceptance receipt is malformed") from None
        if (not isinstance(row, dict) or set(row) != {"schema", "claims", "key_id", "signature"}
                or type(row["schema"]) is not int or row["schema"] != 1
                or row["key_id"] != self.runtime.service.key_id
                or not isinstance(row["claims"], dict) or not isinstance(row["signature"], str)):
            raise TargetAuthorityError("root acceptance receipt fields are invalid")
        try:
            self.runtime.service._verify_signature(
                {"schema": 1, "claims": row["claims"]}, row["signature"],
            )
        except Exception:
            raise TargetAuthorityError("root acceptance receipt signature is invalid") from None
        return row["claims"], _hash(raw)

    def consume_once(self, kind: str, handle: str) -> None:
        directory = self._kind_dir(kind)
        self.get(kind, handle)
        lock_fd = self._lock(directory)
        try:
            path = directory / f"{handle}.consumed"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(path, flags, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(b"consumed\n")
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            raise TargetAuthorityError("workflow admission has already been consumed") from None
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    def was_consumed(self, kind: str, handle: str) -> bool:
        if not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", handle):
            raise TargetAuthorityError("receipt handle is malformed")
        path = self._kind_dir(kind) / f"{handle}.consumed"
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            return False
        try:
            info = os.fstat(fd)
            value = os.read(fd, 32)
        finally:
            os.close(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                or stat.S_IMODE(info.st_mode) != 0o600 or value != b"consumed\n"):
            raise TargetAuthorityError("admission consumption marker custody is invalid")
        return True


@dataclass(frozen=True, slots=True)
class InstalledCandidateReceipt:
    handle: str
    candidate_git_sha: str
    candidate_artifact_closure_sha256: str
    deployment_receipt_sha256: str
    service_generation_digest: str
    baseline_tree_sha256: str
    amendment_manifest_sha256: str
    selected_plan_artifact_id: str
    selected_plan_sha256: str
    issued_monotonic: float


class InstalledCandidateReceiptRegistry:
    """Root-signed view of the immutable release currently executing."""

    def __init__(self, runtime: RootAuthorityRuntime, journal: _RootReceiptJournal,
                 release: Any, actor: Any, *, _seal: object | None = None):
        if _seal is not _SEAL:
            raise TypeError("candidate receipt registries can only be assembled by the installed root verifier")
        self.runtime, self.journal, self.release, self.actor = runtime, journal, release, actor

    @classmethod
    def from_root_runtime(cls, runtime: RootAuthorityRuntime, *,
                          test_uid: int | None = None) -> "InstalledCandidateReceiptRegistry":
        runtime = _root_runtime(runtime)
        try:
            from ..authority.installer_release import (
                InstalledRootReleaseVerifier, RootActorObservation,
                VerifiedInstallerReleaseReceipt,
            )
        except ImportError as exc:
            raise TargetAuthorityError("installed root release verifier is not in this runtime") from exc
        release, actor = InstalledRootReleaseVerifier.from_current_root_process()
        if not isinstance(release, VerifiedInstallerReleaseReceipt) or not isinstance(actor, RootActorObservation):
            raise TargetAuthorityError("installed release verifier returned untyped provenance")
        if (os.geteuid() != 0 or getattr(actor, "uid", None) != 0
                or not callable(getattr(release, "verify_current", None))
                or not callable(getattr(actor, "verify_current", None))):
            release.close()
            raise TargetAuthorityError("current process is not the verified root release actor")
        journal = _RootReceiptJournal(runtime, test_uid=test_uid)
        registry = cls(runtime, journal, release, actor, _seal=_SEAL)
        registry._record_current_release()
        return registry

    def _release_claims(self) -> dict[str, Any]:
        release = self.release
        try:
            release.verify_current()
            self.actor.verify_current(release)
        except Exception as exc:
            raise TargetAuthorityError("installed candidate release or root actor is stale") from exc
        if (not _SHA40.fullmatch(release.release_commit)
                or not _SHA64.fullmatch(release.deployment_receipt_sha256)
                or not _SHA64.fullmatch(release.baseline_tree_sha256)
                or not _SHA64.fullmatch(release.amendment_manifest_sha256)
                or not _SHA64.fullmatch(release.selected_plan_sha256)
                or not isinstance(release.selected_plan_artifact_id, str)):
            raise TargetAuthorityError("installed candidate closure receipt is incomplete")
        files = []
        for row in release.files:
            item = {
                "artifact_id": row.artifact_id,
                "roles": sorted(row.roles),
                "relative_path": row.relative_path,
                "sha256": row.sha256,
                "size_bytes": row.size_bytes,
                "device": row.device,
                "inode": row.inode,
                "mode": row.mode,
            }
            if (not _SHA64.fullmatch(item["sha256"])
                    or type(item["size_bytes"]) is not int or item["size_bytes"] < 0
                    or type(item["device"]) is not int or type(item["inode"]) is not int
                    or type(item["mode"]) is not int):
                raise TargetAuthorityError("candidate artifact closure contains an invalid row")
            files.append(item)
        if not files:
            raise TargetAuthorityError("candidate artifact closure is empty")
        files.sort(key=lambda item: item["relative_path"])
        closure = _hash(_canonical({
            "candidate_git_sha": release.release_commit,
            "deployment_receipt_sha256": release.deployment_receipt_sha256,
            "baseline_tag_object": release.baseline_tag_object,
            "baseline_commit": release.baseline_commit,
            "baseline_tree_sha256": release.baseline_tree_sha256,
            "amendment_manifest_sha256": release.amendment_manifest_sha256,
            "module_closure_sha256": release.module_closure_sha256,
            "selected_plan_artifact_id": release.selected_plan_artifact_id,
            "selected_plan_sha256": release.selected_plan_sha256,
            "files": files,
        }))
        return {
            "candidate_git_sha": release.release_commit,
            "candidate_artifact_closure_sha256": closure,
            "deployment_receipt_sha256": release.deployment_receipt_sha256,
            "baseline_tree_sha256": release.baseline_tree_sha256,
            "amendment_manifest_sha256": release.amendment_manifest_sha256,
            "selected_plan_artifact_id": release.selected_plan_artifact_id,
            "selected_plan_sha256": release.selected_plan_sha256,
            "release_root": str(release.release_root),
            "release_root_device": release.root_device,
            "release_root_inode": release.root_inode,
            "closure_manifest_relative_path": release.closure_manifest_relative_path,
            "closure_manifest_sha256": release.closure_manifest_sha256,
            "service_generation_digest": self.runtime.service.service_generation_digest,
        }

    def _record_current_release(self) -> None:
        claims = self._release_claims()
        # The candidate is immutable within this active service generation.
        handle = "candidate_" + claims["candidate_git_sha"]
        claims.update({"schema": 1, "issued_monotonic": self.runtime.service.monotonic()})
        try:
            self.journal.put_once("candidates", handle, claims)
        except TargetAuthorityError as exc:
            if "already been used" not in str(exc):
                raise
            existing, _ = self.journal.get("candidates", handle)
            for key, value in claims.items():
                if key != "issued_monotonic" and existing.get(key) != value:
                    raise TargetAuthorityError("candidate receipt conflicts with current installed release") from None

    def get_current(self, candidate_git_sha: str) -> InstalledCandidateReceipt:
        if not _SHA40.fullmatch(candidate_git_sha):
            raise TargetAuthorityError("candidate SHA must be a full lowercase Git commit")
        claims = self._release_claims()
        handle = "candidate_" + candidate_git_sha
        stored, _digest = self.journal.get("candidates", handle)
        for key, value in claims.items():
            if stored.get(key) != value:
                raise TargetAuthorityError("candidate receipt no longer matches the current release")
        if stored.get("candidate_git_sha") != candidate_git_sha:
            raise TargetAuthorityError("candidate receipt names another release")
        return InstalledCandidateReceipt(
            handle, candidate_git_sha, claims["candidate_artifact_closure_sha256"],
            claims["deployment_receipt_sha256"], claims["service_generation_digest"],
            claims["baseline_tree_sha256"], claims["amendment_manifest_sha256"],
            claims["selected_plan_artifact_id"], claims["selected_plan_sha256"],
            float(stored["issued_monotonic"]),
        )

    def close(self) -> None:
        self.release.close()


@dataclass(frozen=True, slots=True)
class RootTargetWorkflowAdmission:
    schema: int
    workflow_handle: str
    acceptance_id: str
    target_id: str
    platform: str
    target_machine_identity_sha256: str
    candidate_git_sha: str
    candidate_artifact_closure_sha256: str
    enrollment_generation_id: str
    service_generation_digest: str
    principal_id: str
    intent_id: str
    run_nonce: str
    issued_monotonic: float
    expires_monotonic: float
    signature_sha256: str


@dataclass(frozen=True, slots=True)
class RootSetupSelectionContext:
    """Opaque root-internal references resolved by the setup receipt registry."""

    registry: Any
    receipt_handle: str
    setup_session_handle: str
    transaction_handle: str
    plan_digest: str


class InstallerTrustedTargetAuthorizer:
    """Issue only a short-lived admission for the active protected profile."""

    def __init__(self, runtime: RootAuthorityRuntime, selection: Any,
                 candidate_receipts: InstalledCandidateReceiptRegistry,
                 journal: _RootReceiptJournal, *, target_id: str, machine_digest: str,
                 platform_id: str, principal: Any, generation: str,
                 _seal: object | None = None):
        if _seal is not _SEAL:
            raise TypeError("target authorizers can only be assembled from root-verified selection receipts")
        self.runtime, self.selection = runtime, selection
        self.candidate_receipts, self.journal = candidate_receipts, journal
        self.target_id, self.machine_digest, self.platform_id = target_id, machine_digest, platform_id
        self.principal, self.generation = principal, generation

    def _ensure_current(self) -> None:
        runtime = _root_runtime(self.runtime)
        if _host_facts() != (self.target_id, self.machine_digest, self.platform_id):
            raise TargetAuthorityError("kernel target identity changed since verifier assembly")
        now = runtime.service.monotonic()
        selection = self.selection
        if selection.expires_monotonic <= now:
            raise TargetAuthorityError("root setup principal-selection lease expired")
        try:
            principal = runtime.resolve_selected_native_principal(
                selection.service_profile_id, self.generation,
                runtime.service.service_generation_digest,
            )
        except Exception as exc:
            raise TargetAuthorityError("selected active principal or generation is no longer enrolled") from exc
        if (principal.uid != self.principal.uid
                or principal.principal_id != self.principal.principal_id
                or principal.profile_id != self.principal.profile_id
                or principal.namespace_id != self.principal.namespace_id
                or principal.capabilities != self.principal.capabilities):
            raise TargetAuthorityError("selected principal changed since verifier assembly")

    @classmethod
    def from_root_runtime(cls, root_runtime_composition: RootAuthorityRuntime,
                          verified_setup_or_active_enrollment_receipt: Any,
                          installed_candidate_receipt_registry: InstalledCandidateReceiptRegistry,
                          *, test_uid: int | None = None) -> "InstallerTrustedTargetAuthorizer":
        runtime = _root_runtime(root_runtime_composition)
        if (not isinstance(installed_candidate_receipt_registry, InstalledCandidateReceiptRegistry)
                or installed_candidate_receipt_registry.runtime is not runtime):
            raise TargetAuthorityError("candidate receipts are not bound to this root runtime")
        try:
            from ..authority.bootstrap_enrollment import (
                RootSetupPrincipalSelectionRegistry, VerifiedRootSetupPrincipalSelection,
            )
        except ImportError as exc:
            raise TargetAuthorityError("root setup principal-selection receipts are unavailable") from exc
        context = verified_setup_or_active_enrollment_receipt
        if (not isinstance(context, RootSetupSelectionContext)
                or not isinstance(context.registry, RootSetupPrincipalSelectionRegistry)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", context.receipt_handle)
                or not isinstance(context.setup_session_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", context.setup_session_handle)
                or not isinstance(context.transaction_handle, str) or not context.transaction_handle
                or not _SHA64.fullmatch(context.plan_digest)):
            raise TargetAuthorityError("root setup receipt registry context is unavailable or malformed")
        try:
            selection = context.registry.resolve_selected_principal(
                context.receipt_handle, context.setup_session_handle,
                context.transaction_handle, context.plan_digest,
            )
        except Exception as exc:
            raise TargetAuthorityError("root setup selection receipt could not be revalidated") from exc
        if not isinstance(selection, VerifiedRootSetupPrincipalSelection):
            raise TargetAuthorityError("setup registry returned an untyped principal selection")
        now = runtime.service.monotonic()
        if (selection.schema != 1 or not selection.receipt_id
                or not selection.setup_session_id or not selection.transaction_handle
                or not _SHA64.fullmatch(selection.plan_digest)
                or not selection.principal_id or not selection.service_profile_id
                or not selection.namespace_id or type(selection.expires_monotonic) not in {int, float}
                or selection.expires_monotonic <= now or selection.issued_monotonic > now):
            raise TargetAuthorityError("setup principal-selection receipt is expired or malformed")
        target_id, machine_digest, platform_id = _host_facts()
        catalog = runtime.bindings.enrollment_catalog
        matches = [row for row in catalog._records.values()
                   if row.profile_id == selection.service_profile_id]
        if len(matches) != 1:
            raise TargetAuthorityError("setup-selected profile is absent or ambiguous in the active catalog")
        service_row = matches[0]
        generation = service_row.generation
        try:
            principal = runtime.resolve_selected_native_principal(
                selection.service_profile_id, generation,
                runtime.service.service_generation_digest,
            )
        except Exception as exc:
            raise TargetAuthorityError("setup-selected principal is not active in current managed custody") from exc
        if (principal.principal_id != selection.principal_id
                or principal.profile_id != selection.service_profile_id
                or principal.namespace_id != selection.namespace_id
                or frozenset(selection.capabilities) != principal.capabilities
                or principal.uid != service_row.service_uid):
            raise TargetAuthorityError("setup identity does not match the protected active profile and principal")
        return cls(runtime, selection, installed_candidate_receipt_registry,
                   _RootReceiptJournal(runtime, test_uid=test_uid), target_id=target_id,
                   machine_digest=machine_digest, platform_id=platform_id,
                   principal=principal, generation=generation, _seal=_SEAL)

    def authorize_workflow(self, candidate_git_sha: str, acceptance_id: str,
                           *, maximum_seconds: float = 300.0) -> RootTargetWorkflowAdmission:
        self._ensure_current()
        if (not isinstance(acceptance_id, str) or not re.fullmatch(r"AC\d{2}", acceptance_id)
                or type(maximum_seconds) not in {int, float} or not 0 < maximum_seconds <= 600):
            raise TargetAuthorityError("acceptance action or admission lifetime is invalid")
        candidate = self.candidate_receipts.get_current(candidate_git_sha)
        try:
            from ..authority.bootstrap_enrollment import VerifiedRootSetupPrincipalSelection
        except ImportError:
            raise TargetAuthorityError("root setup principal-selection receipts are unavailable") from None
        selection = self.selection
        if not isinstance(selection, VerifiedRootSetupPrincipalSelection):
            raise TargetAuthorityError("root setup selection no longer has a trusted type")
        now = self.runtime.service.monotonic()
        if selection.expires_monotonic <= now:
            raise TargetAuthorityError("root setup principal-selection lease expired")
        profile = _profile_for_acceptance(acceptance_id)
        if profile is None:
            raise TargetAuthorityError("no installer-owned assertion profile is registered for this acceptance ID")
        handle = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        expiry = min(now + float(maximum_seconds), float(selection.expires_monotonic))
        claims = {
            "schema": 1, "workflow_handle": handle, "acceptance_id": acceptance_id,
            "target_id": self.target_id,
            "platform": self.platform_id,
            "target_machine_identity_sha256": self.machine_digest,
            "candidate_git_sha": candidate.candidate_git_sha,
            "candidate_artifact_closure_sha256": candidate.candidate_artifact_closure_sha256,
            "enrollment_generation_id": self.generation,
            "service_generation_digest": self.runtime.service.service_generation_digest,
            "principal_id": self.principal.principal_id,
            "intent_id": selection.transaction_handle, "run_nonce": nonce,
            "issued_monotonic": now, "expires_monotonic": expiry,
        }
        receipt_digest = self.journal.put_once("admissions", handle, claims)
        return RootTargetWorkflowAdmission(**claims, signature_sha256=receipt_digest)


def _profile_for_acceptance(acceptance_id: str):
    from .profiles import PROBE_PROFILES
    matches = [row for row in PROBE_PROFILES.values() if acceptance_id in row.acceptance_ids]
    return matches[0] if matches else None


@dataclass(frozen=True, slots=True)
class VerifiedRootWorkflowResult:
    workflow_handle: str
    result_receipt_handle: str
    acceptance_id: str
    target_id: str
    candidate_git_sha: str
    candidate_artifact_closure_sha256: str
    service_generation_digest: str
    run_nonce: str
    evidence_ids: tuple[str, ...]
    assertion_receipt_handles: tuple[str, ...]
    observed_result_sha256: str
    observed_monotonic: float
    terminal_state: str
    record: EvidenceRecord


class RootObservationReceiptRegistry:
    """Store signed result observations produced by the fixed root workflow runner."""

    def __init__(self, runtime: RootAuthorityRuntime, journal: _RootReceiptJournal,
                 candidate_receipts: InstalledCandidateReceiptRegistry,
                 *, _seal: object | None = None):
        if _seal is not _SEAL:
            raise TypeError("observation registries can only be assembled by installed root runtime")
        self.runtime, self.journal, self.candidate_receipts = runtime, journal, candidate_receipts
        self._issuer = object()

    @classmethod
    def from_root_runtime(cls, runtime: RootAuthorityRuntime,
                          candidate_receipts: InstalledCandidateReceiptRegistry,
                          *, test_uid: int | None = None) -> "RootObservationReceiptRegistry":
        runtime = _root_runtime(runtime)
        if candidate_receipts.runtime is not runtime:
            raise TargetAuthorityError("observation registry candidate/runtime binding is inconsistent")
        return cls(runtime, _RootReceiptJournal(runtime, test_uid=test_uid), candidate_receipts,
                   _seal=_SEAL)

    def _issue(self, token: object, admission: RootTargetWorkflowAdmission,
               record: EvidenceRecord, retained_result: bytes) -> str:
        if token is not self._issuer:
            raise TargetAuthorityError("only the fixed installer workflow runner can issue observations")
        record.validate()
        admitted, _ = self.journal.get("admissions", admission.workflow_handle)
        self._check_admission(admitted, admission)
        if not self.journal.was_consumed("admissions", admission.workflow_handle):
            raise TargetAuthorityError("root workflow admission was not consumed before the effect")
        candidate = self.candidate_receipts.get_current(admission.candidate_git_sha)
        profile = profile_for(record.evidence_id, admission.acceptance_id)
        if (record.candidate_sha != candidate.candidate_git_sha
                or record.target_id != admission.target_id
                or record.platform != admission.platform
                or set(record.assertions) != set(profile.assertions)
                or len(retained_result) > _MAX_RESULT
                or _hash(retained_result) != record.artifact_sha256):
            raise TargetAuthorityError("workflow result does not match its admitted candidate, target, profile or artifact")
        expected_class = {
            "fixture-x86_64": EvidenceClass.FIXTURE,
            "linux-arm64": EvidenceClass.NATIVE_ARM64,
            "raspberry-pi-5-arm64": EvidenceClass.PHYSICAL_PI,
        }.get(admission.platform)
        if expected_class is None or record.evidence_class is not expected_class:
            raise TargetAuthorityError("workflow evidence class does not match its admitted target platform")
        if record.state == EvidenceState.PENDING and any(value is False for value in record.assertions.values()):
            raise TargetAuthorityError("an observed false assertion cannot be recorded as pending")
        if record.state == EvidenceState.PASS and (
                record.exit_code != 0 or not record.assertions
                or any(value is not True for value in record.assertions.values())):
            raise TargetAuthorityError("a passing root result requires every exact observed assertion")
        handle = secrets.token_urlsafe(32)
        result_sha = _hash(retained_result)
        result_path_handle = secrets.token_urlsafe(32)
        self.journal.put_once("observed-results", result_path_handle, {
            "schema": 1, "bytes_b64": base64.b64encode(retained_result).decode("ascii"),
            "sha256": result_sha,
        })
        assertion_handles = []
        for assertion_id, value in sorted(record.assertions.items()):
            assertion_handle = secrets.token_urlsafe(32)
            self.journal.put_once("assertions", assertion_handle, {
                "schema": 1, "assertion_receipt_handle": assertion_handle,
                "workflow_handle": admission.workflow_handle,
                "acceptance_id": admission.acceptance_id,
                "evidence_id": record.evidence_id,
                "assertion_id": assertion_id, "observed_value": value,
                "target_id": admission.target_id,
                "candidate_git_sha": candidate.candidate_git_sha,
                "candidate_artifact_closure_sha256": candidate.candidate_artifact_closure_sha256,
                "service_generation_digest": self.runtime.service.service_generation_digest,
                "run_nonce": admission.run_nonce,
                "observed_result_sha256": result_sha,
                "observed_monotonic": self.runtime.service.monotonic(),
            })
            assertion_handles.append(assertion_handle)
        claims = {
            "schema": 1, "result_receipt_handle": handle,
            "workflow_handle": admission.workflow_handle,
            "acceptance_id": admission.acceptance_id,
            "evidence_ids": [record.evidence_id], "target_id": admission.target_id,
            "platform": admission.platform,
            "candidate_git_sha": candidate.candidate_git_sha,
            "candidate_artifact_closure_sha256": candidate.candidate_artifact_closure_sha256,
            "service_generation_digest": self.runtime.service.service_generation_digest,
            "run_nonce": admission.run_nonce,
            "assertion_receipt_handles": assertion_handles,
            "result_artifact_handle": result_path_handle,
            "observed_result_sha256": result_sha,
            "observed_monotonic": self.runtime.service.monotonic(),
            "terminal_state": record.state.value,
            "record": asdict(record),
        }
        self.journal.put_once("results", handle, claims)
        return handle

    def _check_admission(self, claims: Mapping[str, Any], admission: RootTargetWorkflowAdmission) -> None:
        expected = asdict(admission)
        expected.pop("signature_sha256")
        if any(claims.get(key) != value for key, value in expected.items()):
            raise TargetAuthorityError("workflow admission receipt changed or does not match")
        if claims.get("expires_monotonic", 0) <= self.runtime.service.monotonic():
            raise TargetAuthorityError("workflow admission expired")

    def verify_result(self, workflow_handle: str, structured_result_receipt_handle: str,
                      *, authorizer: InstallerTrustedTargetAuthorizer) -> VerifiedRootWorkflowResult:
        if authorizer.runtime is not self.runtime:
            raise TargetAuthorityError("result verifier is bound to another root runtime")
        authorizer._ensure_current()
        claims, _receipt_digest = self.journal.get("results", structured_result_receipt_handle)
        admission_claims, _ = self.journal.get("admissions", workflow_handle)
        if (claims.get("workflow_handle") != workflow_handle
                or claims.get("target_id") != authorizer.target_id
                or claims.get("platform") != authorizer.platform_id
                or claims.get("service_generation_digest") != self.runtime.service.service_generation_digest
                or claims.get("candidate_git_sha") != self.candidate_receipts.get_current(
                    claims.get("candidate_git_sha", "")).candidate_git_sha
                or claims.get("run_nonce") != admission_claims.get("run_nonce")
                or claims.get("candidate_artifact_closure_sha256") != admission_claims.get("candidate_artifact_closure_sha256")
                or claims.get("acceptance_id") != admission_claims.get("acceptance_id")
                or not self.journal.was_consumed("admissions", workflow_handle)
                or claims.get("observed_monotonic", 0) < admission_claims.get("issued_monotonic", 0)
                or claims.get("observed_monotonic", 0) > admission_claims.get("expires_monotonic", 0)):
            raise TargetAuthorityError("result receipt is stale or bound to another workflow, target or release")
        record_value = claims.get("record")
        if not isinstance(record_value, Mapping):
            raise TargetAuthorityError("root result receipt has no structured evidence record")
        record = EvidenceRecord.from_dict(record_value)
        if claims.get("terminal_state") != record.state.value:
            raise TargetAuthorityError("root result terminal state does not match its retained evidence record")
        profile = profile_for(record.evidence_id, claims["acceptance_id"])
        artifact_handle = claims.get("result_artifact_handle")
        if not isinstance(artifact_handle, str):
            raise TargetAuthorityError("root result receipt is missing its retained observation artifact")
        artifact_claims, _ = self.journal.get("observed-results", artifact_handle)
        assertion_handles = claims.get("assertion_receipt_handles")
        if not isinstance(assertion_handles, list) or len(assertion_handles) != len(profile.assertions):
            raise TargetAuthorityError("root result has incomplete per-assertion receipts")
        assertion_values = {}
        for handle in assertion_handles:
            assertion, _ = self.journal.get("assertions", handle)
            if (assertion.get("workflow_handle") != workflow_handle
                    or assertion.get("acceptance_id") != claims.get("acceptance_id")
                    or assertion.get("evidence_id") != record.evidence_id
                    or assertion.get("target_id") != claims.get("target_id")
                    or assertion.get("candidate_git_sha") != claims.get("candidate_git_sha")
                    or assertion.get("candidate_artifact_closure_sha256") != claims.get("candidate_artifact_closure_sha256")
                    or assertion.get("service_generation_digest") != claims.get("service_generation_digest")
                    or assertion.get("run_nonce") != claims.get("run_nonce")
                    or assertion.get("observed_result_sha256") != claims.get("observed_result_sha256")
                    or assertion.get("assertion_id") in assertion_values):
                raise TargetAuthorityError("per-assertion receipt is bound to another observation")
            assertion_values[assertion.get("assertion_id")] = assertion.get("observed_value")
        try:
            artifact_bytes = base64.b64decode(artifact_claims["bytes_b64"], validate=True)
            artifact_value = json.loads(artifact_bytes.decode("utf-8"))
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            raise TargetAuthorityError("retained root observation artifact is malformed") from None
        if (record.candidate_sha != claims["candidate_git_sha"]
                or record.target_id != claims["target_id"]
                or record.platform != claims["platform"]
                or set(record.assertions) != set(profile.assertions)
                or claims.get("evidence_ids") != [record.evidence_id]
                or claims.get("observed_result_sha256") != record.artifact_sha256
                or len(artifact_bytes) > _MAX_RESULT
                or artifact_claims.get("sha256") != _hash(artifact_bytes)
                or claims.get("observed_result_sha256") != _hash(artifact_bytes)
                or not isinstance(artifact_value, Mapping)
                or artifact_value.get("candidate_sha") != record.candidate_sha
                or artifact_value.get("target_id") != record.target_id
                or artifact_value.get("platform") != record.platform
                or artifact_value.get("evidence_id") != record.evidence_id
                or artifact_value.get("assertions") != dict(record.assertions)
                or assertion_values != dict(record.assertions)
                or set(assertion_values) != set(profile.assertions)):
            raise TargetAuthorityError("root result evidence does not satisfy its exact installer profile")
        return VerifiedRootWorkflowResult(
            workflow_handle, structured_result_receipt_handle, claims["acceptance_id"],
            claims["target_id"], claims["candidate_git_sha"],
            claims["candidate_artifact_closure_sha256"], claims["service_generation_digest"],
            claims["run_nonce"], tuple(claims["evidence_ids"]),
            tuple(claims["assertion_receipt_handles"]), claims["observed_result_sha256"],
            float(claims["observed_monotonic"]), claims["terminal_state"], record,
        )


class InstallerTrustedResultVerifier:
    """Expose result authentication only over the root receipt registries."""

    def __init__(self, observations: RootObservationReceiptRegistry,
                 candidates: InstalledCandidateReceiptRegistry, current_active_catalog: Any):
        if (observations.candidate_receipts is not candidates
                or current_active_catalog is not observations.runtime.bindings.enrollment_catalog):
            raise TargetAuthorityError("result verifier inputs do not share the current protected catalog")
        self.observations, self.candidates = observations, candidates
        self.runtime = observations.runtime
        self.current_active_catalog = current_active_catalog

    @classmethod
    def from_root_receipts(cls, root_observation_receipt_registry: RootObservationReceiptRegistry,
                           installed_candidate_receipt_registry: InstalledCandidateReceiptRegistry,
                           current_active_catalog: Any) -> "InstallerTrustedResultVerifier":
        _root_runtime(root_observation_receipt_registry.runtime)
        return cls(root_observation_receipt_registry, installed_candidate_receipt_registry,
                   current_active_catalog)

    def verify_result(self, workflow_handle: str, structured_result_receipt_handle: str,
                      *, authorizer: InstallerTrustedTargetAuthorizer) -> VerifiedRootWorkflowResult:
        if (authorizer.runtime is not self.runtime
                or self.current_active_catalog is not self.runtime.bindings.enrollment_catalog):
            raise TargetAuthorityError("active protected catalog changed since result-verifier assembly")
        return self.observations.verify_result(
            workflow_handle, structured_result_receipt_handle, authorizer=authorizer,
        )


class InstallerOwnedWorkflowAdapterRegistry:
    """Static adapters loaded only from the currently verified release tree."""

    def __init__(self, release: Any, workflows: Mapping[str, Callable[..., EvidenceRecord]],
                 *, _seal: object | None = None):
        if _seal is not _SEAL:
            raise TypeError("workflow adapter registries can only be built from an installed verified release")
        self.release = release
        self._workflows = dict(workflows)

    @classmethod
    def from_root_runtime(cls, runtime: RootAuthorityRuntime,
                          candidate_receipts: InstalledCandidateReceiptRegistry,
                          candidate_git_sha: str) -> "InstallerOwnedWorkflowAdapterRegistry":
        if candidate_receipts.runtime is not runtime:
            raise TargetAuthorityError("candidate receipt registry belongs to another root runtime")
        candidate_receipts.get_current(candidate_git_sha)
        release = candidate_receipts.release
        try:
            from .registry_workflows import build_fixed_workflows
            module_path = Path(inspect.getsourcefile(build_fixed_workflows) or "").resolve(strict=True)
        except (OSError, TypeError, ValueError):
            raise TargetAuthorityError("fixed acceptance adapter module is unavailable") from None
        root = Path(release.release_root).resolve(strict=True)
        if not module_path.is_relative_to(root):
            raise TargetAuthorityError("acceptance adapter was not loaded from the current installed release")
        relative = module_path.relative_to(root).as_posix()
        rows = [row for row in release.files if row.relative_path == relative]
        if len(rows) != 1 or rows[0].size_bytes > 4 * 1024 * 1024:
            raise TargetAuthorityError("acceptance adapter source is absent or exceeds its bound")
        try:
            fd = release.open_file(rows[0].artifact_id)
            try:
                source_hash = hashlib.sha256()
                remaining = rows[0].size_bytes
                while remaining:
                    block = os.read(fd, min(65_536, remaining))
                    if not block:
                        raise TargetAuthorityError("acceptance adapter source ended before its pinned size")
                    source_hash.update(block)
                    remaining -= len(block)
                if os.read(fd, 1):
                    raise TargetAuthorityError("acceptance adapter source exceeds its pinned size")
            finally:
                os.close(fd)
        except OSError as exc:
            raise TargetAuthorityError("acceptance adapter source could not be read from release custody") from exc
        if source_hash.hexdigest() != rows[0].sha256:
            raise TargetAuthorityError("acceptance adapter bytes do not match the immutable release closure")
        release.verify_current()
        workflows = build_fixed_workflows(checkout=root, candidate_sha=candidate_git_sha)
        if not isinstance(workflows, Mapping) or any(
                not re.fullmatch(r"AC\d{2}", key) or not callable(value)
                for key, value in workflows.items()):
            raise TargetAuthorityError("installed workflow registry is malformed")
        return cls(release, workflows, _seal=_SEAL)

    def resolve(self, acceptance_id: str) -> Callable[..., EvidenceRecord] | None:
        return self._workflows.get(acceptance_id)


class InstallerOwnedTargetWorkflowRunner:
    """Compose root admission, pinned fixed adapter, and signed root receipt."""

    def __init__(self, runtime: RootAuthorityRuntime,
                 authorizer: InstallerTrustedTargetAuthorizer,
                 adapters: InstallerOwnedWorkflowAdapterRegistry,
                 observations: RootObservationReceiptRegistry):
        self.runtime, self.authorizer = runtime, authorizer
        self.adapters, self.observations = adapters, observations
        self.observations._issuer = self
        self.result_verifier = InstallerTrustedResultVerifier.from_root_receipts(
            observations, authorizer.candidate_receipts,
            runtime.bindings.enrollment_catalog,
        )

    @classmethod
    def from_root_runtime(cls, authorizer: InstallerTrustedTargetAuthorizer,
                          root_workflow_adapter_registry: InstallerOwnedWorkflowAdapterRegistry,
                          root_observation_receipt_registry: RootObservationReceiptRegistry
                          ) -> "InstallerOwnedTargetWorkflowRunner":
        runtime = _root_runtime(authorizer.runtime)
        if (root_workflow_adapter_registry.release is not authorizer.candidate_receipts.release
                or root_observation_receipt_registry.runtime is not runtime):
            raise TargetAuthorityError("workflow adapters or observation registry do not match the current root release")
        return cls(runtime, authorizer, root_workflow_adapter_registry,
                   root_observation_receipt_registry)

    def run(self, acceptance_id: str, candidate_git_sha: str) -> WorkflowResult:
        workflow = self.adapters.resolve(acceptance_id)
        if workflow is None:
            return WorkflowResult(acceptance_id, EvidenceState.PENDING,
                                  "No reviewed functional workflow is registered; exact requirement remains pending.")
        admission = self.authorizer.authorize_workflow(candidate_git_sha, acceptance_id)
        self.observations.journal.consume_once("admissions", admission.workflow_handle)
        now = datetime.now(timezone.utc)
        target = _internal_target(self.authorizer, admission)
        with tempfile.TemporaryDirectory(prefix="hermes-verify-") as temp_dir:
            root = Path(temp_dir)
            os.chmod(root, 0o700)
            result = workflow(target, str(root))
            result.validate()
            files = [path for path in root.rglob("*") if path.is_file() and not path.is_symlink()]
            matching = [path for path in files if _hash(path.read_bytes()) == result.artifact_sha256]
            if len(matching) != 1:
                raise TargetAuthorityError("fixed workflow did not retain one exact bounded result artifact")
            retained = matching[0].read_bytes()
            if len(retained) > _MAX_RESULT:
                raise TargetAuthorityError("fixed workflow result artifact exceeds its bound")
        handle = self.observations._issue(self, admission, result, retained)
        trusted = self.result_verifier.verify_result(admission.workflow_handle, handle,
                                                      authorizer=self.authorizer)
        return WorkflowResult(
            acceptance_id, EvidenceState.PENDING,
            f"Root-observed {trusted.record.evidence_id} retained and authenticated; acceptance remains pending other required assertions.",
            trusted.record,
        )


def _internal_target(authorizer: InstallerTrustedTargetAuthorizer,
                     admission: RootTargetWorkflowAdmission) -> AuthorizedTarget:
    selection = authorizer.selection
    now = datetime.now(timezone.utc)
    target = AuthorizedTarget(
        target_id=admission.target_id,
        platform=authorizer.platform_id,
        owner=selection.username,
        authorization_reference=f"root-active-enrollment:{admission.service_generation_digest}",
        expires_at=(now + timedelta(seconds=max(1, min(300, admission.expires_monotonic
                      - authorizer.runtime.service.monotonic())))).isoformat(),
        allowed_acceptance=(admission.acceptance_id,),
        manifest_sha256=_hash(_canonical({"target": admission.target_id,
                                           "principal": admission.principal_id,
                                           "candidate": admission.candidate_git_sha})),
    )
    target.validate()
    return target
